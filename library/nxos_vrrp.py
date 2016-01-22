#!/usr/bin/env python

# Copyright 2015 Jason Edelman <jedelman8@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

DOCUMENTATION = '''
---

module: nxos_vrrp
short_description: Manages VRRP configuration on NX-API enabled devices
description:
    - Manages VRRP configuration on NX-API enabled devices
author: Jason Edelman (@jedelman8)
requirements:
    - NX-API 1.0
    - NX-OS 6.1(2)I3(1)
    - pycsco
notes:
    - VRRP feature needs to be enabled first on the system
    - SVIs must exist before using this module
    - Interface must be a L3 port before using this module
    - state=absent removes the vrrp group if it exists on the device
    - While username and password are not required params, they are
      if you are not using the .netauth file.  .netauth file is recommended
      as it will clean up the each task in the playbook by not requiring
      the username and password params for every tasks.
    - Using the username and password params will override the .netauth file
options:
    group:
        description:
            - vrrp group number
        required: true
        default: null
        choices: []
        aliases: []
    interface:
        description:
            - Full name of interface that is being managed for vrrp
        required: true
        default: null
        choices: []
        aliases: []
    priority:
        description:
            - vrrp priority
        required: false
        default: null
        choices: []
        aliases: []
    vip:
        description:
            - hsrp virtual IP address
        required: false
        default: null
        choices: []
        aliases: []
    authentication:
        description:
            - clear text authentication string
        required: false
        default: null
        choices: []
        aliases: []
    state:
        description:
            - Specify desired state of the resource
        required: true
        default: present
        choices: ['present','absent']
        aliases: []
    host:
        description:
            - IP Address or hostname (resolvable by Ansible control host)
              of the target NX-API enabled switch
        required: true
        default: null
        choices: []
        aliases: []
    port:
        description:
            - TCP port to use for communication with switch
        required: false
        default: null
        choices: []
        aliases: []
    username:
        description:
            - Username used to login to the switch
        required: false
        default: null
        choices: []
        aliases: []
    password:
        description:
            - Password used to login to the switch
        required: false
        default: null
        choices: []
        aliases: []
    protocol:
        description:
            - Dictates connection protocol to use for NX-API
        required: false
        default: http
        choices: ['http', 'https']
        aliases: []
'''

EXAMPLES = '''

# ensure vrrp group 100 and vip 10.1.100.1 is on vlan10
- nxos_vrrp: interface=vlan10 group=100 vip=10.1.100.1 host={{ inventory_hostname }}

# ensure removal of the vrrp group config # vip is required to ensure the user knows what they are removing
- nxos_vrrp: interface=vlan10 group=100 vip=10.1.100.1 state=absent host={{ inventory_hostname }}

# re-config with more params
- nxos_vrrp: interface=vlan10 group=100 vip=10.1.100.1 preempt=false priority=130 authentication=AUTHKEY host={{ inventory_hostname }}

'''

RETURN = '''
proposed:
    description: k/v pairs of parameters passed into module
    returned: always
    type: dict
    sample: {"authentication": "testing", "group": "150", "vip": "10.1.15.1"}
existing:
    description: k/v pairs of existing vrrp info on the interface
    type: dict
    sample: {}
end_state:
    description: k/v pairs of vrrp after module execution
    returned: always
    type: dict
    sample: {"authentication": "testing", "group": "150", "interval": "1",
            "preempt": true, "priority": "100", "vip": "10.1.15.1"}
state:
    description: state as sent in from the playbook
    returned: always
    type: string
    sample: "present"
commands:
    description: command string sent to the device
    returned: always
    type: string
    sample: "interface vlan10 ; vrrp 150 ; address 10.1.15.1 ; authentication text testing ;"
changed:
    description: check to see if a change was made on the device
    returned: always
    type: boolean
    sample: true
'''

import socket
import xmltodict
try:
    HAS_PYCSCO = True
    from pycsco.nxos.device import Device
    from pycsco.nxos.device import Auth
    from pycsco.nxos.error import CLIError
except ImportError as ie:
    HAS_PYCSCO = False


def parsed_data_from_device(device, command, module, text=False):
    try:
        data = device.show(command, text=text)
    except CLIError as clie:
        if 'show run interface' in command:
            return 'DNE'
        else:
            module.fail_json(msg='Error sending {0}'.format(command),
                             error=str(clie))

    data_dict = xmltodict.parse(data[1])
    body = data_dict['ins_api']['outputs']['output']['body']

    return body


def apply_key_map(key_map, table):
    new_dict = {}
    for key, value in table.items():
        new_key = key_map.get(key)
        if new_key:
            value = table.get(key)
            if value:
                new_dict[new_key] = str(value)
            else:
                new_dict[new_key] = value
    return new_dict


def nested_command_list_to_string(command_lists):
    cmds = ''
    if command_lists:
        cmds = ' '.join(' ; '.join(each) + ' ;'
                        for each in command_lists if each)
    return cmds


def get_vrrp_state(device, module):
    command = 'show feature'
    body = parsed_data_from_device(device, command, module, text=True)
    check = False

    if body:
        splitted_body = body.split('\n')
        for each in splitted_body[2::]:
            stripped = each.strip()
            words = stripped.split()
            feature = str(words[0])
            state = str(words[2])

            if feature == 'vrrp':
                if 'enabled' in state:
                    return True
                else:
                    return False
        return check


def get_interface_type(interface):
    if interface.upper().startswith('ET'):
        return 'ethernet'
    elif interface.upper().startswith('VL'):
        return 'svi'
    elif interface.upper().startswith('LO'):
        return 'loopback'
    elif interface.upper().startswith('MG'):
        return 'management'
    elif interface.upper().startswith('MA'):
        return 'management'
    elif interface.upper().startswith('PO'):
        return 'portchannel'
    else:
        return 'unknown'


def is_default(device, interface, module):
    command = 'show run interface {0}'.format(interface)

    try:
        body = parsed_data_from_device(device, command,
                                       module, text=True)
        if body == 'DNE':
            return 'DNE'
        else:
            raw_list = body.split('\n')
            if raw_list[-1].startswith('interface'):
                return True
            else:
                return False
    except (KeyError):
        return 'DNE'


def get_interface_mode(device, interface, intf_type, module):
    command = 'show interface {0}'.format(interface)
    interface = {}
    mode = 'unknown'

    if intf_type in ['ethernet', 'portchannel']:
        body = parsed_data_from_device(device, command, module)
        interface_table = body['TABLE_interface']['ROW_interface']
        mode = str(interface_table.get('eth_mode', 'layer3'))
        if mode == 'access' or mode == 'trunk':
            mode = 'layer2'
    elif intf_type == 'loopback' or intf_type == 'svi':
        mode = 'layer3'
    return mode


def get_existing_vrrp(device, interface, group, module):
    command = 'show vrrp detail interface {0}'.format(interface)
    body = parsed_data_from_device(device, command, module)
    vrrp = {}

    vrrp_key = {
        'sh_group_id': 'group',
        'sh_vip_addr': 'vip',
        'sh_priority': 'priority',
        'sh_group_preempt': 'preempt',
        'sh_auth_text': 'authentication',
        'sh_adv_interval': 'interval'
    }

    if body:
        vrrp_table = body['TABLE_vrrp_group']

        if isinstance(vrrp_table, dict):
            vrrp_table = [vrrp_table]

        for each_vrrp in vrrp_table:
            vrrp_row = each_vrrp['ROW_vrrp_group']
            parsed_vrrp = apply_key_map(vrrp_key, vrrp_row)

            if parsed_vrrp['preempt'] == 'Disable':
                parsed_vrrp['preempt'] = False
            elif parsed_vrrp['preempt'] == 'Enable':
                parsed_vrrp['preempt'] = True

            if parsed_vrrp['group'] == group:
                return parsed_vrrp
    return vrrp


def get_commands_config_vrrp(delta, group):
    commands = []

    CMDS = {
        'priority': 'priority {0}',
        'preempt': 'preempt',
        'vip': 'address {0}',
        'interval': 'advertisement-interval {0}',
        'auth': 'authentication text {0}'
    }

    vip = delta.get('vip')
    priority = delta.get('priority')
    preempt = delta.get('preempt')
    interval = delta.get('interval')
    auth = delta.get('authentication')

    if vip:
        commands.append((CMDS.get('vip')).format(vip))
    if priority:
        commands.append((CMDS.get('priority')).format(priority))
    if preempt:
        commands.append(CMDS.get('preempt'))
    elif preempt is False:
        commands.append('no ' + CMDS.get('preempt'))
    if interval:
        commands.append((CMDS.get('interval')).format(interval))
    if auth:
        commands.append((CMDS.get('auth')).format(auth))

    commands.insert(0, 'vrrp {0}'.format(group))

    return commands


def main():
    module = AnsibleModule(
        argument_spec=dict(
            group=dict(required=True, type='str'),
            interface=dict(required=True),
            priority=dict(type='str'),
            preempt=dict(choices=BOOLEANS, type='bool'),
            vip=dict(type='str'),
            authentication=dict(type='str'),
            state=dict(choices=['absent', 'present'],
                       default='present'),
            protocol=dict(choices=['http', 'https'], default='http'),
            host=dict(required=True),
            port=dict(required=False, type='int', default=None),
            username=dict(type='str'),
            password=dict(type='str'),
        ),
        supports_check_mode=True
    )
    if not HAS_PYCSCO:
        module.fail_json(msg='pycsco is required for this module')

    auth = Auth(vendor='cisco', model='nexus')
    username = module.params['username'] or auth.username
    password = module.params['password'] or auth.password
    protocol = module.params['protocol']
    port = module.params['port']
    host = socket.gethostbyname(module.params['host'])

    state = module.params['state']
    interface = module.params['interface'].lower()
    group = module.params['group']
    priority = module.params['priority']
    preempt = module.params['preempt']
    vip = module.params['vip']
    authentication = module.params['authentication']

    device = Device(ip=host, username=username, password=password,
                    protocol=protocol, port=port)

    if state == 'present' and not vip:
        module.fail_json(msg='the "vip" param is required when state=present')

    if not get_vrrp_state(device, module):
        module.fail_json(msg='vrrp feature needs to be enabled first')

    intf_type = get_interface_type(interface)
    if intf_type != 'ethernet':
        if is_default(device, interface, module) == 'DNE':
            module.fail_json(msg='That interface does not exist yet.\nCreate '
                                 'it first.', interface=interface)

    mode = get_interface_mode(device, interface, intf_type, module)
    if mode == 'layer2':
        module.fail_json(msg='That interface is a layer2 port.\nMake it '
                             'a layer 3 port first.', interface=interface)

    args = dict(group=group, priority=priority, preempt=preempt,
                vip=vip, authentication=authentication)

    proposed = dict((k, v) for k, v in args.iteritems() if v is not None)
    existing = get_existing_vrrp(device, interface, group, module)

    changed = False
    end_state = existing
    commands = []

    if state == 'present':
        delta = dict(
            set(proposed.iteritems()).difference(existing.iteritems()))
        if delta:
            command = get_commands_config_vrrp(delta, group)
            commands.append(command)

    elif state == 'absent':
        if existing:
            commands.append(['no vrrp {0}'.format(group)])

    if commands:
        commands.insert(0, ['interface {0}'.format(interface)])

    cmds = nested_command_list_to_string(commands)
    if cmds:
        if module.check_mode:
            module.exit_json(changed=True, commands=cmds)
        else:
            changed = True
            device.config(cmds)
            end_state = get_existing_vrrp(device, interface, group, module)

    results = {}
    results['proposed'] = proposed
    results['existing'] = existing
    results['state'] = state
    results['commands'] = cmds
    results['changed'] = changed
    results['end_state'] = end_state

    module.exit_json(**results)


from ansible.module_utils.basic import *
if __name__ == '__main__':
    main()
