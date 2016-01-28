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

module: nxos_hsrp
short_description: Manages HSRP configuration on NX-API enabled devices
description:
    - Manages HSRP configuration on NX-API enabled devices
author: Jason Edelman (@jedelman8)
requirements:
    - NX-API 1.0
    - NX-OS 6.1(2)I3(1)
    - pycsco
notes:
    - HSRP feature needs to be enabled first on the system
    - SVIs must exist before using this module
    - Interface must be a L3 port before using this module
    - While username and password are not required params, they are
      if you are not using the .netauth file.  .netauth file is recommended
      as it will clean up the each task in the playbook by not requiring
      the username and password params for every tasks.
    - Using the username and password params will override the .netauth file
options:
    group:
        description:
            - hsrp group number
        required: true
        default: null
        choices: []
        aliases: []
    interface:
        description:
            - Full name of interface that is being managed for HSRP
        required: true
        default: null
        choices: []
        aliases: []
    version:
        description:
            - nxos_hsrp version
        required: false
        default: 2
        choices: ['1','2']
        aliases: []
    priority:
        description:
            - hsrp priority
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
    auth_string:
        description:
            - Authentication string
        required: false
        default: null
        choices: []
        aliases: []
    auth_type:
        description:
            - Authentication type
        required: false
        default: null
        choices: ['text','md5']
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
# ensure hsrp is configured with following params on a SVI
- nxos_hsrp: group=10 vip=10.1.1.1 priority=150 interface=vlan10 preempt=enabled host={{ inventory_hostname }}

# ensure hsrp is configured with following params on a SVI
- nxos_hsrp: group=10 vip=10.1.1.1 priority=150 interface=vlan10 preempt=enabled host={{ inventory_hostname }} auth_type=text auth_string=CISCO

# removing hsrp config for given interface, group, and vip
- nxos_hsrp: group=10 interface=vlan10 vip=10.1.1.1 host={{ inventory_hostname }} state=absent
'''

RETURN = '''
proposed:
    description: k/v pairs of parameters passed into module
    returned: always
    type: dict
    sample: {"group": "30", "version": "2", "vip": "10.30.1.1"}
existing:
    description: k/v pairs of existing hsrp info on the interface
    type: dict
    sample: {}
end_state:
    description: k/v pairs of hsrp after module execution
    returned: always
    type: dict
    sample: {"auth_string": "cisco", "auth_type": "text",
            "group": "30", "interface": "vlan10", "preempt": "disabled",
            "priority": "100", "version": "2", "vip": "10.30.1.1"}
state:
    description: state as sent in from the playbook
    returned: always
    type: string
    sample: "present"
commands:
    description: command string sent to the device
    returned: always
    type: string
    sample: "interface vlan10 ; hsrp version 2 ; hsrp 30 ; ip 10.30.1.1 ;"
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


def get_hsrp_state(device, module):
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

            if 'hsrp' in feature:
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


def get_hsrp_groups_on_interfaces(device):
    """Gets hsrp groups configured on each interface
    Args:
        device (Device): This is the device object of an NX-API enabled device
            using the Device class within device.py
    Returns:
        dict: k/v pairs in the form of interface/[group list]
    """
    command = 'show hsrp all'
    xmlReturnData = device.show(command)
    result = xmltodict.parse(xmlReturnData[1])
    hsrp = {}
    try:
        get_data = result['ins_api']['outputs']['output']['body'].get(
            'TABLE_grp_detail')['ROW_grp_detail']
        for entry in get_data:
            interface = str(entry['sh_if_index'].lower())
            value = hsrp.get(interface, 'new')
            if value == 'new':
                hsrp[interface] = []
            group = str(entry['sh_group_num'])
            hsrp[interface].append(group)
    except (KeyError, AttributeError, CLIError):
        hsrp = {}

    return hsrp


def get_hsrp_group(device, group, interface, module):
    command = 'show hsrp group {0}'.format(group)
    body = parsed_data_from_device(device, command, module)
    hsrp = {}

    hsrp_key = {
        'sh_if_index': 'interface',
        'sh_group_num': 'group',
        'sh_group_version': 'version',
        'sh_cfg_prio': 'priority',
        'sh_preempt': 'preempt',
        'sh_vip': 'vip',
        'sh_authentication_type': 'auth_type',
        'sh_authentication_data': 'auth_string'
    }

    if body:
        hsrp_table = body['TABLE_grp_detail']['ROW_grp_detail']

        if isinstance(hsrp_table, dict):
            hsrp_table = [hsrp_table]

        for hsrp_group in hsrp_table:
            parsed_hsrp = apply_key_map(hsrp_key, hsrp_group)

            parsed_hsrp['interface'] = parsed_hsrp['interface'].lower()

            if parsed_hsrp['version'] == 'v1':
                parsed_hsrp['version'] = '1'
            elif parsed_hsrp['version'] == 'v2':
                parsed_hsrp['version'] = '2'

            if parsed_hsrp['interface'] == interface:
                return parsed_hsrp
    return hsrp


def get_commands_remove_hsrp(group, interface):
    commands = []
    commands.append('interface {0}'.format(interface))
    commands.append('no hsrp {0}'.format(group))
    return commands


def get_commands_config_hsrp(delta, interface, args):
    commands = []

    config_args = {
        'group': 'hsrp {group}',
        'priority': 'priority {priority}',
        'preempt': '{preempt}',
        'vip': 'ip {vip}'
    }

    preempt = delta.get('preempt', None)
    group = delta.get('group', None)
    if preempt:
        if preempt == 'enabled':
            delta['preempt'] = 'preempt'
        elif preempt == 'disabled':
            delta['preempt'] = 'no preempt'

    for key, value in delta.iteritems():
        command = config_args.get(key, 'DNE').format(**delta)
        if command and command != 'DNE':
            if key == 'group':
                commands.insert(0, command)
            else:
                commands.append(command)
        command = None

    auth_type = delta.get('auth_type', None)
    auth_string = delta.get('auth_string', None)
    if auth_type or auth_string:
        if not auth_type:
            auth_type = args['auth_type']
        elif not auth_string:
            auth_string = args['auth_string']
        if auth_type == 'md5':
            command = 'authentication md5 key-string {0}'.format(auth_string)
            commands.append(command)
        elif auth_type == 'text':
            command = 'authentication text {0}'.format(auth_string)
            commands.append(command)

    if commands and not group:
        commands.insert(0, 'hsrp {0}'.format(args['group']))

    version = delta.get('version', None)
    if version:
        if version == '2':
            command = 'hsrp version 2'
        elif version == '1':
            command = 'hsrp version 1'
        commands.insert(0, command)
        commands.insert(0, 'interface {0}'.format(interface))

    if commands:
        if not commands[0].startswith('interface'):
            commands.insert(0, 'interface {0}'.format(interface))

    return commands


def main():
    module = AnsibleModule(
        argument_spec=dict(
            group=dict(required=True, type='str'),
            interface=dict(required=True),
            version=dict(choices=['1', '2'], default='2'),
            priority=dict(type='str'),
            preempt=dict(type='str', choices=['disabled', 'enabled']),
            vip=dict(type='str'),
            auth_type=dict(choices=['text', 'md5']),
            auth_string=dict(type='str'),
            state=dict(choices=['absent', 'present'], default='present'),
            protocol=dict(choices=['http', 'https'], default='http'),
            port=dict(required=False, type='int', default=None),
            host=dict(required=True),
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

    interface = module.params['interface'].lower()
    group = module.params['group']
    version = module.params['version']
    state = module.params['state']
    priority = module.params['priority']
    preempt = module.params['preempt']
    vip = module.params['vip']
    auth_type = module.params['auth_type']
    auth_string = module.params['auth_string']

    device = Device(ip=host, username=username, password=password,
                    protocol=protocol, port=port)

    if state == 'present' and not vip:
        module.fail_json(msg='the "vip" param is required when state=present')

    if not get_hsrp_state(device, module):
        module.fail_json(msg='HSRP feature needs to be enabled first')

    intf_type = get_interface_type(interface)
    if intf_type != 'ethernet':
        if is_default(device, interface, module) == 'DNE':
            module.fail_json(msg='That interface does not exist yet.\nCreate '
                                 'it first.', interface=interface)

    mode = get_interface_mode(device, interface, intf_type, module)
    if mode == 'layer2':
        module.fail_json(msg='That interface is a layer2 port.\nMake it '
                             'a layer 3 port first.', interface=interface)

    if auth_type or auth_string:
        if not (auth_type and auth_string):
            module.fail_json(msg='When using auth parameters, you need BOTH '
                                 'auth_type AND auth_string.')

    args = dict(group=group, version=version, priority=priority,
                preempt=preempt, vip=vip, auth_type=auth_type,
                auth_string=auth_string)

    proposed = dict((k, v) for k, v in args.iteritems() if v is not None)

    existing = get_hsrp_group(device, group, interface, module)

    # Can't use md5 encryption with hsrp v1.
    # We are just offering have "md5 0 key-string", not using 7 yet.
    # This will enforce better practice.
    if proposed.get('auth_type', None) == 'md5':
        if proposed['version'] == '1':
            module.fail_json(msg="It's recommended to use HSRP v2 "
                                 "when auth_type=md5")

    elif not proposed.get('auth_type', None):
        if (proposed['version'] == '1' and
                existing['auth_type'] == 'md5'):
            module.fail_json(msg="Existing auth_type is md5. It's recommended "
                                 "to use HSRP v2 when using md5")

    changed = False
    end_state = existing
    commands = []
    if state == 'present':
        delta = dict(
                    set(proposed.iteritems()).difference(existing.iteritems()))
        if delta:
            command = get_commands_config_hsrp(delta, interface, args)
            commands.append(command)

    elif state == 'absent':
        if existing:
            command = get_commands_remove_hsrp(group, interface)
            commands.append(command)

    cmds = nested_command_list_to_string(commands)
    if cmds:
        if module.check_mode:
            module.exit_json(changed=True, commands=cmds)
        else:
            changed = True
            device.config(cmds)
            end_state = get_hsrp_group(device, group, interface, module)

    results = {}
    results['proposed'] = proposed
    results['existing'] = existing
    results['end_state'] = end_state
    results['state'] = state
    results['commands'] = cmds
    results['changed'] = changed

    module.exit_json(**results)


from ansible.module_utils.basic import *
if __name__ == '__main__':
    main()
