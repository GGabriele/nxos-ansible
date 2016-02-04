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
module: nxos_udld_interface
short_description: Manages UDLD interface configuration params
description:
    - Manages UDLD interface configuration params
author: Jason Edelman (@jedelman8)
requirements:
    - NX-API 1.0
    - NX-OS 6.1(2)I3(1)
    - pycsco
notes:
    - When state=absent, it unconfigures existing setings if
      they already exist on the switch. It is much cleaner to use
      state=present for all options.
    - If state=absent, existing mode is C(aggressive) and interface is
      a copper one, then the final mode will be C(disabled).
    - If state=absent, existing mode is C(aggressive) and interface is not
      a copper one, then the final mode will be C(enabled).
    - Module will fail if the udld feature has not been previously enabled.
    - While username and password are not required params, they are
      if you are not using the .netauth file.  .netauth file is recommended
      as it will clean up the each task in the playbook by not requiring
      the username and password params for every tasks.
    - Using the username and password params will override the .netauth file
options:
    mode:
        description:
            - Manages udld mode for an interface
        required: true
        default: null
        choices: ['enabled','disabled','aggressive']
        aliases: []
    interface:
        description:
            - FULL name of the interface, i.e. Ethernet1/1
        required: true
        default: null
        choices: []
        aliases: []
    state:
        description:
            - Manage the state of the resource
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
# ensure Ethernet1/1 is configured to be in aggressive mode
- nxos_udld_interface: interface=Ethernet1/1 mode=aggressive state=present host={{ inventory_hostname }}

# Remove the aggressive config only if it's currently in aggressive mode and then disable udld (switch default)
- nxos_udld_interface: interface=Ethernet1/1 mode=aggressive state=absent host={{ inventory_hostname }}

# ensure Ethernet1/1 has aggressive mode enabled
- nxos_udld_interface: interface=Ethernet1/1 mode=enabled host={{ inventory_hostname }}

# ensure Ethernet1/1 has aggressive mode disabled
'''

RETURN = '''
proposed:
    description: k/v pairs of parameters passed into module
    returned: always
    type: dict
    sample: {"mode": "enabled"}
existing:
    description:
        - k/v pairs of existing udld interface configuration
    type: dict
    sample: {"mode": "disabled"}
end_state:
    description: k/v pairs of udld interface configuration after module run
    returned: always
    type: dict
    sample: {"mode": "enabled"}
state:
    description: state as sent in from the playbook
    returned: always
    type: string
    sample: "present"
commands:
    description: command string sent to the device
    returned: always
    type: string
    sample: "interface Ethernet2/1 ; no udld disable ;"
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
        module.fail_json(msg='Error sending {0}'.format(command),
                         error=str(clie))

    data_dict = xmltodict.parse(data[1])
    body = data_dict['ins_api']['outputs']['output']['body']

    return body


def nested_command_list_to_string(command_lists):
    cmds = ''
    if command_lists:
        cmds = ' '.join(' ; '.join(each) + ' ;'
                        for each in command_lists if each)
    return cmds


def normalize_interface(if_name):
    def _get_number(if_name):
        digits = ''
        for char in if_name:
            if char.isdigit() or char == '/':
                digits += char
        return digits

    if if_name.lower().startswith('et'):
        if_type = 'Ethernet'
    elif if_name.lower().startswith('vl'):
        if_type = 'Vlan'
    elif if_name.lower().startswith('lo'):
        if_type = 'Loopback'
    elif if_name.lower().startswith('po'):
        if_type = 'port-channel'
    else:
        if_type = None

    number_list = if_name.split(' ')
    if len(number_list) == 2:
        number = number_list[-1].strip()
    else:
        number = _get_number(if_name)

    if if_type:
        proper_interface = if_type + number
    else:
        proper_interface = if_name

    return proper_interface


def check_interface_type(interface):
    if interface.upper().startswith('ET'):
        return True
    else:
        return False


def get_udld_interface(device, interface, module):
    command = 'show udld {0}'.format(interface)
    interface_udld = {}
    mode = None

    body = parsed_data_from_device(device, command, module)
    udld_table = body['TABLE_interface']['ROW_interface']

    status = udld_table.get('mib-port-status', None)
    aggressive = udld_table.get('mib-aggresive-mode', 'disabled')

    if aggressive == 'enabled':
        mode = 'aggressive'
    else:
        mode = status

    interface_udld['mode'] = mode

    return interface_udld


def is_interface_copper(device, interface, module):
    command = 'show interface status'
    copper = []

    body = parsed_data_from_device(device, command, module)
    interfaces_table = body['TABLE_interface']['ROW_interface']

    for each_interface in interfaces_table:
        interface_type = each_interface.get('type', 'DNE')

        if ('CU' in interface_type or '1000' in interface_type or
                '10GBaseT' in interface_type):
            copper.append(str(each_interface['interface'].lower()))

    if interface.lower() in copper:
        found = True
    else:
        found = False

    return found


def get_commands_config_udld_interface(delta, interface, device, existing, module):
    commands = []
    copper = is_interface_copper(device, interface, module)

    mode = delta['mode']
    if mode == 'aggressive':
        command = 'udld aggressive'
    elif copper:
        if mode == 'enabled':
            if existing['mode'] == 'aggressive':
                command = 'no udld aggressive ; udld enable'
            else:
                command = 'udld enable'
        elif mode == 'disabled':
            command = 'no udld enable'
    elif not copper:
        if mode == 'enabled':
            if existing['mode'] == 'aggressive':
                command = 'no udld aggressive ; no udld disable'
            else:
                command = 'no udld disable'
        elif mode == 'disabled':
            command = 'udld disable'

    if command:
        commands.append(command)
        commands.insert(0, 'interface {0}'.format(interface))

    return commands


def get_commands_remove_udld_interface(delta, interface, device, existing, module):
    commands = []
    copper = is_interface_copper(device, interface, module)

    mode = delta['mode']
    if mode == 'aggressive':
        command = 'no udld aggressive'
    elif copper:
        if mode == 'enabled':
            command = 'no udld enable'
        elif mode == 'disabled':
            command = 'udld enable'
    elif not copper:
        if mode == 'enabled':
            command = 'udld disable'
        elif mode == 'disabled':
            command = 'no udld disable'

    if command:
        commands.append(command)
        commands.insert(0, 'interface {0}'.format(interface))

    return commands


def main():
    module = AnsibleModule(
        argument_spec=dict(
            mode=dict(choices=['enabled', 'disabled', 'aggressive'],
                      required=True),
            interface=dict(type='str'),
            state=dict(choices=['absent', 'present'], default='present'),
            protocol=dict(choices=['http', 'https'], default='http'),
            port=dict(required=False, type='int', default=None),
            host=dict(required=True),
            username=dict(type='str'),
            password=dict(type='str'),
        ),
        supports_check_mode=True
    )

    auth = Auth(vendor='cisco', model='nexus')
    username = module.params['username'] or auth.username
    password = module.params['password'] or auth.password
    protocol = module.params['protocol']
    port = module.params['port']
    host = socket.gethostbyname(module.params['host'])

    interface = module.params['interface'].lower()
    mode = module.params['mode']
    state = module.params['state']

    device = Device(ip=host, username=username, password=password,
                    protocol=protocol, port=port)

    if not check_interface_type(interface):
        module.fail_json(msg='Unsupported interface type. '
                             'This should be Ethernet',
                         interface=interface)

    normalized_interface = normalize_interface(interface)

    proposed = dict(mode=mode)
    existing = get_udld_interface(device, normalized_interface, module)
    end_state = existing

    delta = set(proposed.iteritems()).difference(existing.iteritems())
    changed = False

    commands = []
    if state == 'present':
        if delta:
            command = get_commands_config_udld_interface(
                    dict(delta), normalized_interface, device, existing, module
                    )
            commands.append(command)

    elif state == 'absent':
        common = set(proposed.iteritems()).intersection(existing.iteritems())
        if common:
            command = get_commands_remove_udld_interface(
                    dict(common), normalized_interface, device, existing, module
                        )
            commands.append(command)

    cmds = nested_command_list_to_string(commands)
    if cmds:
        if module.check_mode:
            module.exit_json(changed=True, commands=cmds)
        else:
            changed = True
            device.config(cmds)
            end_state = get_udld_interface(device, normalized_interface, module)

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
