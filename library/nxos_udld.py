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

module: nxos_udld
short_description: Manages UDLD global configuration params
description:
    - Manages UDLD global configuration params
author: Jason Edelman (@jedelman8)
requirements:
    - NX-API 1.0
    - NX-OS 6.1(2)I3(1)
    - pycsco
notes:
    - When state=absent, it unconfigures existing setings msg_time and set it
      to its default value of 15.  It is cleaner to always use state=present.
    - Module will fail if the udld feature has not been previously enabled
    - While username and password are not required params, they are
      if you are not using the .netauth file.  .netauth file is recommended
      as it will clean up the each task in the playbook by not requiring
      the username and password params for every tasks.
    - Using the username and password params will override the .netauth file
options:
    aggressive:
        description:
            - Toggles aggressive mode
        required: false
        default: null
        choices: ['enabled','disabled']
        aliases: []
    msg_time:
        description:
            - Message time in seconds for UDLD packets
        required: false
        default: null
        choices: []
        aliases: []
    reset:
        description:
            - Ability to reset UDLD down interfaces
        required: false
        default: null
        choices: ['true','false']
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
# ensure udld aggressive mode is globally disabled and se global message interval is 20
- nxos_udld: aggressive=disabled msg_time=20 host={{ inventory_hostname }}

# Ensure agg mode is globally enabled and msg time is 15
- nxos_udld: aggressive=enabled msg_time=15 host={{ inventory_hostname }} state=present

# Ensure msg_time is unconfigured (if it is already 25- basically defaults back to 15 anyway)
'''

RETURN = '''
proposed:
    description: k/v pairs of parameters passed into module
    returned: always
    type: dict
    sample: {"aggressive": "enabled", "msg_time": "40"}
existing:
    description:
        - k/v pairs of existing udld configuration
    type: dict
    sample: {"aggressive": "disabled", "msg_time": "15"}
end_state:
    description: k/v pairs of udld configuration after module execution
    returned: always
    type: dict
    sample: {"aggressive": "enabled", "msg_time": "40"}
state:
    description: state as sent in from the playbook
    returned: always
    type: string
    sample: "present"
commands:
    description: command string sent to the device
    returned: always
    type: string
    sample: "udld message-time 40 ; udld aggressive ;"
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


def get_commands_config_udld_global(delta, reset):
    config_args = {
        'enabled': 'udld aggressive',
        'disabled': 'no udld aggressive',
        'msg_time': 'udld message-time {msg_time}'
    }
    commands = []
    for param, value in delta.iteritems():
        if param == 'aggressive':
            if value == 'enabled':
                command = 'udld aggressive'
            elif value == 'disabled':
                command = 'no udld aggressive'
        else:
            command = config_args.get(param, 'DNE').format(**delta)
        if command and command != 'DNE':
            commands.append(command)
        command = None

    if reset:
        command = 'udld reset'
        commands.append(command)
    return commands


def get_commands_remove_udld_global(delta):
    config_args = {
        'aggressive': 'no udld aggressive',
        'msg_time': 'no udld message-time {msg_time}',
    }
    commands = []
    for param, value in delta.iteritems():
        command = config_args.get(param, 'DNE').format(**delta)
        if command and command != 'DNE':
            commands.append(command)
        command = None
    return commands


def get_udld_global(device, module):
    command = 'show udld global'
    udld_table = parsed_data_from_device(device, command, module)

    status = str(udld_table.get('udld-global-mode', None))
    if status == 'enabled-aggressive':
        aggressive = 'enabled'
    else:
        aggressive = 'disabled'

    interval = str(udld_table.get('message-interval', None))
    udld = dict(msg_time=interval, aggressive=aggressive)

    return udld


def main():
    module = AnsibleModule(
        argument_spec=dict(
            aggressive=dict(choices=['enabled', 'disabled']),
            msg_time=dict(type='str'),
            reset=dict(choices=BOOLEANS, type='bool'),
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

    aggressive = module.params['aggressive']
    msg_time = module.params['msg_time']
    reset = module.params['reset']
    state = module.params['state']

    device = Device(ip=host, username=username, password=password,
                    protocol=protocol, port=port)

    if (aggressive or reset) and state == 'absent':
        module.fail_json(msg="It's better to use state=present when "
                             "configuring or unconfiguring aggressive mode "
                             "or using reset flag. state=absent is just for "
                             "when using msg_time param.")

    if msg_time:
        try:
            msg_time_int = int(msg_time)
            if msg_time_int < 7 or msg_time_int > 90:
                raise ValueError
        except ValueError:
            module.fail_json(msg='msg_time must be an integer'
                                 'between 7 and 90')

    args = dict(aggressive=aggressive, msg_time=msg_time, reset=reset)
    proposed = dict((k, v) for k, v in args.iteritems() if v is not None)

    existing = get_udld_global(device, module)
    end_state = existing

    delta = set(proposed.iteritems()).difference(existing.iteritems())
    changed = False

    commands = []
    if state == 'present':
        if delta:
            command = get_commands_config_udld_global(dict(delta), reset)
            commands.append(command)

    elif state == 'absent':
        common = set(proposed.iteritems()).intersection(existing.iteritems())
        if common:
            command = get_commands_remove_udld_global(dict(common))
            commands.append(command)

    cmds = nested_command_list_to_string(commands)
    if cmds:
        if module.check_mode:
            module.exit_json(changed=True, commands=cmds)
        else:
            changed = True
            device.config(cmds)
            end_state = get_udld_global(device, module)

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
