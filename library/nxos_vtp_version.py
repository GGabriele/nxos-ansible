#!/usr/bin/python

# Copyright 2015 Gabriele Gerbino <gabriele@networktocode.com>
# Network to Code, LLC
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

module: nxos_vtp
short_description: Manages VTP configuration
description:
    - Manages VTP configuration
author: Gabriele Gerbino
requirements:
    - NX-API 1.0
    - NX-OS 6.1(2)I3(1)
    - pycsco
notes:
    - This module is used to manage only VTP version.
    - Use this in combination with nxos_vtp_password and nxos_vtp_domain
      to fully manage VTP operations.
    - While username and password are not required params, they are
      if you are not using the .netauth file.  .netauth file is recommended
      as it will clean up the each task in the playbook by not requiring
      the username and password params for every tasks.
    - Using the username and password params will override the .netauth file
options:
    version:
        description:
            - VTP version number
        required: true
        default: null
        choices: ['1', '2']
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
        choices: ['http','https']
        aliases: []
'''
EXAMPLES = '''
# ENSURE VTP VERSION IS 2
- nxos_vtp_version: version=2 host={{ inventory_hostname }}
'''

RETURN = '''
proposed:
    description: k/v pairs of parameters passed into module
    returned: always
    type: dict
    sample: {"version": "2"}
existing:
    description:
        - k/v pairs of existing vtp
    type: dict
    sample: {"domain": "testing", "version": "1", "vtp_password": "\\"}
end_state:
    description: k/v pairs of vtp after module execution
    returned: always
    type: dict
    sample: {"domain": "testing", "version": "2", "vtp_password": "\\"}
commands:
    description: command string sent to the device
    returned: always
    type: string
    sample: "vtp version 2 ;"
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


def get_vtp_config(device, module):
    command = 'show vtp status'
    body = parsed_data_from_device(device, command, module)

    vtp_key = {
        'running-version': 'version',
        'domain_name': 'domain',
        }

    vtp_parsed = apply_key_map(vtp_key, body)
    vtp_parsed['vtp_password'] = get_vtp_password(device, module)

    return vtp_parsed


def get_vtp_password(device, module):
    command = 'show vtp password'
    body = parsed_data_from_device(device, command, module)
    password = body['passwd']
    if password:
        return str(password)
    else:
        return ""


def get_vtp_state(device, module):
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

            if feature == 'vtp':
                if 'enabled' in state:
                    return True
                else:
                    return False
        return check


def main():
    module = AnsibleModule(
        argument_spec=dict(
            version=dict(type='str', choices=['1', '2'], required=True),
            host=dict(required=True),
            username=dict(),
            password=dict(),
            port=dict(required=False, type='int', default=None),
            protocol=dict(choices=['http', 'https'], default='http')
        ),
        supports_check_mode=True
    )
    if not HAS_PYCSCO:
        module.fail_json(msg='pycsco is required for this module')

    auth = Auth(vendor='cisco', model='nexus')
    username = module.params['username'] or auth.username
    password = module.params['password'] or auth.password
    protocol = module.params['protocol']
    host = socket.gethostbyname(module.params['host'])
    port = module.params['port']

    version = module.params['version']

    device = Device(ip=host, username=username, password=password,
                    protocol=protocol, port=port)

    vtp_enabled = get_vtp_state(device, module)
    if vtp_enabled is False:
        module.fail_json(msg='vtp feature not enabled on device')

    existing = get_vtp_config(device, module)
    end_state = existing

    args = dict(version=version)

    changed = False
    proposed = dict((k, v) for k, v in args.iteritems() if v is not None)
    delta = dict(set(proposed.iteritems()).difference(existing.iteritems()))

    commands = []
    if delta:
        commands.append(['vtp version {0}'.format(version)])

    cmds = nested_command_list_to_string(commands)
    if cmds:
        if module.check_mode:
            module.exit_json(changed=True, commands=cmds)
        else:
            changed = True
            device.config(cmds)
            end_state = get_vtp_config(device, module)

    results = {}
    results['proposed'] = proposed
    results['existing'] = existing
    results['end_state'] = end_state
    results['commands'] = cmds
    results['changed'] = changed

    module.exit_json(**results)


from ansible.module_utils.basic import *
if __name__ == '__main__':
    main()
