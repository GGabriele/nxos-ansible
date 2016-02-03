#!/usr/bin/python

# Copyright 2015 Michael Ben-Ami <michael@networktocode.com>
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

module: nxos_aaa_server
short_description: Manages AAA server global configuration
description:
    - Manages AAA server global configuration
author: Michael Ben-Ami
requirements:
    - NX-API 1.0
    - NX-OS 6.1(2)I3(1)
    - pycsco
notes:
    - The server_type parameter is always required.
    - If encrypt_type is not supplied, the global AAA server key will be
      stored as encrypted (type 7).
    - Changes to the global AAA server key with encrypt_type=0
      are not idempotent.
    - If global AAA server key is not found, it's shown as "unknown"
    - state=default will set the supplied parameters to their default values.
      The parameters that you want to default must also be set to default.
      If global_key=default, the global key will be removed.
    - While username and password are not required params, they are
      if you are not using the .netauth file.  .netauth file is recommended
      as it will clean up the each task in the playbook by not requiring
      the username and password params for every tasks.
    - Using the username and password params will override the .netauth file
options:
    server_type:
        description:
            - The server type is either radius or tacacs
        required: true
        default: null
        choices: ['radius', 'tacacs']
        aliases: []
    global_key:
        description:
            - Global AAA shared secret
        required: false
        default: null
        choices: []
        aliases: []
    encrypt_type:
        description:
            - The state of encryption applied to the entered global key.
              O clear text
              7 encrypted
              Type-6 encryption is not supported.
        required: false
        default: null
        choices: ['0', '7']
        aliases: []
    deadtime:
        description:
            - Duration for which a non-reachable AAA server is skipped,
              in minutes
              Range = 1-1440
              Device default = 0
        required: false
        default: null
        choices: []
        aliases: []
    timeout:
        description:
            - Global AAA server timeout period, in seconds
              Range = 1-60
              Device default = 5
        required: false
        default: null
        choices: []
        aliases: []
    directed_request:
        description:
            - Enables direct authentication requests to AAA server
            - Device default = disabled
        required: false
        default: null
        choices: ['enabled', 'disabled']
        aliases: []
    state:
        description:
            - Manage the state of the resource
        required: true
        default: present
        choices: ['present','default']
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
# Radius Server Basic settings
  - name: "Radius Server Basic settings"
    nxos_aaa_server: server_type=radius timeout=9 deadtime=20 directed_request=enabled host={{ inventory_hostname }}

# Tacacs Server Basic settings
  - name: "Tacacs Server Basic settings"
    nxos_aaa_server: server_type=tacacs timeout=8 deadtime=19 directed_request=disabled host={{ inventory_hostname }}

# Setting Global Key
  - name: "AAA Server Global Key"
    nxos_aaa_server: server_type=radius global_key=test-key host={{ inventory_hostname }}
'''

RETURN = '''
proposed:
    description: k/v pairs of parameters passed into module
    returned: always
    type: dict
    sample: {"deadtime": "22", "directed_request": "enabled",
            "server_type": "radius", "timeout": "11"}
existing:
    description:
        - k/v pairs of existing aaa server
    type: dict
    sample: {"deadtime": "0", "directed_request": "disabled",
            "global_key": "unknown", "timeout": "5"}
end_state:
    description: k/v pairs of aaa params after module execution
    returned: always
    type: dict
    sample: {"deadtime": "22", "directed_request": "enabled",
            "global_key": "unknown", "timeout": "11"}
state:
    description: state as sent in from the playbook
    returned: always
    type: string
    sample: "present"
commands:
    description: command string sent to the device
    returned: always
    type: string
    sample: "radius-server deadtime 22 ; radius-server timeout 11 ;
            radius-server directed-request ;"
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


def get_aaa_server_info(device, server_type, module):
    aaa_server_info = {}
    server_command = 'show {0}-server'.format(server_type)
    request_command = 'show {0}-server directed-request'.format(server_type)
    global_key_command = 'show run | sec {0}'.format(server_type)
    aaa_regex = '.*{0}-server\skey\s\d\s+(?P<key>\S+).*'.format(server_type)

    server_body = parsed_data_from_device(device, server_command,
                                          module, text=True)

    splitted_server = server_body.split('\n')

    for line in splitted_server:
        if line.startswith('timeout'):
            aaa_server_info['timeout'] = line.split(':')[1]

        elif line.startswith('deadtime'):
            aaa_server_info['deadtime'] = line.split(':')[1]

    request_body = parsed_data_from_device(device, request_command,
                                           module, text=True)
    aaa_server_info['directed_request'] = request_body

    key_body = parsed_data_from_device(device, global_key_command,
                                       module, text=True)

    try:
        match_global_key = re.match(aaa_regex, key_body, re.DOTALL)
        group_key = match_global_key.groupdict()
        aaa_server_info['global_key'] = group_key["key"]
    except (AttributeError, TypeError):
        aaa_server_info['global_key'] = 'unknown'

    return aaa_server_info


def set_aaa_server_global_key(encrypt_type, key, server_type):
    if not encrypt_type:
        encrypt_type = ''
    return '{0}-server key {1} {2}'.format(
        server_type, encrypt_type, key)


def config_aaa_server(params, server_type):
    cmds = []

    deadtime = params.get('deadtime')
    timeout = params.get('timeout')
    directed_request = params.get('directed_request')
    encrypt_type = params.get('encrypt_type', '7')
    global_key = params.get('global_key')

    if deadtime is not None:
        cmds.append('{0}-server deadtime {1}'.format(server_type, deadtime))

    if timeout is not None:
        cmds.append('{0}-server timeout {1}'.format(server_type, timeout))

    if directed_request is not None:
        if directed_request == 'enabled':
            cmds.append('{0}-server directed-request'.format(server_type))
        elif directed_request == 'disabled':
            cmds.append('no {0}-server directed-request'.format(server_type))

    if global_key is not None:
        cmds.append('{0}-server key {1} {2}'.format(server_type, encrypt_type,
                                                    global_key))

    return cmds


def default_aaa_server(params, server_type):
    cmds = []

    deadtime = params.get('deadtime')
    timeout = params.get('timeout')
    directed_request = params.get('directed_request')
    global_key = params.get('global_key')

    if deadtime is not None:
        cmds.append('no {0}-server deadtime 1'.format(server_type))

    if timeout is not None:
        cmds.append('no {0}-server timeout 1'.format(server_type))

    if directed_request is not None:
        cmds.append('no {0}-server directed-request'.format(server_type))

    if global_key is not None:
        cmds.append('no {0}-server key'.format(server_type))

    return cmds


def main():
    module = AnsibleModule(
        argument_spec=dict(
            server_type=dict(type='str',
                             choices=['radius', 'tacacs'], required=True),
            global_key=dict(type='str'),
            encrypt_type=dict(type='str', choices=['0', '7']),
            deadtime=dict(type='str'),
            timeout=dict(type='str'),
            directed_request=dict(type='str',
                                  choices=['enabled', 'disabled', 'default']),
            state=dict(choices=['default', 'present'], default='present'),
            port=dict(required=False, type='int', default=None),
            host=dict(required=True),
            username=dict(),
            password=dict(),
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
    port = module.params['port']
    host = socket.gethostbyname(module.params['host'])

    server_type = module.params['server_type']
    global_key = module.params['global_key']
    encrypt_type = module.params['encrypt_type']
    deadtime = module.params['deadtime']
    timeout = module.params['timeout']
    directed_request = module.params['directed_request']
    state = module.params['state']

    device = Device(ip=host, username=username, password=password,
                    protocol=protocol, port=port)

    if encrypt_type and not global_key:
        module.fail_json(msg='encrypt_type must be used with global_key')

    args = dict(server_type=server_type, global_key=global_key,
                encrypt_type=encrypt_type, deadtime=deadtime,
                timeout=timeout, directed_request=directed_request)

    changed = False
    proposed = dict((k, v) for k, v in args.iteritems() if v is not None)

    existing = get_aaa_server_info(device, server_type, module)
    end_state = existing

    commands = []
    if state == 'present':
        if deadtime:
            try:
                if int(deadtime) < 0 or int(deadtime) > 1440:
                    raise ValueError
            except ValueError:
                module.fail_json(
                        msg='deadtime must be an integer between 0 and 1440')

        if timeout:
            try:
                if int(timeout) < 1 or int(timeout) > 60:
                    raise ValueError
            except ValueError:
                module.fail_json(
                    msg='timeout must be an integer between 1 and 60')

        delta = dict(set(proposed.iteritems()).difference(
                                                    existing.iteritems()))
        if delta:
            command = config_aaa_server(delta, server_type)
            if command:
                commands.append(command)

    elif state == 'default':
        for key, value in proposed.iteritems():
            if key != 'server_type' and value != 'default':
                module.fail_json(
                    msg='Parameters must be set to "default"'
                        'when state=default')
        command = default_aaa_server(proposed, server_type)
        if command:
            commands.append(command)

    cmds = nested_command_list_to_string(commands)
    if cmds:
        if module.check_mode:
            module.exit_json(changed=True, commands=cmds)
        else:
            changed = True
            device.config(cmds)
            end_state = get_aaa_server_info(device, server_type, module)

    results = {}
    results['proposed'] = proposed
    results['existing'] = existing
    results['state'] = module.params['state']
    results['commands'] = cmds
    results['changed'] = changed
    results['end_state'] = end_state

    module.exit_json(**results)


from ansible.module_utils.basic import *
if __name__ == '__main__':
    main()
