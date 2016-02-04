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

module: nxos_aaa_server_host
short_description: Manages AAA server host-specific configuration
description:
    - Manages AAA server host-specific configuration
author: Michael Ben-Ami
requirements:
    - NX-API 1.0
    - NX-OS 6.1(2)I3(1)
    - pycsco
notes:
    - The server_type parameter is always required.
    - To preserve idempotency, only encrypt_type=7 is supported in this module
    - state=absent removes supplied params, if already existing on the device 
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
    address:
        description:
            - Address or name of the radius or tacacs host
        required: true
        default: null
        choices: []
        aliases: []
    key:
        description:
            - shared secret for the specified host
        required: false
        default: null
        choices: []
        aliases: []
    encrypt_type:
        description:
            - The state of encryption applied to the entered key.
              The only supported type is "7"
        required: false
        default: null
        choices: []
        aliases: []
    timeout:
        description:
            - Timeout period for specified host, in seconds
              Range=1-60
              Device default=global AAA timeout period
        required: false
        default: null
        choices: []
        aliases: []
    auth_port:
        description:
            - Alternate UDP port for RADIUS authentication
        required: false
        default: null
        choices: []
        aliases: []
    acct_port:
        description:
            - Alternate UDP port for RADIUS accounting
        required: false
        default: null
        choices: []
        aliases: []
    tacacs_port:
        description:
            - Alternate TCP port TACACS Server
        required: false
        default: null
        choices: []
        aliases: []
    state:
        description:
            - Manage the state of the resource
        required: true
        default: present
        choices: ['present','absent']
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
# Radius Server Host Basic settings
  - name: "Radius Server Host Basic settings"
    nxos_aaa_server_host: state=present server_type=radius address=1.2.3.4 acct_port=2084 timeout=10 host={{ inventory_hostname }}

# Radius Server Host Key Configuration
  - name: "Radius Server Host Key Configuration"
    nxos_aaa_server_host: state=present server_type=radius address=1.2.3.4 key=hello encrypt_type=7 host={{ inventory_hostname }}

# TACACS Server Host Configuration
  - name: "Tacacs Server Host Configuration"
    nxos_aaa_server_host: state=present server_type=tacacs tacacs_port=89 timeout=10 address=5.6.7.8 host={{ inventory_hostname }}
'''

RETURN = '''
proposed:
    description: k/v pairs of parameters passed into module
    returned: always
    type: dict
    sample: {"tacacs_port": "89", "timeout": "10"}
existing:
    description:
        - k/v pairs of existing aaa host configuration
    type: dict
    sample: {"acct_port": null, "auth_port": null,
            "key": null, "port": null, "timeout": null}
end_state:
    description: k/v pairs of aaa host configuration after module execution
    returned: always
    type: dict
    sample: {"acct_port": null, "auth_port": null, "key": null,
            "port": "89", "timeout": "10"}
state:
    description: state as sent in from the playbook
    returned: always
    type: string
    sample: "present"
commands:
    description: command string sent to the device
    returned: always
    type: string
    sample: "tacacs-server host 5.6.7.8 port 89 timeout 10 ;"
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


def get_aaa_host_info(device, server_type, address, module):
    command = 'sh run | inc "{0}-server host {1}"'.format(
                                                server_type, address)
    aaa_host_info = {}

    aaa_regex = (
                '.*-server\shost\s+\S+(\s+key\s+7\s+"?(?P<key>\S+)"?)?'
                '(\s+port\s+(?P<port>\d+))?(\s+auth-port\s(?P<auth_port>\d+))?'
                '(\s+acct-port\s(?P<acct_port>\d+))?(.*timeout\s+'
                '(?P<timeout>\d+))?.*'
                )

    response = parsed_data_from_device(device, command, module, text=True)

    if response:
        try:
            match_aaa = re.match(aaa_regex, response, re.DOTALL)
            group_aaa = match_aaa.groupdict()

            aaa_host_info['key'] = group_aaa["key"]
            aaa_host_info['auth_port'] = group_aaa['auth_port']
            aaa_host_info['acct_port'] = group_aaa['acct_port']
            aaa_host_info['timeout'] = group_aaa['timeout']
            aaa_host_info['port'] = group_aaa['port']
        except (AttributeError, KeyError):
            aaa_host_info = {}

    return aaa_host_info


def config_aaa_host(server_type, address, params, clear=False):
    cmds = []
    cmd_strings = []

    if clear:
        cmds.append('no {0}-server host {1}'.format(server_type, address))

    cmd_strings.append('{0}-server host {1}'.format(server_type, address))

    key = params.get('key')
    timeout = params.get('timeout')
    auth_port = params.get('auth_port')
    acct_port = params.get('acct_port')
    port = params.get('tacacs_port')

    if auth_port:
        cmd_strings.append(' auth-port {0}'.format(auth_port))
    if acct_port:
        cmd_strings.append(' acct-port {0}'.format(acct_port))
    if port:
        cmd_strings.append(' port {0}'.format(port))
    if timeout:
        cmd_strings.append(' timeout {0}'.format(timeout))
    if key:
        cmds.append('{0}-server host {1} key 7 {2}'.format(
                                    server_type, address, key))

    cmds.append(''.join(cmd_strings))

    return cmds


def main():
    module = AnsibleModule(
        argument_spec=dict(
            server_type=dict(type='str',
                             choices=['radius', 'tacacs'], required=True),
            address=dict(type='str', required=True),
            key=dict(type='str'),
            encrypt_type=dict(type='str'),
            timeout=dict(type='str'),
            auth_port=dict(type='str'),
            acct_port=dict(type='str'),
            tacacs_port=dict(type='str'),
            state=dict(choices=['absent', 'present'], default='present'),
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
    address = module.params['address']
    key = module.params['key']
    encrypt_type = module.params['encrypt_type']
    timeout = module.params['timeout']
    auth_port = module.params['auth_port']
    acct_port = module.params['acct_port']
    tacacs_port = module.params['tacacs_port']
    state = module.params['state']

    device = Device(ip=host, username=username, password=password,
                    protocol=protocol, port=port)

    if encrypt_type and not key:
        module.fail_json(msg='encrypt_type must be used with key')

    if encrypt_type:
        if encrypt_type != '7':
            module.fail_json(msg='this module supports only encryption '
                                 'type 7.')

    if tacacs_port and server_type != 'tacacs':
        module.fail_json(
            msg='tacacs_port can only be used with server_type=tacacs')

    if (auth_port or acct_port) and server_type != 'radius':
        module.fail_json(
            msg='auth_port and acct_port can only be used '
                'when server_type=radius')

    if timeout:
        try:
            if int(timeout) < 1 or int(timeout) > 60:
                raise ValueError
        except ValueError:
            module.fail_json(msg='timeout must be an integer between 1 and 60')

    args = dict(key=key, timeout=timeout, auth_port=auth_port,
                acct_port=acct_port, tacacs_port=tacacs_port)

    changed = False
    proposed = dict((k, v) for k, v in args.iteritems() if v is not None)

    commands = []

    existing = get_aaa_host_info(device, server_type, address, module)
    end_state = existing

    if state == 'present':
        delta = dict(set(proposed.iteritems()).difference(
                                                existing.iteritems()))
        if delta:
            union = existing.copy()
            union.update(delta)
            command = config_aaa_host(server_type, address, union)
            if command:
                commands.append(command)

    elif state == 'absent':
        intersect = dict(set(proposed.iteritems()).intersection(
                                                existing.iteritems()))
        if intersect:
            remainder = dict(set(existing.iteritems()).difference(
                                                intersect.iteritems()))
            command = config_aaa_host(server_type, address, remainder, True)
            if command:
                commands.append(command)

    cmds = nested_command_list_to_string(commands)
    if cmds:
        if module.check_mode:
            module.exit_json(changed=True, commands=cmds)
        else:
            changed = True
            device.config(cmds)
            end_state = get_aaa_host_info(device, server_type, address, module)
            if dict(set(proposed.iteritems()).difference(existing.iteritems())):
                changed = True

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
