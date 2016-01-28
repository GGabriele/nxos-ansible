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

module: nxos_ntp_auth
short_description: Manages NTP authentication
description:
    - Manages NTP authentication
author: Michael Ben-Ami
requirements:
    - NX-API 1.0
    - NX-OS 6.1(2)I3(1)
    - pycsco
notes:
    - If state=absent, the moudle will attempt to remove the given key configuration.
      If a matching key configuration isn't found on the device, the module will fail.
    - If state=absent and authentication=on, authentication will be turned off.
    - If state=absent and authentication=off, authentication will be turned on.
    - While username and password are not required params, they are
      if you are not using the .netauth file.  .netauth file is recommended
      as it will clean up the each task in the playbook by not requiring
      the username and password params for every tasks.
    - Using the username and password params will override the .netauth file
options:
    key_id:
        description:
            - Authentication key identifier (numeric)
        required: true
        default: null
        choices: []
        aliases: []
    md5string:
        description:
            - MD5 String
        required: true
        default: null
        choices: []
        aliases: []
    auth_type:
        description:
            - Whether the given md5string is in cleartext or
              has been encrypted. If in cleartext, the device
              will encrypt it before storing it.
        required: false
        default: 'text'
        choices: ['text', 'encrypt']
        aliases: []
    trusted_key:
        description:
            - Whether the given key is required to be supplied by a time source
              for the device to synchronize to the time source.
        required: false
        default: 'false'
        choices: ['true', 'false']
        aliases: []
    authentication:
        description:
            - Turns NTP authenication on or off.
        required: false
        default: null
        choices: ['on', 'off']
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
        choices: ['http','https']
        aliases: []
'''

EXAMPLES = '''
# Basic NTP authentication configuration
- nxos_ntp_auth: key_id=32 md5string=hello auth_type=text host={{ inventory_hostname }}
'''

RETURN = '''
proposed:
    description: k/v pairs of parameters passed into module
    returned: always
    type: dict
    sample: {"auth_type": "text", "authentication": "off",
            "key_id": "32", "md5string": "helloWorld",
            "trusted_key": "true"}
existing:
    description:
        - k/v pairs of existing ntp authentication
    type: dict
    sample: {"authentication": "off", "trusted_key": "false"}
end_state:
    description: k/v pairs of ntp autherntication after module execution
    returned: always
    type: dict
    sample: {"authentication": "off", "key_id": "32",
            "md5string": "kapqgWjwdg", "trusted_key": "true"}
state:
    description: state as sent in from the playbook
    returned: always
    type: string
    sample: "present"
commands:
    description: command string sent to the device
    returned: always
    type: string
    sample: "ntp authentication-key 32 md5 helloWorld 0 ; ntp trusted-key 32 ;"
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


def get_ntp_auth(device, module):
    command = 'show ntp authentication-status'

    body = parsed_data_from_device(device, command, module)
    ntp_auth_str = body['authentication']

    if 'enabled' in ntp_auth_str:
        ntp_auth = True
    else:
        ntp_auth = False

    return ntp_auth


def get_ntp_trusted_key(device, module):
    trusted_key_list = []
    command = 'show run | inc "ntp trusted-key"'

    trusted_key_str = parsed_data_from_device(device, command,
                                              module, text=True)
    if trusted_key_str:
        trusted_keys = trusted_key_str.split('\n')
    else:
        trusted_keys = []

    for line in trusted_keys:
        trusted_key_list.append(str(line.split()[2]))

    return trusted_key_list


def get_ntp_auth_key(device, key_id, module):
    authentication_key = {}
    command = 'show run | inc "ntp authentication-key {0}"'.format(key_id)
    auth_regex = (".*ntp\sauthentication-key\s(?P<key_id>\d+)\s"
                  "md5\s(?P<md5string>\S+).*")

    body = parsed_data_from_device(device, command, module, text=True)

    try:
        match_authentication = re.match(auth_regex, body, re.DOTALL)
        group_authentication = match_authentication.groupdict()
        key_id = group_authentication["key_id"]
        md5string = group_authentication['md5string']
        authentication_key['key_id'] = key_id
        authentication_key['md5string'] = md5string
    except (AttributeError, TypeError):
        authentication_key = {}

    return authentication_key


def get_ntp_auth_info(device, key_id, module):
    auth_info = get_ntp_auth_key(device, key_id, module)
    trusted_key_list = get_ntp_trusted_key(device, module)
    auth_power = get_ntp_auth(device, module)

    if key_id in trusted_key_list:
        auth_info['trusted_key'] = 'true'
    else:
        auth_info['trusted_key'] = 'false'

    if auth_power:
        auth_info['authentication'] = 'on'
    else:
        auth_info['authentication'] = 'off'

    return auth_info


def auth_type_to_num(auth_type):
    return '7' if auth_type == 'encrypt' else '0'


def set_ntp_auth_key(key_id, md5string, auth_type, trusted_key, authentication):
    ntp_auth_cmds = []
    auth_type_num = auth_type_to_num(auth_type)
    ntp_auth_cmds.append(
        'ntp authentication-key {0} md5 {1} {2}'.format(
            key_id, md5string, auth_type_num))

    if trusted_key == 'true':
        ntp_auth_cmds.append(
            'ntp trusted-key {0}'.format(key_id))
    elif trusted_key == 'false':
        ntp_auth_cmds.append(
            'no ntp trusted-key {0}'.format(key_id))

    if authentication == 'on':
        ntp_auth_cmds.append(
            'ntp authenticate')
    elif authentication == 'off':
        ntp_auth_cmds.append(
            'no ntp authenticate')

    return ntp_auth_cmds


def remove_ntp_auth_key(key_id, md5string, auth_type, trusted_key, authentication):
    auth_remove_cmds = []
    auth_type_num = auth_type_to_num(auth_type)
    auth_remove_cmds.append(
        'no ntp authentication-key {0} md5 {1} {2}'.format(
            key_id, md5string, auth_type_num))

    if authentication == 'on':
        auth_remove_cmds.append(
            'no ntp authenticate')
    elif authentication == 'off':
        auth_remove_cmds.append(
            'ntp authenticate')

    return auth_remove_cmds


def main():
    module = AnsibleModule(
        argument_spec=dict(
            key_id=dict(required=True, type='str'),
            md5string=dict(required=True, type='str'),
            auth_type=dict(choices=['text', 'encrypt'], default='text'),
            trusted_key=dict(choices=['true', 'false'], default='false'),
            authentication=dict(choices=['on', 'off']),
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
    host = socket.gethostbyname(module.params['host'])
    port = module.params['port']

    key_id = module.params['key_id']
    md5string = module.params['md5string']
    auth_type = module.params['auth_type']
    trusted_key = module.params['trusted_key']
    authentication = module.params['authentication']
    state = module.params['state']

    device = Device(ip=host, username=username, password=password,
                    protocol=protocol, port=port)

    args = dict(key_id=key_id, md5string=md5string,
                auth_type=auth_type, trusted_key=trusted_key,
                authentication=authentication)

    changed = False
    proposed = dict((k, v) for k, v in args.iteritems() if v is not None)

    existing = get_ntp_auth_info(device, key_id, module)
    end_state = existing

    delta = dict(set(proposed.iteritems()).difference(existing.iteritems()))

    commands = []
    if state == 'present':
        if delta:
            command = set_ntp_auth_key(
                key_id, md5string, auth_type, trusted_key, delta.get('authentication'))
            if command:
                commands.append(command)
    elif state == 'absent':
        if existing:
            auth_toggle = None
            if authentication == existing.get('authentication'):
                auth_toggle = authentication
            command = remove_ntp_auth_key(
                key_id, md5string, auth_type, trusted_key, auth_toggle)
            if command:
                commands.append(command)

    cmds = nested_command_list_to_string(commands)
    if cmds:
        if module.check_mode:
            module.exit_json(changed=True, commands=cmds)
        else:
            try:
                device.config(cmds)
            except CLIError as e:
                module.fail_json(msg=str(e) + ": " + cmds)
            end_state = get_ntp_auth_info(device, key_id, module)
            delta = dict(set(end_state.iteritems()).difference(existing.iteritems()))
            if delta or (len(existing) != len(end_state)):
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
