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

module: nxos_ntp_options
short_description: Manages NTP options
description:
    - Manages NTP options, e.g. authoritative server and logging
author: Michael Ben-Ami
requirements:
    - NX-API 1.0
    - NX-OS 6.1(2)I3(1)
    - pycsco
notes:
    - At least one of "master" or "logging" params must be supplied.
    - If the stratum parameter is supplied, then the "master" param must also
      be supplied.
    - When state=absent, boolean parameters are flipped,
      e.g. master=true will disable the authoritative server.
    - When state=absent and master=true, the stratum will be removed as well.
    - When state=absent and master=false, the stratum will be configured
      to its default value, 8.
    - While username and password are not required params, they are
      if you are not using the .netauth file.  .netauth file is recommended
      as it will clean up the each task in the playbook by not requiring
      the username and password params for every tasks.
    - Using the username and password params will override the .netauth file
options:
    master:
        description:
            - Sets whether the device is an authoritative NTP server
        required: false
        default: null
        choices: booleans
        aliases: []
    stratrum:
        description:
            - If master=true, an optional stratum can be supplied (1-15).
              The device default is 8.
        required: false
        default: null
        choices: []
        aliases: []
    logging:
        description:
            - Sets whether NTP logging is enabled on the device.
        required: false
        default: null
        choices: booleans
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
# Basic NTP options configuration
- nxos_ntp_options: master=true stratum=12 logging=false host={{ inventory_hostname }}
'''

RETURN = '''
proposed:
    description: k/v pairs of parameters passed into module
    returned: always
    type: dict
    sample: {"logging": false, "master": true, "stratum": "11"}
existing:
    description:
        - k/v pairs of existing ntp options
    type: dict
    sample: {"logging": true, "master": true, "stratum": "8"}
end_state:
    description: k/v pairs of ntp options after module execution
    returned: always
    type: dict
    sample: {"logging": false, "master": true, "stratum": "11"}
state:
    description: state as sent in from the playbook
    returned: always
    type: string
    sample: "present"
commands:
    description: command string sent to the device
    returned: always
    type: string
    sample: "no ntp logging ; ntp master 11 ;"
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


def get_ntp_master(device, module):
    command = 'show run | inc "ntp master"'
    master_string = parsed_data_from_device(device, command,
                                            module, text=True)

    master = True if master_string else False
    stratum = str(master_string.split()[2]) if master is True else None

    return master, stratum


def get_ntp_log(device, module):
    command = 'show ntp logging'
    body = parsed_data_from_device(device, command, module)

    logging_string = body['loggingstatus']
    ntp_log = True if 'enabled' in logging_string else False

    return ntp_log


def get_ntp_options(device, module):
    existing = {}
    existing['logging'] = get_ntp_log(device, module)
    existing['master'], existing['stratum'] = get_ntp_master(device, module)

    return existing


def config_ntp_options(delta, flip=False):
    master = delta.get('master')
    stratum = delta.get('stratum')
    log = delta.get('logging')
    ntp_cmds = []

    if flip:
        log = not log
        master = not master

    if log is not None:
        if log is True:
            ntp_cmds.append('ntp logging')
        elif log is False:
            ntp_cmds.append('no ntp logging')
    if master is not None:
        if master is True:
            if not stratum:
                stratum = ''
            ntp_cmds.append('ntp master {0}'.format(stratum))
        elif master is False:
            ntp_cmds.append('no ntp master')

    return ntp_cmds


def main():
    module = AnsibleModule(
        argument_spec=dict(
            master=dict(choices=BOOLEANS, type='bool'),
            stratum=dict(type='str'),
            logging=dict(choices=BOOLEANS, type='bool'),
            state=dict(choices=['absent', 'present'], default='present'),
            port=dict(required=False, type='int', default=None),
            host=dict(required=True),
            username=dict(),
            password=dict(),
            protocol=dict(choices=['http', 'https'], default='http')
        ),
        required_one_of=[['master', 'logging']],
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

    master = module.params['master']
    stratum = module.params['stratum']
    logging = module.params['logging']
    state = module.params['state']

    device = Device(ip=host, username=username, password=password,
                    protocol=protocol, port=port)

    if stratum:
        if master is None:
            module.fail_json(msg='The master param must be supplied when '
                                 'stratum is supplied')
        try:
            stratum_int = int(stratum)
            if stratum_int < 1 or stratum_int > 15:
                raise ValueError
        except ValueError:
            module.fail_json(msg='Stratum must be an integer between 1 and 15')

    existing = get_ntp_options(device, module)
    end_state = existing

    args = dict(master=master, stratum=stratum, logging=logging)

    changed = False
    proposed = dict((k, v) for k, v in args.iteritems() if v is not None)

    if master is False:
        proposed['stratum'] = None
        stratum = None

    delta = dict(set(proposed.iteritems()).difference(existing.iteritems()))
    delta_stratum = delta.get('stratum')

    if delta_stratum:
        delta['master'] = True

    commands = []
    if state == 'present':
        if delta:
            command = config_ntp_options(delta)
            if command:
                commands.append(command)
    elif state == 'absent':
        if existing:
            isection = dict(set(proposed.iteritems()).intersection(
                existing.iteritems()))
            command = config_ntp_options(isection, flip=True)
            if command:
                commands.append(command)

    cmds = nested_command_list_to_string(commands)
    if cmds:
        if module.check_mode:
            module.exit_json(changed=True, commands=cmds)
        else:
            changed = True
            device.config(cmds)
            end_state = get_ntp_options(device, module)

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
