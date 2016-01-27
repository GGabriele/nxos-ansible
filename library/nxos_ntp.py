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

module: nxos_ntp
short_description: Manages core NTP configuration
description:
    - Manages core NTP configuration
author: Michael Ben-Ami
requirements:
    - NX-API 1.0
    - NX-OS 6.1(2)I3(1)
    - pycsco
notes:
    - At most one of server or peer parameters may be given.
    - At most one of source_addr and source_int parameters may be given.
    - When state=absent, a given NTP server or peer will be removed,
      regardless of other supplied parameters.
    - While username and password are not required params, they are
      if you are not using the .netauth file.  .netauth file is recommended
      as it will clean up the each task in the playbook by not requiring
      the username and password params for every tasks.
    - Using the username and password params will override the .netauth file
options:
    server:
        description:
            - Network address of NTP server
        required: false
        default: null
        choices: []
        aliases: []
    peer:
        description:
            - Network address of NTP peer
        required: false
        default: null
        choices: []
        aliases: []
    key_id:
        description:
            - Authentication key identifier to use with
              given NTP server or peer
        required: false
        default: null
        choices: []
        aliases: []
    prefer:
        description:
            - Makes given NTP server or peer the preferred
              NTP server or peer for the device
        required: false
        default: null
        choices: ['enabled', 'disabled']
        aliases: []
    vrf_name:
        description:
            - Makes the device communicate with the given
              NTP server or peer over a specific VRF
        required: false
        default: null
        choices: []
        aliases: []
    source_addr:
        description:
            - Local source address from which NTP messages are sent
        required: false
        default: null
        choices: []
        aliases: []
    source_int:
        description:
            - Local source interface from which NTP messages are sent.
              Must be fully qualified interface name.
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
# Set NTP Server with parameters
- nxos_ntp: server=1.2.3.4 key_id=32 prefer=enabled host={{ inventory_hostname }}
'''

RETURN = '''
proposed:
    description: k/v pairs of parameters passed into module
    returned: always
    type: dict
    sample: {"address": "2.2.2.2", "key_id": "48",
            "peer_type": "server", "prefer": "enabled",
            "source": "3.3.3.3", "source_type": "source"}
existing:
    description:
        - k/v pairs of existing ntp server/peer
    type: dict
    sample: {"address": "2.2.2.2", "key_id": "32",
            "peer_type": "server", "prefer": "enabled",
            "source": "ethernet2/1", "source_type": "source-interface"}
end_state:
    description: k/v pairs of ntp info after module execution
    returned: always
    type: dict
    sample: {"address": "2.2.2.2", "key_id": "48",
            "peer_type": "server", "prefer": "enabled",
            "source": "3.3.3.3", "source_type": "source"}
state:
    description: state as sent in from the playbook
    returned: always
    type: string
    sample: "present"
commands:
    description: command string sent to the device
    returned: always
    type: string
    sample: "ntp server 2.2.2.2 prefer key 48 ;
            no ntp source-interface ethernet2/1 ; ntp source 3.3.3.3 ;"
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


def get_ntp_source(device, module):
    source_type = None
    source = None
    command = 'show run | inc "ntp source"'
    output = parsed_data_from_device(device, command, module, text=True)

    if output:
        if 'interface' in output:
            source_type = 'source-interface'
        else:
            source_type = 'source'
        source = output.split()[2].lower()

    return source_type, source


def get_ntp_peer(device, module):
    command = 'show run | inc "ntp (server|peer)"'
    ntp_peer_list = []
    ntp = parsed_data_from_device(device, command, module, text=True)

    ntp_regex = (
                ".*ntp\s(server\s(?P<address>\S+)|peer\s(?P<peer_address>\S+))"
                "\s*((?P<prefer>prefer)\s*)?(use-vrf\s(?P<vrf_name>\S+)\s*)?"
                "(key\s(?P<key_id>\d+))?.*"
                )

    splitted_ntp = ntp.split('\n')
    for peer_line in splitted_ntp:
        ntp_peer = {}
        try:
            peer_address = None
            vrf_name = None
            prefer = None
            key_id = None
            match_ntp = re.match(ntp_regex, peer_line, re.DOTALL)
            group_ntp = match_ntp.groupdict()

            address = group_ntp["address"]
            peer_address = group_ntp['peer_address']
            prefer = group_ntp['prefer']
            vrf_name = group_ntp['vrf_name']
            key_id = group_ntp['key_id']

            if address is not None:
                peer_type = 'server'
            elif peer_address is not None:
                peer_type = 'peer'
                address = peer_address

            args = dict(peer_type=peer_type, address=address, prefer=prefer,
                        vrf_name=vrf_name, key_id=key_id)

            ntp_peer = dict((k, v) for k, v in args.iteritems() if v is not None)
            ntp_peer_list.append(ntp_peer)
        except AttributeError:
            ntp_peer_list = []

    for peer in ntp_peer_list:
        try:
            if peer['prefer']:
                peer['prefer'] = 'enabled'
        except:
            peer['prefer'] = 'disabled'

    return ntp_peer_list


def get_ntp_existing(device, address, peer_type, module):
    peer_dict = {}

    peer_list = get_ntp_peer(device, module)
    for peer in peer_list:
        if peer['address'] == address:
            peer_dict.update(peer)

    source_type, source = get_ntp_source(device, module)

    if (source_type is not None and source is not None):
        peer_dict['source_type'] = source_type
        peer_dict['source'] = source

    return peer_dict


def set_ntp_server_peer(peer_type, address, prefer, key_id, vrf_name):
    command_strings = []

    if prefer:
        command_strings.append(' prefer')
    if key_id:
        command_strings.append(' key {0}'.format(key_id))
    if vrf_name:
        command_strings.append(' use-vrf {0}'.format(vrf_name))

    command_strings.insert(0, 'ntp {0} {1}'.format(peer_type, address))

    command = ''.join(command_strings)

    return command


def config_ntp(delta, existing):
    address = delta.get('address', existing.get('address'))
    peer_type = delta.get('peer_type', existing.get('peer_type'))
    vrf_name = delta.get('vrf_name', existing.get('vrf_name'))
    key_id = delta.get('key_id', existing.get('key_id'))
    prefer = delta.get('prefer', existing.get('prefer'))

    source_type = delta.get('source_type')
    source = delta.get('source')

    if prefer:
        if prefer == 'enabled':
            prefer = True
        elif prefer == 'disabled':
            prefer = False

    if source:
        source_type = delta.get('source_type', existing.get('source_type'))

    ntp_cmds = []
    if peer_type:
        ntp_cmds.append(set_ntp_server_peer(
            peer_type, address, prefer, key_id, vrf_name))
    if source:
        existing_source_type = existing.get('source_type')
        existing_source = existing.get('source')
        if existing_source_type and source_type != existing_source_type:
            ntp_cmds.append('no ntp {0} {1}'.format(existing_source_type, existing_source))
        ntp_cmds.append('ntp {0} {1}'.format(source_type, source))

    return ntp_cmds


def main():
    module = AnsibleModule(
        argument_spec=dict(
            server=dict(type='str'),
            peer=dict(type='str'),
            key_id=dict(type='str'),
            prefer=dict(type='str', choices=['enabled', 'disabled']),
            vrf_name=dict(type='str'),
            source_addr=dict(type='str'),
            source_int=dict(type='str'),
            state=dict(choices=['absent', 'present'], default='present'),
            port=dict(required=False, type='int', default=None),
            host=dict(required=True),
            username=dict(),
            password=dict(),
            protocol=dict(choices=['http', 'https'], default='http')
        ),
        mutually_exclusive=[['server', 'peer'], ['source_addr', 'source_int']],
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

    server = module.params['server'] or None
    peer = module.params['peer'] or None
    key_id = module.params['key_id']
    prefer = module.params['prefer']
    vrf_name = module.params['vrf_name']
    source_addr = module.params['source_addr']
    source_int = module.params['source_int']
    state = module.params['state']
    if source_int is not None:
        source_int = source_int.lower()

    if server:
        peer_type = 'server'
        address = server
    elif peer:
        peer_type = 'peer'
        address = peer
    else:
        peer_type = None
        address = None

    source_type = None
    source = None
    if source_addr:
        source_type = 'source'
        source = source_addr
    elif source_int:
        source_type = 'source-interface'
        source = source_int

    device = Device(ip=host, username=username, password=password,
                    protocol=protocol, port=port)

    if key_id or vrf_name or prefer:
        if not server and not peer:
            module.fail_json(
                msg='Please supply the server or peer parameter')

    args = dict(peer_type=peer_type, address=address, key_id=key_id,
                prefer=prefer, vrf_name=vrf_name, source_type=source_type,
                source=source)

    proposed = dict((k, v) for k, v in args.iteritems() if v is not None)

    existing = get_ntp_existing(device, address, peer_type, module)
    end_state = existing
    changed = False
    commands = []

    if state == 'present':
        delta = dict(set(proposed.iteritems()).difference(
            existing.iteritems()))
        if delta:
            command = config_ntp(delta, existing)
            if command:
                commands.append(command)

    elif state == 'absent':
        if existing.get('peer_type') and existing.get('address'):
            command = 'no ntp {0} {1}'.format(
                existing['peer_type'], existing['address'])
            if command:
                commands.append([command])

        existing_source_type = existing.get('source_type')
        existing_source = existing.get('source')
        proposed_source_type = proposed.get('source_type')
        proposed_source = proposed.get('source')

        if proposed_source_type:
            if proposed_source_type == existing_source_type:
                if proposed_source == existing_source:
                    command = 'no ntp {0} {1}'.format(
                                existing_source_type, existing_source)
                    if command:
                        commands.append([command])

    cmds = nested_command_list_to_string(commands)
    if cmds:
        if module.check_mode:
            module.exit_json(changed=True, commands=cmds)
        else:
            changed = True
            device.config(cmds)
            end_state = get_ntp_existing(device, address, peer_type, module)

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
