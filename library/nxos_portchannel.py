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

module: nxos_portchannel
short_description: Manages port-channel interfaces
description:
    - Manages port-channel specific configuration parameters
author: Jason Edelman (@jedelman8)
requirements:
    - NX-API 1.0
    - NX-OS 6.1(2)I3(1)
    - pycsco
notes:
    - Absent removes the portchannel config and interface if it
      already exists. If members to be removed are not explicitly
      passed, all existing members (if any), are removed.
    - Members must be a list
    - LACP needs to be enabled first if active/passive modes are used
    - While username and password are not required params, they are
      if you are not using the .netauth file.  .netauth file is recommended
      as it will clean up the each task in the playbook by not requiring
      the username and password params for every tasks.
    - Using the username and password params will override the .netauth file
options:
    group:
        description:
            - channel-group number for the port-channel
        required: true
        default: null
        choices: []
        aliases: []
    mode:
        description:
            - Mode for the port-channel, i.e. on, active, passive
        required: false
        default: on
        choices: ['active','passive','on']
        aliases: []
    min_links:
        description:
            - min links required to keep portchannel up
        required: false
        default: null
        choices: []
        aliases: []
    members:
        description:
            - List of interfaces that will be managed in a given portchannel
        required: false
        default: null
        choices: []
        aliases: []
    state:
        description:
            - Manage the state of the resource
        required: true
        default: null
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
# Ensure port-channel 99 doesn't exist on the switch
- nxos_portchannel: group=99 host={{ inventory_hostname }} state=absent

# Ensure port-channel99 is created, add two members, and set to mode on
- nxos_portchannel:
    group: 99
    members: ['Ethernet1/1','Ethernet1/2']
    mode: 'active'
    host: "{{ inventory_hostname }}"
    state: present

'''

RETURN = '''
proposed:
    description: k/v pairs of parameters passed into module
    returned: always
    type: dict
    sample: {"group": "12", "members": ["Ethernet2/5",
            "Ethernet2/6"], "mode": "on"}
existing:
    description:
        - k/v pairs of existing portchannel
    type: dict
    sample: {"group": "12", "members": ["Ethernet2/5",
            "Ethernet2/6"], "members_detail": {
            "Ethernet2/5": {"mode": "active", "status": "D"},
            "Ethernet2/6": {"mode": "active", "status": "D"}},
            "min_links": null, "mode": "active"}
end_state:
    description: k/v pairs of portchannel info after module execution
    returned: always
    type: dict
    sample: {"group": "12", "members": ["Ethernet2/5",
            "Ethernet2/6"], "members_detail": {
            "Ethernet2/5": {"mode": "on", "status": "D"},
            "Ethernet2/6": {"mode": "on", "status": "D"}},
            "min_links": null, "mode": "on"}
state:
    description: state as sent in from the playbook
    returned: always
    type: string
    sample: "present"
commands:
    description: command string sent to the device
    returned: always
    type: string
    sample: "interface Ethernet2/6 ; no channel-group 12 ;
            interface Ethernet2/5 ; no channel-group 12 ;
            interface Ethernet2/6 ; channel-group 12 mode on ;
            interface Ethernet2/5 ; channel-group 12 mode on ;"
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
        if 'show port-channel summary' in command:
            return {}
        else:
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


def get_lacp_state(device, module):
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

            if feature == 'lacp':
                if 'enabled' in state:
                    return True
                else:
                    return False
        return check


def get_portchannel_members(pchannel):
    try:
        members = pchannel['TABLE_member']['ROW_member']
    except KeyError:
        members = []

    return members


def get_portchannel_mode(device, interface, protocol, module):
    if protocol != 'LACP':
        mode = 'on'
    else:
        command = 'show run interface {0}'.format(interface)
        mode = 'Unknown'

        body = parsed_data_from_device(device, command, module, text=True)

        mode_list = body.split('\n')
        for line in mode_list:
            this_line = line.strip()
            if this_line.startswith('channel-group'):
                find = this_line
        if 'mode' in find:
            if 'passive' in find:
                mode = 'passive'
            elif 'active' in find:
                mode = 'active'
    return mode


def get_min_links(device, group, module):
    command = 'show run interface port-channel{0}'.format(group)
    minlinks = None
    body = parsed_data_from_device(device, command, module, text=True)
    ml_list = body.split('\n')
    for line in ml_list:
        this_line = line.strip()
        if 'min-links' in this_line:
            minlinks = str(this_line.split('min-links ')[-1])
    return minlinks


def get_portchannel(device, group, module):
    command = 'show port-channel summary\
                interface port-channel {0}'.format(group)
    portchannel = {}
    members = []

    body = parsed_data_from_device(device, command, module)

    try:
        portchannel_table = body['TABLE_channel']['ROW_channel']
        portchannel['group'] = portchannel_table['group']
        protocol = portchannel_table['prtcl']
        members_list = get_portchannel_members(portchannel_table)

        if isinstance(members_list, dict):
            members_list = [members_list]

        member_dictionary = {}
        for each_member in members_list:
            interface = each_member['port']
            members.append(interface)

            pc_member = {}
            pc_member['status'] = str(each_member['port-status'])
            pc_member['mode'] = get_portchannel_mode(device, interface,
                                                     protocol, module)

            member_dictionary[interface] = pc_member
            portchannel['members'] = members
            portchannel['members_detail'] = member_dictionary
            portchannel['min_links'] = get_min_links(device, group, module)

        # Ensure each member have the same mode.
        modes = set()
        for each, value in member_dictionary.iteritems():
            modes.update([value['mode']])
        if len(modes) == 1:
            portchannel['mode'] = value['mode']
        else:
            portchannel['mode'] = 'unknown'

    except (KeyError, AttributeError):
        portchannel = {}

    return portchannel


def get_portchannel_list(device, module):
    command = 'show port-channel summary'
    portchannels = []

    body = parsed_data_from_device(device, command, module)

    try:
        portchannel_table = body['TABLE_channel']['ROW_channel']

        if isinstance(portchannel_table, dict):
            portchannel_table = [portchannel_table]

        for each_portchannel in portchannel_table:
            portchannels.append(each_portchannel['group'])
    except (KeyError, AttributeError):
        return portchannels

    return portchannels


def config_portchannel(proposed, mode, group):
    commands = []
    config_args = {
        'mode': 'channel-group {group} mode {mode}',
        'min_links': 'lacp min-links {min_links}',
    }

    for member in proposed.get('members', []):
        commands.append('interface {0}'.format(member))
        commands.append(config_args.get('mode').format(group=group, mode=mode))

    min_links = proposed.get('min_links', None)
    if min_links:
        command = 'interface port-channel {0}'.format(group)
        commands.append(command)
        commands.append(config_args.get('min_links').format(
                                                    min_links=min_links))

    return commands


def get_commands_to_add_members(proposed, existing):
    try:
        proposed_members = proposed['members']
    except KeyError:
        proposed_members = []

    try:
        existing_members = existing['members']
    except KeyError:
        existing_members = []

    members_to_add = list(set(proposed_members).difference(existing_members))

    commands = []
    if members_to_add:
        for member in members_to_add:
            commands.append('interface {0}'.format(member))
            commands.append('channel-group {0} mode {1}'.format(
                existing['group'], proposed['mode']))

    return commands


def get_commands_to_remove_members(proposed, existing):
    try:
        proposed_members = proposed['members']
    except KeyError:
        proposed_members = []

    try:
        existing_members = existing['members']
    except KeyError:
        existing_members = []

    members_to_remove = list(set(existing_members).difference(proposed_members))

    commands = []
    if members_to_remove:
        for member in members_to_remove:
            commands.append('interface {0}'.format(member))
            commands.append('no channel-group {0}'.format(existing['group']))

    return commands


def get_commands_if_mode_change(proposed, existing, group, mode, module):
    try:
        proposed_members = proposed['members']
    except KeyError:
        proposed_members = []

    try:
        existing_members = existing['members']
    except KeyError:
        existing_members = []

    try:
        members_dict = existing['members_detail']
    except KeyError:
        members_dict = {}

    members_to_remove = set(existing_members).difference(proposed_members)
    members_with_mode_change = []
    if members_dict:
        for interface, values in members_dict.iteritems():
            if (interface in proposed_members and
                    (interface not in members_to_remove)):
                if values['mode'] != mode:
                    members_with_mode_change.append(interface)

    commands = []
    if members_with_mode_change:
        for member in members_with_mode_change:
            commands.append('interface {0}'.format(member))
            commands.append('no channel-group {0}'.format(group))

        for member in members_with_mode_change:
            commands.append('interface {0}'.format(member))
            commands.append('channel-group {0} mode {1}'.format(group, mode))

    return commands


def get_commands_min_links(existing, proposed, group, min_links, module):
    commands = []
    try:
        if (existing['min_links'] is None or
                (existing['min_links'] != proposed['min_links'])):
            commands.append('interface port-channel{0}'.format(group))
            commands.append('lacp min-link {0}'.format(min_links))
    except KeyError:
        commands.append('interface port-channel{0}'.format(group))
        commands.append('lacp min-link {0}'.format(min_links))
    return commands


def main():
    module = AnsibleModule(
        argument_spec=dict(
            group=dict(required=True, type='str'),
            mode=dict(choices=['on', 'active', 'passive'],
                      default='on',
                      type='str'),
            min_links=dict(default=None, type='str'),
            members=dict(default=None),
            state=dict(choices=['absent', 'present'],
                       default='present'),
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

    group = module.params['group']
    mode = module.params['mode']
    min_links = module.params['min_links']
    members = module.params['members']
    state = module.params['state']

    device = Device(ip=host, username=username, password=password,
                    protocol=protocol, port=port)

    if ((min_links or mode) and
            (not members and state == 'present')):
        module.fail_json(msg='"members" is required when state=present and '
                             '"min_links" or "mode" are provided')

    if mode in ['active', 'passive']:
        if not get_lacp_state(device, module):
            module.fail_json(msg='LACP feature needs to be enabled first')

    changed = False

    existing = get_portchannel(device, group, module)

    args = dict(group=group, mode=mode, min_links=min_links, members=members)
    proposed = dict((k, v) for k, v in args.iteritems() if v is not None)
    end_state = existing

    commands = []
    changed = False
    active_portchannels = get_portchannel_list(device, module)
    if state == 'absent':
        if existing:
            commands.append(['no interface port-channel{0}'.format(group)])
    elif state == 'present':
        if group not in active_portchannels:
            command = config_portchannel(proposed, mode, group)
            commands.append(command)

        elif existing and group in active_portchannels:
            command = get_commands_to_remove_members(proposed, existing)
            commands.append(command)

            command = get_commands_to_add_members(proposed, existing)
            commands.append(command)

            mode_command = get_commands_if_mode_change(proposed, existing,
                                                       group, mode, module)

            commands.insert(0, mode_command)

            if min_links:
                command = get_commands_min_links(existing, proposed,
                                                 group, min_links, module)
                commands.append(command)

    cmds = nested_command_list_to_string(commands)
    if cmds:
        if module.check_mode:
            module.exit_json(changed=True, commands=cmds)
        else:
            changed = True
            device.config(cmds)
            end_state = get_portchannel(device, group, module)

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
