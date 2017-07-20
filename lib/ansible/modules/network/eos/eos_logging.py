#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2017, Ansible by Red Hat, inc
#
# This file is part of Ansible by Red Hat
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#

ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['preview'],
                    'supported_by': 'core'}

DOCUMENTATION = """
---
module: eos_logging
version_added: "2.4"
author: "Trishna Guha (@trishnag)"
short_description: Manage logging on network devices
description:
  - This module provides declarative management of logging
    on Arista Eos devices.
options:
  dest:
    description:
      - Destination of the logs.
    choices: ['on', 'host', console', 'monitor', 'buffered']
  name:
    description:
      - If value of C(dest) is I(host) C(name) should be specified,
        which indicates hostname or IP address.
  size:
    description:
      - Size of buffer. The acceptable value is in range from 10 to
        2147483647 bytes.
  facility:
    description:
      - Set logging facility.
  level:
    description:
      - Set logging severity levels.
    choices: ['emergencies', 'alerts', 'critical', 'errors',
              'warnings', 'notifications', 'informational', 'debugging']
  aggregate:
    description: List of logging definitions.
  purge:
    description:
      - Purge logging not defined in the aggregate parameter.
    default: no
  state:
    description:
      - State of the logging configuration.
    default: present
    choices: ['present', 'absent']
"""

EXAMPLES = """
- name: configure host logging
  eos_logging:
    dest: host
    name: 172.16.0.1
    state: present
- name: remove host logging configuration
  eos_logging:
    dest: host
    name: 172.16.0.1
    state: absent
- name: configure console logging level and facility
  eos_logging:
    dest: console
    facility: local7
    level: debugging
    state: present
- name: enable logging to all
  eos_logging:
    dest : on
- name: configure buffer size
  eos_logging:
    dest: buffered
    size: 5000
"""

RETURN = """
commands:
  description: The list of configuration mode commands to send to the device
  returned: always
  type: list
  sample:
    - logging facility local7
    - logging host 172.16.0.1
"""

import re

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.eos import get_config, load_config
from ansible.module_utils.eos import eos_argument_spec, check_args


DEST_GROUP = ['on', 'host', 'console', 'monitor', 'buffered']
LEVEL_GROUP = ['emergencies', 'alerts', 'critical', 'errors',
               'warnings', 'notifications', 'informational',
               'debugging']


def validate_size(value, module):
    if value:
        if not int(10) <= value <= int(2147483647):
            module.fail_json(msg='size must be between 10 and 2147483647')
        else:
            return value


def map_obj_to_commands(updates, module):
    commands = list()
    want, have = updates

    for w in want:
        dest = w['dest']
        name = w['name']
        size = w['size']
        facility = w['facility']
        level = w['level']
        state = w['state']
        del w['state']

        if state == 'absent' and w in have:
            if dest == 'host':
                commands.append('no logging host {}'.format(name))
            elif dest:
                commands.append('no logging {}'.format(dest))
            else:
                module.fail_json(msg='dest must be among console, monitor, buffered, host, on')

            if facility:
                commands.append('no logging facility {}'.format(facility))

        if state == 'present' and w not in have:
            if facility:
                commands.append('logging facility {}'.format(facility))

            if dest == 'host':
                commands.append('logging host {}'.format(name))

            elif dest == 'on':
                commands.append('logging on')

            elif dest == 'buffered' and size:
                commands.append('logging buffered {}'.format(size))

            else:
                dest_cmd = 'logging {}'.format(dest)
                if level:
                    dest_cmd += ' {}'.format(level)

                commands.append(dest_cmd)

    return commands


def parse_facility(line):
    facility = None
    match = re.search(r'logging facility (\S+)', line, re.M)
    if match:
        facility = match.group(1)

    return facility


def parse_size(line, dest):
    size = None

    if dest == 'buffered':
        match = re.search(r'logging buffered (\S+)', line, re.M)
        if match:
            try:
                int_size = int(match.group(1))
            except ValueError:
                int_size = None

            if int_size:
                if isinstance(int_size, int):
                    size = str(match.group(1))
                else:
                    size = str(10)

    return size


def parse_name(line, dest):
    name = None
    if dest == 'host':
        match = re.search(r'logging host (\S+)', line, re.M)
        if match:
            name = match.group(1)

    return name


def parse_level(line, dest, module):
    level = None

    if dest is not 'host':
        match = re.search(r'logging {} (\S+)'.format(dest), line, re.M)
        if match:
            if match.group(1) in LEVEL_GROUP:
                level = match.group(1)

    return level


def map_config_to_obj(module):
    obj = []

    data = get_config(module, flags=['section logging'])

    for line in data.split('\n'):
        match = re.search(r'logging (\S+)', line, re.M)

        if match.group(1) in DEST_GROUP:
            dest = match.group(1)
        else:
            pass

        obj.append({'dest': dest,
                    'name': parse_name(line, dest),
                    'size': parse_size(line, dest),
                    'facility': parse_facility(line),
                    'level': parse_level(line, dest, module)})

    return obj


def map_params_to_obj(module):
    obj = []

    if 'aggregate' in module.params and module.params['aggregate']:
        args = {'dest': '',
                'name': '',
                'size': '',
                'facility': '',
                'level': '',
                }

        for c in module.params['aggregate']:
            d = c.copy()

            for key in args:
                if key not in d:
                    d[key] = None

            if d['dest'] != 'host':
                d['name'] = None

            if 'state' not in d:
                d['state'] = module.params['state']

            if d['dest'] == 'buffered':
                if 'size' in d:
                    d['size'] = str(validate_size(d['size'], module))
                elif 'size' not in d:
                    d['size'] = str(10)
                else:
                    pass

            if d['dest'] != 'buffered':
                d['size'] = None

            obj.append(d)

    else:
        if module.params['dest'] != 'host':
            module.params['name'] = None

        if module.params['dest'] == 'buffered':
            if not module.params['size']:
                module.params['size'] = str(10)
        else:
            module.params['size'] = None

        if module.params['size'] is None:
            obj.append({
                'dest': module.params['dest'],
                'name': module.params['name'],
                'size': module.params['size'],
                'facility': module.params['facility'],
                'level': module.params['level'],
                'state': module.params['state']
            })

        else:
            obj.append({
                'dest': module.params['dest'],
                'name': module.params['name'],
                'size': str(validate_size(module.params['size'], module)),
                'facility': module.params['facility'],
                'level': module.params['level'],
                'state': module.params['state']
            })

    return obj


def main():
    """ main entry point for module execution
    """
    argument_spec = dict(
        dest=dict(type='str', choices=DEST_GROUP),
        name=dict(type='str'),
        size=dict(type='int'),
        facility=dict(type='str'),
        level=dict(type='str', choices=LEVEL_GROUP),
        state=dict(default='present', choices=['present', 'absent']),
        aggregate=dict(type='list'),
        purge=dict(default=False, type='bool')
    )

    argument_spec.update(eos_argument_spec)

    required_if = [('dest', 'host', ['name'])]

    module = AnsibleModule(argument_spec=argument_spec,
                           required_if=required_if,
                           supports_check_mode=True)

    warnings = list()
    check_args(module, warnings)

    result = {'changed': False}
    if warnings:
        result['warnings'] = warnings

    want = map_params_to_obj(module)
    have = map_config_to_obj(module)

    commands = map_obj_to_commands((want, have), module)
    result['commands'] = commands

    if commands:
        commit = not module.check_mode
        response = load_config(module, commands, commit=commit)
        if response.get('diff') and module._diff:
            result['diff'] = {'prepared': response.get('diff')}
        result['session_name'] = response.get('session')
        result['changed'] = True

    module.exit_json(**result)

if __name__ == '__main__':
    main()
