#!/usr/bin/python
# Copyright 2015, Hans-Joachim Kliemeck <git@kliemeck.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'core'}


DOCUMENTATION = r'''
---
module: win_owner
version_added: "2.1"
short_description: Set owner
description:
    - Set owner of files or directories
options:
  path:
    description:
      - Path to be used for changing owner
    required: true
  user:
    description:
      - Name to be used for changing owner
    required: true
  recurse:
    description:
      - Indicates if the owner should be changed recursively
    type: bool
    default: 'no'
author: Hans-Joachim Kliemeck (@h0nIg)
'''

EXAMPLES = r'''
- name: Change owner of Path
  win_owner:
    path: C:\apache
    user: apache
    recurse: yes

- name: Set the owner of root directory
  win_owner:
    path: C:\apache
    user: SYSTEM
    recurse: no
'''

RETURN = r'''

'''
