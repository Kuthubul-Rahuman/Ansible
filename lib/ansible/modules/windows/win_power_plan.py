#!/usr/bin/python
# Copyright (c) 2017 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = '''
---
module: win_power_plan
short_description: Changes the power plan of a Windows system
description:
  - This module will change the power plan of a Windows system to the defined string.
  - Windows defaults to C(balanced) which will cause CPU throttling. In some cases it can be preferable
    to change the mode to C(high performance) to increase CPU performance.
version_added: "2.4"
author:
  - Noah Sparks (@nwsparks)
options:
  name:
    description:
      - String value that indicates the desired power plan. The power plan must already be
        present on the system. Commonly there will be options for C(balanced) and C(high performance).
requirements:
  - Windows Server 2008R2 (6.1) or higher
'''

EXAMPLES = '''
- name: change power plan to high performance
  win_power_plan:
    name: high performance
'''

RETURN = r'''
power_plan_name:
  description: Value of the intended power plan
  returned: always
  type: string
  sample: balanced
power_plan_enabled:
  description: State of the intended power plan
  returned: success
  type: boolean
  sample: True
all_available_plans:
  description: The name and enabled state of all power plans
  returned: always
  type: dictionary
  sample: |
    {
        "High performance":  false,
        "Balanced":  true,
        "Power saver":  false
    }
'''
