#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2019 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#############################################
#                WARNING                    #
#############################################
#
# This file is auto generated by the resource
#   module builder playbook.
#
# Do not edit this file manually.
#
# Changes to this file will be over written
#   by the resource module builder.
#
# Changes should be made in the model used to
#   generate this file or in the resource module
#   builder template.
#
#############################################

"""
The module file for eos_vlans
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'network'
}

DOCUMENTATION = """
---
module: eos_vlans
version_added: 2.9
short_description: Manage VLANs on Arista EOS devices.
description: This module provides declarative management of VLANs on Arista EOS network devices.
author: Nathaniel Case (@qalthos)
notes:
- Tested against Arista EOS 4.20.10M
- This module works with connection C(network_cli). See the
  L(EOS Platform Options,../network/user_guide/platform_eos.html).
options:
  config:
    description: A dictionary of VLANs options
    type: list
    elements: dict
    suboptions:
      name:
        description:
        - Name of the VLAN.
        type: str
      vlan_id:
        description:
        - ID of the VLAN. Range 1-4094
        type: int
        required: true
      state:
        description:
        - Operational state of the VLAN
        type: str
        choices:
        - active
        - suspend
  state:
    description:
    - The state of the configuration after module completion
    type: str
    choices:
    - merged
    - replaced
    - overridden
    - deleted
    default: merged
"""
EXAMPLES = """
# Using deleted

# Before state:
# -------------
#
# veos(config-vlan-20)#show running-config | section vlan
# vlan 10
#    name ten
# !
# vlan 20
#    name twenty

- name: Delete attributes of the given VLANs.
  eos_vlans:
    config:
      - vlan_id: 20
    state: deleted

# After state:
# ------------
#
# veos(config-vlan-20)#show running-config | section vlan
# vlan 10
#    name ten


# Using merged

# Before state:
# -------------
#
# veos(config-vlan-20)#show running-config | section vlan
# vlan 10
#    name ten
# !
# vlan 20
#    name twenty

- name: Merge given VLAN attributes with device configuration
  eos_vlans:
    config:
      - vlan_id: 20
        state: suspend
    state: merged

# After state:
# ------------
#
# veos(config-vlan-20)#show running-config | section vlan
# vlan 10
#    name ten
# !
# vlan 20
#    name twenty
#    state suspend


# Using overridden

# Before state:
# -------------
#
# veos(config-vlan-20)#show running-config | section vlan
# vlan 10
#    name ten
# !
# vlan 20
#    name twenty

- name: Override device configuration of all VLANs with provided configuration
  eos_vlans:
    config:
      - vlan_id: 20
        state: suspend
    state: overridden

# After state:
# ------------
#
# veos(config-vlan-20)#show running-config | section vlan
# vlan 20
#    state suspend


# Using replaced

# Before state:
# -------------
#
# veos(config-vlan-20)#show running-config | section vlan
# vlan 10
#    name ten
# !
# vlan 20
#    name twenty

- name: Replace all attributes of specified VLANs with provided configuration
  eos_vlans:
    config:
      - vlan_id: 20
        state: suspend
    state: replaced

# After state:
# ------------
#
# veos(config-vlan-20)#show running-config | section vlan
# vlan 10
#    name ten
# !
# vlan 20
#    state suspend


"""
RETURN = """
before:
  description: The configuration as structured data prior to module invocation.
  returned: always
  type: list
  sample: >
    The configuration returned will always be in the same format
     of the parameters above.
after:
  description: The configuration as structured data after module completion.
  returned: when changed
  type: list
  sample: >
    The configuration returned will always be in the same format
     of the parameters above.
commands:
  description: The set of commands pushed to the remote device.
  returned: always
  type: list
  sample: ['vlan 10', 'no name', 'vlan 11', 'name Eleven']

"""


from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.network.eos.argspec.vlans.vlans import VlansArgs
from ansible.module_utils.network.eos.config.vlans.vlans import Vlans


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=VlansArgs.argument_spec,
                           supports_check_mode=True)

    result = Vlans(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
