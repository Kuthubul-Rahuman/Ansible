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
The module file for ios_static_routes
"""


from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'network'}

DOCUMENTATION = """
---
module: ios_static_routes
version_added: "2.10"
short_description: Configure and manage static routes on IOS devices.
description: This module configures and manages the static routes on IOS platforms.
author: Sumit Jaiswal (@justjais)
notes:
- Tested against Cisco IOSv Version 15.2 on VIRL
- This module works with connection C(network_cli).
  See L(IOS Platform Options,../network/user_guide/platform_ios.html).
options:
  config:
    description: A dictionary of static route options
    type: list
    elements: dict
    suboptions:
      vrf:
        description:
        - IP VPN Routing/Forwarding instance name.
        - NOTE, In case of IPV4/IPV6 VRF routing table should pre-exist before
          configuring.
        - NOTE, if the vrf information is not provided then the routes shall be
          configured under global vrf.
        type: str
      address_families:
        elements: dict
        description:
        - Address family to use for the static routes
        type: list
        suboptions:
          afi:
            description:
            - Top level address family indicator.
            type: str
            required: true
            choices:
              - ipv4
              - ipv6
          routes:
            description: Configuring static route
            type: list
            elements: dict
            suboptions:
              dest:
                description: Destination prefix with its subnet mask
                type: str
                required: true
              topology:
                description:
                - Configure static route for a Topology Routing/Forwarding instance
                - NOTE, VRF and Topology can be used together only with Multicast and
                  Topology should pre-exist before it can be used
                type: str
              next_hops:
                description:
                - next hop address or interface
                type: list
                elements: dict
                suboptions:
                  forward_router_address:
                    description: Forwarding router's address
                    type: str
                  interface:
                    description: Interface for directly connected static routes
                    type: str
                  dhcp:
                    description: Default gateway obtained from DHCP
                    type: bool
                  distance_metric:
                    description: Distance metric for this route
                    type: int
                  global:
                    description: Next hop address is global
                    type: bool
                  name:
                    description: Specify name of the next hop
                    type: str
                  multicast:
                    description: multicast route
                    type: bool
                  permanent:
                    description: permanent route
                    type: bool
                  tag:
                    description:
                    - Set tag for this route
                    - Refer to vendor documentation for valid values.
                    type: int
                  track:
                    description:
                    - Install route depending on tracked item with tracked object number.
                    - Tracking does not support multicast
                    - Refer to vendor documentation for valid values.
                    type: int
  state:
    description:
    - The state the configuration should be left in
    type: str
    choices:
    - merged
    - replaced
    - overridden
    - deleted
    - gathered
    - rendered
    - gathered
    - rendered
    - parsed
    default: merged
"""

EXAMPLES = """
---

# Using merged

# Before state:
# -------------
#
# viosl2#show running-config | section ^ip route|ipv6 route
# ip route 0.0.0.0 0.0.0.0 10.8.38.1

- name: Merge provided configuration with device configuration
  ios_static_routes:
    config:
      - vrf: blue
        address_families:
        - afi: ipv4
          routes:
          - dest: 192.168.2.0/24
            next_hops:
            - forward_router_address: 10.0.0.8
              name: merged_blue
              tag: 50
              track: 150
      - address_families:
        - afi: ipv4
          routes:
          - dest: 192.168.3.0/24
            next_hops:
            - forward_router_address: 10.0.0.1
              name: merged_route_1
              distance_metric: 110
              tag: 40
              multicast: True
            - forward_router_address: 10.0.0.2
              name: merged_route_2
              distance_metric: 30
        - afi: ipv6
          routes:
          - dest: FD5D:12C9:2201:1::/64
            next_hops:
            - forward_router_address: FD5D:12C9:2202::2
              name: merged_v6
              tag: 105
    state: merged

# After state:
# ------------
#
# viosl2#show running-config | section ^ip route|ipv6 route
# ip route vrf blue 192.168.2.0 255.255.255.0 10.0.0.8 tag 50 name merged_blue track 150
# ip route 0.0.0.0 0.0.0.0 10.8.38.1
# ip route 192.168.3.0 255.255.255.0 10.0.0.2 30 name merged_route_2
# ip route 192.168.3.0 255.255.255.0 10.0.0.1 110 tag 40 name merged_route_1 multicast
# ipv6 route FD5D:12C9:2201:1::/64 FD5D:12C9:2202::2 tag 105 name merged_v6

# Using replaced

# Before state:
# -------------
#
# viosl2#show running-config | section ^ip route|ipv6 route
# ip route vrf blue 192.168.2.0 255.255.255.0 10.0.0.8 tag 50 name merged_blue track 150
# ip route 0.0.0.0 0.0.0.0 10.8.38.1
# ip route 192.168.3.0 255.255.255.0 10.0.0.2 30 name merged_route_2
# ip route 192.168.3.0 255.255.255.0 10.0.0.1 110 tag 40 name merged_route_1 multicast
# ipv6 route FD5D:12C9:2201:1::/64 FD5D:12C9:2202::2 tag 105 name merged_v6

- name: Replace provided configuration with device configuration
  ios_static_routes:
    config:
      - vrf: blue
        address_families:
        - afi: ipv4
          routes:
          - dest: 192.168.2.0/24
            next_hops:
            - forward_router_address: 10.0.0.8
              name: replaced_vrf_new
              tag: 75
              track: 155
      - address_families:
        - afi: ipv4
          routes:
          - dest: 192.168.3.0/24
            next_hops:
            - forward_router_address: 10.0.0.1
              name: replaced_route
              distance_metric: 175
              tag: 70
              multicast: True
        - afi: ipv6
          routes:
          - dest: FD5D:12C9:2201:1::/64
            next_hops:
            - forward_router_address: FD5D:12C9:2202::2
              name: replaced_v6
              tag: 110
    state: replaced

# After state:
# ------------
#
# viosl2#show running-config | section ^ip route|ipv6 route
# ip route vrf blue 192.168.2.0 255.255.255.0 10.0.0.8 tag 75 name replaced_vrf_new track 155
# ip route 0.0.0.0 0.0.0.0 10.8.38.1
# ip route 192.168.3.0 255.255.255.0 10.0.0.2 30 name merged_route_2
# ip route 192.168.3.0 255.255.255.0 10.0.0.1 175 tag 70 name replaced_route multicast
# ipv6 route FD5D:12C9:2201:1::/64 FD5D:12C9:2202::2 tag 110 name replaced_v6

# Using overridden

# Before state:
# -------------
#
# viosl2#show running-config | section ^ip route|ipv6 route
# ip route vrf blue 192.168.2.0 255.255.255.0 10.0.0.8 tag 50 name merged_blue track 150
# ip route 0.0.0.0 0.0.0.0 10.8.38.1
# ip route 192.168.3.0 255.255.255.0 10.0.0.2 30 name merged_route_2
# ip route 192.168.3.0 255.255.255.0 10.0.0.1 110 tag 40 name merged_route_1 multicast
# ipv6 route FD5D:12C9:2201:1::/64 FD5D:12C9:2202::2 tag 105 name merged_v6

- name: Override provided configuration with device configuration
  ios_static_routes:
    config:
      - vrf: blue
        address_families:
        - afi: ipv4
          routes:
          - dest: 192.168.2.0/24
            next_hops:
            - forward_router_address: 10.0.0.4
              name: override_vrf
              tag: 50
              track: 150
      - address_families:
        - afi: ipv4
          routes:
          - dest: 192.168.3.0/24
            next_hops:
            - forward_router_address: 10.0.0.3
              multicast: True
              name: override_route
        - afi: ipv6
          routes:
          - dest: FD5D:12C9:2201:1::/64
            next_hops:
            - forward_router_address: FD5D:12C9:2202::2
              name: override_v6
              tag: 175
    state: overridden

# After state:
# ------------
#
# viosl2#show running-config | section ^ip route|ipv6 route
# ip route vrf blue 192.168.2.0 255.255.255.0 10.0.0.8 tag 50 name override_vrf track 150
# ip route 192.168.3.0 255.255.255.0 10.0.0.3 name override_route multicast
# ipv6 route FD5D:12C9:2201:1::/64 FD5D:12C9:2202::2 tag 175 name override_v6

# Using Deleted

# Before state:
# -------------
#
# viosl2#show running-config | section ^ip route|ipv6 route
# ip route vrf blue 192.168.2.0 255.255.255.0 10.0.0.8 tag 50 name merged_blue track 150
# ip route 0.0.0.0 0.0.0.0 10.8.38.1
# ip route 192.168.3.0 255.255.255.0 10.0.0.2 30 name merged_route_2
# ip route 192.168.3.0 255.255.255.0 10.0.0.1 110 tag 40 name merged_route_1 multicast
# ipv6 route FD5D:12C9:2201:1::/64 FD5D:12C9:2202::2 tag 105 name merged_v6

- name: Delete provided configuration from the device configuration
  ios_static_routes:
    config:
      - vrf: blue
        address_families:
        - afi: ipv4
          routes:
          - dest: 192.168.2.0/24
            next_hops:
            - forward_router_address: 10.0.0.8
              name: merged_blue
              tag: 50
              track: 150
      - address_families:
        - afi: ipv4
          routes:
          - dest: 192.168.3.0/24
            next_hops:
            - forward_router_address: 10.0.0.1
              name: merged_route_1
              distance_metric: 110
              tag: 40
              multicast: True
            - forward_router_address: 10.0.0.2
              name: merged_route_2
              distance_metric: 30
            - forward_router_address: 10.0.0.3
              name: merged_route_3
        - afi: ipv6
          routes:
          - dest: FD5D:12C9:2201:1::/64
            next_hops:
            - forward_router_address: FD5D:12C9:2202::2
              name: merged_v6
              tag: 105
    state: deleted

# After state:
# ------------
#
# viosl2#show running-config | section ^ip route|ipv6 route
# ip route 0.0.0.0 0.0.0.0 10.8.38.1

# Using Deleted without any config passed
#"(NOTE: This will delete all of configured resource module attributes from each configured interface)"

# Before state:
# -------------
#
# viosl2#show running-config | section ^ip route|ipv6 route
# ip route vrf blue 192.168.2.0 255.255.255.0 10.0.0.8 tag 50 name merged_blue track 150
# ip route 0.0.0.0 0.0.0.0 10.8.38.1
# ip route 192.168.3.0 255.255.255.0 10.0.0.2 30 name merged_route_2
# ip route 192.168.3.0 255.255.255.0 10.0.0.1 110 tag 40 name merged_route_1 multicast
# ipv6 route FD5D:12C9:2201:1::/64 FD5D:12C9:2202::2 tag 105 name merged_v6

- name: Delete ALL configured IOS static routes
  ios_static_routes:
    state: deleted

# After state:
# -------------
#
# viosl2#show running-config | section ^ip route|ipv6 route
#

# Using gathered

# Before state:
# -------------
#
# viosl2#show running-config | section ^ip route|ipv6 route
# ip route 0.0.0.0 0.0.0.0 10.8.38.1
# ip route 192.168.3.0 255.255.255.0 10.0.0.3
# ip route vrf blue 192.168.2.0 255.255.255.0 10.0.0.2 name test_blue multicast
# ip route 192.168.3.0 255.255.255.0 10.0.0.3 name test_route track 20

- name: Merge provided configuration with device configuration
  ios_static_routes:
    config:
    state: gathered

# After state:
# ------------
#
# Ansible will just display the routing facts
# viosl2#show running-config | section ^ip route|ipv6 route


# Using rendered

# Before state:
# -------------
#
# viosl2#show running-config | section ^ip route|ipv6 route


# After state:
# ------------
#
# viosl2#show running-config | section ^ip route|ipv6 route
# ip route vrf blue 192.168.2.0 255.255.255.0 10.0.0.2 name test_blue multicast
# ip route 192.168.3.0 255.255.255.0 10.0.0.3 name test_route track 20

"""

RETURN = """
before:
  description: The configuration as structured data prior to module invocation.
  returned: always
  type: list
  sample: The configuration returned will always be in the same format of the parameters above.
after:
  description: The configuration as structured data after module completion.
  returned: when changed
  type: list
  sample: The configuration returned will always be in the same format of the parameters above.
commands:
  description: The set of commands pushed to the remote device
  returned: always
  type: list
  sample: ['ip route vrf test 172.31.10.0 255.255.255.0 10.10.10.2 name new_test multicast']
"""


from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.network.ios.argspec.static_routes.static_routes import Static_RoutesArgs
from ansible.module_utils.network.ios.config.static_routes.static_routes import Static_Routes


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    required_if = [('state', 'merged', ('config',)),
                   ('state', 'replaced', ('config',)),
                   ('state', 'overridden', ('config',))]

    module = AnsibleModule(argument_spec=Static_RoutesArgs.argument_spec,
                           required_if=required_if,
                           supports_check_mode=True)

    result = Static_Routes(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
