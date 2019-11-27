#
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
The arg spec for the ios_static_routes module
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type


class Static_RoutesArgs(object):
    """The arg spec for the ios_static_routes module
    """

    def __init__(self, **kwargs):
        pass

    argument_spec = {
        'config': {
            'elements': 'dict',
            'options': {
                'vrf': {'type': 'str'},
                'address_families': {
                    'elements': 'dict',
                    'type': 'list',
                    'options': {
                        'afi': {'choices': ['ipv4', 'ipv6'], 'type': 'str'},
                        'routes': {
                            'elements': 'dict',
                            'type': 'list',
                            'options': {
                                'dest': {'required': True, 'type': 'str'},
                                'topology': {'type': 'str'},
                                'next_hops': {
                                    'elements': 'dict',
                                    'type': 'list',
                                    'options': {
                                        'forward_router_address': {'type': 'str'},
                                        'interface': {'type': 'str'},
                                        'dhcp': {'type': 'bool'},
                                        'distance_metric': {'type': 'int'},
                                        'global': {'type': 'bool'},
                                        'name': {'type': 'str'},
                                        'multicast': {'type': 'bool'},
                                        'permanent': {'type': 'bool'},
                                        'tag': {'type': 'int'},
                                        'track': {'type': 'int'}
                                    }
                                }
                            }
                        }
                    }
                }
            },
            'type': 'list'
        },
        'state': {
            'choices': ['merged', 'replaced', 'overridden', 'deleted', 'gathered', 'rendered', 'parsed'],
            'default': 'merged',
            'type': 'str'
        }
    }
