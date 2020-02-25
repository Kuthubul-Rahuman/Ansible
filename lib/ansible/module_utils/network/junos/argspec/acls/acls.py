#
# _*_ coding: utf_8 _*_
# Copyright 2020 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl_3.0.txt)

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
The arg spec for the junos_acls module
"""
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


class AclsArgs(object):  # pylint: disable=R0903
    """The arg spec for the junos_acls module
    """

    def __init__(self, **kwargs):
        pass

    argument_spec = {
        'config': {
            'elements': 'dict',
            'type': 'list',
            'options': {
                'afi': {
                    'choices': ['ipv4', 'ipv6'],
                    'default': 'ipv4',
                    'type': 'str'},
                'acls': {
                    'elements': 'dict',
                    'type': 'list',
                    'options': {
                        'name': {
                            'required': True,
                            'type': 'str'},
                        'aces': {
                            'elements': 'dict',
                            'type': 'list',
                            'options': {
                                'name': {
                                    'required': True,
                                    'type': 'str'},
                                'source': {
                                    'type': 'dict',
                                    'options': {
                                        'address': {'type': 'str'},
                                        'prefix_list': {'type': 'str'},
                                    },
                                },
                                'destination': {
                                    'type': 'dict',
                                    'options': {
                                        'address': {'type': 'str'},
                                        'prefix_list': {'type': 'str'},
                                    },
                                },
                                'icmp-code': {
                                    'type': 'dict',
                                    'options': {
                                        'range': {'type': 'int'},
                                        'communication-prohibited-by-filtering': {'type': 'bool'},
                                        'destination-host-prohibited': {'type': 'bool'},
                                        'destination-host-unknown': {'type': 'bool'},
                                        'destination-network-prohibited': {'type': 'bool'},
                                        'destination-network-unknown': {'type': 'bool'},
                                        'fragmentation-needed': {'type': 'bool'},
                                        'host-precedence-violation': {'type': 'bool'},
                                        'host-unreachable': {'type': 'bool'},
                                        'host-unreachable-for-tos': {'type': 'bool'},
                                        'ip-header-bad': {'type': 'bool'},
                                        'network-unreachable': {'type': 'bool'},
                                        'network-unreachable-for-tos': {'type': 'bool'},
                                        'port-unreachable': {'type': 'bool'},
                                        'precedence-cutoff-in-effect': {'type': 'bool'},
                                        'protocol-unreachable': {'type': 'bool'},
                                        'redirect-for-host': {'type': 'bool'},
                                        'redirect-for-network': {'type': 'bool'},
                                        'redirect-for-tos-and-host': {'type': 'bool'},
                                        'redirect-for-tos-and-net': {'type': 'bool'},
                                        'required-option-missing': {'type': 'bool'},
                                        'source-host-isolated': {'type': 'bool'},
                                        'source-route-failed': {'type': 'bool'},
                                        'ttl-eq-zero-during-reassembly': {'type': 'bool'},
                                        'ttl-eq-zero-during-transit': {'type': 'bool'},
                                    },
                                },
                                'icmp-type': {
                                    'type': 'dict',
                                    'options': {
                                        'range': {'type': 'int'},
                                        'echo-reply': {'type': 'bool'},
                                        'echo-request': {'type': 'bool'},
                                        'info-reply': {'type': 'bool'},
                                        'info-request': {'type': 'bool'},
                                        'mask-reply': {'type': 'bool'},
                                        'mask-request': {'type': 'bool'},
                                        'parameter-problem': {'type': 'bool'},
                                        'redirect': {'type': 'bool'},
                                        'router-advertisement': {'type': 'bool'},
                                        'router-solicit': {'type': 'bool'},
                                        'source-quench': {'type': 'bool'},
                                        'time-exceeded': {'type': 'bool'},
                                        'timestamp': {'type': 'bool'},
                                        'timestamp-reply': {'type': 'bool'},
                                        'unreachable': {'type': 'bool'},
                                    },
                                },
                                'port': {
                                    'type': 'dict',
                                    'options': {
                                        'range': {'type': 'int'},
                                        'afs': {'type': 'bool'},
                                        'bgp': {'type': 'bool'},
                                        'biff': {'type': 'bool'},
                                        'bootpc': {'type': 'bool'},
                                        'bootpf': {'type': 'bool'},
                                        'cmd': {'type': 'bool'},
                                        'cvspserver': {'type': 'bool'},
                                        'dhcp': {'type': 'bool'},
                                        'domain': {'type': 'bool'},
                                        'eklogin': {'type': 'bool'},
                                        'ekshell': {'type': 'bool'},
                                        'exec': {'type': 'bool'},
                                        'finger': {'type': 'bool'},
                                        'ftp': {'type': 'bool'},
                                        'ftp-data': {'type': 'bool'},
                                        'http': {'type': 'bool'},
                                        'https': {'type': 'bool'},
                                        'ident': {'type': 'bool'},
                                        'imap': {'type': 'bool'},
                                        'kerberos-sec': {'type': 'bool'},
                                        'klogin': {'type': 'bool'},
                                        'kpasswd': {'type': 'bool'},
                                        'krb-prop': {'type': 'bool'},
                                        'krbupdate': {'type': 'bool'},
                                        'kshell': {'type': 'bool'},
                                        'ldap': {'type': 'bool'},
                                        'ldp': {'type': 'bool'},
                                        'login': {'type': 'bool'},
                                        'mobileip-agent': {'type': 'bool'},
                                        'mobileip-mn': {'type': 'bool'},
                                        'msdp': {'type': 'bool'},
                                        'netbios-dgm': {'type': 'bool'},
                                        'netbios-ns': {'type': 'bool'},
                                        'netbios-ssn': {'type': 'bool'},
                                        'nfsd': {'type': 'bool'},
                                        'nntp': {'type': 'bool'},
                                        'ntalk': {'type': 'bool'},
                                        'ntp': {'type': 'bool'},
                                        'pop3': {'type': 'bool'},
                                        'pptp': {'type': 'bool'},
                                        'printer': {'type': 'bool'},
                                        'radacct': {'type': 'bool'},
                                        'radius': {'type': 'bool'},
                                        'rip': {'type': 'bool'},
                                        'rkinit': {'type': 'bool'},
                                        'smtp': {'type': 'bool'},
                                        'snmp': {'type': 'bool'},
                                        'snmptrap': {'type': 'bool'},
                                        'snpp': {'type': 'bool'},
                                        'socks': {'type': 'bool'},
                                        'ssh': {'type': 'bool'},
                                        'sunrpc': {'type': 'bool'},
                                        'syslog': {'type': 'bool'},
                                        'tacacs': {'type': 'bool'},
                                        'tacacsds': {'type': 'bool'},
                                        'talk': {'type': 'bool'},
                                        'telnet': {'type': 'bool'},
                                        'tftp': {'type': 'bool'},
                                        'timed': {'type': 'bool'},
                                        'who': {'type': 'bool'},
                                        'xdmcp': {'type': 'bool'},
                                        'zephyr-clt': {'type': 'bool'},
                                        'zephyr-hm': {'type': 'bool'},
                                        'zephyr-srv': {'type': 'bool'},
                                    },
                                },
                                'protocol': {
                                    'type': 'dict',
                                    'options': {
                                        'range': {'type': 'int'},
                                        'ah': {'type': 'bool'},
                                        'dstopts': {'type': 'bool'},
                                        'egp': {'type': 'bool'},
                                        'esp': {'type': 'bool'},
                                        'fragment': {'type': 'bool'},
                                        'gre': {'type': 'bool'},
                                        'hop-by-hop': {'type': 'bool'},
                                        'icmp': {'type': 'bool'},
                                        'icmp6': {'type': 'bool'},
                                        'igmp': {'type': 'bool'},
                                        'ipip': {'type': 'bool'},
                                        'ipv6': {'type': 'bool'},
                                        'no-next-header': {'type': 'bool'},
                                        'ospf': {'type': 'bool'},
                                        'pim': {'type': 'bool'},
                                        'routing': {'type': 'bool'},
                                        'rsvp': {'type': 'bool'},
                                        'sctp': {'type': 'bool'},
                                        'tcp': {'type': 'bool'},
                                        'udp': {'type': 'bool'},
                                        'vrrp': {'type': 'bool'},
                                    },
                                },
                                'grant': {'type': 'str', "choice": ["permit", "deny"]},
                            },
                        },
                    },
                },
            },
        },
        'state': {
            'choices': [
                'merged',
                'replaced',
                'overridden',
                'deleted',
                'gathered'],
            'default': 'merged',
            'type': 'str'
        },
    }
# pylint: disable=C0301
