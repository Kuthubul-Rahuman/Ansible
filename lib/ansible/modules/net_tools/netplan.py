#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (c) 2018, Luis Eduardo <leduardo@lsd.ufcg.edu.br>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: netplan
author:
    - Luis Eduardo (@lets00)
short_description: Manage network configurations using netplan.
version_added: "2.8"
description:
    - This module allows to you manage network configurations using netplan.
      It creates/edits a netplan YAML file, saves on /etc/netplan/ directory
      and apply the YAML files on system (neplan apply).

requirements: [ PyYAML, netplan ]
notes:
    - Introduction to Netplan U(https://github.com/CanonicalLtd/netplan/blob/master/doc/netplan.md)
options:
  filename:
    description:
      - Name of file that will be create or open to add/remove network
        interfaces.
    required: true

  renderer:
    description:
      - Network backend to use for this definition. Currently supported
        are C(networkd)(default) and C(NetworkManager).
    choices: [ networkd, NetworkManager ]
    required: false

  version:
    description:
      - The syntax of the YAML file currently being used. Default is 2.
    required: false
    type: int

  interface-id:
    description:
      - Interface ID that must be unique.
    required: true

  type:
    description:
      - Interface type. Some types support additional parameters.
        C(bridges) specific params:C(ageing-time), C(priority),
        C(port-priority), C(forward-delay), C(hello-time), C(max-age),
        C(path-cost) and C(stp).

        C(bonds) specific params:C(bonding-mode), C(lacp-rate),
        C(mii-monitor-interval), C(min-links), C(transmit-hash-policy),
        C(ad-select), C(all-slaves-active), C(arp-interval), C(arp-ip-targets),
        C(arp-validate), C(arp-all-targets), C(up-delay), C(down-delay),
        C(fail-over-mac-policy), C(gratuitous-arp), C(packets-per-slave),
        C(primary-reselect-policy), C(resend-igmp), C(learn-packet-interval)
        and C(primary).

        C(tunnels) specific params:C(tunneling-mode), C(local), C(remote),
        C(key), C(keys-input-output).

        C(vlans) specific params:C(id) and C(link).

        C(wifis) specific params:C(access-points-ssid),
        C(access-points-password) and C(access-points-mode).
    choices: [ bridges, bonds, tunnels, ethernets, vlans, wifis ]
    required: true

  state:
    description:
      - C(present) add a net interface on C(filename);
        C(absent) remove a net interface on C(filename).
    choices: [ present, absent ]
    required: true

  dhcp4:
    description:
      - Enable/Disable DHCP for IPv4. Default is disabled.
        Supported for all device types.
    required: false
    type: bool

  dhcp6:
    description:
      - Enable/Disable DHCP for IPv6. Default is disabled.
        Supported for all device types.
    required: false
    type: bool

  ipv6-privacy:
    description:
      - Enable IPv6 Privacy Extensions (RFC 4941) for the specified interface,
        and prefer temporary addresses. Defaults to false
        (no privacy extensions). There is currently no way to have a
        private address but prefer the public address. Supported for all device
        types.
    required: false
    type: bool

  link-local:
    description:
      - Configure the link-local addresses to bring up. Valid options are
        C(ipv4) and C(ipv6) (default), which respectively allow enabling IPv4
        and IPv6 link local addressing. Supported for all device types.
    choices: [ ipv4, ipv6 ]
    required: false

  critical:
    description:
      - Designate the connection as "critical to the system", meaning that
        special care will be taken by systemd-networkd to not release the IP
        from DHCP when it the daemon is restarted. Networkd backend only.
        False for default. Supported for all device types.
    required: false
    type: bool

  dhcp-identifier:
    description:
      - When set to C(mac); pass that setting over to systemd-networkd to use
        the device's MAC address as a unique identifier rather than a
        RFC4361-compliant Client ID. This has no effect when NetworkManager
        is used as a renderer. Supported for all device types.
    required: false

  accept-ra:
    description:
      - Accept Router Advertisement that would have the kernel configure IPv6
        by itself. When enabled, accept Router Advertisements. When disabled,
        do not respond to Router Advertisements. If unset use the host kernel
        default setting. Supported for all device types.
    required: false
    type: bool

  addresses:
    description:
      - Addresses statically assigned to the interface. They are used in
        addition to the autoconfigured ones, and are represented in
        CIDR notation. Supported for all device types.
    required: false
    type: list

  gateway4:
    description:
      - Set default gateway for IPv4, for manual address configuration.
        This requires setting addresses too. Gateway IPs must be in a form
        recognized by C(inet_pton). Supported for all device types.
    required: false

  gateway6:
    description:
      - Set default gateway for IPv6, for manual address configuration.
        This requires setting addresses too. Gateway IPs must be in a form
        recognized by C(inet_pton). Supported for all device types.
    required: false

  nameservers-search:
    description:
      -  Set a list of DNS servers search domains.
         Supported for all device types.
    required: false
    type: list

  nameservers-addresses:
    description:
      -  Set a list of ipv4/ipv6 DNS servers.
         Supported for all device types.
    required: false
    type: list

  macaddress:
    description:
      - Set the device's MAC address. The MAC address must be in the form
        XX:XX:XX:XX:XX:XX. Supported for all device types.
    required: false

  mtu:
    description:
      - Set the Maximum Transmission Unit for the interface.
        The default is 1500. Valid values depend on your network interface.
        Supported for all device types.
    required: false
    type: int

  optional:
    description:
      - An optional device is not required for booting. Normally, networkd
        will wait some time for device to become configured before proceeding
        with booting. However, if a device is marked as optional, networkd will
        not wait for it. This is only supported by networkd, and the
        default is false. Supported for all device types.
    required: false
    type: bool

  optional-addresses:
    description:
      - Specify types of addresses that are not required for a device to be
        considered online. This changes the behavior of backends at boot time
        to avoid waiting for addresses that are marked optional, and thus
        consider the interface as "usable" sooner. This does not disable
        these addresses, which will be brought up anyway.
        Supported for all device types.
    required: false
    type: list

  match-name:
    description:
      - This selects the current interface name in physical devices
        by various hardware properties. Globs are supported.
        Supported only physical devices.
    required: false

  match-macaddress:
    description:
      - This selects the physical device that matchs with MAC address
        in the form "XX:XX:XX:XX:XX:XX". Globs are not supported.
        Supported only physical devices.
    required: false

  match-driver:
    description:
      - This selects the physical device that matchs with Kernel driver name
        corresponding to the C(DRIVER) udev property. Globs are supported.
        Supported only physical devices.
    required: false

  set-name:
    description:
      - This property can be used to give that device a more
        specific/desirable/nicer name than the default from udev's ifnames.
        Supported only physical devices.
    required: false

  wakeonlan:
    description:
      - Enable/Disable(default) wake on LAN. Supported only physical devices.
    required: false
    type: bool

  dhcp4-overrides-use-dns:
    description:
      - The DNS servers received from the DHCP server will be used and take
        precedence statically-configured ones. Only C(networkd) backend and
        C(dhcp4) must be true. Supported for all device types.
    required: false
    type: bool

  dhcp4-overrides-use-ntp:
    description:
      - The NTP servers received from the DHCP server will be used by
        systemd-timesyncd and take precedence statically-configured
        ones. Only C(networkd) backend and C(dhcp4) must be true.
        Supported for all device types.
    required: false
    type: bool

  dhcp4-overrides-use-hostname:
    description:
      - The hostname received from the DHCP server will be set as the transient
        hostname of the system. Only C(networkd) backend and C(dhcp4)
        must be true. Supported for all device types.
    required: false
    type: bool

  dhcp4-overrides-send-hostname:
    description:
      - The machine's hostname will be sent to the DHCP serverself.
        Only C(networkd) backend and C(dhcp4) must be true.
        Supported for all device types.
    required: false
    type: bool

  dhcp4-overrides-hostname:
    description:
      - Use this value for the hostname which is sent to the DHCP server,
        instead of machine's hostname. Only C(networkd) backend and C(dhcp4)
        must be true. Supported for all device types.
    required: false

  dhcp6-overrides-use-dns:
    description:
      - The DNS servers received from the DHCP server will be used and take
        precedence over any statically. Only C(networkd) backend and C(dhcp6)
        must be true. Supported for all device types.
    required: false
    type: bool

  dhcp6-overrides-use-ntp:
    description:
      - The NTP servers received from the DHCP server will be used by
        systemd-timesyncd and take precedence over any statically configured
        ones. Only C(networkd) backend and C(dhcp6) must be true.
        Supported for all device types.
    required: false
    type: bool

  dhcp6-overrides-use-hostname:
    description:
      - The hostname received from the DHCP server will be set as the transient
        hostname of the system. Only C(networkd) backend and C(dhcp6)
        must be true. Supported for all device types.
    required: false
    type: bool

  dhcp6-overrides-send-hostname:
    description:
      - The machine's hostname will be sent to the DHCP serverself.
        Only C(networkd) backend and C(dhcp6) must be true.
        Supported for all device types.
    required: false
    type: bool

  dhcp6-overrides-hostname:
    description:
      - Use this value for the hostname which is sent to the DHCP server,
        instead of machine's hostname. Only C(networkd) backend and C(dhcp6)
        must be true. Supported for all device types.
    required: false

  routes:
    description:
      - Defines standard static routes for an interface. The routes must be
        defined using a list of dicts, E.g:- {to:0.0.0.0/0, via:1.1.1.1/8}.
        Valid dict keys are:C(from) set a source IP address for traffic going
        through the route;
        C(to) defines the destination address for the route;
        C(via) defines the gateway address to use for this route;
        C(on-link) specifies that the route is directly connected to
        the interface (boolean);
        C(metric) specifies the relative priority of the route.
        Must be a positive integer value;
        C(type) specifies the type of route. Valid options are "unicast"
        (default), "unreachable", "blackhole" or "prohibit";
        C(scope) defines the route scope, how wide-ranging it is to the network.
        Possible values are "global", "link", or "host";
        C(table) defines the table number to use for the route.
        In some scenarios, it may be useful to set routes in a separate
        routing table. It may also be used to refer to routing policy rules
        which also accept a table parameter. Allowed values are positive
        integers starting from 1. Some values are already in use to refer to
        specific routing tables:see C(/etc/iproute2/rt_tables).

        At least the suboptions I(to) and I(via) must be specified.
        Supported for all device types.
    required: false
    type: list

  routing-policy:
    description:
      - Defines  extra routing policy for a network, where traffic may be
        handled specially based on the source IP, firewall marking, etc.
        The routing-policy must be defined using a list of dicts,
        E.g:- {from:192.168.0.0/24, table:102}. Valid dict keys are:C(from)
        set a source IP address to match traffic for this policy rule;
        C(to) match on traffic going to the specified destination;
        C(table) specifies the table number to match for the route.
        In some scenarios, it may be useful to set routes in a separate
        routing table. It may also be used to refer to routes which also accept
        a table parameter. Allowed values are positive integers starting from 1.
        Some values are already in use to refer to specific routing tables:see
        C(/etc/iproute2/rt_tables);
        C(priority) specifies a priority for the routing policy rule, to
        influence the order in which routing rules are processed. A higher
        number means lower priority (rules are processed in order by increasing
        priority number);
        C(mark) defines a mark that this routing policy rule match on
        traffic that has been marked by the iptables firewall with this value.
        Allowed values are positive integers starting from 1;
        C(type-of-service) defines this policy rule based on the type of
        service number applied to the traffic;
        Supported for all devices types.
    required: false
    type: list

  auth-key-management:
    description:
      - The supported key management modes are C(none) (no key management);
        C(psk) (WPA with pre-shared key, common for home wifi); C(eap) (WPA
        with EAP, common for enterprise wifi); and C(802.1x) (used primarily
        for wired Ethernet connections). Supported ethernets and wifis device
        types.
    choices: [ none, psk, eap, 802.1x ]
    required: false

  auth-password:
    description:
      - The password string for EAP, or the pre-shared key for WPA-PSK.
         Supported ethernets and wifis device types.
    required: false

  auth-method:
    description:
      - The EAP/802.1x method to use. The supported EAP/802.1x methods are
        C(tls) (TLS), C(peap) (Protected EAP), and C(ttls) (Tunneled TLS).
        I(auth-key-management=eap) or I(auth-key-management=802.1x).
        Supported ethernets and wifis device types.
    choices: [ tls, peap, ttls ]
    required: false

  auth-identity:
    description:
      - The identity to use for EAP/802.1x.
        I(auth-key-management=eap) or I(auth-key-management=802.1x).
        Supported ethernets and wifis device types.
    required: false

  auth-anonymous-identity:
    description:
      - The identity to pass over the unencrypted channel if the chosen
        EAP/802.1x method supports passing a different tunnelled identity.
        I(auth-key-management=eap) or I(auth-key-management=802.1x).
        Supported ethernets and wifis device types.
    required: false

  auth-ca-certificate:
    description:
      - Path to a file with one or more trusted certificate authority (CA)
        certificates.
        I(auth-key-management=eap) or I(auth-key-management=802.1x).
        Supported ethernets and wifis device types.
    required: false

  auth-client-certificate:
    description:
      - Path to a file containing the certificate to be used by the client
        during authentication.
        I(auth-key-management=eap) or I(auth-key-management=802.1x).
        Supported ethernets and wifis device types.
    required: false

  auth-client-key:
    description:
      - Path to a file containing the private key corresponding to
        C(auth-client-certificate).
        I(auth-key-management=eap) or I(auth-key-management=802.1x).
        Supported ethernets and wifis device types.
    required: false

  auth-client-key-password:
    description:
      - Password to use to decrypt the private key specified in
        C(auth-client-key) if it is encrypted.
        I(auth-key-management=eap) or I(auth-key-management=802.1x).
        Supported ethernets and wifis device types.
    required: false

  interfaces:
    description:
      - All devices matching this ID list will be added or associated to
        bridges or bonds. Required if I(state=present) and I(type=bonds) or
        I(type=bridges). Supported bridges and bonds device types.
    required: false
    type: list

  bonding-mode:
    description:
      - Set the link bonding mode used for the interfaces.
        Required if I(state=present) and I(type=bonds).
        Supported only bond device types.
    choices: [ balance-rr, active-backup, balance-xor, broadcast,
               802.3ad, balance-tlb, balance-alb ]
    required: false

  lacp-rate:
    description:
      - Set the rate at which LACP DUs are transmitted. This is only useful
        in 802.3ad mode. Possible values are C(slow) (30 seconds, default),
        and C(fast) (every second). Supported only bond device types.
    choices: [ slow, fast ]
    required: false

  mii-monitor-interval:
    description:
      - Specifies the interval for MII monitoring (verifying if an interface
        of the bond has carrier). The default is 0; which disables MII
        monitoring. This is equivalent to the MIIMonitorSec= field for the
        networkd backend. Supported only bond device types.
    required: false
    type: int

  min-links:
    description:
      - The minimum number of links up in a bond to consider the bond
        interface to be up (default is 1). Supported only bond device types.
    required: false
    type: int

  transmit-hash-policy:
    description:
      - Specifies the transmit hash policy for the selection of slaves. This
        is only useful in balance-xor, 802.3ad and balance-tlb modes. Possible
        values are C(layer2), C(layer3+4), C(layer2+3), C(encap2+3), and
        C(encap3+4). Supported only bond device types.
    choices: [ layer2, layer3+4, layer2+3, encap2+3, encap3+4 ]
    required: false

  ad-select:
    description:
      - Set the aggregation selection mode. Possible values are C(stable),
        C(bandwidth), and C(count). This option is only used in C(802.3ad)
        mode. Supported only bond device types.
    choices: [ stable, bandwidth, count ]
    required: false

  all-slaves-active:
    description:
      - If the bond should drop duplicate frames received on inactive ports,
        set this option to C(false). If they should be delivered, set this
        option to C(true). The default value is false, and is the desirable
        behavior in most situations. Supported only bond device types.
    required: false
    type: bool

  arp-interval:
    description:
      - Set the interval value for how frequently ARP link monitoring should
        happen. The default value is 0, which disables ARP monitoring.
        For the networkd backend, this maps to the ARPIntervalSec= property.
        Supported only bond device types.
    required: false

  arp-ip-targets:
    description:
      - IPs of other hosts on the link which should be sent ARP requests in
        order to validate that a slave is up. This option is only used when
        C(arp-interval) is set to a value other than 0. At least one IP
        address must be given for ARP link monitoring to function. Only IPv4
        addresses are supported. You can specify up to 16 IP addresses. The
        default value is an empty list. Supported only bond device types.
    required: false
    type: list

  arp-validate:
    description:
      - Configure how ARP replies are to be validated when using ARP link
        monitoring. Possible values are C(none), C(active), C(backup),
        and C(all). Supported only bond device types.
        Supported only bond device types.
    choices: [ none, active, backup, all ]
    required: false

  arp-all-targets:
    description:
      - Specify whether to use any ARP IP target being up as sufficient for
        a slave to be considered up; or if all the targets must be up. This
        is only used for C(active-backup) mode when C(arp-validate) is
        enabled. Possible values are C(any) and C(all).
        Supported only bond device types.
    choices: [ any, all ]
    required: false

  up-delay:
    description:
      - Specify the delay before enabling a link once the link is physically
        up. The default value is 0. This maps to the UpDelaySec= property for
        the networkd renderer. Supported only bond device types.
    required: false
    type: int

  down-delay:
    description:
      - Specify the delay before disabling a link once the link has been
        lost. The default value is 0. This maps to the DownDelaySec=
        property for the networkd renderer. Supported only bond device types.
    required: false
    type: int

  fail-over-mac-policy:
    description:
      - Set whether to set all slaves to the same MAC address when adding
        them to the bond, or how else the system should handle MAC addresses.
        The possible values are C(none), C(active), and C(follow).
        Supported only bond device types.
    required: false
    choices: [ none, active, follow ]

  gratuitous-arp:
    description:
      - Specify how many ARP packets to send after failover. Once a link is
        up on a new slave, a notification is sent and possibly repeated if
        this value is set to a number greater than 1. The default value
        is 1 and valid values are between 1 and 255. This only affects
        active-backup mode. Supported only bond device types.
    required: false
    type: int

  packets-per-slave:
    description:
      - In C(balance-rr) mode, specifies the number of packets to transmit
        on a slave before switching to the next. When this value is set to
        0, slaves are chosen at random. Allowable values are between
        0 and 65535. The default value is 1. This setting is
        only used in C(balance-rr) mode. Supported only bond device types.
    required: false
    type: int

  primary-reselect-policy:
    description:
      - Specific the reselection policy for the primary slave. On failure of
        the active slave, the system will use this policy to decide how the new
        active slave will be chosen and how recovery will be handled. The
        possible values are C(always), C(better), and C(failure).
        Supported only bond device types.
    required: false
    choices: [ always, better, failure ]

  resend-igmp:
    description:
      - Specifies how many IGMP membership reports are issued on a failover
        event. Values range from 0 to 255. 0 disables sending membership
        reports. Otherwise, the first membership report is sent on failover and
        subsequent reports are sent at 200ms intervals. In modes C(balance-rr),
        C(active-backup), C(balance-tlb) and C(balance-alb), a failover can
        switch IGMP traffic from one slave to another.
        Supported only bond device types.
    required: false
    type: int

  learn-packet-interval:
    description:
      - Specify the interval (seconds) between sending learning packets to
        each slave.  The value range is between 1 and 0x7fffffff.
        The default value is 1. This option only affects C(balance-tlb)
        and C(balance-alb) modes. Using the networkd renderer, this field
        maps to the LearnPacketIntervalSec= property.
        Supported only bond device types.
    required: false
    type: int

  primary:
    description:
      - Specify a device to be used as a primary slave, or preferred device
        to use as a slave for the bond (ie. the preferred device to send
        data through), whenever it is available. This only affects
        C(active-backup), C(balance-alb), and C(balance-tlb) bonding-modes.
        Supported only bond device types.
    required: false

  ageing-time:
    description:
      - Set the period of time (in seconds) to keep a MAC address in the
        forwarding database after a packet is received. This maps to the
        AgeingTimeSec= property when the networkd renderer is used.
        Supported only bridge device types.
    required: false
    type: int

  priority:
    description:
      - Set the priority value for the bridge. This value should be a
        number between 0 and 65535. Lower values mean higher priority.
        The bridge with the higher priority will be elected as
        the root bridge. Supported only bridge device types.
    required: false
    type: int

  port-priority:
    description:
      - Specify the period of time the bridge will remain in Listening and
        Learning states before getting to the Forwarding state. This field
        maps to the ForwardDelaySec= property for the networkd renderer.
        If no time suffix is specified, the value will be interpreted as
        seconds. You must define an array, with a interface name and the
        forward delay. E.g:['eno1', 15]. Supported only bridge device types.
    required: false
    type: list

  forward-delay:
    description:
      - Specify the period of time (in seconds) the bridge will remain in
        Listening and Learning states before getting to the Forwarding state.
        This field maps to the ForwardDelaySec= property for the networkd
        renderer. Supported only bridge device types.
    required: false
    type: int

  hello-time:
    description:
      - Specify the interval (in seconds) between two hello packets being sent
        out from the root and designated bridges. Hello packets communicate
        information about the network topology. When the networkd renderer
        is used, this maps to the HelloTimeSec= property.
        Supported only bridge device types.
    required: false
    type: int

  max-age:
    description:
      - Set the maximum age (in seconds) of a hello packet. If the last hello
        packet is older than that value, the bridge will attempt to become the
        root bridge. This maps to the MaxAgeSec= property when the networkd.
        Supported only bridge device types.
    required: false
    type: int

  path-cost:
    description:
      - Set the cost of a path on the bridge. Faster interfaces should have
        a lower cost. This allows a finer control on the network topology
        so that the fastest paths are available whenever possible.
        You must define a list, with a interface name and the path-cost.
        E.g:['eno1', 15]. Supported only bridge device types.
    required: false
    type: list

  stp:
    description:
      - Define whether the bridge should use Spanning Tree Protocol. The
        default value is C(true), which means that Spanning Tree should be
        used. Supported only bridge device types.
    required: false
    type: bool

  tunneling-mode:
    description:
      - Defines the tunnel mode. Valid options are sit, gre, ip6gre, ipip,
        ipip6, ip6ip6, vti, and vti6. Additionally, the networkd backend also
        supports gretap and ip6gretap modes. In addition, the NetworkManager
        backend supports isatap tunnels.
        Required if I(state=present) and I(type=tunnels).
        Supported only tunnel device types.
    required: false
    choices: [ sit, gre, ip6gre, ipip, ipip6, ip6ip6, vti, vti6, gretap,
               ip6gretap, isatap ]

  local:
    description:
       - Defines the address of the local endpoint of the tunnel.
         Required if I(state=present) and I(type=tunnels).
         Supported only tunnel device types.
    required: false

  remote:
    description:
      - Defines the address of the remote endpoint of the tunnel.
        Required if I(state=present) and I(type=tunnels).
        Supported only tunnel device types.
    required: false

  key:
    description:
      - Specifiy key to use for the tunnel. The key can be a number or a dotted
        quad (an IPv4 address). It is used for identification of IP transforms.
        This is only required for C(vti) and C(vti6) when using the C(networkd)
        backend, and for C(gre) or C(ip6gre) tunnels when using the
        NetworkManager backend. Supported only tunnel device types.
    required: false

  keys-input-output:
    description:
      - Specifiy input and output keys to use for the tunnel. If this param is
        defined, you can't define the key param. The first value passed on list
        is the input key and the second value is the output key.
        E.g:[1234, 5678]. Supported only tunnel device types.
    required: false
    type: list

  id:
    description:
      - VLAN ID, a number between 0 and 4094. Supported only vlan device types.
    required: false
    type: int

  link:
    description:
      - netplan ID of the underlying device definition on which this VLAN
        gets created. Supported only vlan device types.
    required: false

  access-points-ssid:
    description:
      - Network SSID. Required if I(state=present) and (type=wifis).
        Supported only wifi device types.
    required: false

  access-points-password:
    description:
      - Enable WPA2 authentication and set the passphrase for it. If defined
        C(None), the network is assumed to be open. Other authentication modes
        are not currently supported.
        Required if I(state=present) and (type=wifis).
        Supported only wifi device types.
    required: false

  access-points-mode:
    description:
      - Possible access point modes are C(infrastructure) (the default),
        C(ap) (create an access point to which other devices can connect),
        and C(adhoc) (peer to peer networks without a central access point).
        C(ap) is only supported with C(NetworkManager).
        Required if I(state=present) and (type=wifis).
        Supported only wifi device types.
    required: false
    choices: [ infrastructure, ap, adhoc ]
'''

EXAMPLES = '''
 - name: Add eth1 interface
   netplan:
     filename: 10-interfaces
     type: ethernets
     interface-id: eth1
     state: present
     dhcp4: false
     addresses:
       - 192.168.1.100/24

 - name: Add eth2 interface
   netplan:
     filename: 10-interfaces
     type: ethernets
     interface-id: eth2
     state: present
     dhcp4: false
     addresses:
       - 192.168.2.100/24
     routes:
       - {to: 0.0.0.0/0, via: 192.168.2.1/24, type: unicast, scope: global}
       - {to: 10.0.0.0/0, via: 192.168.2.2/24}
     routing-policy:
        - {from: 192.168.100.0/24, table: 1, priority: 10}
        - {from: 192.168.200.0/24, table: 2, mark: 100}


 - name: Add br0 bridge interface
   netplan:
     filename: 11-bridges
     type: bridges
     interfaces:
       - eth1
       - eth2
     interface-id: br0
     state: present
     ageing-time: 100
     priority: 2
     port-priority:
       - [eth1, 20]
       - [eth2, 15]
     path-cost:
       - [eth1, 20]
       - [eth2, 15]
     forward-delay: 150
     hello-time: 200
     max-age: 500
     stp: false
     dhcp4: false
     addresses:
       - 192.168.1.1/24
       - 192.168.1.2/24

 - name: Add br1 bridge interface
   netplan:
     filename: 11-bridges
     type: bridges
     interface-id: br1
     state: present
     dhcp4: false

 - name: Add vlan config interfaces
   netplan:
     filename: 12-vlans
     interface-id: brvlan15
     state: present
     type: vlans
     id: 15
     link: br0

 - name: Remove vlan config interfaces into netplan YAML file
   netplan:
     filename: 12-vlans
     interface-id: brvlan15
     type: vlans
     state: absent

 - name: Add ethernet config interfaces
   netplan:
     filename: 10-interfaces
     interface-id: eth0
     type: ethernets
     state: present
     addresses:
       - 192.168.0.1/24
       - 192.168.1.1/24

 - name: Add bridge config interface
   netplan:
     filename: 11-bridges
     interface-id: br0
     type: bridge
     interfaces: eth1
     state: present

 - name: Create bond0 interface
   netplan:
     filename: 13-bonds
     type: bonds
     interface-id: bond0
     state: present
     bonding-mode: 802.3ad
     lacp-rate: slow
     mii-monitor-interval: 10
     min-links: 10
     up-delay: 20
     down-delay: 30
     all-slaves-active: true
     ad-select: stable
     arp-interval: 15
     arp-validate: all
     arp-all-targets: all
     fail-over-mac-policy: none
     arp-ip-targets: [10.10.10.10, 20.20.20.20]
     interfaces: [br0, br1]
     dhcp4: true

 - name: Create tunnel0 interface
   netplan:
     filename: 14-tunnel
     type: tunnels
     interface-id: tunnel0
     tunneling-mode: sit
     local: 1.1.1.1
     remote: 2.2.2.2
     addresses:
       - 9.9.9.9/8
     state: present
     dhcp4: false

 - name: Up veths interfaces
   netplan:
     filename: 15-wifis
     type: wifis
     interface-id: wifi00
     state: present
     access-points-ssid: asdf
     access-points-password: test1234
     access-points-mode: infrastructure
     auth-key-management: eap
     auth-method: tls
     auth-anonymous-identity: "@cust.example.com"
     auth-identity: "cert-joe@cust.example.com"
     auth-ca-certificate: /etc/ssl/cust-cacrt.pem
     auth-client-certificate: /etc/ssl/cust-crt.pem
     auth-client-key: /etc/ssl/cust-key.pem
     auth-client-key-password: "d3cryptPr1v4t3K3y"
'''

RETURN = '''
'''

from ansible.module_utils.basic import AnsibleModule
import os.path
try:
    import yaml
    HAS_YAML = True
except:
    HAS_YAML = False

NETPLAN_PATH = '/etc/netplan'

SPECIFC_ANSIBLE_NETPLAN = ['filename', 'renderer', 'version', 'type',
                           'interface-id', 'state']

GENERAL = ['addresses', 'dhcp4', 'dhcp6', 'ipv6-privacy', 'link-local',
           'critical', 'dhcp-identifier', 'accept-ra', 'addresses',
           'gateway4', 'gateway6', 'nameservers-search',
           'nameservers-addresses', 'macaddress', 'optional',
           'optional-addresses', 'routes', 'routing-policy']

MATCH = ['match-name', 'match-macaddress', 'match-driver']

PHYSICAL = MATCH + ['set-name', 'wakeonlan']

DHCP_OVERRIDES = ['dhcp4-overrides-use-dns',
                  'dhcp4-overrides-use-ntp',
                  'dhcp4-overrides-use-hostname',
                  'dhcp4-overrides-send-hostname',
                  'dhcp4-overrides-hostname',
                  'dhcp6-overrides-use-dns',
                  'dhcp6-overrides-use-ntp',
                  'dhcp6-overrides-use-hostname',
                  'dhcp6-overrides-send-hostname',
                  'dhcp6-overrides-hostname']

ROUTES = ['from', 'to', 'via', 'on-link', 'metric', 'type', 'scope', 'table']

ROUTING_POLICY = ['from', 'to', 'table', 'priority', 'mark', 'type-of-service']

AUTH = ['auth-key-management', 'auth-password', 'auth-method', 'auth-identity',
        'auth-anonymous-identity', 'auth-ca-certificate',
        'auth-client-certificate', 'auth-client-key',
        'auth-client-key-password']

BONDS = ['bonding-mode', 'lacp-rate', 'mii-monitor-interval', 'min-links',
         'transmit-hash-policy', 'ad-select', 'all-slaves-active',
         'arp-interval', 'arp-ip-targets', 'arp-validate', 'arp-all-targets',
         'up-delay', 'down-delay', 'fail-over-mac-policy', 'gratuitous-arp',
         'packets-per-slave', 'primary-reselect-policy', 'resend-igmp',
         'learn-packet-interval', 'primary']

BRIDGES = ['ageing-time', 'priority', 'port-priority', 'forward-delay',
           'hello-time', 'max-age', 'path-cost', 'stp']

TUNNELS = ['tunneling-mode', 'local', 'remote', 'key', 'keys-input-output']

VLANS = ['id', 'link']

WIFIS = ['access-points-ssid', 'access-points-password', 'access-points-mode']


def validate_args(module):
    if module.params['state'] == 'present':
        # validate general params
        if module.params.get('routes'):
            for route in module.params.get('routes'):
                # to and via specified
                if not route.get('to') or not route.get('via'):
                    module.fail_json(msg='Route keys \'to\' and \'via\' must be specified on route dict')
                # on-link specified
                if route.get('on-link'):
                    on_link_values = ['true', 'false']
                    if route.get('on-link') not in on_link_values:
                        module.fail_json(msg='Routes on-link supported: {0}'.format(on_link_values))
                # metric specified
                if route.get('metric'):
                    if int(route.get('metric')) < 0:
                        module.fail_json(msg='Routes metric must be a positive integer value')
                # type specified
                if route.get('type'):
                    type_values = ['unicast', 'unreachable', 'blackhole', 'prohibit']
                    if route.get('type') not in type_values:
                        module.fail_json(msg='Routes type supported: {0}'.format(type_values))
                # scope specified
                if route.get('scope'):
                    scope_values = ['global', 'link', 'host']
                    if route.get('scope') not in scope_values:
                        module.fail_json(msg='Routes scope supported: {0}'.format(scope_values))
                # table specified
                # Verify /etc/iproute2/rt_tables before try to add a table.
                if route.get('table'):
                    if int(route.get('table')) < 1:
                        module.fail_json(msg='Routes table values must be positive integers starting from 1.')
                for route_keys in route.keys():
                    if route_keys not in ROUTES:
                        module.fail_json(msg='Routes subparams supported: {0}'.format(ROUTES))
        if module.params.get('routing-policy'):
            for rp in module.params.get('routing-policy'):
                # table specified
                # Verify /etc/iproute2/rt_tables before try to add a table.
                if rp.get('table'):
                    if int(rp.get('table')) < 1:
                        module.fail_json(msg='Routing-policy table values must be positive integers starting from 1.')
                # mark specified
                if rp.get('mark'):
                    if int(rp.get('mark')) < 1:
                        module.fail_json(msg='Routing-policy mark values must be positive integers starting from 1.')
                for rp_key in rp.keys():
                    if rp_key not in ROUTING_POLICY:
                        module.fail_json(msg='Routing-policy subparams supported: {0}'.format(ROUTING_POLICY))
        if module.params['type'] == 'bridges':
            for key in module.params:
                if module.params.get(key):
                    if key in BONDS:
                        module.fail_json(msg='BONDs options can not be defined with bridge Type')
                    if key in TUNNELS:
                        module.fail_json(msg='TUNNELs options can not be defined with bridge Type')
                    if key in VLANS:
                        module.fail_json(msg='VLANs options can not be defined with bridge Type')
                    if key in WIFIS:
                        module.fail_json(msg='WIFIs options can not be defined with bridge Type')
                    if key in AUTH:
                        module.fail_json(msg='AUTHs options can not be defined with bridge Type')
        if module.params['type'] == 'bonds':
            if not module.params.get('interfaces') or not module.params.get('bonding-mode'):
                module.fail_json(msg='bonds type require: [interfaces, bonding-mode]')
            for key in module.params:
                if module.params.get(key):
                    if key in BRIDGES:
                        module.fail_json(msg='BRIDGES options can not be defined with bonds Type')
                    if key in TUNNELS:
                        module.fail_json(msg='TUNNELs options can not be defined with bonds Type')
                    if key in VLANS:
                        module.fail_json(msg='VLANS options can not be defined with bonds Type')
                    if key in WIFIS:
                        module.fail_json(msg='WIFIs options can not be defined with bonds Type')
                    if key in AUTH:
                        module.fail_json(msg='AUTHs options can not be defined with bond Type')
                    # Verify bonds params dependences:
                    # lacpt-rate depends on bonding-mode == 802.3ad
                    # transmit-hash-policy depends on bonding-mode == 802.3ad or balance-tlb or balance-xor
                    # ad-select depends on bonding-mode == 802.3ad
                    # arp-all-target depends on bonding-mode == active-backup and arp-validate == true
                    # gratuitous-arp depends on bonding-mode == active-backup
                    # packets-per-slave depends on bonding-mode == balance-rr
                    # learn-packet-interval depends on bonding-mode == balance-tlb or balance-alb
                    # primary depends on bonding-mode == active-backup or balance-tlb or balance-alb
                    if key == 'lacpt-rate' or key == 'ad-select':
                        if module.params['bonding-mode'] != '802.3ad':
                            module.fail_json(msg='bonding-mode must be 802.3ad to define {0} param'.format(key))
                    if key == 'transmit-hash-policy':
                        if module.params['bonding-mode'] != '802.3ad' or module.params['bonding-mode'] != 'balance-tlb' \
                           or module.params['bonding-mode'] != 'balance-xor':
                            module.fail_json(msg='bonding-mode must be 802.3ad or balance-tlb or balance-xor to define {0} param'.format(key))
                    if key == 'arp-all-target':
                        if module.params['bonding-mode'] != 'active-backup' and not module.params['arp-validate']:
                            module.fail_json(msg='bonding-mode and arp-validade both must be active-backup and true to define {0} param'.format(key))
                    if key == 'gratuitous-arp':
                        if module.params['bonding-mode'] != 'active-backup':
                            module.fail_json(msg='bonding-mode must be active-backup to define {0} param'.format(key))
                    if key == 'packets-per-slave':
                        if module.params['bonding-mode'] != 'balance-rr':
                            module.fail_json(msg='bonding-mode must be balance-rr to define {0} param'.format(key))
                    if key == 'learn-packet-interval':
                        if module.params['bonding-mode'] != 'balance-tlb' or module.params['bonding-mode'] != 'balance-alb':
                            module.fail_json(msg='bonding-mode must be balance-tlb or balance-alb to define {0} param'.format(key))
                    if key == 'primary':
                        if module.params['bonding-mode'] != 'active-backup' or module.params['bonding-mode'] != 'balance-tlb' or \
                           module.params['bonding-mode'] != 'balance-alb':
                            module.fail_json(msg='bonding-mode must be active-backup or balance-tlb or balance-alb to define {0} param'.format(key))
        if module.params['type'] == 'tunnels':
            if not module.params.get('tunneling-mode') or not module.params.get('local') or not module.params.get('remote'):
                module.fail_json(msg='tunnels type require: [tunneling-mode, local, remote]')
            for key in module.params:
                if module.params.get(key):
                    if key in BONDS:
                        module.fail_json(msg='BONDs options can not be defined with tunnel Type')
                    if key in BRIDGES:
                        module.fail_json(msg='BRIDGES options can not be defined with tunnel Type')
                    if key in VLANS:
                        module.fail_json(msg='VLANs options can not be defined with tunnel Type')
                    if key in WIFIS:
                        module.fail_json(msg='WIFIs options can not be defined with tunnel Type')
                    if key in AUTH:
                        module.fail_json(msg='AUTHs options can not be defined with tunnel Type')
                    # gretap and ip6gretap tunneling-mode only supported if renderer == networkd
                    # isatap tunneling-mode only supported if renderer == NetworkManager
                    if key == 'tunneling-mode':
                        if module.params['tunneling-mode'] == 'gretap' or module.params['tunneling-mode'] == 'ip6gretap':
                            if module.params['renderer'] == 'NetworkManager':
                                module.fail_json(msg="gretap and ip6gretap tunneling-mode are only supported on networkd render")
                        if module.params['tunneling-mode'] == 'isatap':
                            if module.params['renderer'] == 'networkd' or not module.params.get('renderer'):
                                module.fail_json(msg="isatap tunneling-mode is only supported on NetworkManager render")
        if module.params['type'] == 'ethernets':
            for key in module.params:
                if module.params.get(key):
                    if key in BONDS:
                        module.fail_json(msg='BONDS options can not be defined with ethernets Type')
                    if key in BRIDGES:
                        module.fail_json(msg='BRIDGES options can not be defined with ethernets Type')
                    if key in TUNNELS:
                        module.fail_json(msg='TUNNELs options can not be defined with ethernets Type')
                    if key in VLANS:
                        module.fail_json(msg='VLANS options can not be defined with ethernets Type')
                    if key in WIFIS:
                        module.fail_json(msg='WIFIs options can not be defined with ethernets Type')
        if module.params['type'] == 'vlans':
            if not module.params.get('id') or not module.params.get('link'):
                module.fail_json(msg='vlans type require: [id, link]')
            for key in module.params:
                if module.params.get(key):
                    if key in BONDS:
                        module.fail_json(msg='BONDS options can not be defined with vlans Type')
                    if key in BRIDGES:
                        module.fail_json(msg='BRIDGES options can not be defined with vlans Type')
                    if key in TUNNELS:
                        module.fail_json(msg='TUNNELS options can not be defined with vlans Type')
                    if key in WIFIS:
                        module.fail_json(msg='WIFIs options can not be defined with vlans Type')
                    if key in AUTH:
                        module.fail_json(msg='AUTHs options can not be defined with vlans Type')
        if module.params['type'] == 'wifis':
            if not module.params.get('access-points-ssid') or not module.params.get('access-points-password') or not module.params.get('access-points-mode'):
                module.fail_json(msg='wifis type require: [access-points-ssid, access-points-password, access-points-mode]')
            for key in module.params:
                if module.params.get(key):
                    if key in BONDS:
                        module.fail_json(msg='BONDS options can not be defined with wifis Type')
                    if key in BRIDGES:
                        module.fail_json(msg='BRIDGES options can not be defined with wifis Type')
                    if key in TUNNELS:
                        module.fail_json(msg='TUNNELS options can not be defined with wifis Type')
                    if key in VLANS:
                        module.fail_json(msg='VLANS options can not be defined with wifis Type')
    else:
        for key in module.params:
            if module.params.get(key):
                if key in BRIDGES + BONDS + TUNNELS + VLANS + WIFIS + DHCP_OVERRIDES + GENERAL + PHYSICAL + AUTH:
                    module.fail_json(msg="When state is absent, just use this params:[filename, type, interface-id]")


def get_netplan_dict(params):
    # Alias to improve readability
    p_type = params.get('type')
    p_ifid = params.get('interface-id')

    netplan_dict = {'network': dict()}
    # Define default netplan version and renderes both to 2 and networkd
    if params.get('version'):
        netplan_dict['network']['version'] = params.get('version')
    else:
        netplan_dict['network']['version'] = 2
    if params.get('renderer'):
        netplan_dict['network']['renderer'] = params.get('renderer')
    else:
        netplan_dict['network']['renderer'] = 'networkd'
    netplan_dict['network'][p_type] = dict()
    netplan_dict['network'][p_type][p_ifid] = dict()
    for key in params:
        if key not in SPECIFC_ANSIBLE_NETPLAN and params.get(key):
            if key in MATCH:
                match_option = '{0}'.format(key.split('match-')[1])
                netplan_dict['network'][p_type][p_ifid]['match'] = dict()
                netplan_dict['network'][p_type][p_ifid]['match'][match_option] = params.get(key)
            # dhcp4-overrides
            elif key in DHCP_OVERRIDES:
                override_option = '{0}'.format(key.split('dhcp4-overrides-')[1])
                if not netplan_dict['network'][p_type][p_ifid].get('dhcp4-overrides'):
                    netplan_dict['network'][p_type][p_ifid]['dhcp4-overrides'] = dict()
                netplan_dict['network'][p_type][p_ifid]['dhcp4-overrides'][override_option] = params.get(key)
            elif key in BONDS:
                if not netplan_dict['network'][p_type][p_ifid].get('parameters'):
                    netplan_dict['network'][p_type][p_ifid]['parameters'] = dict()
                # Put bonding-mode param into mode param.
                # This is used because mode param is used in others locals like: Tunnels and wifis.
                if key == 'bonding-mode':
                    netplan_dict['network'][p_type][p_ifid]['parameters']['mode'] = params.get(key)
                else:
                    netplan_dict['network'][p_type][p_ifid]['parameters'][key] = params.get(key)
            elif key in BRIDGES:
                if not netplan_dict['network'][p_type][p_ifid].get('parameters'):
                    netplan_dict['network'][p_type][p_ifid]['parameters'] = dict()
                if key == 'path-cost':
                    if not netplan_dict['network'][p_type][p_ifid]['parameters'].get('path-cost'):
                        netplan_dict['network'][p_type][p_ifid]['parameters']['path-cost'] = dict()
                    for pc in params.get(key):
                        netplan_dict['network'][p_type][p_ifid]['parameters']['path-cost'][pc[0]] = pc[1]
                elif key == 'port-priority':
                    if not netplan_dict['network'][p_type][p_ifid]['parameters'].get('port-priority'):
                        netplan_dict['network'][p_type][p_ifid]['parameters']['port-priority'] = dict()
                    for pp in params.get(key):
                        netplan_dict['network'][p_type][p_ifid]['parameters']['port-priority'][pp[0]] = pp[1]
                else:
                    netplan_dict['network'][p_type][p_ifid]['parameters'][key] = params.get(key)
            elif key in TUNNELS:
                if key == 'tunneling-mode':
                    netplan_dict['network'][p_type][p_ifid]['mode'] = params.get(key)
                elif key == 'keys-input-output':
                    if not netplan_dict['network'][p_type][p_ifid]['mode'].get('keys'):
                        netplan_dict['network'][p_type][p_ifid]['mode']['keys'] = dict()
                    netplan_dict['network'][p_type][p_ifid]['mode']['keys']['input'] = params.get(key)[0]
                    netplan_dict['network'][p_type][p_ifid]['mode']['keys']['output'] = params.get(key)[1]
                else:
                    netplan_dict['network'][p_type][p_ifid][key] = params.get(key)
            elif key in WIFIS:
                if key != 'access-points-ssid':
                    wifi_option = key.split('access-points-')[1]
                    if not netplan_dict['network'][p_type][p_ifid].get('access-points'):
                        netplan_dict['network'][p_type][p_ifid]['access-points'] = dict()
                    if not netplan_dict['network'][p_type][p_ifid]['access-points'].get(params.get('access-points-ssid')):
                        netplan_dict['network'][p_type][p_ifid]['access-points'][params.get('access-points-ssid')] = dict()
                    netplan_dict['network'][p_type][p_ifid]['access-points'][params.get('access-points-ssid')][wifi_option] = params.get(key)
            elif key in AUTH:
                auth_option = key.split('auth-')[1]
                if p_type == 'wifis':
                    if not netplan_dict['network'][p_type][p_ifid].get('access-points'):
                        netplan_dict['network'][p_type][p_ifid]['access-points'] = dict()
                    if not netplan_dict['network'][p_type][p_ifid]['access-points'].get(params.get('access-points-ssid')):
                        netplan_dict['network'][p_type][p_ifid]['access-points'][params.get('access-points-ssid')] = dict()
                    if not netplan_dict['network'][p_type][p_ifid]['access-points'][params.get('access-points-ssid')].get('auth'):
                        netplan_dict['network'][p_type][p_ifid]['access-points'][params.get('access-points-ssid')]['auth'] = dict()
                    netplan_dict['network'][p_type][p_ifid]['access-points'][params.get('access-points-ssid')]['auth'][auth_option] = params.get(key)
                else:
                    # type == ethernets
                    if not netplan_dict['network'][p_type][p_ifid].get('auth'):
                        netplan_dict['network'][p_type][p_ifid]['auth'] = dict()
                    netplan_dict['network'][p_type][p_ifid]['auth'][auth_option] = params.get(key)
            else:
                netplan_dict['network'][p_type][p_ifid][key] = params.get(key)
    return netplan_dict


def main():
    argument_spec = {
        'filename': {'required': True},
        'renderer': {'choices': ['networkd', 'NetworkManager'],
                     'required': False},
        'version': {'required': False},
        'type': {'choices': ['bridges', 'bonds', 'tunnels', 'ethernets',
                             'vlans', 'wifis'],
                 'required': True},
        'interface-id': {'required': True},
        'state': {'choices': ['present', 'absent'], 'required': True},
        'dhcp4': {'required': False},
        'dhcp6': {'required': False},
        'ipv6-privacy': {'required': False, 'type': 'bool'},
        'link-local': {'choices': ['ipv4', 'ipv6'],
                       'required': False,
                       'type': 'list'},
        'critical': {'required': False,
                     'type': 'bool'},
        'dhcp-identifier': {'required': False},
        'accept-ra': {'required': False, 'type': 'bool'},
        'addresses': {'required': False,
                      'type': 'list'},
        'gateway4': {'required': False},
        'gateway6': {'required': False},
        'nameservers-search': {'required': False,
                               'type': 'list'},
        'nameservers-addresses': {'required': False,
                                  'type': 'list'},
        'macaddress': {'required': False},
        'mtu': {'required': False, 'type': 'int'},
        'optional': {'required': False, 'type': 'bool'},
        'optional-addresses': {'required': False, 'type': 'list'},
        'match-name': {'required': False},
        'match-macaddress': {'required': False},
        'match-driver': {'required': False},
        'set-name': {'required': False},
        'wakeonlan': {'required': False, 'type': 'bool'},
        'dhcp4-overrides-use-dns': {'required': False, 'type': 'bool'},
        'dhcp4-overrides-use-ntp': {'required': False, 'type': 'bool'},
        'dhcp4-overrides-use-hostname': {'required': False, 'type': 'bool'},
        'dhcp4-overrides-send-hostname': {'required': False, 'type': 'bool'},
        'dhcp4-overrides-hostname': {'required': False},
        'dhcp6-overrides-use-dns': {'required': False, 'type': 'bool'},
        'dhcp6-overrides-use-ntp': {'required': False, 'type': 'bool'},
        'dhcp6-overrides-use-hostname': {'required': False, 'type': 'bool'},
        'dhcp6-overrides-send-hostname': {'required': False, 'type': 'bool'},
        'dhcp6-overrides-hostname': {'required': False},
        'routes': {'required': False, 'type': 'list'},
        'routing-policy': {'required': False, 'type': 'list'},
        'auth-key-management': {'choices': ['none', 'psk', 'eap', '802.1x'],
                                'required': False},
        'auth-password': {'required': False},
        'auth-method': {'choices': ['tls', 'peap', 'ttls'], 'required': False},
        'auth-identity': {'required': False},
        'auth-anonymous-identity': {'required': False},
        'auth-ca-certificate': {'required': False},
        'auth-client-certificate': {'required': False},
        'auth-client-key': {'required': False},
        'auth-client-key-password': {'required': False},
        'interfaces': {'required': False, 'type': 'list'},
        'bonding-mode': {'choices': ['balance-rr', 'active-backup', 'balance-xor',
                                     'broadcast', '802.3ad', 'balance-tlb',
                                     'balance-alb'],
                         'required': False},
        'lacp-rate': {'choices': ['slow', 'fast'],
                      'required': False},
        'mii-monitor-interval': {'required': False, 'type': 'int'},
        'min-links': {'required': False, 'type': 'int'},
        'transmit-hash-policy': {'choices': ['layer2', 'layer3+4', 'layer2+3',
                                             'encap2+3', 'encap3+4'],
                                 'required': False},
        'ad-select': {'choices': ['stable', 'bandwidth', 'count'],
                      'required': False},
        'all-slaves-active': {'required': False, 'type': 'bool'},
        'arp-interval': {'required': False, 'type': 'int'},
        'arp-ip-targets': {'required': False, 'type': 'list'},
        'arp-validate': {'choices': ['none', 'active', 'backup', 'all'],
                         'required': False},
        'arp-all-targets': {'choices': ['any', 'all'], 'required': False},
        'up-delay': {'required': False, 'type': 'int'},
        'down-delay': {'required': False, 'type': 'int'},
        'fail-over-mac-policy': {'choices': ['none', 'active', 'follow'],
                                 'required': False},
        'gratuitous-arp': {'required': False, 'type': 'int'},
        'packets-per-slave': {'required': False, 'type': 'int'},
        'primary-reselect-policy': {'choices': ['always', 'better',
                                                'failure'],
                                    'required': False},
        'resend-igmp': {'required': False, 'type': 'int'},
        'primary': {'required': False},
        'learn-packet-interval': {'required': False, 'type': 'int'},
        'ageing-time': {'required': False, 'type': 'int'},
        'priority': {'required': False, 'type': 'int'},
        'port-priority': {'required': False, 'type': 'list'},
        'forward-delay': {'required': False, 'type': 'int'},
        'hello-time': {'required': False, 'type': 'int'},
        'max-age': {'required': False, 'type': 'int'},
        'path-cost': {'required': False, 'type': 'list'},
        'stp': {'required': False, 'type': 'bool'},
        'tunneling-mode': {'choices': ['sit', 'gre', 'ip6gre', 'ipip', 'ipip6',
                                       'ip6ip6', 'vti', 'vti6', 'gretap',
                                       'ip6gretap', 'isatap'],
                           'required': False},
        'local': {'required': False},
        'remote': {'required': False},
        'id': {'required': False, 'type': 'int'},
        'key': {'required': False, 'type': 'int'},
        'keys-input-output': {'required': False, 'type': 'list'},
        'link': {'required': False},
        'access-points-ssid': {'required': False},
        'access-points-password': {'required': False},
        'access-points-mode': {'choices': ['infrastructure', 'ap', 'adhoc'],
                               'required': False}
    }

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    if not HAS_YAML:
        module.fail_json(msg='The PyYAML Python module is required')

    validate_args(module)

    NETPLAN_FILENAME = '{0}/{1}.yaml'.format(NETPLAN_PATH, module.params.get('filename'))

    # Alias to improve readability
    p_type = module.params.get('type')
    p_ifid = module.params.get('interface-id')

    if os.path.isfile(NETPLAN_FILENAME):
        with open(NETPLAN_FILENAME, 'r') as yamlfile:
            netplan_file_dict = yaml.load(yamlfile)
        netplan_module_dict = get_netplan_dict(module.params)

        # Add interface
        if module.params.get('state') == 'present':
            if netplan_file_dict == netplan_module_dict:
                module.exit_json(changed=False)
            else:
                if not netplan_file_dict['network'].get(p_type):
                    netplan_file_dict['network'][p_type] = dict()
                # Verify if interface exist and if dicts are equal
                if netplan_file_dict['network'][p_type].get(p_ifid):
                    if netplan_file_dict['network'][p_type][p_ifid] == netplan_module_dict['network'][p_type][p_ifid]:
                        module.exit_json(changed=False)
                netplan_file_dict['network'][p_type][p_ifid] = dict()
                netplan_file_dict['network'][p_type][p_ifid] = netplan_module_dict['network'][p_type][p_ifid]
                with open(NETPLAN_FILENAME, 'w') as yamlfile:
                    yaml.dump(netplan_file_dict, yamlfile, default_flow_style=False)
                module.run_command('netplan apply', check_rc=True)
                module.exit_json(changed=True)
        # Remove interface
        else:
            if not netplan_file_dict['network'].get(p_type):
                module.exit_json(changed=False)
            if not netplan_file_dict['network'][p_type].pop(p_ifid):
                module.exit_json(changed=False)
            else:
                # Verify if type key is None to remove from dict
                if not netplan_file_dict['network'].get(p_type):
                    netplan_file_dict['network'].pop(p_type)
                with open(NETPLAN_FILENAME, 'w') as yamlfile:
                    yaml.dump(netplan_file_dict, yamlfile, default_flow_style=False)
                module.run_command('netplan apply', check_rc=True)
                module.exit_json(changed=True)
    else:
        if module.params.get('state') == 'present':
            netplan_dict = get_netplan_dict(module.params)
            with open(NETPLAN_FILENAME, 'w') as yamlfile:
                yaml.dump(netplan_dict, yamlfile, default_flow_style=False)
            module.run_command('netplan apply', check_rc=True)
            module.exit_json(changed=True)
        else:
            module.fail_json(msg='Interface {0} can not be removed because {1} file does not exist'.format(p_ifid, NETPLAN_FILENAME))


if __name__ == '__main__':
    main()
