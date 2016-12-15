#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2016, Adam Števko <adam.stevko@gmail.com>
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible. If not, see <http://www.gnu.org/licenses/>.
#

DOCUMENTATION = '''
---
module: dladm_iptun
short_description: Manage IP tunnel interfaces on Solaris/illumos systems.
description:
    - Manage IP tunnel interfaces on Solaris/illumos systems.
version_added: "2.3"
author: Adam Števko (@xen0l)
options:
    name:
        description:
            - IP tunnel interface name.
        required: true
        aliases: [ "tunnel", "link" ]
    temporary:
        description:
            - Specifies that the IP tunnel interface is temporary. Temporary IP tunnel
              interfaces do not persist across reboots.
        required: false
        default: false
    type:
        description:
            - Specifies the type of tunnel to be created.
        required: false
        default: "ipv4"
        choices: [ "ipv4", "ipv6", "6to4" ]
    local_address:
        description:
            - Literat IP address or hostname corresponding to the tunnel source.
        required: false
        aliases: [ "local" ]
    remote_address:
        description:
            - Literal IP address or hostname corresponding to the tunnel destination.
        required: false
        aliases: [ "remote" ]
    state:
        description:
            - Create or delete Solaris/illumos VNIC.
        required: false
        default: "present"
        choices: [ "present", "absent" ]
'''

EXAMPLES = '''
# Create IPv4 tunnel interface 'iptun0'
dladm_iptun: name=iptun0 local_address=192.0.2.23 remote_address=203.0.113.10 state=present

# Change IPv4 tunnel remote address
dladm_iptun: name=iptun0 type=ipv4 local_address=192.0.2.23 remote_address=203.0.113.11

# Create IPv6 tunnel interface 'tun0'
dladm_iptun: name=tun0 type=ipv6 local_address=192.0.2.23 remote_address=203.0.113.42

# Remove 'iptun0' tunnel interface
dladm_iptun: name=iptun0 state=absent
'''

SUPPORTED_TYPES = ['ipv4', 'ipv6', '6to4']


class IPTun(object):

    def __init__(self, module):
        self.module = module

        self.name = module.params['name']
        self.type = module.params['type']
        self.local_address = module.params['local_address']
        self.remote_address = module.params['remote_address']
        self.temporary = module.params['temporary']
        self.state = module.params['state']

        self.dladm_bin = self.module.get_bin_path('dladm', True)

    def iptun_exists(self):
        cmd = [self.dladm_bin]

        cmd.append('show-iptun')
        cmd.append(self.name)

        (rc, _, _) = self.module.run_command(cmd)

        if rc == 0:
            return True
        else:
            return False

    def create_iptun(self):
        cmd = [self.dladm_bin]

        cmd.append('create-iptun')

        if self.temporary:
            cmd.append('-t')

        cmd.append('-T')
        cmd.append(self.type)
        cmd.append('-a')
        cmd.append('local=' + self.local_address + ',remote=' + self.remote_address)
        cmd.append(self.name)

        return self.module.run_command(cmd)

    def delete_iptun(self):
        cmd = [self.dladm_bin]

        cmd.append('delete-iptun')

        if self.temporary:
            cmd.append('-t')
        cmd.append(self.name)

        return self.module.run_command(cmd)

    def update_iptun(self):
        cmd = [self.dladm_bin]

        cmd.append('modify-iptun')

        if self.temporary:
            cmd.append('-t')
        cmd.append('-a')
        cmd.append('local=' + self.local_address + ',remote=' + self.remote_address)
        cmd.append(self.name)

        return self.module.run_command(cmd)

    def _query_iptun_props(self):
        cmd = [self.dladm_bin]

        cmd.append('show-iptun')
        cmd.append('-p')
        cmd.append('-c')
        cmd.append('link,type,flags,local,remote')
        cmd.append(self.name)

        return self.module.run_command(cmd)

    def iptun_needs_updating(self):
        (rc, out, err) = self._query_iptun_props()

        NEEDS_UPDATING = False

        if rc == 0:
            configured_local, configured_remote = out.split(':')[3:]

            if self.local_address != configured_local or self.remote_address != configured_remote:
                NEEDS_UPDATING = True

            return NEEDS_UPDATING
        else:
            self.module.fail_json(msg='Failed to query tunnel interface %s properties' % self.name,
                                  err=err,
                                  rc=rc)



def main():
    module = AnsibleModule(
        argument_spec=dict(
            name=dict(required=True, type='str'),
            type=dict(default='ipv4', type='str', aliases=['tunnel_type'],
                      choices=SUPPORTED_TYPES),
            local_address=dict(type='str', aliases=['local']),
            remote_address=dict(type='str', aliases=['remote']),
            temporary=dict(default=False, type='bool'),
            state=dict(default='present', choices=['absent', 'present']),
        ),
        required_if=[
            ['state', 'present', ['local_address', 'remote_address']],
        ],
        supports_check_mode=True
    )

    iptun = IPTun(module)

    rc = None
    out = ''
    err = ''
    result = {}
    result['name'] = iptun.name
    result['type'] = iptun.type
    result['local_address'] = iptun.local_address
    result['remote_address'] = iptun.remote_address
    result['state'] = iptun.state
    result['temporary'] = iptun.temporary

    if iptun.state == 'absent':
        if iptun.iptun_exists():
            if module.check_mode:
                module.exit_json(changed=True)
            (rc, out, err) = iptun.delete_iptun()
            if rc != 0:
                module.fail_json(name=iptun.name, msg=err, rc=rc)
    elif iptun.state == 'present':
        if not iptun.iptun_exists():
            if module.check_mode:
                module.exit_json(changed=True)
            (rc, out, err) = iptun.create_iptun()

            if rc is not None and rc != 0:
                module.fail_json(name=iptun.name, msg=err, rc=rc)
        else:
            if iptun.iptun_needs_updating():
                (rc, out, err) = ipyim.update_iptun()
                if rc != 0:
                    module.fail_json(msg='Error while updating tunnel interface: "%s"' % err,
                                     name=iptun.name,
                                     stderr=err,
                                     rc=rc)

    if rc is None:
        result['changed'] = False
    else:
        result['changed'] = True

    if out:
        result['stdout'] = out
    if err:
        result['stderr'] = err

    module.exit_json(**result)

from ansible.module_utils.basic import *
main()
