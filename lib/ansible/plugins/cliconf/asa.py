#
# (c) 2017 Red Hat Inc.
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import re
import json

from itertools import chain

from ansible.module_utils._text import to_bytes, to_text
from ansible.module_utils.network_common import to_list
from ansible.plugins.cliconf import CliconfBase, enable_mode


class Cliconf(CliconfBase):

    def get_device_info(self):
        device_info = {}

        device_info['network_os'] = 'asa'
        reply = self.get(b'show version')
        data = to_text(reply, errors='surrogate_or_strict').strip()

        match = re.search(r'Version (\S+),', data)
        if match:
            device_info['network_os_version'] = match.group(1)

        match = re.search(r'^Model Id:\s+(.+) \(revision', data, re.M)
        if match:
            device_info['network_os_model'] = match.group(1)

        match = re.search(r'^(.+) up', data, re.M)
        if match:
            device_info['network_os_hostname'] = match.group(1)

        return device_info

    @enable_mode
    def get_config(self, source='running'):
        if source not in ('running', 'startup'):
            return self.invalid_params("fetching configuration from %s is not supported" % source)
        if source == 'running':
            cmd = b'show running-config all'
        else:
            cmd = b'show startup-config'
        return self.send_command(cmd)

    @enable_mode
    def edit_config(self, command):
        for cmd in chain([b'configure terminal'], to_list(command), [b'end']):
            self.send_command(cmd)

    def get(self, *args, **kwargs):
        return self.send_command(*args, **kwargs)

    def get_capabilities(self):
        result = {}
        result['rpc'] = self.get_base_rpc()
        result['network_api'] = 'cliconf'
        result['device_info'] = self.get_device_info()
        return json.dumps(result)
