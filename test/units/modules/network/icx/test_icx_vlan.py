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

# Make coding more python3-ish
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type
from units.compat.mock import patch
from ansible.modules.network.icx import icx_vlan
from units.modules.utils import set_module_args
from .icx_module import TestICXModule, load_fixture


class TestICXVlanModule(TestICXModule):

    module = icx_vlan

    def setUp(self):
        super(TestICXVlanModule, self).setUp()
        self.mock_exec_command = patch('ansible.modules.network.icx.icx_vlan.exec_command')
        self.exec_command = self.mock_exec_command.start()

        self.mock_load_config = patch('ansible.modules.network.icx.icx_vlan.load_config')
        self.load_config = self.mock_load_config.start()

        self.mock_get_config = patch('ansible.modules.network.icx.icx_vlan.get_config')
        self.get_config = self.mock_get_config.start()

        self.mock_get_env_diff = patch('ansible.modules.network.icx.icx_vlan.get_env_diff')
        self.get_env_diff = self.mock_get_env_diff.start()
        self.set_running_config()

    def tearDown(self):
        super(TestICXVlanModule, self).tearDown()
        self.mock_exec_command.stop()
        self.mock_load_config.stop()
        self.mock_get_config.stop()
        self.mock_get_env_diff.stop()

    def load_fixtures(self, commands=None):
        # def load_env_value(*args,**kwargs):
        #     module,commands = args
        #     if module.params['compare'] is True:
        #         return 'yes'
        #     else:
        #         return False
        compares = None

        def load_file(*args, **kwargs):
            module = args
            for arg in args:
                if arg.params['check_running_config'] is not None:
                    compares = arg.params['check_running_config']
                    break
                else:
                    compares = None
            env = self.get_running_config(compares)
            self.get_env_diff.return_value = self.get_running_config(compare=compares)
            if env is True:
                self.exec_command.return_value = (0, load_fixture('icx_vlan_config').strip(), None)
                return load_fixture('icx_banner_show_banner.txt').strip()
            else:
                self.exec_command.return_value = (0, ''.strip(), None)
                return ''

        self.get_config.side_effect = load_file
        self.load_config.return_value = None
        # self.get_env_diff.side_effect=load_env_value
        # else:
        #     self.get_config.return_value = load_fixture('icx_vlan_config')
        #     self.exec_command.return_value = (0, load_fixture('icx_vlan_config').strip(), None)
        #     self.load_config.return_value = None
        #     self.get_env_diff.return_value='yes'

    def test_icx_vlan_set_tagged_port(self):
        set_module_args(dict(name='test_vlan', vlan_id=5, tagged=dict(name=['ethernet 1/1/40 to 1/1/43', 'lag 44'])))
        if not self.ENV_ICX_USE_DIFF:
            result = self.execute_module(changed=True)
            expected_commands = [
                'vlan 5',
                'vlan 5 name test_vlan',
                'tagged ethernet 1/1/40 to 1/1/43',
                'tagged lag 44'
            ]
            self.assertEqual(result['commands'], expected_commands)
        else:
            result = self.execute_module(changed=True)
            expected_commands = [
                'vlan 5',
                'vlan 5 name test_vlan',
                'tagged ethernet 1/1/40 to 1/1/43',
                'tagged lag 44'
            ]
            self.assertEqual(result['commands'], expected_commands)

    def test_icx_vlan_add_untagged_port(self):
        set_module_args(dict(name='test_vlan', vlan_id=3, interfaces=dict(name=['ethernet 1/1/10', 'lag 5'])))

        if not self.ENV_ICX_USE_DIFF:
            result = self.execute_module(changed=True)
            expected_commands = [
                'vlan 3',
                'vlan 3 name test_vlan',
                'untagged ethernet 1/1/10',
                'untagged lag 5',
            ]
            self.assertEqual(result['commands'], expected_commands)
        else:
            result = self.execute_module(changed=True)
            expected_commands = [
                'vlan 3',
                'vlan 3 name test_vlan',
                'untagged lag 5',
                'untagged ethernet 1/1/10'
            ]
            self.assertEqual(result['commands'], expected_commands)

    def test_icx_vlan_purge_untagged_port(self):
        set_module_args(dict(vlan_id=3, tagged=dict(name=['ethernet 1/1/40 to 1/1/43', 'lag 44'], purge=True)))
        if not self.ENV_ICX_USE_DIFF:
            result = self.execute_module(changed=True)
            expected_commands = [
                'vlan 3',
                'tagged ethernet 1/1/40 to 1/1/43',
                'tagged lag 44'
            ]
            self.assertEqual(result['commands'], expected_commands)
        else:
            result = self.execute_module(changed=True)
            expected_commands = [
                'vlan 3',
                'no tagged ethernet 1/1/31',
                'no tagged ethernet 1/1/9',
                'no tagged ethernet 1/1/11',
                'no tagged lag 13',
                'no tagged ethernet 1/1/10'
            ]
            self.assertEqual(result['commands'], expected_commands)

    def test_icx_vlan_enable_ip_arp_inspection(self):
        set_module_args(dict(vlan_id=5, ip_arp_inspection=True))
        if not self.ENV_ICX_USE_DIFF:
            result = self.execute_module(changed=True)
            expected_commands = [
                'vlan 5',
                'ip arp inspection vlan 5'
            ]
            self.assertEqual(result['commands'], expected_commands)
        else:
            result = self.execute_module(changed=True)
            expected_commands = [
                'vlan 5',
                'ip arp inspection vlan 5'
            ]
            self.assertEqual(result['commands'], expected_commands)

    def test_icx_vlan_enable_ip_dhcp_snooping(self):
        set_module_args(dict(vlan_id=5, ip_dhcp_snooping=True))
        if not self.ENV_ICX_USE_DIFF:
            result = self.execute_module(changed=True)
            expected_commands = [
                'vlan 5',
                'ip dhcp snooping vlan 5'
            ]
            self.assertEqual(result['commands'], expected_commands)
        else:
            result = self.execute_module(changed=True)
            expected_commands = [
                'vlan 5',
                'ip dhcp snooping vlan 5'
            ]
            self.assertEqual(result['commands'], expected_commands)

    def test_icx_vlan_aggregate(self):
        aggregate = [
            dict(vlan_id=9, name='vlan_9', interfaces=dict(name=['ethernet 1/1/40 to 1/1/43', 'ethernet 1/1/44']), ip_arp_inspection=True),
            dict(vlan_id=7, name='vlan_7', interfaces=dict(name=['ethernet 1/1/20 to 1/1/23', 'ethernet 1/1/24']), ip_dhcp_snooping=True),
        ]
        set_module_args(dict(aggregate=aggregate))
        if not self.ENV_ICX_USE_DIFF:
            result = self.execute_module(changed=True)
            expected_commands = [
                'vlan 9',
                'vlan 9 name vlan_9',
                'untagged ethernet 1/1/40 to 1/1/43',
                'untagged ethernet 1/1/44',
                'ip arp inspection vlan 9',
                'vlan 7',
                'vlan 7 name vlan_7',
                'untagged ethernet 1/1/20 to 1/1/23',
                'untagged ethernet 1/1/24',
                'ip dhcp snooping vlan 7',
            ]
            self.assertEqual(result['commands'], expected_commands)
        else:
            result = self.execute_module(changed=True)
            expected_commands = [
                'vlan 9',
                'vlan 9 name vlan_9',
                'untagged ethernet 1/1/40 to 1/1/43',
                'untagged ethernet 1/1/44',
                'ip arp inspection vlan 9',
                'vlan 7',
                'vlan 7 name vlan_7',
                'untagged ethernet 1/1/20 to 1/1/23',
                'untagged ethernet 1/1/24',
                'ip dhcp snooping vlan 7',
            ]
            self.assertEqual(result['commands'], expected_commands)

    def test_icx_vlan_interfaces_cndt(self):
        set_module_args(dict(vlan_id=3, associated_interfaces=['ethernet 1/1/20 to 1/1/22', 'ethernet 1/1/27', 'lag 11 to 12']))
        if not self.ENV_ICX_USE_DIFF:
            self.execute_module(failed=True)
        else:
            self.execute_module(changed=False)

    def test_icx_vlan_tagged_cndt(self):
        set_module_args(dict(vlan_id=3, associated_tagged=['ethernet 1/1/9 to 1/1/11', 'ethernet 1/1/31', 'lag 13']))
        if not self.ENV_ICX_USE_DIFF:
            self.execute_module(failed=True)
        else:
            self.execute_module(changed=False)

    def test_icx_vlan_purge(self):
        set_module_args(dict(vlan_id=3, purge=True))
        if not self.ENV_ICX_USE_DIFF:
            result = self.execute_module(changed=False)
            expected_commands = []
            self.assertEqual(result['commands'], expected_commands)
        else:
            result = self.execute_module(changed=True)
            expected_commands = [
                'no vlan 6',
                'no vlan 10',
                'no vlan 21'
            ]
            self.assertEqual(result['commands'], expected_commands)

    def test_icx_vlan_stp_802_1w(self):
        stp_spec = dict(dict(type='802-1w', priority='20', enabled=True))
        set_module_args(dict(vlan_id=3, interfaces=dict(name=['ethernet 1/1/40']), stp=stp_spec))
        if not self.ENV_ICX_USE_DIFF:
            result = self.execute_module(changed=True)
            expected_commands = [
                'vlan 3',
                'untagged ethernet 1/1/40',
                'spanning-tree 802-1w',
                'spanning-tree 802-1w priority 20'
            ]
            self.assertEqual(result['commands'], expected_commands)
        else:
            result = self.execute_module(changed=True)
            expected_commands = [
                'vlan 3',
                'untagged ethernet 1/1/40',
                'spanning-tree 802-1w',
                'spanning-tree 802-1w priority 20'
            ]
            self.assertEqual(result['commands'], expected_commands)

    def test_icx_vlan_stp_rstp_absent(self):
        stp_spec = dict(dict(type='rstp', enabled=False))
        set_module_args(dict(vlan_id=3, interfaces=dict(name=['ethernet 1/1/40']), stp=stp_spec))
        if not self.ENV_ICX_USE_DIFF:
            result = self.execute_module(changed=True)
            expected_commands = [
                'vlan 3',
                'untagged ethernet 1/1/40',
                'no spanning-tree'
            ]
            self.assertEqual(result['commands'], expected_commands)
        else:
            result = self.execute_module(changed=True)
            expected_commands = [
                'vlan 3',
                'untagged ethernet 1/1/40',
                'no spanning-tree'
            ]
            self.assertEqual(result['commands'], expected_commands)

    def test_icx_vlan_stp_802_1w_absent(self):
        stp_spec = dict(dict(type='802-1w', enabled=False))
        set_module_args(dict(vlan_id=3, stp=stp_spec))
        if not self.ENV_ICX_USE_DIFF:
            result = self.execute_module(changed=True)
            expected_commands = [
                'vlan 3',
                'no spanning-tree 802-1w',
                'no spanning-tree'
            ]
            self.assertEqual(result['commands'], expected_commands)
        else:
            result = self.execute_module(changed=True)
            expected_commands = [
                'vlan 3',
                'no spanning-tree 802-1w',
                'no spanning-tree'
            ]
            self.assertEqual(result['commands'], expected_commands)
