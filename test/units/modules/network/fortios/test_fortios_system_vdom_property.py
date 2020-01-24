# Copyright 2019 Fortinet, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <https://www.gnu.org/licenses/>.

# Make coding more python3-ish
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
import json
import pytest
from mock import ANY
from ansible.module_utils.network.fortios.fortios import FortiOSHandler

try:
    from ansible.modules.network.fortios import fortios_system_vdom_property
except ImportError:
    pytest.skip("Could not load required modules for testing", allow_module_level=True)


@pytest.fixture(autouse=True)
def connection_mock(mocker):
    connection_class_mock = mocker.patch('ansible.modules.network.fortios.fortios_system_vdom_property.Connection')
    return connection_class_mock


fos_instance = FortiOSHandler(connection_mock)


def test_system_vdom_property_creation(mocker):
    schema_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.schema')

    set_method_result = {'status': 'success', 'http_method': 'POST', 'http_status': 200}
    set_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.set', return_value=set_method_result)

    input_data = {
        'username': 'admin',
        'state': 'present',
        'system_vdom_property': {
            'custom_service': 'test_value_3',
            'description': 'test_value_4',
            'dialup_tunnel': 'test_value_5',
            'firewall_address': 'test_value_6',
            'firewall_addrgrp': 'test_value_7',
            'firewall_policy': 'test_value_8',
            'ipsec_phase1': 'test_value_9',
            'ipsec_phase1_interface': 'test_value_10',
            'ipsec_phase2': 'test_value_11',
            'ipsec_phase2_interface': 'test_value_12',
            'log_disk_quota': 'test_value_13',
            'name': 'default_name_14',
            'onetime_schedule': 'test_value_15',
            'proxy': 'test_value_16',
            'recurring_schedule': 'test_value_17',
            'service_group': 'test_value_18',
            'session': 'test_value_19',
            'snmp_index': '20',
            'sslvpn': 'test_value_21',
            'user': 'test_value_22',
            'user_group': 'test_value_23'
        },
        'vdom': 'root'}

    is_error, changed, response = fortios_system_vdom_property.fortios_system(input_data, fos_instance)

    expected_data = {
        'custom-service': 'test_value_3',
        'description': 'test_value_4',
        'dialup-tunnel': 'test_value_5',
        'firewall-address': 'test_value_6',
        'firewall-addrgrp': 'test_value_7',
        'firewall-policy': 'test_value_8',
        'ipsec-phase1': 'test_value_9',
        'ipsec-phase1-interface': 'test_value_10',
        'ipsec-phase2': 'test_value_11',
        'ipsec-phase2-interface': 'test_value_12',
        'log-disk-quota': 'test_value_13',
        'name': 'default_name_14',
                'onetime-schedule': 'test_value_15',
                'proxy': 'test_value_16',
                'recurring-schedule': 'test_value_17',
                'service-group': 'test_value_18',
                'session': 'test_value_19',
                'snmp-index': '20',
                'sslvpn': 'test_value_21',
                'user': 'test_value_22',
                'user-group': 'test_value_23'
    }

    set_method_mock.assert_called_with('system', 'vdom-property', data=expected_data, vdom='root')
    schema_method_mock.assert_not_called()
    assert not is_error
    assert changed
    assert response['status'] == 'success'
    assert response['http_status'] == 200


def test_system_vdom_property_creation_fails(mocker):
    schema_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.schema')

    set_method_result = {'status': 'error', 'http_method': 'POST', 'http_status': 500}
    set_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.set', return_value=set_method_result)

    input_data = {
        'username': 'admin',
        'state': 'present',
        'system_vdom_property': {
            'custom_service': 'test_value_3',
            'description': 'test_value_4',
            'dialup_tunnel': 'test_value_5',
            'firewall_address': 'test_value_6',
            'firewall_addrgrp': 'test_value_7',
            'firewall_policy': 'test_value_8',
            'ipsec_phase1': 'test_value_9',
            'ipsec_phase1_interface': 'test_value_10',
            'ipsec_phase2': 'test_value_11',
            'ipsec_phase2_interface': 'test_value_12',
            'log_disk_quota': 'test_value_13',
            'name': 'default_name_14',
            'onetime_schedule': 'test_value_15',
            'proxy': 'test_value_16',
            'recurring_schedule': 'test_value_17',
            'service_group': 'test_value_18',
            'session': 'test_value_19',
            'snmp_index': '20',
            'sslvpn': 'test_value_21',
            'user': 'test_value_22',
            'user_group': 'test_value_23'
        },
        'vdom': 'root'}

    is_error, changed, response = fortios_system_vdom_property.fortios_system(input_data, fos_instance)

    expected_data = {
        'custom-service': 'test_value_3',
        'description': 'test_value_4',
        'dialup-tunnel': 'test_value_5',
        'firewall-address': 'test_value_6',
        'firewall-addrgrp': 'test_value_7',
        'firewall-policy': 'test_value_8',
        'ipsec-phase1': 'test_value_9',
        'ipsec-phase1-interface': 'test_value_10',
        'ipsec-phase2': 'test_value_11',
        'ipsec-phase2-interface': 'test_value_12',
        'log-disk-quota': 'test_value_13',
        'name': 'default_name_14',
                'onetime-schedule': 'test_value_15',
                'proxy': 'test_value_16',
                'recurring-schedule': 'test_value_17',
                'service-group': 'test_value_18',
                'session': 'test_value_19',
                'snmp-index': '20',
                'sslvpn': 'test_value_21',
                'user': 'test_value_22',
                'user-group': 'test_value_23'
    }

    set_method_mock.assert_called_with('system', 'vdom-property', data=expected_data, vdom='root')
    schema_method_mock.assert_not_called()
    assert is_error
    assert not changed
    assert response['status'] == 'error'
    assert response['http_status'] == 500


def test_system_vdom_property_removal(mocker):
    schema_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.schema')

    delete_method_result = {'status': 'success', 'http_method': 'POST', 'http_status': 200}
    delete_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.delete', return_value=delete_method_result)

    input_data = {
        'username': 'admin',
        'state': 'absent',
        'system_vdom_property': {
            'custom_service': 'test_value_3',
            'description': 'test_value_4',
            'dialup_tunnel': 'test_value_5',
            'firewall_address': 'test_value_6',
            'firewall_addrgrp': 'test_value_7',
            'firewall_policy': 'test_value_8',
            'ipsec_phase1': 'test_value_9',
            'ipsec_phase1_interface': 'test_value_10',
            'ipsec_phase2': 'test_value_11',
            'ipsec_phase2_interface': 'test_value_12',
            'log_disk_quota': 'test_value_13',
            'name': 'default_name_14',
            'onetime_schedule': 'test_value_15',
            'proxy': 'test_value_16',
            'recurring_schedule': 'test_value_17',
            'service_group': 'test_value_18',
            'session': 'test_value_19',
            'snmp_index': '20',
            'sslvpn': 'test_value_21',
            'user': 'test_value_22',
            'user_group': 'test_value_23'
        },
        'vdom': 'root'}

    is_error, changed, response = fortios_system_vdom_property.fortios_system(input_data, fos_instance)

    delete_method_mock.assert_called_with('system', 'vdom-property', mkey=ANY, vdom='root')
    schema_method_mock.assert_not_called()
    assert not is_error
    assert changed
    assert response['status'] == 'success'
    assert response['http_status'] == 200


def test_system_vdom_property_deletion_fails(mocker):
    schema_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.schema')

    delete_method_result = {'status': 'error', 'http_method': 'POST', 'http_status': 500}
    delete_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.delete', return_value=delete_method_result)

    input_data = {
        'username': 'admin',
        'state': 'absent',
        'system_vdom_property': {
            'custom_service': 'test_value_3',
            'description': 'test_value_4',
            'dialup_tunnel': 'test_value_5',
            'firewall_address': 'test_value_6',
            'firewall_addrgrp': 'test_value_7',
            'firewall_policy': 'test_value_8',
            'ipsec_phase1': 'test_value_9',
            'ipsec_phase1_interface': 'test_value_10',
            'ipsec_phase2': 'test_value_11',
            'ipsec_phase2_interface': 'test_value_12',
            'log_disk_quota': 'test_value_13',
            'name': 'default_name_14',
            'onetime_schedule': 'test_value_15',
            'proxy': 'test_value_16',
            'recurring_schedule': 'test_value_17',
            'service_group': 'test_value_18',
            'session': 'test_value_19',
            'snmp_index': '20',
            'sslvpn': 'test_value_21',
            'user': 'test_value_22',
            'user_group': 'test_value_23'
        },
        'vdom': 'root'}

    is_error, changed, response = fortios_system_vdom_property.fortios_system(input_data, fos_instance)

    delete_method_mock.assert_called_with('system', 'vdom-property', mkey=ANY, vdom='root')
    schema_method_mock.assert_not_called()
    assert is_error
    assert not changed
    assert response['status'] == 'error'
    assert response['http_status'] == 500


def test_system_vdom_property_idempotent(mocker):
    schema_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.schema')

    set_method_result = {'status': 'error', 'http_method': 'DELETE', 'http_status': 404}
    set_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.set', return_value=set_method_result)

    input_data = {
        'username': 'admin',
        'state': 'present',
        'system_vdom_property': {
            'custom_service': 'test_value_3',
            'description': 'test_value_4',
            'dialup_tunnel': 'test_value_5',
            'firewall_address': 'test_value_6',
            'firewall_addrgrp': 'test_value_7',
            'firewall_policy': 'test_value_8',
            'ipsec_phase1': 'test_value_9',
            'ipsec_phase1_interface': 'test_value_10',
            'ipsec_phase2': 'test_value_11',
            'ipsec_phase2_interface': 'test_value_12',
            'log_disk_quota': 'test_value_13',
            'name': 'default_name_14',
            'onetime_schedule': 'test_value_15',
            'proxy': 'test_value_16',
            'recurring_schedule': 'test_value_17',
            'service_group': 'test_value_18',
            'session': 'test_value_19',
            'snmp_index': '20',
            'sslvpn': 'test_value_21',
            'user': 'test_value_22',
            'user_group': 'test_value_23'
        },
        'vdom': 'root'}

    is_error, changed, response = fortios_system_vdom_property.fortios_system(input_data, fos_instance)

    expected_data = {
        'custom-service': 'test_value_3',
        'description': 'test_value_4',
        'dialup-tunnel': 'test_value_5',
        'firewall-address': 'test_value_6',
        'firewall-addrgrp': 'test_value_7',
        'firewall-policy': 'test_value_8',
        'ipsec-phase1': 'test_value_9',
        'ipsec-phase1-interface': 'test_value_10',
        'ipsec-phase2': 'test_value_11',
        'ipsec-phase2-interface': 'test_value_12',
        'log-disk-quota': 'test_value_13',
        'name': 'default_name_14',
                'onetime-schedule': 'test_value_15',
                'proxy': 'test_value_16',
                'recurring-schedule': 'test_value_17',
                'service-group': 'test_value_18',
                'session': 'test_value_19',
                'snmp-index': '20',
                'sslvpn': 'test_value_21',
                'user': 'test_value_22',
                'user-group': 'test_value_23'
    }

    set_method_mock.assert_called_with('system', 'vdom-property', data=expected_data, vdom='root')
    schema_method_mock.assert_not_called()
    assert not is_error
    assert not changed
    assert response['status'] == 'error'
    assert response['http_status'] == 404


def test_system_vdom_property_filter_foreign_attributes(mocker):
    schema_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.schema')

    set_method_result = {'status': 'success', 'http_method': 'POST', 'http_status': 200}
    set_method_mock = mocker.patch('ansible.module_utils.network.fortios.fortios.FortiOSHandler.set', return_value=set_method_result)

    input_data = {
        'username': 'admin',
        'state': 'present',
        'system_vdom_property': {
            'random_attribute_not_valid': 'tag',
            'custom_service': 'test_value_3',
            'description': 'test_value_4',
            'dialup_tunnel': 'test_value_5',
            'firewall_address': 'test_value_6',
            'firewall_addrgrp': 'test_value_7',
            'firewall_policy': 'test_value_8',
            'ipsec_phase1': 'test_value_9',
            'ipsec_phase1_interface': 'test_value_10',
            'ipsec_phase2': 'test_value_11',
            'ipsec_phase2_interface': 'test_value_12',
            'log_disk_quota': 'test_value_13',
            'name': 'default_name_14',
            'onetime_schedule': 'test_value_15',
            'proxy': 'test_value_16',
            'recurring_schedule': 'test_value_17',
            'service_group': 'test_value_18',
            'session': 'test_value_19',
            'snmp_index': '20',
            'sslvpn': 'test_value_21',
            'user': 'test_value_22',
            'user_group': 'test_value_23'
        },
        'vdom': 'root'}

    is_error, changed, response = fortios_system_vdom_property.fortios_system(input_data, fos_instance)

    expected_data = {
        'custom-service': 'test_value_3',
        'description': 'test_value_4',
        'dialup-tunnel': 'test_value_5',
        'firewall-address': 'test_value_6',
        'firewall-addrgrp': 'test_value_7',
        'firewall-policy': 'test_value_8',
        'ipsec-phase1': 'test_value_9',
        'ipsec-phase1-interface': 'test_value_10',
        'ipsec-phase2': 'test_value_11',
        'ipsec-phase2-interface': 'test_value_12',
        'log-disk-quota': 'test_value_13',
        'name': 'default_name_14',
                'onetime-schedule': 'test_value_15',
                'proxy': 'test_value_16',
                'recurring-schedule': 'test_value_17',
                'service-group': 'test_value_18',
                'session': 'test_value_19',
                'snmp-index': '20',
                'sslvpn': 'test_value_21',
                'user': 'test_value_22',
                'user-group': 'test_value_23'
    }

    set_method_mock.assert_called_with('system', 'vdom-property', data=expected_data, vdom='root')
    schema_method_mock.assert_not_called()
    assert not is_error
    assert changed
    assert response['status'] == 'success'
    assert response['http_status'] == 200
