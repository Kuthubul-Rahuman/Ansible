# -*- coding: utf-8 -*-

# Copyright 2017 Sloane Hertel <shertel@redhat.com>
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

# Make coding more python3-ish
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import unittest
import pytest
import datetime

from ansible.errors import AnsibleError
from ansible.plugins.inventory.aws_ec2 import InventoryModule
from ansible.plugins.inventory.aws_ec2 import instance_data_filter_to_boto_attr, instance_meta_filter_to_boto_attr

instances = {
u'Instances': [
    {u'Monitoring': {u'State': 'disabled'},
     u'PublicDnsName': 'ec2-12-345-67-890.compute-1.amazonaws.com',
     u'State': {u'Code': 16, u'Name': 'running'},
     u'EbsOptimized': False,
     u'LaunchTime': datetime.datetime(2017, 10, 31, 12, 59, 25),
     u'PublicIpAddress': '12.345.67.890',
     u'PrivateIpAddress': '098.76.54.321',
     u'ProductCodes': [],
     u'VpcId': 'vpc-12345678',
     u'StateTransitionReason': '',
     u'InstanceId': 'i-00000000000000000',
     u'EnaSupport': True,
     u'ImageId': 'ami-12345678',
     u'PrivateDnsName': 'ip-098-76-54-321.ec2.internal',
     u'KeyName': 'testkey',
     u'SecurityGroups': [{u'GroupName': 'default', u'GroupId': 'sg-12345678'}],
     u'ClientToken': '',
     u'SubnetId': 'subnet-12345678',
     u'InstanceType': 't2.micro',
     u'NetworkInterfaces': [
        {u'Status': 'in-use',
         u'MacAddress': '12:a0:50:42:3d:a4',
         u'SourceDestCheck': True,
         u'VpcId': 'vpc-12345678',
         u'Description': '',
         u'NetworkInterfaceId': 'eni-12345678',
         u'PrivateIpAddresses': [
            {u'PrivateDnsName': 'ip-098-76-54-321.ec2.internal',
             u'PrivateIpAddress': '098.76.54.321',
             u'Primary': True,
             u'Association':
                {u'PublicIp': '12.345.67.890',
                 u'PublicDnsName': 'ec2-12-345-67-890.compute-1.amazonaws.com',
                 u'IpOwnerId': 'amazon'}}],
         u'PrivateDnsName': 'ip-098-76-54-321.ec2.internal',
         u'Attachment':
            {u'Status': 'attached',
             u'DeviceIndex': 0,
             u'DeleteOnTermination': True,
             u'AttachmentId': 'eni-attach-12345678',
             u'AttachTime': datetime.datetime(2017, 10, 31, 12, 59, 25)},
         u'Groups': [
            {u'GroupName': 'default',
             u'GroupId': 'sg-12345678'}],
         u'Ipv6Addresses': [],
         u'OwnerId': '123456789000',
         u'PrivateIpAddress': '098.76.54.321',
         u'SubnetId': 'subnet-12345678',
         u'Association':
            {u'PublicIp': '12.345.67.890',
             u'PublicDnsName': 'ec2-12-345-67-890.compute-1.amazonaws.com',
             u'IpOwnerId': 'amazon'}}],
     u'SourceDestCheck': True,
     u'Placement':
        {u'Tenancy': 'default',
         u'GroupName': '',
         u'AvailabilityZone': 'us-east-1c'},
     u'Hypervisor': 'xen',
     u'BlockDeviceMappings': [
        {u'DeviceName': '/dev/xvda',
         u'Ebs':
            {u'Status': 'attached',
             u'DeleteOnTermination': True,
             u'VolumeId': 'vol-01234567890000000',
             u'AttachTime': datetime.datetime(2017, 10, 31, 12, 59, 26)}}],
     u'Architecture': 'x86_64',
     u'RootDeviceType': 'ebs',
     u'RootDeviceName': '/dev/xvda',
     u'VirtualizationType': 'hvm',
     u'Tags': [{u'Value': 'test', u'Key': 'ansible'}],
     u'AmiLaunchIndex': 0}],
u'ReservationId': 'r-01234567890000000',
u'Groups': [],
u'OwnerId': '123456789000'}


def test_get_group_by_value():
    inv = InventoryModule()
    formatted_instance = [instance for instance in inv._format_instance_data('us-east-1', instances)][0]
    group_by = "instance-type"
    assert inv._get_group_by_value(group_by, formatted_instance) == "t2.micro"


def test_compile_values():
    inv = InventoryModule()
    formatted_instance = [instance for instance in inv._format_instance_data('us-east-1', instances)][0]
    chain_of_keys = instance_data_filter_to_boto_attr['instance.group-id']
    found_value = formatted_instance.instance_data
    for attr in chain_of_keys:
        found_value = inv._compile_values(found_value, attr)
    assert found_value == "sg-12345678"


def test_get_boto_attr_chain():
    inv = InventoryModule()
    formatted_instance = [instance for instance in inv._format_instance_data('us-east-1', instances)][0]
    assert inv._get_boto_attr_chain('network-interface.addresses.private-ip-address', formatted_instance) == "098.76.54.321"


def test_get_group_by_name_and_value():
    inv = InventoryModule()
    groups_to_make = ["tag:ansible=tests", "instance-type=t2.micro"]
    group_generator = inv._get_group_by_name_and_value(groups_to_make)
    formatted_groups_to_make = sorted([(group_name, group_value) for group_name, group_value in group_generator])
    assert formatted_groups_to_make == [('instance-type', 't2.micro'), ('tag:', 'ansible=tests')]


def test_compare_tag_groupings():
    # _compare_tag_groupings() takes group_value (a list of tag keys or tag values or a dict of key:values and the tags associated with an instance)
    pass


def test_assemble_groups():
    inv = InventoryModule()
    formatted_instances = [instance for instance in inv._format_instance_data('us-east-1', instances)]
    groups_to_make = ["tag:ansible=tests", "instance-type=t2.micro"]
    groups = inv._assemble_groups(formatted_instances, groups_to_make)
    assert sorted(list(groups.keys())) == ['instance-type', 'tag:']
    assert groups['instance-type']['t2.micro'] == formatted_instances


def test_boto3_conn():
    config_data = {"boto_profile": "test_profile",
                   "aws_access_key_id": "test_access_key",
                   "aws_secret_access_key": "test_secret_key"}
    inv = InventoryModule()
    inv._set_credentials(config_data)
    with pytest.raises(AnsibleError) as error_message:
        for connection, region in inv._boto3_conn(regions=['us-east-1']):
            assert error_message == "Insufficient credentials found."


def test_format_instance_data():
    meta_keys = ["Groups", "OwnerId", "RequesterId", "ReservationId"]
    data_keys = ["AmiLaunchIndex", "Architecture", "BlockDeviceMappings", "ClientToken",
                 "EbsOptimized", "EnaSupport", "Hypervisor", "ImageId", "InstanceId",
                 "InstanceType", "KeyName", "LaunchTime", "Monitoring", "NetworkInterfaces",
                 "Placement", "PrivateDnsName", "PrivateIpAddress", "ProductCodes",
                 "PublicDnsName", "PublicIpAddress", "RootDeviceName", "RootDeviceType",
                 "SecurityGroups", "SourceDestCheck", "State", "StateTransitionReason",
                 "SubnetId", "Tags", "VirtualizationType", "VpcId"]

    for instance in InventoryModule._format_instance_data(InventoryModule, 'us-east-1', instances):
        assert instance.region == 'us-east-1'
        assert sorted(list(instance.instance_meta.keys())) == meta_keys
        assert sorted(list(instance.instance_data.keys())) == data_keys


def test_get_hostname_default():
    inv = InventoryModule()
    formatted_instance = [instance for instance in inv._format_instance_data('us-east-1', instances)][0]
    assert inv._get_hostname(formatted_instance, hostnames=None) == "ec2-12-345-67-890.compute-1.amazonaws.com"


def test_get_hostname():
    hostnames = ['ip-address']
    inv = InventoryModule()
    formatted_instance = [instance for instance in inv._format_instance_data('us-east-1', instances)][0]
    assert inv._get_hostname(formatted_instance, hostnames) == "12.345.67.890"


def test_find_cred(monkeypatch):
    monkeypatch.setenv(name="AWS_PROFILE", value="")
    monkeypatch.setenv(name="AWS_DEFAULT_PROFILE", value="test_profile")
    possible_env_vars = ["AWS_PROFILE", "AWS_DEFAULT_PROFILE"]
    assert InventoryModule._find_cred(InventoryModule, possible_env_vars) == "test_profile"


def test_set_credentials(monkeypatch):
    monkeypatch.setenv(name="AWS_PROFILE", value="test_profile")
    monkeypatch.setenv(name="AWS_DEFAULT_PROFILE", value="other_profile")
    monkeypatch.setenv(name="AWS_ACCESS_KEY_ID", value="")
    monkeypatch.setenv(name="AWS_ACCESS_KEY", value="test_access_key")
    monkeypatch.setenv(name="AWS_SECRET_ACCESS_KEY", value="test_secret_key")
    monkeypatch.setenv(name="AWS_SECURITY_TOKEN", value="test_security_token")

    inv = InventoryModule()
    inv._set_credentials(config_data={})

    assert inv.boto_profile == "test_profile"
    assert inv.aws_access_key_id == "test_access_key"
    assert inv.aws_secret_access_key == "test_secret_key"
    assert inv.aws_security_token == "test_security_token"


def test_insufficient_credentials(monkeypatch):
    profile_vars = ['AWS_PROFILE', 'AWS_DEFAULT_PROFILE']
    access_key_vars = ['AWS_ACCESS_KEY_ID', 'AWS_ACCESS_KEY', 'EC2_ACCESS_KEY']
    secret_key_vars = ['AWS_SECRET_ACCESS_KEY', 'AWS_SECRET_KEY', 'EC2_SECRET_KEY']
    security_token_vars = ['AWS_SECURITY_TOKEN', 'AWS_SESSION_TOKEN', 'EC2_SECURITY_TOKEN']

    for possible_vars in (profile_vars, access_key_vars, secret_key_vars, security_token_vars):
        for name in possible_vars:
            monkeypatch.setenv(name, "")

    inv = InventoryModule()
    with pytest.raises(AnsibleError) as error_message:
        inv._set_credentials(config_data={})
        assert "Insufficient boto credentials found" in error_message
