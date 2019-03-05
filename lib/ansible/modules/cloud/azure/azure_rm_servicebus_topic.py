#!/usr/bin/python
#
# Copyright (c) 2018 Yuwei Zhou, <yuwzho@microsoft.com>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = '''
---
module: azure_rm_servicebus_topic
version_added: "2.8"
short_description: Manage Azure Service Bus.
description:
    - Create, update or delete an Azure Service Bus topics.
options:
    resource_group:
        description:
            - name of resource group.
        required: true
    name:
        description:
            - name of the topic.
        required: true
    namespace:
        description:
            - Servicebus namespace name.
            - A namespace is a scoping container for all messaging components.
            - Multipletopics can reside within a single namespace.
        required: true
    state:
        description:
            - Assert the state of the topic. Use 'present' to create or update and
              'absent' to delete.
        default: present
        choices:
            - absent
            - present
    auto_delete_on_idle_in_seconds:
        description:
            - Time idle interval after which a topic is automatically deleted.
            - The minimum duration is 5 minutes.
        type: int
    default_message_time_to_live_seconds:
        description:
            - Default message timespan to live value.
            - This is the duration after which the message expires, starting from when the message is sent to Service Bus.
            - This is the default value used when TimeToLive is not set on a message itself.
        type: int
    enable_batched_operations:
        description:
            - Value that indicates whether server-side batched operations are enabled.
        type: bool
    enable_express:
        description:
            - Value that indicates whether Express Entities are enabled.
            - An express topic holds a message in memory temporarily before writing it to persistent storage.
        type: bool
    enable_partitioning:
        description:
            - A value that indicates whether the topic is to be partitioned across multiple message brokers.
        type: bool
    max_size_in_mb:
        description:
            - The maximum size of the topic in megabytes, which is the size of memory allocated for the topic.
        type: int
    requires_duplicate_detection:
        description:
            -  A value indicating if this topic requires duplicate detection.
        type: bool
    duplicate_detection_time_in_seconds:
        description:
            - TimeSpan structure that defines the duration of the duplicate detection history.
        type: int
    support_ordering:
        description:
            - Value that indicates whether the topic supports ordering.
        type: bool
    status:
        description:
            - Status of the entity.
        choices:
            - active
            - disabled
            - restoring
            - send_disabled
            - receive_disabled
            - creating
            - deleting
            - renaming
            - unkown

extends_documentation_fragment:
    - azure
    - azure_tags

author:
    - "Yuwei Zhou (@yuwzho)"

'''

EXAMPLES = '''
- name: Create a topic
  azure_rm_servicebus_topic:
      name: subtopic
      resource_group: foo
      namespace: bar
      duplicate_detection_time_in_seconds: 600
'''
RETURN = '''
id:
    description: Current state of the topic.
    returned: success
    type: str
'''

try:
    from msrestazure.azure_exceptions import CloudError
except ImportError:
    # This is handled in azure_rm_common
    pass

from ansible.module_utils.azure_rm_common import AzureRMModuleBase
from ansible.module_utils.common.dict_transformations import _snake_to_camel, _camel_to_snake
from ansible.module_utils._text import to_native
from datetime import datetime, timedelta


duration_spec_map = dict(
    default_message_time_to_live='default_message_time_to_live_seconds',
    duplicate_detection_history_time_window='duplicate_detection_time_in_seconds',
    auto_delete_on_idle='auto_delete_on_idle_in_seconds'
)


sas_policy_spec = dict(
    state=dict(type='str', default='present', choices=['present', 'absent']),
    name=dict(type='str', required=True),
    regenerate_key=dict(type='bool'),
    rights=dict(type='str', choices=['manage', 'listen', 'send', 'listen_send'])
)


class AzureRMServiceBusTopic(AzureRMModuleBase):

    def __init__(self):

        self.module_arg_spec = dict(
            auto_delete_on_idle_in_seconds=dict(type='int'),
            default_message_time_to_live_seconds=dict(type='int'),
            duplicate_detection_time_in_seconds=dict(type='int'),
            enable_batched_operations=dict(type='bool'),
            enable_express=dict(type='bool'),
            enable_partitioning=dict(type='bool'),
            max_size_in_mb=dict(type='int'),
            name=dict(type='str', required=True),
            namespace=dict(type='str'),
            requires_duplicate_detection=dict(type='bool'),
            resource_group=dict(type='str', required=True),
            state=dict(type='str', default='present', choices=['present', 'absent']),
            status=dict(type='str',
                        choices=['active', 'disabled', 'restoring', 'send_disabled', 'receive_disabled', 'creating', 'deleting', 'renaming', 'unkown']),
            support_ordering=dict(type='bool')
        )

        self.resource_group = None
        self.name = None
        self.state = None
        self.namespace = None
        self.auto_delete_on_idle_in_seconds = None
        self.default_message_time_to_live_seconds = None
        self.enable_batched_operations = None
        self.enable_express = None
        self.enable_partitioning = None
        self.max_size_in_mb = None
        self.requires_duplicate_detection = None
        self.status = None
        self.support_ordering = None

        self.results = dict(
            changed=False,
            id=None
        )

        super(AzureRMServiceBusTopic, self).__init__(self.module_arg_spec,
                                                     supports_check_mode=True)

    def exec_module(self, **kwargs):

        for key in list(self.module_arg_spec.keys()):
            setattr(self, key, kwargs[key])

        changed = False
        original = self.get()
        if self.state == 'present':
            # Create the resource instance
            params = dict(
                enable_batched_operations=self.enable_batched_operations,
                enable_express=self.enable_express,
                enable_partitioning=self.enable_partitioning,
                max_size_in_megabytes=self.max_size_in_mb,
                support_ordering=self.support_ordering
            )
            if self.status:
                params['status'] = self.servicebus_models.EntityStatus(str.capitalize(_snake_to_camel(self.status)))
            for k, v in duration_spec_map.items():
                seconds = getattr(self, v)
                if seconds:
                    params[k] = timedelta(seconds=seconds)

            instance = self.servicebus_models.SBTopic(**params)
            result = original
            if not original:
                changed = True
                result = instance
            else:
                result = original
                attribute_map = set(self.servicebus_models.SBTopic._attribute_map.keys()) - set(self.servicebus_models.SBTopic._validation.keys())
                for attribute in attribute_map:
                    value = getattr(instance, attribute)
                    if value and value != getattr(original, attribute):
                        changed = True
            if changed and not self.check_mode:
                result = self.create_or_update(instance)
            self.results = self.to_dict(result)

            # handle SAS policies
            rules = self.get_auth_rules()
            for name in rules.keys():
                rules[name]['keys'] = self.get_sas_key(name)
            self.results['sas_policies'] = rules
        elif original:
            changed = True
            if not self.check_mode:
                self.delete()
                self.results['deleted'] = True

        self.results['changed'] = changed
        return self.results

    def create_or_update(self, param):
        try:
            client = self._get_client()
            return client.create_or_update(self.resource_group, self.namespace, self.name, param)
        except Exception as exc:
            self.fail("Error creating or updating topic {0} - {1}".format(self.name, str(exc)))

    def delete(self):
        try:
            client = self._get_client()
            client.delete(self.resource_group, self.namespace, self.name)
            return True
        except Exception as exc:
            self.fail("Error deleting topic {0} - {1}".format(self.name, str(exc)))

    def _get_client(self):
        return self.servicebus_client.topics

    def get(self):
        try:
            client = self._get_client()
            return client.get(self.resource_group, self.namespace, self.name)
        except Exception:
            return None

    def to_dict(self, instance):
        result = dict()
        attribute_map = self.servicebus_models.SBTopic._attribute_map
        for attribute in attribute_map.keys():
            value = getattr(instance, attribute)
            if not value:
                continue
            if attribute_map[attribute]['type'] == 'duration':
                if is_valid_timedelta(value):
                    key = duration_spec_map.get(attribute) or attribute
                    result[key] = int(value.total_seconds())
            elif attribute == 'status':
                result['status'] = _camel_to_snake(value)
            elif isinstance(value, self.servicebus_models.MessageCountDetails):
                result[attribute] = value.as_dict()
            elif isinstance(value, self.servicebus_models.SBSku):
                result[attribute] = value.name.lower()
            elif isinstance(value, datetime):
                result[attribute] = str(value)
            elif isinstance(value, str):
                result[attribute] = to_native(value)
            elif attribute == 'max_size_in_megabytes':
                result['max_size_in_mb'] = value
            else:
                result[attribute] = value
        return result

    # SAS policy
    def get_auth_rules(self):
        result = dict()
        try:
            client = self._get_client()
            rules = client.list_authorization_rules(self.resource_group, self.namespace, self.name)
            while True:
                rule = rules.next()
                result[rule.name] = self.policy_to_dict(rule)
        except Exception:
            pass
        return result

    def get_sas_key(self, name):
        try:
            client = self._get_client()
            return client.list_keys(self.resource_group, self.namespace, self.name, name).as_dict()
        except Exception as exc:
            self.fail('Error when getting SAS policy {0}\'s key - {1}'.format(name, exc.message or str(exc)))
        return None

    def policy_to_dict(self, rule):
        result = rule.as_dict()
        rights = result['rights']
        if 'Manage' in rights:
            result['rights'] = 'manage'
        elif 'Listen' in rights and 'Send' in rights:
            result['rights'] = 'listen_send'
        else:
            result['rights'] = rights[0].lower()
        return result


def is_valid_timedelta(value):
    if value == timedelta(10675199, 10085, 477581):
        return None
    return value


def main():
    AzureRMServiceBusTopic()


if __name__ == '__main__':
    main()
