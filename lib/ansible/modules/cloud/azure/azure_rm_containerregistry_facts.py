#!/usr/bin/python
#
# Copyright (c) 2018 Zim Kalinowski, <zikalino@microsoft.com>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = '''
---
module: azure_rm_containerregistry_facts
version_added: "2.7"
short_description: Get Azure Container Registry facts.
description:
    - Get facts of Registry.

options:
    resource_group:
        description:
            - The name of the resource group to which the container registry belongs.
        required: True
    name:
        description:
            - The name of the container registry.
    tags:
        description:
            - Limit results by providing a list of tags. Format tags as 'key' or 'key:value'.

extends_documentation_fragment:
    - azure

author:
    - "Zim Kalinowski (@zikalino)"

'''

EXAMPLES = '''
  - name: Get instance of Registry
    azure_rm_containerregistry_facts:
      resource_group: sampleresourcegroup
      name: sampleregistry

  - name: List instances of Registry
    azure_rm_containerregistry_facts:
      resource_group: sampleresourcegroup
'''

RETURN = '''
registries:
    description: A list of dictionaries containing facts for registries.
    returned: always
    type: complex
    contains:
        id:
            description:
                - The resource ID.
            returned: always
            type: str
            sample: "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/myResourceGroup/providers/Microsoft.ContainerRegistry/registr
                    ies/myRegistry"
        name:
            description:
                - The name of the resource.
            returned: always
            type: str
            sample: myRegistry
        location:
            description:
                - The location of the resource. This cannot be changed after the resource is created.
            returned: always
            type: str
            sample: westus
        admin_user_enabled:
            description:
                - Is admin user enabled.
            returned: always
            type: bool
            sample: yes
        sku:
            description:
                - The SKU name of the container registry.
            returned: always
            type: str
            sample: classic
        provisioning_state:
            description:
                - Provisioning state of the container registry
            returned: always
            type: str
            sample: Succeeded
        login_server:
            description:
                - Login server for the registry.
            returned: always
            type: str
            sample: acrd08521b.azurecr.io
        username:
            description:
                - The user name for container registry.
            returned: always
            type: str
            sample: zim
        password:
            description:
                - Password 1 for container registry.
            returned: always
            type: str
            sample: Password1!!
        password2:
            description:
                - Password 2 for container registry.
            returned: always
            type: str
            sample: Password2!!
'''

from ansible.module_utils.azure_rm_common import AzureRMModuleBase

try:
    from msrestazure.azure_exceptions import CloudError
    from msrestazure.azure_operation import AzureOperationPoller
    from azure.mgmt.containerregistry import ContainerRegistryManagementClient
    from msrest.serialization import Model
except ImportError:
    # This is handled in azure_rm_common
    pass


class AzureRMRegistryFacts(AzureRMModuleBase):
    def __init__(self):
        # define user inputs into argument
        self.module_arg_spec = dict(
            resource_group=dict(
                type='str',
                required=True
            ),
            name=dict(
                type='str'
            ),
            tags=dict(
                type='list'
            )
        )
        # store the results of the module operation
        self.results = dict(
            changed=False
        )
        self.resource_group = None
        self.name = None
        super(AzureRMRegistryFacts, self).__init__(self.module_arg_spec, supports_tags=False)

    def exec_module(self, **kwargs):
        for key in self.module_arg_spec:
            setattr(self, key, kwargs[key])

        if self.name:
            self.results['registries'] = self.get()
        elif self.resource_group:
            self.results['registries'] = self.list_by_resource_group()
        else:
            self.results['registries'] = self.list_all()

        return self.results

    def get(self):
        response = None
        results = []
        try:
            response = self.containerregistry_client.registries.get(resource_group_name=self.resource_group,
                                                                    registry_name=self.name)
            self.log("Response : {0}".format(response))
        except CloudError as e:
            self.log('Could not get facts for Registries.')

        if response is not None:
            if self.has_tags(response.tags, self.tags):
                results.append(self.format_item(response))

        return results

    def list_all(self):
        response = None
        results = []
        try:
            response = self.containerregistry_client.registries.list()
            self.log("Response : {0}".format(response))
        except CloudError as e:
            self.fail('Could not get facts for Registries.')

        if response is not None:
            for item in response:
                if self.has_tags(item.tags, self.tags):
                    results.append(self.format_item(item))
        return results

    def list_by_resource_group(self):
        response = None
        results = []
        try:
            response = self.containerregistry_client.registries.list_by_resource_group(resource_group_name=self.resource_group)
            self.log("Response : {0}".format(response))
        except CloudError as e:
            self.fail('Could not get facts for Registries.')

        if response is not None:
            for item in response:
                if self.has_tags(item.tags, self.tags):
                    results.append(self.format_item(item))
        return results

    def format_item(self, item):
        d = item.as_dict()
        resource_group = d['id'].split('resourceGroups/')[1].split('/')[0]
        name = d['name']
        credentials = None
        try:
            credentials = self.containerregistry_client.registries.list_credentials(resource_group_name=resource_group,                                                                                 registry_name=name)
        except CloudError as e:
            self.fail('Could not list credentials.')

        d = {
            'resource_group': resource_group,
            'name': d['name'],
            'location': d['location'],
            'admin_user_enabled': d['admin_user_enabled'],
            'sku': d['sku']['tier'].lower(),
            'provisioning_state': d['provisioning_state'],
            'login_server': d['login_server'],
            'id': d['id'],
            'tags': d.get('tags', None),
            'username': credentials['username'],
            'password': credentials['passwords']['password'],
            'password2': credentials['passwords']['password2']
        }
        return d


def main():
    AzureRMRegistryFacts()


if __name__ == '__main__':
    main()
