#!/usr/bin/python
#
# Copyright (c) 2019 Zim Kalinowski, (@zikalino)
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = '''
---
module: azure_rm_apimanagementdiagnosticlogger
version_added: '2.8'
short_description: Manage Azure DiagnosticLogger instance.
description:
  - 'Create, update and delete instance of Azure DiagnosticLogger.'
options:
  resource_group_name:
    description:
      - The name of the resource group.
  service_name:
    description:
      - The name of the API Management service.
  diagnostic_id:
    description:
      - >-
        Diagnostic identifier. Must be unique in the current API Management
        service instance.
  loggerid:
    description:
      - >-
        Logger identifier. Must be unique in the API Management service
        instance.
  state:
    description:
      - Assert the state of the DiagnosticLogger.
      - >-
        Use C(present) to create or update an DiagnosticLogger and C(absent) to
        delete it.
    default: present
    choices:
      - absent
      - present
extends_documentation_fragment:
  - azure
author:
  - Zim Kalinowski (@zikalino)

'''

EXAMPLES = '''
- name: ApiManagementCreateDiagnosticLogger
  azure_rm_apimanagementdiagnosticlogger:
    serviceName: apimService1
    resourceGroupName: myResourceGroup
    diagnosticId: default
    loggerid: applicationinsights

'''

RETURN = '''
{}

'''

import time
import json
from ansible.module_utils.azure_rm_common import AzureRMModuleBase
from ansible.module_utils.azure_rm_common_rest import GenericRestClient
from copy import deepcopy
from msrestazure.azure_exceptions import CloudError


class Actions:
    NoAction, Create, Update, Delete = range(4)


class AzureRMDiagnosticLogger(AzureRMModuleBase):
    """Configuration class for an Azure RM DiagnosticLogger resource"""

    def __init__(self):
        self.module_arg_spec = dict(
            resource_group_name=dict(
                type='str'
            ),
            service_name=dict(
                type='str'
            ),
            diagnostic_id=dict(
                type='str'
            ),
            loggerid=dict(
                type='str'
            ),
            state=dict(
                type='str',
                default='present',
                choices=['present', 'absent']
            )
        )

        self.resource_group_name = None
        self.service_name = None
        self.diagnostic_id = None
        self.loggerid = None

        self.results = dict(changed=False)
        self.mgmt_client = None
        self.state = None
        self.url = None
        self.status_code = [200, 202]
        self.to_do = Actions.NoAction

        self.body = {}
        self.query_parameters = {}
        self.query_parameters['api-version'] = '2018-01-01'
        self.header_parameters = {}
        self.header_parameters['Content-Type'] = 'application/json; charset=utf-8'

        super(AzureRMDiagnosticLogger, self).__init__(derived_arg_spec=self.module_arg_spec,
                                                      supports_check_mode=True,
                                                      supports_tags=False)

    def exec_module(self, **kwargs):
        """Main module execution method"""

        for key in list(self.module_arg_spec.keys()):
            if hasattr(self, key):
                setattr(self, key, kwargs[key])

        old_response = None
        response = None

        self.mgmt_client = self.get_mgmt_svc_client(GenericRestClient,
                                                    base_url=self._cloud_environment.endpoints.resource_manager)

        self.url = ('/subscriptions' +
                    '/{{ subscription_id }}' +
                    '/resourceGroups' +
                    '/{{ resource_group }}' +
                    '/providers' +
                    '/Microsoft.ApiManagement' +
                    '/service' +
                    '/{{ service_name }}' +
                    '/diagnostics' +
                    '/{{ diagnostic_name }}' +
                    '/loggers' +
                    '/{{ logger_name }}')
        self.url = self.url.replace('{{ subscription_id }}', self.subscription_id)
        self.url = self.url.replace('{{ resource_group }}', self.resource_group)
        self.url = self.url.replace('{{ service_name }}', self.service_name)
        self.url = self.url.replace('{{ diagnostic_name }}', self.diagnostic_name)
        self.url = self.url.replace('{{ logger_name }}', self.logger_name)

        old_response = self.get_diagnosticlogger()

        if not old_response:
            self.log("DiagnosticLogger instance doesn't exist")

            if self.state == 'absent':
                self.log("Old instance didn't exist")
            else:
                self.to_do = Actions.Create
        else:
            self.log('DiagnosticLogger instance already exists')

            if self.state == 'absent':
                self.to_do = Actions.Delete
            elif self.state == 'present':
                self.log('Need to check if DiagnosticLogger instance has to be deleted or may be updated')

        if (self.to_do == Actions.Create) or (self.to_do == Actions.Update):
            self.log('Need to Create / Update the DiagnosticLogger instance')

            if self.check_mode:
                self.results['changed'] = True
                return self.results

            response = self.create_update_diagnosticlogger()

            # if not old_response:
            self.results['changed'] = True
            self.results['response'] = response
            # else:
            #     self.results['changed'] = old_response.__ne__(response)
            self.log('Creation / Update done')
        elif self.to_do == Actions.Delete:
            self.log('DiagnosticLogger instance deleted')
            self.results['changed'] = True

            if self.check_mode:
                return self.results

            self.delete_diagnosticlogger()

            # make sure instance is actually deleted, for some Azure resources, instance is hanging around
            # for some time after deletion -- this should be really fixed in Azure
            while self.get_diagnosticlogger():
                time.sleep(20)
        else:
            self.log('DiagnosticLogger instance unchanged')
            self.results['changed'] = False
            response = old_response


        return self.results

    def rename_key(self, d, old_name, new_name):
        old_value = d.get(old_name, None)
        if old_value is not None:
            d.pop(old_name, None)
            d[new_name] = old_value

    def create_update_diagnosticlogger(self):
        '''
        Creates or updates DiagnosticLogger with the specified configuration.

        :return: deserialized DiagnosticLogger instance state dictionary
        '''
        # self.log('Creating / Updating the DiagnosticLogger instance {0}'.format(self.))

        try:
            if self.to_do == Actions.Create:
                response = self.mgmt_client.query(self.url,
                                                  'PUT',
                                                  self.query_parameters,
                                                  self.header_parameters,
                                                  self.body,
                                                  self.status_code)
            else:
                response = self.mgmt_client.query(self.url,
                                                  'PUT',
                                                  self.query_parameters,
                                                  self.header_parameters,
                                                  self.body,
                                                  self.status_code)
            # implement poller in another way
            # if isinstance(response, AzureOperationPoller):
            #    response = self.get_poller_result(response)

        except CloudError as exc:
            self.log('Error attempting to create the DiagnosticLogger instance.')
            self.fail('Error creating the DiagnosticLogger instance: {0}'.format(str(exc)))

        try:
            response = json.loads(response.text)
        except Exception:
            response = {'text': response.text}
            pass

        return response

    def delete_diagnosticlogger(self):
        '''
        Deletes specified DiagnosticLogger instance in the specified subscription and resource group.

        :return: True
        '''
        # self.log('Deleting the DiagnosticLogger instance {0}'.format(self.))
        try:
            response = self.mgmt_client.query(self.url,
                                              'DELETE',
                                              self.query_parameters,
                                              self.header_parameters,
                                              None,
                                              self.status_code)
        except CloudError as e:
            self.log('Error attempting to delete the DiagnosticLogger instance.')
            self.fail('Error deleting the DiagnosticLogger instance: {0}'.format(str(e)))

        return True

    def get_diagnosticlogger(self):
        '''
        Gets the properties of the specified DiagnosticLogger.

        :return: deserialized DiagnosticLogger instance state dictionary
        '''
        # self.log('Checking if the DiagnosticLogger instance {0} is present'.format(self.))
        found = False
        try:
            response = self.mgmt_client.query(self.url,
                                              'GET',
                                              self.query_parameters,
                                              self.header_parameters,
                                              None,
                                              self.status_code)
            found = True
            self.log("Response : {0}".format(response))
            # self.log("DiagnosticLogger instance : {0} found".format(response.name))
        except CloudError as e:
            self.log('Did not find the DiagnosticLogger instance.')
        if found is True:
            return response

        return False


def main():
    """Main execution"""
    AzureRMDiagnosticLogger()


if __name__ == '__main__':
    main()
