#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2017 Google
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# ----------------------------------------------------------------------------
#
#     ***     AUTO GENERATED CODE    ***    AUTO GENERATED CODE     ***
#
# ----------------------------------------------------------------------------
#
#     This file is automatically generated by Magic Modules and manual
#     changes will be clobbered when the file is regenerated.
#
#     Please read more about how to change this file at
#     https://www.github.com/GoogleCloudPlatform/magic-modules
#
# ----------------------------------------------------------------------------

from __future__ import absolute_import, division, print_function
__metaclass__ = type

################################################################################
# Documentation
################################################################################

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ["preview"],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: gcp_spanner_instance_facts
description:
  - Gather facts for GCP Instance
short_description: Gather facts for GCP Instance
version_added: 2.8
author: Google Inc. (@googlecloudplatform)
requirements:
    - python >= 2.6
    - requests >= 2.18.4
    - google-auth >= 1.3.0
extends_documentation_fragment: gcp
'''

EXAMPLES = '''
- name:  a instance facts
  gcp_spanner_instance_facts:
      project: test_project
      auth_kind: serviceaccount
      service_account_file: "/tmp/auth.pem"
'''

RETURN = '''
items:
    description: List of items
    returned: always
    type: complex
    contains:
        name:
            description:
                - A unique identifier for the instance, which cannot be changed after the instance
                  is created. Values are of the form projects/<project>/instances/[a-z][-a-z0-9]*[a-z0-9].
                  The final segment of the name must be between 6 and 30 characters in length.
            returned: success
            type: str
        config:
            description:
                - A reference to the instance configuration.
            returned: success
            type: str
        displayName:
            description:
                - The descriptive name for this instance as it appears in UIs. Must be unique per
                  project and between 4 and 30 characters in length.
            returned: success
            type: str
        nodeCount:
            description:
                - The number of nodes allocated to this instance.
            returned: success
            type: int
        labels:
            description:
                - Cloud Labels are a flexible and lightweight mechanism for organizing cloud resources
                  into groups that reflect a customer's organizational needs and deployment strategies.
                  Cloud Labels can be used to filter collections of resources. They can be used to
                  control how resource metrics are aggregated. And they can be used as arguments to
                  policy management rules (e.g. route, firewall, load balancing, etc.).
                - 'Label keys must be between 1 and 63 characters long and must conform to the following
                  regular expression: `[a-z]([-a-z0-9]*[a-z0-9])?`.'
                - Label values must be between 0 and 63 characters long and must conform to the regular
                  expression `([a-z]([-a-z0-9]*[a-z0-9])?)?`.
                - No more than 64 labels can be associated with a given resource.
                - See U(https://goo.gl/xmQnxf) for more information on and examples of labels.
                - 'If you plan to use labels in your own code, please note that additional characters
                  may be allowed in the future. And so you are advised to use an internal label representation,
                  such as JSON, which doesn''t rely upon specific characters being disallowed. For
                  example, representing labels as the string: name + "_" + value would prove problematic
                  if we were to allow "_" in a future release.'
                - 'An object containing a list of "key": value pairs.'
                - 'Example: { "name": "wrench", "mass": "1.3kg", "count": "3" }.'
            returned: success
            type: dict
'''

################################################################################
# Imports
################################################################################
from ansible.module_utils.gcp_utils import navigate_hash, GcpSession, GcpModule, GcpRequest
import json

################################################################################
# Main
################################################################################


def main():
    module = GcpModule(
        argument_spec=dict(
        )
    )

    if 'scopes' not in module.params:
        module.params['scopes'] = ['https://www.googleapis.com/auth/spanner.admin']

    items = fetch_list(module, collection(module))
    if items.get('instances'):
        items = items.get('instances')
    else:
        items = []
    return_value = {
        'items': items
    }
    module.exit_json(**return_value)


def collection(module):
    return "https://spanner.googleapis.com/v1/projects/{project}/instances".format(**module.params)


def fetch_list(module, link):
    auth = GcpSession(module, 'spanner')
    response = auth.get(link)
    return return_if_object(module, response)


def return_if_object(module, response):
    # If not found, return nothing.
    if response.status_code == 404:
        return None

    # If no content, return nothing.
    if response.status_code == 204:
        return None

    try:
        module.raise_for_status(response)
        result = response.json()
    except getattr(json.decoder, 'JSONDecodeError', ValueError) as inst:
        module.fail_json(msg="Invalid JSON response with error: %s" % inst)

    if navigate_hash(result, ['error', 'errors']):
        module.fail_json(msg=navigate_hash(result, ['error', 'errors']))

    return result


if __name__ == "__main__":
    main()
