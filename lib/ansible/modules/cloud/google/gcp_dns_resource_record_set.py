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
module: gcp_dns_resource_record_set
description:
    - A single DNS record that exists on a domain name (i.e. in a managed zone).
    - This record defines the information about the domain and where the domain
      / subdomains direct to.
    - The record will include the domain/subdomain name, a type (i.e. A, AAA,
      CAA, MX, CNAME, NS, etc).
short_description: Creates a GCP ResourceRecordSet
version_added: 2.6
author: Google Inc. (@googlecloudplatform)
requirements:
    - python >= 2.6
    - requests >= 2.18.4
    - google-auth >= 1.3.0
options:
    state:
        description:
            - Whether the given object should exist in GCP
        required: true
        choices: ['present', 'absent']
        default: 'present'
    name:
        description:
            - For example, www.example.com.
        required: true
    type:
        description:
            - One of valid DNS resource types.
        required: true
        choices: ['A', 'AAAA', 'CAA', 'CNAME', 'MX', 'NAPTR', 'NS', 'PTR', 'SOA', 'SPF', 'SRV', 'TXT']
    ttl:
        description:
            - Number of seconds that this ResourceRecordSet can be cached by
              resolvers.
        required: false
    target:
        description:
            - As defined in RFC 1035 (section 5) and RFC 1034 (section 3.6.1).
        required: false
    managed_zone:
        description:
            - A reference to ManagedZone resource.
        required: true
extends_documentation_fragment: gcp
'''

EXAMPLES = '''
- name: create a managed zone
  gcp_dns_managed_zone:
      name: 'managedzone-rrs'
      dns_name: 'testzone-4.com.'
      description: 'test zone'
      project: "{{ gcp_project }}"
      auth_kind: "{{ gcp_cred_kind }}"
      service_account_file: "{{ gcp_cred_file }}"
      scopes:
        - https://www.googleapis.com/auth/ndev.clouddns.readwrite
      state: present
  register: managed_zone

- name: create a resource record set
  gcp_dns_resource_record_set:
      name: 'www.testzone-4.com.'
      managed_zone: "{{ managed_zone }}"
      type: 'A'
      ttl: 600
      target:
        - 10.1.2.3
        - 40.5.6.7
      project: testProject
      auth_kind: service_account
      service_account_file: /tmp/auth.pem
      scopes:
        - https://www.googleapis.com/auth/ndev.clouddns.readwrite
      state: present
'''

RETURN = '''
    name:
        description:
            - For example, www.example.com.
        returned: success
        type: str
    type:
        description:
            - One of valid DNS resource types.
        returned: success
        type: str
    ttl:
        description:
            - Number of seconds that this ResourceRecordSet can be cached by
              resolvers.
        returned: success
        type: int
    target:
        description:
            - As defined in RFC 1035 (section 5) and RFC 1034 (section 3.6.1).
        returned: success
        type: list
    managed_zone:
        description:
            - A reference to ManagedZone resource.
        returned: success
        type: dict
'''

################################################################################
# Imports
################################################################################

from ansible.module_utils.gcp_utils import navigate_hash, GcpSession, GcpModule, GcpRequest, replace_resource_dict
import json
import copy
import datetime
import time

################################################################################
# Main
################################################################################


def main():
    """Main function"""

    module = GcpModule(
        argument_spec=dict(
            state=dict(default='present', choices=['present', 'absent'], type='str'),
            name=dict(required=True, type='str'),
            type=dict(required=True, type='str', choices=['A', 'AAAA', 'CAA', 'CNAME', 'MX', 'NAPTR', 'NS', 'PTR', 'SOA', 'SPF', 'SRV', 'TXT']),
            ttl=dict(type='int'),
            target=dict(type='list', elements='str'),
            managed_zone=dict(required=True, type='dict')
        )
    )

    state = module.params['state']
    kind = 'dns#resourceRecordSet'

    fetch = fetch_wrapped_resource(module, 'dns#resourceRecordSet',
                                   'dns#resourceRecordSetsListResponse',
                                   'rrsets')
    changed = False

    if fetch:
        if state == 'present':
            if is_different(module, fetch):
                fetch = update(module, self_link(module), kind, fetch)
                changed = True
        else:
            delete(module, self_link(module), kind, fetch)
            fetch = {}
            changed = True
    else:
        if state == 'present':
            fetch = create(module, collection(module), kind)
            changed = True
        else:
            fetch = {}

    fetch.update({'changed': changed})

    module.exit_json(**fetch)


def create(module, link, kind):
    change = create_change(None, updated_record(module), module)
    change_id = int(change['id'])
    if change['status'] == 'pending':
        wait_for_change_to_complete(change_id, module)
    return fetch_wrapped_resource(module, 'dns#resourceRecordSet',
                                  'dns#resourceRecordSetsListResponse',
                                  'rrsets')


def update(module, link, kind, fetch):
    change = create_change(fetch, updated_record(module), module)
    change_id = int(change['id'])
    if change['status'] == 'pending':
        wait_for_change_to_complete(change_id, module)
    return fetch_wrapped_resource(module, 'dns#resourceRecordSet',
                                  'dns#resourceRecordSetsListResponse',
                                  'rrsets')


def delete(module, link, kind, fetch):
    change = create_change(fetch, None, module)
    change_id = int(change['id'])
    if change['status'] == 'pending':
        wait_for_change_to_complete(change_id, module)
    return fetch_wrapped_resource(module, 'dns#resourceRecordSet',
                                  'dns#resourceRecordSetsListResponse',
                                  'rrsets')


def resource_to_request(module):
    request = {
        u'kind': 'dns#resourceRecordSet',
        u'managed_zone': replace_resource_dict(module.params.get(u'managed_zone', {}), 'name'),
        u'name': module.params.get('name'),
        u'type': module.params.get('type'),
        u'ttl': module.params.get('ttl'),
        u'rrdatas': module.params.get('target')
    }
    return_vals = {}
    for k, v in request.items():
        if v:
            return_vals[k] = v

    return return_vals


def fetch_resource(module, link, kind):
    auth = GcpSession(module, 'dns')
    return return_if_object(module, auth.get(link), kind)


def fetch_wrapped_resource(module, kind, wrap_kind, wrap_path):
    result = fetch_resource(module, self_link(module), wrap_kind)
    if result is None or wrap_path not in result:
        return None

    result = unwrap_resource(result[wrap_path], module)

    if result is None:
        return None

    if result['kind'] != kind:
        module.fail_json(msg="Incorrect result: {kind}".format(**result))

    return result


def self_link(module):
    return "https://www.googleapis.com/dns/v1/projects/{project}/managedZones/{managed_zone}/rrsets?name={name}&type={type}".format(**module.params)


def collection(module, extra_url=''):
    return "https://www.googleapis.com/dns/v1/projects/{project}/managedZones/{managed_zone}/changes".format(**module.params) + extra_url


def return_if_object(module, response, kind):
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
    if result['kind'] != kind:
        module.fail_json(msg="Incorrect result: {kind}".format(**result))

    return result


def is_different(module, response):
    request = resource_to_request(module)
    response = response_to_hash(module, response)

    # Remove all output-only from response.
    response_vals = {}
    for k, v in response.items():
        if k in request:
            response_vals[k] = v

    request_vals = {}
    for k, v in request.items():
        if k in response:
            request_vals[k] = v

    return GcpRequest(request_vals) != GcpRequest(response_vals)


# Remove unnecessary properties from the response.
# This is for doing comparisons with Ansible's current parameters.
def response_to_hash(module, response):
    return {
        u'name': response.get(u'name'),
        u'type': response.get(u'type'),
        u'ttl': response.get(u'ttl'),
        u'rrdatas': response.get(u'target')
    }


def updated_record(module):
    return {
        'kind': 'dns#resourceRecordSet',
        'name': module.params['name'],
        'type': module.params['type'],
        'ttl': module.params['ttl'] if module.params['ttl'] else 900,
        'rrdatas': module.params['target']
    }


def unwrap_resource(result, module):
    if not result:
        return None
    return result[0]


class SOAForwardable(object):
    def __init__(self, params, module):
        self.params = params
        self.module = module

    def fail_json(self, *args, **kwargs):
        self.module.fail_json(*args, **kwargs)


def prefetch_soa_resource(module):
    name = module.params['name'].split('.')[1:]

    resource = SOAForwardable({
        'type': 'SOA',
        'managed_zone': module.params['managed_zone'],
        'name': '.'.join(name),
        'project': module.params['project'],
        'scopes': module.params['scopes'],
        'service_account_file': module.params['service_account_file'],
        'auth_kind': module.params['auth_kind'],
        'service_account_email': module.params['service_account_email']
    }, module)

    result = fetch_wrapped_resource(resource, 'dns#resourceRecordSet',
                                    'dns#resourceRecordSetsListResponse',
                                    'rrsets')
    if not result:
        raise ValueError("Google DNS Managed Zone %s not found" % module.params['managed_zone'])
    return result


def create_change(original, updated, module):
    auth = GcpSession(module, 'dns')
    return return_if_change_object(module,
                                   auth.post(collection(module),
                                             resource_to_change_request(
                                                 original, updated, module)
                                             ))


# Fetch current SOA. We need the last SOA so we can increment its serial
def update_soa(module):
    original_soa = prefetch_soa_resource(module)

    # Create a clone of the SOA record so we can update it
    updated_soa = copy.deepcopy(original_soa)

    soa_parts = updated_soa['rrdatas'][0].split(' ')
    soa_parts[2] = str(int(soa_parts[2]) + 1)
    updated_soa['rrdatas'][0] = ' '.join(soa_parts)
    return [original_soa, updated_soa]


def resource_to_change_request(original_record, updated_record, module):
    original_soa, updated_soa = update_soa(module)
    result = new_change_request()
    add_additions(result, updated_soa, updated_record)
    add_deletions(result, original_soa, original_record)
    return result


def add_additions(result, updated_soa, updated_record):
    if updated_soa:
        result['additions'].append(updated_soa)
    if updated_record:
        result['additions'].append(updated_record)


def add_deletions(result, original_soa, original_record):
    if original_soa:
        result['deletions'].append(original_soa)

    if original_record:
        result['deletions'].append(original_record)


# TODO(nelsonjr): Merge and delete this code once async operation
# declared in api.yaml
def wait_for_change_to_complete(change_id, module):
    status = 'pending'
    while status == 'pending':
        status = get_change_status(change_id, module)
        if status != 'done':
            time.sleep(0.5)


def get_change_status(change_id, module):
    auth = GcpSession(module, 'dns')
    link = collection(module, "/%s" % change_id)
    return return_if_change_object(module, auth.get(link))['status']


def new_change_request():
    return {
        'kind': 'dns#change',
        'additions': [],
        'deletions': [],
        'start_time': datetime.datetime.now().isoformat()
    }


def return_if_change_object(module, response):
    # If not found, return nothing.
    if response.status_code == 404:
        return None

    if response.status_code == 204:
        return None

    try:
        response.raise_for_status()
        result = response.json()
    except getattr(json.decoder, 'JSONDecodeError', ValueError) as inst:
        module.fail_json(msg="Invalid JSON response with error: %s" % inst)

    if result['kind'] != 'dns#change':
        module.fail_json(msg="Invalid result: %s" % result['kind'])

    return result


if __name__ == '__main__':
    main()
