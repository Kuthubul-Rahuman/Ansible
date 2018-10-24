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
module: gcp_compute_backend_service
description:
- Creates a BackendService resource in the specified project using the data included
  in the request.
short_description: Creates a GCP BackendService
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
    choices:
    - present
    - absent
    default: present
  affinity_cookie_ttl_sec:
    description:
    - Lifetime of cookies in seconds if session_affinity is GENERATED_COOKIE. If set
      to 0, the cookie is non-persistent and lasts only until the end of the browser
      session (or equivalent). The maximum allowed value for TTL is one day.
    - When the load balancing scheme is INTERNAL, this field is not used.
    required: false
  backends:
    description:
    - The list of backends that serve this BackendService.
    required: false
    suboptions:
      balancing_mode:
        description:
        - Specifies the balancing mode for this backend.
        - For global HTTP(S) or TCP/SSL load balancing, the default is UTILIZATION.
          Valid values are UTILIZATION, RATE (for HTTP(S)) and CONNECTION (for TCP/SSL).
        - This cannot be used for internal load balancing.
        required: false
        choices:
        - UTILIZATION
        - RATE
        - CONNECTION
      capacity_scaler:
        description:
        - A multiplier applied to the group's maximum servicing capacity (based on
          UTILIZATION, RATE or CONNECTION).
        - Default value is 1, which means the group will serve up to 100% of its configured
          capacity (depending on balancingMode). A setting of 0 means the group is
          completely drained, offering 0% of its available Capacity. Valid range is
          [0.0,1.0].
        - This cannot be used for internal load balancing.
        required: false
      description:
        description:
        - An optional description of this resource.
        - Provide this property when you create the resource.
        required: false
      group:
        description:
        - This instance group defines the list of instances that serve traffic. Member
          virtual machine instances from each instance group must live in the same
          zone as the instance group itself.
        - No two backends in a backend service are allowed to use same Instance Group
          resource.
        - When the BackendService has load balancing scheme INTERNAL, the instance
          group must be in a zone within the same region as the BackendService.
        - 'This field represents a link to a InstanceGroup resource in GCP. It can
          be specified in two ways. You can add `register: name-of-resource` to a
          gcp_compute_instance_group task and then set this group field to "{{ name-of-resource
          }}" Alternatively, you can set this group to a dictionary with the selfLink
          key where the value is the selfLink of your InstanceGroup'
        required: false
      max_connections:
        description:
        - The max number of simultaneous connections for the group. Can be used with
          either CONNECTION or UTILIZATION balancing modes.
        - For CONNECTION mode, either maxConnections or maxConnectionsPerInstance
          must be set.
        - This cannot be used for internal load balancing.
        required: false
      max_connections_per_instance:
        description:
        - The max number of simultaneous connections that a single backend instance
          can handle. This is used to calculate the capacity of the group. Can be
          used in either CONNECTION or UTILIZATION balancing modes.
        - For CONNECTION mode, either maxConnections or maxConnectionsPerInstance
          must be set.
        - This cannot be used for internal load balancing.
        required: false
      max_rate:
        description:
        - The max requests per second (RPS) of the group.
        - Can be used with either RATE or UTILIZATION balancing modes, but required
          if RATE mode. For RATE mode, either maxRate or maxRatePerInstance must be
          set.
        - This cannot be used for internal load balancing.
        required: false
      max_rate_per_instance:
        description:
        - The max requests per second (RPS) that a single backend instance can handle.
          This is used to calculate the capacity of the group. Can be used in either
          balancing mode. For RATE mode, either maxRate or maxRatePerInstance must
          be set.
        - This cannot be used for internal load balancing.
        required: false
      max_utilization:
        description:
        - Used when balancingMode is UTILIZATION. This ratio defines the CPU utilization
          target for the group. The default is 0.8. Valid range is [0.0, 1.0].
        - This cannot be used for internal load balancing.
        required: false
  cdn_policy:
    description:
    - Cloud CDN configuration for this BackendService.
    required: false
    suboptions:
      cache_key_policy:
        description:
        - The CacheKeyPolicy for this CdnPolicy.
        required: false
        suboptions:
          include_host:
            description:
            - If true requests to different hosts will be cached separately.
            required: false
            type: bool
          include_protocol:
            description:
            - If true, http and https requests will be cached separately.
            required: false
            type: bool
          include_query_string:
            description:
            - If true, include query string parameters in the cache key according
              to query_string_whitelist and query_string_blacklist. If neither is
              set, the entire query string will be included.
            - If false, the query string will be excluded from the cache key entirely.
            required: false
            type: bool
          query_string_blacklist:
            description:
            - Names of query string parameters to exclude in cache keys.
            - All other parameters will be included. Either specify query_string_whitelist
              or query_string_blacklist, not both.
            - "'&' and '=' will be percent encoded and not treated as delimiters."
            required: false
          query_string_whitelist:
            description:
            - Names of query string parameters to include in cache keys.
            - All other parameters will be excluded. Either specify query_string_whitelist
              or query_string_blacklist, not both.
            - "'&' and '=' will be percent encoded and not treated as delimiters."
            required: false
  connection_draining:
    description:
    - Settings for connection draining.
    required: false
    suboptions:
      draining_timeout_sec:
        description:
        - Time for which instance will be drained (not accept new connections, but
          still work to finish started).
        required: false
  description:
    description:
    - An optional description of this resource.
    required: false
  enable_cdn:
    description:
    - If true, enable Cloud CDN for this BackendService.
    - When the load balancing scheme is INTERNAL, this field is not used.
    required: false
    type: bool
  health_checks:
    description:
    - The list of URLs to the HttpHealthCheck or HttpsHealthCheck resource for health
      checking this BackendService. Currently at most one health check can be specified,
      and a health check is required.
    - For internal load balancing, a URL to a HealthCheck resource must be specified
      instead.
    required: false
  iap:
    description:
    - Settings for enabling Cloud Identity Aware Proxy.
    required: false
    version_added: 2.7
    suboptions:
      enabled:
        description:
        - Enables IAP.
        required: false
        type: bool
      oauth2_client_id:
        description:
        - OAuth2 Client ID for IAP.
        required: false
      oauth2_client_secret:
        description:
        - OAuth2 Client Secret for IAP.
        required: false
      oauth2_client_secret_sha256:
        description:
        - OAuth2 Client Secret SHA-256 for IAP.
        required: false
  load_balancing_scheme:
    description:
    - Indicates whether the backend service will be used with internal or external
      load balancing. A backend service created for one type of load balancing cannot
      be used with the other.
    required: false
    version_added: 2.7
    choices:
    - INTERNAL
    - EXTERNAL
  name:
    description:
    - Name of the resource. Provided by the client when the resource is created. The
      name must be 1-63 characters long, and comply with RFC1035. Specifically, the
      name must be 1-63 characters long and match the regular expression `[a-z]([-a-z0-9]*[a-z0-9])?`
      which means the first character must be a lowercase letter, and all following
      characters must be a dash, lowercase letter, or digit, except the last character,
      which cannot be a dash.
    required: false
  port_name:
    description:
    - Name of backend port. The same name should appear in the instance groups referenced
      by this service. Required when the load balancing scheme is EXTERNAL.
    - When the load balancing scheme is INTERNAL, this field is not used.
    required: false
  protocol:
    description:
    - The protocol this BackendService uses to communicate with backends.
    - Possible values are HTTP, HTTPS, TCP, and SSL. The default is HTTP.
    - For internal load balancing, the possible values are TCP and UDP, and the default
      is TCP.
    required: false
    choices:
    - HTTP
    - HTTPS
    - TCP
    - SSL
  region:
    description:
    - The region where the regional backend service resides.
    - This field is not applicable to global backend services.
    required: false
  session_affinity:
    description:
    - Type of session affinity to use. The default is NONE.
    - When the load balancing scheme is EXTERNAL, can be NONE, CLIENT_IP, or GENERATED_COOKIE.
    - When the load balancing scheme is INTERNAL, can be NONE, CLIENT_IP, CLIENT_IP_PROTO,
      or CLIENT_IP_PORT_PROTO.
    - When the protocol is UDP, this field is not used.
    required: false
    choices:
    - NONE
    - CLIENT_IP
    - GENERATED_COOKIE
    - CLIENT_IP_PROTO
    - CLIENT_IP_PORT_PROTO
  timeout_sec:
    description:
    - How many seconds to wait for the backend before considering it a failed request.
      Default is 30 seconds. Valid range is [1, 86400].
    required: false
    aliases:
    - timeout_seconds
extends_documentation_fragment: gcp
'''

EXAMPLES = '''
- name: create a instance group
  gcp_compute_instance_group:
      name: "instancegroup-backendservice"
      zone: us-central1-a
      project: "{{ gcp_project }}"
      auth_kind: "{{ gcp_cred_kind }}"
      service_account_file: "{{ gcp_cred_file }}"
      state: present
  register: instancegroup

- name: create a http health check
  gcp_compute_http_health_check:
      name: "httphealthcheck-backendservice"
      healthy_threshold: 10
      port: 8080
      timeout_sec: 2
      unhealthy_threshold: 5
      project: "{{ gcp_project }}"
      auth_kind: "{{ gcp_cred_kind }}"
      service_account_file: "{{ gcp_cred_file }}"
      state: present
  register: healthcheck

- name: create a backend service
  gcp_compute_backend_service:
      name: "test_object"
      backends:
      - group: "{{ instancegroup }}"
      health_checks:
      - "{{ healthcheck.selfLink }}"
      enable_cdn: true
      project: "test_project"
      auth_kind: "serviceaccount"
      service_account_file: "/tmp/auth.pem"
      state: present
'''

RETURN = '''
affinityCookieTtlSec:
  description:
  - Lifetime of cookies in seconds if session_affinity is GENERATED_COOKIE. If set
    to 0, the cookie is non-persistent and lasts only until the end of the browser
    session (or equivalent). The maximum allowed value for TTL is one day.
  - When the load balancing scheme is INTERNAL, this field is not used.
  returned: success
  type: int
backends:
  description:
  - The list of backends that serve this BackendService.
  returned: success
  type: complex
  contains:
    balancingMode:
      description:
      - Specifies the balancing mode for this backend.
      - For global HTTP(S) or TCP/SSL load balancing, the default is UTILIZATION.
        Valid values are UTILIZATION, RATE (for HTTP(S)) and CONNECTION (for TCP/SSL).
      - This cannot be used for internal load balancing.
      returned: success
      type: str
    capacityScaler:
      description:
      - A multiplier applied to the group's maximum servicing capacity (based on UTILIZATION,
        RATE or CONNECTION).
      - Default value is 1, which means the group will serve up to 100% of its configured
        capacity (depending on balancingMode). A setting of 0 means the group is completely
        drained, offering 0% of its available Capacity. Valid range is [0.0,1.0].
      - This cannot be used for internal load balancing.
      returned: success
      type: str
    description:
      description:
      - An optional description of this resource.
      - Provide this property when you create the resource.
      returned: success
      type: str
    group:
      description:
      - This instance group defines the list of instances that serve traffic. Member
        virtual machine instances from each instance group must live in the same zone
        as the instance group itself.
      - No two backends in a backend service are allowed to use same Instance Group
        resource.
      - When the BackendService has load balancing scheme INTERNAL, the instance group
        must be in a zone within the same region as the BackendService.
      returned: success
      type: dict
    maxConnections:
      description:
      - The max number of simultaneous connections for the group. Can be used with
        either CONNECTION or UTILIZATION balancing modes.
      - For CONNECTION mode, either maxConnections or maxConnectionsPerInstance must
        be set.
      - This cannot be used for internal load balancing.
      returned: success
      type: int
    maxConnectionsPerInstance:
      description:
      - The max number of simultaneous connections that a single backend instance
        can handle. This is used to calculate the capacity of the group. Can be used
        in either CONNECTION or UTILIZATION balancing modes.
      - For CONNECTION mode, either maxConnections or maxConnectionsPerInstance must
        be set.
      - This cannot be used for internal load balancing.
      returned: success
      type: int
    maxRate:
      description:
      - The max requests per second (RPS) of the group.
      - Can be used with either RATE or UTILIZATION balancing modes, but required
        if RATE mode. For RATE mode, either maxRate or maxRatePerInstance must be
        set.
      - This cannot be used for internal load balancing.
      returned: success
      type: int
    maxRatePerInstance:
      description:
      - The max requests per second (RPS) that a single backend instance can handle.
        This is used to calculate the capacity of the group. Can be used in either
        balancing mode. For RATE mode, either maxRate or maxRatePerInstance must be
        set.
      - This cannot be used for internal load balancing.
      returned: success
      type: str
    maxUtilization:
      description:
      - Used when balancingMode is UTILIZATION. This ratio defines the CPU utilization
        target for the group. The default is 0.8. Valid range is [0.0, 1.0].
      - This cannot be used for internal load balancing.
      returned: success
      type: str
cdnPolicy:
  description:
  - Cloud CDN configuration for this BackendService.
  returned: success
  type: complex
  contains:
    cacheKeyPolicy:
      description:
      - The CacheKeyPolicy for this CdnPolicy.
      returned: success
      type: complex
      contains:
        includeHost:
          description:
          - If true requests to different hosts will be cached separately.
          returned: success
          type: bool
        includeProtocol:
          description:
          - If true, http and https requests will be cached separately.
          returned: success
          type: bool
        includeQueryString:
          description:
          - If true, include query string parameters in the cache key according to
            query_string_whitelist and query_string_blacklist. If neither is set,
            the entire query string will be included.
          - If false, the query string will be excluded from the cache key entirely.
          returned: success
          type: bool
        queryStringBlacklist:
          description:
          - Names of query string parameters to exclude in cache keys.
          - All other parameters will be included. Either specify query_string_whitelist
            or query_string_blacklist, not both.
          - "'&' and '=' will be percent encoded and not treated as delimiters."
          returned: success
          type: list
        queryStringWhitelist:
          description:
          - Names of query string parameters to include in cache keys.
          - All other parameters will be excluded. Either specify query_string_whitelist
            or query_string_blacklist, not both.
          - "'&' and '=' will be percent encoded and not treated as delimiters."
          returned: success
          type: list
connectionDraining:
  description:
  - Settings for connection draining.
  returned: success
  type: complex
  contains:
    drainingTimeoutSec:
      description:
      - Time for which instance will be drained (not accept new connections, but still
        work to finish started).
      returned: success
      type: int
creationTimestamp:
  description:
  - Creation timestamp in RFC3339 text format.
  returned: success
  type: str
description:
  description:
  - An optional description of this resource.
  returned: success
  type: str
enableCDN:
  description:
  - If true, enable Cloud CDN for this BackendService.
  - When the load balancing scheme is INTERNAL, this field is not used.
  returned: success
  type: bool
healthChecks:
  description:
  - The list of URLs to the HttpHealthCheck or HttpsHealthCheck resource for health
    checking this BackendService. Currently at most one health check can be specified,
    and a health check is required.
  - For internal load balancing, a URL to a HealthCheck resource must be specified
    instead.
  returned: success
  type: list
id:
  description:
  - The unique identifier for the resource.
  returned: success
  type: int
iap:
  description:
  - Settings for enabling Cloud Identity Aware Proxy.
  returned: success
  type: complex
  contains:
    enabled:
      description:
      - Enables IAP.
      returned: success
      type: bool
    oauth2ClientId:
      description:
      - OAuth2 Client ID for IAP.
      returned: success
      type: str
    oauth2ClientSecret:
      description:
      - OAuth2 Client Secret for IAP.
      returned: success
      type: str
    oauth2ClientSecretSha256:
      description:
      - OAuth2 Client Secret SHA-256 for IAP.
      returned: success
      type: str
loadBalancingScheme:
  description:
  - Indicates whether the backend service will be used with internal or external load
    balancing. A backend service created for one type of load balancing cannot be
    used with the other.
  returned: success
  type: str
name:
  description:
  - Name of the resource. Provided by the client when the resource is created. The
    name must be 1-63 characters long, and comply with RFC1035. Specifically, the
    name must be 1-63 characters long and match the regular expression `[a-z]([-a-z0-9]*[a-z0-9])?`
    which means the first character must be a lowercase letter, and all following
    characters must be a dash, lowercase letter, or digit, except the last character,
    which cannot be a dash.
  returned: success
  type: str
portName:
  description:
  - Name of backend port. The same name should appear in the instance groups referenced
    by this service. Required when the load balancing scheme is EXTERNAL.
  - When the load balancing scheme is INTERNAL, this field is not used.
  returned: success
  type: str
protocol:
  description:
  - The protocol this BackendService uses to communicate with backends.
  - Possible values are HTTP, HTTPS, TCP, and SSL. The default is HTTP.
  - For internal load balancing, the possible values are TCP and UDP, and the default
    is TCP.
  returned: success
  type: str
region:
  description:
  - The region where the regional backend service resides.
  - This field is not applicable to global backend services.
  returned: success
  type: str
sessionAffinity:
  description:
  - Type of session affinity to use. The default is NONE.
  - When the load balancing scheme is EXTERNAL, can be NONE, CLIENT_IP, or GENERATED_COOKIE.
  - When the load balancing scheme is INTERNAL, can be NONE, CLIENT_IP, CLIENT_IP_PROTO,
    or CLIENT_IP_PORT_PROTO.
  - When the protocol is UDP, this field is not used.
  returned: success
  type: str
timeoutSec:
  description:
  - How many seconds to wait for the backend before considering it a failed request.
    Default is 30 seconds. Valid range is [1, 86400].
  returned: success
  type: int
'''

################################################################################
# Imports
################################################################################

from ansible.module_utils.gcp_utils import navigate_hash, GcpSession, GcpModule, GcpRequest, remove_nones_from_dict, replace_resource_dict
import json
import re
import time

################################################################################
# Main
################################################################################


def main():
    """Main function"""

    module = GcpModule(
        argument_spec=dict(
            state=dict(default='present', choices=['present', 'absent'], type='str'),
            affinity_cookie_ttl_sec=dict(type='int'),
            backends=dict(type='list', elements='dict', options=dict(
                balancing_mode=dict(type='str', choices=['UTILIZATION', 'RATE', 'CONNECTION']),
                capacity_scaler=dict(type='str'),
                description=dict(type='str'),
                group=dict(type='dict'),
                max_connections=dict(type='int'),
                max_connections_per_instance=dict(type='int'),
                max_rate=dict(type='int'),
                max_rate_per_instance=dict(type='str'),
                max_utilization=dict(type='str')
            )),
            cdn_policy=dict(type='dict', options=dict(
                cache_key_policy=dict(type='dict', options=dict(
                    include_host=dict(type='bool'),
                    include_protocol=dict(type='bool'),
                    include_query_string=dict(type='bool'),
                    query_string_blacklist=dict(type='list', elements='str'),
                    query_string_whitelist=dict(type='list', elements='str')
                ))
            )),
            connection_draining=dict(type='dict', options=dict(
                draining_timeout_sec=dict(type='int')
            )),
            description=dict(type='str'),
            enable_cdn=dict(type='bool'),
            health_checks=dict(type='list', elements='str'),
            iap=dict(type='dict', options=dict(
                enabled=dict(type='bool'),
                oauth2_client_id=dict(type='str'),
                oauth2_client_secret=dict(type='str'),
                oauth2_client_secret_sha256=dict(type='str')
            )),
            load_balancing_scheme=dict(type='str', choices=['INTERNAL', 'EXTERNAL']),
            name=dict(type='str'),
            port_name=dict(type='str'),
            protocol=dict(type='str', choices=['HTTP', 'HTTPS', 'TCP', 'SSL']),
            region=dict(type='str'),
            session_affinity=dict(type='str', choices=['NONE', 'CLIENT_IP', 'GENERATED_COOKIE', 'CLIENT_IP_PROTO', 'CLIENT_IP_PORT_PROTO']),
            timeout_sec=dict(type='int', aliases=['timeout_seconds'])
        )
    )

    if not module.params['scopes']:
        module.params['scopes'] = ['https://www.googleapis.com/auth/compute']

    state = module.params['state']
    kind = 'compute#backendService'

    fetch = fetch_resource(module, self_link(module), kind)
    changed = False

    if fetch:
        if state == 'present':
            if is_different(module, fetch):
                update(module, self_link(module), kind)
                fetch = fetch_resource(module, self_link(module), kind)
                changed = True
        else:
            delete(module, self_link(module), kind)
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
    auth = GcpSession(module, 'compute')
    return wait_for_operation(module, auth.post(link, resource_to_request(module)))


def update(module, link, kind):
    auth = GcpSession(module, 'compute')
    return wait_for_operation(module, auth.put(link, resource_to_request(module)))


def delete(module, link, kind):
    auth = GcpSession(module, 'compute')
    return wait_for_operation(module, auth.delete(link))


def resource_to_request(module):
    request = {
        u'kind': 'compute#backendService',
        u'affinityCookieTtlSec': module.params.get('affinity_cookie_ttl_sec'),
        u'backends': BackendServiceBackendsArray(module.params.get('backends', []), module).to_request(),
        u'cdnPolicy': BackendServiceCdnpolicy(module.params.get('cdn_policy', {}), module).to_request(),
        u'connectionDraining': BackendServiceConnectiondraining(module.params.get('connection_draining', {}), module).to_request(),
        u'description': module.params.get('description'),
        u'enableCDN': module.params.get('enable_cdn'),
        u'healthChecks': module.params.get('health_checks'),
        u'iap': BackendServiceIap(module.params.get('iap', {}), module).to_request(),
        u'loadBalancingScheme': module.params.get('load_balancing_scheme'),
        u'name': module.params.get('name'),
        u'portName': module.params.get('port_name'),
        u'protocol': module.params.get('protocol'),
        u'region': region_selflink(module.params.get('region'), module.params),
        u'sessionAffinity': module.params.get('session_affinity'),
        u'timeoutSec': module.params.get('timeout_sec')
    }
    return_vals = {}
    for k, v in request.items():
        if v:
            return_vals[k] = v

    return return_vals


def fetch_resource(module, link, kind, allow_not_found=True):
    auth = GcpSession(module, 'compute')
    return return_if_object(module, auth.get(link), kind, allow_not_found)


def self_link(module):
    return "https://www.googleapis.com/compute/v1/projects/{project}/global/backendServices/{name}".format(**module.params)


def collection(module):
    return "https://www.googleapis.com/compute/v1/projects/{project}/global/backendServices".format(**module.params)


def return_if_object(module, response, kind, allow_not_found=False):
    # If not found, return nothing.
    if allow_not_found and response.status_code == 404:
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
        u'affinityCookieTtlSec': response.get(u'affinityCookieTtlSec'),
        u'backends': BackendServiceBackendsArray(response.get(u'backends', []), module).from_response(),
        u'cdnPolicy': BackendServiceCdnpolicy(response.get(u'cdnPolicy', {}), module).from_response(),
        u'connectionDraining': BackendServiceConnectiondraining(response.get(u'connectionDraining', {}), module).from_response(),
        u'creationTimestamp': response.get(u'creationTimestamp'),
        u'description': response.get(u'description'),
        u'enableCDN': response.get(u'enableCDN'),
        u'healthChecks': response.get(u'healthChecks'),
        u'id': response.get(u'id'),
        u'iap': BackendServiceIap(response.get(u'iap', {}), module).from_response(),
        u'loadBalancingScheme': response.get(u'loadBalancingScheme'),
        u'name': response.get(u'name'),
        u'portName': response.get(u'portName'),
        u'protocol': response.get(u'protocol'),
        u'region': response.get(u'region'),
        u'sessionAffinity': response.get(u'sessionAffinity'),
        u'timeoutSec': response.get(u'timeoutSec')
    }


def region_selflink(name, params):
    if name is None:
        return
    url = r"https://www.googleapis.com/compute/v1/projects/.*/regions/[a-z1-9\-]*"
    if not re.match(url, name):
        name = "https://www.googleapis.com/compute/v1/projects/{project}/regions/%s".format(**params) % name
    return name


def async_op_url(module, extra_data=None):
    if extra_data is None:
        extra_data = {}
    url = "https://www.googleapis.com/compute/v1/projects/{project}/global/operations/{op_id}"
    combined = extra_data.copy()
    combined.update(module.params)
    return url.format(**combined)


def wait_for_operation(module, response):
    op_result = return_if_object(module, response, 'compute#operation')
    if op_result is None:
        return {}
    status = navigate_hash(op_result, ['status'])
    wait_done = wait_for_completion(status, op_result, module)
    return fetch_resource(module, navigate_hash(wait_done, ['targetLink']), 'compute#backendService')


def wait_for_completion(status, op_result, module):
    op_id = navigate_hash(op_result, ['name'])
    op_uri = async_op_url(module, {'op_id': op_id})
    while status != 'DONE':
        raise_if_errors(op_result, ['error', 'errors'], 'message')
        time.sleep(1.0)
        if status not in ['PENDING', 'RUNNING', 'DONE']:
            module.fail_json(msg="Invalid result %s" % status)
        op_result = fetch_resource(module, op_uri, 'compute#operation')
        status = navigate_hash(op_result, ['status'])
    return op_result


def raise_if_errors(response, err_path, module):
    errors = navigate_hash(response, err_path)
    if errors is not None:
        module.fail_json(msg=errors)


class BackendServiceBackendsArray(object):
    def __init__(self, request, module):
        self.module = module
        if request:
            self.request = request
        else:
            self.request = []

    def to_request(self):
        items = []
        for item in self.request:
            items.append(self._request_for_item(item))
        return items

    def from_response(self):
        items = []
        for item in self.request:
            items.append(self._response_from_item(item))
        return items

    def _request_for_item(self, item):
        return remove_nones_from_dict({
            u'balancingMode': item.get('balancing_mode'),
            u'capacityScaler': item.get('capacity_scaler'),
            u'description': item.get('description'),
            u'group': replace_resource_dict(item.get(u'group', {}), 'selfLink'),
            u'maxConnections': item.get('max_connections'),
            u'maxConnectionsPerInstance': item.get('max_connections_per_instance'),
            u'maxRate': item.get('max_rate'),
            u'maxRatePerInstance': item.get('max_rate_per_instance'),
            u'maxUtilization': item.get('max_utilization')
        })

    def _response_from_item(self, item):
        return remove_nones_from_dict({
            u'balancingMode': item.get(u'balancingMode'),
            u'capacityScaler': item.get(u'capacityScaler'),
            u'description': item.get(u'description'),
            u'group': item.get(u'group'),
            u'maxConnections': item.get(u'maxConnections'),
            u'maxConnectionsPerInstance': item.get(u'maxConnectionsPerInstance'),
            u'maxRate': item.get(u'maxRate'),
            u'maxRatePerInstance': item.get(u'maxRatePerInstance'),
            u'maxUtilization': item.get(u'maxUtilization')
        })


class BackendServiceCdnpolicy(object):
    def __init__(self, request, module):
        self.module = module
        if request:
            self.request = request
        else:
            self.request = {}

    def to_request(self):
        return remove_nones_from_dict({
            u'cacheKeyPolicy': BackendServiceCachekeypolicy(self.request.get('cache_key_policy', {}), self.module).to_request()
        })

    def from_response(self):
        return remove_nones_from_dict({
            u'cacheKeyPolicy': BackendServiceCachekeypolicy(self.request.get(u'cacheKeyPolicy', {}), self.module).from_response()
        })


class BackendServiceCachekeypolicy(object):
    def __init__(self, request, module):
        self.module = module
        if request:
            self.request = request
        else:
            self.request = {}

    def to_request(self):
        return remove_nones_from_dict({
            u'includeHost': self.request.get('include_host'),
            u'includeProtocol': self.request.get('include_protocol'),
            u'includeQueryString': self.request.get('include_query_string'),
            u'queryStringBlacklist': self.request.get('query_string_blacklist'),
            u'queryStringWhitelist': self.request.get('query_string_whitelist')
        })

    def from_response(self):
        return remove_nones_from_dict({
            u'includeHost': self.request.get(u'includeHost'),
            u'includeProtocol': self.request.get(u'includeProtocol'),
            u'includeQueryString': self.request.get(u'includeQueryString'),
            u'queryStringBlacklist': self.request.get(u'queryStringBlacklist'),
            u'queryStringWhitelist': self.request.get(u'queryStringWhitelist')
        })


class BackendServiceConnectiondraining(object):
    def __init__(self, request, module):
        self.module = module
        if request:
            self.request = request
        else:
            self.request = {}

    def to_request(self):
        return remove_nones_from_dict({
            u'drainingTimeoutSec': self.request.get('draining_timeout_sec')
        })

    def from_response(self):
        return remove_nones_from_dict({
            u'drainingTimeoutSec': self.request.get(u'drainingTimeoutSec')
        })


class BackendServiceIap(object):
    def __init__(self, request, module):
        self.module = module
        if request:
            self.request = request
        else:
            self.request = {}

    def to_request(self):
        return remove_nones_from_dict({
            u'enabled': self.request.get('enabled'),
            u'oauth2ClientId': self.request.get('oauth2_client_id'),
            u'oauth2ClientSecret': self.request.get('oauth2_client_secret'),
            u'oauth2ClientSecretSha256': self.request.get('oauth2_client_secret_sha256')
        })

    def from_response(self):
        return remove_nones_from_dict({
            u'enabled': self.request.get(u'enabled'),
            u'oauth2ClientId': self.request.get(u'oauth2ClientId'),
            u'oauth2ClientSecret': self.request.get(u'oauth2ClientSecret'),
            u'oauth2ClientSecretSha256': self.request.get(u'oauth2ClientSecretSha256')
        })


if __name__ == '__main__':
    main()
