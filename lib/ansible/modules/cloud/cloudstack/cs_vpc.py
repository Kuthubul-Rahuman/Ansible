#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2016, René Moser <mail@renemoser.net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['stableinterface'],
                    'supported_by': 'community'}


DOCUMENTATION = '''
---
module: cs_vpc
short_description: "Manages VPCs on Apache CloudStack based clouds."
description:
  - "Create, update and delete VPCs."
version_added: "2.3"
author: "René Moser (@resmo)"
options:
  name:
    description:
      - "Name of the VPC."
    required: true
  display_text:
    description:
      - "Display text of the VPC."
      - "If not set, C(name) will be used for creating."
  cidr:
    description:
      - "CIDR of the VPC, e.g. 10.1.0.0/16"
      - "All VPC guest networks' CIDRs must be within this CIDR."
      - "Required on C(state=present)."
  network_domain:
    description:
      - "Network domain for the VPC."
      - "All networks inside the VPC will belong to this domain."
      - "Only considered while creating the VPC, can not be changed."
  vpc_offering:
    description:
      - "Name of the VPC offering."
      - "If not set, default VPC offering is used."
  clean_up:
    description:
      - "Whether to redeploy a VPC router or not when C(state=restarted)"
    version_added: "2.5"
  state:
    description:
      - "State of the VPC."
    default: present
    choices:
      - present
      - absent
      - restarted
  domain:
    description:
      - "Domain the VPC is related to."
  account:
    description:
      - "Account the VPC is related to."
  project:
    description:
      - "Name of the project the VPC is related to."
  zone:
    description:
      - "Name of the zone."
      - "If not set, default zone is used."
  tags:
    description:
      - "List of tags. Tags are a list of dictionaries having keys C(key) and C(value)."
      - "For deleting all tags, set an empty list e.g. C(tags: [])."
    aliases:
      - tag
  poll_async:
    description:
      - "Poll async jobs until job has finished."
    default: true
extends_documentation_fragment: cloudstack
'''

EXAMPLES = '''
- name: Ensure a VPC is present
  local_action:
    module: cs_vpc
    name: my_vpc
    display_text: My example VPC
    cidr: 10.10.0.0/16

- name: Ensure a VPC is absent
  local_action:
    module: cs_vpc
    name: my_vpc
    state: absent

- name: Ensure a VPC is restarted with clean up
  local_action:
    module: cs_vpc
    name: my_vpc
    clean_up: true
    state: restarted
'''

RETURN = '''
---
id:
  description: "UUID of the VPC."
  returned: success
  type: string
  sample: 04589590-ac63-4ffc-93f5-b698b8ac38b6
name:
  description: "Name of the VPC."
  returned: success
  type: string
  sample: my_vpc
display_text:
  description: "Display text of the VPC."
  returned: success
  type: string
  sample: My example VPC
cidr:
  description: "CIDR of the VPC."
  returned: success
  type: string
  sample: 10.10.0.0/16
network_domain:
  description: "Network domain of the VPC."
  returned: success
  type: string
  sample: example.com
region_level_vpc:
  description: "Whether the VPC is region level or not."
  returned: success
  type: boolean
  sample: true
restart_required:
  description: "Whether the VPC router needs a restart or not."
  returned: success
  type: boolean
  sample: true
distributed_vpc_router:
  description: "Whether the VPC uses distributed router or not."
  returned: success
  type: boolean
  sample: true
redundant_vpc_router:
  description: "Whether the VPC has redundant routers or not."
  returned: success
  type: boolean
  sample: true
domain:
  description: "Domain the VPC is related to."
  returned: success
  type: string
  sample: example domain
account:
  description: "Account the VPC is related to."
  returned: success
  type: string
  sample: example account
project:
  description: "Name of project the VPC is related to."
  returned: success
  type: string
  sample: Production
zone:
  description: "Name of zone the VPC is in."
  returned: success
  type: string
  sample: ch-gva-2
state:
  description: "State of the VPC."
  returned: success
  type: string
  sample: Enabled
tags:
  description: "List of resource tags associated with the VPC."
  returned: success
  type: dict
  sample: '[ { "key": "foo", "value": "bar" } ]'
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.cloudstack import (
    AnsibleCloudStack,
    cs_argument_spec,
    cs_required_together,
)


class AnsibleCloudStackVpc(AnsibleCloudStack):

    def __init__(self, module):
        super(AnsibleCloudStackVpc, self).__init__(module)
        self.returns = {
            'cidr': 'cidr',
            'networkdomain': 'network_domain',
            'redundantvpcrouter': 'redundant_vpc_router',
            'distributedvpcrouter': 'distributed_vpc_router',
            'regionlevelvpc': 'region_level_vpc',
            'restartrequired': 'restart_required',
        }
        self.vpc = None

    def get_vpc_offering(self, key=None):
        vpc_offering = self.module.params.get('vpc_offering')
        args = {}
        if vpc_offering:
            args['name'] = vpc_offering
        else:
            args['isdefault'] = True

        vpc_offerings = self.query_api('listVPCOfferings', **args)
        if vpc_offerings:
            return self._get_by_key(key, vpc_offerings['vpcoffering'][0])
        self.module.fail_json(msg="VPC offering not found: %s" % vpc_offering)

    def get_vpc(self):
        if self.vpc:
            return self.vpc
        args = {
            'account': self.get_account(key='name'),
            'domainid': self.get_domain(key='id'),
            'projectid': self.get_project(key='id'),
            'zoneid': self.get_zone(key='id'),
        }
        vpcs = self.query_api('listVPCs', **args)
        if vpcs:
            vpc_name = self.module.params.get('name')
            for v in vpcs['vpc']:
                if vpc_name in [v['name'], v['displaytext'], v['id']]:
                    # Fail if the identifyer matches more than one VPC
                    if self.vpc:
                        self.module.fail_json(msg="More than one VPC found with the provided identifyer: %s" % vpc_name)
                    else:
                        self.vpc = v
        return self.vpc

    def restart_vpc(self):
        self.result['changed'] = True
        vpc = self.get_vpc()
        if vpc and not self.module.check_mode:
            args = {
                'id': vpc['id'],
                'cleanup': self.module.params.get('clean_up'),
            }
            res = self.query_api('restartVPC', **args)

            poll_async = self.module.params.get('poll_async')
            if poll_async:
                self.poll_job(res, 'vpc')
        return vpc

    def present_vpc(self):
        vpc = self.get_vpc()
        if not vpc:
            vpc = self._create_vpc(vpc)
        else:
            vpc = self._update_vpc(vpc)

        if vpc:
            vpc = self.ensure_tags(resource=vpc, resource_type='Vpc')
        return vpc

    def _create_vpc(self, vpc):
        self.result['changed'] = True
        args = {
            'name': self.module.params.get('name'),
            'displaytext': self.get_or_fallback('display_text', 'name'),
            'networkdomain': self.module.params.get('network_domain'),
            'vpcofferingid': self.get_vpc_offering(key='id'),
            'cidr': self.module.params.get('cidr'),
            'account': self.get_account(key='name'),
            'domainid': self.get_domain(key='id'),
            'projectid': self.get_project(key='id'),
            'zoneid': self.get_zone(key='id'),
        }
        self.result['diff']['after'] = args
        if not self.module.check_mode:
            res = self.query_api('createVPC', **args)

            poll_async = self.module.params.get('poll_async')
            if poll_async:
                vpc = self.poll_job(res, 'vpc')
        return vpc

    def _update_vpc(self, vpc):
        args = {
            'id': vpc['id'],
            'displaytext': self.module.params.get('display_text'),
        }
        if self.has_changed(args, vpc):
            self.result['changed'] = True
            if not self.module.check_mode:
                res = self.query_api('updateVPC', **args)

                poll_async = self.module.params.get('poll_async')
                if poll_async:
                    vpc = self.poll_job(res, 'vpc')
        return vpc

    def absent_vpc(self):
        vpc = self.get_vpc()
        if vpc:
            self.result['changed'] = True
            self.result['diff']['before'] = vpc
            if not self.module.check_mode:
                res = self.query_api('deleteVPC', id=vpc['id'])

                poll_async = self.module.params.get('poll_async')
                if poll_async:
                    self.poll_job(res, 'vpc')
        return vpc


def main():
    argument_spec = cs_argument_spec()
    argument_spec.update(dict(
        name=dict(required=True),
        cidr=dict(),
        display_text=dict(),
        vpc_offering=dict(),
        network_domain=dict(),
        clean_up=dict(type='bool'),
        state=dict(choices=['present', 'absent', 'restarted'], default='present'),
        domain=dict(),
        account=dict(),
        project=dict(),
        zone=dict(),
        tags=dict(type='list', aliases=['tag']),
        poll_async=dict(type='bool', default=True),
    ))

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_together=cs_required_together(),
        required_if=[
            ('state', 'present', ['cidr']),
        ],
        supports_check_mode=True,
    )

    acs_vpc = AnsibleCloudStackVpc(module)

    state = module.params.get('state')
    if state == 'absent':
        vpc = acs_vpc.absent_vpc()
    elif state == 'restarted':
        vpc = acs_vpc.restart_vpc()
    else:
        vpc = acs_vpc.present_vpc()

    result = acs_vpc.get_result(vpc)

    module.exit_json(**result)


if __name__ == '__main__':
    main()
