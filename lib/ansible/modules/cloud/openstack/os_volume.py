#!/usr/bin/python

# Copyright (c) 2014 Hewlett-Packard Development Company, L.P.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
from ansible.module_utils._text import to_native
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = '''
---
module: os_volume
short_description: Create/Delete Cinder Volumes
extends_documentation_fragment: openstack
version_added: "2.0"
author: "Monty Taylor (@emonty)"
description:
   - Create or Remove cinder block storage volumes
options:
   size:
     description:
        - Size of volume in GB. This parameter is required when the
          I(state) parameter is 'present'.
   display_name:
     description:
        - Name of volume
     required: true
   display_description:
     description:
       - String describing the volume
   volume_type:
     description:
       - Volume type for volume
   image:
     description:
       - Image name or id for boot from volume
   snapshot_id:
     description:
       - Volume snapshot id to create from
   volume:
     description:
       - Volume name or id to create from
     version_added: "2.3"
   state:
     description:
       - Should the resource be present or absent.
     choices: [present, absent]
     default: present
   availability_zone:
     description:
       - Ignored. Present for backwards compatibility
   scheduler_hints:
     description:
       - Scheduler hints passed to volume API in form of dict
     version_added: "2.4"
requirements:
     - "python >= 2.7"
     - "openstacksdk"
'''

EXAMPLES = '''
# Creates a new volume
- name: create a volume
  hosts: localhost
  tasks:
  - name: create 40g test volume
    os_volume:
      state: present
      cloud: mordred
      availability_zone: az2
      size: 40
      display_name: test_volume
      scheduler_hints:
        same_host: 243e8d3c-8f47-4a61-93d6-7215c344b0c0
'''
from distutils.version import StrictVersion


from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.openstack import openstack_full_argument_spec, openstack_module_kwargs, openstack_cloud_from_module


def _present_volume(module, cloud, sdk):
    if cloud.volume_exists(module.params['display_name']):
        v = cloud.get_volume(module.params['display_name'])
        module.exit_json(changed=False, id=v['id'], volume=v)

    volume_args = dict(
        size=module.params['size'],
        volume_type=module.params['volume_type'],
        display_name=module.params['display_name'],
        display_description=module.params['display_description'],
        snapshot_id=module.params['snapshot_id'],
        availability_zone=module.params['availability_zone'],
    )
    if module.params['image']:
        image_id = cloud.get_image_id(module.params['image'])
        volume_args['imageRef'] = image_id

    if module.params['volume']:
        volume_id = cloud.get_volume_id(module.params['volume'])
        if not volume_id:
            module.fail_json(msg="Failed to find volume '%s'" % module.params['volume'])
        volume_args['source_volid'] = volume_id

    if module.params['scheduler_hints']:
        volume_args['scheduler_hints'] = module.params['scheduler_hints']

    try:
        volume = cloud.create_volume(
            wait=module.params['wait'], timeout=module.params['timeout'],
            **volume_args)
    except sdk.exceptions.HttpException as e:
        if hasattr(e, 'details'):
            module.fail_json(msg=to_native(e.details))
        raise
    module.exit_json(changed=True, id=volume['id'], volume=volume)


def _absent_volume(module, cloud, sdk):
    changed = False
    if cloud.volume_exists(module.params['display_name']):
        try:
            changed = cloud.delete_volume(name_or_id=module.params['display_name'],
                                          wait=module.params['wait'],
                                          timeout=module.params['timeout'])
        except sdk.exceptions.ResourceTimeout:
            module.exit_json(changed=changed)

    module.exit_json(changed=changed)


def main():
    argument_spec = openstack_full_argument_spec(
        size=dict(default=None),
        volume_type=dict(default=None),
        display_name=dict(required=True, aliases=['name']),
        display_description=dict(default=None, aliases=['description']),
        image=dict(default=None),
        snapshot_id=dict(default=None),
        volume=dict(default=None),
        state=dict(default='present', choices=['absent', 'present']),
        scheduler_hints=dict(default=None, type='dict')
    )
    module_kwargs = openstack_module_kwargs(
        mutually_exclusive=[
            ['image', 'snapshot_id', 'volume'],
        ],
    )
    module = AnsibleModule(argument_spec=argument_spec, **module_kwargs)

    state = module.params['state']

    if state == 'present' and not module.params['size']:
        module.fail_json(msg="Size is required when state is 'present'")

    sdk, cloud = openstack_cloud_from_module(module)
    try:
        if state == 'present':
            _present_volume(module, cloud, sdk)
        if state == 'absent':
            _absent_volume(module, cloud, sdk)
    except sdk.exceptions.OpenStackCloudException as e:
        module.fail_json(msg=str(e))


if __name__ == '__main__':
    main()
