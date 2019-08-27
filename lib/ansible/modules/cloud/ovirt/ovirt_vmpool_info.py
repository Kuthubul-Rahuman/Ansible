#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2016 Red Hat, Inc.
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
#

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = '''
---
module: ovirt_vmpool_info
short_description: Retrieve information about one or more oVirt/RHV vmpools
author: "Ondra Machacek (@machacekondra)"
version_added: "2.3"
description:
    - "Retrieve information about one or more oVirt/RHV vmpools."
    - This module was called C(ovirt_vmpool_facts) before Ansible 2.9, returning C(ansible_facts).
      Note that the M(ovirt_vmpool_info) module no longer returns C(ansible_facts)!
notes:
    - "This module returns a variable C(ovirt_vmpools), which
       contains a list of vmpools. You need to register the result with
       the I(register) keyword to use it."
options:
    pattern:
      description:
        - "Search term which is accepted by oVirt/RHV search backend."
        - "For example to search vmpool X: name=X"
extends_documentation_fragment: ovirt_info
'''

EXAMPLES = '''
# Examples don't contain auth parameter for simplicity,
# look at ovirt_auth module to see how to reuse authentication:

# Gather information about all vm pools which names start with C(centos):
- ovirt_vmpool_info:
    pattern: name=centos*
  register: result
- debug:
    var: result.ovirt_vmpools
'''

RETURN = '''
ovirt_vm_pools:
    description: "List of dictionaries describing the vmpools. Vm pool attributes are mapped to dictionary keys,
                  all vmpools attributes can be found at following url: http://ovirt.github.io/ovirt-engine-api-model/master/#types/vm_pool."
    returned: On success.
    type: list
'''

import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ovirt import (
    check_sdk,
    create_connection,
    get_dict_of_struct,
    ovirt_info_full_argument_spec,
)


def main():
    argument_spec = ovirt_info_full_argument_spec(
        pattern=dict(default='', required=False),
    )
    module = AnsibleModule(argument_spec)
    is_old_facts = module._name == 'ovirt_vmpool_facts'
    if is_old_facts:
        module.deprecate("The 'ovirt_vmpool_facts' module has been renamed to 'ovirt_vmpool_info', "
                         "and the renamed one no longer returns ansible_facts", version='2.13')

    check_sdk(module)

    try:
        auth = module.params.pop('auth')
        connection = create_connection(auth)
        vmpools_service = connection.system_service().vm_pools_service()
        vmpools = vmpools_service.list(search=module.params['pattern'])
        result = dict(
            ovirt_vm_pools=[
                get_dict_of_struct(
                    struct=c,
                    connection=connection,
                    fetch_nested=module.params.get('fetch_nested'),
                    attributes=module.params.get('nested_attributes'),
                ) for c in vmpools
            ],
        )
        if is_old_facts:
            module.exit_json(changed=False, ansible_facts=result)
        else:
            module.exit_json(changed=False, **result)
    except Exception as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())
    finally:
        connection.close(logout=auth.get('token') is None)


if __name__ == '__main__':
    main()
