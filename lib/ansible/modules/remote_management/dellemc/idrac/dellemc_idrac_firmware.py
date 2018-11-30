#!/usr/bin/python
# -*- coding: utf-8 -*-

#
# Dell EMC OpenManage Ansible Modules
# Version 1.0
# Copyright (C) 2018 Dell Inc.

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# All rights reserved. Dell, EMC, and other trademarks are trademarks of Dell Inc. or its subsidiaries.
# Other trademarks may be trademarks of their respective owners.
#


from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: dellemc_idrac_firmware
short_description: Firmware update from a repository on a network share (CIFS, NFS).
version_added: "2.8"
description:
    - Update the Firmware by connecting to a network share (either CIFS or NFS) that contains a catalog of
        available updates.
    - Network share should contain a valid repository of Update Packages (DUPs) and a catalog file describing the DUPs.
    - All applicable updates contained in the repository are applied to the system.
    - This feature is available only with iDRAC Enterprise License.
options:
    idrac_ip:
        required: True
        description: iDRAC IP Address.
    idrac_user:
        required: True
        description: iDRAC username.
    idrac_pwd:
        required: True
        description: iDRAC user password.
    idrac_port:
        required: False
        description: iDRAC port.
        default: 443
    share_name:
        required: True
        description: CIFS or NFS Network share.
    share_user:
        required: False
        description: Network share user in the format 'user@domain' or 'domain\\user' if user is
            part of a domain else 'user'. This option is mandatory for CIFS Network Share.
    share_pwd:
        required: False
        description: Network share user password. This option is mandatory for CIFS Network Share.
    share_mnt:
        required: True
        description: Local mount path of the network share with read-write permission for ansible user.
            This option is mandatory for Network Share.
    reboot:
        required: False
        description: Whether to reboots after applying the updates or not.
        default: False
        type: bool
    job_wait:
        required:  True
        description: Whether to wait for job completion or not.
        type: bool
        default: True
    catalog_file_name:
        required: False
        description: Catalog file name relative to the I(share_name).
        type: str
        default: 'Catalog.xml'

requirements:
    - "omsdk"
    - "python >= 2.7.5"
author: "Rajeev Arakkal (@rajeevarakkal)"
"""

EXAMPLES = """
---
- name: Update firmware from repository on a Network Share
  dellemc_idrac_firmware:
       idrac_ip:   "{{ idrac_ip }}"
       idrac_user: "{{ idrac_user }}"
       idrac_pwd:  "{{ idrac_pwd }}"
       share_name: "xx.xx.xx.xx:/share"
       share_user: "{{ share_user }}"
       share_pwd:  "{{ share_pwd }}"
       share_mnt: "/mnt/share"
       reboot:     True
       job_wait:   True
       catalog_file_name:  "Catalog.xml"
"""

RETURN = """
---
msg:
    description: Updates firmware from a repository on a network share (CIFS, NFS).
    returned: success
    type: string
    sample: "{
        'CompletionTime': '2018-01-24T00:47:33',
        'Id': 'JID_XXXXXXXXXXXX',
        'JobState': 'Completed',
        'JobType': 'ImportConfiguration',
        'Message': 'Successfully imported and applied Server Configuration Profile.',
        'MessageId': 'SYSXXX',
        'Name': 'Import Configuration',
        'StartTime': 'TIME_NOW',
        'Status': 'Success',
    }"
"""


from ansible.module_utils.remote_management.dellemc.dellemc_idrac import iDRACConnection
from ansible.module_utils.basic import AnsibleModule
try:
    from omsdk.sdkcreds import UserCredentials
    from omsdk.sdkfile import FileOnShare
    HAS_OMSDK = True
except ImportError:
    HAS_OMSDK = False


def _validate_catalog_file(catalog_file_name):
    normilized_file_name = catalog_file_name.lower()
    if not normilized_file_name:
        raise ValueError('catalog_file_name should be a non-empty string.')
    elif not normilized_file_name.endswith("xml"):
        raise ValueError('catalog_file_name should be an XML file.')


def update_firmware(idrac, module):
    """Update firmware from a network share and return the job details."""
    msg = {}
    msg['changed'] = False
    msg['msg'] = {}
    err = False

    try:
        _validate_catalog_file(module.params['catalog_file_name'])
    except ValueError as e:
        module.fail_json(msg=str(e))

    try:
        upd_share = FileOnShare(remote=module.params['share_name'] + "/" + module.params['catalog_file_name'],
                                mount_point=module.params['share_mnt'],
                                isFolder=False,
                                creds=UserCredentials(
                                    module.params['share_user'],
                                    module.params['share_pwd'])
                                )

        idrac.use_redfish = True
        if '12' in idrac.ServerGeneration or '13' in idrac.ServerGeneration:
            idrac.use_redfish = False

        apply_update = True
        msg['msg'] = idrac.update_mgr.update_from_repo(upd_share,
                                                       apply_update,
                                                       module.params['reboot'],
                                                       module.params['job_wait'])

        if "Status" in msg['msg']:
            if msg['msg']['Status'] == "Success":
                if module.params['job_wait'] is True:
                    msg['changed'] = True
            else:
                err = True

    except Exception as e:
        err = True
        msg['msg'] = str(e)

    return msg, err


def main():
    module = AnsibleModule(
        argument_spec=dict(

            # iDRAC Credentials
            idrac_ip=dict(required=True, type='str'),
            idrac_user=dict(required=True, type='str'),
            idrac_pwd=dict(required=True, type='str', no_log=True),
            idrac_port=dict(required=False, default=443, type='int'),

            # Network File Share
            share_name=dict(required=True, type='str'),
            share_user=dict(required=False, type='str'),
            share_pwd=dict(required=False, type='str', no_log=True),
            share_mnt=dict(required=True, type='str'),

            # Firmware update parameters
            catalog_file_name=dict(required=False, type='str', default='Catalog.xml'),
            reboot=dict(required=False, default=False, type='bool'),
            job_wait=dict(required=False, default=True, type='bool')
        ),

        supports_check_mode=False)

    try:
        # Connect to iDRAC and update firmware
        with iDRACConnection(module.params) as idrac:
            msg, err = update_firmware(idrac, module)
    except (ImportError, ValueError, RuntimeError) as e:
        module.fail_json(msg=str(e))

    if err:
        module.fail_json(**msg)
    module.exit_json(**msg)


if __name__ == '__main__':
    main()
