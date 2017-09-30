#!/usr/bin/python
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

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'
                    }

DOCUMENTATION = '''
---
module: aws_elasticbeanstalk_app

short_description: create, update, and delete an elastic beanstalk application

version_added: "2.5"

description:
    - "creates, updates, deletes beanstalk applications if app_name is provided"

options:
  app_name:
    description:
      - name of the beanstalk application you wish to manage
    required: false
    default: null
    aliases: [ 'name' ]
  description:
    description:
      - describes the application
    required: false
    default: null
  state:
    description:
      - whether to ensure the application is present or absent
    required: false
    default: present
    choices: ['absent','present']
  terminate_by_force:
    description:
      - when set to true, running environments will be terminated before deleting the application
    required: false
    default: false
author:
    - Harpreet Singh (@hsingh)
    - Stephen Granger (@viper233)
extends_documentation_fragment: aws
'''

EXAMPLES = '''
# Create or update an application
- aws_elasticbeanstalk_app:
    app_name: Sample_App
    description: "Hello World App"
    state: present

# Delete application
- aws_elasticbeanstalk_app:
    app_name: Sample_App
    state: absent

'''

RETURN = '''
app:
    description: beanstalk application
    returned: success and when state != list
    type: dict
    sample: {
        "ApplicationName": "app-name",
        "ConfigurationTemplates": [],
        "DateCreated": "2016-12-28T14:50:03.185000+00:00",
        "DateUpdated": "2016-12-28T14:50:03.185000+00:00",
        "Description": "description",
        "Versions": [
            "1.0.0",
            "1.0.1"
        ]
    }
output:
    description: message indicating what change will occur
    returned: in check mode
    type: string
    sample: App is up-to-date
'''


try:
    import boto3
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False

from ansible.module_utils.aws.core import AnsibleAWSModule
from ansible.module_utils.ec2 import boto3_conn, ec2_argument_spec, get_aws_connection_info


def describe_app(ebs, app_name):
    apps = list_apps(ebs, app_name)

    return None if len(apps) != 1 else apps[0]


def list_apps(ebs, app_name):
    if app_name is not None:
        apps = ebs.describe_applications(ApplicationNames=[app_name])
    else:
        apps = ebs.describe_applications()

    return apps.get("Applications", [])


def check_app(ebs, app, module):
    app_name = module.params['app_name']
    description = module.params['description']
    state = module.params['state']
    terminate_by_force = module.params['terminate_by_force']

    result = {}

    if state == 'present' and app is None:
        result = dict(changed=True, output="App would be created")
    elif state == 'present' and app.get("Description", None) != description:
        result = dict(changed=True, output="App would be updated", app=app)
    elif state == 'present' and app.get("Description", None) == description:
        result = dict(changed=False, output="App is up-to-date", app=app)
    elif state == 'absent' and app is None:
        result = dict(changed=False, output="App does not exist")
    elif state == 'absent' and app is not None:
        result = dict(changed=True, output="App will be deleted", app=app)
    elif state == 'absent' and app is not None and terminate_by_force is True:
        result = dict(changed=True, output="Running environments terminated before the App will be deleted", app=app)

    module.exit_json(**result)


def filter_empty(**kwargs):
    retval = {}
    for k, v in kwargs.items():
        if v:
            retval[k] = v
    return retval


def main():
    argument_spec = ec2_argument_spec()

    argument_spec.update(
        dict(
            app_name=dict(aliases=['name'], type='str', required=False),
            description=dict(),
            state=dict(choices=['present', 'absent', 'list'], default='present'),
            terminate_by_force=dict(type='bool', default=False, required=False)
        )
    )

    module = AnsibleAWSModule(argument_spec=argument_spec, supports_check_mode=True)

    if not HAS_BOTO3:
        module.fail_json(msg='boto3 required for this module')

    app_name = module.params['app_name']
    description = module.params['description']
    state = module.params['state']
    terminate_by_force = module.params['terminate_by_force']

    if app_name is None:
        module.fail_json(msg='Module parameter "app_name" is required')

    result = {}
    region, ec2_url, aws_connect_params = get_aws_connection_info(module, boto3=True)

    if region:
        ebs = boto3_conn(module, conn_type='client', resource='elasticbeanstalk',
                         region=region, endpoint=ec2_url, **aws_connect_params)
    else:
        module.fail_json(msg='region must be specified')

    app = describe_app(ebs, app_name)

    if module.check_mode:
        check_app(ebs, app, module)
        module.fail_json(msg='ASSERTION FAILURE: check_app() should not return control.')

    if state == 'present':
        if app is None:
            create_app = ebs.create_application(**filter_empty(ApplicationName=app_name,
                                                Description=description))
            app = describe_app(ebs, app_name)

            result = dict(changed=True, app=app)
        else:
            if app.get("Description", None) != description:
                if not description:
                    ebs.update_application(ApplicationName=app_name)
                else:
                    ebs.update_application(ApplicationName=app_name, Description=description)

                app = describe_app(ebs, app_name)

                result = dict(changed=True, app=app)
            else:
                result = dict(changed=False, app=app)

    else:
        if app is None:
            result = dict(changed=False, output='Application not found')
        else:
            if terminate_by_force:
                # Running environments will be terminated before deleting the application
                ebs.delete_application(ApplicationName=app_name, TerminateEnvByForce=terminate_by_force)
            else:
                try:
                    ebs.delete_application(ApplicationName=app_name)
                except Exception as e:
                    module.fail_json_aws(e, msg="Cannot terminate app with running environments")

            result = dict(changed=True, app=app)


    module.exit_json(**result)


if __name__ == '__main__':
    main()
