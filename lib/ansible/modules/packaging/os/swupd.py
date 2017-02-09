#!/usr/bin/python

# (c) 2017, Alberto Murillo <alberto.murillo.silva@intel.com>
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

ANSIBLE_METADATA = {
    'status': ['preview'],
    'supported_by': 'community',
    'version': '1.0'
}

DOCUMENTATION = '''
---
module: swupd
short_description: Manages bundles with M(swupd).
description:
  - Manages bundles with the M(swupd) update manager, which is used by the
    Clear Linux Project for Intel Architecture.
version_added: "2.3"
author: Alberto Murillo (@albertomurillo)
options:
  contenturl:
    description:
      - URL for content file download.
    required: false
    default: null
  format:
    description:
      - The format suffix for version file downloads.
    required: false
    default: null
  manifest:
    description:
      - Manifest to verify against to.
    required: false
    default: null
    aliases: [release, version]
  name:
    description:
      - Name of the (I)bundle to install or remove.
    required: false
    default: null
    aliases: [bundle]
  state:
    description:
      - Indicates the desired (I)bundle state. C(present) ensures the bundle
        is installed while C(absent) ensures the (I)bundle is not installed.
    required: false
    default: present
    choices: [present, absent]
  update:
    description:
      - Updates the OS to the latest version.
    required: false
    default: no
  url:
    description:
      - Overrides both I(contenturl) and I(versionurl).
    required: false
    default: null
  verify:
    description:
      - Verify content for OS version.
    required: false
    default: null
  versionurl:
    description:
      - URL for version string download.
    required: false
    default: null
'''

EXAMPLES = '''
- name Update the OS to the latest version
  swupd:
    update: yes

- name: Installs the "foo" bundle
  swupd:
    name: foo
    state: present

- name: Removes the "foo" bundle
  swupd:
    name: foo
    state: absent

- name: Check integrity of filesystem
  swupd:
    verify: yes

- name: Downgrade OS to release 12920
  swupd:
    verify: yes
    manifest: 12920
'''

RETURN = '''
stdout:
  description: stdout of swupd
  returned: always
  type: string
stderr:
  description: stderr of swupd
  returned: always
  type: string
'''

import os
from ansible.module_utils.basic import AnsibleModule


class Swupd(object):
    FILES_NOT_MATCH = "files did not match"
    FILES_REPLACED = "missing files were replaced"
    FILES_FIXED = "files were fixed"
    FILES_DELETED = "files were deleted"

    def __init__(self, module):
        # Fail if swupd is not found
        self.module = module
        self.swupd_cmd = module.get_bin_path("swupd", False)
        if not self.swupd_cmd:
            module.fail_json(msg="Could not find swupd.")

        # Initialize parameters
        for key in module.params.keys():
            setattr(self, key, module.params[key])

        # Initialize return values
        self.changed = False
        self.failed = False
        self.msg = None
        self.rc = None
        self.stderr = ""
        self.stdout = ""

    def _run_cmd(self, cmd):
        self.rc, self.stdout, self.stderr = self.module.run_command(cmd, check_rc=False)

    def _get_cmd(self, command):
        cmd = "%s %s" % (self.swupd_cmd, command)

        if self.format:
            cmd += " --format=%s" % self.format
        if self.manifest:
            cmd += " --manifest=%s" % self.manifest
        if self.url:
            cmd += " --url=%s" % self.url
        else:
            if self.contenturl and command != "check-update":
                cmd += " --contenturl=%s" % self.contenturl
            if self.versionurl:
                cmd += " --versionurl=%s" % self.versionurl

        return cmd

    def _is_bundle_installed(self, bundle):
        try:
            os.stat("/usr/share/clear/bundles/%s" % bundle)
        except OSError:
            return False

        return True

    def _needs_update(self):
        cmd = self._get_cmd("check-update")
        self._run_cmd(cmd)

        if self.rc == 0:
            return True

        if self.rc == 1:
            return False

        self.failed = True
        self.msg = "Failed to check for updates"

    def _needs_verify(self):
        cmd = self._get_cmd("verify")
        self._run_cmd(cmd)

        if self.rc != 0:
            self.failed = True
            self.msg = "Failed to check for filesystem inconsistencies."

        if self.FILES_NOT_MATCH in self.stdout:
            return True

        return False

    def install_bundle(self, bundle):
        """Installs a bundle with `swupd bundle-add bundle`"""
        if self.module.check_mode:
            self.module.exit_json(changed=not self._is_bundle_installed(bundle))

        if self._is_bundle_installed(bundle):
            self.msg = "Bundle %s is already installed" % bundle
            return

        cmd = self._get_cmd("bundle-add %s" % bundle)
        self._run_cmd(cmd)

        if self.rc == 0:
            self.changed = True
            self.msg = "Bundle %s installed" % bundle
            return

        if self.rc == 18:
            self.msg = "Bundle name %s is invalid" % bundle
            return

        self.failed = True
        self.msg = "Failed to install bundle %s" % bundle

    def remove_bundle(self, bundle):
        """Removes a bundle with `swupd bundle-remove bundle`"""
        if self.module.check_mode:
            self.module.exit_json(changed=self._is_bundle_installed(bundle))

        if not self._is_bundle_installed(bundle):
            self.msg = "Bundle %s not installed"
            return

        cmd = self._get_cmd("bundle-remove %s" % bundle)
        self._run_cmd(cmd)

        if self.rc == 0:
            self.changed = True
            self.msg = "Bundle %s removed" % bundle
            return

        self.failed = True
        self.msg = "Failed to remove bundle %s" % bundle

    def update_os(self):
        """Updates the os with `swupd update`"""
        if self.module.check_mode:
            self.module.exit_json(changed=self._needs_update())

        if not self._needs_update():
            self.msg = "There are no updates available"
            return

        cmd = self._get_cmd("update")
        self._run_cmd(cmd)

        if self.rc == 0:
            self.changed = True
            self.msg = "Update successful"
            return

        self.failed = True
        self.msg = "Failed to check for updates"

    def verify_os(self):
        """Verifies filesystem agains specified or current version"""
        if self.module.check_mode:
            self.module.exit_json(changed=self._needs_verify())

        if not self._needs_verify():
            self.msg = "No files where changed"
            return

        cmd = self._get_cmd("verify --fix")
        self._run_cmd(cmd)

        if self.rc == 0 and (self.FILES_REPLACED in self.stdout or self.FILES_FIXED in self.stdout or self.FILES_DELETED in self.stdout):
            self.changed = True
            self.msg = "Fix successful"
            return

        self.failed = True
        self.msg = "Failed to verify the OS"


def main():
    """The main function."""
    module = AnsibleModule(
        argument_spec=dict(
            contenturl=dict(type="str"),
            format=dict(type="str"),
            manifest=dict(aliases=["release", "version"], type="int"),
            name=dict(aliases=["bundle"], type="str"),
            state=dict(default="present", choices=["present", "absent"], type="str"),
            update=dict(default=False, type="bool"),
            url=dict(type="str"),
            verify=dict(default=False, type="bool"),
            versionurl=dict(type="str"),
        ),
        required_one_of=[["name", "update", "verify"]],
        mutually_exclusive=[["name", "update", "verify"]],
        supports_check_mode=True
    )

    swupd = Swupd(module)

    name = module.params["name"]
    state = module.params["state"]
    update = module.params["update"]
    verify = module.params["verify"]

    if update:
        swupd.update_os()
    elif verify:
        swupd.verify_os()
    elif state == "present":
        swupd.install_bundle(name)
    elif state == "absent":
        swupd.remove_bundle(name)
    else:
        swupd.failed = True

    if swupd.failed:
        module.fail_json(msg=swupd.msg, stdout=swupd.stdout, stderr=swupd.stderr)
    else:
        module.exit_json(changed=swupd.changed, msg=swupd.msg, stdout=swupd.stdout, stderr=swupd.stderr)


if __name__ == '__main__':
    main()
