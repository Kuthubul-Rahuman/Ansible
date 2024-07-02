# -*- coding: utf-8 -*-
# Copyright (c) 2024 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations


DOCUMENTATION = """
---
module: extended_mount_facts
version_added: 2.18
short_description: Retrieve information about mounts that match both a requested file system in O(fstypes) and device in O(devices).
description:
  - Retrieve information about mounts that match both a requested file system in O(fstypes) and device in O(devices).
options:
  devices:
    description: A list of fnmatch patterns to filter mounts by the special device or remote file system.
    required: true
    type: list
    elements: str
  fstypes:
    description: A list of fnmatch patterns to filter mounts by the type of the file system.
    required: true
    type: list
    elements: str
  timeout:
    description:
      - This is the maximum number of seconds to query for each mount. This can also be set to V(null) to wait indefinitely.
      - This timeout also applies to the C(mount) command, which is executed if mounts cannot be listed using a file.
    required: true
    type: raw
  on_timeout:
    description:
      - The action to take when a timeout occurs.
      - When this is set to V(warn) or V(ignore), mounts that time out will be excluded from the results.
    choices:
      - error
      - warn
      - ignore
    default: error
    type: str
extends_documentation_fragment:
  - action_common_attributes
attributes:
  check_mode:
    support: full
  diff_mode:
    support: none
  platform:
    platforms: posix
author:
  - Ansible Core Team
"""

EXAMPLES = """
- name: Get NFS and FUSE subtype mounts
  extended_mount_facts:
    devices:
      - "[!/]*"
    fstypes:
      - "nfs"
      - "nfs4"
      - "fuse.*"
"""

RETURN = """
ansible_facts:
    description: An ansible_facts dictionary containing C(extended_mounts).
    returned: always
    type: dict
    sample:
      extended_mounts:
        /mnt/mount:
          info:
            block_available: 3242510
            block_size: 4096
            block_total: 3789825
            block_used: 547315
            device: hostname:/srv/sshfs
            fstype: fuse.sshfs
            inode_available: 1875503
            inode_total: 1966080
            mount: /mnt/mount
            options: "rw,nosuid,nodev,relatime,user_id=0,group_id=0"
            size_available: 13281320960
            size_total: 15523123200
          uuid: N/A
"""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.validation import check_type_int
from ansible.module_utils.facts import timeout
from ansible.module_utils.facts.hardware.linux import LinuxHardware
from ansible.module_utils.facts.utils import get_mount_size, get_file_content

from fnmatch import fnmatch
from typing import Callable, Optional
from sys import platform

import re
import subprocess

# Regular expressions to match individual lines from mount

# FreeBSD: hostname:/srv/sshfs on /mnt/sshfs (fusefs.sshfs)
# MacOSX: //user@hostname/public on /mnt/cifs (smbfs, nodev, nosuid, mounted by user)
BSD_MOUNT_RE = re.compile(r"^(?P<device>\S+) on (?P<mount>\S+) \((?P<fstype>.+)\)$")

# AIX: hostname /mount /mounted_over nfs Dec 17 08:06 ro, log  =/dev/hd8
AIX_MOUNT_RE = re.compile(r"^(?P<node>\S+)\s+(?P<mount>\S+)\s+(?P<mounted_over>\S+)\s+(?P<fstype>\S+)\s+(?P<time>\S+\s+\d+\s+\d+:\d+)\s+(?P<options>.*)$")

# TODO...?

# No mount parsing preferably
# Fedora, Debian, Ubuntu, Arch use /etc/mtab or /proc/mounts
# Solaris uses /etc/mnttab


def get_mount_info(
    module: AnsibleModule,
    mount: str,
    device: str,
    uuids: dict[str, str],
    udevadm_uuid: Callable[[str], str]
) -> tuple[Optional[dict], Optional[str]]:
    """
    Attempts to get the mount size and UUID within an optional timeout.
    """
    def _get_mount_info(mount, device, uuids, udevadm_uuid):
        mount_size = get_mount_size(mount)
        uuid = uuids.get(device, udevadm_uuid(device))
        return mount_size, uuid

    if module.params["timeout"] is None:
        return _get_mount_info(mount, device, uuids, udevadm_uuid)

    seconds = module.params["timeout"]
    on_error = module.params["on_timeout"]
    try:
        return timeout.timeout(seconds)(_get_mount_info)(mount, device, uuids, udevadm_uuid)
    except timeout.TimeoutError:
        if on_error == "error":
            module.fail_json(msg=f"{device} on {mount} timed out")
        elif on_error == "warn":
            module.warn(f"{device} on {mount} timed out")

    return None, None


def parse_mount(line: str) -> Optional[dict[str, str]]:
    """
    Parse a line of mount information and return a dictionary with mount details.
    """
    match = None
    if platform.startswith(("freebsd", "netbsd", "openbsd", "dragonfly", "darwin", "linux")):
        match = BSD_MOUNT_RE.match(line)
    if platform.startswith(("aix", "linux")):
        match = match or AIX_MOUNT_RE.match(line)
    if match is None:
        return None

    mount_info = {"mount": match.group("mount")}
    if len(match.groups()) == 3:
        if "," in (fstype := match.group("fstype")):
            fstype, options = fstype.split(", ", 1)
        else:
            options = ""
        mount_info.update({
            "fstype": fstype,
            "options": options,
            "device": match.group("device")
        })
    else:
        device = match.group("node") + ":" + match.group("mounted_over")
        mount_info.update({
            "fstype": match.group("fstype"),
            "options": match.group("options"),
            "time": match.group("time"),
            "device": device
        })
    return mount_info


def parse_mount_output(module: AnsibleModule) -> list[dict[str, str]]:
    """
    Parse output from the mount command.
    """
    mount_path = module.get_bin_path("mount")
    mount_output = ""
    if mount_path:
        if platform.startswith("dragonfly"):
            args = [mount_path, "-p"]
        else:
            args = [mount_path]
        try:
            mount_output = subprocess.run(*args, capture_output=True, text=True, check=True, timeout=module.params["timeout"])
        except subprocess.TimeoutExpired as e:
            if module.params["on_timeout"] == "error":
                module.fail_json(msg="Running the mount command timed out, unable to retrieve mount facts.")
            elif module.params["on_timeout"] == "warn":
                module.warn("Running the mount command timed out, unable to retrieve mount facts.")
            return []
        except subprocess.CalledProcessError as e:
            module.fail_json(msg=f"An error occurred while running the mount command: {str(e)}")

    mounts = []
    for line in mount_output.splitlines():
        if (mount_info := parse_mount(line)):
            mounts.append(mount_info)
    return mounts


def list_current_mounts(module: AnsibleModule) -> list[dict[str, str]]:
    """
    Checks the following sources for current mounts:
      * /etc/mtab
      * /proc/mounts
      * /etc/mnttab (Solaris)
    If no information if found in the files, attempts to parse the output from mount.
    """
    mounts = []

    # device mount fstype options dump passno
    mtab_entries = get_file_content("/etc/mtab", "") or get_file_content("/proc/mounts", "")

    # device mount fstype options time
    mnttab = get_file_content("/etc/mnttab", "")

    for mtab_entry in (mtab_entries or mnttab).splitlines():
        fields = mtab_entry.split(" ")
        if len(fields) < 4:
            continue

        mount_info = {
            "mount": fields[1],
            "device": fields[0],
            "fstype": fields[2],
            "options": fields[3],
        }

        if mtab_entries:
            if len(fields) >= 6:
                mount_info.update({"dump": fields[4], "passno": fields[5]})
        elif len(fields) >= 5:
            mount_info.update({"time": fields[4]})

        mounts.append(mount_info)

    if not mounts:
        mounts = parse_mount_output(module)
    return mounts


def main():
    module = AnsibleModule(
        argument_spec=dict(
            devices=dict(type="list", elements="str", required=True),
            fstypes=dict(type="list", elements="str", required=True),
            timeout=dict(type="raw", required=True),
            on_timeout=dict(choices=["error", "warn", "ignore"], default="error"),
        ),
        supports_check_mode=True,
    )
    if (timeout := module.params["timeout"]) is not None:
        try:
            module.params["timeout"] = check_type_int(timeout)
        except TypeError as te:
            module.fail_json(msg=f"argument 'timeout' is of type {type(timeout)} and we were unable to convert to int: {te}")
        if module.params["timeout"] <= 0:
            module.fail_json(msg="argument 'timeout' must be a positive integer or null")

    results = {}

    hardware = LinuxHardware(module)
    uuids = hardware._lsblk_uuid()
    udevadm_uuid = hardware._udevadm_uuid

    for fields in list_current_mounts(module):
        mount = fields["mount"]
        device = fields["device"]
        fstype = fields["fstype"]

        if not any(fnmatch(device, pattern) for pattern in module.params["devices"]):
            continue
        if not any(fnmatch(fstype, pattern) for pattern in module.params["fstypes"]):
            continue

        mount_size, uuid = get_mount_info(module, mount, device, uuids, udevadm_uuid)
        if mount_size:
            fields.update(mount_size)

        results[mount] = {"info": fields, "uuid": uuid or "N/A"}

    module.exit_json(ansible_facts={"extended_mounts": results})


if __name__ == "__main__":
    main()
