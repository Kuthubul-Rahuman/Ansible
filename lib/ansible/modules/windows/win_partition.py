#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Varun Chopra (@chopraaa)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: win_partition
version_added: '2.8'
short_description: Creates, changes and removes partitions on Windows Server
description:
- The M(win_partition) module can create, modify or delete a partition on a disk
options:
  state:
    description:
      - Used to specify the state of the partition. Use C(absent) to specify if a partition should be removed and C(present) to specify if the partition should be created or updated.
    type: string
    choices: [ absent, present]
    default: present
  drive_letter:
    description:
      - Used for accessing partitions if I(disk_number) and I(partition_number) are not provided.
      - Use C(auto) for automatically assigning a drive letter, or a letter A-Z for manually assigning a drive letter to a new partition.
        If not specified, no drive letter is assigned when creating a new partition.
    type: string
  disk_number:
    description:
      - Disk number is mandatory for creating new partitions.
      - A combination of I(disk_number) and I(partition_number) can be used to specify the partition instead of I(drive_letter) if required.
    type: int
  partition_number:
    description:
      - Used in conjunction with I(disk_number) to uniquely identify a partition.
    type: int
  partition_size:
    description:
      - Specify size of the partition in GB. Use -1 to specify maximum supported size.
      - Partition size is mandatory for creating a new partition but not for updating or deleting a partition.
    type: int
  read_only:
    description:
      - Make the partition read only, restricting changes from being made to the partition.
    type: bool
  active:
    description:
      - Specifies if the partition is active and can be used to start the system. This property is only valid when the disk's partition style is MBR.
    type: bool
  hidden:
    description:
      - Hides the target partition, making it undetectable by the mount manager.
    type: bool
  offline:
    description:
      - Sets the partition offline.
      - Adding a mount point (such as a drive letter) will cause the partition to go online again.
    required: no
    type: bool
  mbr_type:
    description:
      - Specify the partition's MBR type if the disk's partition style is MBR.
      - This only applies to new partitions.
    type: string
    choices: [ FAT12, FAT16, Extended, Huge, IFS, FAT32 ]
  gpt_type:
    description:
      - Specify the partition's GPT type if the disk's partition style is GPT.
      - This only applies to new partitions.
    type: string
    choices: [ SystemPartition, MicrosoftReserved, BasicData, MicrosoftRecovery ]

notes:
- This module cannot be used for removing the drive letter associated with a partition.
- Idempotence works only if you're specifying a drive letter or other unique attributes such as a combination of disk number and partition number.
- For more information, see U(https://msdn.microsoft.com/en-us/library/windows/desktop/hh830524(v=vs.85).aspx).
author:
- Varun Chopra (@chopraaa)
'''

EXAMPLES = r'''
# Create a partitition with drive letter D and size 5 GB
- win_partition:
    drive_letter: D
    partition_size: 5
    disk_number: 1

# Resize previously created partition to it's maximum size and change it's drive letter to E
- win_partition:
    drive_letter: E
    partition_size: -1
    partition_number: 1
    disk_number: 1

# Delete partition
- win_partition:
    disk_number: 1
    partition_number: 1
    state: absent
'''

RETURN = r'''
#
'''
