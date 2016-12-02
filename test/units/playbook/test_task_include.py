# (c) 2016, Adrian Likins <alikins@redhat.com>
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

# Make coding more python3-ish
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible.compat.tests import unittest
from units.mock.loader import DictDataLoader

from ansible.playbook.task import Task

from ansible.playbook.task_include import TaskInclude


class TestTaskInclude(unittest.TestCase):

    def test(self):
        parent_task_ds = {'debug': 'msg=foo'}
        parent_task = Task()
        parent_task.load(parent_task_ds)

        task_ds = {'include': 'include_test.yml'}
        task_include = TaskInclude()
        loaded_task = task_include.load(task_ds, task_include=parent_task)
        self.assertIsInstance(loaded_task, TaskInclude)

    def test_child(self):
        parent_task_ds = {'debug': 'msg=foo'}
        parent_task = Task()
        parent_task.load(parent_task_ds)

        task_ds = {'include': 'include_test.yml'}
        task_include = TaskInclude()
        loaded_task = task_include.load(task_ds, task_include=parent_task)
        self.assertIsInstance(loaded_task, TaskInclude)

        child_task_ds = {'include': 'other_include_test.yml'}
        child_task_include = TaskInclude()
        loaded_child_task = child_task_include.load(child_task_ds, task_include=loaded_task)
        self.assertIsInstance(loaded_child_task, TaskInclude)

    def test_copy(self):
        task_ds = {'include': 'include_test.yml'}
        task_include = TaskInclude()
        fake_loader = DictDataLoader({})
        loaded_task = task_include.load(task_ds, loader=fake_loader)

        task_include_copy = loaded_task.copy()
        self.assertEqual(loaded_task, task_include_copy)

    def test_copy_static(self):
        task_ds = {'include': 'include_test.yml'}
        task_include = TaskInclude()
        fake_loader = DictDataLoader({})
        task_include.static = True
        loaded_task = task_include.load(task_ds, loader=fake_loader)

        task_include_copy = loaded_task.copy()
        self.assertEqual(loaded_task, task_include_copy)

    def test_copy_exclude_parent(self):
        task_ds = {'include': 'include_test.yml'}
        task_include = TaskInclude()
        loaded_task = task_include.load(task_ds)

        task_include_copy = loaded_task.copy(exclude_parent=True)
        self.assertEqual(loaded_task, task_include_copy)

    def test_copy_exclude_parent_exclude_tasks(self):
        task_ds = {'include': 'include_test.yml'}
        task_include = TaskInclude()
        fake_loader = DictDataLoader({})
        loaded_task = task_include.load(task_ds, loader=fake_loader)

        task_include_copy = loaded_task.copy(exclude_parent=True, exclude_tasks=True)
        self.assertEqual(loaded_task, task_include_copy)

    def test_copy_parent(self):
        task_ds = {'include': 'include_test.yml',
                   'blip': 'foo',
                   'vars': {'tags': ['tag1', 'tag2'],
                            'when': 'true'}
                   }
        task_include = TaskInclude()
        loaded_task = task_include.load(task_ds)

        child_task_ds = {'include': 'other_include_test.yml',
                         'tags': []}
        child_task_include = TaskInclude()
        loaded_child_task = child_task_include.load(child_task_ds, task_include=loaded_task)

        task_include_copy = loaded_child_task.copy()
        self.assertEqual(loaded_child_task, task_include_copy)


class TestTaskIncludeGetVars(unittest.TestCase):
    def test_get_vars(self):
        task_ds = {'include': 'include_test.yml',
                   'blip': 'foo',
                   'vars': {'tags': ['tag1', 'tag2'],
                            'when': 'true'}
                   }
        task_include = TaskInclude()
        loaded_task = task_include.load(task_ds)

        child_task_ds = {'include': 'other_include_test.yml',
                         'tags': []}
        child_task_include = TaskInclude()
        loaded_child_task = child_task_include.load(child_task_ds, task_include=loaded_task)

        task_vars = loaded_child_task.get_vars()
        self.assertIn('blip', task_vars)
        self.assertNotIn('tags', task_vars)
        self.assertNotIn('when', task_vars)
