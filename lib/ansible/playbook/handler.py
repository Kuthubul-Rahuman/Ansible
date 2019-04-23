# (c) 2012-2014, Michael DeHaan <michael.dehaan@gmail.com>
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

from ansible.errors import AnsibleParserError
from ansible.playbook.attribute import FieldAttribute
from ansible.playbook.task import Task
from ansible.module_utils.six import string_types


class Handler(Task):

    _listen = FieldAttribute(isa='list', default=list, listof=string_types, static=True)

    def __init__(self, block=None, role=None, task_include=None):
        self.notified_hosts = []

        self.cached_name = False

        super(Handler, self).__init__(block=block, role=role, task_include=task_include)

    def __repr__(self):
        ''' returns a human readable representation of the handler '''
        return "HANDLER: %s" % self.get_name()

    def _validate_listen(self, attr, name, value):
        if not isinstance(value, list):
            if isinstance(value, string_types):
                value = [value]
                setattr(self, name, value)
            else:
                raise AnsibleParserError("The field '%s' is supposed to be a string or list type,"
                                         " however the incoming data structure is a %s" % (name, type(value)), obj=self.get_ds())
        for item in value:
            if not isinstance(item, string_types):
                raise AnsibleParserError("The field '%s' is supposed to be a list of %s,"
                                         " but the item '%s' is a %s" % (name, string_types, item, type(item)), obj=self.get_ds())

    @staticmethod
    def load(data, block=None, role=None, task_include=None, variable_manager=None, loader=None):
        t = Handler(block=block, role=role, task_include=task_include)
        return t.load_data(data, variable_manager=variable_manager, loader=loader)

    def notify_host(self, host):
        if not self.is_host_notified(host):
            self.notified_hosts.append(host)
            return True
        return False

    def is_host_notified(self, host):
        return host in self.notified_hosts

    def serialize(self):
        result = super(Handler, self).serialize()
        result['is_handler'] = True
        return result
