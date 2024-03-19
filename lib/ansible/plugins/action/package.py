# (c) 2015, Ansible Inc,
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
from __future__ import annotations

from ansible import constants as C
from ansible.errors import AnsibleAction, AnsibleActionFail
from ansible.executor.module_common import get_action_args_with_defaults
from ansible.module_utils.facts.system.pkg_mgr import PKG_MGRS
from ansible.plugins.action import ActionBase
from ansible.utils.display import Display
from ansible.utils.vars import combine_vars

display = Display()


class ActionModule(ActionBase):

    TRANSFERS_FILES = False

    BUILTIN_PKG_MGR_MODULES = {manager['name'] for manager in PKG_MGRS}

    def run(self, tmp=None, task_vars=None):
        ''' handler for package operations '''

        self._supports_check_mode = True
        self._supports_async = True

        result = super(ActionModule, self).run(tmp, task_vars)
        del tmp  # tmp no longer has any effect

        module = self._task.args.get('use', 'auto')

        if module == 'auto':
            try:
                if self._task.delegate_to:  # if we delegate, we should use delegated host's facts
                    module = C.config.get_config_value('PACKAGE_MANAGER_OVERRIDE', variables=combine_vars(self._task.vars, task_vars.get('delegated_vars', {})))
                    if module is None:
                        dh = '%s' % self._task.delegate_to
                        module = self._templar.template(f"{{hostvars['{dh}']['ansible_local']['overrides']]['pkg_mgr']|default(hostvars['{dh}']['ansible_facts']['pkg_mgr'])}}")
                else:
                    module = C.config.get_config_value('PACKAGE_MANAGER_OVERRIDE', variables=task_vars)
                    if module is None:
                        module = self._templar.template("{{ansible_local['overrides']['pkg_mgr']|default(ansible_facts['pkg_mgr'])}}")
            except Exception:
                pass  # could not get it from template!

        try:
            if module == 'auto':
                # TODO: change to action 'gather_facts'
                facts = self._execute_module(
                    module_name='ansible.legacy.setup',
                    module_args=dict(filter='ansible_pkg_mgr', gather_subset='!all'),
                    task_vars=task_vars)
                display.debug("Facts %s" % facts)
                module = facts.get('ansible_facts', {}).get('ansible_pkg_mgr', 'auto')

            if module != 'auto':
                if not self._shared_loader_obj.module_loader.has_plugin(module):
                    raise AnsibleActionFail('Could not find a module for %s.' % module)
                else:
                    # run the 'package' module
                    new_module_args = self._task.args.copy()
                    if 'use' in new_module_args:
                        del new_module_args['use']

                    # get defaults for specific module
                    context = self._shared_loader_obj.module_loader.find_plugin_with_context(module, collection_list=self._task.collections)
                    new_module_args = get_action_args_with_defaults(
                        context.resolved_fqcn, new_module_args, self._task.module_defaults, self._templar,
                        action_groups=self._task._parent._play._action_groups
                    )

                    if module in self.BUILTIN_PKG_MGR_MODULES:
                        # prefix with ansible.legacy to eliminate external collisions while still allowing library/ override
                        module = 'ansible.legacy.' + module

                    display.vvvv("Running %s" % module)
                    result.update(self._execute_module(module_name=module, module_args=new_module_args, task_vars=task_vars, wrap_async=self._task.async_val))
            else:
                raise AnsibleActionFail('Could not detect which package manager to use. Try gathering facts or setting the "use" option.')

        except AnsibleAction as e:
            result.update(e.result)
        finally:
            if not self._task.async_val:
                # remove a temporary path we created
                self._remove_tmp_path(self._connection._shell.tmpdir)

        return result
