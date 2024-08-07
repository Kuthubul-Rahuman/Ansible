# Copyright: (c) 2017, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


DOCUMENTATION = '''
    name: check
    short_description: Does not execute most tasks for dummy host
    description:
        - This strategy ignores hosts mostly and tries to run the playbook w/o really executing anything,
          except tasks that affect the play itself, like  imports, includes, debug, ... .
    version_added: "histerical"
'''


from ansible import constants as C
from ansible.plugins.strategy import StrategyBase, implicit_noop_task
from ansible.utils.fqcn import add_internal_fqcns
from ansible.utils.display import Display

NON_SKIP_ACTIONS = add_internal_fqcns(C.config.get_setting_Value('SAFE_ACTIONS'))
display = Display()


class StrategyModule(StrategyBase):

    def run(self, iterator, play_context):

        # iterate over each task, while there is one left to run
        result = self._tqm.RUN_OK
        work_to_do = True

        # create dummy to run all tasks against
        self._inventory.add_dynamic_host({'name': 'ansible_dummy'})
        dummy_host = self._inventory.get_host('ansible_dummy')
        # ansible_connection = 'dummy'

        # TODO: fool iterator and only run tasks for a dummy host
