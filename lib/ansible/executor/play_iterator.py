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

from __future__ import annotations

import fnmatch

from enum import IntEnum, IntFlag

from ansible import constants as C
from ansible.errors import AnsibleAssertionError
from ansible.module_utils.parsing.convert_bool import boolean
from ansible.playbook.block import Block
from ansible.playbook.task import Task
from ansible.utils.display import Display


display = Display()


__all__ = ['PlayIterator', 'IteratingStates', 'FailedStates']


class IteratingStates(IntEnum):
    SETUP = 0
    TASKS = 1
    RESCUE = 2
    ALWAYS = 3
    HANDLERS = 4
    COMPLETE = 5


class FailedStates(IntFlag):
    NONE = 0
    SETUP = 1
    TASKS = 2
    RESCUE = 4
    ALWAYS = 8
    HANDLERS = 16  # NOTE not in use anymore


class HostState:
    def __init__(self, blocks):
        self._blocks = blocks[:]
        self.handlers = []

        self.handler_notifications = []

        self.cur_block = 0
        self.cur_regular_task = 0
        self.cur_rescue_task = 0
        self.cur_always_task = 0
        self.cur_handlers_task = 0
        self.run_state = IteratingStates.SETUP
        self.fail_state = FailedStates.NONE
        self.pre_flushing_run_state = None
        self.update_handlers = True
        self.pending_setup = False
        self.child_state = None
        self.did_start_at_task = False

    def __repr__(self):
        return "HostState(%r)" % self._blocks

    def __str__(self):
        return ("HOST STATE: block=%d, task=%d, rescue=%d, always=%d, handlers=%d, run_state=%s, fail_state=%s, "
                "pre_flushing_run_state=%s, update_handlers=%s, pending_setup=%s, "
                "child state? (%s), did start at task? %s" % (
                    self.cur_block,
                    self.cur_regular_task,
                    self.cur_rescue_task,
                    self.cur_always_task,
                    self.cur_handlers_task,
                    self.run_state,
                    self.fail_state,
                    self.pre_flushing_run_state,
                    self.update_handlers,
                    self.pending_setup,
                    self.child_state,
                    self.did_start_at_task,
                ))

    def __eq__(self, other):
        if not isinstance(other, HostState):
            return False

        for attr in ('_blocks',
                     'cur_block', 'cur_regular_task', 'cur_rescue_task', 'cur_always_task', 'cur_handlers_task',
                     'run_state', 'fail_state', 'pre_flushing_run_state', 'update_handlers', 'pending_setup',
                     'child_state'):
            if getattr(self, attr) != getattr(other, attr):
                return False

        return True

    def get_current_block(self):
        return self._blocks[self.cur_block]

    def copy(self):
        new_state = HostState(self._blocks)
        new_state.handlers = self.handlers[:]
        new_state.handler_notifications = self.handler_notifications[:]
        new_state.cur_block = self.cur_block
        new_state.cur_regular_task = self.cur_regular_task
        new_state.cur_rescue_task = self.cur_rescue_task
        new_state.cur_always_task = self.cur_always_task
        new_state.cur_handlers_task = self.cur_handlers_task
        new_state.run_state = self.run_state
        new_state.fail_state = self.fail_state
        new_state.pre_flushing_run_state = self.pre_flushing_run_state
        new_state.update_handlers = self.update_handlers
        new_state.pending_setup = self.pending_setup
        new_state.did_start_at_task = self.did_start_at_task
        if self.child_state is not None:
            new_state.child_state = self.child_state.copy()
        return new_state


class PlayIterator:

    def __init__(self, inventory, play, play_context, variable_manager, all_vars, start_at_done=False):
        self._play = play
        self._blocks = []
        self._variable_manager = variable_manager

        setup_block = Block(play=self._play)
        # Gathering facts with run_once would copy the facts from one host to
        # the others.
        setup_block.run_once = False
        setup_task = Task(block=setup_block)
        setup_task.action = 'gather_facts'
        # TODO: hardcoded resolution here, but should use actual resolution code in the end,
        #       in case of 'legacy' mismatch
        setup_task.resolved_action = 'ansible.builtin.gather_facts'
        setup_task.name = 'Gathering Facts'
        setup_task.args = {}

        # Unless play is specifically tagged, gathering should 'always' run
        if not self._play.tags:
            setup_task.tags = ['always']

        # Default options to gather
        for option in ('gather_subset', 'gather_timeout', 'fact_path'):
            value = getattr(self._play, option, None)
            if value is not None:
                setup_task.args[option] = value

        setup_task.set_loader(self._play._loader)
        # short circuit fact gathering if the entire playbook is conditional
        if self._play._included_conditional is not None:
            setup_task.when = self._play._included_conditional[:]
        setup_block.block = [setup_task]

        setup_block = setup_block.filter_tagged_tasks(all_vars)
        self._blocks.append(setup_block)

        # keep flatten (no blocks) list of all tasks from the play
        # used for the lockstep mechanism in the linear strategy
        self.all_tasks = setup_block.get_tasks()

        for block in self._play.compile():
            new_block = block.filter_tagged_tasks(all_vars)
            if new_block.has_tasks():
                self._blocks.append(new_block)
                self.all_tasks.extend(new_block.get_tasks())

        # keep list of all handlers, it is copied into each HostState
        # at the beginning of IteratingStates.HANDLERS
        # the copy happens at each flush in order to restore the original
        # list and remove any included handlers that might not be notified
        # at the particular flush
        self.handlers = [h for b in self._play.handlers for h in b.block]

        self._host_states = {}
        start_at_matched = False
        batch = inventory.get_hosts(self._play.hosts, order=self._play.order)
        self.batch_size = len(batch)
        for host in batch:
            self.set_state_for_host(host.name, HostState(blocks=self._blocks))
            # if we're looking to start at a specific task, iterate through
            # the tasks for this host until we find the specified task
            if play_context.start_at_task is not None and not start_at_done:
                while True:
                    (s, task) = self.get_next_task_for_host(host, peek=True)
                    if s.run_state == IteratingStates.COMPLETE:
                        break
                    if task.name == play_context.start_at_task or (task.name and fnmatch.fnmatch(task.name, play_context.start_at_task)) or \
                       task.get_name() == play_context.start_at_task or fnmatch.fnmatch(task.get_name(), play_context.start_at_task):
                        start_at_matched = True
                        break
                    self.set_state_for_host(host.name, s)

                # finally, reset the host's state to IteratingStates.SETUP
                if start_at_matched:
                    self._host_states[host.name].did_start_at_task = True
                    self._host_states[host.name].run_state = IteratingStates.SETUP

        if start_at_matched:
            # we have our match, so clear the start_at_task field on the
            # play context to flag that we've started at a task (and future
            # plays won't try to advance)
            play_context.start_at_task = None

        self.end_play = False
        self.cur_task = 0

    def get_host_state(self, host):
        # Since we're using the PlayIterator to carry forward failed hosts,
        # in the event that a previous host was not in the current inventory
        # we create a stub state for it now
        if host.name not in self._host_states:
            self.set_state_for_host(host.name, HostState(blocks=[]))

        return self._host_states[host.name].copy()

    def get_next_task_for_host(self, host, peek=False):

        display.debug("getting the next task for host %s" % host.name)
        s = self.get_host_state(host)

        task = None
        if s.run_state == IteratingStates.COMPLETE:
            display.debug("host %s is done iterating, returning" % host.name)
            return s, None

        s, task = self._get_next_task_from_state(s, host=host)

        if not peek:
            self.set_state_for_host(host.name, s)

        display.debug("done getting next task for host %s" % host.name)
        display.debug(" ^ task is: %s" % task)
        display.debug(" ^ state is: %s" % s)
        return s, task

    def _get_next_task_from_state(self, state, host):

        task = None

        # try and find the next task, given the current state.
        while True:
            # try to get the current block from the list of blocks, and
            # if we run past the end of the list we know we're done with
            # this block
            try:
                block = state._blocks[state.cur_block]
            except IndexError:
                state.run_state = IteratingStates.COMPLETE
                return state, None

            match state.run_state:
                case IteratingStates.SETUP:
                    # First, we check to see if we were pending setup. If not, this is
                    # the first trip through IteratingStates.SETUP, so we set the pending_setup
                    # flag and try to determine if we do in fact want to gather facts for
                    # the specified host.
                    if not state.pending_setup:
                        state.pending_setup = True

                        # Gather facts if the default is 'smart' and we have not yet
                        # done it for this host; or if 'explicit' and the play sets
                        # gather_facts to True; or if 'implicit' and the play does
                        # NOT explicitly set gather_facts to False.

                        gathering = C.DEFAULT_GATHERING
                        implied = self._play.gather_facts is None or boolean(self._play.gather_facts, strict=False)

                        if (gathering == 'implicit' and implied) or \
                           (gathering == 'explicit' and boolean(self._play.gather_facts, strict=False)) or \
                           (gathering == 'smart' and implied and not (self._variable_manager._fact_cache.get(host.name, {}).get('_ansible_facts_gathered', False))):
                            # The setup block is always self._blocks[0], as we inject it
                            # during the play compilation in __init__ above.
                            setup_block = self._blocks[0]
                            if setup_block.has_tasks() and len(setup_block.block) > 0:
                                task = setup_block.block[0]
                    else:
                        # This is the second trip through IteratingStates.SETUP, so we clear
                        # the flag and move onto the next block in the list while setting
                        # the run state to IteratingStates.TASKS
                        state.pending_setup = False
                        state.run_state = IteratingStates.TASKS
                        if not state.did_start_at_task:
                            state.cur_block += 1

                case IteratingStates.TASKS:
                    # clear the pending setup flag, since we're past that and it didn't fail
                    if state.pending_setup:
                        state.pending_setup = False

                    # First, we check for a child task state that is not failed, and if we
                    # have one recurse into it for the next task. If we're done with the child
                    # state, we clear it and drop back to getting the next task from the list.
                    if state.child_state:
                        state.child_state, task = self._get_next_task_from_state(state.child_state, host=host)
                        if self._check_failed_state(state.child_state):
                            # failed child state, so clear it and move into the rescue portion
                            state.child_state = None
                            self._set_failed_state(state)
                        elif state.child_state.run_state == IteratingStates.COMPLETE:
                            # we're done with the child state, so clear it and continue
                            # back to the top of the loop to get the next task
                            state.child_state = None
                    else:
                        # First here, we check to see if we've failed anywhere down the chain
                        # of states we have, and if so we move onto the rescue portion. Otherwise,
                        # we check to see if we've moved past the end of the list of tasks. If so,
                        # we move into the always portion of the block, otherwise we get the next
                        # task from the list.
                        try:
                            task = block.block[state.cur_regular_task]
                        except IndexError:
                            state.run_state = IteratingStates.ALWAYS
                        else:
                            # if the current task is actually a child block, create a child
                            # state for us to recurse into on the next pass
                            if isinstance(task, Block):
                                state.child_state = HostState(blocks=[task])
                                state.child_state.run_state = IteratingStates.TASKS
                                # since we've created the child state, clear the task
                                # so we can pick up the child state on the next pass
                                task = None
                            state.cur_regular_task += 1

                case IteratingStates.RESCUE:
                    # The process here is identical to IteratingStates.TASKS, except instead
                    # we move into the always portion of the block.
                    if state.child_state:
                        state.child_state, task = self._get_next_task_from_state(state.child_state, host=host)
                        if self._check_failed_state(state.child_state):
                            state.child_state = None
                            self._set_failed_state(state)
                        elif state.child_state.run_state == IteratingStates.COMPLETE:
                            state.child_state = None
                    else:
                        try:
                            task = block.rescue[state.cur_rescue_task]
                        except IndexError:
                            if block.rescue:
                                state.fail_state = FailedStates.NONE
                            state.run_state = IteratingStates.ALWAYS
                        else:
                            if isinstance(task, Block):
                                state.child_state = HostState(blocks=[task])
                                state.child_state.run_state = IteratingStates.TASKS
                                task = None
                            state.cur_rescue_task += 1

                case IteratingStates.ALWAYS:
                    # And again, the process here is identical to IteratingStates.TASKS, except
                    # instead we either move onto the next block in the list, or we set the
                    # run state to IteratingStates.COMPLETE in the event of any errors, or when we
                    # have hit the end of the list of blocks.
                    if state.child_state:
                        state.child_state, task = self._get_next_task_from_state(state.child_state, host=host)
                        if self._check_failed_state(state.child_state):
                            state.child_state = None
                            self._set_failed_state(state)
                        elif state.child_state.run_state == IteratingStates.COMPLETE:
                            state.child_state = None
                    else:
                        try:
                            task = block.always[state.cur_always_task]
                        except IndexError:
                            if state.fail_state != FailedStates.NONE:
                                state.run_state = IteratingStates.COMPLETE
                            else:
                                state.cur_block += 1
                                state.cur_regular_task = 0
                                state.cur_rescue_task = 0
                                state.cur_always_task = 0
                                state.run_state = IteratingStates.TASKS
                        else:
                            if isinstance(task, Block):
                                state.child_state = HostState(blocks=[task])
                                state.child_state.run_state = IteratingStates.TASKS
                                task = None
                            state.cur_always_task += 1

                case IteratingStates.HANDLERS:
                    if state.update_handlers:
                        # reset handlers for HostState since handlers from include_tasks
                        # might be there from previous flush
                        state.handlers = self.handlers[:]
                        state.update_handlers = False

                    while True:
                        try:
                            task = state.handlers[state.cur_handlers_task]
                        except IndexError:
                            task = None
                            state.cur_handlers_task = 0
                            state.run_state = state.pre_flushing_run_state
                            state.update_handlers = True
                            break
                        else:
                            state.cur_handlers_task += 1
                            if task.is_host_notified(host):
                                break

                case IteratingStates.COMPLETE:
                    return state, None

            # if something above set the task, break out of the loop now
            if task:
                break

        return state, task

    def _set_failed_state(self, state):
        if state.run_state == IteratingStates.HANDLERS:
            # we are failing `meta: flush_handlers`, so just reset the state to whatever
            # it was before and let `_set_failed_state` figure out the next state
            state.run_state = state.pre_flushing_run_state
            state.update_handlers = True

        if state.run_state == IteratingStates.SETUP:
            state.fail_state |= FailedStates.SETUP
            state.run_state = IteratingStates.COMPLETE
        else:
            s = self.get_active_state(state)
            match s.run_state:
                case IteratingStates.TASKS:
                    s.fail_state |= FailedStates.TASKS
                    if s._blocks[s.cur_block].rescue:
                        s.run_state = IteratingStates.RESCUE
                    elif s._blocks[s.cur_block].always:
                        s.run_state = IteratingStates.ALWAYS
                    else:
                        s.run_state = IteratingStates.COMPLETE
                case IteratingStates.RESCUE:
                    s.fail_state |= FailedStates.RESCUE
                    if s._blocks[s.cur_block].always:
                        s.run_state = IteratingStates.ALWAYS
                    else:
                        s.run_state = IteratingStates.COMPLETE
                case IteratingStates.ALWAYS:
                    s.fail_state |= FailedStates.ALWAYS
                    s.run_state = IteratingStates.COMPLETE
        return state


    def mark_host_failed(self, host):
        s = self.get_host_state(host)
        display.debug("marking host %s failed, current state: %s" % (host, s))
        s = self._set_failed_state(s)
        display.debug("^ failed state is now: %s" % s)
        self.set_state_for_host(host.name, s)
        self._play._removed_hosts.append(host.name)

    def get_failed_hosts(self):
        return dict((host, True) for (host, state) in self._host_states.items() if self._check_failed_state(state))

    def _check_failed_state(self, state):
        if state is None:
            return False
        return state.fail_state != FailedStates.NONE and state.run_state == IteratingStates.COMPLETE

    def is_failed(self, host):
        s = self.get_host_state(host)
        return self._check_failed_state(s)

    def clear_host_errors(self, host):
        s = self.get_state_for_host(host.name)
        while s is not None:
            s.fail_state = FailedStates.NONE
            s = s.child_state

    def get_active_state(self, state):
        '''
        Finds the active state, recursively if necessary when there are child states.
        '''
        s = state
        if s.run_state in {
            IteratingStates.TASKS,
            IteratingStates.RESCUE,
            IteratingStates.ALWAYS
        }:
            while s.child_state is not None:
                s = s.child_state

        return s

    def is_any_block_rescuing(self, state):
        '''
        Given the current HostState state, determines if the current block, or any child blocks,
        are in rescue mode.
        '''
        s = state
        while s is not None:
            if s.run_state == IteratingStates.TASKS and s.get_current_block().rescue:
                return True
            s = s.child_state

        return False

    def add_tasks(self, host, task_list):
        if not task_list:
            return

        s = self.get_active_state(self._host_states[host.name])
        if s.run_state == IteratingStates.HANDLERS:
            s.handlers[s.cur_handlers_task:s.cur_handlers_task] = [h for b in task_list for h in b.block]
        else:
            target_block = s._blocks[s.cur_block].copy()
            match s.run_state:
                case IteratingStates.TASKS:
                    target_block.block[s.cur_regular_task:s.cur_regular_task] = task_list
                case IteratingStates.RESCUE:
                    target_block.rescue[s.cur_rescue_task:s.cur_rescue_task] = task_list
                case IteratingStates.ALWAYS:
                    target_block.always[s.cur_always_task:s.cur_always_task] = task_list
            s._blocks[s.cur_block] = target_block

        return s

    @property
    def host_states(self):
        return self._host_states

    def get_state_for_host(self, hostname: str) -> HostState:
        return self._host_states[hostname]

    def set_state_for_host(self, hostname: str, state: HostState) -> None:
        if not isinstance(state, HostState):
            raise AnsibleAssertionError('Expected state to be a HostState but was a %s' % type(state))
        self._host_states[hostname] = state

    def set_run_state_for_host(self, hostname: str, run_state: IteratingStates) -> None:
        if not isinstance(run_state, IteratingStates):
            raise AnsibleAssertionError('Expected run_state to be a IteratingStates but was %s' % (type(run_state)))
        self._host_states[hostname].run_state = run_state

    def set_fail_state_for_host(self, hostname: str, fail_state: FailedStates) -> None:
        if not isinstance(fail_state, FailedStates):
            raise AnsibleAssertionError('Expected fail_state to be a FailedStates but was %s' % (type(fail_state)))
        self._host_states[hostname].fail_state = fail_state

    def add_notification(self, hostname: str, notification: str) -> None:
        # preserve order
        host_state = self._host_states[hostname]
        if notification not in host_state.handler_notifications:
            host_state.handler_notifications.append(notification)

    def clear_notification(self, hostname: str, notification: str) -> None:
        self._host_states[hostname].handler_notifications.remove(notification)

    def end_host(self, hostname: str) -> None:
        """Used by ``end_host``, ``end_batch`` and ``end_play`` meta tasks to end executing given host."""
        state = self.get_active_state(self.get_state_for_host(hostname))
        if state.run_state == IteratingStates.RESCUE:
            # This is a special case for when ending a host occurs in rescue.
            # By definition the meta task responsible for ending the host
            # is the last task, so we need to clear the fail state to mark
            # the host as rescued.
            # The reason we need to do that is because this operation is
            # normally done when PlayIterator transitions from rescue to
            # always when only then we can say that rescue didn't fail
            # but with ending a host via meta task, we don't get to that transition.
            self.set_fail_state_for_host(hostname, FailedStates.NONE)
        self.set_run_state_for_host(hostname, IteratingStates.COMPLETE)
        self._play._removed_hosts.append(hostname)
