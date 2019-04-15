#!/usr/bin/python
#
# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: onyx_traffic_class
version_added: "2.9"
author: "Anas Badaha (@anasb)"
short_description: Configures Traffic Class
description:
  - This module provides declarative management of Traffic Class configuration
    on Mellanox ONYX network devices.
options:
  state:
    description:
      - enable congestion control on interface.
    choices: ['enabled','disabled']
    default: enabled
  interfaces:
    description:
      - list of interfaces name.
    required: true
  tc:
    description:
      - traffic class, range 0-7.
    required: true
  congestion_control:
    description:
      - configure congestion control on interface.
    suboptions:
      control:
        description:
          - congestion control type.
        choices: ['red', 'ecn', 'both']
        required: true
      min_absolute:
        description:
          - Set minimum-absolute value (in KBs) for marking traffic-class queue.
      max_absolute:
        description:
          - Set maximum-absolute value (in KBs) for marking traffic-class queue.
      min_relative:
        description:
          - Set minimum- relative value (in KBs) for marking traffic-class queue.
      max_relative:
        description:
          - Set maximum- relative value (in KBs) for marking traffic-class queue.
  dcb:
    description:
      - configure dcb control on interface.
    suboptions:
      mode:
        description:
          - dcb control mode.
        choices: ['strict', 'wrr']
        required: true
      weight:
        description:
          - Relevant only for wrr mode.
        type: int
"""

EXAMPLES = """
- name: configure traffic class
  onyx_traffic_class:
    interfaces:
      - Eth1/1
      - Eth1/2
    tc: 3
    congestion_control:
      control: ecn
      min_absolute: 500
      max_absolute: 1500
    dcb:
      mode: strict
"""

RETURN = """
commands:
  description: The list of configuration mode commands to send to the device.
  returned: always
  type: list
  sample:
    - interface ethernet 1/15 traffic-class 3 congestion-control ecn minimum-absolute 150 maximum-absolute 1500
    - interface ethernet 1/16 traffic-class 3 congestion-control ecn minimum-absolute 150 maximum-absolute 1500
    - interface mlag-port-channel 7 traffic-class 3 congestion-control ecn minimum-absolute 150 maximum-absolute 1500
    - interface port-channel 1 traffic-class 3 congestion-control ecn minimum-absolute 150 maximum-absolute 1500
    - interface ethernet 1/15 traffic-class 6 dcb ets strict
    - interface ethernet 1/16 traffic-class 6 dcb ets strict
    - interface mlag-port-channel 7 traffic-class 6 dcb ets strict
    - interface port-channel 1 traffic-class 6 dcb ets strict
"""

import re
from ansible.module_utils.six import iteritems
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.network.onyx.onyx import show_cmd
from ansible.module_utils.network.onyx.onyx import BaseOnyxModule


class OnyxTrafficClassModule(BaseOnyxModule):

    IF_ETH_REGEX = re.compile(r"^Eth(\d+\/\d+|Eth\d+\/\d+\d+)$")
    IF_PO_REGEX = re.compile(r"^Po(\d+)$")
    MLAG_NAME_REGEX = re.compile(r"^Mpo(\d+)$")

    IF_TYPE_ETH = "ethernet"
    PORT_CHANNEL = "port-channel"
    MLAG_PORT_CHANNEL = "mlag-port-channel"

    IF_TYPE_MAP = {
        IF_TYPE_ETH: IF_ETH_REGEX,
        PORT_CHANNEL: IF_PO_REGEX,
        MLAG_PORT_CHANNEL: MLAG_NAME_REGEX
    }

    def init_module(self):
        """ initialize module
        """
        congestion_control_spec = dict(control=dict(choices=['red', 'ecn', 'both'], required=True),
                                       min_absolute=dict(type=int),
                                       max_absolute=dict(type=int),
                                       min_relative=dict(type=int),
                                       max_relative=dict(type=int))

        dcb_spec = dict(mode=dict(choices=['strict', 'wrr'], required=True),
                        weight=dict(type=int))

        element_spec = dict(
            interfaces=dict(type='list', required=True),
            tc=dict(type=int, required=True),
            congestion_control=dict(type='dict', options=congestion_control_spec),
            dcb=dict(type='dict', options=dcb_spec),
            state=dict(choices=['enabled', 'disabled'], default='enabled'))

        argument_spec = dict()
        argument_spec.update(element_spec)
        self._module = AnsibleModule(
            argument_spec=argument_spec,
            supports_check_mode=True)

    def get_required_config(self):
        module_params = self._module.params
        self._required_config = dict(module_params)
        self.validate_param_values(self._required_config)

    def validate_tc(self, value):
        if value and not 0 <= int(value) <= 7:
            self._module.fail_json(msg='tc value must be between 0 and 7')

    def validate_param_values(self, obj, param=None):
        congestion_control = obj.get("congestion_control")
        if congestion_control is not None:
            min_absolute = congestion_control.get("min_absolute")
            max_absolute = congestion_control.get("max_absolute")
            min_relative = congestion_control.get("min_relative")
            max_relative = congestion_control.get("max_relative")
            if (min_absolute and min_relative and max_absolute and max_relative) is not None:
                self._module.fail_json(msg='User can specify absolute or relative not both')
            elif min_absolute is None and min_relative is None and max_absolute is None and max_relative is None:
                self._module.fail_json(msg='User can not send both absolute and relative empty')
            elif (min_absolute is not None and max_absolute is None) or (min_absolute is None and max_absolute is not None):
                self._module.fail_json(msg='User should send both mix_absolute and min_absolute')
            elif (min_relative is not None and max_relative is None) or (min_relative is None and max_relative is not None):
                self._module.fail_json(msg='User should send both max_relative and min_relative')

        dcb = obj.get("dcb")
        if dcb is not None:
            dcb_mode = dcb.get("mode")
            weight = dcb.get("weight")
            if dcb_mode == "wrr" and weight is None:
                self._module.fail_json(msg='User should send weight attribute when dcb mode is wrr')
        super(OnyxTrafficClassModule, self).validate_param_values(obj, param)

    def _get_interface_type(self, if_name):
        if_type = None
        if_id = None
        for interface_type, interface_regex in iteritems(self.IF_TYPE_MAP):
            match = interface_regex.match(if_name)
            if match:
                if_type = interface_type
                if_id = match.group(1)
                break
        return if_type, if_id

    def _set_interface_congestion_control_config(self, interface_congestion_control_config, interface, if_type, if_id):
        tc = self._required_config.get("tc")
        interface_dcb_ets = self._show_interface_dcb_ets(if_type, if_id)[0].get(interface)
        ets_per_tc = interface_dcb_ets[2].get("ETS per TC")
        tc_config = ets_per_tc[0].get(str(tc))
        dcb_mode = tc_config[0].get("S.Mode")
        dcb_weight = int(tc_config[0].get("W"))
        dcb = dict(mode=dcb_mode.lower(), weight=dcb_weight)
        interface_congestion_control_config = interface_congestion_control_config[tc + 1]
        mode = interface_congestion_control_config.get("Mode")
        if mode == "none":
            self._current_config[interface] = dict(state="disabled", dcb=dcb, if_type=if_type, if_id=if_id)
            return

        congestion_control = dict()
        threshold_mode = interface_congestion_control_config.get("Threshold mode")
        max_threshold = interface_congestion_control_config.get("Maximum threshold")
        min_threshold = interface_congestion_control_config.get("Minimum threshold")

        if threshold_mode == "absolute":
            min_absolute = int(min_threshold.split(" ")[0])
            max_absolute = int(max_threshold.split(" ")[0])
            congestion_control = dict(control=mode.lower(), min_absolute=min_absolute, max_absolute=max_absolute)
        elif threshold_mode == "relative":
            min_relative = int(min_threshold.split("%")[0])
            max_relative = int(max_threshold.split("%")[0])
            congestion_control = dict(control=mode.lower(), min_relative=min_relative, max_relative=max_relative)

        self._current_config[interface] = dict(state="enabled", congestion_control=congestion_control,
                                               dcb=dcb, if_type=if_type, if_id=if_id)

    def _show_interface_congestion_control(self, if_type, interface):
        cmd = "show interfaces {0} {1} congestion-control".format(if_type, interface)
        return show_cmd(self._module, cmd, json_fmt=True, fail_on_error=False)

    def _show_interface_dcb_ets(self, if_type, interface):
        cmd = "show dcb ets interface {0} {1}".format(if_type, interface)
        return show_cmd(self._module, cmd, json_fmt=True, fail_on_error=False)

    def load_current_config(self):
        self._current_config = dict()
        for interface in self._required_config.get("interfaces"):
            if_type, if_id = self._get_interface_type(interface)
            if not if_id:
                self._module.fail_json(
                    msg='unsupported interface: {0}'.format(interface))
            interface_congestion_control_config = self._show_interface_congestion_control(if_type, if_id)
            if interface_congestion_control_config is not None:
                self._set_interface_congestion_control_config(interface_congestion_control_config,
                                                              interface, if_type, if_id)
            else:
                self._module.fail_json(
                    msg='Interface {0} does not exist on switch'.format(interface))

    def generate_commands(self):
        state = self._required_config.get("state")
        tc = self._required_config.get("tc")
        interfaces = self._required_config.get("interfaces")
        for interface in interfaces:
            current_interface = self._current_config.get(interface)
            current_state = current_interface.get("state")
            if_type = current_interface.get("if_type")
            if_id = current_interface.get("if_id")
            if state == "disabled" and current_state == "enabled":
                self._commands.append('interface {0} {1} no traffic-class {2} congestion-control'.format(if_type, if_id, tc))
                continue
            elif state == "disabled" and current_state == "disabled":
                continue

            congestion_control = self._required_config.get("congestion_control")

            if congestion_control is not None:
                min_absolute = congestion_control.get("min_absolute")
                control = congestion_control.get("control")
                current_congestion_control = current_interface.get("congestion_control")
                current_control = None
                if current_congestion_control is not None:
                    current_control = current_congestion_control.get("control")

                if min_absolute is not None:
                    max_absolute = congestion_control.get("max_absolute")
                    if current_control is None or control != current_control:
                        self._generate_congestion_control_absolute_cmds(if_type, if_id, tc,
                                                                        control, min_absolute, max_absolute)
                    else:
                        current_min_absolute = current_congestion_control.get("min_absolute")
                        current_max_absolute = current_congestion_control.get("max_absolute")
                        if min_absolute != current_min_absolute or max_absolute != current_max_absolute:
                            self._generate_congestion_control_absolute_cmds(if_type, if_id, tc,
                                                                            control, min_absolute, max_absolute)
                else:
                    min_relative = congestion_control.get("min_relative")
                    max_relative = congestion_control.get("max_relative")
                    if current_control is None or control != current_control:
                        self._generate_congestion_control_relative_cmds(if_type, if_id, tc, control,
                                                                        min_relative, max_relative)
                    else:
                        current_min_relative = current_congestion_control.get("min_relative")
                        current_max_relative = current_congestion_control.get("max_relative")
                        if min_relative != current_min_relative or max_relative != current_max_relative:
                            self._generate_congestion_control_relative_cmds(if_type, if_id, tc, control,
                                                                            min_relative, max_relative)

            dcb = self._required_config.get("dcb")
            if dcb is not None:
                dcb_mode = dcb.get("mode")
                current_dcb = current_interface.get("dcb")
                current_dcb_mode = current_dcb.get("mode")
                if dcb_mode == "strict" and dcb_mode != current_dcb_mode:
                    self._commands.append('interface {0} {1} traffic-class {2} '
                                          'dcb ets {3}'.format(if_type, if_id, tc, dcb_mode))
                elif dcb_mode == "wrr":
                    weight = dcb.get("weight")
                    current_weight = current_dcb.get("weight")
                    if dcb_mode != current_dcb_mode:
                        self._commands.append('interface {0} {1} traffic-class {2} '
                                              'dcb ets {3} {4}'.format(if_type, if_id, tc, dcb_mode, weight))
                    elif weight != current_weight:
                        self._commands.append('interface {0} {1} traffic-class {2} '
                                              'dcb ets {3} {4}'.format(if_type, if_id, tc, dcb_mode, weight))

    def _generate_congestion_control_absolute_cmds(self, if_type, if_id, tc, control,
                                                   min_absolute, max_absolute):
        self._commands.append('interface {0} {1} traffic-class {2} '
                              'congestion-control {3} minimum-absolute {4} '
                              'maximum-absolute {5}'.format(if_type, if_id, tc, control,
                                                            min_absolute, max_absolute))

    def _generate_congestion_control_relative_cmds(self, if_type, if_id, tc, control,
                                                   min_relative, max_relative):
        self._commands.append('interface {0} {1} traffic-class {2} '
                              'congestion-control {3} minimum-relative {4} '
                              'maximum-relative {5}'.format(if_type, if_id, tc, control,
                                                            min_relative, max_relative))


def main():
    """ main entry point for module execution
    """
    OnyxTrafficClassModule.main()


if __name__ == '__main__':
    main()
