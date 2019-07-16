#
# -*- coding: utf-8 -*-
# Copyright 2019 Cisco and/or its affiliates.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The nxos telemetry utility library
"""

import re


def get_module_params_subsection(module_params, tms_config, resource_key=None):
    """
    Helper method to get a specific module_params subsection
    """
    mp = {}
    if tms_config == 'TMS_GLOBAL':
        relevant_keys = ['certificate',
                         'compression',
                         'source_interface',
                         'vrf']
        for key in relevant_keys:
            mp[key] = module_params[key]

    if tms_config == 'TMS_DESTGROUP':
        mp['destination_groups'] = []
        for destgrp in module_params['destination_groups']:
            if destgrp['id'] == resource_key:
                mp['destination_groups'].append(destgrp)

    if tms_config == 'TMS_SENSORGROUP':
        mp['sensor_groups'] = []
        for sensor in module_params['sensor_groups']:
            if sensor['id'] == resource_key:
                mp['sensor_groups'].append(sensor)

    if tms_config == 'TMS_SUBSCRIPTION':
        mp['subscriptions'] = []
        for sensor in module_params['subscriptions']:
            if sensor['id'] == resource_key:
                mp['subscriptions'].append(sensor)

    return mp


def valiate_input(playvals, type, module):
    """
    Helper method to validate playbook values for destination groups
    """
    if type == 'destination_groups':
        if not playvals.get('id'):
            msg = "Invalid playbook value: {0}.".format(playvals)
            msg = msg + " Parameter <id> under <destination_groups> is required"
            module.fail_json(msg=msg)
        if playvals.get('destination') and not isinstance(playvals['destination'], dict):
            msg = "Invalid playbook value: {0}.".format(playvals)
            msg = msg + " Parameter <destination> under <destination_groups> must be a dict"
            module.fail_json(msg=msg)
        if not playvals.get('destination') and len(playvals) > 1:
            msg = "Invalid playbook value: {0}.".format(playvals)
            msg = msg + " Playbook entry contains unrecongnized parameters."
            msg = msg + " Make sure <destination> keys under <destination_groups> are specified as follows:"
            msg = msg + " destination: {ip: <ip>, port: <port>, protocol: <prot>, encoding: <enc>}}"
            module.fail_json(msg=msg)

    if type == 'sensor_groups':
        if not playvals.get('id'):
            msg = "Invalid playbook value: {0}.".format(playvals)
            msg = msg + " Parameter <id> under <sensor_groups> is required"
            module.fail_json(msg=msg)
        if playvals.get('path') and 'name' not in playvals['path'].keys():
            msg = "Invalid playbook value: {0}.".format(playvals)
            msg = msg + " Parameter <path> under <sensor_groups> requires <name> key"
            module.fail_json(msg=msg)


def get_instance_data(key, cr_key, cr, existing_key):
    """
    Helper method to get instance data used to populate list structure in config
    fact dictionary
    """
    data = {}
    if existing_key is None:
        instance = None
    else:
        instance = cr._ref[cr_key]['existing'][existing_key]

    if key == 'destination_groups':
        m = re.search("destination-group (\d+)", cr._ref['_resource_key'])
        instance_key = m.group(1)
        data = {'id': instance_key, cr_key: instance}

    if key == 'sensor_groups':
        m = re.search("sensor-group (\d+)", cr._ref['_resource_key'])
        instance_key = m.group(1)
        data = {'id': instance_key, cr_key: instance}

    if key == 'subscriptions':
        m = re.search("subscription (\d+)", cr._ref['_resource_key'])
        instance_key = m.group(1)
        data = {'id': instance_key, cr_key: instance}

    # Remove None values
    data = dict((k, v) for k, v in data.items() if v is not None)
    return data


def cr_key_lookup(key, mo):
    """
    Helper method to get instance key value for mo
    """
    cr_keys = [key]
    if key == 'destination_groups' and mo == 'TMS_DESTGROUP':
        cr_keys = ['destination']
    elif key == 'sensor_groups' and mo == 'TMS_SENSORGROUP':
        cr_keys = ['data_source', 'path']
    elif key == 'subscriptions' and mo == 'TMS_SUBSCRIPTION':
        cr_keys = ['destination_group', 'sensor_group']

    return cr_keys


def normalize_data(cmd_ref):
    ''' Normalize playbook values and get_exisiting data '''

    playval = cmd_ref._ref.get('destination').get('playval')
    existing = cmd_ref._ref.get('destination').get('existing')

    dest_props = ['protocol', 'encoding']
    if playval:
        for prop in dest_props:
            for key in playval.keys():
                playval[key][prop] = playval[key][prop].lower()
    if existing:
        for key in existing.keys():
            for prop in dest_props:
                existing[key][prop] = existing[key][prop].lower()


def remove_duplicate_context(cmds):
    ''' Helper method to remove duplicate telemetry context commands '''
    if not cmds:
        return cmds
    feature_indices = [i for i, x in enumerate(cmds) if x == "feature telemetry"]
    telemetry_indeces = [i for i, x in enumerate(cmds) if x == "telemetry"]
    if len(feature_indices) == 1 and len(telemetry_indeces) == 1:
        return cmds
    if len(feature_indices) == 1 and not telemetry_indeces:
        return cmds
    if len(telemetry_indeces) == 1 and not feature_indices:
        return cmds
    if feature_indices and feature_indices[-1] > 1:
        cmds.pop(feature_indices[-1])
        return remove_duplicate_context(cmds)
    if telemetry_indeces and telemetry_indeces[-1] > 1:
        cmds.pop(telemetry_indeces[-1])
        return remove_duplicate_context(cmds)


def get_setval_path(module):
    ''' Build setval for path parameter based on playbook inputs
        Full Command:
          - path {name} depth {depth} query-condition {query_condition} filter-condition {filter_condition}
        Required:
          - path {name}
        Optional:
          - depth {depth}
          - query-condition {query_condition},
          - filter-condition {filter_condition}
    '''
    path = module.params['config']['sensor_groups'][0].get('path')
    if path is None:
        return path

    setval = 'path {name}'
    if 'depth' in path.keys():
        setval = setval + ' depth {depth}'
    if 'query_condition' in path.keys():
        setval = setval + ' query-condition {query_condition}'
    if 'filter_condition' in path.keys():
        setval = setval + ' filter-condition {filter_condition}'

    return setval
