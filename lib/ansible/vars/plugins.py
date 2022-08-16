# Copyright (c) 2018 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# Make coding more python3-ish
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os

from ansible import constants as C
from ansible.errors import AnsibleError
from ansible.inventory.host import Host
from ansible.module_utils._text import to_bytes
from ansible.plugins.loader import vars_loader
from ansible.utils.collection_loader import AnsibleCollectionRef
from ansible.utils.display import Display
from ansible.utils.vars import combine_vars

display = Display()


def get_plugin_vars(loader, plugin, path, entities):

    data = {}
    try:
        data = plugin.get_vars(loader, path, entities)
    except AttributeError:
        try:
            for entity in entities:
                if isinstance(entity, Host):
                    data |= plugin.get_host_vars(entity.name)
                else:
                    data |= plugin.get_group_vars(entity.name)
        except AttributeError:
            if hasattr(plugin, 'run'):
                raise AnsibleError("Cannot use v1 type vars plugin %s from %s" % (plugin._load_name, plugin._original_path))
            else:
                raise AnsibleError("Invalid vars plugin %s from %s" % (plugin._load_name, plugin._original_path))
    return data


def get_vars_from_path(loader, path, entities, stage):

    data = {}

    vars_plugin_list = list(vars_loader.all())
    for plugin_name in C.VARIABLE_PLUGINS_ENABLED:
        if AnsibleCollectionRef.is_valid_fqcr(plugin_name):
            vars_plugin = vars_loader.get(plugin_name)
            if vars_plugin is None:
                # Error if there's no play directory or the name is wrong?
                continue
            if vars_plugin not in vars_plugin_list:
                vars_plugin_list.append(vars_plugin)

    for plugin in vars_plugin_list:
        # Only plugins loaded via vars_loader.all() support REQUIRES_ENABLED = False. A collection plugin was enabled to get to this point.
        # FIXME: support enabling builtin/legacy plugins by FQCN. They are loaded by all() and always the unqualified name.
        not_legacy = '.' in plugin._load_name

        # 2.x plugins shipped with ansible should require enabling (host_group_vars is enabled by default for backwards compat).
        # ansible.legacy should load automatically and run accoring to REQUIRES_ENABLED.
        if hasattr(plugin, 'REQUIRES_WHITELIST'):
            display.deprecated("The VarsModule class variable 'REQUIRES_WHITELIST' is deprecated. "
                               "Use 'REQUIRES_ENABLED' instead.", version=2.18)
            if not_legacy and not plugin.REQUIRES_WHITELIST:
                # collection misleadingly has REQUIRES_WHITELIST = False, but the plugin does actually require enabling.
                display.warning("Vars plugins in collections must be enabled to be loaded, REQUIRES_WHITELIST = False is not supported.")
            if plugin._load_name not in C.VARIABLE_PLUGINS_ENABLED and plugin.REQUIRES_WHITELIST:
                continue
        elif hasattr(plugin, 'REQUIRES_ENABLED'):
            if not_legacy and not plugin.REQUIRES_ENABLED:
                # collection misleadingly has REQUIRES_ENABLED = False, but the plugin does actually require enabling.
                display.warning("Vars plugins in collections must be enabled to be loaded, REQUIRES_ENABLED = False is not supported.")
            if plugin._load_name not in C.VARIABLE_PLUGINS_ENABLED and plugin.REQUIRES_ENABLED:
                continue

        has_stage = hasattr(plugin, 'get_option') and plugin.has_option('stage')

        # if a plugin-specific setting has not been provided, use the global setting
        # older/non shipped plugins that don't support the plugin-specific setting should also use the global setting
        use_global = (has_stage and plugin.get_option('stage') is None) or not has_stage

        if use_global:
            if C.RUN_VARS_PLUGINS == 'demand' and stage == 'inventory':
                continue
            elif C.RUN_VARS_PLUGINS == 'start' and stage == 'task':
                continue
        elif has_stage and plugin.get_option('stage') not in ('all', stage):
            continue

        data = combine_vars(data, get_plugin_vars(loader, plugin, path, entities))

    return data


def get_vars_from_inventory_sources(loader, sources, entities, stage):

    data = {}
    for path in sources:

        if path is None:
            continue
        if ',' in path and not os.path.exists(path):  # skip host lists
            continue
        elif not os.path.isdir(to_bytes(path)):
            # always pass the directory of the inventory source file
            path = os.path.dirname(path)

        data = combine_vars(data, get_vars_from_path(loader, path, entities, stage))

    return data
