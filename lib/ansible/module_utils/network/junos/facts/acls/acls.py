#
# -*- coding: utf-8 -*-
# Copyright 2020 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The junos acls fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from copy import deepcopy

from ansible.module_utils._text import to_bytes
from ansible.module_utils.basic import missing_required_lib
from ansible.module_utils.network.common import utils
from ansible.module_utils.network.junos.argspec.acls.acls import AclsArgs
from ansible.module_utils.six import string_types
try:
    from lxml import etree
    HAS_LXML = True
except ImportError:
    HAS_LXML = False
try:
    import xmltodict
    HAS_XMLTODICT = True
except ImportError:
    HAS_XMLTODICT = False


class AclsFacts(object):
    """ The junos acls fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = AclsArgs.argument_spec
        spec = deepcopy(self.argument_spec)
        if subspec:
            if options:
                facts_argument_spec = spec[subspec][options]
            else:
                facts_argument_spec = spec[subspec]
        else:
            facts_argument_spec = spec

        self.generated_spec = utils.generate_dict(facts_argument_spec)

    def populate_facts(self, connection, ansible_facts, data=None):
        """ Populate the facts for acls
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        if not HAS_LXML:
            self._module.fail_json(msg=missing_required_lib("lxml"))

        if not data:
            config_filter = """
                <configuration>
                  <firewall/>
                </configuration>
                """
            data = connection.get_configuration(filter=config_filter)

        if isinstance(data, string_types):
            data = etree.fromstring(to_bytes(data,
                                             errors='surrogate_then_replace'))

        resources = data.xpath('configuration/firewall')

        objs = []
        for resource in resources:
            if resource:
                xml = self._get_xml_dict(resource)
                obj = self.render_config(self.generated_spec, xml)
                if obj:
                    objs.append(obj)

        facts = {}
        if objs:
            facts['junos_acls'] = []
            params = utils.validate_config(self.argument_spec, {'config': objs})
            for cfg in params['config']:
                facts['junos_acls'].append(utils.remove_empties(cfg))

        ansible_facts['ansible_network_resources'].update(facts)
        return ansible_facts

    def _get_xml_dict(self, xml_root):
        if not HAS_XMLTODICT:
            self._module.fail_json(msg=missing_required_lib("xmltodict"))

        xml_dict = xmltodict.parse(etree.tostring(xml_root), dict_constructor=dict)
        return xml_dict

    def render_config(self, spec, conf):
        """
        Render config as dictionary structure and delete keys
          from spec for null values

        :param spec: The facts tree, generated from the argspec
        :param conf: The configuration
        :rtype: dictionary
        :returns: The generated config
        """
        config = deepcopy(spec)
        protocol = 'inet'
        if config['afi'] == 'ipv6':
            protocol = 'inet6'
        acls = conf.get('firewall').get('family').get(protocol).get('filter')
        if not isinstance(acls, list):
            acls = [acls]
        config['acls'] = []
        for acl in acls:
            acl_dict = {'name': acl['name'],
                        'aces': []}
            if acl.get('term'):
                ace = {'name': acl['term'].get('name')}
                if acl['term'].get('from'):
                    if acl['term']['from'].get('source-address'):
                        ace['source'] = {}
                        ace['source']['source_address'] = acl['term']['from']['source-address']['name']
                    if acl['term']['from'].get('port'):
                        ace['port'] = {}
                        ace['port']['range'] = acl['term']['from']['port']
                    if acl['term']['from'].get('protocol'):
                        ace['protocol'] = {}
                        protocol = acl['term']['from']['protocol']
                        ace['protocol'][protocol] = True
                acl_dict['aces'].append(ace)
            config['acls'].append(acl_dict)
        return utils.remove_empties(config)
