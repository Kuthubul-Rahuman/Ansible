#!/usr/bin/python
#
# (c) 2015, Steve Gargan <steve.gargan@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
module: consul_acl
short_description: Manipulate Consul ACL keys and rules
description:
 - Allows the addition, modification and deletion of ACL keys and associated
   rules in a consul cluster via the agent. For more details on using and
   configuring ACLs, see https://www.consul.io/docs/guides/acl.html.
version_added: "2.0"
author:
  - Steve Gargan (@sgargan)
  - Colin Nolan (@colin-nolan)
options:
  mgmt_token:
    description:
      - a management token is required to manipulate the acl lists
  state:
    description:
      - whether the ACL pair should be present or absent
    required: false
    choices: ['present', 'absent']
    default: present
  token_type:
    description:
      - the type of token that should be created, either management or client
    choices: ['client', 'management']
    default: client
  name:
    description:
      - the name that should be associated with the acl key, this is opaque
        to Consul
    required: false
  token:
    description:
      - the token key indentifying an ACL rule set. If generated by consul
        this will be a UUID
    required: false
  rules:
    description:
      - a list of the rules that should be associated with a given token
    required: false
  host:
    description:
      - host of the consul agent defaults to localhost
    required: false
    default: localhost
  port:
    description:
      - the port on which the consul agent is running
    required: false
    default: 8500
  scheme:
    description:
      - the protocol scheme on which the consul agent is running
    required: false
    default: http
    version_added: "2.1"
  validate_certs:
    description:
      - whether to verify the tls certificate of the consul agent
    required: false
    default: True
    version_added: "2.1"
requirements:
  - "python >= 2.6"
  - python-consul
  - pyhcl
  - requests
"""

EXAMPLES = """
- name: create an ACL with rules
  consul_acl:
    host: consul1.example.com
    mgmt_token: some_management_acl
    name: Foo access
    rules:
      - key: "foo"
        policy: read
      - key: "private/foo"
        policy: deny

- name: create an ACL with a specific token
  consul_acl:
    host: consul1.example.com
    mgmt_token: some_management_acl
    name: Foo access
    token: my-token
    rules:
      - key: "foo"
        policy: read

- name: update the rules associated to an ACL token
  consul_acl:
    host: consul1.example.com
    mgmt_token: some_management_acl
    name: Foo access
    token: some_client_token
    rules:
      - event: "bbq"
        policy: write
      - key: "foo"
        policy: read
      - key: "private"
        policy: deny
      - keyring: write
      - node: "hgs4"
        policy: write
      - operator: read
      - query: ""
        policy: write
      - service: "consul"
        policy: write
      - session: "standup"
        policy: write

- name: remove a token
  consul_acl:
    host: consul1.example.com
    mgmt_token: some_management_acl
    token: 172bd5c8-9fe9-11e4-b1b0-3c15c2c9fd5e
    state: absent
"""

RETURN = """
token:
    description: the token associated to the ACL (the ACL's ID)
    returned: success
    type: string
    sample: a2ec332f-04cf-6fba-e8b8-acf62444d3da
rules:
    description: the HCL JSON representation of the rules associated to the ACL, in the format described in the
                 Consul documentation (https://www.consul.io/docs/guides/acl.html#rule-specification).
    returned: I(status) == "present"
    type: string
    sample: {
        "key": {
            "foo": {
                "policy": "write"
            },
            "bar": {
                "policy": "deny"
            }
        }
    }
operation:
    description: the operation performed on the ACL
    returned: changed
    type: string
    sample: update
"""


try:
    import consul
    python_consul_installed = True
except ImportError:
    python_consul_installed = False

try:
    import hcl
    pyhcl_installed = True
except ImportError:
    pyhcl_installed = False

from collections import defaultdict
from requests.exceptions import ConnectionError
from ansible.module_utils.basic import to_text, AnsibleModule


RULE_SCOPES = ["agent", "event", "key", "keyring", "node", "operator", "query", "service", "session"]

MANAGEMENT_PARAMETER_NAME = "mgmt_token"
HOST_PARAMETER_NAME = "host"
SCHEME_PARAMETER_NAME = "scheme"
VALIDATE_CERTS_PARAMETER_NAME = "validate_certs"
NAME_PARAMETER_NAME = "name"
PORT_PARAMETER_NAME = "port"
RULES_PARAMETER_NAME = "rules"
STATE_PARAMETER_NAME = "state"
TOKEN_PARAMETER_NAME = "token"
TOKEN_TYPE_PARAMETER_NAME = "token_type"

PRESENT_STATE_VALUE = "present"
ABSENT_STATE_VALUE = "absent"

CLIENT_TOKEN_TYPE_VALUE = "client"
MANAGEMENT_TOKEN_TYPE_VALUE = "management"

REMOVE_OPERATION = "remove"
UPDATE_OPERATION = "update"
CREATE_OPERATION = "create"

_POLICY_JSON_PROPERTY = "policy"
_RULES_JSON_PROPERTY = "Rules"
_TOKEN_JSON_PROPERTY = "ID"
_TOKEN_TYPE_JSON_PROPERTY = "Type"
_NAME_JSON_PROPERTY = "Name"
_POLICY_YML_PROPERTY = "policy"
_POLICY_HCL_PROPERTY = "policy"

_ARGUMENT_SPEC = {
    MANAGEMENT_PARAMETER_NAME: dict(required=True, no_log=True),
    HOST_PARAMETER_NAME: dict(default='localhost'),
    SCHEME_PARAMETER_NAME: dict(required=False, default='http'),
    VALIDATE_CERTS_PARAMETER_NAME: dict(required=False, type='bool', default=True),
    NAME_PARAMETER_NAME: dict(required=False),
    PORT_PARAMETER_NAME: dict(default=8500, type='int'),
    RULES_PARAMETER_NAME: dict(default=None, required=False, type='list'),
    STATE_PARAMETER_NAME: dict(default=PRESENT_STATE_VALUE, choices=[PRESENT_STATE_VALUE, ABSENT_STATE_VALUE]),
    TOKEN_PARAMETER_NAME: dict(required=False),
    TOKEN_TYPE_PARAMETER_NAME: dict(required=False, choices=[CLIENT_TOKEN_TYPE_VALUE, MANAGEMENT_TOKEN_TYPE_VALUE],
                                    default=CLIENT_TOKEN_TYPE_VALUE)
}


def set_acl(consul_client, configuration):
    """
    Sets an ACL based on the given configuration.
    :param consul_client: the consul client
    :param configuration: the run configuration
    :return: the output of setting the ACL
    """
    acls_as_json = decode_acls_as_json(consul_client.acl.list())
    existing_acls_mapped_by_name = dict((acl.name, acl) for acl in acls_as_json if acl.name is not None)
    existing_acls_mapped_by_token = dict((acl.token, acl) for acl in acls_as_json)
    if None in existing_acls_mapped_by_token:
        raise AssertionError("expecting ACL list to be associated to a token: %s" %
                             existing_acls_mapped_by_token[None])

    if configuration.token is None and configuration.name is not None \
            and configuration.name in existing_acls_mapped_by_name:
        # Name used as identifier instead of token - get token of ACL with identifying name
        configuration.token = existing_acls_mapped_by_name[configuration.name].token

    if configuration.token and configuration.token in existing_acls_mapped_by_token:
        # Token given and ACL with token exists - update the existing ACL
        return update_acl(
            consul_client, configuration.token, configuration.name, configuration.token_type, configuration.rules)
    else:
        if configuration.token in existing_acls_mapped_by_token:
            raise AssertionError()
        if configuration.name in existing_acls_mapped_by_name:
            raise AssertionError()
        return create_acl(
            consul_client, configuration.token, configuration.name, configuration.token_type, configuration.rules)


def update_acl(consul_client, token, name, token_type, rules):
    """
    Updates an ACL.
    :param consul_client: the consul client
    :param token: token of the ACL
    :param name: name of the ACL
    :param token_type: type of ACL
    :param rules: the rules associated to the ACL
    :return: the output of the update
    """
    existing_acl = load_acl_with_token(consul_client, token)
    changed = existing_acl.rules != rules

    if changed:
        name = name if name is not None else existing_acl.name
        rules_as_hcl = encode_rules_as_hcl_string(rules)
        updated_token = consul_client.acl.update(token, name=name, type=token_type, rules=rules_as_hcl)
        if updated_token != token:
            raise AssertionError()

    return Output(changed=changed, token=token, rules=rules, operation=UPDATE_OPERATION)


def create_acl(consul_client, token, name, token_type, rules):
    """
    Creates an ACL.
    :param consul_client: the consul client
    :param token: token of the ACL
    :param name: name of the ACL
    :param token_type: type of ACL
    :param rules: the rules associated to the ACL
    :return: the output of the creation
    """
    rules_as_hcl = encode_rules_as_hcl_string(rules) if len(rules) > 0 else None
    token = consul_client.acl.create(
        name=name, type=token_type, rules=rules_as_hcl, acl_id=token)
    return Output(changed=True, token=token, rules=rules, operation=CREATE_OPERATION)


def remove_acl(consul_client, token):
    """
    Removes an ACL.
    :param consul_client: the consul client
    :param token: token of the ACL
    :return: the output of the removal
    """
    changed = consul_client.acl.info(token) is not None
    if changed:
        consul_client.acl.destroy(token)
    return Output(changed=changed, token=token, operation=REMOVE_OPERATION)


def load_acl_with_token(consul_client, token):
    """
    Loads the ACL with the given token (token == rule ID).
    :param consul_client: the consul client
    :param token: the ACL "token"/ID (not name)
    :return: the ACL associated to the given token
    :exception ConsulACLTokenNotFoundException: raised if the given token does not exist
    """
    acl_as_json = consul_client.acl.info(token)
    if acl_as_json is None:
        raise ConsulACLNotFoundException(token)
    return decode_acl_as_json(acl_as_json)


def encode_rules_as_hcl_string(rules):
    """
    Converts the given rules into the equivalent HCL (string) representation.
    :param rules: the rules
    :return: the equivalent HCL (string) representation of the rules. Will be None if there is no rules (see internal
    note for justification)
    """
    if len(rules) == 0:
        # Note: empty string is not valid HCL according to `hcl.load` however, the ACL `Rule` property will be an empty
        # string if there is no rules...
        return None
    rules_as_hcl = ""
    for rule in rules:
        rules_as_hcl += encode_rule_as_hcl_string(rule)
    return rules_as_hcl


def encode_rule_as_hcl_string(rule):
    """
    Converts the given rule into the equivalent HCL (string) representation.
    :param rule: the rule
    :return: the equivalent HCL (string) representation of the rule
    """
    if rule.pattern is not None:
        return '%s "%s" {\n  %s = "%s"\n}\n' % (rule.scope, rule.pattern, _POLICY_HCL_PROPERTY, rule.policy)
    else:
        return '%s = "%s"\n' % (rule.scope, rule.policy)


def decode_rules_as_hcl_string(rules_as_hcl):
    """
    Converts the given HCL (string) representation of rules into a list of rule domain models.
    :param rules_as_hcl: the HCL (string) representation of a collection of rules
    :return: the equivalent domain model to the given rules
    """
    rules_as_hcl = to_text(rules_as_hcl)
    rules_as_json = hcl.loads(rules_as_hcl)
    return decode_rules_as_json(rules_as_json)


def decode_rules_as_json(rules_as_json):
    """
    Converts the given JSON representation of rules into a list of rule domain models.
    :param rules_as_json: the JSON representation of a collection of rules
    :return: the equivalent domain model to the given rules
    """
    rules = RuleCollection()
    for scope in rules_as_json:
        if not isinstance(rules_as_json[scope], dict):
            rules.add(Rule(scope, rules_as_json[scope]))
        else:
            for pattern, policy in rules_as_json[scope].items():
                rules.add(Rule(scope, policy[_POLICY_JSON_PROPERTY], pattern))
    return rules


def encode_rules_as_json(rules):
    """
    Converts the given rules into the equivalent JSON representation according to the documentation:
    https://www.consul.io/docs/guides/acl.html#rule-specification.
    :param rules: the rules
    :return: JSON representation of the given rules
    """
    rules_as_json = defaultdict(dict)
    for rule in rules:
        if rule.pattern is not None:
            if rule.pattern in rules_as_json[rule.scope]:
                raise AssertionError()
            rules_as_json[rule.scope][rule.pattern] = {
                _POLICY_JSON_PROPERTY: rule.policy
            }
        else:
            if rule.scope in rules_as_json:
                raise AssertionError()
            rules_as_json[rule.scope] = rule.policy
    return rules_as_json


def decode_rules_as_yml(rules_as_yml):
    """
    Converts the given YAML representation of rules into a list of rule domain models.
    :param rules_as_yml: the YAML representation of a collection of rules
    :return: the equivalent domain model to the given rules
    """
    rules = RuleCollection()
    if rules_as_yml:
        for rule_as_yml in rules_as_yml:
            rule_added = False
            for scope in RULE_SCOPES:
                if scope in rule_as_yml:
                    if rule_as_yml[scope] is None:
                        raise ValueError("Rule for '%s' does not have a value associated to the scope" % scope)
                    policy = rule_as_yml[_POLICY_YML_PROPERTY] if _POLICY_YML_PROPERTY in rule_as_yml \
                        else rule_as_yml[scope]
                    pattern = rule_as_yml[scope] if _POLICY_YML_PROPERTY in rule_as_yml else None
                    rules.add(Rule(scope, policy, pattern))
                    rule_added = True
                    break
            if not rule_added:
                raise ValueError("A rule requires one of %s and a policy." % ('/'.join(RULE_SCOPES)))
    return rules


def decode_acl_as_json(acl_as_json):
    """
    Converts the given JSON representation of an ACL into the equivalent domain model.
    :param acl_as_json: the JSON representation of an ACL
    :return: the equivalent domain model to the given ACL
    """
    rules_as_hcl = acl_as_json[_RULES_JSON_PROPERTY]
    rules = decode_rules_as_hcl_string(acl_as_json[_RULES_JSON_PROPERTY]) if rules_as_hcl.strip() != "" \
        else RuleCollection()
    return ACL(
        rules=rules,
        token_type=acl_as_json[_TOKEN_TYPE_JSON_PROPERTY],
        token=acl_as_json[_TOKEN_JSON_PROPERTY],
        name=acl_as_json[_NAME_JSON_PROPERTY]
    )


def decode_acls_as_json(acls_as_json):
    """
    Converts the given JSON representation of ACLs into a list of ACL domain models.
    :param acls_as_json: the JSON representation of a collection of ACLs
    :return: list of equivalent domain models for the given ACLs (order not guaranteed to be the same)
    """
    return [decode_acl_as_json(acl_as_json) for acl_as_json in acls_as_json]


class ConsulACLNotFoundException(Exception):
    """
    Exception raised if an ACL with is not found.
    """


class Configuration:
    """
    Configuration for this module.
    """
    def __init__(self, management_token=None, host=None, scheme=None, validate_certs=None, name=None, port=None,
                 rules=None, state=None, token=None, token_type=None):
        self.management_token = management_token    # type: str
        self.host = host    # type: str
        self.scheme = scheme    # type: str
        self.validate_certs = validate_certs    # type: bool
        self.name = name    # type: str
        self.port = port    # type: bool
        self.rules = rules    # type: RuleCollection
        self.state = state    # type: str
        self.token = token    # type: str
        self.token_type = token_type    # type: str


class Output:
    """
    Output of an action of this module.
    """
    def __init__(self, changed=None, token=None, rules=None, operation=None):
        self.changed = changed  # type: bool
        self.token = token  # type: str
        self.rules = rules  # type: RuleCollection
        self.operation = operation  # type: str


class ACL:
    """
    Consul ACL. See: https://www.consul.io/docs/guides/acl.html.
    """
    def __init__(self, rules, token_type, token, name):
        self.rules = rules
        self.token_type = token_type
        self.token = token
        self.name = name

    def __eq__(self, other):
        return other \
            and isinstance(other, self.__class__) \
            and self.rules == other.rules \
            and self.token_type == other.token_type \
            and self.token == other.token \
            and self.name == other.name

    def __hash__(self):
        return hash(self.rules) ^ hash(self.token_type) ^ hash(self.token) ^ hash(self.name)


class Rule:
    """
    ACL rule. See: https://www.consul.io/docs/guides/acl.html#acl-rules-and-scope.
    """
    def __init__(self, scope, policy, pattern=None):
        self.scope = scope
        self.policy = policy
        self.pattern = pattern

    def __eq__(self, other):
        return isinstance(other, self.__class__) \
            and self.scope == other.scope \
            and self.policy == other.policy \
            and self.pattern == other.pattern

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return (hash(self.scope) ^ hash(self.policy)) ^ hash(self.pattern)

    def __str__(self):
        return encode_rule_as_hcl_string(self)


class RuleCollection:
    """
    Collection of ACL rules, which are part of a Consul ACL.
    """
    def __init__(self):
        self._rules = {}
        for scope in RULE_SCOPES:
            self._rules[scope] = {}

    def __iter__(self):
        all_rules = []
        for scope, pattern_keyed_rules in self._rules.items():
            for pattern, rule in pattern_keyed_rules.items():
                all_rules.append(rule)
        return iter(all_rules)

    def __len__(self):
        count = 0
        for scope in RULE_SCOPES:
            count += len(self._rules[scope])
        return count

    def __eq__(self, other):
        return isinstance(other, self.__class__) \
            and set(self) == set(other)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        return encode_rules_as_hcl_string(self)

    def add(self, rule):
        """
        Adds the given rule to this collection.
        :param rule: model of a rule
        :raises ValueError: raised if there already exists a rule for a given scope and pattern
        """
        if rule.pattern in self._rules[rule.scope]:
            patten_info = " and pattern '%s'" % rule.pattern if rule.pattern is not None else ""
            raise ValueError("Duplicate rule for scope '%s'%s" % (rule.scope, patten_info))
        self._rules[rule.scope][rule.pattern] = rule


def get_consul_client(configuration):
    """
    Gets a Consul client for the given configuration.

    Does not check if the Consul client can connect.
    :param configuration: the run configuration
    :return: Consul client
    """
    token = configuration.management_token
    if token is None:
        token = configuration.token
    if token is None:
        raise AssertionError("Expecting the management token to always be set")
    return consul.Consul(host=configuration.host, port=configuration.port, scheme=configuration.scheme,
                         verify=configuration.validate_certs, token=token)


def check_dependencies():
    """
    Checks that the required dependencies have been imported.
    :exception ImportError: if it is detected that any of the required dependencies have not been iported
    """
    if not python_consul_installed:
        raise ImportError("python-consul required for this module. "
                          "See: http://python-consul.readthedocs.org/en/latest/#installation")

    if not pyhcl_installed:
        raise ImportError("pyhcl required for this module. "
                          "See: https://pypi.python.org/pypi/pyhcl")


def main():
    """
    Main method.
    """
    module = AnsibleModule(_ARGUMENT_SPEC, supports_check_mode=False)

    try:
        check_dependencies()
    except ImportError as e:
        module.fail_json(msg=str(e))

    configuration = Configuration(
        management_token=module.params.get(MANAGEMENT_PARAMETER_NAME),
        host=module.params.get(HOST_PARAMETER_NAME),
        scheme=module.params.get(SCHEME_PARAMETER_NAME),
        validate_certs=module.params.get(VALIDATE_CERTS_PARAMETER_NAME),
        name=module.params.get(NAME_PARAMETER_NAME),
        port=module.params.get(PORT_PARAMETER_NAME),
        rules=decode_rules_as_yml(module.params.get(RULES_PARAMETER_NAME)),
        state=module.params.get(STATE_PARAMETER_NAME),
        token=module.params.get(TOKEN_PARAMETER_NAME),
        token_type=module.params.get(TOKEN_TYPE_PARAMETER_NAME)
    )
    consul_client = get_consul_client(configuration)

    try:
        if configuration.state == PRESENT_STATE_VALUE:
            output = set_acl(consul_client, configuration)
        else:
            output = remove_acl(consul_client, configuration.token)
    except ConnectionError as e:
        module.fail_json(msg='Could not connect to consul agent at %s:%s, error was %s' % (
            configuration.host, configuration.port, str(e)))
        raise

    return_values = dict(changed=output.changed, token=output.token, operation=output.operation)
    if output.rules is not None:
        return_values["rules"] = encode_rules_as_json(output.rules)
    module.exit_json(**return_values)


if __name__ == "__main__":
    main()
