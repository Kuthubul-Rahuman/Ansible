# (c) 2012, Michael DeHaan <michael.dehaan@gmail.com>
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

#############################################

import fnmatch
import os
import re
import sys

import subprocess
import ansible.constants as C
from ansible.inventory.ini import InventoryParser
from ansible.inventory.script import InventoryScript
from ansible.inventory.dir import InventoryDirectory
from ansible.inventory.group import Group
from ansible.inventory.host import Host
from ansible import errors
from ansible import utils

LOCALHOST_ALIASES = ('localhost', '127.0.0.1')

class Inventory(object):
    """
    Host inventory for ansible.
    """

    __slots__ = [ 'host_list', 'groups', '_restriction', '_also_restriction', '_subset', 
                  'parser', '_vars_per_host', '_vars_per_group', '_hosts_cache', '_groups_list',
                  '_vars_plugins', '_playbook_basedir', '_implicit_localhost']

    def __init__(self, host_list=C.DEFAULT_HOST_LIST):

        # the host file file, or script path, or list of hosts
        # if a list, inventory data will NOT be loaded
        self.host_list = host_list

        # caching to avoid repeated calculations, particularly with
        # external inventory scripts.

        self._vars_per_host  = {}
        self._vars_per_group = {}
        self._hosts_cache    = {}
        self._groups_list    = {} 

        # to be set by calling set_playbook_basedir by ansible-playbook
        self._playbook_basedir = None

        # the inventory object holds a list of groups
        self.groups = []

        # a list of host(names) to contain current inquiries to
        self._restriction = None
        self._also_restriction = None
        self._subset = None

        # to avoid having localhost explicitly in inventory (see #3129)
        self._implicit_localhost = None

        if isinstance(host_list, basestring):
            if "," in host_list:
                host_list = host_list.split(",")
                host_list = [ h for h in host_list if h and h.strip() ]

        if isinstance(host_list, list):
            self.parser = None
            all = Group('all')
            self.groups = [ all ]
            ipv6_re = re.compile('\[([a-f:A-F0-9]*[%[0-z]+]?)\](?::(\d+))?')
            for x in host_list:
                m = ipv6_re.match(x)
                if m:
                    all.add_host(Host(m.groups()[0], m.groups()[1]))
                else:
                    if ":" in x:
                        tokens = x.rsplit(":", 1)
                        # if there is ':' in the address, then this is a ipv6
                        if ':' in tokens[0]:
                            all.add_host(Host(x))
                        else:
                            all.add_host(Host(tokens[0], tokens[1]))
                    else:
                        all.add_host(Host(x))
        elif os.path.exists(host_list):
            if os.path.isdir(host_list):
                # Ensure basedir is inside the directory
                self.host_list = os.path.join(self.host_list, "")
                self.parser = InventoryDirectory(filename=host_list)
                self.groups = self.parser.groups.values()
            elif utils.is_executable(host_list):
                self.parser = InventoryScript(filename=host_list)
                self.groups = self.parser.groups.values()
            else:
                self.parser = InventoryParser(filename=host_list)
                self.groups = self.parser.groups.values()

            utils.plugins.vars_loader.add_directory(self.basedir(), with_subdir=True)
        else:
            raise errors.AnsibleError("Unable to find an inventory file, specify one with -i ?")

        self._vars_plugins = [ x for x in utils.plugins.vars_loader.all(self) ]


    def _match(self, strs, pattern_str):
        if pattern_str.startswith('~'):
            return any(re.search(pattern_str[1:], str) for str in strs)
        else:
            return any(fnmatch.fnmatch(str, pattern_str) for str in strs)

    def get_hosts(self, pattern='all', full=False):
        """ 
        find all host names matching a pattern string, taking into account any inventory restrictions or
        applied subsets.
        """

        # process patterns
        if isinstance(pattern, list):
            pattern = ';'.join(pattern)
        patterns = pattern.replace(";",":").split(":")
        hosts = self._get_hosts(patterns, full)

        # exclude hosts not in a subset, if defined
        if self._subset:
            subset = self._get_hosts(self._subset, full)
            hosts.intersection_update(subset)

        # exclude hosts mentioned in any restriction (ex: failed hosts)
        if self._restriction is not None:
            hosts = [ h for h in hosts if h.name in self._restriction ]
        if self._also_restriction is not None:
            hosts = [ h for h in hosts if h.name in self._also_restriction ]

        return sorted(hosts, key=lambda x: x.name)

    def _get_hosts(self, patterns, full=False):
        """
        finds hosts that match a list of patterns. Handles negative
        matches as well as intersection matches.
        """

        # Host specifiers should be sorted to ensure consistent behavior
        pattern_regular = []
        pattern_intersection = []
        pattern_exclude = []
        for p in patterns:
            if p.startswith("!"):
                pattern_exclude.append(p)
            elif p.startswith("&"):
                pattern_intersection.append(p)
            else:
                pattern_regular.append(p)

        # if no regular pattern was given, hence only exclude and/or intersection
        # make that magically work
        if pattern_regular == []:
            pattern_regular = ['all']

        # when applying the host selectors, run those without the "&" or "!"
        # first, then the &s, then the !s.
        patterns = pattern_regular + pattern_intersection + pattern_exclude

        hosts = set()
        for p in patterns:
            if p.startswith("!"):
                # Discard excluded hosts
                hosts.difference_update(self.__get_hosts(p, full))
            elif p.startswith("&"):
                # Only leave the intersected hosts
                hosts.intersection_update(self.__get_hosts(p, full))
            else:
                # Get all hosts from both patterns
                hosts.update(self.__get_hosts(p, full))
        return hosts

    def __get_hosts(self, pattern, full=False):
        """ 
        finds hosts that postively match a particular pattern.  Does not
        take into account negative matches.
        """

        (name, enumeration_details) = self._enumeration_info(pattern)
        hpat = self._hosts_in_unenumerated_pattern(name, full)
        hpat = sorted(hpat, key=lambda x: x.name)

        return set(self._apply_ranges(pattern, hpat))

    def _enumeration_info(self, pattern):
        """
        returns (pattern, limits) taking a regular pattern and finding out
        which parts of it correspond to start/stop offsets.  limits is
        a tuple of (start, stop) or None
        """

        if not "[" in pattern or pattern.startswith('~'):
            return (pattern, None)
        (first, rest) = pattern.split("[")
        rest = rest.replace("]","")
        if "-" in rest:
            (left, right) = rest.split("-",1)
            return (first, (left, right))
        else:
            return (first, (rest, rest))

    def _apply_ranges(self, pat, hosts):
        """
        given a pattern like foo, that matches hosts, return all of hosts
        given a pattern like foo[0:5], where foo matches hosts, return the first 6 hosts
        """ 

        (loose_pattern, limits) = self._enumeration_info(pat)
        if not limits:
            return hosts

        (left, right) = limits
        enumerated = enumerate(hosts)
        if left == '':
            left = 0
        if right == '':
            right = 0
        left=int(left)
        right=int(right)
        enumerated = [ h for (i,h) in enumerated if i>=left and i<=right ]
        return enumerated

    def implicit_localhost(self):
        if self._implicit_localhost is None:
            self._implicit_localhost = Host(name='localhost')
            self._implicit_localhost.set_variable('ansible_connection', 'local')
            self._implicit_localhost.set_variable('ansible_python_interpreter', sys.executable)
        return self._implicit_localhost

    def _host_match(self, host_name, pattern):
        if host_name in LOCALHOST_ALIASES:
            return self._match(LOCALHOST_ALIASES, pattern)
        else:
            return self._match([host_name], pattern)

    # TODO: cache this logic so if called a second time the result is not recalculated
    def _hosts_in_unenumerated_pattern(self, pattern, full=False):
        """ Get all host names matching the pattern """

        hosts = {}
        # ignore any negative checks here, this is handled elsewhere
        pattern = pattern.replace("!","").replace("&", "")

        groups = self.get_groups()
        for group in groups:
            for host in group.get_hosts():
                if pattern == 'all' or self._host_match(group.name, pattern) or self._host_match(host.name, pattern):
                    hosts[host.name] = host

        if pattern in LOCALHOST_ALIASES and not hosts:
            hosts['localhost'] = self.implicit_localhost()
        elif pattern == 'all' and full and 'localhost' not in hosts:
            hosts['localhost'] = self.implicit_localhost()

        return sorted(hosts.values(), key=lambda x: x.name)

    def groups_for_host(self, host):
        results = []
        groups = self.get_groups()
        for group in groups:
            for hostn in group.get_hosts():
                if host == hostn.name:
                    results.append(group)
                    continue
        return results

    def groups_list(self):
        if not self._groups_list:
            groups = {}
            for g in self.groups:
                groups[g.name] = [h.name for h in g.get_hosts()]
                ancestors = g.get_ancestors()
                for a in ancestors:
                    if a.name not in groups:
                        groups[a.name] = [h.name for h in a.get_hosts()]
            self._groups_list = groups
        return self._groups_list

    def get_groups(self):
        return self.groups

    def get_host(self, hostname):
        if hostname not in self._hosts_cache:
            self._hosts_cache[hostname] = self._get_host(hostname)
        return self._hosts_cache[hostname]

    def _get_host(self, hostname):
        if hostname in LOCALHOST_ALIASES:
            return self.__get_host(LOCALHOST_ALIASES) or self.implicit_localhost()
        else:
            return self.__get_host([hostname])

    def __get_host(self, hostnames):
        for group in self.groups:
            for host in group.get_hosts():
                if host.name in hostnames:
                    return host

    def get_group(self, groupname):
        for group in self.groups:
            if group.name == groupname:
                return group
        return None

    def get_group_variables(self, groupname):
        if groupname not in self._vars_per_group:
            self._vars_per_group[groupname] = self._get_group_variables(groupname)
        return self._vars_per_group[groupname]

    def _get_group_variables(self, groupname):
        group = self.get_group(groupname)
        if group is None:
            raise Exception("group not found: %s" % groupname)
        return group.get_variables()

    def get_variables(self, hostname):
        if hostname not in self._vars_per_host:
            self._vars_per_host[hostname] = self._get_variables(hostname)
        return self._vars_per_host[hostname]

    def _get_variables(self, hostname):

        host = self.get_host(hostname)
        if host is None:
            raise errors.AnsibleError("host not found: %s" % hostname)

        vars = {}
        vars_results = [ plugin.run(host) for plugin in self._vars_plugins ] 
        for updated in vars_results:
            if updated is not None:
                vars.update(updated)

        vars.update(host.get_variables())
        if self.parser is not None:
            vars.update(self.parser.get_host_variables(host))
        return vars

    def add_group(self, group):
        self.groups.append(group)
        self._groups_list = None  # invalidate internal cache 

    def list_hosts(self, pattern='all', full=False):
        return [ h.name for h in self.get_hosts(pattern, full) ]

    def list_groups(self):
        return sorted([ g.name for g in self.groups ], key=lambda x: x)

    # TODO: remove this function
    def get_restriction(self):
        return self._restriction

    def restrict_to(self, restriction):
        """ 
        Restrict list operations to the hosts given in restriction.  This is used
        to exclude failed hosts in main playbook code, don't use this for other
        reasons.
        """
        if not isinstance(restriction, list):
            restriction = [ restriction ]
        self._restriction = restriction

    def also_restrict_to(self, restriction):
        """
        Works like restict_to but offers an additional restriction.  Playbooks use this
        to implement serial behavior.
        """
        if not isinstance(restriction, list):
            restriction = [ restriction ]
        self._also_restriction = restriction
    
    def subset(self, subset_pattern):
        """ 
        Limits inventory results to a subset of inventory that matches a given
        pattern, such as to select a given geographic of numeric slice amongst
        a previous 'hosts' selection that only select roles, or vice versa.  
        Corresponds to --limit parameter to ansible-playbook
        """        
        if subset_pattern is None:
            self._subset = None
        else:
            subset_pattern = subset_pattern.replace(',',':')
            subset_pattern = subset_pattern.replace(";",":").split(":")
            results = []
            # allow Unix style @filename data
            for x in subset_pattern:
                if x.startswith("@"):
                    fd = open(x[1:])
                    results.extend(fd.read().split("\n"))
                    fd.close()
                else:
                    results.append(x)
            self._subset = results

    def lift_restriction(self):
        """ Do not restrict list operations """
        self._restriction = None
    
    def lift_also_restriction(self):
        """ Clears the also restriction """
        self._also_restriction = None

    def is_file(self):
        """ did inventory come from a file? """
        if not isinstance(self.host_list, basestring):
            return False
        return os.path.exists(self.host_list)

    def basedir(self):
        """ if inventory came from a file, what's the directory? """
        if not self.is_file():
            return None
        dname = os.path.dirname(self.host_list)
        if dname is None or dname == '' or dname == '.':
            cwd = os.getcwd()
            return cwd 
        return dname

    def src(self):
        """ if inventory came from a file, what's the directory and file name? """
        if not self.is_file():
            return None
        return self.host_list

    def playbook_basedir(self):
        """ returns the directory of the current playbook """
        return self._playbook_basedir

    def set_playbook_basedir(self, dir):
        """ 
        sets the base directory of the playbook so inventory plugins can use it to find
        variable files and other things. 
        """
        self._playbook_basedir = dir


