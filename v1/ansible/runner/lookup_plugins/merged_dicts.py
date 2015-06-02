# (c) 2015, Rumen Telbizov <telbizov@gmail.com>
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

from ansible.utils import safe_eval
import ansible.utils as utils
import ansible.errors as errors

def flatten_hashes_to_list(terms):
    ret = []
    merged = {}
    
    for cur_dict in terms:
        if not isinstance(cur_dict, dict):
            raise errors.AnsibleError("with_merged_dicts expects a list of dictionaries")
        merged.update(cur_dict)

    for key in merged:
        ret.append({'key': key, 'value': merged[key]})
    
    return ret

class LookupModule(object):

    def __init__(self, basedir=None, **kwargs):
        self.basedir = basedir

    def run(self, terms, inject=None, **kwargs):
        terms = utils.listify_lookup_plugin_terms(terms, self.basedir, inject)

        if not isinstance(terms, list):
            raise errors.AnsibleError("with_merged_dicts expects a list of dictionaries")

        return flatten_hashes_to_list(terms)
