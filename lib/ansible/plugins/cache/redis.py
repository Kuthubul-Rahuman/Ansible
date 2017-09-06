# (c) 2014, Brian Coca, Josh Drake, et al
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
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import time
import json

from ansible import constants as C
from ansible.errors import AnsibleError
from ansible.plugins.cache import BaseCacheModule

try:
    from redis import StrictRedis
except ImportError:
    raise AnsibleError("The 'redis' python module is required for the redis fact cache, 'pip install redis'")


class CacheModule(BaseCacheModule):
    """
    A caching module backed by redis.

    Keys are maintained in a zset with their score being the timestamp
    when they are inserted. This allows for the usage of 'zremrangebyscore'
    to expire keys. This mechanism is used or a pattern matched 'scan' for
    performance.
    """
    def __init__(self, *args, **kwargs):
        if C.CACHE_PLUGIN_CONNECTION:
            connection = C.CACHE_PLUGIN_CONNECTION.split(':')
        else:
            connection = []

        self._timeout = float(C.CACHE_PLUGIN_TIMEOUT)
        self._prefix = C.CACHE_PLUGIN_PREFIX
        self._cache = {}
        self._db= StrictRedis(*connection)
        self._keys_set = 'ansible_cache_keys'

    def _make_key(self, key):
        return self._prefix + key

    def get(self, key):

        if not key in self._cache:
            value = self._db.get(self._make_key(key))
            # guard against the key not being removed from the zset;
            # this could happen in cases where the timeout value is changed
            # between invocations
            if value is None:
                self.delete(key)
                raise KeyError
            self._cache[key] = json.loads(value)

        return self._cache.get(key)

    def set(self, key, value):

        value2 = json.dumps(value)
        if self._timeout > 0:  # a timeout of 0 is handled as meaning 'never expire'
            self._db.setex(self._make_key(key), int(self._timeout), value2)
        else:
            self._db.set(self._make_key(key), value2)

        self._db.zadd(self._keys_set, time.time(), key)
        self._cache[key] = value

    def _expire_keys(self):
        if self._timeout > 0:
            expiry_age = time.time() - self._timeout
            self._db.zremrangebyscore(self._keys_set, 0, expiry_age)

    def keys(self):
        self._expire_keys()
        return self._db.zrange(self._keys_set, 0, -1)

    def contains(self, key):
        self._expire_keys()
        return (self._db.zrank(self._keys_set, key) is not None)

    def delete(self, key):
        del self.cache[key]
        self._db.delete(self._make_key(key))
        self._db.zrem(self._keys_set, key)

    def flush(self):
        for key in self.keys():
            self.delete(key)

    def copy(self):
        # TODO: there is probably a better way to do this in redis
        ret = dict()
        for key in self.keys():
            ret[key] = self.get(key)
        return ret

    def __getstate__(self):
        return dict()

    def __setstate__(self, data):
        self.__init__()
