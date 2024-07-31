# -*- coding: utf-8 -*-
# Copyright: (c) 2018, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

import pytest
import random
import string
import sys
import unittest

from ansible import constants as C
from ansible.cli.arguments import option_helpers as opt_help
from ansible import __path__ as ansible_path
from ansible.release import __version__ as ansible_version

cpath = C.DEFAULT_MODULE_PATH

FAKE_PROG = u'ansible-cli-test'
VERSION_OUTPUT = opt_help.version(prog=FAKE_PROG)


@pytest.mark.parametrize(
    'must_have', [
        FAKE_PROG + u' [core %s]' % ansible_version,
        u'config file = %s' % C.CONFIG_FILE,
        u'configured module search path = %s' % cpath,
        u'ansible python module location = %s' % ':'.join(ansible_path),
        u'ansible collection location = %s' % ':'.join(C.COLLECTIONS_PATHS),
        u'executable location = ',
        u'python version = %s' % ''.join(sys.version.splitlines()),
    ]
)
def test_option_helper_version(must_have):
    assert must_have in VERSION_OUTPUT


class TestHelperFunctions(unittest.TestCase):

    def setUp(self):

        self.good_strings = ['no bad chars', '-', 'らとみ', 'café']
        source = string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation
        while len(self.good_strings) < 10:
            rand = ''.join(random.choices(source, k=random.randrange(1,32)))
            if 'F' in rand or ';' in rand:
               continue  # we only want 'GOOD' strings
            self.good_strings.append(rand)

        self.bad_strings = [True, 'I have F', 'i ;', 'both ; and F', None, 'らとみ with F', ';café;']

    def test_str_sans_forbidden_characters_detection(self):

        @opt_help.str_sans_forbidden_characters('F', ';')
        def iusestring(string):
            return string

        for good in self.good_strings:
            self.assertEqual(iusestring(good), good)

        for bad in self.bad_strings:
            self.assertRaises(ValueError, iusestring(bad))

    def test_str_sans_forbidden_characters_input(self):

        @opt_help.str_sans_forbidden_characters(None)
        def iusestring(string):
            return string

        for anystring in self.good_strings + self.bad_strings:
            self.assertRaises(TypeError, iusestring(anystring))
