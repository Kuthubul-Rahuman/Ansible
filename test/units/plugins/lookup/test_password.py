# -*- coding: utf-8 -*-
# (c) 2015, Toshio Kuratomi <tkuratomi@ansible.com>
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

try:
    import passlib
    from passlib.handlers import pbkdf2
except ImportError:  # pragma: nocover
    passlib = None
    pbkdf2 = None

import pytest

from units.mock.loader import DictDataLoader

import unittest
from unittest.mock import mock_open, patch
from ansible.errors import AnsibleError
import builtins
from ansible.module_utils.common.text.converters import to_bytes
from ansible.plugins.loader import PluginLoader, lookup_loader
from ansible.plugins.lookup import password


DEFAULT_LENGTH = 20
DEFAULT_CHARS = sorted([u'ascii_letters', u'digits', u".,:-_"])
DEFAULT_CANDIDATE_CHARS = u'.,:-_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'

# Currently there isn't a new-style
old_style_params_data = (
    # Simple case
    dict(
        term=u'/path/to/file',
        filename=u'/path/to/file',
        params=dict(length=DEFAULT_LENGTH, encrypt=None, ident=None, chars=DEFAULT_CHARS, seed=None),
        candidate_chars=DEFAULT_CANDIDATE_CHARS,
    ),

    # Special characters in path
    dict(
        term=u'/path/with/embedded spaces and/file',
        filename=u'/path/with/embedded spaces and/file',
        params=dict(length=DEFAULT_LENGTH, encrypt=None, ident=None, chars=DEFAULT_CHARS, seed=None),
        candidate_chars=DEFAULT_CANDIDATE_CHARS,
    ),
    dict(
        term=u'/path/with/equals/cn=com.ansible',
        filename=u'/path/with/equals/cn=com.ansible',
        params=dict(length=DEFAULT_LENGTH, encrypt=None, ident=None, chars=DEFAULT_CHARS, seed=None),
        candidate_chars=DEFAULT_CANDIDATE_CHARS,
    ),
    dict(
        term=u'/path/with/unicode/くらとみ/file',
        filename=u'/path/with/unicode/くらとみ/file',
        params=dict(length=DEFAULT_LENGTH, encrypt=None, ident=None, chars=DEFAULT_CHARS, seed=None),
        candidate_chars=DEFAULT_CANDIDATE_CHARS,
    ),

    # Mix several special chars
    dict(
        term=u'/path/with/utf 8 and spaces/くらとみ/file',
        filename=u'/path/with/utf 8 and spaces/くらとみ/file',
        params=dict(length=DEFAULT_LENGTH, encrypt=None, ident=None, chars=DEFAULT_CHARS, seed=None),
        candidate_chars=DEFAULT_CANDIDATE_CHARS,
    ),
    dict(
        term=u'/path/with/encoding=unicode/くらとみ/file',
        filename=u'/path/with/encoding=unicode/くらとみ/file',
        params=dict(length=DEFAULT_LENGTH, encrypt=None, ident=None, chars=DEFAULT_CHARS, seed=None),
        candidate_chars=DEFAULT_CANDIDATE_CHARS,
    ),
    dict(
        term=u'/path/with/encoding=unicode/くらとみ/and spaces file',
        filename=u'/path/with/encoding=unicode/くらとみ/and spaces file',
        params=dict(length=DEFAULT_LENGTH, encrypt=None, ident=None, chars=DEFAULT_CHARS, seed=None),
        candidate_chars=DEFAULT_CANDIDATE_CHARS,
    ),

    # Simple parameters
    dict(
        term=u'/path/to/file length=42',
        filename=u'/path/to/file',
        params=dict(length=42, encrypt=None, ident=None, chars=DEFAULT_CHARS, seed=None),
        candidate_chars=DEFAULT_CANDIDATE_CHARS,
    ),
    dict(
        term=u'/path/to/file encrypt=pbkdf2_sha256',
        filename=u'/path/to/file',
        params=dict(length=DEFAULT_LENGTH, encrypt='pbkdf2_sha256', ident=None, chars=DEFAULT_CHARS, seed=None),
        candidate_chars=DEFAULT_CANDIDATE_CHARS,
    ),
    dict(
        term=u'/path/to/file chars=abcdefghijklmnop',
        filename=u'/path/to/file',
        params=dict(length=DEFAULT_LENGTH, encrypt=None, ident=None, chars=[u'abcdefghijklmnop'], seed=None),
        candidate_chars=u'abcdefghijklmnop',
    ),
    dict(
        term=u'/path/to/file chars=digits,abc,def',
        filename=u'/path/to/file',
        params=dict(length=DEFAULT_LENGTH, encrypt=None, ident=None,
                    chars=sorted([u'digits', u'abc', u'def']), seed=None),
        candidate_chars=u'abcdef0123456789',
    ),
    dict(
        term=u'/path/to/file seed=1',
        filename=u'/path/to/file',
        params=dict(length=DEFAULT_LENGTH, encrypt=None, ident=None, chars=DEFAULT_CHARS, seed='1'),
        candidate_chars=DEFAULT_CANDIDATE_CHARS,
    ),

    # Including comma in chars
    dict(
        term=u'/path/to/file chars=abcdefghijklmnop,,digits',
        filename=u'/path/to/file',
        params=dict(length=DEFAULT_LENGTH, encrypt=None, ident=None,
                    chars=sorted([u'abcdefghijklmnop', u',', u'digits']), seed=None),
        candidate_chars=u',abcdefghijklmnop0123456789',
    ),
    dict(
        term=u'/path/to/file chars=,,',
        filename=u'/path/to/file',
        params=dict(length=DEFAULT_LENGTH, encrypt=None, ident=None,
                    chars=[u','], seed=None),
        candidate_chars=u',',
    ),

    # Including = in chars
    dict(
        term=u'/path/to/file chars=digits,=,,',
        filename=u'/path/to/file',
        params=dict(length=DEFAULT_LENGTH, encrypt=None, ident=None,
                    chars=sorted([u'digits', u'=', u',']), seed=None),
        candidate_chars=u',=0123456789',
    ),
    dict(
        term=u'/path/to/file chars=digits,abc=def',
        filename=u'/path/to/file',
        params=dict(length=DEFAULT_LENGTH, encrypt=None, ident=None,
                    chars=sorted([u'digits', u'abc=def']), seed=None),
        candidate_chars=u'abc=def0123456789',
    ),

    # Including unicode in chars
    dict(
        term=u'/path/to/file chars=digits,くらとみ,,',
        filename=u'/path/to/file',
        params=dict(length=DEFAULT_LENGTH, encrypt=None, ident=None,
                    chars=sorted([u'digits', u'くらとみ', u',']), seed=None),
        candidate_chars=u',0123456789くらとみ',
    ),
    # Including only unicode in chars
    dict(
        term=u'/path/to/file chars=くらとみ',
        filename=u'/path/to/file',
        params=dict(length=DEFAULT_LENGTH, encrypt=None, ident=None,
                    chars=sorted([u'くらとみ']), seed=None),
        candidate_chars=u'くらとみ',
    ),

    # Include ':' in path
    dict(
        term=u'/path/to/file_with:colon chars=ascii_letters,digits',
        filename=u'/path/to/file_with:colon',
        params=dict(length=DEFAULT_LENGTH, encrypt=None, ident=None,
                    chars=sorted([u'ascii_letters', u'digits']), seed=None),
        candidate_chars=u'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
    ),

    # Including special chars in both path and chars
    # Special characters in path
    dict(
        term=u'/path/with/embedded spaces and/file chars=abc=def',
        filename=u'/path/with/embedded spaces and/file',
        params=dict(length=DEFAULT_LENGTH, encrypt=None, ident=None, chars=[u'abc=def'], seed=None),
        candidate_chars=u'abc=def',
    ),
    dict(
        term=u'/path/with/equals/cn=com.ansible chars=abc=def',
        filename=u'/path/with/equals/cn=com.ansible',
        params=dict(length=DEFAULT_LENGTH, encrypt=None, ident=None, chars=[u'abc=def'], seed=None),
        candidate_chars=u'abc=def',
    ),
    dict(
        term=u'/path/with/unicode/くらとみ/file chars=くらとみ',
        filename=u'/path/with/unicode/くらとみ/file',
        params=dict(length=DEFAULT_LENGTH, encrypt=None, ident=None, chars=[u'くらとみ'], seed=None),
        candidate_chars=u'くらとみ',
    ),
)


class TestParseParameters(unittest.TestCase):

    def setUp(self):
        self.fake_loader = DictDataLoader({'/path/to/somewhere': 'sdfsdf'})
        self.password_lookup = lookup_loader.get('password')
        self.password_lookup._loader = self.fake_loader

    def test(self):
        for testcase in old_style_params_data:
            filename, params = self.password_lookup._parse_parameters(testcase['term'])
            params['chars'].sort()
            self.assertEqual(filename, testcase['filename'])
            self.assertEqual(params, testcase['params'])

    def test_unrecognized_value(self):
        testcase = dict(term=u'/path/to/file chars=くらとみi  sdfsdf',
                        filename=u'/path/to/file',
                        params=dict(length=DEFAULT_LENGTH, encrypt=None, chars=[u'くらとみ']),
                        candidate_chars=u'くらとみ')
        self.assertRaises(AnsibleError, self.password_lookup._parse_parameters, testcase['term'])

    def test_invalid_params(self):
        testcase = dict(term=u'/path/to/file chars=くらとみi  somethign_invalid=123',
                        filename=u'/path/to/file',
                        params=dict(length=DEFAULT_LENGTH, encrypt=None, chars=[u'くらとみ']),
                        candidate_chars=u'くらとみ')
        self.assertRaises(AnsibleError, self.password_lookup._parse_parameters, testcase['term'])


class TestReadPasswordFile(unittest.TestCase):
    def setUp(self):
        self.os_path_exists = password.os.path.exists

    def tearDown(self):
        password.os.path.exists = self.os_path_exists

    def test_no_password_file(self):
        password.os.path.exists = lambda x: False
        self.assertEqual(password._read_password_file(b'/nonexistent'), None)

    def test_with_password_file(self):
        password.os.path.exists = lambda x: True
        with patch.object(builtins, 'open', mock_open(read_data=b'Testing\n')) as m:
            self.assertEqual(password._read_password_file(b'/etc/motd'), u'Testing')


class TestGenCandidateChars(unittest.TestCase):
    def _assert_gen_candidate_chars(self, testcase):
        expected_candidate_chars = testcase['candidate_chars']
        params = testcase['params']
        chars_spec = params['chars']
        res = password._gen_candidate_chars(chars_spec)
        self.assertEqual(res, expected_candidate_chars)

    def test_gen_candidate_chars(self):
        for testcase in old_style_params_data:
            self._assert_gen_candidate_chars(testcase)


class TestRandomPassword(unittest.TestCase):
    def _assert_valid_chars(self, res, chars):
        for res_char in res:
            self.assertIn(res_char, chars)

    def test_default(self):
        res = password.random_password()
        self.assertEqual(len(res), DEFAULT_LENGTH)
        self.assertTrue(isinstance(res, str))
        self._assert_valid_chars(res, DEFAULT_CANDIDATE_CHARS)

    def test_zero_length(self):
        res = password.random_password(length=0)
        self.assertEqual(len(res), 0)
        self.assertTrue(isinstance(res, str))
        self._assert_valid_chars(res, u',')

    def test_just_a_common(self):
        res = password.random_password(length=1, chars=u',')
        self.assertEqual(len(res), 1)
        self.assertEqual(res, u',')

    def test_free_will(self):
        # A Rush and Spinal Tap reference twofer
        res = password.random_password(length=11, chars=u'a')
        self.assertEqual(len(res), 11)
        self.assertEqual(res, 'aaaaaaaaaaa')
        self._assert_valid_chars(res, u'a')

    def test_unicode(self):
        res = password.random_password(length=11, chars=u'くらとみ')
        self._assert_valid_chars(res, u'くらとみ')
        self.assertEqual(len(res), 11)

    def test_seed(self):
        pw1 = password.random_password(seed=1)
        pw2 = password.random_password(seed=1)
        pw3 = password.random_password(seed=2)
        self.assertEqual(pw1, pw2)
        self.assertNotEqual(pw1, pw3)

    def test_gen_password(self):
        for testcase in old_style_params_data:
            params = testcase['params']
            candidate_chars = testcase['candidate_chars']
            params_chars_spec = password._gen_candidate_chars(params['chars'])
            password_string = password.random_password(length=params['length'],
                                                       chars=params_chars_spec)
            self.assertEqual(len(password_string),
                             params['length'],
                             msg='generated password=%s has length (%s) instead of expected length (%s)' %
                             (password_string, len(password_string), params['length']))

            for char in password_string:
                self.assertIn(char, candidate_chars,
                              msg='%s not found in %s from chars spect %s' %
                              (char, candidate_chars, params['chars']))


class TestParseContent(unittest.TestCase):

    def test_empty_password_file(self):
        plaintext_password, salt, ident = password._parse_content(u'')
        self.assertEqual(plaintext_password, u'')
        self.assertEqual(salt, None)
        self.assertEqual(ident, None)

    def test(self):
        expected_content = u'12345678'
        file_content = expected_content
        plaintext_password, salt, ident = password._parse_content(file_content)
        self.assertEqual(plaintext_password, expected_content)
        self.assertEqual(salt, None)
        self.assertEqual(ident, None)

    def test_with_salt(self):
        expected_content = u'12345678 salt=87654321'
        file_content = expected_content
        plaintext_password, salt, ident = password._parse_content(file_content)
        self.assertEqual(plaintext_password, u'12345678')
        self.assertEqual(salt, u'87654321')
        self.assertEqual(ident, None)

    def test_with_salt_and_ident(self):
        expected_content = u'12345678 salt=87654321 ident=2a'
        file_content = expected_content
        plaintext_password, salt, ident = password._parse_content(file_content)
        self.assertEqual(plaintext_password, u'12345678')
        self.assertEqual(salt, u'87654321')
        self.assertEqual(ident, u'2a')


class TestFormatContent(unittest.TestCase):
    def test_no_encrypt(self):
        self.assertEqual(
            password._format_content(password=u'hunter42',
                                     salt=u'87654321',
                                     encrypt=False),
            u'hunter42 salt=87654321')

    def test_no_encrypt_no_salt(self):
        self.assertEqual(
            password._format_content(password=u'hunter42',
                                     salt=None,
                                     encrypt=None),
            u'hunter42')

    def test_encrypt(self):
        self.assertEqual(
            password._format_content(password=u'hunter42',
                                     salt=u'87654321',
                                     encrypt='pbkdf2_sha256'),
            u'hunter42 salt=87654321')

    def test_encrypt_no_salt(self):
        self.assertRaises(AssertionError, password._format_content, u'hunter42', None, 'pbkdf2_sha256')


class TestWritePasswordFile(unittest.TestCase):
    def setUp(self):
        self.makedirs_safe = password.os.makedirs
        self.os_chmod = password.os.chmod
        password.os.makedirs = lambda path, mode: None
        password.os.chmod = lambda path, mode: None

    def tearDown(self):
        password.os.makedirs = self.makedirs_safe
        password.os.chmod = self.os_chmod

    def test_content_written(self):

        with patch.object(builtins, 'open', mock_open()) as m:
            password._write_password_file(b'/this/is/a/test/caf\xc3\xa9', u'Testing Café')

            m.assert_called_once_with(b'/this/is/a/test/caf\xc3\xa9', 'wb')
            m().write.assert_called_once_with(u'Testing Café\n'.encode('utf-8'))


class BaseTestLookupModule(unittest.TestCase):
    def setUp(self):
        self.fake_loader = DictDataLoader({'/path/to/somewhere': 'sdfsdf'})
        self.password_lookup = lookup_loader.get('password')
        self.password_lookup._loader = self.fake_loader
        self.os_path_exists = password.os.path.exists
        self.os_open = password.os.open
        password.os.open = lambda path, flag: None
        self.os_close = password.os.close
        password.os.close = lambda fd: None
        self.makedirs_safe = password.makedirs_safe
        password.makedirs_safe = lambda path, mode: None
        self.os_remove = password.os.remove
        password.os.remove = lambda path: None

    def tearDown(self):
        password.os.path.exists = self.os_path_exists
        password.os.open = self.os_open
        password.os.close = self.os_close
        password.makedirs_safe = self.makedirs_safe
        password.os.remove = self.os_remove


class TestLookupModuleWithoutPasslib(BaseTestLookupModule):
    @patch.object(PluginLoader, '_get_paths')
    @patch('ansible.plugins.lookup.password._write_password_file')
    def test_no_encrypt(self, mock_get_paths, mock_write_file):
        mock_get_paths.return_value = ['/path/one', '/path/two', '/path/three']

        results = self.password_lookup.run([u'/path/to/somewhere'], None)

        # FIXME: assert something useful
        for result in results:
            assert len(result) == DEFAULT_LENGTH
            assert isinstance(result, str)

    @patch.object(PluginLoader, '_get_paths')
    @patch('ansible.plugins.lookup.password._write_password_file')
    def test_password_already_created_no_encrypt(self, mock_get_paths, mock_write_file):
        mock_get_paths.return_value = ['/path/one', '/path/two', '/path/three']
        password.os.path.exists = lambda x: x == to_bytes('/path/to/somewhere')

        with patch.object(builtins, 'open', mock_open(read_data=b'hunter42 salt=87654321\n')) as m:
            results = self.password_lookup.run([u'/path/to/somewhere chars=anything'], None)

        for result in results:
            self.assertEqual(result, u'hunter42')

    @patch.object(PluginLoader, '_get_paths')
    @patch('ansible.plugins.lookup.password._write_password_file')
    def test_only_a(self, mock_get_paths, mock_write_file):
        mock_get_paths.return_value = ['/path/one', '/path/two', '/path/three']

        results = self.password_lookup.run([u'/path/to/somewhere chars=a'], None)
        for result in results:
            self.assertEqual(result, u'a' * DEFAULT_LENGTH)

    @patch('time.sleep')
    def test_lock_been_held(self, mock_sleep):
        # pretend the lock file is here
        password.os.path.exists = lambda x: True
        with pytest.raises(AnsibleError):
            with patch.object(builtins, 'open', mock_open(read_data=b'hunter42 salt=87654321\n')) as m:
                # should timeout here
                self.password_lookup.run([u'/path/to/somewhere chars=anything'], None)

    def test_lock_not_been_held(self):
        # pretend now there is password file but no lock
        password.os.path.exists = lambda x: x == to_bytes('/path/to/somewhere')
        with patch.object(builtins, 'open', mock_open(read_data=b'hunter42 salt=87654321\n')) as m:
            # should not timeout here
            results = self.password_lookup.run([u'/path/to/somewhere chars=anything'], None)

        for result in results:
            self.assertEqual(result, u'hunter42')


@pytest.mark.skipif(passlib is None, reason='passlib must be installed to run these tests')
class TestLookupModuleWithPasslib(BaseTestLookupModule):
    def setUp(self):
        super(TestLookupModuleWithPasslib, self).setUp()

        # Different releases of passlib default to a different number of rounds
        self.sha256 = passlib.registry.get_crypt_handler('pbkdf2_sha256')
        sha256_for_tests = pbkdf2.create_pbkdf2_hash("sha256", 32, 20000)
        passlib.registry.register_crypt_handler(sha256_for_tests, force=True)

    def tearDown(self):
        super(TestLookupModuleWithPasslib, self).tearDown()

        passlib.registry.register_crypt_handler(self.sha256, force=True)

    @patch.object(PluginLoader, '_get_paths')
    @patch('ansible.plugins.lookup.password._write_password_file')
    def test_encrypt(self, mock_get_paths, mock_write_file):
        mock_get_paths.return_value = ['/path/one', '/path/two', '/path/three']

        results = self.password_lookup.run([u'/path/to/somewhere encrypt=pbkdf2_sha256'], None)

        # pbkdf2 format plus hash
        expected_password_length = 76

        for result in results:
            self.assertEqual(len(result), expected_password_length)
            # result should have 5 parts split by '$'
            str_parts = result.split('$', 5)

            # verify the result is parseable by the passlib
            crypt_parts = passlib.hash.pbkdf2_sha256.parsehash(result)

            # verify it used the right algo type
            self.assertEqual(str_parts[1], 'pbkdf2-sha256')

            self.assertEqual(len(str_parts), 5)

            # verify the string and parsehash agree on the number of rounds
            self.assertEqual(int(str_parts[2]), crypt_parts['rounds'])
            self.assertIsInstance(result, str)

    @patch('ansible.plugins.lookup.password._write_password_file')
    def test_password_already_created_encrypt(self, mock_write_file):
        password.os.path.exists = lambda x: x == to_bytes('/path/to/somewhere')

        with patch.object(builtins, 'open', mock_open(read_data=b'hunter42 salt=87654321\n')) as m:
            results = self.password_lookup.run([u'/path/to/somewhere chars=anything encrypt=pbkdf2_sha256'], None)
        for result in results:
            self.assertEqual(result, u'$pbkdf2-sha256$20000$ODc2NTQzMjE$Uikde0cv0BKaRaAXMrUQB.zvG4GmnjClwjghwIRf2gU')

        # Assert the password file is not rewritten
        mock_write_file.assert_not_called()


@pytest.mark.skipif(passlib is None, reason='passlib must be installed to run these tests')
class TestLookupModuleWithPasslibWrappedAlgo(BaseTestLookupModule):
    def setUp(self):
        super(TestLookupModuleWithPasslibWrappedAlgo, self).setUp()
        self.os_path_exists = password.os.path.exists

    def tearDown(self):
        super(TestLookupModuleWithPasslibWrappedAlgo, self).tearDown()
        password.os.path.exists = self.os_path_exists

    @patch('ansible.plugins.lookup.password._write_password_file')
    def test_encrypt_wrapped_crypt_algo(self, mock_write_file):

        password.os.path.exists = self.password_lookup._loader.path_exists
        with patch.object(builtins, 'open', mock_open(read_data=self.password_lookup._loader._get_file_contents('/path/to/somewhere')[0])) as m:
            results = self.password_lookup.run([u'/path/to/somewhere encrypt=ldap_sha256_crypt'], None)

            wrapper = getattr(passlib.hash, 'ldap_sha256_crypt')

            self.assertEqual(len(results), 1)
            result = results[0]
            self.assertIsInstance(result, str)

            expected_password_length = 76
            self.assertEqual(len(result), expected_password_length)

            # result should have 5 parts split by '$'
            str_parts = result.split('$')
            self.assertEqual(len(str_parts), 5)

            # verify the string and passlib agree on the number of rounds
            self.assertEqual(str_parts[2], "rounds=%s" % wrapper.default_rounds)

            # verify it used the right algo type
            self.assertEqual(str_parts[0], '{CRYPT}')

            # verify it used the right algo type
            self.assertTrue(wrapper.verify(self.password_lookup._loader._get_file_contents('/path/to/somewhere')[0], result))

            # verify a password with a non default rounds value
            # generated with: echo test | mkpasswd -s --rounds 660000 -m sha-256 --salt testansiblepass.
            hashpw = '{CRYPT}$5$rounds=660000$testansiblepass.$KlRSdA3iFXoPI.dEwh7AixiXW3EtCkLrlQvlYA2sluD'
            self.assertTrue(wrapper.verify('test', hashpw))
