# (c) The Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

import json

from abc import abstractmethod

from ansible.module_utils.common.text.converters import to_bytes, to_text


class VaultCipher:
    """
        Base class all ciphers must implement
    """
    defaults = {}

    @abstractmethod
    def encrypt(self, b_plaintext, secret, salt=None, options=None):
        """
        :arg plaintext: A byte string to encrypt
        :arg secret: A populated VaultSecret object
        :arg salt: Optional salt to use in encryption, for backwards compat
                  In most ciphers this will not be used
        :arg options: encryption options dict/data class

        :returns: A ciphered byte string that includes the encrypted data and
                  other needed items for decryption

        :raises: AnsibleVaultError do to missing requirements or other issues
        """
        pass

    @abstractmethod
    def decrypt(self, b_vaulttext, secret):
        """
        :arg b_vaulttext: A ciphered byte string that includes the encrypted
                data and other needed items for decryption
        :arg secret: A populated VaultSecret object

        :returns: decrypted byte string

        :raises: AnsibleVaultError do to missing requirements or other issues
        """
        pass

    @staticmethod
    def encode_options(options):
        # TODO: do per value b64encoding
        return to_bytes(json.dumps(options))

    @staticmethod
    def decode_options(b_options):
        # TODO: do per value b64encoding
        return json.loads(to_text(b_options, errors='surrogate_or_strict'))

    def set_defaults(self, options):

        if options is None:
            options = {}

        for k in self.defaults.keys():
            if k not in options:
                options[k] = self.defaults[k]
        return options
