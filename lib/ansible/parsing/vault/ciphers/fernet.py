# (c) The Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt

from __future__ import annotations

import base64
import os

HAS_CRYPTOGRAPHY = False
try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    HAS_CRYPTOGRAPHY = True
except ImportError:
    pass

from ansible.errors import AnsibleVaultError
from ansible.parsing.vault.ciphers import VaultCipher
from ansible.utils.display import Display

display = Display()


class VaultFERNET(VaultCipher):
    """
    very simple vault implementation relying on fernet
    """
    # memory cost: 128 bytes × cost (n) × block_size (r)
    # cpu cost: log(iterations^cost (n))
    defaults = dict(
            length=32,
            cost=2**14,  # implicitly sets iterations
            block_size=8,
            parallel=1,  # multiplier of mem and cpu costs to calculate result x more times
                         # possibly not parallel depending on implementation
            )

    @staticmethod
    def _require_crypto(f):
        def inner(self, *args, **kwargs):
            if HAS_CRYPTOGRAPHY:
                return f(self, *args, **kwargs)
            else:
                raise AnsibleVaultError("The FERNET cipher for ansible-vault requires the cryptography library in order to function")
        return inner

    def _key_from_password(self, b_password, salt=None, options=None):

        if salt is None:
            salt = os.urandom(32)

        options = self.set_defaults(options)

        # derive
        kdf = Scrypt(
                salt=salt,
                length=options['length'],
                n=options['cost'],
                r=options['block_size'],
                p=options['parallel'],
            )
        try:
            return base64.urlsafe_b64encode(kdf.derive(b_password)), salt, options
        except InvalidToken as e:
            raise AnsibleVaultError("Failed to derive key", orig_exc=e)

    @_require_crypto
    def encrypt(self, b_plaintext, secret, options=None):

        if secret is None:
            raise AnsibleVaultError('The secret passed to encrypt() was None')

        b_password = secret.bytes
        if len(b_password) < 10:
            raise AnsibleVaultError('The fernet cipher requires secrets longer than 10 bytes')

        key, salt, options = self._key_from_password(b_password, options)
        f = Fernet(key)
        try:
            return base64.b64encode(b';'.join([salt, f.encrypt(b_plaintext), self.encode_options(options)]))
        except InvalidToken as e:
            raise AnsibleVaultError("Failed to encrypt", orig_exc=e)

    @_require_crypto
    def decrypt(self, b_vaulttext, secret):
        salt, b_msg, b_options = base64.b64decode(b_vaulttext).split(b';', 2)
        f = Fernet(self._key_from_password(secret.bytes, salt, self.decode_options(b_options))[0])
        try:
            return f.decrypt(b_msg)
        except InvalidToken as e:
            raise AnsibleVaultError("Failed to decrypt", orig_exc=e)
