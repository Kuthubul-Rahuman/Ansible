# (c) The Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt

from __future__ import annotations

import base64

try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
except ImportError as e:
    raise ImportError("The FERNET cipher for ansible-vault requires the cryptography library in order to function") from e

from ansible.module_utils.common.text.converters import to_bytes
from ansible.parsing.vault.ciphers import VaultCipher
from ansible.utils.display import Display

display = Display()

PASS = {}

class VaultFERNETKEY(VaultCipher):
    """
    very simple vault implementation relying on fernet
    """

    @classmethod
    def _key_from_password(cls, b_password, options=None):

        global PASS
        if b_password not in PASS.keys():
            if options is None:
                # FIXME: use defaults
                options = dict(salt=b'ansible', length=32, n=2**14, r=8, p=1)

            # derive
            kdf = Scrypt(
                         salt=to_bytes(options['salt']),
                         length=options['length'],
                         n=options['n'],
                         r=options['r'],
                         p=options['p'],
                        )
            try:
                PASS[b_password] = base64.urlsafe_b64encode(kdf.derive(b_password))
            except InvalidToken as e:
                raise ValueError("Failed to derive key") from e

        return PASS[b_password], options

    @classmethod
    def encrypt(cls, b_plaintext, secret, options=None):

        if secret is None:
            raise ValueError('The secret passed to encrypt() was None')

        b_password = secret.bytes
        if len(b_password) < 10:
            raise ValueError('The fernet cipher requires secrets longer than 10 bytes')

        # use random key to encrypt text
        key = Fernet.generate_key()
        f = Fernet(key)
        ciphered = f.encrypt(b_plaintext)

        # now crypt random key with vault secret
        password_key, options = cls._key_from_password(b_password, options)
        p = Fernet(password_key)
        options['key'] = p.encrypt(key)
        try:
            return base64.b64encode(b';'.join([ciphered, cls.encode_options(options)]))
        except InvalidToken as e:
            raise ValueError("Failed to encrypt") from e

    @classmethod
    def decrypt(cls, b_vaulttext, secret):
        b_msg, b_options = base64.b64decode(b_vaulttext).split(b';', 2)

        options = cls.decode_options(b_options)
        password_key, options = cls._key_from_password(secret.bytes, options)

        p = Fernet(password_key)
        try:
            key = p.decrypt(to_bytes(options['key']))
        except InvalidToken as e:
            raise ValueError("Failed to decrypt key") from e

        f = Fernet(key)
        try:
            return f.decrypt(b_msg)
        except InvalidToken as e:
            raise ValueError("Failed to decrypt text") from e
