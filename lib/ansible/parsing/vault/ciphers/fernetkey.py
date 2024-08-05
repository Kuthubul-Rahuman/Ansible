# (c) The Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt

from __future__ import annotations

import base64

from dataclasses import dataclass

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


# slots and kw_only are 3.10 only, nice to use going forward
@dataclass
class Defaults():
    salt: bytes = b'ansible'
    length: int = 32
    n: int = 2**14
    r: int = 8
    p: int = 1
    key: bytes = None

    def to_dict(self):
        return self.__dict__.copy()


class VaultFERNETKEY(VaultCipher):
    """
    very simple vault implementation relying on fernet
    """

    @classmethod
    def set_defaults(cls, options):
        return Defaults(**options).to_dict()

    @classmethod
    def _key_from_password(cls, b_password, options=None):

        global PASS
        if b_password not in PASS:
            PASS[b_password] = {}

        if options is None:
            options = {}

        o = cls.set_defaults(options)

        if o.salt not in PASS[b_password]:
            # derive as not in cache

            kdf = Scrypt(salt=o['salt'], length=o['length'], n=o['n'], r=o['r'], p=o['p'])
            try:
                PASS[b_password][o.salt] = base64.urlsafe_b64encode(kdf.derive(b_password))
            except InvalidToken as e:
                raise ValueError("Failed to derive key") from e

        return PASS[b_password][o.salt], o

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

        # put random key (encrypted with vault secret) in options to store in ciphered text
        options['key'] = p.encrypt(key)

        try:
            return base64.b64encode(b';'.join([ciphered, cls.encode_options(options)]))
        except InvalidToken as e:
            raise ValueError("Failed to encrypt") from e

    @classmethod
    def decrypt(cls, b_vaulttext, secret):

        b_msg, b_options = base64.b64decode(b_vaulttext).split(b';', 2)

        options = cls.decode_options(b_options)
        if 'salt' in options and not isinstance(options['salt'], bytes):
            options['salt'] = to_bytes(options['salt'])

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
