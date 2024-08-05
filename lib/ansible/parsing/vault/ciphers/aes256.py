# (c) The Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt

from __future__ import annotations

import os
import warnings

from binascii import hexlify
from binascii import unhexlify
from binascii import Error as BinasciiError

HAS_CRYPTOGRAPHY = False
CRYPTOGRAPHY_BACKEND = None
try:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, padding
    from cryptography.hazmat.primitives.hmac import HMAC
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.ciphers import (
        Cipher as C_Cipher, algorithms, modes
    )
    CRYPTOGRAPHY_BACKEND = default_backend()
    HAS_CRYPTOGRAPHY = True
except ImportError:
    pass

from ansible.errors import AnsibleVaultError
from ansible import constants as C
from ansible.module_utils.common.text.converters import to_bytes
from ansible.utils.display import Display
from ansible.parsing.vault.ciphers import VaultCipher

display = Display()


class VaultAES256(VaultCipher):
    """
    Vault implementation using AES-CTR with an HMAC-SHA256 authentication code.
    Keys are derived using PBKDF2

    http://www.daemonology.net/blog/2009-06-11-cryptographic-right-answers.html
    Note: strings in this class should be byte strings by default.

    """

    NEED_CRYPTO_LIBRARY = "The AES256 cipher for ansible-vault requires the cryptography library in order to function"

    def __init__(self):
        if not HAS_CRYPTOGRAPHY:
            raise AnsibleVaultError(self.NEED_CRYPTO_LIBRARY)

    @staticmethod
    def _unhexlify(b_data):
        try:
            return unhexlify(b_data)
        except (BinasciiError, TypeError) as exc:
            raise AnsibleVaultError('Invalid vaulted text format, cannot unhexlify: %s' % exc)

    @staticmethod
    def _require_crypto(f):
        def inner(self, *args, **kwargs):
            if HAS_CRYPTOGRAPHY:
                return f(self, *args, **kwargs)
            else:
                raise AnsibleVaultError(self.NEED_CRYPTO_LIBRARY)
        return inner

    @staticmethod
    def _create_key_cryptography(b_password, b_salt, key_length, iv_length):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=2 * key_length + iv_length,
            salt=b_salt,
            iterations=1000,
            backend=CRYPTOGRAPHY_BACKEND)
        b_derivedkey = kdf.derive(b_password)

        return b_derivedkey

    def _gen_key_initctr(self, b_password, b_salt):
        # 16 for AES 128, 32 for AES256
        key_length = 32

        # AES is a 128-bit block cipher, so IVs and counter nonces are 16 bytes
        iv_length = algorithms.AES.block_size // 8

        b_derivedkey = self._create_key_cryptography(b_password, b_salt, key_length, iv_length)
        b_iv = b_derivedkey[(key_length * 2):(key_length * 2) + iv_length]

        b_key1 = b_derivedkey[:key_length]
        b_key2 = b_derivedkey[key_length:(key_length * 2)]

        return b_key1, b_key2, b_iv

    @staticmethod
    def _encrypt_cryptography(b_plaintext, b_key1, b_key2, b_iv):
        cipher = C_Cipher(algorithms.AES(b_key1), modes.CTR(b_iv), CRYPTOGRAPHY_BACKEND)
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        b_ciphertext = encryptor.update(padder.update(b_plaintext) + padder.finalize())
        b_ciphertext += encryptor.finalize()

        # COMBINE SALT, DIGEST AND DATA
        hmac = HMAC(b_key2, hashes.SHA256(), CRYPTOGRAPHY_BACKEND)
        hmac.update(b_ciphertext)
        b_hmac = hmac.finalize()

        return to_bytes(hexlify(b_hmac), errors='surrogate_or_strict'), hexlify(b_ciphertext)

    @staticmethod
    def _get_salt():
        # won't deprecate, this is unsafe, but cipher itself will be deprecated
        custom_salt = C.config.get_config_value('VAULT_ENCRYPT_SALT')
        if not custom_salt:
            custom_salt = os.urandom(32)
        return to_bytes(custom_salt)

    @_require_crypto
    def encrypt(self, b_plaintext, secret, options=None):

        if secret is None:
            raise AnsibleVaultError('The secret passed to encrypt() was None')

        b_salt = self._get_salt()
        b_password = secret.bytes
        b_key1, b_key2, b_iv = self._gen_key_initctr(b_password, b_salt)

        b_hmac, b_ciphertext = self._encrypt_cryptography(b_plaintext, b_key1, b_key2, b_iv)

        b_vaulttext = b'\n'.join([hexlify(b_salt), b_hmac, b_ciphertext])
        # Unnecessary x2 hexlifying but getting rid of it is a backwards incompatible change
        b_vaulttext = hexlify(b_vaulttext)
        return b_vaulttext

    @staticmethod
    def _decrypt_cryptography(b_ciphertext, b_crypted_hmac, b_key1, b_key2, b_iv):
        hmac = HMAC(b_key2, hashes.SHA256(), CRYPTOGRAPHY_BACKEND)
        hmac.update(b_ciphertext)
        try:
            hmac.verify(b_crypted_hmac)
        except InvalidSignature as e:
            raise AnsibleVaultError('HMAC verification failed: %s' % e)

        cipher = C_Cipher(algorithms.AES(b_key1), modes.CTR(b_iv), CRYPTOGRAPHY_BACKEND)
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(128).unpadder()
        b_plaintext = unpadder.update(
            decryptor.update(b_ciphertext) + decryptor.finalize()
        ) + unpadder.finalize()

        return b_plaintext

    @_require_crypto
    def decrypt(self, b_vaulttext, secret):
        try:
            b_salt, b_crypted_hmac, b_ciphertext = [self._unhexlify(x) for x in self._unhexlify(b_vaulttext).split(b"\n", 2)]
        except ValueError as e:
            raise AnsibleVaultError("Invalid ciphered data in vault", orig_exc=e)

        b_password = secret.bytes
        b_key1, b_key2, b_iv = self._gen_key_initctr(b_password, b_salt)

        b_plaintext = self._decrypt_cryptography(b_ciphertext, b_crypted_hmac, b_key1, b_key2, b_iv)

        return b_plaintext
