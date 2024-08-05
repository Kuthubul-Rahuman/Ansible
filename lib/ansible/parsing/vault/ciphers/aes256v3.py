# (c) The Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt

from __future__ import annotations

import base64
import os
import warnings

CRYPTOGRAPHY_BACKEND = None
try:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        from cryptography.exceptions import InvalidSignature

    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, padding
    from cryptography.hazmat.primitives.hmac import HMAC
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    CRYPTOGRAPHY_BACKEND = default_backend()
except ImportError as e:
    raise ImportError("The AES256v2 cipher for ansible-vault requires the cryptography library in order to function") from e

from ansible.utils.display import Display
from ansible.parsing.vault.ciphers import VaultCipher

display = Display()
PASS = {}

class VaultAES256V2(VaultCipher):
    """
    Vault implementation using AES-CTR with an HMAC-SHA256 authentication code.
    Keys are derived using PBKDF2

    http://www.daemonology.net/blog/2009-06-11-cryptographic-right-answers.html
    Note: strings in this class should be byte strings by default.

    only raises ValueError when missing deps, or TypeError when args are invalid
    """


    defaults = dict(
        algo = 'SHA256',
        iterations = 600000,  # recommended as Q2/2024
        key_length = 32,  # for AES256
        iv_length = 16,  # default for 128 AES block size
        # key_length = algorithms.AES.block_size // 4
        # iv_length = algorithms.AES.block_size // 8
    )

    @staticmethod
    def _create_key_cryptography(b_password, b_salt, options):

        if b_password not in PASS:
            PASS[b_password] = {}

        if b_salt not in PASS[b_password]:
           crypto_hash = getattr(hashes, options['algo'])

           kdf = PBKDF2HMAC(
                   algorithm=crypto_hash(),
                   backend=CRYPTOGRAPHY_BACKEND,
                   iterations=options['iterations'],
                   length=2 * options['key_length'] + options['iv_length'],
                   salt=b_salt,
               )
           PASS[b_password][b_salt] = kdf.derive(b_password)

        return PASS[b_password][b_salt]

    @classmethod
    def _gen_key_initctr(cls, b_password, b_salt, options=None):

        options = cls.set_defaults(options)

        key_length = options['key_length']
        iv_length = options['iv_length']

        b_derivedkey = cls._create_key_cryptography(b_password, b_salt, options)
        b_iv = b_derivedkey[(key_length * 2):(key_length * 2) + iv_length]

        b_key1 = b_derivedkey[:key_length]
        b_key2 = b_derivedkey[key_length:(key_length * 2)]

        return b_key1, b_key2, b_iv, options

    @staticmethod
    def _encrypt_cryptography(b_plaintext, b_key1, b_key2, b_iv):
        cipher = Cipher(algorithms.AES(b_key1), modes.CTR(b_iv), CRYPTOGRAPHY_BACKEND)
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        b_ciphertext = encryptor.update(padder.update(b_plaintext) + padder.finalize())
        b_ciphertext += encryptor.finalize()

        # COMBINE SALT, DIGEST AND DATA
        hmac = HMAC(b_key2, hashes.SHA256(), CRYPTOGRAPHY_BACKEND)
        hmac.update(b_ciphertext)
        b_hmac = hmac.finalize()

        return b_hmac, b_ciphertext

    @classmethod
    def encrypt(cls, b_plaintext, secret, options=None):

        if not secret:
            raise ValueError('The AESv2 cipher reqquires a secret to encrypt()')
        b_password = secret.bytes
        if len(b_password) < 10:
            raise ValueError('The AESv2 cipher reqquires a secret to be at least 10 bytes long')

        b_salt = os.urandom(32)
        b_key1, b_key2, b_iv, options = cls._gen_key_initctr(b_password, b_salt, options)
        b_hmac, b_ciphertext = cls._encrypt_cryptography(b_plaintext, b_key1, b_key2, b_iv)

        return b';'.join(base64.b64encode(x) for x in [b_salt, b_hmac, b_ciphertext, cls.encode_options(options)])

    @staticmethod
    def _decrypt_cryptography(b_ciphertext, b_crypted_hmac, b_key1, b_key2, b_iv):
        hmac = HMAC(b_key2, hashes.SHA256(), CRYPTOGRAPHY_BACKEND)
        hmac.update(b_ciphertext)
        try:
            hmac.verify(b_crypted_hmac)
        except InvalidSignature as e:
            raise ValueError('HMAC verification failed') from  e

        cipher = Cipher(algorithms.AES(b_key1), modes.CTR(b_iv), CRYPTOGRAPHY_BACKEND)
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(128).unpadder()
        b_plaintext = unpadder.update(
            decryptor.update(b_ciphertext) + decryptor.finalize()
        ) + unpadder.finalize()

        return b_plaintext

    @classmethod
    def decrypt(cls, b_vaulttext, secret):

        try:
            b_salt, b_crypted_hmac, b_ciphertext, b_options = [base64.b64decode(x) for x in b_vaulttext.split(b";", 3)]
        except ValueError as e:
            raise ValueError("Invalid ciphered data in vault") from e

        b_password = secret.bytes
        b_key1, b_key2, b_iv, options = cls._gen_key_initctr(b_password, b_salt, cls.decode_options(b_options))

        b_plaintext = cls._decrypt_cryptography(b_ciphertext, b_crypted_hmac, b_key1, b_key2, b_iv)
        display.log(f"Decrypted vault using {options}")

        return b_plaintext
