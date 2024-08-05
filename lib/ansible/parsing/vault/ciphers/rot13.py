# (c) The Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt

from __future__ import annotations

import base64

from ansible.module_utils.common.text.converters import to_bytes, to_text
from ansible.parsing.vault.ciphers import VaultCipher
from ansible.utils.display import Display

display = Display()


class VaultROT13(VaultCipher):
    """
    DO NOT USE
    """

    @staticmethod
    def _rot13(string):
        lower = "abcdefghijklmnopqrstuvwxyz"
        rotten = lower[13:] + lower[:13]

        def _rot(c):
            return rotten[lower.find(c)] if lower.find(c)>-1 else c

        cipher = []
        for char in string:
            low = char.islower()
            x = _rot(char.lower())
            if not low:
                x = x.upper()
            cipher.append(x)

        return ''.join(cipher)

    @classmethod
    def encrypt(cls, b_plaintext, secret, options=None):

        if secret is not None:
            display.warning("You passed a secret? .. funny")

        return base64.b64encode(to_bytes(cls._rot13(to_text(b_plaintext, errors='surrogate_or_strict'))))


    @classmethod
    def decrypt(cls, b_vaulttext, secret):
        if secret is not None:
            display.warning("You passed a secret? .. funny")

        return to_bytes(cls._rot13(to_text(base64.b64decode(b_vaulttext))))
