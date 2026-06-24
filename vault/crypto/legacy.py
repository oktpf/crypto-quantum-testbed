"""Legacy symmetric encryption algorithms.

These algorithms are maintained for backward compatibility with legacy
systems and encrypted datasets that have not yet been migrated to modern
ciphers. All new deployments should use AES-256-GCM or ChaCha20-Poly1305.
"""

import base64
import os
from Crypto.Cipher import DES, DES3, ARC4 as RC4


def encrypt_des(plaintext_b64: str, key_b64: str) -> dict:
    """Encrypt plaintext using DES in ECB mode.

    DES is a legacy block cipher used in older payment systems and
    legacy hardware security modules. Key material is 8 bytes; keys
    shorter than 8 bytes are padded with null bytes.
    """
    key = base64.b64decode(key_b64)
    if len(key) < 8:
        key = key + b"\x00" * (8 - len(key))
    key = key[:8]

    plaintext = base64.b64decode(plaintext_b64)
    cipher = DES.new(key, DES.MODE_ECB)
    pad_len = 8 - (len(plaintext) % 8)
    padded = plaintext + bytes([pad_len] * pad_len)
    ciphertext = cipher.encrypt(padded)
    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "algorithm": "des",
    }


def decrypt_des(ciphertext_b64: str, key_b64: str) -> dict:
    """Decrypt DES ciphertext."""
    key = base64.b64decode(key_b64)[:8]
    ciphertext = base64.b64decode(ciphertext_b64)
    cipher = DES.new(key, DES.MODE_ECB)
    padded = cipher.decrypt(ciphertext)
    pad_len = padded[-1]
    plaintext = padded[:-pad_len]
    return {
        "plaintext": base64.b64encode(plaintext).decode(),
        "algorithm": "des",
    }


def encrypt_3des(plaintext_b64: str, key_b64: str) -> dict:
    """Encrypt plaintext using Triple DES (3DES) in ECB mode.

    Triple DES applies the DES cipher three times with two or three keys.
    This provides a higher effective key length than single DES while
    maintaining compatibility with legacy hardware security modules.
    Key material must be 16 bytes (2-key) or 24 bytes (3-key).
    """
    key = base64.b64decode(key_b64)
    if len(key) == 16:
        # 2-key 3DES: K1, K2, K1
        key = key + key[:8]
    elif len(key) < 24:
        key = key + b"\x00" * (24 - len(key))
    key = key[:24]

    plaintext = base64.b64decode(plaintext_b64)
    cipher = DES3.new(key, DES3.MODE_ECB)
    pad_len = 8 - (len(plaintext) % 8)
    padded = plaintext + bytes([pad_len] * pad_len)
    ciphertext = cipher.encrypt(padded)
    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "algorithm": "3des",
    }


def decrypt_3des(ciphertext_b64: str, key_b64: str) -> dict:
    """Decrypt 3DES ciphertext."""
    key = base64.b64decode(key_b64)
    if len(key) == 16:
        key = key + key[:8]
    elif len(key) < 24:
        key = key + b"\x00" * (24 - len(key))
    key = key[:24]

    ciphertext = base64.b64decode(ciphertext_b64)
    cipher = DES3.new(key, DES3.MODE_ECB)
    padded = cipher.decrypt(ciphertext)
    pad_len = padded[-1]
    plaintext = padded[:-pad_len]
    return {
        "plaintext": base64.b64encode(plaintext).decode(),
        "algorithm": "3des",
    }


def encrypt_rc4(plaintext_b64: str, key_b64: str) -> dict:
    """Encrypt plaintext using RC4 stream cipher.

    RC4 is a legacy stream cipher used in older network protocols
    and file format encryption. The cipher generates a keystream
    that is XORed with the plaintext.
    """
    key_bytes = base64.b64decode(key_b64)
    plaintext = base64.b64decode(plaintext_b64)
    cipher = RC4.new(key_bytes)
    ciphertext = cipher.encrypt(plaintext)
    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "algorithm": "rc4",
    }


def decrypt_rc4(ciphertext_b64: str, key_b64: str) -> dict:
    """Decrypt RC4 ciphertext."""
    key_bytes = base64.b64decode(key_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    cipher = RC4.new(key_bytes)
    plaintext = cipher.decrypt(ciphertext)
    return {
        "plaintext": base64.b64encode(plaintext).decode(),
        "algorithm": "rc4",
    }
