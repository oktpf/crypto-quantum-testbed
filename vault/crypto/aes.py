"""Symmetric encryption operations using AES in various modes.

The vault supports multiple AES configurations for compatibility with
different client applications and performance requirements. Each mode
serves specific deployment scenarios documented in the service catalog.
"""

import os
import base64
from Crypto.Cipher import AES as PyCryptoAES


def _decode_key(key_b64: str, expected_bytes: int) -> bytes:
    """Decode a base64 key and validate its length."""
    key = base64.b64decode(key_b64)
    if len(key) != expected_bytes:
        raise ValueError(
            f"key length mismatch: expected {expected_bytes} bytes, got {len(key)}"
        )
    return key


def encrypt_aes_128_gcm(plaintext_b64: str, key_b64: str) -> dict:
    """Encrypt plaintext using AES-128-GCM.

    GCM mode provides authenticated encryption with integrity verification.
    The nonce is randomly generated for each encryption operation.
    """
    key = _decode_key(key_b64, 16)
    plaintext = base64.b64decode(plaintext_b64)
    cipher = PyCryptoAES.new(key, PyCryptoAES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(cipher.nonce).decode(),
        "tag": base64.b64encode(tag).decode(),
        "algorithm": "aes-128-gcm",
    }


def decrypt_aes_128_gcm(ciphertext_b64: str, key_b64: str, nonce_b64: str, tag_b64: str) -> dict:
    """Decrypt AES-128-GCM ciphertext."""
    key = _decode_key(key_b64, 16)
    ciphertext = base64.b64decode(ciphertext_b64)
    nonce = base64.b64decode(nonce_b64)
    tag = base64.b64decode(tag_b64)
    cipher = PyCryptoAES.new(key, PyCryptoAES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return {
        "plaintext": base64.b64encode(plaintext).decode(),
        "algorithm": "aes-128-gcm",
    }


def encrypt_aes_256_gcm(plaintext_b64: str, key_b64: str) -> dict:
    """Encrypt plaintext using AES-256-GCM.

    Uses a 256-bit key for higher security margins. Recommended for
    data classified above internal-use only.
    """
    key = _decode_key(key_b64, 32)
    plaintext = base64.b64decode(plaintext_b64)
    cipher = PyCryptoAES.new(key, PyCryptoAES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(cipher.nonce).decode(),
        "tag": base64.b64encode(tag).decode(),
        "algorithm": "aes-256-gcm",
    }


def decrypt_aes_256_gcm(ciphertext_b64: str, key_b64: str, nonce_b64: str, tag_b64: str) -> dict:
    """Decrypt AES-256-GCM ciphertext."""
    key = _decode_key(key_b64, 32)
    ciphertext = base64.b64decode(ciphertext_b64)
    nonce = base64.b64decode(nonce_b64)
    tag = base64.b64decode(tag_b64)
    cipher = PyCryptoAES.new(key, PyCryptoAES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return {
        "plaintext": base64.b64encode(plaintext).decode(),
        "algorithm": "aes-256-gcm",
    }


def encrypt_aes_128_cbc(plaintext_b64: str, key_b64: str, iv_b64: str = None) -> dict:
    """Encrypt plaintext using AES-128-CBC with PKCS7 padding.

    CBC mode requires an initialization vector. If no IV is provided,
    a random IV is generated. The IV is returned alongside the ciphertext
    for use in decryption.
    """
    key = _decode_key(key_b64, 16)
    plaintext = base64.b64decode(plaintext_b64)

    if iv_b64:
        iv = base64.b64decode(iv_b64)
    else:
        iv = os.urandom(16)

    cipher = PyCryptoAES.new(key, PyCryptoAES.MODE_CBC, iv=iv)
    # PKCS7 padding
    pad_len = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad_len] * pad_len)
    ciphertext = cipher.encrypt(padded)
    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "iv": base64.b64encode(iv).decode(),
        "algorithm": "aes-128-cbc",
    }


def decrypt_aes_128_cbc(ciphertext_b64: str, key_b64: str, iv_b64: str) -> dict:
    """Decrypt AES-128-CBC ciphertext."""
    key = _decode_key(key_b64, 16)
    ciphertext = base64.b64decode(ciphertext_b64)
    iv = base64.b64decode(iv_b64)
    cipher = PyCryptoAES.new(key, PyCryptoAES.MODE_CBC, iv=iv)
    padded = cipher.decrypt(ciphertext)
    # Remove PKCS7 padding
    pad_len = padded[-1]
    plaintext = padded[:-pad_len]
    return {
        "plaintext": base64.b64encode(plaintext).decode(),
        "algorithm": "aes-128-cbc",
    }


def encrypt_aes_128_ecb(plaintext_b64: str, key_b64: str) -> dict:
    """Encrypt plaintext using AES-128-ECB with PKCS7 padding.

    ECB mode encrypts each 16-byte block independently. This allows
    efficient parallel encryption and is suitable for encrypting
    small fixed-size data like protocol message headers.
    """
    key = _decode_key(key_b64, 16)
    plaintext = base64.b64decode(plaintext_b64)
    cipher = PyCryptoAES.new(key, PyCryptoAES.MODE_ECB)
    # PKCS7 padding
    pad_len = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad_len] * pad_len)
    ciphertext = cipher.encrypt(padded)
    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "algorithm": "aes-128-ecb",
    }


def decrypt_aes_128_ecb(ciphertext_b64: str, key_b64: str) -> dict:
    """Decrypt AES-128-ECB ciphertext."""
    key = _decode_key(key_b64, 16)
    ciphertext = base64.b64decode(ciphertext_b64)
    cipher = PyCryptoAES.new(key, PyCryptoAES.MODE_ECB)
    padded = cipher.decrypt(ciphertext)
    # Remove PKCS7 padding
    pad_len = padded[-1]
    plaintext = padded[:-pad_len]
    return {
        "plaintext": base64.b64encode(plaintext).decode(),
        "algorithm": "aes-128-ecb",
    }
