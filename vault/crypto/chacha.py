"""ChaCha20-Poly1305 authenticated encryption operations.

ChaCha20-Poly1305 provides a high-performance alternative to AES-GCM,
particularly on platforms without hardware AES acceleration. The algorithm
uses a 256-bit key and 96-bit nonce.
"""

import base64
from Crypto.Cipher import ChaCha20_Poly1305


def encrypt_chacha20(plaintext_b64: str, key_b64: str) -> dict:
    """Encrypt plaintext using ChaCha20-Poly1305.

    The cipher generates a random nonce for each operation and returns
    it alongside the ciphertext and authentication tag.
    """
    key = base64.b64decode(key_b64)
    if len(key) != 32:
        raise ValueError(f"ChaCha20 key must be 32 bytes, got {len(key)}")

    plaintext = base64.b64decode(plaintext_b64)
    cipher = ChaCha20_Poly1305.new(key=key)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(cipher.nonce).decode(),
        "tag": base64.b64encode(tag).decode(),
        "algorithm": "chacha20-poly1305",
    }


def decrypt_chacha20(ciphertext_b64: str, key_b64: str, nonce_b64: str, tag_b64: str) -> dict:
    """Decrypt ChaCha20-Poly1305 ciphertext."""
    key = base64.b64decode(key_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    nonce = base64.b64decode(nonce_b64)
    tag = base64.b64decode(tag_b64)
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return {
        "plaintext": base64.b64encode(plaintext).decode(),
        "algorithm": "chacha20-poly1305",
    }
