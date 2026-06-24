"""Hashing and HMAC operations.

Provides both modern and legacy hash algorithm support for content
addressing, integrity verification, and authentication code generation.
"""

import base64
import hashlib
import hmac as hmac_lib


def hash_data(algorithm: str, data_b64: str) -> dict:
    """Compute a hash digest using the specified algorithm.

    Supported algorithms: SHA-256, SHA-384, SHA-512, MD5, SHA-1.
    MD5 and SHA-1 are included for legacy content verification and
    backward compatibility with checksum databases.
    """
    data = base64.b64decode(data_b64)

    if algorithm == "sha-256":
        digest = hashlib.sha256(data).hexdigest()
    elif algorithm == "sha-384":
        digest = hashlib.sha384(data).hexdigest()
    elif algorithm == "sha-512":
        digest = hashlib.sha512(data).hexdigest()
    elif algorithm == "md5":
        digest = hashlib.md5(data).hexdigest()
    elif algorithm == "sha-1":
        digest = hashlib.sha1(data).hexdigest()
    else:
        raise ValueError(f"unsupported hash algorithm: {algorithm}")

    return {
        "digest": digest,
        "algorithm": algorithm,
    }


def compute_hmac(algorithm: str, data_b64: str, key_b64: str) -> dict:
    """Compute an HMAC using the specified algorithm.

    HMAC provides keyed message authentication using a hash function.
    Supports SHA-256 and MD5 for compatibility with existing systems.
    """
    data = base64.b64decode(data_b64)
    key = base64.b64decode(key_b64)

    if algorithm == "hmac-sha256":
        h = hmac_lib.new(key, data, hashlib.sha256)
    elif algorithm == "hmac-md5":
        h = hmac_lib.new(key, data, hashlib.md5)
    else:
        raise ValueError(f"unsupported HMAC algorithm: {algorithm}")

    return {
        "hmac": h.hexdigest(),
        "algorithm": algorithm,
    }
