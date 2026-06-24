"""Crypto Vault — Symmetric Encryption and Hashing Microservice.

This service provides symmetric cryptographic operations to the API gateway.
It runs as an internal microservice and should not be directly exposed to
external clients. All requests should be routed through the API gateway.
"""

import os
import base64
from flask import Flask, request, jsonify

from crypto.aes import (
    encrypt_aes_128_gcm,
    decrypt_aes_128_gcm,
    encrypt_aes_256_gcm,
    decrypt_aes_256_gcm,
    encrypt_aes_128_cbc,
    decrypt_aes_128_cbc,
    encrypt_aes_128_ecb,
    decrypt_aes_128_ecb,
)
from crypto.chacha import encrypt_chacha20, decrypt_chacha20
from crypto.legacy import (
    encrypt_des, decrypt_des,
    encrypt_3des, decrypt_3des,
    encrypt_rc4, decrypt_rc4,
)
from crypto.hash import hash_data, compute_hmac

app = Flask(__name__)


# ─── Health ────────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint.

    Returns the vault status and supported algorithm list.
    """
    return jsonify({
        "status": "ok",
        "service": "crypto-vault",
        "version": "1.0.0",
        "supported_symmetric": [
            "aes-128-gcm", "aes-256-gcm", "chacha20-poly1305",
            "aes-128-cbc", "aes-128-ecb", "des", "3des", "rc4",
        ],
        "supported_hashes": ["sha-256", "sha-384", "sha-512", "md5", "sha-1"],
        "supported_hmac": ["hmac-sha256", "hmac-md5"],
    })


# ─── Encryption ────────────────────────────────────────────────────────────

@app.route("/vault/encrypt", methods=["POST"])
def encrypt():
    """Encrypt data using the specified symmetric algorithm.

    The algorithm and key material are provided in the request body.
    Supported algorithms: aes-128-gcm, aes-256-gcm, chacha20-poly1305,
    aes-128-cbc, des, 3des, rc4.
    """
    body = request.get_json(force=True)
    algorithm = body.get("algorithm", "").lower()
    plaintext = body.get("plaintext", "")
    key = body.get("key", "")
    iv = body.get("iv")

    if not plaintext or not key:
        return jsonify({"error": "plaintext and key are required"}), 400

    try:
        if algorithm == "aes-128-gcm":
            result = encrypt_aes_128_gcm(plaintext, key)
        elif algorithm == "aes-256-gcm":
            result = encrypt_aes_256_gcm(plaintext, key)
        elif algorithm == "chacha20-poly1305":
            result = encrypt_chacha20(plaintext, key)
        elif algorithm == "aes-128-cbc":
            result = encrypt_aes_128_cbc(plaintext, key, iv)
        elif algorithm == "aes-128-ecb":
            result = encrypt_aes_128_ecb(plaintext, key)
        elif algorithm == "des":
            result = encrypt_des(plaintext, key)
        elif algorithm == "3des":
            result = encrypt_3des(plaintext, key)
        elif algorithm == "rc4":
            result = encrypt_rc4(plaintext, key)
        else:
            return jsonify({"error": f"unsupported algorithm: {algorithm}"}), 400
        return jsonify(result)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"encryption failed: {str(e)}"}), 500


@app.route("/vault/decrypt", methods=["POST"])
def decrypt():
    """Decrypt data using the specified symmetric algorithm."""
    body = request.get_json(force=True)
    algorithm = body.get("algorithm", "").lower()
    ciphertext = body.get("ciphertext", "")
    key = body.get("key", "")
    nonce = body.get("nonce", "")
    tag = body.get("tag", "")
    iv = body.get("iv", "")

    if not ciphertext or not key:
        return jsonify({"error": "ciphertext and key are required"}), 400

    try:
        if algorithm == "aes-128-gcm":
            result = decrypt_aes_128_gcm(ciphertext, key, nonce, tag)
        elif algorithm == "aes-256-gcm":
            result = decrypt_aes_256_gcm(ciphertext, key, nonce, tag)
        elif algorithm == "chacha20-poly1305":
            result = decrypt_chacha20(ciphertext, key, nonce, tag)
        elif algorithm == "aes-128-cbc":
            result = decrypt_aes_128_cbc(ciphertext, key, iv)
        elif algorithm == "aes-128-ecb":
            result = decrypt_aes_128_ecb(ciphertext, key)
        elif algorithm == "des":
            result = decrypt_des(ciphertext, key)
        elif algorithm == "3des":
            result = decrypt_3des(ciphertext, key)
        elif algorithm == "rc4":
            result = decrypt_rc4(ciphertext, key)
        else:
            return jsonify({"error": f"unsupported algorithm: {algorithm}"}), 400
        return jsonify(result)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"decryption failed: {str(e)}"}), 500


# ─── Hashing ───────────────────────────────────────────────────────────────

@app.route("/vault/hash", methods=["POST"])
def hash_endpoint():
    """Compute a hash digest using the specified algorithm.

    Supported: SHA-256, SHA-384, SHA-512, MD5, SHA-1.
    """
    body = request.get_json(force=True)
    algorithm = body.get("algorithm", "").lower()
    data = body.get("data", "")

    if not data:
        return jsonify({"error": "data is required"}), 400

    try:
        result = hash_data(algorithm, data)
        return jsonify(result)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"hashing failed: {str(e)}"}), 500


# ─── HMAC ──────────────────────────────────────────────────────────────────

@app.route("/vault/hmac", methods=["POST"])
def hmac_endpoint():
    """Compute an HMAC using the specified algorithm.

    Supported: HMAC-SHA256, HMAC-MD5.
    """
    body = request.get_json(force=True)
    algorithm = body.get("algorithm", "").lower()
    data = body.get("data", "")
    key = body.get("key", "")

    if not data or not key:
        return jsonify({"error": "data and key are required"}), 400

    try:
        result = compute_hmac(algorithm, data, key)
        return jsonify(result)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"hmac failed: {str(e)}"}), 500


if __name__ == "__main__":
    port = int(os.environ.get("VAULT_PORT", "9090"))
    app.run(host="0.0.0.0", port=port, debug=False)
