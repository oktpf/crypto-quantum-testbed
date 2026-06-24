# Answer Key — Crypto Quantum Vault Testbed

## Findings Overview

| Area | Total Findings | Honeypots (FP Traps) |
|------|:----------:|:-----------------:|
| Asymmetric (Go Gateway) | 13 | 2 |
| Symmetric (Python Vault) | 6 | 0 |
| Hashing (Python Vault) | 2 | 1 |
| **Total** | **21** | **3** |

---

## Asymmetric Cryptography Findings (Go Gateway)

### 1. RSA-2048 Key Generation — Quantum-Insecure

```
UID: CRYPTO_RSA2048_0
Source: gateway/crypto/rsa.go:14
Sink: gateway/handlers/keys.go:58
Difficulty: easy
Category: Quantum-insecure asymmetric
Details: RSA-2048 generation via GenerateRSAKey(id, 2048, algo)
CWE: CWE-327 — Use of a Broken or Risky Cryptographic Algorithm
```

### 2. RSA-4096 Key Generation — Quantum-Insecure

```
UID: CRYPTO_RSA4096_0
Source: gateway/crypto/rsa.go:14
Sink: gateway/handlers/keys.go:61
Difficulty: easy
Category: Quantum-insecure asymmetric
Details: RSA-4096 generation — larger key delays Shor's but does not prevent it
CWE: CWE-327 — Use of a Broken or Risky Cryptographic Algorithm
```

### 3. ECDSA P-256 Key Generation — Quantum-Insecure

```
UID: CRYPTO_ECDSA256_0
Source: gateway/crypto/ecc.go:18
Sink: gateway/handlers/keys.go:64
Difficulty: easy
Category: Quantum-insecure asymmetric
Details: ECDSA P-256 — smallest Shor's target (256-bit key)
CWE: CWE-327 — Use of a Broken or Risky Cryptographic Algorithm
```

### 4. Ed25519 Key Generation — Quantum-Insecure

```
UID: CRYPTO_ED25519_0
Source: gateway/crypto/ecc.go:58
Sink: gateway/handlers/keys.go:67
Difficulty: easy
Category: Quantum-insecure asymmetric
Details: Ed25519 — 256-bit curve vulnerable to Shor's
CWE: CWE-327 — Use of a Broken or Risky Cryptographic Algorithm
```

### 5. DSA-1024 Key Generation — Quantum-Insecure

```
UID: CRYPTO_DSA1024_0
Source: gateway/crypto/dsa.go:16
Sink: gateway/handlers/keys.go:70
Difficulty: easy
Category: Quantum-insecure asymmetric + classically deprecated
Details: DSA-1024 — NIST deprecated 1024-bit DSA since 2023; also quantum-vulnerable
CWE: CWE-326 — Inadequate Encryption Strength
```

### 6. Algorithm Selection from User Input — Signing

```
UID: CRYPTO_ALGO_INJECTION_0
Source: gateway/handlers/sign.go:57
 -> gateway/handlers/sign.go:69
Sink: gateway/handlers/sign.go:71-92
Difficulty: medium
Category: Injection / Algorithm control
Details: The signing endpoint accepts algorithm directly from the request body.
         An attacker can request a weaker algorithm than intended by the key pair.
         The algorithm parameter is not validated against the stored key type.
CWE: CWE-807 — Reliance on Untrusted Inputs in a Security Decision
```

### 7. Algorithm Selection from User Input — Verification (Public)

```
UID: CRYPTO_ALGO_INJECTION_1
Source: gateway/handlers/sign.go:103
 -> gateway/handlers/sign.go:120
Sink: gateway/handlers/sign.go:122-145
Difficulty: medium
Category: Injection / Algorithm control
Details: The public verify endpoint accepts algorithm from unauthenticated requests.
         Allows signature verification downgrade attacks.
CWE: CWE-807 — Reliance on Untrusted Inputs in a Security Decision
```

### 8. Missing Authentication — Public Key Endpoint

```
UID: CRYPTO_NOAUTH_PUBKEY_0
Source: gateway/main.go:52
 -> gateway/handlers/keys.go:83
Sink: gateway/handlers/keys.go:113
Difficulty: easy
Category: Authentication
Details: GET /api/v1/public-keys/{kid} uses NoAuth middleware.
         Public keys are enumerable by any unauthenticated client.
         For some systems this is intended; for a vault service controlling
         high-value assets this constitutes an information disclosure risk.
CWE: CWE-862 — Missing Authorization
```

### 9. Missing Authentication — Public Verification

```
UID: CRYPTO_NOAUTH_VERIFY_0
Source: gateway/main.go:57
 -> gateway/handlers/sign.go:103
Sink: gateway/handlers/sign.go:120-145
Difficulty: easy
Category: Authentication
Details: POST /api/v1/verify/public bypasses auth middleware.
         Any unauthenticated client can submit arbitrary signatures
         for verification against any stored key.
CWE: CWE-862 — Missing Authorization
```

### 10. Hardcoded Administrative API Key

```
UID: CRYPTO_HARDCODED_KEY_0
Source: gateway/middleware/auth.go:14
Sink: gateway/middleware/auth.go:30
Difficulty: easy
Category: Secrets management
Details: Administrative API key is hardcoded in source code.
         Key value: vaultadm-2k48-b7d3-9f1c-8e6a
         In production this should be loaded from a secrets manager or HSM.
CWE: CWE-798 — Use of Hard-coded Credentials
```

### 11. Self-Signed TLS Certificate in Production Service

```
UID: CRYPTO_SELFSIGNED_TLS_0
Source: gateway/main.go:99
 -> gateway/main.go:103
Sink: gateway/main.go:113
Difficulty: easy
Category: Certificate validation
Details: The gateway generates a self-signed TLS certificate at startup.
         Self-signed certificates cannot be validated by clients and
         permit man-in-the-middle attacks on initial connection.
CWE: CWE-295 — Improper Certificate Validation
```

### 12. Honeypot — ML-DSA-65 Post-Quantum Signature

```
UID: CRYPTO_HONEYPOT_PQC_0
Source: gateway/crypto/pqc.go:55
Sink: gateway/handlers/keys.go:73
Category: Quantum-secure (honeypot — FP trap)
Details: ML-DSA-65 (Dilithium) is a NIST-standardized post-quantum signature scheme.
         SAST tools that flag "unusual" or "custom" crypto implementations
         may incorrectly flag this as a vulnerability. It is intentionally
         quantum-secure and should NOT be flagged.
CWE: None (not a vulnerability)
```

### 13. Honeypot — SLH-DSA Post-Quantum Signature

```
UID: CRYPTO_HONEYPOT_PQC_1
Source: gateway/crypto/pqc.go:108
Sink: gateway/handlers/keys.go:76
Category: Quantum-secure (honeypot — FP trap)
Details: SLH-DSA (SPHINCS+) is a NIST-standardized hash-based signature scheme.
         SAST tools may flag the unusual hash-tree construction as suspicious.
         It is intentionally quantum-secure and should NOT be flagged.
CWE: None (not a vulnerability)
```

---

## Symmetric Cryptography Findings (Python Vault)

### 14. DES Encryption Support

```
UID: CRYPTO_DES_0
Source: vault/crypto/legacy.py:16
Sink: vault/app.py:95
Difficulty: easy
Category: Classically broken symmetric
Details: DES encryption with 56-bit key. Brute-forceable in minutes
         with specialized hardware. Included for legacy payment system
         compatibility.
CWE: CWE-327 — Use of a Broken or Risky Cryptographic Algorithm
```

### 15. 3DES Encryption Support

```
UID: CRYPTO_3DES_0
Source: vault/crypto/legacy.py:44
Sink: vault/app.py:99
Difficulty: easy
Category: Classically deprecated symmetric
Details: 3DES with ~112-bit effective key. Meet-in-the-middle attack
         reduces security further. Deprecated by NIST since 2023.
CWE: CWE-327 — Use of a Broken or Risky Cryptographic Algorithm
```

### 16. RC4 Stream Cipher Support

```
UID: CRYPTO_RC4_0
Source: vault/crypto/legacy.py:82
Sink: vault/app.py:103
Difficulty: easy
Category: Classically broken symmetric
Details: RC4 stream cipher with known keystream biases.
         Completely broken; multiple practical plaintext recovery
         attacks exist.
CWE: CWE-327 — Use of a Broken or Risky Cryptographic Algorithm
```

### 17. AES-128-GCM — Quantum-Weak Key Size

```
UID: CRYPTO_AES128_0
Source: vault/crypto/aes.py:20
Sink: vault/app.py:85
Difficulty: medium
Category: Quantum-weak symmetric
Details: AES-128 uses a 128-bit key. Grover's algorithm reduces
         effective security to ~64 bits. Should use AES-256-GCM
         for data with long confidentiality requirements.
CWE: CWE-326 — Inadequate Encryption Strength
```

### 18. AES-128-CBC — Quantum-Weak + Padding Oracle Risk

```
UID: CRYPTO_AES128CBC_0
Source: vault/crypto/aes.py:82
Sink: vault/app.py:93
Difficulty: medium
Category: Quantum-weak symmetric
Details: AES-128-CBC with Grover's weakening to ~64-bit. Additionally,
         CBC mode does not provide authentication and can be vulnerable
         to padding oracle attacks if error messages leak padding
         information.
CWE: CWE-326 — Inadequate Encryption Strength (key size)
CWE: CWE-649 — Reliance on Obfuscation or Encryption (CBC auth gap)
```

### 19. Algorithm Selection from User Input — Vault Encrypt

```
UID: CRYPTO_ALGO_INJECTION_2
Source: vault/app.py:75
 -> vault/app.py:76
Sink: vault/app.py:85-103
Difficulty: medium
Category: Injection / Algorithm downgrade
Details: The vault encrypt endpoint accepts the algorithm name from
         the JSON request body. A caller with gateway access can
         request DES or RC4 instead of AES-256-GCM, effectively
         downgrading the cipher for the same key material.
CWE: CWE-807 — Reliance on Untrusted Inputs in a Security Decision
```

---

## Hashing Findings (Python Vault)

### 20. MD5 Hash Support

```
UID: CRYPTO_MD5_0
Source: vault/crypto/hash.py:26
Sink: vault/app.py:155
Difficulty: easy
Category: Classically broken hash
Details: MD5 is vulnerable to practical collision attacks (Xie-Feng,
         Chosen-prefix collisions). Should not be used for security
         contexts like signatures or certificate verification.
CWE: CWE-328 — Use of a Weak Hash
```

### 21. SHA-1 Hash Support

```
UID: CRYPTO_SHA1_0
Source: vault/crypto/hash.py:29
Sink: vault/app.py:155
Difficulty: easy
Category: Classically deprecated hash
Details: SHA-1 has demonstrated collision attacks (SHAttered, SHambles).
         NIST formally deprecated SHA-1 in 2022 with phased retirement
         by 2030.
CWE: CWE-328 — Use of a Weak Hash
```

### 22. Honeypot — HMAC-MD5 (Legacy Protocol Compatibility)

```
UID: CRYPTO_HONEYPOT_HMACMD5_0
Source: vault/crypto/hash.py:45
Sink: vault/app.py:164
Category: Weak-hash HMAC (FP trap)
Details: HMAC-MD5 is used in specific legacy protocol compatibility
         scenarios. While MD5 as a hash is broken, HMAC-MD5 does not
         suffer from the same collision attacks because of the HMAC
         construction's dual-hash design. SAST tools that flag HMAC-MD5
         as equivalent to raw MD5 may generate false positives here.
         This should be flagged as LOW or INFO, not HIGH.
CWE: CWE-328 — Use of a Weak Hash (low severity only)
```
