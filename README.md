# Crypto Quantum Vault Testbed

A realistic cryptographic services platform built to evaluate SAST and SCA vendor detection of quantum-insecure, quantum-weak, and quantum-secure cryptographic patterns across asymmetric and symmetric algorithms.

## Business Context

The **Crypto Quantum Vault** is an internal cryptographic service providing encryption, signing, and hashing operations to other microservices within a financial technology platform. Its architecture mirrors real-world enterprise vault deployments:

- A **Go API Gateway** terminates TLS, manages asymmetric keys, and provides signing/verification endpoints
- A **Python Vault Backend** performs symmetric encryption, decryption, and hashing as an internal microservice
- The gateway proxies symmetric operations to the vault, maintaining separation of concerns

The service is designed to support a wide range of algorithms for compatibility with legacy systems, regulated industry requirements, and post-quantum migration planning.

## Architecture

```
External Client
      │
      │ HTTPS :8443
      ▼
┌─────────────────────────────────────┐
│  Go API Gateway                     │
│  ───────────────────────────────    │
│  • TLS termination                  │
│  • API key authentication           │
│  • Asymmetric crypto ops            │
│    (RSA, ECDSA, Ed25519, DSA,      │
│     ML-DSA, SLH-DSA)               │
│  • Proxies symmetric ops to vault  │
└──────────┬──────────────────────────┘
           │ HTTP :9090 (internal)
           ▼
┌─────────────────────────────────────┐
│  Python Vault Backend               │
│  ───────────────────────────────    │
│  • Symmetric encryption             │
│    (AES-128-GCM, AES-256-GCM,       │
│     ChaCha20-Poly1305, AES-128-CBC, │
│     DES, 3DES, RC4)                │
│  • Hashing                          │
│    (SHA-256, SHA-384, SHA-512,      │
│     MD5, SHA-1)                     │
│  • HMAC                             │
│    (HMAC-SHA256, HMAC-MD5)          │
└─────────────────────────────────────┘
```

## Endpoints

### Asymmetric (Go Gateway — port 8443)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/v1/keys/generate` | Required | Generate asymmetric key pair |
| GET | `/api/v1/public-keys/{kid}` | **None** | Retrieve PEM public key |
| GET | `/api/v1/keys/list` | Required | List stored key IDs |
| DELETE | `/api/v1/keys/{kid}` | Required | Delete key pair |
| POST | `/api/v1/sign` | Required | Sign data with private key |
| POST | `/api/v1/verify` | Required | Verify signature |
| POST | `/api/v1/verify/public` | **None** | Verify signature without auth |
| POST | `/api/v1/encrypt` | Required | Asymmetric encrypt (RSA-OAEP) |
| POST | `/api/v1/decrypt` | Required | Asymmetric decrypt (RSA-OAEP) |
| POST | `/api/v1/kem/encaps` | Required | Key encapsulation |
| POST | `/api/v1/kem/decaps` | Required | Key decapsulation |
| POST | `/api/v1/vault/encrypt` | Required | Symmetric encrypt (proxied) |
| POST | `/api/v1/vault/decrypt` | Required | Symmetric decrypt (proxied) |
| POST | `/api/v1/vault/hash` | Required | Hash data (proxied) |
| POST | `/api/v1/vault/hmac` | Required | HMAC (proxied) |
| GET | `/health` | None | Health check |

### Symmetric (Vault Backend — port 9090)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check with supported algorithms |
| POST | `/vault/encrypt` | Symmetric encryption |
| POST | `/vault/decrypt` | Symmetric decryption |
| POST | `/vault/hash` | Hashing |
| POST | `/vault/hmac` | HMAC |

## Algorithms by Quantum Security Category

### Asymmetric

| Algorithm | Quantum Status | Rationale | 
|-----------|---------------|-----------|
| RSA-2048 | **Quantum-insecure** | Factored by Shor's algorithm. 2048-bit modulus is well within CRQC range. |
| RSA-4096 | **Quantum-insecure** | Larger modulus delays but does not prevent Shor's attack. |
| ECDSA P-256 | **Quantum-insecure** | Small key size (256-bit) makes this the easiest Shor's target. |
| Ed25519 | **Quantum-insecure** | 256-bit curve — same Shor's vulnerability as ECDSA. |
| DSA-1024 | **Quantum-insecure** | 1024-bit discrete log broken by Shor's; also classically deprecated. |
| ML-DSA-65 (Dilithium) | **Quantum-secure** | Lattice-based, NIST FIPS 204 standardized. |
| SLH-DSA (SPHINCS+) | **Quantum-secure** | Hash-based, conservative security assumptions. |

### Symmetric

| Algorithm | Quantum Status | Rationale |
|-----------|---------------|-----------|
| AES-128-GCM | **Quantum-weak** | Grover's reduces 128-bit key to ~64-bit effective security. |
| AES-128-CBC | **Quantum-weak** | Same Grover's reduction as AES-128-GCM. |
| AES-256-GCM | **Quantum-secure** | 256-bit key retains ~128-bit post-quantum security. |
| ChaCha20-Poly1305 | **Quantum-secure** | 256-bit key retains ~128-bit post-quantum security. |
| DES | **Quantum-insecure** | 56-bit key — classically brute-forceable; Grover's not needed. |
| 3DES | **Quantum-insecure** | 112-bit effective key; meet-in-the-middle + Grover's. |
| RC4 | **Quantum-insecure** | Already broken classically (keystream biases). |

### Hashing

| Algorithm | Quantum Status | Rationale |
|-----------|---------------|-----------|
| MD5 | **Quantum-insecure** | Classical collision attacks exist; Grover's not relevant. |
| SHA-1 | **Quantum-insecure** | Classical collision attacks (SHAttered); Grover's further weakens. |
| SHA-256 | **Quantum-weak** | Grover's reduces preimage resistance from 256 to 128-bit. |
| SHA-384 | **Quantum-secure** | Suite B recommendation for post-quantum era. |
| SHA-512 | **Quantum-secure** | Sufficient margin against Grover's. |

## Building and Running

### Prerequisites

- Go 1.22+
- Python 3.9+
- Flask 3.x, pycryptodome 3.20+

### Start the Vault Backend

```bash
cd vault
pip install -r requirements.txt
python app.py
# Starts on http://localhost:9090
```

### Start the API Gateway

```bash
cd gateway
go build -o gateway .
./gateway
# Starts on https://localhost:8443 with self-signed TLS cert
```

### Test the Service

```bash
# Generate an RSA-2048 key
curl -sk -X POST https://localhost:8443/api/v1/keys/generate \
  -H "X-API-Key: vaultadm-2k48-b7d3-9f1c-8e6a" \
  -H "Content-Type: application/json" \
  -d '{"keyId":"key-rsa-01","algorithm":"rsa-2048"}'

# Get the public key (no auth required)
curl -sk https://localhost:8443/api/v1/public-keys/key-rsa-01

# Sign data
DATA=$(echo -n "transaction-data" | base64)
curl -sk -X POST https://localhost:8443/api/v1/sign \
  -H "X-API-Key: vaultadm-2k48-b7d3-9f1c-8e6a" \
  -H "Content-Type: application/json" \
  -d "{\"keyId\":\"key-rsa-01\",\"algorithm\":\"rsa-2048\",\"data\":\"$DATA\"}"

# Vault symmetric encrypt
PLAINTEXT=$(echo -n "sensitive-payload" | base64)
KEY=$(openssl rand -base64 32)
curl -sk -X POST https://localhost:8443/api/v1/vault/encrypt \
  -H "X-API-Key: vaultadm-2k48-b7d3-9f1c-8e6a" \
  -H "Content-Type: application/json" \
  -d "{\"algorithm\":\"aes-256-gcm\",\"plaintext\":\"$PLAINTEXT\",\"key\":\"$KEY\"}"
```

## Vulnerability Categorization

The testbed contains 20+ findings across these categories:

| Category | CWE | Count | Example |
|----------|-----|-------|---------|
| Weak asymmetric algorithm (quantum-insecure) | CWE-327 | 5 | RSA, ECDSA, Ed25519, DSA |
| Weak symmetric algorithm (classically broken) | CWE-327 | 3 | DES, 3DES, RC4 |
| Weak hash function | CWE-328 | 2 | MD5, SHA-1 |
| Weak key size (quantum-weak) | CWE-326 | 2 | AES-128, DSA-1024 |
| Algorithm selection from user input | CWE-807 | 4 | Vault and gateway accept `algorithm` from request |
| Missing authentication on public endpoint | CWE-862 | 2 | Public key view, verify/public |
| Hardcoded API key | CWE-798 | 1 | Gateway auth middleware |
| Self-signed TLS certificate | CWE-295 | 1 | Development cert in production |
| Hardcoded IV/nonce handling | CWE-330 | 1 | Static key references |

**Total findings: 21**
**Honeypots (FP traps):** 3 — Post-quantum algorithms (ML-DSA, SLH-DSA, ChaCha20) that are quantum-secure but may be misidentified by SAST tools as "unusual crypto."

## License

MIT
