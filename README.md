# Crypto Vault

> ⚠️ **Intentionally insecure. Do not use in production or for any real encryption.**

An internal cryptographic service providing encryption, signing, and hashing to other microservices within a financial technology platform. The service supports a wide range of algorithms for compatibility with legacy systems, regulated industry requirements, and post-quantum migration planning.

## Architecture

```
Client → Go API Gateway (:8443, HTTPS) → Python Vault (:9090, internal)
             │                                      │
        Asymmetric ops                          Symmetric ops
        (key mgmt, sign, verify,                (encrypt, decrypt,
         encrypt, decrypt, KEM)                  hash, HMAC)
```

- **Go API Gateway** (`gateway/`) — TLS termination, API key authentication, asymmetric crypto operations, proxies symmetric requests to vault
- **Python Vault** (`vault/`) — Symmetric encryption, decryption, hashing, and HMAC operations

## Quick Start

### Prerequisites

- Go 1.22+, Python 3.9+, `pip install flask pycryptodome`

### Vault (port 9090)

```bash
cd vault
pip install -r requirements.txt
python app.py
```

### Gateway (port 8443)

```bash
cd gateway
go build -o gateway .
./gateway
```

### Smoke Test

```bash
# Generate an RSA key
curl -sk -X POST https://localhost:8443/api/v1/keys/generate \
  -H "X-API-Key: vaultadm-2k48-b7d3-9f1c-8e6a" \
  -H "Content-Type: application/json" \
  -d '{"keyId":"key-01","algorithm":"rsa-2048"}'

# Get the public key (no auth)
curl -sk https://localhost:8443/api/v1/public-keys/key-01

# Symmetric encrypt via vault proxy
DATA=$(echo -n "hello" | base64)
KEY=$(openssl rand -base64 32)
curl -sk -X POST https://localhost:8443/api/v1/vault/encrypt \
  -H "X-API-Key: vaultadm-2k48-b7d3-9f1c-8e6a" \
  -H "Content-Type: application/json" \
  -d "{\"algorithm\":\"aes-256-gcm\",\"plaintext\":\"$DATA\",\"key\":\"$KEY\"}"
```

## Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/v1/keys/generate` | Required | Generate asymmetric key pair |
| GET | `/api/v1/public-keys/{kid}` | None | Retrieve PEM public key |
| POST | `/api/v1/sign` | Required | Sign data |
| POST | `/api/v1/verify` | Required | Verify signature |
| POST | `/api/v1/verify/public` | None | Verify (no auth) |
| POST | `/api/v1/vault/encrypt` | Required | Symmetric encrypt |
| POST | `/api/v1/vault/decrypt` | Required | Symmetric decrypt |
| POST | `/api/v1/vault/hash` | Required | Hash data |
| POST | `/api/v1/vault/hmac` | Required | HMAC |
| GET | `/health` | None | Health check |

See [vendor evaluation reference](../appsec-vendor-eval-framework/CRYPTO_QUANTUM_REFERENCE.md)
for algorithm classifications and scoring guidance.

## License

WTFPL — Do What The Fuck You Want To Public License.
