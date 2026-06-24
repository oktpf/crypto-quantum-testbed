package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	gwcrypto "github.com/oktpf/crypto-quantum-testbed/gateway/crypto"
)

// KeyHandler handles key management operations.
type KeyHandler struct {
	Store *gwcrypto.KeyStore
}

// GenerateKeyRequest is the payload for generating a new key pair.
type GenerateKeyRequest struct {
	KeyID     string                `json:"keyId"`
	Algorithm gwcrypto.KeyAlgorithm `json:"algorithm"`
}

// KeyResponse is the standard key metadata response.
type KeyResponse struct {
	KeyID     string                `json:"keyId"`
	Algorithm gwcrypto.KeyAlgorithm `json:"algorithm"`
	PublicKey string                `json:"publicKey,omitempty"`
}

// errorJSON writes a JSON error response.
func errorJSON(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// writeJSON writes a JSON success response.
func writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

// HandleGenerate processes key generation requests.
// The caller specifies the key ID and algorithm. Supported algorithms include
// both classical (RSA, ECDSA, Ed25519) and post-quantum (ML-DSA, SLH-DSA) variants.
func (h *KeyHandler) HandleGenerate(w http.ResponseWriter, r *http.Request) {
	var req GenerateKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorJSON(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.KeyID == "" {
		errorJSON(w, "keyId is required", http.StatusBadRequest)
		return
	}
	if req.Algorithm == "" {
		errorJSON(w, "algorithm is required", http.StatusBadRequest)
		return
	}

	var kp *gwcrypto.KeyPair
	var err error
	switch req.Algorithm {
	case gwcrypto.AlgorithmRSA2048:
		kp, err = gwcrypto.GenerateRSAKey(req.KeyID, 2048, req.Algorithm)
	case gwcrypto.AlgorithmRSA4096:
		kp, err = gwcrypto.GenerateRSAKey(req.KeyID, 4096, req.Algorithm)
	case gwcrypto.AlgorithmECDSA256:
		kp, err = gwcrypto.GenerateECDSAKey(req.KeyID)
	case gwcrypto.AlgorithmEd25519:
		kp, err = gwcrypto.GenerateEd25519Key(req.KeyID)
	case gwcrypto.AlgorithmDSA1024:
		kp, err = gwcrypto.GenerateDSAKey(req.KeyID)
	case gwcrypto.AlgorithmMLDSA65:
		kp, err = gwcrypto.GenerateMLDSAKey(req.KeyID)
	case gwcrypto.AlgorithmSLHDSA:
		kp, err = gwcrypto.GenerateSLHDSAKey(req.KeyID)
	default:
		errorJSON(w, "unsupported algorithm: "+string(req.Algorithm), http.StatusBadRequest)
		return
	}
	if err != nil {
		errorJSON(w, "key generation failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	h.Store.Store(kp)
	writeJSON(w, KeyResponse{
		KeyID:     kp.ID,
		Algorithm: kp.Algorithm,
		PublicKey: kp.PublicKeyString(),
	})
}

// HandleGetPublicKey returns the PEM-encoded public key for a given key ID.
// This endpoint does not require authentication, as public keys are
// designed to be shared with clients and verifying parties.
func (h *KeyHandler) HandleGetPublicKey(w http.ResponseWriter, r *http.Request) {
	kid := strings.TrimPrefix(r.URL.Path, "/api/v1/public-keys/")
	// Strip any trailing slash
	kid = strings.TrimSuffix(kid, "/")

	if kid == "" {
		errorJSON(w, "key ID is required", http.StatusBadRequest)
		return
	}

	kp, ok := h.Store.Get(kid)
	if !ok {
		errorJSON(w, "key not found", http.StatusNotFound)
		return
	}

	var pubPEM string
	var err error
	switch kp.Algorithm {
	case gwcrypto.AlgorithmRSA2048, gwcrypto.AlgorithmRSA4096:
		pubPEM, err = gwcrypto.RSAExportPublicPEM(kp)
	case gwcrypto.AlgorithmECDSA256:
		pubPEM, err = gwcrypto.ECDSAExportPublicPEM(kp)
	case gwcrypto.AlgorithmEd25519:
		pubPEM, err = gwcrypto.Ed25519ExportPublicPEM(kp)
	case gwcrypto.AlgorithmMLDSA65:
		pubPEM = "-----BEGIN ML-DSA PUBLIC KEY-----\n" + kid + "\n-----END ML-DSA PUBLIC KEY-----"
	case gwcrypto.AlgorithmSLHDSA:
		pubPEM = "-----BEGIN SLH-DSA PUBLIC KEY-----\n" + kid + "\n-----END SLH-DSA PUBLIC KEY-----"
	default:
		pubPEM = kp.PublicKeyString()
	}
	if err != nil {
		errorJSON(w, "failed to export public key", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(pubPEM))
}

// HandleList returns all stored key IDs.
func (h *KeyHandler) HandleList(w http.ResponseWriter, r *http.Request) {
	keys := h.Store.List()
	resp := make([]KeyResponse, 0, len(keys))
	for _, kp := range keys {
		resp = append(resp, KeyResponse{
			KeyID:     kp.ID,
			Algorithm: kp.Algorithm,
		})
	}
	writeJSON(w, resp)
}

// HandleDelete removes a key pair from storage.
func (h *KeyHandler) HandleDelete(w http.ResponseWriter, r *http.Request) {
	kid := strings.TrimPrefix(r.URL.Path, "/api/v1/keys/")
	kid = strings.TrimSuffix(kid, "/delete")
	kid = strings.TrimSuffix(kid, "/")
	if kid == "" {
		errorJSON(w, "key ID is required", http.StatusBadRequest)
		return
	}
	h.Store.Delete(kid)
	writeJSON(w, map[string]string{"status": "deleted", "keyId": kid})
}
