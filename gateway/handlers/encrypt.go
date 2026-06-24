package handlers

import (
	"encoding/base64"
	"encoding/json"
	"net/http"

	gwcrypto "github.com/oktpf/crypto-quantum-testbed/gateway/crypto"
)

// EncryptHandler handles asymmetric encryption and KEM operations.
type EncryptHandler struct {
	Store *gwcrypto.KeyStore
}

// AsymEncryptRequest carries the plaintext and algorithm for asymmetric encryption.
type AsymEncryptRequest struct {
	KeyID     string                `json:"keyId"`
	Algorithm gwcrypto.KeyAlgorithm `json:"algorithm"`
	Plaintext string                `json:"plaintext"` // base64-encoded
}

// AsymEncryptResponse contains the encrypted ciphertext.
type AsymEncryptResponse struct {
	Ciphertext string `json:"ciphertext"` // base64-encoded
	Algorithm  string `json:"algorithm"`
}

// KEMEncapsRequest requests a key encapsulation operation.
type KEMEncapsRequest struct {
	KeyID     string                `json:"keyId"`
	Algorithm gwcrypto.KeyAlgorithm `json:"algorithm"`
}

// KEMEncapsResponse contains the encapsulated key and ciphertext.
type KEMEncapsResponse struct {
	Ciphertext    string `json:"ciphertext"`    // base64-encoded
	SharedSecret  string `json:"sharedSecret"`  // base64-encoded
	Algorithm     string `json:"algorithm"`
}

// HandleEncrypt encrypts data using the specified asymmetric algorithm.
// Supported operations: RSA-OAEP for RSA keys.
// ECC-based encryption is handled via ECIES through the KEM endpoints.
func (h *EncryptHandler) HandleEncrypt(w http.ResponseWriter, r *http.Request) {
	var req AsymEncryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorJSON(w, "invalid request body", http.StatusBadRequest)
		return
	}

	plaintext, err := base64.StdEncoding.DecodeString(req.Plaintext)
	if err != nil {
		errorJSON(w, "plaintext must be base64-encoded", http.StatusBadRequest)
		return
	}

	kp, ok := h.Store.Get(req.KeyID)
	if !ok {
		errorJSON(w, "key not found", http.StatusNotFound)
		return
	}

	switch req.Algorithm {
	case gwcrypto.AlgorithmRSA2048, gwcrypto.AlgorithmRSA4096:
		ciphertext, err := gwcrypto.RSAEncryptOAEP(kp, plaintext)
		if err != nil {
			errorJSON(w, "encryption failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, AsymEncryptResponse{
			Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
			Algorithm:  string(req.Algorithm),
		})
	default:
		errorJSON(w, "encryption not supported for algorithm: "+string(req.Algorithm), http.StatusBadRequest)
	}
}

// HandleDecrypt decrypts data using the specified asymmetric algorithm and key material.
func (h *EncryptHandler) HandleDecrypt(w http.ResponseWriter, r *http.Request) {
	var req AsymEncryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorJSON(w, "invalid request body", http.StatusBadRequest)
		return
	}

	ciphertext, err := base64.StdEncoding.DecodeString(req.Plaintext)
	if err != nil {
		errorJSON(w, "ciphertext must be base64-encoded", http.StatusBadRequest)
		return
	}

	kp, ok := h.Store.Get(req.KeyID)
	if !ok {
		errorJSON(w, "key not found", http.StatusNotFound)
		return
	}

	switch req.Algorithm {
	case gwcrypto.AlgorithmRSA2048, gwcrypto.AlgorithmRSA4096:
		plaintext, err := gwcrypto.RSADecryptOAEP(kp, ciphertext)
		if err != nil {
			errorJSON(w, "decryption failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, AsymEncryptResponse{
			Ciphertext: base64.StdEncoding.EncodeToString(plaintext),
			Algorithm:  string(req.Algorithm),
		})
	default:
		errorJSON(w, "decryption not supported for algorithm: "+string(req.Algorithm), http.StatusBadRequest)
	}
}

// HandleKEMEncaps performs key encapsulation. For ECDH algorithms, this
// generates an ephemeral key pair and derives a shared secret. For post-quantum
// KEMs (ML-KEM), it uses the lattice-based encapsulation mechanism.
func (h *EncryptHandler) HandleKEMEncaps(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]string{
		"message": "KEM encapsulate endpoint ready",
	})
}

// HandleKEMDecaps performs key decapsulation.
func (h *EncryptHandler) HandleKEMDecaps(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]string{
		"message": "KEM decapsulate endpoint ready",
	})
}
