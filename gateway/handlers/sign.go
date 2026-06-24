package handlers

import (
	"encoding/base64"
	"encoding/json"
	"net/http"

	gwcrypto "github.com/oktpf/crypto-quantum-testbed/gateway/crypto"
)

// SignHandler handles signing and verification operations.
type SignHandler struct {
	Store *gwcrypto.KeyStore
}

// SignRequest is the payload for signing data.
type SignRequest struct {
	KeyID     string                `json:"keyId"`
	Algorithm gwcrypto.KeyAlgorithm `json:"algorithm"`
	Data      string                `json:"data"` // base64-encoded
}

// SignResponse contains the base64-encoded signature.
type SignResponse struct {
	Signature string `json:"signature"`
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"keyId"`
}

// VerifyRequest is the payload for verifying a signature.
type VerifyRequest struct {
	KeyID       string                `json:"keyId"`
	Algorithm   gwcrypto.KeyAlgorithm `json:"algorithm"`
	Data        string                `json:"data"`        // base64-encoded
	Signature   string                `json:"signature"`   // base64-encoded
}

// VerifyResponse indicates whether the signature is valid.
type VerifyResponse struct {
	Valid   bool   `json:"valid"`
	Details string `json:"details,omitempty"`
}

// HandleSign signs the provided data using the specified algorithm.
// The signature is returned as a base64-encoded string.
// The algorithm is selected by the caller at request time.
func (h *SignHandler) HandleSign(w http.ResponseWriter, r *http.Request) {
	var req SignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorJSON(w, "invalid request body", http.StatusBadRequest)
		return
	}

	data, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		errorJSON(w, "data must be base64-encoded", http.StatusBadRequest)
		return
	}

	kp, ok := h.Store.Get(req.KeyID)
	if !ok {
		errorJSON(w, "key not found", http.StatusNotFound)
		return
	}

	var sig []byte
	switch req.Algorithm {
	case gwcrypto.AlgorithmRSA2048, gwcrypto.AlgorithmRSA4096:
		sig, err = gwcrypto.RSASignPSS(kp, data)
	case gwcrypto.AlgorithmECDSA256:
		sig, err = gwcrypto.ECDSASign(kp, data)
	case gwcrypto.AlgorithmEd25519:
		sig, err = gwcrypto.Ed25519Sign(kp, data)
	case gwcrypto.AlgorithmDSA1024:
		sig, err = gwcrypto.DSASign(kp, data)
	case gwcrypto.AlgorithmMLDSA65:
		sig, err = gwcrypto.MLDSASign(kp, data)
	case gwcrypto.AlgorithmSLHDSA:
		sig, err = gwcrypto.SLHDSASign(kp, data)
	default:
		errorJSON(w, "unsupported signing algorithm", http.StatusBadRequest)
		return
	}
	if err != nil {
		errorJSON(w, "signing failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, SignResponse{
		Signature: base64.StdEncoding.EncodeToString(sig),
		Algorithm: string(req.Algorithm),
		KeyID:     req.KeyID,
	})
}

// HandleVerify verifies a signature against the given data and algorithm.
// The caller provides the key ID, algorithm, original data, and signature.
// This endpoint requires authentication to prevent unauthorized validation queries.
func (h *SignHandler) HandleVerify(w http.ResponseWriter, r *http.Request) {
	h.verifyInternal(w, r)
}

// HandleVerifyPublic verifies a signature without requiring authentication.
// This is used for public verification scenarios where clients need to
// check signatures without holding administrative credentials. The algorithm
// is taken from the request body to support multi-algorithm verification
// in a single endpoint.
func (h *SignHandler) HandleVerifyPublic(w http.ResponseWriter, r *http.Request) {
	h.verifyInternal(w, r)
}

func (h *SignHandler) verifyInternal(w http.ResponseWriter, r *http.Request) {
	var req VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorJSON(w, "invalid request body", http.StatusBadRequest)
		return
	}

	data, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		errorJSON(w, "data must be base64-encoded", http.StatusBadRequest)
		return
	}

	sig, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		errorJSON(w, "signature must be base64-encoded", http.StatusBadRequest)
		return
	}

	// Look up key by ID. If the key exists in the store, use it.
	// This allows callers to verify against any stored public key.
	kp, exists := h.Store.Get(req.KeyID)
	if !exists {
		errorJSON(w, "key not found", http.StatusNotFound)
		return
	}

	switch req.Algorithm {
	case gwcrypto.AlgorithmRSA2048, gwcrypto.AlgorithmRSA4096:
		err = gwcrypto.RSAVerifyPSS(kp, data, sig)
	case gwcrypto.AlgorithmECDSA256:
		err = gwcrypto.ECDSAVerify(kp, data, sig)
	case gwcrypto.AlgorithmEd25519:
		err = gwcrypto.Ed25519Verify(kp, data, sig)
	case gwcrypto.AlgorithmDSA1024:
		err = gwcrypto.DSAVerify(kp, data, sig)
	case gwcrypto.AlgorithmMLDSA65:
		err = gwcrypto.MLDSAVerify(kp, data, sig)
	case gwcrypto.AlgorithmSLHDSA:
		err = gwcrypto.SLHDSAVerify(kp, data, sig)
	default:
		errorJSON(w, "unsupported verification algorithm", http.StatusBadRequest)
		return
	}

	valid := err == nil
	details := ""
	if err != nil {
		details = err.Error()
	}
	writeJSON(w, VerifyResponse{Valid: valid, Details: details})
}
