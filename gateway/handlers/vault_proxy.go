package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	vaultBackendURL = "http://localhost:9090"
	proxyTimeout    = 30 * time.Second
)

// VaultProxyHandler proxies symmetric crypto requests to the vault backend.
// The vault runs as a separate microservice handling all symmetric encryption,
// hashing, and key wrapping operations. This separation allows the asymmetric
// gateway to focus on key management while the vault handles bulk data operations.
type VaultProxyHandler struct {
	client *http.Client
}

// NewVaultProxyHandler creates a proxy handler for the vault backend.
func NewVaultProxyHandler() *VaultProxyHandler {
	return &VaultProxyHandler{
		client: &http.Client{
			Timeout: proxyTimeout,
		},
	}
}

// ProxyEncrypt forwards an encryption request to the vault backend.
// The vault supports multiple symmetric algorithms: AES-128-GCM, AES-256-GCM,
// ChaCha20-Poly1305, AES-128-CBC, DES, and RC4. The algorithm, key material,
// and plaintext are provided in the request body and forwarded as-is.
func (h *VaultProxyHandler) ProxyEncrypt(w http.ResponseWriter, r *http.Request) {
	h.proxyToVault(w, r, "/vault/encrypt")
}

// ProxyDecrypt forwards a decryption request to the vault backend.
func (h *VaultProxyHandler) ProxyDecrypt(w http.ResponseWriter, r *http.Request) {
	h.proxyToVault(w, r, "/vault/decrypt")
}

// ProxyHash forwards a hashing request to the vault backend.
// Supported hash algorithms: SHA-256, SHA-384, SHA-512, MD5, SHA-1.
func (h *VaultProxyHandler) ProxyHash(w http.ResponseWriter, r *http.Request) {
	h.proxyToVault(w, r, "/vault/hash")
}

// ProxyHMAC forwards an HMAC request to the vault backend.
func (h *VaultProxyHandler) ProxyHMAC(w http.ResponseWriter, r *http.Request) {
	h.proxyToVault(w, r, "/vault/hmac")
}

func (h *VaultProxyHandler) proxyToVault(w http.ResponseWriter, r *http.Request, path string) {
	// Read the incoming request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		errorJSON(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	// Create the proxied request to the vault backend
	vaultURL := fmt.Sprintf("%s%s", vaultBackendURL, path)
	proxyReq, err := http.NewRequestWithContext(r.Context(), "POST", vaultURL, bytes.NewReader(body))
	if err != nil {
		errorJSON(w, "failed to create proxy request", http.StatusInternalServerError)
		return
	}
	proxyReq.Header.Set("Content-Type", "application/json")

	// Send the request to the vault
	resp, err := h.client.Do(proxyReq)
	if err != nil {
		errorJSON(w, fmt.Sprintf("vault backend unavailable: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Read and forward the vault response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		errorJSON(w, "failed to read vault response", http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

// VaultHealthCheck returns the health status of the vault backend.
func (h *VaultProxyHandler) VaultHealthCheck(w http.ResponseWriter, r *http.Request) {
	resp, err := h.client.Get(vaultBackendURL + "/health")
	if err != nil {
		errorJSON(w, fmt.Sprintf("vault unreachable: %v", err), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	var health map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&health)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"gateway": "ok",
		"vault":   health,
	})
}
