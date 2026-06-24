package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/oktpf/crypto-quantum-testbed/gateway/crypto"
	"github.com/oktpf/crypto-quantum-testbed/gateway/handlers"
	"github.com/oktpf/crypto-quantum-testbed/gateway/middleware"
)

const (
	defaultPort = "8443"
)

func main() {
	port := os.Getenv("GATEWAY_PORT")
	if port == "" {
		port = defaultPort
	}

	store := crypto.NewKeyStore()
	keyHandler := &handlers.KeyHandler{Store: store}
	signHandler := &handlers.SignHandler{Store: store}
	encryptHandler := &handlers.EncryptHandler{Store: store}
	vaultProxy := handlers.NewVaultProxyHandler()

	mux := http.NewServeMux()

	// Key management endpoints (require authentication)
	mux.HandleFunc("/api/v1/keys/generate", middleware.Authenticate(http.HandlerFunc(keyHandler.HandleGenerate)).ServeHTTP)
	mux.HandleFunc("/api/v1/keys/list", middleware.Authenticate(http.HandlerFunc(keyHandler.HandleList)).ServeHTTP)
	mux.HandleFunc("/api/v1/keys/", middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "DELETE" {
			keyHandler.HandleDelete(w, r)
			return
		}
		http.NotFound(w, r)
	})).ServeHTTP)

	// Public key distribution (no authentication required)
	mux.HandleFunc("/api/v1/public-keys/", middleware.NoAuth(http.HandlerFunc(keyHandler.HandleGetPublicKey)).ServeHTTP)

	// Signing endpoints (authenticated)
	mux.HandleFunc("/api/v1/sign", middleware.Authenticate(http.HandlerFunc(signHandler.HandleSign)).ServeHTTP)

	// Verification endpoints
	mux.HandleFunc("/api/v1/verify", middleware.Authenticate(http.HandlerFunc(signHandler.HandleVerify)).ServeHTTP)
	mux.HandleFunc("/api/v1/verify/public", middleware.NoAuth(http.HandlerFunc(signHandler.HandleVerifyPublic)).ServeHTTP)

	// Asymmetric encryption endpoints (authenticated)
	mux.HandleFunc("/api/v1/encrypt", middleware.Authenticate(http.HandlerFunc(encryptHandler.HandleEncrypt)).ServeHTTP)
	mux.HandleFunc("/api/v1/decrypt", middleware.Authenticate(http.HandlerFunc(encryptHandler.HandleDecrypt)).ServeHTTP)

	// KEM endpoints (authenticated)
	mux.HandleFunc("/api/v1/kem/encaps", middleware.Authenticate(http.HandlerFunc(encryptHandler.HandleKEMEncaps)).ServeHTTP)
	mux.HandleFunc("/api/v1/kem/decaps", middleware.Authenticate(http.HandlerFunc(encryptHandler.HandleKEMDecaps)).ServeHTTP)

	// Vault proxy endpoints (authenticated — forwards to symmetric crypto backend)
	mux.HandleFunc("/api/v1/vault/encrypt", middleware.Authenticate(http.HandlerFunc(vaultProxy.ProxyEncrypt)).ServeHTTP)
	mux.HandleFunc("/api/v1/vault/decrypt", middleware.Authenticate(http.HandlerFunc(vaultProxy.ProxyDecrypt)).ServeHTTP)
	mux.HandleFunc("/api/v1/vault/hash", middleware.Authenticate(http.HandlerFunc(vaultProxy.ProxyHash)).ServeHTTP)
	mux.HandleFunc("/api/v1/vault/hmac", middleware.Authenticate(http.HandlerFunc(vaultProxy.ProxyHMAC)).ServeHTTP)

	// Health check
	mux.HandleFunc("/health", middleware.NoAuth(http.HandlerFunc(vaultProxy.VaultHealthCheck)).ServeHTTP)
	mux.HandleFunc("/api/v1/health", middleware.NoAuth(http.HandlerFunc(vaultProxy.VaultHealthCheck)).ServeHTTP)

	// Generate self-signed TLS certificate for testing
	cert, err := generateSelfSignedCert()
	if err != nil {
		log.Fatalf("failed to generate TLS certificate: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	server := &http.Server{
		Addr:         fmt.Sprintf(":%s", port),
		Handler:      mux,
		TLSConfig:    tlsConfig,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	log.Printf("Crypto Vault Gateway starting on :%s", port)
	log.Printf("TLS enabled with self-signed certificate")
	log.Printf("Public key endpoint: GET /api/v1/public-keys/{keyId}")
	log.Printf("Signing endpoint: POST /api/v1/sign")
	log.Printf("Verification endpoint: POST /api/v1/verify")
	log.Printf("Asymmetric encrypt: POST /api/v1/encrypt")
	log.Printf("Vault proxy (symmetric): POST /api/v1/vault/{encrypt,decrypt,hash,hmac}")

	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

// generateSelfSignedCert creates a development TLS certificate.
// In production, certificates would be issued by a trusted CA.
func generateSelfSignedCert() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate key: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Crypto Vault Gateway"},
			CommonName:   "vault-gateway.local",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", "vault-gateway.local"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to create certificate: %w", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}, nil
}
