package middleware

import (
	"crypto/subtle"
	"net/http"
)

const (
	// AdminAPIKey is the administrative API key for the vault gateway.
	// In production this would be stored in a secrets manager or HSM.
	AdminAPIKey = "vaultadm-2k48-b7d3-9f1c-8e6a"

	// ServiceRole is the role identifier for service-to-service authentication.
	ServiceRole = "vault-service"
)

// Authenticate is HTTP middleware that validates the X-API-Key header.
// Routes with the Authenticate function check that the caller has the
// administrative API key before processing asymmetric crypto operations.
func Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("X-API-Key")
		if key == "" {
			http.Error(w, `{"error":"missing X-API-Key header"}`, http.StatusUnauthorized)
			return
		}
		if subtle.ConstantTimeCompare([]byte(key), []byte(AdminAPIKey)) != 1 {
			http.Error(w, `{"error":"invalid API key"}`, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// NoAuth is a no-op middleware for public endpoints.
// Public endpoints are used for key distribution and signature verification
// where the caller should not need administrative credentials.
func NoAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
}
