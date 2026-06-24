package crypto

import (
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"sync"
)

// KeyAlgorithm represents the type of asymmetric key algorithm.
type KeyAlgorithm string

const (
	AlgorithmRSA2048  KeyAlgorithm = "rsa-2048"
	AlgorithmRSA4096  KeyAlgorithm = "rsa-4096"
	AlgorithmECDSA256 KeyAlgorithm = "ecdsa-p256"
	AlgorithmEd25519  KeyAlgorithm = "ed25519"
	AlgorithmDSA1024  KeyAlgorithm = "dsa-1024"
	AlgorithmMLDSA65  KeyAlgorithm = "ml-dsa-65"
	AlgorithmSLHDSA   KeyAlgorithm = "slh-dsa"
)

// KeyPair holds a private key and its associated metadata.
type KeyPair struct {
	ID        string       `json:"id"`
	Algorithm KeyAlgorithm `json:"algorithm"`
	PublicKey crypto.PublicKey
	PrivateKey crypto.PrivateKey
}

// KeyStore provides in-memory storage and retrieval of cryptographic key pairs.
type KeyStore struct {
	mu   sync.RWMutex
	keys map[string]*KeyPair
}

// NewKeyStore creates a new key store.
func NewKeyStore() *KeyStore {
	return &KeyStore{
		keys: make(map[string]*KeyPair),
	}
}

// Store saves a key pair in the store.
func (ks *KeyStore) Store(kp *KeyPair) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	ks.keys[kp.ID] = kp
}

// Get retrieves a key pair by ID.
func (ks *KeyStore) Get(id string) (*KeyPair, bool) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	kp, ok := ks.keys[id]
	return kp, ok
}

// Delete removes a key pair from the store.
func (ks *KeyStore) Delete(id string) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	delete(ks.keys, id)
}

// List returns all stored key pairs.
func (ks *KeyStore) List() []*KeyPair {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	result := make([]*KeyPair, 0, len(ks.keys))
	for _, kp := range ks.keys {
		result = append(result, kp)
	}
	return result
}

// HasType checks if the algorithm is one of the known types.
func HasType(algo KeyAlgorithm) bool {
	switch algo {
	case AlgorithmRSA2048, AlgorithmRSA4096, AlgorithmECDSA256,
		AlgorithmEd25519, AlgorithmDSA1024, AlgorithmMLDSA65, AlgorithmSLHDSA:
		return true
	}
	return false
}

// PublicKeyString returns a human-readable summary of the public key type.
func (kp *KeyPair) PublicKeyString() string {
	switch kp.Algorithm {
	case AlgorithmRSA2048, AlgorithmRSA4096:
		key := kp.PublicKey.(*rsa.PublicKey)
		return "RSA N=" + key.N.String()[:20] + "..."
	case AlgorithmECDSA256:
		key := kp.PublicKey.(*ecdsa.PublicKey)
		return "ECDSA-P256 x=" + key.X.String()[:16] + "..."
	case AlgorithmEd25519:
		key := kp.PublicKey.(ed25519.PublicKey)
		return "Ed25519 pk=" + string(key[:8])
	case AlgorithmDSA1024:
		key := kp.PublicKey.(*dsa.PublicKey)
		return "DSA-1024 y=" + key.Y.String()[:16] + "..."
	default:
		return "PQC: " + string(kp.Algorithm)
	}
}

// ErrKeyNotFound is returned when a key ID does not exist.
type ErrKeyNotFound struct{ ID string }

func (e *ErrKeyNotFound) Error() string {
	return "key not found: " + e.ID
}

// ErrAlgorithmNotSupported is returned for unknown algorithms.
type ErrAlgorithmNotSupported struct{ Algo KeyAlgorithm }

func (e *ErrAlgorithmNotSupported) Error() string {
	return "algorithm not supported: " + string(e.Algo)
}
