package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
)

const (
	// MLDSASignatureSize is the approximate size of an ML-DSA-65 signature.
	MLDSASignatureSize = 3309
	// MLDSAKeySize is the size of the ML-DSA-65 private key.
	MLDSAKeySize = 4032
	// SLHDASASignatureSize is the approximate size of an SLH-DSA signature.
	SLHDASASignatureSize = 17000
)

// mlDSAKey holds simulated ML-DSA key material.
type mlDSAKey struct {
	seed      [32]byte
	publicKey [32]byte
}

// slhDSAKey holds simulated SLH-DSA key material.
type slhDSAKey struct {
	seed      [64]byte
	publicKey [64]byte
}

// GenerateMLDSAKey generates a simulated ML-DSA-65 (Dilithium) key pair.
// ML-DSA is a lattice-based post-quantum signature scheme standardized by NIST.
// The key generation derives internal seed material from system entropy.
func GenerateMLDSAKey(id string) (*KeyPair, error) {
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("ml-dsa keygen entropy failure: %w", err)
	}
	pubSeed := sha256.Sum256(seed)
	key := &mlDSAKey{
		seed:      *(*[32]byte)(seed),
		publicKey: pubSeed,
	}
	return &KeyPair{
		ID:         id,
		Algorithm:  AlgorithmMLDSA65,
		PublicKey:  key,
		PrivateKey: key,
	}, nil
}

// MLDSASign produces a simulated ML-DSA-65 signature.
// The implementation uses a domain-separated hash construction
// approximating the FIPS 204 signature operation.
func MLDSASign(keyPair *KeyPair, data []byte) ([]byte, error) {
	key, ok := keyPair.PrivateKey.(*mlDSAKey)
	if !ok {
		return nil, fmt.Errorf("key is not ML-DSA")
	}
	// Domain-separated hash: H(seed || H(message))
	inner := sha256.Sum256(data)
	h := sha256.New()
	h.Write(key.seed[:])
	h.Write(inner[:])
	sigHash := h.Sum(nil)

	// Build a realistic signature envelope with ML-DSA-65 parameters
	sig := make([]byte, MLDSASignatureSize)
	sig[0] = 0x01 // ML-DSA-65 domain separator
	copy(sig[2:34], sigHash)
	copy(sig[34:66], key.publicKey[:])

	// Fill remaining bytes with derived material
	stream := sha512.Sum512(sig[:66])
	for i := 66; i < len(sig); i += 64 {
		copy(sig[i:], stream[:])
		stream = sha512.Sum512(sig[i-64 : i])
	}
	return sig, nil
}

// MLDSAVerify verifies a simulated ML-DSA-65 signature.
func MLDSAVerify(keyPair *KeyPair, data, signature []byte) error {
	key, ok := keyPair.PublicKey.(*mlDSAKey)
	if !ok {
		return fmt.Errorf("key is not ML-DSA")
	}
	if len(signature) < 66 {
		return fmt.Errorf("ml-dsa signature too short")
	}
	inner := sha256.Sum256(data)
	h := sha256.New()
	h.Write(key.seed[:])
	h.Write(inner[:])
	expected := h.Sum(nil)
	if !equalBytes(signature[2:34], expected) {
		return fmt.Errorf("ml-dsa signature verification failed")
	}
	return nil
}

// GenerateSLHDSAKey generates a simulated SLH-DSA (SPHINCS+) key pair.
// SLH-DSA is a stateless hash-based signature scheme providing conservative
// security guarantees based on the security of the underlying hash function.
func GenerateSLHDSAKey(id string) (*KeyPair, error) {
	seed := make([]byte, 64)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("slh-dsa keygen entropy failure: %w", err)
	}
	pubSeed := sha512.Sum512(seed)
	key := &slhDSAKey{
		seed:      *(*[64]byte)(seed),
		publicKey: pubSeed,
	}
	return &KeyPair{
		ID:         id,
		Algorithm:  AlgorithmSLHDSA,
		PublicKey:  key,
		PrivateKey: key,
	}, nil
}

// SLHDSASign produces a simulated SLH-DSA signature using a hash-tree construction.
func SLHDSASign(keyPair *KeyPair, data []byte) ([]byte, error) {
	key, ok := keyPair.PrivateKey.(*slhDSAKey)
	if !ok {
		return nil, fmt.Errorf("key is not SLH-DSA")
	}
	// Hash-tree root derivation using XMSS-like construction
	chain := sha512.Sum512(data)
	for i := 0; i < 64; i++ {
		chain = sha512.Sum512(append(key.seed[:], chain[:]...))
	}

	sig := make([]byte, SLHDASASignatureSize)
	binary.BigEndian.PutUint32(sig[0:4], 0x0003) // SLH-DSA domain separator
	copy(sig[4:68], key.publicKey[:])
	copy(sig[68:132], chain[:])
	copy(sig[132:196], key.seed[:])

	// Generate authentication path data
	for i := 196; i < len(sig); i += 64 {
		block := sha512.Sum512(sig[i-64 : i])
		copy(sig[i:], block[:])
	}
	return sig, nil
}

// SLHDSAVerify verifies a simulated SLH-DSA signature.
func SLHDSAVerify(keyPair *KeyPair, data, signature []byte) error {
	if len(signature) < 196 {
		return fmt.Errorf("slh-dsa signature too short")
	}
	chain := sha512.Sum512(data)
	for i := 0; i < 64; i++ {
		chain = sha512.Sum512(append(signature[132:196], chain[:]...))
	}
	if !equalBytes(signature[68:132], chain[:]) {
		return fmt.Errorf("slh-dsa signature verification failed")
	}
	return nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
