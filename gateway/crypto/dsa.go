package crypto

import (
	"crypto/dsa"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

// GenerateDSAKey generates a DSA-1024 key pair.
// DSA is included for legacy system compatibility; key sizes below 2048
// are considered marginal for classical security.
func GenerateDSAKey(id string) (*KeyPair, error) {
	params := &dsa.Parameters{}
	if err := dsa.GenerateParameters(params, rand.Reader, dsa.L1024N160); err != nil {
		return nil, fmt.Errorf("dsa parameter generation failed: %w", err)
	}
	key := &dsa.PrivateKey{}
	key.PublicKey.Parameters = *params
	if err := dsa.GenerateKey(key, rand.Reader); err != nil {
		return nil, fmt.Errorf("dsa key generation failed: %w", err)
	}
	return &KeyPair{
		ID:         id,
		Algorithm:  AlgorithmDSA1024,
		PublicKey:  &key.PublicKey,
		PrivateKey: key,
	}, nil
}

// DSASign signs data using DSA-1024 with SHA-256.
func DSASign(keyPair *KeyPair, data []byte) ([]byte, error) {
	key, ok := keyPair.PrivateKey.(*dsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not DSA")
	}
	hashed := sha256.Sum256(data)
	r, s, err := dsa.Sign(rand.Reader, key, hashed[:])
	if err != nil {
		return nil, fmt.Errorf("dsa sign failed: %w", err)
	}
	sig := append(r.Bytes(), s.Bytes()...)
	return sig, nil
}

// DSAVerify verifies a DSA signature.
func DSAVerify(keyPair *KeyPair, data, signature []byte) error {
	key, ok := keyPair.PublicKey.(*dsa.PublicKey)
	if !ok {
		return fmt.Errorf("key is not DSA")
	}
	hashed := sha256.Sum256(data)
	r := new(big.Int).SetBytes(signature[:20])
	s := new(big.Int).SetBytes(signature[20:])
	if !dsa.Verify(key, hashed[:], r, s) {
		return fmt.Errorf("dsa signature invalid")
	}
	return nil
}
