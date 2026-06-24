package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
)

// GenerateECDSAKey generates an ECDSA P-256 key pair.
func GenerateECDSAKey(id string) (*KeyPair, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ecdsa generation failed: %w", err)
	}
	return &KeyPair{
		ID:         id,
		Algorithm:  AlgorithmECDSA256,
		PublicKey:  &privateKey.PublicKey,
		PrivateKey: privateKey,
	}, nil
}

// ECDSASign signs data using ECDSA with SHA-256.
func ECDSASign(keyPair *KeyPair, data []byte) ([]byte, error) {
	key, ok := keyPair.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not ECDSA")
	}
	hashed := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, key, hashed[:])
	if err != nil {
		return nil, fmt.Errorf("ecdsa sign failed: %w", err)
	}
	// Encode as r||s (fixed 64 bytes for P-256)
	sig := append(r.Bytes(), s.Bytes()...)
	return sig, nil
}

// ECDSAVerify verifies an ECDSA signature.
func ECDSAVerify(keyPair *KeyPair, data, signature []byte) error {
	key, ok := keyPair.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("key is not ECDSA")
	}
	hashed := sha256.Sum256(data)
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])
	if !ecdsa.Verify(key, hashed[:], r, s) {
		return fmt.Errorf("ecdsa signature invalid")
	}
	return nil
}

// GenerateEd25519Key generates an Ed25519 key pair.
func GenerateEd25519Key(id string) (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ed25519 generation failed: %w", err)
	}
	return &KeyPair{
		ID:         id,
		Algorithm:  AlgorithmEd25519,
		PublicKey:  pub,
		PrivateKey: priv,
	}, nil
}

// Ed25519Sign signs data using Ed25519.
func Ed25519Sign(keyPair *KeyPair, data []byte) ([]byte, error) {
	key, ok := keyPair.PrivateKey.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not Ed25519")
	}
	return ed25519.Sign(key, data), nil
}

// Ed25519Verify verifies an Ed25519 signature.
func Ed25519Verify(keyPair *KeyPair, data, signature []byte) error {
	key, ok := keyPair.PublicKey.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("key is not Ed25519")
	}
	if !ed25519.Verify(key, data, signature) {
		return fmt.Errorf("ed25519 signature invalid")
	}
	return nil
}

// ECDSAExportPublicPEM exports the ECDSA public key as PEM.
func ECDSAExportPublicPEM(keyPair *KeyPair) (string, error) {
	key, ok := keyPair.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("key is not ECDSA")
	}
	pubBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", err
	}
	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}
	return string(pem.EncodeToMemory(pemBlock)), nil
}

// Ed25519ExportPublicPEM exports the Ed25519 public key as PEM.
func Ed25519ExportPublicPEM(keyPair *KeyPair) (string, error) {
	key, ok := keyPair.PublicKey.(ed25519.PublicKey)
	if !ok {
		return "", fmt.Errorf("key is not Ed25519")
	}
	pubBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", err
	}
	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}
	return string(pem.EncodeToMemory(pemBlock)), nil
}
