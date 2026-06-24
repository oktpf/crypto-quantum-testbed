package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// GenerateRSAKey generates an RSA key pair with the specified bit size.
func GenerateRSAKey(id string, bits int, algo KeyAlgorithm) (*KeyPair, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("rsa generation failed: %w", err)
	}
	return &KeyPair{
		ID:         id,
		Algorithm:  algo,
		PublicKey:  &privateKey.PublicKey,
		PrivateKey: privateKey,
	}, nil
}

// RSASignPSS signs the digest of data using RSA-PSS with SHA-256.
func RSASignPSS(keyPair *KeyPair, data []byte) ([]byte, error) {
	key, ok := keyPair.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not RSA")
	}
	hashed := sha256.Sum256(data)
	signature, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, hashed[:], &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
	})
	if err != nil {
		return nil, fmt.Errorf("rsa sign failed: %w", err)
	}
	return signature, nil
}

// RSAVerifyPSS verifies an RSA-PSS signature.
func RSAVerifyPSS(keyPair *KeyPair, data, signature []byte) error {
	key, ok := keyPair.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("key is not RSA")
	}
	hashed := sha256.Sum256(data)
	return rsa.VerifyPSS(key, crypto.SHA256, hashed[:], signature, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
	})
}

// RSAEncryptOAEP encrypts data using RSA-OAEP with SHA-256.
func RSAEncryptOAEP(keyPair *KeyPair, plaintext []byte) ([]byte, error) {
	key, ok := keyPair.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not RSA")
	}
	label := []byte("vault-encryption")
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, key, plaintext, label)
	if err != nil {
		return nil, fmt.Errorf("rsa encrypt failed: %w", err)
	}
	return ciphertext, nil
}

// RSADecryptOAEP decrypts data using RSA-OAEP with SHA-256.
func RSADecryptOAEP(keyPair *KeyPair, ciphertext []byte) ([]byte, error) {
	key, ok := keyPair.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not RSA")
	}
	label := []byte("vault-encryption")
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, ciphertext, label)
	if err != nil {
		return nil, fmt.Errorf("rsa decrypt failed: %w", err)
	}
	return plaintext, nil
}

// RSAExportPublicPEM exports the RSA public key as a PEM-encoded string.
func RSAExportPublicPEM(keyPair *KeyPair) (string, error) {
	key, ok := keyPair.PublicKey.(*rsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("key is not RSA")
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
