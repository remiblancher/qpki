// Package pki provides the public API for qpki.
// This file exposes crypto operations from internal/crypto.
package pki

import (
	pkicrypto "github.com/remiblancher/qpki/internal/crypto"
)

// Re-export crypto types
type (
	// AlgorithmID represents a cryptographic algorithm identifier.
	AlgorithmID = pkicrypto.AlgorithmID

	// KeyPair represents a public/private key pair.
	KeyPair = pkicrypto.KeyPair

	// HybridKeyPair represents a hybrid key pair.
	HybridKeyPair = pkicrypto.HybridKeyPair

	// KEMKeyPair represents a KEM key pair.
	KEMKeyPair = pkicrypto.KEMKeyPair

	// HSMConfig holds HSM configuration.
	HSMConfig = pkicrypto.HSMConfig

	// PKCS11Config holds PKCS#11 HSM configuration.
	PKCS11Config = pkicrypto.PKCS11Config

	// PKCS11Signer implements crypto.Signer using PKCS#11.
	PKCS11Signer = pkicrypto.PKCS11Signer

	// HybridSigner signs with both classical and PQC algorithms.
	HybridSigner = pkicrypto.HybridSignerImpl

	// CryptoSigner is the internal signer interface.
	CryptoSigner = pkicrypto.Signer

	// SoftwareSigner is a software-based signer.
	SoftwareSigner = pkicrypto.SoftwareSigner
)

// GenerateKeyPair generates a new key pair.
func GenerateKeyPair(alg AlgorithmID) (*KeyPair, error) {
	return pkicrypto.GenerateKeyPair(alg)
}

// GenerateHybridKeyPair generates a hybrid key pair.
func GenerateHybridKeyPair(alg AlgorithmID) (*HybridKeyPair, error) {
	return pkicrypto.GenerateHybridKeyPair(alg)
}

// GenerateKEMKeyPair generates a KEM key pair.
func GenerateKEMKeyPair(alg AlgorithmID) (*KEMKeyPair, error) {
	return pkicrypto.GenerateKEMKeyPair(alg)
}

// LoadHSMConfig loads HSM configuration from a file.
func LoadHSMConfig(path string) (*HSMConfig, error) {
	return pkicrypto.LoadHSMConfig(path)
}

// NewPKCS11Signer creates a PKCS#11 backed signer.
func NewPKCS11Signer(cfg PKCS11Config) (*PKCS11Signer, error) {
	return pkicrypto.NewPKCS11Signer(cfg)
}

// NewHybridSigner creates a hybrid signer.
func NewHybridSigner(classical, pqc CryptoSigner) (*HybridSigner, error) {
	return pkicrypto.NewHybridSigner(classical, pqc)
}

// IsPostQuantumAlgorithm checks if an algorithm is post-quantum.
func IsPostQuantumAlgorithm(alg AlgorithmID) bool {
	return alg.IsPQC()
}

// IsSupportedAlgorithm checks if an algorithm is supported.
func IsSupportedAlgorithm(alg AlgorithmID) bool {
	return alg.IsValid()
}

// IsClassicalAlgorithm checks if an algorithm is classical.
func IsClassicalAlgorithm(alg AlgorithmID) bool {
	return alg.IsClassical()
}

// LoadPrivateKey loads a private key from a PEM file.
func LoadPrivateKey(path string, passphrase []byte) (*SoftwareSigner, error) {
	return pkicrypto.LoadPrivateKey(path, passphrase)
}

// CryptoLoadPrivateKey loads a private key (alias for LoadPrivateKey).
func CryptoLoadPrivateKey(path string, passphrase []byte) (*SoftwareSigner, error) {
	return pkicrypto.LoadPrivateKey(path, passphrase)
}
