//go:build !cgo

// Package crypto provides cryptographic primitives for the PKI.
// This file provides stub implementations when CGO is not available.
// HSM support via PKCS#11 requires CGO.
package crypto

// PKCS11KeyManager implements KeyManager for PKCS#11 (HSM) keys.
// This stub is used when CGO is not available.
type PKCS11KeyManager struct{}

// Ensure PKCS11KeyManager implements KeyManager.
var _ KeyManager = (*PKCS11KeyManager)(nil)

// NewPKCS11KeyManager creates a new PKCS11KeyManager.
func NewPKCS11KeyManager() *PKCS11KeyManager {
	return &PKCS11KeyManager{}
}

// Load loads an existing key from the HSM.
// This stub returns an error when CGO is not available.
func (m *PKCS11KeyManager) Load(_ KeyStorageConfig) (Signer, error) {
	return nil, errNoCGO
}

// Generate generates a new key in the HSM.
// This stub returns an error when CGO is not available.
func (m *PKCS11KeyManager) Generate(_ AlgorithmID, _ KeyStorageConfig) (Signer, error) {
	return nil, errNoCGO
}
