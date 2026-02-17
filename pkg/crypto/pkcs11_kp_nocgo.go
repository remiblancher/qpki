//go:build !cgo

// Package crypto provides cryptographic primitives for the PKI.
// This file provides stub implementations when CGO is not available.
// HSM support via PKCS#11 requires CGO.
package crypto

// PKCS11KeyProvider implements KeyProvider for PKCS#11 (HSM) keys.
// This stub is used when CGO is not available.
type PKCS11KeyProvider struct{}

// Ensure PKCS11KeyProvider implements KeyProvider.
var _ KeyProvider = (*PKCS11KeyProvider)(nil)

// NewPKCS11KeyProvider creates a new PKCS11KeyProvider.
func NewPKCS11KeyProvider() *PKCS11KeyProvider {
	return &PKCS11KeyProvider{}
}

// Load loads an existing key from the HSM.
// This stub returns an error when CGO is not available.
func (m *PKCS11KeyProvider) Load(_ KeyStorageConfig) (Signer, error) {
	return nil, errNoCGO
}

// Generate generates a new key in the HSM.
// This stub returns an error when CGO is not available.
func (m *PKCS11KeyProvider) Generate(_ AlgorithmID, _ KeyStorageConfig) (Signer, error) {
	return nil, errNoCGO
}
