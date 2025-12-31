//go:build !cgo

// Package crypto provides cryptographic primitives for the PKI.
// This file provides stub implementations when CGO is not available.
// HSM support via PKCS#11 requires CGO.
package crypto

import (
	"crypto"
	"fmt"
	"io"
)

// PKCS11Config holds PKCS#11 configuration.
type PKCS11Config struct {
	ModulePath           string
	TokenLabel           string
	TokenSerial          string
	PIN                  string
	KeyLabel             string
	KeyID                string
	SlotID               *uint
	LogoutAfterUse       bool
	VerifyKeyCertBinding bool
}

// PKCS11Signer implements the Signer interface using PKCS#11.
// This stub is used when CGO is not available.
type PKCS11Signer struct{}

// PKCS11SignerProvider implements SignerProvider for PKCS#11.
type PKCS11SignerProvider struct{}

// Ensure PKCS11SignerProvider implements SignerProvider.
var _ SignerProvider = (*PKCS11SignerProvider)(nil)

// errNoCGO is returned when PKCS#11 operations are attempted without CGO.
var errNoCGO = fmt.Errorf("HSM support requires CGO (build with CGO_ENABLED=1)")

// NewPKCS11Signer creates a new PKCS#11 signer.
// This stub returns an error when CGO is not available.
func NewPKCS11Signer(_ PKCS11Config) (*PKCS11Signer, error) {
	return nil, errNoCGO
}

// Algorithm returns the algorithm used by this signer.
func (s *PKCS11Signer) Algorithm() AlgorithmID {
	return ""
}

// Public returns the public key.
func (s *PKCS11Signer) Public() crypto.PublicKey {
	return nil
}

// Sign signs the digest using the HSM.
func (s *PKCS11Signer) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, errNoCGO
}

// Close closes the PKCS#11 session.
func (s *PKCS11Signer) Close() error {
	return nil
}

// LoadSigner loads a signer from PKCS#11.
func (p *PKCS11SignerProvider) LoadSigner(_ SignerConfig) (Signer, error) {
	return nil, errNoCGO
}

// GenerateAndSave generates a new key pair in the HSM.
func (p *PKCS11SignerProvider) GenerateAndSave(_ AlgorithmID, _ SignerConfig) (Signer, error) {
	return nil, errNoCGO
}

// HSMInfo contains information about an HSM.
type HSMInfo struct {
	ModulePath string
	Slots      []SlotInfo
}

// SlotInfo contains information about an HSM slot.
type SlotInfo struct {
	ID           uint
	Description  string
	TokenLabel   string
	TokenSerial  string
	Manufacturer string
	HasToken     bool
}

// KeyInfo contains information about a key in the HSM.
type KeyInfo struct {
	Label   string
	ID      string
	Type    string
	Size    int
	CanSign bool
}

// ListHSMSlots lists available slots in a PKCS#11 module.
func ListHSMSlots(_ string) (*HSMInfo, error) {
	return nil, errNoCGO
}

// GenerateHSMKeyPairConfig holds configuration for key generation.
type GenerateHSMKeyPairConfig struct {
	ModulePath string
	TokenLabel string
	PIN        string
	KeyLabel   string
	KeyID      []byte
	Algorithm  AlgorithmID
}

// GenerateHSMKeyPairResult holds the result of key generation.
type GenerateHSMKeyPairResult struct {
	KeyLabel string
	KeyID    string
	Type     string
	Size     int
}

// GenerateHSMKeyPair generates a new key pair in the HSM.
func GenerateHSMKeyPair(_ GenerateHSMKeyPairConfig) (*GenerateHSMKeyPairResult, error) {
	return nil, errNoCGO
}

// ListHSMKeys lists keys in a token.
func ListHSMKeys(_, _, _ string) ([]KeyInfo, error) {
	return nil, errNoCGO
}
