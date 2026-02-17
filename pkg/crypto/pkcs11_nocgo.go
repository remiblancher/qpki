//go:build !cgo

// Package crypto provides cryptographic primitives for the PKI.
// This file provides stub implementations when CGO is not available.
// HSM support via PKCS#11 requires CGO.
package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"fmt"
	"io"
)

// PKCS11Config holds PKCS#11 configuration.
type PKCS11Config struct {
	ModulePath     string
	TokenLabel     string
	TokenSerial    string
	PIN            string
	KeyLabel       string
	KeyID          string
	SlotID         *uint
	LogoutAfterUse bool
}

// PKCS11Signer implements the Signer interface using PKCS#11.
// This stub is used when CGO is not available.
type PKCS11Signer struct{}

// PKCS11HybridSigner wraps two PKCS11Signers for Catalyst hybrid mode.
// This stub is used when CGO is not available.
type PKCS11HybridSigner struct{}

// Ensure PKCS11HybridSigner implements HybridSigner.
var _ HybridSigner = (*PKCS11HybridSigner)(nil)

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

// NewPKCS11HybridSigner creates a HybridSigner from two HSM keys.
// This stub returns an error when CGO is not available.
func NewPKCS11HybridSigner(_ PKCS11Config) (*PKCS11HybridSigner, error) {
	return nil, errNoCGO
}

// Public returns the public key.
func (s *PKCS11HybridSigner) Public() crypto.PublicKey {
	return nil
}

// Sign signs the digest.
func (s *PKCS11HybridSigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, errNoCGO
}

// Algorithm returns the algorithm.
func (s *PKCS11HybridSigner) Algorithm() AlgorithmID {
	return ""
}

// ClassicalSigner returns the classical signer.
func (s *PKCS11HybridSigner) ClassicalSigner() Signer {
	return nil
}

// PQCSigner returns the PQC signer.
func (s *PKCS11HybridSigner) PQCSigner() Signer {
	return nil
}

// SignHybrid performs hybrid signing.
func (s *PKCS11HybridSigner) SignHybrid(_ io.Reader, _ []byte) ([]byte, []byte, error) {
	return nil, nil, errNoCGO
}

// Close closes the signers.
func (s *PKCS11HybridSigner) Close() error {
	return nil
}

// Decrypt implements crypto.Decrypter for RSA keys.
func (s *PKCS11Signer) Decrypt(_ io.Reader, _ []byte, _ crypto.DecrypterOpts) ([]byte, error) {
	return nil, errNoCGO
}

// DecapsulateKEM performs ML-KEM decapsulation via PKCS#11.
func (s *PKCS11Signer) DecapsulateKEM(_ []byte) ([]byte, error) {
	return nil, errNoCGO
}

// DeriveECDH performs ECDH key derivation via PKCS#11.
func (s *PKCS11Signer) DeriveECDH(_ *ecdsa.PublicKey) ([]byte, error) {
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

// GetPublicKeyFromHSM extracts the public key from an HSM key.
func GetPublicKeyFromHSM(_ PKCS11Config) (crypto.PublicKey, error) {
	return nil, errNoCGO
}

// ListHSMKeys lists keys in a token.
func ListHSMKeys(_, _, _ string) ([]KeyInfo, error) {
	return nil, errNoCGO
}

// MechanismInfo contains information about a PKCS#11 mechanism.
type MechanismInfo struct {
	ID          uint
	Name        string
	MinKeySize  uint
	MaxKeySize  uint
	Flags       uint
	CanEncrypt  bool
	CanDecrypt  bool
	CanSign     bool
	CanVerify   bool
	CanDerive   bool
	CanWrap     bool
	CanUnwrap   bool
	CanGenerate bool
}

// ListHSMMechanisms lists available mechanisms for a given slot.
func ListHSMMechanisms(_ string, _ uint) ([]MechanismInfo, error) {
	return nil, errNoCGO
}

// CloseAllPools closes all session pools.
// This stub does nothing when CGO is not available.
func CloseAllPools() {
	// No-op: HSM support requires CGO
}
