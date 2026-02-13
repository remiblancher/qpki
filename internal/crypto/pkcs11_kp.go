//go:build cgo

// Package crypto provides cryptographic primitives for the PKI.
// This file implements the PKCS11KeyProvider for HSM-based key management.
package crypto

import (
	"encoding/hex"
	"fmt"
)

// PKCS11KeyProvider implements KeyProvider for PKCS#11 (HSM) keys.
type PKCS11KeyProvider struct{}

// Ensure PKCS11KeyProvider implements KeyProvider.
var _ KeyProvider = (*PKCS11KeyProvider)(nil)

// NewPKCS11KeyProvider creates a new PKCS11KeyProvider.
func NewPKCS11KeyProvider() *PKCS11KeyProvider {
	return &PKCS11KeyProvider{}
}

// Load loads an existing key from the HSM and returns a Signer.
func (m *PKCS11KeyProvider) Load(cfg KeyStorageConfig) (Signer, error) {
	if cfg.Type != KeyProviderTypePKCS11 {
		return nil, fmt.Errorf("PKCS11KeyProvider only supports pkcs11 keys, got: %s", cfg.Type)
	}

	if cfg.PKCS11Lib == "" {
		return nil, fmt.Errorf("pkcs11_lib is required for PKCS#11 key storage")
	}
	if cfg.PKCS11KeyLabel == "" && cfg.PKCS11KeyID == "" {
		return nil, fmt.Errorf("at least one of pkcs11_key_label or pkcs11_key_id is required")
	}

	pkcs11Cfg := PKCS11Config{
		ModulePath: cfg.PKCS11Lib,
		TokenLabel: cfg.PKCS11Token,
		SlotID:     cfg.PKCS11Slot,
		PIN:        cfg.PKCS11Pin,
		KeyLabel:   cfg.PKCS11KeyLabel,
		KeyID:      cfg.PKCS11KeyID,
	}

	return NewPKCS11Signer(pkcs11Cfg)
}

// Generate generates a new key in the HSM and returns a Signer.
func (m *PKCS11KeyProvider) Generate(alg AlgorithmID, cfg KeyStorageConfig) (Signer, error) {
	if cfg.Type != KeyProviderTypePKCS11 {
		return nil, fmt.Errorf("PKCS11KeyProvider only supports pkcs11 keys, got: %s", cfg.Type)
	}

	if cfg.PKCS11Lib == "" {
		return nil, fmt.Errorf("pkcs11_lib is required for PKCS#11 key storage")
	}
	if cfg.PKCS11KeyLabel == "" {
		return nil, fmt.Errorf("pkcs11_key_label is required for key generation")
	}

	// Convert key ID from hex if provided
	var keyID []byte
	if cfg.PKCS11KeyID != "" {
		var err error
		keyID, err = hex.DecodeString(cfg.PKCS11KeyID)
		if err != nil {
			return nil, fmt.Errorf("invalid pkcs11_key_id hex: %w", err)
		}
	}

	// Generate the key in the HSM
	_, err := GenerateHSMKeyPair(GenerateHSMKeyPairConfig{
		ModulePath: cfg.PKCS11Lib,
		TokenLabel: cfg.PKCS11Token,
		SlotID:     cfg.PKCS11Slot,
		PIN:        cfg.PKCS11Pin,
		KeyLabel:   cfg.PKCS11KeyLabel,
		KeyID:      keyID,
		Algorithm:  alg,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate key in HSM: %w", err)
	}

	// Load and return the newly created signer
	return m.Load(cfg)
}
