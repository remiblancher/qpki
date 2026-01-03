// Package crypto provides cryptographic primitives for the PKI.
// This file implements the SoftwareKeyManager for software-based key management.
package crypto

import (
	"fmt"
)

// SoftwareKeyManager implements KeyManager for software-based keys.
// Keys are stored as PEM files on disk.
type SoftwareKeyManager struct{}

// Ensure SoftwareKeyManager implements KeyManager.
var _ KeyManager = (*SoftwareKeyManager)(nil)

// NewSoftwareKeyManager creates a new SoftwareKeyManager.
func NewSoftwareKeyManager() *SoftwareKeyManager {
	return &SoftwareKeyManager{}
}

// Load loads a private key from disk and returns a Signer.
func (m *SoftwareKeyManager) Load(cfg KeyStorageConfig) (Signer, error) {
	if cfg.Type != KeyManagerTypeSoftware && cfg.Type != "" {
		return nil, fmt.Errorf("SoftwareKeyManager only supports software keys, got: %s", cfg.Type)
	}

	if cfg.KeyPath == "" {
		return nil, fmt.Errorf("key_path is required for software key storage")
	}

	passphrase := ResolvePassphrase(cfg.Passphrase)
	// Use LoadPrivateKeysAsHybrid to support multi-key files (Composite credentials)
	return LoadPrivateKeysAsHybrid(cfg.KeyPath, passphrase)
}

// Generate generates a new key pair, saves it to disk, and returns a Signer.
func (m *SoftwareKeyManager) Generate(alg AlgorithmID, cfg KeyStorageConfig) (Signer, error) {
	if cfg.Type != KeyManagerTypeSoftware && cfg.Type != "" {
		return nil, fmt.Errorf("SoftwareKeyManager only supports software keys, got: %s", cfg.Type)
	}

	if cfg.KeyPath == "" {
		return nil, fmt.Errorf("key_path is required for software key storage")
	}

	// Generate the key pair
	signer, err := GenerateSoftwareSigner(alg)
	if err != nil {
		return nil, fmt.Errorf("failed to generate %s key: %w", alg, err)
	}

	// Save to disk
	passphrase := ResolvePassphrase(cfg.Passphrase)
	if err := signer.SavePrivateKey(cfg.KeyPath, passphrase); err != nil {
		return nil, fmt.Errorf("failed to save private key: %w", err)
	}

	return signer, nil
}
