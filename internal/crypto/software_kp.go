// Package crypto provides cryptographic primitives for the PKI.
// This file implements the SoftwareKeyProvider for software-based key management.
package crypto

import (
	"fmt"
)

// SoftwareKeyProvider implements KeyProvider for software-based keys.
// Keys are stored as PEM files on disk.
type SoftwareKeyProvider struct{}

// Ensure SoftwareKeyProvider implements KeyProvider.
var _ KeyProvider = (*SoftwareKeyProvider)(nil)

// NewSoftwareKeyProvider creates a new SoftwareKeyProvider.
func NewSoftwareKeyProvider() *SoftwareKeyProvider {
	return &SoftwareKeyProvider{}
}

// Load loads a private key from disk and returns a Signer.
func (m *SoftwareKeyProvider) Load(cfg KeyStorageConfig) (Signer, error) {
	if cfg.Type != KeyProviderTypeSoftware && cfg.Type != "" {
		return nil, fmt.Errorf("SoftwareKeyProvider only supports software keys, got: %s", cfg.Type)
	}

	if cfg.KeyPath == "" {
		return nil, fmt.Errorf("key_path is required for software key storage")
	}

	passphrase := ResolvePassphrase(cfg.Passphrase)
	// Use LoadPrivateKeysAsHybrid to support multi-key files (Composite credentials)
	return LoadPrivateKeysAsHybrid(cfg.KeyPath, passphrase)
}

// Generate generates a new key pair, saves it to disk, and returns a Signer.
func (m *SoftwareKeyProvider) Generate(alg AlgorithmID, cfg KeyStorageConfig) (Signer, error) {
	if cfg.Type != KeyProviderTypeSoftware && cfg.Type != "" {
		return nil, fmt.Errorf("SoftwareKeyProvider only supports software keys, got: %s", cfg.Type)
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
