// Package crypto provides cryptographic primitives for the PKI.
// This file defines the KeyProvider interface for unified key management.
package crypto

import (
	"fmt"
	"os"
	"path/filepath"
)

// KeyProviderType identifies the type of key provider backend.
type KeyProviderType string

const (
	// KeyProviderTypeSoftware uses software-based key storage.
	KeyProviderTypeSoftware KeyProviderType = "software"

	// KeyProviderTypePKCS11 uses PKCS#11 (HSM) key storage.
	KeyProviderTypePKCS11 KeyProviderType = "pkcs11"
)

// KeyStorageConfig holds configuration for key storage/retrieval.
// It supports both software-based keys and HSM-based keys.
type KeyStorageConfig struct {
	// Type specifies the storage backend ("software" or "pkcs11").
	Type KeyProviderType `json:"type" yaml:"type"`

	// Software key storage
	KeyPath    string `json:"key_path,omitempty" yaml:"key_path,omitempty"`
	Passphrase string `json:"-" yaml:"-"` // Never serialized

	// PKCS#11 (HSM) key storage
	PKCS11Lib        string `json:"pkcs11_lib,omitempty" yaml:"pkcs11_lib,omitempty"`
	PKCS11Token      string `json:"pkcs11_token,omitempty" yaml:"pkcs11_token,omitempty"`
	PKCS11Pin        string `json:"-" yaml:"-"` // Never serialized
	PKCS11KeyLabel   string `json:"pkcs11_key_label,omitempty" yaml:"pkcs11_key_label,omitempty"`
	PKCS11KeyID      string `json:"pkcs11_key_id,omitempty" yaml:"pkcs11_key_id,omitempty"`
	PKCS11ConfigPath string `json:"pkcs11_config_path,omitempty" yaml:"pkcs11_config_path,omitempty"` // Path to hsm-config.yaml
}

// KeyProvider provides a unified interface for key management operations.
// It abstracts the differences between software keys and HSM-based keys.
//
// Usage:
//
//	// Software key management
//	kp := NewSoftwareKeyProvider()
//	signer, err := kp.Generate(AlgECDSAP384, KeyStorageConfig{
//	    Type:    KeyProviderTypeSoftware,
//	    KeyPath: "/path/to/key.pem",
//	})
//
//	// HSM key management
//	kp := NewPKCS11KeyProvider()
//	signer, err := kp.Load(KeyStorageConfig{
//	    Type:           KeyProviderTypePKCS11,
//	    PKCS11Lib:      "/usr/lib/softhsm/libsofthsm2.so",
//	    PKCS11Token:    "my-token",
//	    PKCS11Pin:      "1234",
//	    PKCS11KeyLabel: "my-key",
//	})
type KeyProvider interface {
	// Load loads an existing key and returns a Signer.
	// For software keys, this reads from disk.
	// For HSM keys, this opens a session and finds the key.
	Load(cfg KeyStorageConfig) (Signer, error)

	// Generate generates a new key, stores it, and returns a Signer.
	// For software keys, this creates a file on disk.
	// For HSM keys, this creates the key in the HSM.
	Generate(alg AlgorithmID, cfg KeyStorageConfig) (Signer, error)
}

// NewKeyProvider creates a KeyProvider based on the storage type.
// If cfg.Type is empty, it defaults to KeyProviderTypeSoftware.
func NewKeyProvider(cfg KeyStorageConfig) KeyProvider {
	switch cfg.Type {
	case KeyProviderTypePKCS11:
		return &PKCS11KeyProvider{}
	default:
		return &SoftwareKeyProvider{}
	}
}

// NewKeyProviderFromHSMConfig creates a KeyProvider from an HSMConfig file.
// This is a convenience function for CLI usage with --hsm-config flag.
func NewKeyProviderFromHSMConfig(hsmConfigPath, keyLabel, keyID string) (KeyProvider, KeyStorageConfig, error) {
	hsmCfg, err := LoadHSMConfig(hsmConfigPath)
	if err != nil {
		return nil, KeyStorageConfig{}, fmt.Errorf("failed to load HSM config: %w", err)
	}

	pin, err := hsmCfg.GetPIN()
	if err != nil {
		return nil, KeyStorageConfig{}, err
	}

	cfg := KeyStorageConfig{
		Type:           KeyProviderTypePKCS11,
		PKCS11Lib:      hsmCfg.PKCS11.Lib,
		PKCS11Token:    hsmCfg.PKCS11.Token,
		PKCS11Pin:      pin,
		PKCS11KeyLabel: keyLabel,
		PKCS11KeyID:    keyID,
	}

	return NewKeyProvider(cfg), cfg, nil
}

// ResolvePassphrase resolves a passphrase that may be "env:VAR_NAME".
// This is exported for use by other packages.
func ResolvePassphrase(passphrase string) []byte {
	if passphrase == "" {
		return nil
	}
	if len(passphrase) > 4 && passphrase[:4] == "env:" {
		envValue := os.Getenv(passphrase[4:])
		return []byte(envValue)
	}
	return []byte(passphrase)
}

// StorageRef describes how a key is stored.
// This is used in metadata files (ca.meta.json, credential.meta.json).
type StorageRef struct {
	// Type is "software" or "pkcs11"
	Type string `json:"type"`

	// Software storage
	Path string `json:"path,omitempty"`

	// PKCS#11 (HSM) storage
	Config string `json:"config,omitempty"` // Path to hsm-config.yaml
	Label  string `json:"label,omitempty"`  // CKA_LABEL
	KeyID  string `json:"key_id,omitempty"` // CKA_ID (hex)
}

// ToKeyStorageConfig converts a StorageRef to KeyStorageConfig.
// For PKCS#11, the basePath is used to resolve relative config paths.
func (s *StorageRef) ToKeyStorageConfig(basePath, passphrase string) (KeyStorageConfig, error) {
	switch s.Type {
	case "software", "":
		keyPath := s.Path
		if basePath != "" && !filepath.IsAbs(keyPath) {
			keyPath = filepath.Join(basePath, keyPath)
		}
		return KeyStorageConfig{
			Type:       KeyProviderTypeSoftware,
			KeyPath:    keyPath,
			Passphrase: passphrase,
		}, nil

	case "pkcs11":
		configPath := s.Config
		if basePath != "" && !filepath.IsAbs(configPath) {
			configPath = filepath.Join(basePath, configPath)
		}

		hsmCfg, err := LoadHSMConfig(configPath)
		if err != nil {
			return KeyStorageConfig{}, fmt.Errorf("failed to load HSM config: %w", err)
		}

		pin, err := hsmCfg.GetPIN()
		if err != nil {
			return KeyStorageConfig{}, err
		}

		return KeyStorageConfig{
			Type:           KeyProviderTypePKCS11,
			PKCS11Lib:      hsmCfg.PKCS11.Lib,
			PKCS11Token:    hsmCfg.PKCS11.Token,
			PKCS11Pin:      pin,
			PKCS11KeyLabel: s.Label,
			PKCS11KeyID:    s.KeyID,
		}, nil

	default:
		return KeyStorageConfig{}, fmt.Errorf("unsupported storage type: %s", s.Type)
	}
}
