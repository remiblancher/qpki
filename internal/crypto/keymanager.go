// Package crypto provides cryptographic primitives for the PKI.
// This file defines the KeyManager interface for unified key management.
package crypto

import (
	"fmt"
	"os"
)

// KeyManagerType identifies the type of key manager backend.
type KeyManagerType string

const (
	// KeyManagerTypeSoftware uses software-based key storage.
	KeyManagerTypeSoftware KeyManagerType = "software"

	// KeyManagerTypePKCS11 uses PKCS#11 (HSM) key storage.
	KeyManagerTypePKCS11 KeyManagerType = "pkcs11"
)

// KeyStorageConfig holds configuration for key storage/retrieval.
// It supports both software-based keys and HSM-based keys.
type KeyStorageConfig struct {
	// Type specifies the storage backend ("software" or "pkcs11").
	Type KeyManagerType `json:"type" yaml:"type"`

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

// KeyManager provides a unified interface for key management operations.
// It abstracts the differences between software keys and HSM-based keys.
//
// Usage:
//
//	// Software key management
//	km := NewSoftwareKeyManager()
//	signer, err := km.Generate(AlgECDSAP384, KeyStorageConfig{
//	    Type:    KeyManagerTypeSoftware,
//	    KeyPath: "/path/to/key.pem",
//	})
//
//	// HSM key management
//	km := NewPKCS11KeyManager()
//	signer, err := km.Load(KeyStorageConfig{
//	    Type:           KeyManagerTypePKCS11,
//	    PKCS11Lib:      "/usr/lib/softhsm/libsofthsm2.so",
//	    PKCS11Token:    "my-token",
//	    PKCS11Pin:      "1234",
//	    PKCS11KeyLabel: "my-key",
//	})
type KeyManager interface {
	// Load loads an existing key and returns a Signer.
	// For software keys, this reads from disk.
	// For HSM keys, this opens a session and finds the key.
	Load(cfg KeyStorageConfig) (Signer, error)

	// Generate generates a new key, stores it, and returns a Signer.
	// For software keys, this creates a file on disk.
	// For HSM keys, this creates the key in the HSM.
	Generate(alg AlgorithmID, cfg KeyStorageConfig) (Signer, error)
}

// NewKeyManager creates a KeyManager based on the storage type.
// If cfg.Type is empty, it defaults to KeyManagerTypeSoftware.
func NewKeyManager(cfg KeyStorageConfig) KeyManager {
	switch cfg.Type {
	case KeyManagerTypePKCS11:
		return &PKCS11KeyManager{}
	default:
		return &SoftwareKeyManager{}
	}
}

// NewKeyManagerFromHSMConfig creates a KeyManager from an HSMConfig file.
// This is a convenience function for CLI usage with --hsm-config flag.
func NewKeyManagerFromHSMConfig(hsmConfigPath, keyLabel, keyID string) (KeyManager, KeyStorageConfig, error) {
	hsmCfg, err := LoadHSMConfig(hsmConfigPath)
	if err != nil {
		return nil, KeyStorageConfig{}, fmt.Errorf("failed to load HSM config: %w", err)
	}

	pin, err := hsmCfg.GetPIN()
	if err != nil {
		return nil, KeyStorageConfig{}, err
	}

	cfg := KeyStorageConfig{
		Type:           KeyManagerTypePKCS11,
		PKCS11Lib:      hsmCfg.PKCS11.Lib,
		PKCS11Token:    hsmCfg.PKCS11.Token,
		PKCS11Pin:      pin,
		PKCS11KeyLabel: keyLabel,
		PKCS11KeyID:    keyID,
	}

	return NewKeyManager(cfg), cfg, nil
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
// This is used in metadata files (ca.meta.json, credential.json).
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
		if basePath != "" && !isAbsPath(keyPath) {
			keyPath = joinPath(basePath, keyPath)
		}
		return KeyStorageConfig{
			Type:       KeyManagerTypeSoftware,
			KeyPath:    keyPath,
			Passphrase: passphrase,
		}, nil

	case "pkcs11":
		configPath := s.Config
		if basePath != "" && !isAbsPath(configPath) {
			configPath = joinPath(basePath, configPath)
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
			Type:           KeyManagerTypePKCS11,
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

// isAbsPath checks if a path is absolute (simple implementation).
func isAbsPath(path string) bool {
	return len(path) > 0 && path[0] == '/'
}

// joinPath joins path components (simple implementation to avoid filepath import).
func joinPath(base, path string) string {
	if base == "" {
		return path
	}
	if path == "" {
		return base
	}
	if base[len(base)-1] == '/' {
		return base + path
	}
	return base + "/" + path
}
