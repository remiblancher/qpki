package ca

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
)

// MetadataFile is the name of the CA metadata file.
const MetadataFile = "ca.meta.json"

// CAMetadata contains metadata about the CA.
// This file is stored at {ca-path}/ca.meta.json and tracks CA configuration
// including key storage references for both software and HSM keys.
type CAMetadata struct {
	// Profile is the profile used to create this CA.
	Profile string `json:"profile"`

	// Created is when the CA was initialized.
	Created time.Time `json:"created"`

	// Keys are references to the CA's keys.
	// A CA may have multiple keys for hybrid mode (classical + PQC) or rotation.
	Keys []KeyRef `json:"keys"`
}

// KeyRef references a CA key with its storage information.
type KeyRef struct {
	// ID identifies this key within the CA ("default", "classical", "pqc", etc.)
	ID string `json:"id"`

	// Algorithm is the cryptographic algorithm.
	Algorithm pkicrypto.AlgorithmID `json:"algorithm"`

	// Storage describes where the key is stored.
	Storage pkicrypto.StorageRef `json:"storage"`
}

// NewCAMetadata creates a new CAMetadata with default values.
func NewCAMetadata(profile string) *CAMetadata {
	return &CAMetadata{
		Profile: profile,
		Created: time.Now(),
		Keys:    make([]KeyRef, 0),
	}
}

// AddKey adds a key reference to the metadata.
func (m *CAMetadata) AddKey(ref KeyRef) {
	m.Keys = append(m.Keys, ref)
}

// GetKey returns a key reference by ID.
func (m *CAMetadata) GetKey(id string) *KeyRef {
	for i, key := range m.Keys {
		if key.ID == id {
			return &m.Keys[i]
		}
	}
	return nil
}

// GetDefaultKey returns the default key (first key or the one with ID "default").
func (m *CAMetadata) GetDefaultKey() *KeyRef {
	if len(m.Keys) == 0 {
		return nil
	}

	// Look for a key with ID "default"
	if key := m.GetKey("default"); key != nil {
		return key
	}

	// Fall back to the first key
	return &m.Keys[0]
}

// GetClassicalKey returns the classical key for hybrid CAs.
func (m *CAMetadata) GetClassicalKey() *KeyRef {
	return m.GetKey("classical")
}

// GetPQCKey returns the PQC key for hybrid CAs.
func (m *CAMetadata) GetPQCKey() *KeyRef {
	return m.GetKey("pqc")
}

// IsHybrid returns true if the CA has both classical and PQC keys.
func (m *CAMetadata) IsHybrid() bool {
	return m.GetClassicalKey() != nil && m.GetPQCKey() != nil
}

// Save saves the metadata to the CA store.
func (m *CAMetadata) Save(store *Store) error {
	return SaveCAMetadata(store.BasePath(), m)
}

// SaveCAMetadata saves CA metadata to the specified path.
func SaveCAMetadata(basePath string, meta *CAMetadata) error {
	path := filepath.Join(basePath, MetadataFile)

	data, err := json.MarshalIndent(meta, "", "    ")
	if err != nil {
		return fmt.Errorf("failed to marshal CA metadata: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write CA metadata: %w", err)
	}

	return nil
}

// LoadCAMetadata loads CA metadata from the specified path.
// Returns nil (not an error) if the metadata file doesn't exist.
// For versioned CAs, this checks both root and active/ directory.
func LoadCAMetadata(basePath string) (*CAMetadata, error) {
	path := filepath.Join(basePath, MetadataFile)

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Check if versioned CA - try active/ directory
			activePath := filepath.Join(basePath, "active", MetadataFile)
			data, err = os.ReadFile(activePath)
			if err != nil {
				if os.IsNotExist(err) {
					return nil, nil // No metadata file, legacy CA
				}
				return nil, fmt.Errorf("failed to read CA metadata: %w", err)
			}
		} else {
			return nil, fmt.Errorf("failed to read CA metadata: %w", err)
		}
	}

	var meta CAMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("failed to parse CA metadata: %w", err)
	}

	return &meta, nil
}

// MetadataExists checks if the metadata file exists for a store.
func MetadataExists(basePath string) bool {
	path := filepath.Join(basePath, MetadataFile)
	_, err := os.Stat(path)
	return err == nil
}

// CreateSoftwareKeyRef creates a StorageRef for a software key.
func CreateSoftwareKeyRef(keyPath string) pkicrypto.StorageRef {
	return pkicrypto.StorageRef{
		Type: "software",
		Path: keyPath,
	}
}

// CreatePKCS11KeyRef creates a StorageRef for a PKCS#11 (HSM) key.
func CreatePKCS11KeyRef(hsmConfigPath, keyLabel, keyID string) pkicrypto.StorageRef {
	return pkicrypto.StorageRef{
		Type:   "pkcs11",
		Config: hsmConfigPath,
		Label:  keyLabel,
		KeyID:  keyID,
	}
}

// BuildKeyStorageConfig converts a KeyRef to a KeyStorageConfig.
// The basePath is used to resolve relative paths.
func (k *KeyRef) BuildKeyStorageConfig(basePath, passphrase string) (pkicrypto.KeyStorageConfig, error) {
	return k.Storage.ToKeyStorageConfig(basePath, passphrase)
}

// CAKeyPathForAlgorithm returns the key path following the new naming convention.
// Example: private/ca.ecdsa-p384.key
func CAKeyPathForAlgorithm(basePath string, alg pkicrypto.AlgorithmID) string {
	return filepath.Join(basePath, "private", fmt.Sprintf("ca.%s.key", alg))
}

// RelativeCAKeyPathForAlgorithm returns the relative key path for use in metadata.
// Example: private/ca.ecdsa-p384.key
func RelativeCAKeyPathForAlgorithm(alg pkicrypto.AlgorithmID) string {
	return fmt.Sprintf("private/ca.%s.key", alg)
}
