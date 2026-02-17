package credential

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	pkicrypto "github.com/remiblancher/post-quantum-pki/pkg/crypto"
)

// VersionStatus represents the status of a credential version.
type VersionStatus string

const (
	// VersionStatusActive indicates this is the currently active version.
	VersionStatusActive VersionStatus = "active"

	// VersionStatusPending indicates a newly rotated credential awaiting activation.
	VersionStatusPending VersionStatus = "pending"

	// VersionStatusArchived indicates a previously active version that has been superseded.
	VersionStatusArchived VersionStatus = "archived"
)

// VersionCertRef holds a reference to a certificate within a version.
type VersionCertRef struct {
	// Profile is the profile name used (e.g., "ec/tls-server").
	Profile string `json:"profile"`

	// Algorithm is the cryptographic algorithm (e.g., "ecdsa-p256", "ml-dsa-65").
	Algorithm string `json:"algorithm"`

	// AlgorithmFamily is the algorithm family for grouping (e.g., "ec", "ml-dsa").
	AlgorithmFamily string `json:"algorithm_family"`

	// Serial is the certificate serial number (hex-encoded).
	Serial string `json:"serial,omitempty"`

	// Fingerprint is the SHA-256 fingerprint of the certificate.
	Fingerprint string `json:"fingerprint,omitempty"`

	// NotBefore is the certificate validity start.
	NotBefore time.Time `json:"not_before"`

	// NotAfter is the certificate validity end.
	NotAfter time.Time `json:"not_after"`
}

// Version represents a credential version with multiple certificates.
// Each version contains one or more certificates (one per profile/algorithm).
// Note: Status is computed, not stored. Use Credential.GetVersionStatus().
type Version struct {
	// ID is the unique version identifier (e.g., v1, v2).
	ID string `json:"id"`

	// Profiles lists all profile names in this version.
	Profiles []string `json:"profiles"`

	// Certificates holds references to all certificates in this version.
	Certificates []VersionCertRef `json:"certificates"`

	// Created is when this version was created.
	Created time.Time `json:"created"`

	// ActivatedAt is when this version was activated (if status is active/archived).
	ActivatedAt *time.Time `json:"activated_at,omitempty"`

	// ArchivedAt is when this version was archived (if status is archived).
	ArchivedAt *time.Time `json:"archived_at,omitempty"`
}

// VersionStore manages credential version storage.
// It wraps a Credential and provides version-related operations.
// All data is stored in credential.meta.json (no separate versions.json).
type VersionStore struct {
	basePath string
	cred     *Credential
}

// NewVersionStore creates a version store for a credential.
func NewVersionStore(credentialPath string) *VersionStore {
	return &VersionStore{basePath: credentialPath}
}

// loadCredential loads the credential if not already loaded.
func (vs *VersionStore) loadCredential() error {
	if vs.cred != nil {
		return nil
	}

	// Try to load existing credential
	if CredentialExists(vs.basePath) {
		cred, err := LoadCredential(vs.basePath)
		if err != nil {
			return fmt.Errorf("failed to load credential: %w", err)
		}
		vs.cred = cred
	}

	return nil
}

// VersionsDir returns the path to the versions directory.
func (vs *VersionStore) VersionsDir() string {
	return filepath.Join(vs.basePath, "versions")
}

// VersionDir returns the directory for a specific version.
func (vs *VersionStore) VersionDir(versionID string) string {
	return filepath.Join(vs.VersionsDir(), versionID)
}

// KeysDir returns the keys directory for a specific version.
func (vs *VersionStore) KeysDir(versionID string) string {
	return filepath.Join(vs.VersionDir(versionID), "keys")
}

// CertsDir returns the certs directory for a specific version.
func (vs *VersionStore) CertsDir(versionID string) string {
	return filepath.Join(vs.VersionDir(versionID), "certs")
}

// CertPath returns the certificate path for a specific algorithm.
// Format: versions/{versionID}/certs/credential.{algorithm}.pem
func (vs *VersionStore) CertPath(versionID, algorithm string) string {
	return filepath.Join(vs.CertsDir(versionID), fmt.Sprintf("credential.%s.pem", algorithm))
}

// KeyPath returns the private key path for a specific algorithm.
// Format: versions/{versionID}/keys/credential.{algorithm}.key
func (vs *VersionStore) KeyPath(versionID, algorithm string) string {
	return filepath.Join(vs.KeysDir(versionID), fmt.Sprintf("credential.%s.key", algorithm))
}

// ProfileDir returns the directory for a specific profile within a version.
// Deprecated: Use CertsDir or KeysDir instead. Kept for migration compatibility.
func (vs *VersionStore) ProfileDir(versionID, algorithmFamily string) string {
	return filepath.Join(vs.VersionDir(versionID), algorithmFamily)
}

// ActiveVersionDir returns the directory for the active version.
// This reads directly from versions/{active}/ (no separate active/ directory).
func (vs *VersionStore) ActiveVersionDir() (string, error) {
	if err := vs.loadCredential(); err != nil {
		return "", err
	}
	if vs.cred == nil || vs.cred.Active == "" {
		return "", fmt.Errorf("no active version")
	}
	return vs.VersionDir(vs.cred.Active), nil
}

// Init initializes the version store if needed.
func (vs *VersionStore) Init() error {
	if err := os.MkdirAll(vs.VersionsDir(), 0755); err != nil {
		return fmt.Errorf("failed to create versions directory: %w", err)
	}
	return nil
}

// exists checks if a path exists.
func (vs *VersionStore) exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// IsVersioned returns true if this credential uses versioning.
// A credential is versioned if it has a versions directory with at least one version.
func (vs *VersionStore) IsVersioned() bool {
	if err := vs.loadCredential(); err != nil {
		return false
	}
	return vs.cred != nil && len(vs.cred.Versions) > 0
}

// knownAlgorithmFamilies is the list of algorithm families to check for migration.
var knownAlgorithmFamilies = []string{"ec", "rsa", "ed", "ml-dsa", "slh-dsa", "ml-kem", "hybrid"}

// MigrateIfNeeded migrates old credential formats to the new unified format.
// This handles:
// 1. Old non-versioned credentials (algo dirs at root)
// 2. Old versioned credentials with versions.json
// 3. Old versioned credentials with algo dirs (versions/v1/ec/) to new structure (versions/v1/keys/, versions/v1/certs/)
func (vs *VersionStore) MigrateIfNeeded() error {
	// First, migrate from versions.json if it exists
	if err := vs.migrateFromVersionsJSON(); err != nil {
		return err
	}

	// Then migrate from root algo dirs if needed
	if err := vs.migrateFromRootAlgoDirs(); err != nil {
		return err
	}

	// Finally, migrate from algo dirs to keys/certs structure
	return vs.migrateToKeysAndCertsStructure()
}

// migrateFromVersionsJSON migrates from the old versions.json format.
func (vs *VersionStore) migrateFromVersionsJSON() error {
	versionsJSONPath := filepath.Join(vs.basePath, "versions.json")

	// Check if versions.json exists
	data, err := os.ReadFile(versionsJSONPath)
	if os.IsNotExist(err) {
		return nil // No migration needed
	}
	if err != nil {
		return fmt.Errorf("failed to read versions.json: %w", err)
	}

	// Parse old VersionIndex
	var oldIndex struct {
		Versions []struct {
			ID           string            `json:"id"`
			Profiles     []string          `json:"profiles"`
			Certificates []VersionCertRef  `json:"certificates"`
			Created      time.Time         `json:"created"`
			ActivatedAt  *time.Time        `json:"activated_at,omitempty"`
			ArchivedAt   *time.Time        `json:"archived_at,omitempty"`
		} `json:"versions"`
		ActiveVersion string `json:"active_version"`
		NextVersion   int    `json:"next_version"`
	}
	if err := json.Unmarshal(data, &oldIndex); err != nil {
		return fmt.Errorf("failed to parse versions.json: %w", err)
	}

	// Load credential
	if err := vs.loadCredential(); err != nil {
		return err
	}
	if vs.cred == nil {
		return fmt.Errorf("credential not found for migration")
	}

	// Migrate versions to credential.Versions if empty
	if len(vs.cred.Versions) == 0 && len(oldIndex.Versions) > 0 {
		for _, v := range oldIndex.Versions {
			// Extract algos from certificates
			algos := make([]string, 0)
			for _, cert := range v.Certificates {
				if cert.AlgorithmFamily != "" {
					algos = append(algos, cert.AlgorithmFamily)
				}
			}

			vs.cred.Versions[v.ID] = CredVersion{
				Profiles:    v.Profiles,
				Algos:       algos,
				Created:     v.Created,
				ActivatedAt: v.ActivatedAt,
				ArchivedAt:  v.ArchivedAt,
			}
		}
		vs.cred.Active = oldIndex.ActiveVersion
		if err := vs.cred.Save(); err != nil {
			return fmt.Errorf("failed to save migrated credential: %w", err)
		}
	}

	// Remove old active/ directory if it exists (no longer needed)
	activeDir := filepath.Join(vs.basePath, "active")
	if vs.exists(activeDir) {
		_ = os.RemoveAll(activeDir)
	}

	// Remove versions.json
	if err := os.Remove(versionsJSONPath); err != nil {
		return fmt.Errorf("failed to remove versions.json: %w", err)
	}

	return nil
}

// migrateFromRootAlgoDirs migrates old non-versioned credentials.
func (vs *VersionStore) migrateFromRootAlgoDirs() error {
	// Check if already versioned
	if vs.IsVersioned() {
		return nil
	}

	// Check if there are any root files to migrate
	if !vs.hasRootFiles() {
		return nil
	}

	// Load credential
	if err := vs.loadCredential(); err != nil {
		return err
	}
	if vs.cred == nil {
		return fmt.Errorf("credential not found for migration")
	}

	// Initialize version store
	if err := vs.Init(); err != nil {
		return fmt.Errorf("failed to init version store: %w", err)
	}

	// Create versions/v1/
	v1Dir := vs.VersionDir("v1")
	if err := os.MkdirAll(v1Dir, 0755); err != nil {
		return fmt.Errorf("failed to create v1 directory: %w", err)
	}

	// Move algorithm family directories from root to v1
	migratedFamilies := []string{}
	for _, algoFamily := range knownAlgorithmFamilies {
		srcDir := filepath.Join(vs.basePath, algoFamily)
		if vs.exists(srcDir) {
			dstDir := filepath.Join(v1Dir, algoFamily)
			if err := os.Rename(srcDir, dstDir); err != nil {
				return fmt.Errorf("failed to move %s to v1: %w", algoFamily, err)
			}
			migratedFamilies = append(migratedFamilies, algoFamily)
		}
	}

	// Remove root certificates.pem and private-keys.pem if they exist
	for _, filename := range []string{"certificates.pem", "private-keys.pem"} {
		srcFile := filepath.Join(vs.basePath, filename)
		if vs.exists(srcFile) {
			_ = os.Remove(srcFile)
		}
	}

	// Update credential with v1 version
	now := time.Now()
	vs.cred.Versions["v1"] = CredVersion{
		Profiles:    []string{},
		Algos:       migratedFamilies,
		Created:     now,
		ActivatedAt: &now,
	}
	vs.cred.Active = "v1"

	return vs.cred.Save()
}

// hasRootFiles checks if there are any algorithm family directories at the root.
func (vs *VersionStore) hasRootFiles() bool {
	for _, algoFamily := range knownAlgorithmFamilies {
		if vs.exists(filepath.Join(vs.basePath, algoFamily)) {
			return true
		}
	}
	return false
}

// migrateToKeysAndCertsStructure migrates from old algo-dir structure to new keys/certs structure.
// Old: versions/v1/ec/certificates.pem, versions/v1/ec/private-keys.pem
// New: versions/v1/certs/credential.ec.pem, versions/v1/keys/credential.ec.key
func (vs *VersionStore) migrateToKeysAndCertsStructure() error {
	// Check if versioned
	if !vs.IsVersioned() {
		return nil
	}

	// Load credential
	if err := vs.loadCredential(); err != nil {
		return err
	}
	if vs.cred == nil {
		return nil
	}

	// Check each version for old structure
	for versionID, ver := range vs.cred.Versions {
		versionDir := vs.VersionDir(versionID)

		// Check if old structure exists (algo family dirs like ec/, ml-dsa/)
		hasOldStructure := false
		for _, algoFamily := range ver.Algos {
			algoDirPath := filepath.Join(versionDir, algoFamily)
			if vs.exists(algoDirPath) {
				// Check for certificates.pem or private-keys.pem inside
				if vs.exists(filepath.Join(algoDirPath, "certificates.pem")) ||
					vs.exists(filepath.Join(algoDirPath, "private-keys.pem")) {
					hasOldStructure = true
					break
				}
			}
		}

		if !hasOldStructure {
			// Also check known families in case Algos is empty
			for _, algoFamily := range knownAlgorithmFamilies {
				algoDirPath := filepath.Join(versionDir, algoFamily)
				if vs.exists(algoDirPath) {
					if vs.exists(filepath.Join(algoDirPath, "certificates.pem")) ||
						vs.exists(filepath.Join(algoDirPath, "private-keys.pem")) {
						hasOldStructure = true
						break
					}
				}
			}
		}

		if !hasOldStructure {
			continue // Already migrated or new structure
		}

		// Create new directories
		keysDir := vs.KeysDir(versionID)
		certsDir := vs.CertsDir(versionID)
		if err := os.MkdirAll(keysDir, 0700); err != nil {
			return fmt.Errorf("failed to create keys directory: %w", err)
		}
		if err := os.MkdirAll(certsDir, 0755); err != nil {
			return fmt.Errorf("failed to create certs directory: %w", err)
		}

		// Migrate each algo family
		migratedAlgos := []string{}
		for _, algoFamily := range knownAlgorithmFamilies {
			algoDirPath := filepath.Join(versionDir, algoFamily)
			if !vs.exists(algoDirPath) {
				continue
			}

			// Migrate certificates.pem -> certs/credential.{algo}.pem
			oldCertPath := filepath.Join(algoDirPath, "certificates.pem")
			if vs.exists(oldCertPath) {
				newCertPath := vs.CertPath(versionID, algoFamily)
				if err := os.Rename(oldCertPath, newCertPath); err != nil {
					return fmt.Errorf("failed to migrate certificate for %s: %w", algoFamily, err)
				}
			}

			// Migrate private-keys.pem -> keys/credential.{algo}.key
			oldKeyPath := filepath.Join(algoDirPath, "private-keys.pem")
			if vs.exists(oldKeyPath) {
				newKeyPath := vs.KeyPath(versionID, algoFamily)
				if err := os.Rename(oldKeyPath, newKeyPath); err != nil {
					return fmt.Errorf("failed to migrate key for %s: %w", algoFamily, err)
				}
			}

			// Remove old algo directory (should be empty now)
			_ = os.Remove(algoDirPath)

			migratedAlgos = append(migratedAlgos, algoFamily)
		}

		// Update algos in version if we found new ones
		if len(migratedAlgos) > 0 && len(ver.Algos) == 0 {
			ver.Algos = migratedAlgos
			vs.cred.Versions[versionID] = ver
		}
	}

	return vs.cred.Save()
}

// CreateInitialVersion creates the first version (v1) during enrollment.
// This should only be called when creating a new credential.
func (vs *VersionStore) CreateInitialVersion(profiles []string) (*Version, error) {
	if err := vs.Init(); err != nil {
		return nil, err
	}

	if len(profiles) == 0 {
		return nil, fmt.Errorf("at least one profile is required")
	}

	// Load or create credential
	if err := vs.loadCredential(); err != nil {
		return nil, err
	}
	if vs.cred == nil {
		return nil, fmt.Errorf("credential not found")
	}

	now := time.Now()
	version := &Version{
		ID:           "v1",
		Profiles:     profiles,
		Certificates: []VersionCertRef{},
		Created:      now,
		ActivatedAt:  &now,
	}

	// Create version directory structure
	versionDir := vs.VersionDir("v1")
	if err := os.MkdirAll(versionDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create version directory: %w", err)
	}

	// Update credential with v1 version
	vs.cred.Versions["v1"] = CredVersion{
		Profiles:    profiles,
		Algos:       []string{},
		Created:     now,
		ActivatedAt: &now,
	}
	vs.cred.Active = "v1"

	if err := vs.cred.Save(); err != nil {
		return nil, fmt.Errorf("failed to save credential: %w", err)
	}

	return version, nil
}

// CreateVersion creates a new version entry with multiple profiles (for rotation).
// This creates versions v2, v3, etc. with PENDING status.
func (vs *VersionStore) CreateVersion(profiles []string) (*Version, error) {
	if err := vs.Init(); err != nil {
		return nil, err
	}

	if len(profiles) == 0 {
		return nil, fmt.Errorf("at least one profile is required")
	}

	// Load credential
	if err := vs.loadCredential(); err != nil {
		return nil, err
	}
	if vs.cred == nil {
		return nil, fmt.Errorf("credential not found")
	}

	// Generate next version ID
	id := vs.cred.NextVersionID()

	version := &Version{
		ID:           id,
		Profiles:     profiles,
		Certificates: []VersionCertRef{},
		Created:      time.Now(),
	}

	// Create version directory structure
	versionDir := vs.VersionDir(id)
	if err := os.MkdirAll(versionDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create version directory: %w", err)
	}

	// Add version to credential (pending status - no ActivatedAt)
	vs.cred.Versions[id] = CredVersion{
		Profiles: profiles,
		Algos:    []string{},
		Created:  version.Created,
	}

	if err := vs.cred.Save(); err != nil {
		return nil, fmt.Errorf("failed to save credential: %w", err)
	}

	return version, nil
}

// AddCertificate adds a certificate reference to a version.
func (vs *VersionStore) AddCertificate(versionID string, certRef VersionCertRef) error {
	if err := vs.loadCredential(); err != nil {
		return err
	}
	if vs.cred == nil {
		return fmt.Errorf("credential not found")
	}

	ver, ok := vs.cred.Versions[versionID]
	if !ok {
		return fmt.Errorf("version not found: %s", versionID)
	}

	// Add algo to the version's Algos list if not present
	algoFound := false
	for _, a := range ver.Algos {
		if a == certRef.AlgorithmFamily {
			algoFound = true
			break
		}
	}
	if !algoFound && certRef.AlgorithmFamily != "" {
		ver.Algos = append(ver.Algos, certRef.AlgorithmFamily)
	}

	vs.cred.Versions[versionID] = ver
	return vs.cred.Save()
}

// GetVersion returns a version by ID.
func (vs *VersionStore) GetVersion(id string) (*Version, error) {
	if err := vs.loadCredential(); err != nil {
		return nil, err
	}
	if vs.cred == nil {
		return nil, fmt.Errorf("credential not found")
	}

	ver, ok := vs.cred.Versions[id]
	if !ok {
		return nil, fmt.Errorf("version not found: %s", id)
	}

	// Build certificates from algos
	var certs []VersionCertRef
	for _, algo := range ver.Algos {
		certs = append(certs, VersionCertRef{
			AlgorithmFamily: algo,
		})
	}

	return &Version{
		ID:           id,
		Profiles:     ver.Profiles,
		Certificates: certs,
		Created:      ver.Created,
		ActivatedAt:  ver.ActivatedAt,
		ArchivedAt:   ver.ArchivedAt,
	}, nil
}

// GetActiveVersion returns the active version.
func (vs *VersionStore) GetActiveVersion() (*Version, error) {
	if err := vs.loadCredential(); err != nil {
		return nil, err
	}
	if vs.cred == nil || vs.cred.Active == "" {
		return nil, fmt.Errorf("no active version")
	}

	return vs.GetVersion(vs.cred.Active)
}

// GetCertForAlgo returns the certificate reference for a given algorithm family.
func (vs *VersionStore) GetCertForAlgo(versionID, algorithmFamily string) (*VersionCertRef, error) {
	version, err := vs.GetVersion(versionID)
	if err != nil {
		return nil, err
	}

	for _, cert := range version.Certificates {
		if cert.AlgorithmFamily == algorithmFamily {
			return &cert, nil
		}
	}

	return nil, fmt.Errorf("no certificate found for algorithm family %s in version %s", algorithmFamily, versionID)
}

// GetActiveCertForAlgo returns the certificate for a given algorithm family from the active version.
func (vs *VersionStore) GetActiveCertForAlgo(algorithmFamily string) (*VersionCertRef, error) {
	activeVersion, err := vs.GetActiveVersion()
	if err != nil {
		return nil, err
	}

	return vs.GetCertForAlgo(activeVersion.ID, algorithmFamily)
}

// ListAlgorithmFamilies returns all algorithm families in the active version.
func (vs *VersionStore) ListAlgorithmFamilies() ([]string, error) {
	activeVersion, err := vs.GetActiveVersion()
	if err != nil {
		return nil, err
	}

	families := make([]string, 0, len(activeVersion.Certificates))
	for _, cert := range activeVersion.Certificates {
		families = append(families, cert.AlgorithmFamily)
	}
	return families, nil
}

// Activate activates a pending or archived version (for rollback).
func (vs *VersionStore) Activate(versionID string) error {
	if err := vs.loadCredential(); err != nil {
		return err
	}
	if vs.cred == nil {
		return fmt.Errorf("credential not found")
	}

	if err := vs.cred.ActivateVersion(versionID); err != nil {
		return err
	}

	return vs.cred.Save()
}

// ListVersions returns all versions sorted by creation time (newest first).
func (vs *VersionStore) ListVersions() ([]Version, error) {
	if err := vs.loadCredential(); err != nil {
		return nil, err
	}
	if vs.cred == nil {
		return nil, nil
	}

	versions := make([]Version, 0, len(vs.cred.Versions))
	for id, ver := range vs.cred.Versions {
		// Build certificates from algos
		var certs []VersionCertRef
		for _, algo := range ver.Algos {
			certs = append(certs, VersionCertRef{
				AlgorithmFamily: algo,
			})
		}

		versions = append(versions, Version{
			ID:           id,
			Profiles:     ver.Profiles,
			Certificates: certs,
			Created:      ver.Created,
			ActivatedAt:  ver.ActivatedAt,
			ArchivedAt:   ver.ArchivedAt,
		})
	}

	// Sort by creation time (newest first)
	sort.Slice(versions, func(i, j int) bool {
		return versions[i].Created.After(versions[j].Created)
	})

	return versions, nil
}

// generateVersionID creates a sequential version ID (v1, v2, v3...).
func generateVersionID(n int) string {
	return fmt.Sprintf("v%d", n)
}

// copyFile copies a file from src to dst.
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}

// copyDir recursively copies a directory from src to dst.
func copyDir(src, dst string) error {
	srcInfo, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("failed to stat source: %w", err)
	}

	if err := os.MkdirAll(dst, srcInfo.Mode()); err != nil {
		return fmt.Errorf("failed to create destination: %w", err)
	}

	entries, err := os.ReadDir(src)
	if err != nil {
		return fmt.Errorf("failed to read source directory: %w", err)
	}

	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		if entry.IsDir() {
			if err := copyDir(srcPath, dstPath); err != nil {
				return err
			}
		} else {
			if err := copyFile(srcPath, dstPath); err != nil {
				return fmt.Errorf("failed to copy %s: %w", entry.Name(), err)
			}
		}
	}

	return nil
}

// ============================================================================
// Standalone functions (public API)
// These functions provide a decoupled interface for version operations,
// following the same pattern as ca.LoadCAInfo() and ca.SaveCAInfo().
// ============================================================================

// CredentialPath returns the path to a credential directory.
func CredentialPath(basePath, credentialID string) string {
	return filepath.Join(basePath, credentialID)
}

// IsVersioned returns true if a credential uses versioning.
func IsVersioned(basePath, credentialID string) bool {
	vs := NewVersionStore(CredentialPath(basePath, credentialID))
	return vs.IsVersioned()
}

// ListVersions returns all versions for a credential.
func ListVersions(basePath, credentialID string) ([]Version, error) {
	vs := NewVersionStore(CredentialPath(basePath, credentialID))
	return vs.ListVersions()
}

// ActivateVersion activates a pending version for a credential.
func ActivateVersion(basePath, credentialID, versionID string) error {
	vs := NewVersionStore(CredentialPath(basePath, credentialID))
	return vs.Activate(versionID)
}

// SaveVersion saves a credential version with its certificates and keys in the version directory.
// This is used for multi-profile versioned credentials.
// Files are saved as: versions/{versionID}/certs/credential.{algoFamily}.pem
//
//	versions/{versionID}/keys/credential.{algoFamily}.key
func SaveVersion(basePath, credentialID, versionID, algoFamily string, certs []*x509.Certificate, signers []pkicrypto.Signer, passphrase []byte) error {
	vs := NewVersionStore(CredentialPath(basePath, credentialID))

	// Create keys and certs directories
	if err := os.MkdirAll(vs.KeysDir(versionID), 0700); err != nil {
		return fmt.Errorf("failed to create keys directory: %w", err)
	}
	if err := os.MkdirAll(vs.CertsDir(versionID), 0755); err != nil {
		return fmt.Errorf("failed to create certs directory: %w", err)
	}

	// Save certificates
	if len(certs) > 0 {
		certsPEM, err := EncodeCertificatesPEM(certs)
		if err != nil {
			return fmt.Errorf("failed to encode certificates: %w", err)
		}

		certPath := vs.CertPath(versionID, algoFamily)
		if err := os.WriteFile(certPath, certsPEM, 0644); err != nil {
			return fmt.Errorf("failed to write certificates: %w", err)
		}
	}

	// Save private keys (encrypted)
	if len(signers) > 0 {
		keysPEM, err := EncodePrivateKeysPEM(signers, passphrase)
		if err != nil {
			return fmt.Errorf("failed to encode private keys: %w", err)
		}

		if len(keysPEM) > 0 {
			keyPath := vs.KeyPath(versionID, algoFamily)
			if err := os.WriteFile(keyPath, keysPEM, 0600); err != nil {
				return fmt.Errorf("failed to write private keys: %w", err)
			}
		}
	}

	return nil
}

// LoadVersionCertificates loads certificates from a specific version and algorithm family.
// Reads from: versions/{versionID}/certs/credential.{algoFamily}.pem
func LoadVersionCertificates(basePath, credentialID, versionID, algoFamily string) ([]*x509.Certificate, error) {
	vs := NewVersionStore(CredentialPath(basePath, credentialID))
	certPath := vs.CertPath(versionID, algoFamily)

	data, err := os.ReadFile(certPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read certificates: %w", err)
	}

	return DecodeCertificatesPEM(data)
}

// LoadVersionKeys loads private keys from a specific version and algorithm family.
// Reads from: versions/{versionID}/keys/credential.{algoFamily}.key
func LoadVersionKeys(basePath, credentialID, versionID, algoFamily string, passphrase []byte) ([]pkicrypto.Signer, error) {
	vs := NewVersionStore(CredentialPath(basePath, credentialID))
	keyPath := vs.KeyPath(versionID, algoFamily)

	data, err := os.ReadFile(keyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read private keys: %w", err)
	}

	return DecodePrivateKeysPEM(data, passphrase)
}

// ============================================================================
// Backward compatibility
// ============================================================================

// VersionIndex is kept for backward compatibility during migration.
// Deprecated: Use Credential.Versions instead.
type VersionIndex struct {
	Versions      []Version `json:"versions"`
	ActiveVersion string    `json:"active_version"`
	NextVersion   int       `json:"next_version"`
}

// LoadIndex returns a VersionIndex for backward compatibility.
// Deprecated: Use Credential.Versions directly.
func (vs *VersionStore) LoadIndex() (*VersionIndex, error) {
	if err := vs.loadCredential(); err != nil {
		return nil, err
	}
	if vs.cred == nil {
		return &VersionIndex{Versions: []Version{}}, nil
	}

	versions, err := vs.ListVersions()
	if err != nil {
		return nil, err
	}

	return &VersionIndex{
		Versions:      versions,
		ActiveVersion: vs.cred.Active,
		NextVersion:   len(vs.cred.Versions) + 1,
	}, nil
}

// GetVersionStatus returns the computed status of a version.
// Deprecated: Use Credential.GetVersionStatus() instead.
func (idx *VersionIndex) GetVersionStatus(versionID string) VersionStatus {
	if versionID == idx.ActiveVersion {
		return VersionStatusActive
	}
	for _, ver := range idx.Versions {
		if ver.ID == versionID {
			if ver.ArchivedAt != nil {
				return VersionStatusArchived
			}
			return VersionStatusPending
		}
	}
	return VersionStatusPending
}

// ActiveDir returns the path to the active version directory.
// Deprecated: Use ActiveVersionDir() instead.
func (vs *VersionStore) ActiveDir() string {
	dir, err := vs.ActiveVersionDir()
	if err != nil {
		// Fallback for compatibility - return v1 path
		return vs.VersionDir("v1")
	}
	return dir
}
