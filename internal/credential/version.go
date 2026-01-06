package credential

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
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
type Version struct {
	// ID is the unique version identifier (e.g., v20251228_abc123).
	ID string `json:"id"`

	// Status is the current status of this version.
	Status VersionStatus `json:"status"`

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

// VersionIndex holds the index of all credential versions.
type VersionIndex struct {
	// Versions is the list of all versions (ordered by creation time, newest first).
	Versions []Version `json:"versions"`

	// ActiveVersion is the ID of the currently active version.
	ActiveVersion string `json:"active_version"`

	// NextVersion is the next version number to use (v1, v2, v3...).
	NextVersion int `json:"next_version"`
}

// VersionStore manages credential version storage.
type VersionStore struct {
	// basePath is the credential directory (credentials/{credentialID}).
	basePath string
}

// NewVersionStore creates a version store for a credential.
func NewVersionStore(credentialPath string) *VersionStore {
	return &VersionStore{basePath: credentialPath}
}

// VersionsDir returns the path to the versions directory.
func (vs *VersionStore) VersionsDir() string {
	return filepath.Join(vs.basePath, "versions")
}

// IndexPath returns the path to the versions index file.
func (vs *VersionStore) IndexPath() string {
	return filepath.Join(vs.basePath, "versions.json")
}

// VersionDir returns the directory for a specific version.
func (vs *VersionStore) VersionDir(versionID string) string {
	return filepath.Join(vs.VersionsDir(), versionID)
}

// ProfileDir returns the directory for a specific profile within a version.
// The directory is named after the algorithm family (e.g., "ec", "ml-dsa").
func (vs *VersionStore) ProfileDir(versionID, algorithmFamily string) string {
	return filepath.Join(vs.VersionDir(versionID), algorithmFamily)
}

// CurrentLink returns the path to the "current" symlink (deprecated, kept for compatibility).
func (vs *VersionStore) CurrentLink() string {
	return filepath.Join(vs.basePath, "current")
}

// ActiveDir returns the path to the active directory.
func (vs *VersionStore) ActiveDir() string {
	return filepath.Join(vs.basePath, "active")
}

// ActiveDirNew returns the path to the temporary new active directory.
func (vs *VersionStore) ActiveDirNew() string {
	return filepath.Join(vs.basePath, "active.new")
}

// ActiveDirOld returns the path to the temporary old active directory.
func (vs *VersionStore) ActiveDirOld() string {
	return filepath.Join(vs.basePath, "active.old")
}

// Init initializes the version store if needed.
func (vs *VersionStore) Init() error {
	if err := os.MkdirAll(vs.VersionsDir(), 0755); err != nil {
		return fmt.Errorf("failed to create versions directory: %w", err)
	}
	return nil
}

// RecoverIfNeeded recovers from a crash during activation.
// It should be called at the beginning of any operation that reads or modifies the version store.
func (vs *VersionStore) RecoverIfNeeded() error {
	active := vs.ActiveDir()
	activeOld := vs.ActiveDirOld()
	activeNew := vs.ActiveDirNew()

	// Check if we crashed between the two renames during activation
	// If active doesn't exist but active.old does, we need to rollback
	activeExists := vs.exists(active)
	activeOldExists := vs.exists(activeOld)

	if !activeExists && activeOldExists {
		// Crash between rename 1 and 2: rollback to old version
		if err := os.Rename(activeOld, active); err != nil {
			return fmt.Errorf("failed to recover from crash (rollback): %w", err)
		}
	}

	// Cleanup any temporary directories
	_ = os.RemoveAll(activeNew)
	_ = os.RemoveAll(activeOld)

	return nil
}

// exists checks if a path exists.
func (vs *VersionStore) exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// IsVersioned returns true if this credential uses versioning.
func (vs *VersionStore) IsVersioned() bool {
	_, err := os.Stat(vs.IndexPath())
	return err == nil
}

// knownAlgorithmFamilies is the list of algorithm families to check for migration.
var knownAlgorithmFamilies = []string{"ec", "rsa", "ed", "ml-dsa", "slh-dsa", "ml-kem", "hybrid"}

// MigrateIfNeeded migrates an old non-versioned credential to the new versioned format.
// It should be called when loading a credential.
// If the credential is already versioned, this is a no-op.
func (vs *VersionStore) MigrateIfNeeded() error {
	// Already versioned, nothing to do
	if vs.IsVersioned() {
		return nil
	}

	// Check if there are any root files to migrate
	if !vs.hasRootFiles() {
		return nil // Empty credential, nothing to migrate
	}

	// 1. Initialize version store
	if err := vs.Init(); err != nil {
		return fmt.Errorf("failed to init version store: %w", err)
	}

	// 2. Create versions/v1/
	v1Dir := vs.VersionDir("v1")
	if err := os.MkdirAll(v1Dir, 0755); err != nil {
		return fmt.Errorf("failed to create v1 directory: %w", err)
	}

	// 3. Move algorithm family directories from root to v1
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

	// 4. Move root certificates.pem and private-keys.pem if they exist
	for _, filename := range []string{"certificates.pem", "private-keys.pem"} {
		srcFile := filepath.Join(vs.basePath, filename)
		if vs.exists(srcFile) {
			// These are redundant copies, just remove them
			// The algorithm family directories contain the actual files
			_ = os.Remove(srcFile)
		}
	}

	// 5. Create versions.json with v1 as ACTIVE
	now := time.Now()
	index := &VersionIndex{
		ActiveVersion: "v1",
		NextVersion:   2,
		Versions: []Version{{
			ID:          "v1",
			Status:      VersionStatusActive,
			Profiles:    []string{}, // Will be populated from credential.json if available
			Created:     now,
			ActivatedAt: &now,
		}},
	}

	// Add certificate refs for migrated families
	for _, algoFamily := range migratedFamilies {
		index.Versions[0].Certificates = append(index.Versions[0].Certificates, VersionCertRef{
			AlgorithmFamily: algoFamily,
		})
	}

	if err := vs.SaveIndex(index); err != nil {
		return fmt.Errorf("failed to save version index: %w", err)
	}

	// 6. Create active/ directory as copy of v1
	if err := copyDir(v1Dir, vs.ActiveDir()); err != nil {
		return fmt.Errorf("failed to create active directory: %w", err)
	}

	return nil
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

// LoadIndex loads the version index.
func (vs *VersionStore) LoadIndex() (*VersionIndex, error) {
	data, err := os.ReadFile(vs.IndexPath())
	if err != nil {
		if os.IsNotExist(err) {
			return &VersionIndex{Versions: []Version{}}, nil
		}
		return nil, fmt.Errorf("failed to read version index: %w", err)
	}

	var index VersionIndex
	if err := json.Unmarshal(data, &index); err != nil {
		return nil, fmt.Errorf("failed to parse version index: %w", err)
	}

	return &index, nil
}

// SaveIndex saves the version index.
func (vs *VersionStore) SaveIndex(index *VersionIndex) error {
	// Sort versions by creation time (newest first)
	sort.Slice(index.Versions, func(i, j int) bool {
		return index.Versions[i].Created.After(index.Versions[j].Created)
	})

	data, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal version index: %w", err)
	}

	if err := os.WriteFile(vs.IndexPath(), data, 0644); err != nil {
		return fmt.Errorf("failed to write version index: %w", err)
	}

	return nil
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

	now := time.Now()
	version := &Version{
		ID:           "v1",
		Status:       VersionStatusActive, // v1 is immediately active
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

	// Create index with v1 as active
	index := &VersionIndex{
		ActiveVersion: "v1",
		NextVersion:   2, // Next rotation will be v2
		Versions:      []Version{*version},
	}

	if err := vs.SaveIndex(index); err != nil {
		return nil, err
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

	// Load index to get NextVersion
	index, err := vs.LoadIndex()
	if err != nil {
		return nil, err
	}

	// Initialize NextVersion if needed (should be 2 after v1 creation)
	if index.NextVersion == 0 {
		index.NextVersion = 2
	}

	id := generateVersionID(index.NextVersion)
	index.NextVersion++

	version := &Version{
		ID:           id,
		Status:       VersionStatusPending,
		Profiles:     profiles,
		Certificates: []VersionCertRef{},
		Created:      time.Now(),
	}

	// Create version directory structure
	versionDir := vs.VersionDir(id)
	if err := os.MkdirAll(versionDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create version directory: %w", err)
	}

	index.Versions = append(index.Versions, *version)

	if err := vs.SaveIndex(index); err != nil {
		return nil, err
	}

	return version, nil
}

// ActivateInitialVersion creates the active/ directory from v1.
// This should be called after saving files to versions/v1/.
func (vs *VersionStore) ActivateInitialVersion() error {
	v1Dir := vs.VersionDir("v1")
	if !vs.exists(v1Dir) {
		return fmt.Errorf("v1 directory does not exist")
	}

	// Create active/ as copy of v1
	if err := copyDir(v1Dir, vs.ActiveDir()); err != nil {
		return fmt.Errorf("failed to create active directory: %w", err)
	}

	return nil
}

// AddCertificate adds a certificate reference to a version.
func (vs *VersionStore) AddCertificate(versionID string, certRef VersionCertRef) error {
	index, err := vs.LoadIndex()
	if err != nil {
		return err
	}

	for i := range index.Versions {
		if index.Versions[i].ID == versionID {
			index.Versions[i].Certificates = append(index.Versions[i].Certificates, certRef)
			return vs.SaveIndex(index)
		}
	}

	return fmt.Errorf("version not found: %s", versionID)
}

// GetVersion returns a version by ID.
func (vs *VersionStore) GetVersion(id string) (*Version, error) {
	index, err := vs.LoadIndex()
	if err != nil {
		return nil, err
	}

	for _, v := range index.Versions {
		if v.ID == id {
			return &v, nil
		}
	}

	return nil, fmt.Errorf("version not found: %s", id)
}

// GetActiveVersion returns the active version.
func (vs *VersionStore) GetActiveVersion() (*Version, error) {
	index, err := vs.LoadIndex()
	if err != nil {
		return nil, err
	}

	if index.ActiveVersion == "" {
		return nil, fmt.Errorf("no active version")
	}

	return vs.GetVersion(index.ActiveVersion)
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

// Activate activates a version and archives the previously active one.
// Uses atomic directory rename for crash-safe activation.
func (vs *VersionStore) Activate(versionID string) error {
	// Recover from any previous crash
	if err := vs.RecoverIfNeeded(); err != nil {
		return fmt.Errorf("recovery failed: %w", err)
	}

	index, err := vs.LoadIndex()
	if err != nil {
		return err
	}

	now := time.Now()
	var found bool

	for i := range index.Versions {
		switch index.Versions[i].ID {
		case versionID:
			if index.Versions[i].Status != VersionStatusPending {
				return fmt.Errorf("can only activate pending versions, current status: %s", index.Versions[i].Status)
			}
			index.Versions[i].Status = VersionStatusActive
			index.Versions[i].ActivatedAt = &now
			found = true
		case index.ActiveVersion:
			// Archive previously active version
			index.Versions[i].Status = VersionStatusArchived
			index.Versions[i].ArchivedAt = &now
		}
	}

	if !found {
		return fmt.Errorf("version not found: %s", versionID)
	}

	index.ActiveVersion = versionID

	// Atomic activation: copy version to active.new, then atomic rename
	if err := vs.activateAtomic(versionID); err != nil {
		return err
	}

	return vs.SaveIndex(index)
}

// activateAtomic performs atomic activation using directory rename.
// This is crash-safe: if we crash at any point, RecoverIfNeeded will restore consistency.
func (vs *VersionStore) activateAtomic(versionID string) error {
	versionDir := vs.VersionDir(versionID)
	active := vs.ActiveDir()
	activeNew := vs.ActiveDirNew()
	activeOld := vs.ActiveDirOld()

	// 1. Prepare new active directory
	if err := os.RemoveAll(activeNew); err != nil {
		return fmt.Errorf("failed to cleanup active.new: %w", err)
	}
	if err := copyDir(versionDir, activeNew); err != nil {
		return fmt.Errorf("failed to prepare active.new: %w", err)
	}

	// 2. Atomic rename sequence
	// If active exists, rename it to active.old
	if vs.exists(active) {
		if err := os.Rename(active, activeOld); err != nil {
			return fmt.Errorf("failed to rename active to active.old: %w", err)
		}
	}

	// Rename active.new to active (ATOMIC on same filesystem)
	if err := os.Rename(activeNew, active); err != nil {
		// Try to rollback
		if vs.exists(activeOld) {
			_ = os.Rename(activeOld, active)
		}
		return fmt.Errorf("failed to rename active.new to active: %w", err)
	}

	// 3. Cleanup old directory
	_ = os.RemoveAll(activeOld)

	return nil
}

// updateCurrentLink updates the "current" symlink to point to the given version.
func (vs *VersionStore) updateCurrentLink(versionID string) error {
	linkPath := vs.CurrentLink()

	// Remove existing link if it exists
	if _, err := os.Lstat(linkPath); err == nil {
		if err := os.Remove(linkPath); err != nil {
			return fmt.Errorf("failed to remove old current link: %w", err)
		}
	}

	// Create relative symlink
	relPath := filepath.Join("versions", versionID)
	if err := os.Symlink(relPath, linkPath); err != nil {
		return fmt.Errorf("failed to create current link: %w", err)
	}

	return nil
}

// syncToRoot copies the active version's files to the credential root for backward compatibility.
// This updates certificates.pem and private-keys.pem in the root directory.
func (vs *VersionStore) syncToRoot(versionID string) error {
	version, err := vs.GetVersion(versionID)
	if err != nil {
		return err
	}

	// Sync each algorithm family's files to root subdirectory
	for _, cert := range version.Certificates {
		algoFamily := cert.AlgorithmFamily
		profileDir := vs.ProfileDir(versionID, algoFamily)

		// Create algorithm family directory at root
		dstAlgoDir := filepath.Join(vs.basePath, algoFamily)
		if err := os.MkdirAll(dstAlgoDir, 0755); err != nil {
			return fmt.Errorf("failed to create %s directory: %w", algoFamily, err)
		}

		// Copy certificates
		srcCert := filepath.Join(profileDir, "certificates.pem")
		dstCert := filepath.Join(dstAlgoDir, "certificates.pem")
		if _, statErr := os.Stat(srcCert); statErr == nil {
			if err := copyFile(srcCert, dstCert); err != nil {
				return fmt.Errorf("failed to sync %s/certificates.pem: %w", algoFamily, err)
			}
		}

		// Copy private keys
		srcKey := filepath.Join(profileDir, "private-keys.pem")
		dstKey := filepath.Join(dstAlgoDir, "private-keys.pem")
		if _, statErr := os.Stat(srcKey); statErr == nil {
			if err := copyFile(srcKey, dstKey); err != nil {
				return fmt.Errorf("failed to sync %s/private-keys.pem: %w", algoFamily, err)
			}
		}
	}

	// For backward compatibility, also copy the first (or EC) certificate to root
	if len(version.Certificates) > 0 {
		var primaryCert *VersionCertRef
		for i := range version.Certificates {
			if version.Certificates[i].AlgorithmFamily == "ec" {
				primaryCert = &version.Certificates[i]
				break
			}
		}
		if primaryCert == nil {
			primaryCert = &version.Certificates[0]
		}

		profileDir := vs.ProfileDir(versionID, primaryCert.AlgorithmFamily)

		// Copy primary certificates to root
		srcCert := filepath.Join(profileDir, "certificates.pem")
		dstCert := filepath.Join(vs.basePath, "certificates.pem")
		if _, statErr := os.Stat(srcCert); statErr == nil {
			if err := copyFile(srcCert, dstCert); err != nil {
				return fmt.Errorf("failed to sync root certificates.pem: %w", err)
			}
		}

		// Copy primary key to root
		srcKey := filepath.Join(profileDir, "private-keys.pem")
		dstKey := filepath.Join(vs.basePath, "private-keys.pem")
		if _, statErr := os.Stat(srcKey); statErr == nil {
			if err := copyFile(srcKey, dstKey); err != nil {
				return fmt.Errorf("failed to sync root private-keys.pem: %w", err)
			}
		}
	}

	return nil
}

// ListVersions returns all versions.
func (vs *VersionStore) ListVersions() ([]Version, error) {
	index, err := vs.LoadIndex()
	if err != nil {
		return nil, err
	}
	return index.Versions, nil
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
	// Get source info
	srcInfo, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("failed to stat source: %w", err)
	}

	// Create destination directory
	if err := os.MkdirAll(dst, srcInfo.Mode()); err != nil {
		return fmt.Errorf("failed to create destination: %w", err)
	}

	// Read source directory
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
