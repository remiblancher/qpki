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

// CurrentLink returns the path to the "current" symlink.
func (vs *VersionStore) CurrentLink() string {
	return filepath.Join(vs.basePath, "current")
}

// Init initializes the version store if needed.
func (vs *VersionStore) Init() error {
	if err := os.MkdirAll(vs.VersionsDir(), 0755); err != nil {
		return fmt.Errorf("failed to create versions directory: %w", err)
	}
	return nil
}

// IsVersioned returns true if this credential uses versioning.
func (vs *VersionStore) IsVersioned() bool {
	_, err := os.Stat(vs.IndexPath())
	return err == nil
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

// CreateVersion creates a new version entry with multiple profiles.
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

	// Initialize NextVersion if needed (v1 = original credential, v2 = first rotation)
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
func (vs *VersionStore) Activate(versionID string) error {
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

	// Update current symlink
	if err := vs.updateCurrentLink(versionID); err != nil {
		return err
	}

	// Sync files to root for backward compatibility
	if err := vs.syncToRoot(versionID); err != nil {
		return err
	}

	return vs.SaveIndex(index)
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
