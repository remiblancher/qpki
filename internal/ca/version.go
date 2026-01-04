// Package ca implements Certificate Authority functionality.
package ca

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// VersionStatus represents the status of a CA version.
type VersionStatus string

const (
	// VersionStatusActive indicates this is the currently active CA version.
	VersionStatusActive VersionStatus = "active"

	// VersionStatusPending indicates a newly rotated CA awaiting activation.
	VersionStatusPending VersionStatus = "pending"

	// VersionStatusArchived indicates a previously active CA that has been superseded.
	VersionStatusArchived VersionStatus = "archived"
)

// Version represents a CA version.
// Each version has its own directory with keys, certificates, and metadata.
type Version struct {
	// ID is the unique version identifier (e.g., v20251228_abc123).
	ID string `json:"id"`

	// Status is the current status of this version.
	Status VersionStatus `json:"status"`

	// Profile is the profile name used for this CA version.
	Profile string `json:"profile"`

	// Algorithm is the primary algorithm used.
	Algorithm string `json:"algorithm"`

	// Created is when this version was created.
	Created time.Time `json:"created"`

	// ActivatedAt is when this version was activated (if status is active/archived).
	ActivatedAt *time.Time `json:"activated_at,omitempty"`

	// ArchivedAt is when this version was archived (if status is archived).
	ArchivedAt *time.Time `json:"archived_at,omitempty"`

	// CrossSignedBy lists version IDs that have cross-signed this CA.
	CrossSignedBy []string `json:"cross_signed_by,omitempty"`

	// Subject is the CA certificate subject.
	Subject string `json:"subject"`

	// NotBefore is the CA certificate validity start.
	NotBefore time.Time `json:"not_before"`

	// NotAfter is the CA certificate validity end.
	NotAfter time.Time `json:"not_after"`
}

// VersionIndex holds the index of all CA versions.
type VersionIndex struct {
	// Versions is the list of all versions (ordered by creation time, newest first).
	Versions []Version `json:"versions"`

	// ActiveVersion is the ID of the currently active version.
	ActiveVersion string `json:"active_version"`
}

// VersionStore manages CA version storage.
type VersionStore struct {
	basePath string
}

// NewVersionStore creates a version store at the given path.
func NewVersionStore(basePath string) *VersionStore {
	return &VersionStore{basePath: basePath}
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

// IsVersioned returns true if this CA uses versioning.
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

// CreateVersion creates a new version entry.
func (vs *VersionStore) CreateVersion(profile, algorithm, subject string, notBefore, notAfter time.Time) (*Version, error) {
	if err := vs.Init(); err != nil {
		return nil, err
	}

	id := generateVersionID()

	version := &Version{
		ID:        id,
		Status:    VersionStatusPending,
		Profile:   profile,
		Algorithm: algorithm,
		Created:   time.Now(),
		Subject:   subject,
		NotBefore: notBefore,
		NotAfter:  notAfter,
	}

	// Create version directory
	versionDir := vs.VersionDir(id)
	if err := os.MkdirAll(filepath.Join(versionDir, "private"), 0755); err != nil {
		return nil, fmt.Errorf("failed to create version directory: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(versionDir, "certs"), 0755); err != nil {
		return nil, fmt.Errorf("failed to create certs directory: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(versionDir, "crl"), 0755); err != nil {
		return nil, fmt.Errorf("failed to create crl directory: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(versionDir, "cross-signed"), 0755); err != nil {
		return nil, fmt.Errorf("failed to create cross-signed directory: %w", err)
	}

	// Load and update index
	index, err := vs.LoadIndex()
	if err != nil {
		return nil, err
	}

	index.Versions = append(index.Versions, *version)

	if err := vs.SaveIndex(index); err != nil {
		return nil, err
	}

	return version, nil
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

	// Copy active version files to root (backward compatibility)
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

// syncToRoot copies the active version's files to the CA root for backward compatibility.
// This allows existing tools that expect ca.crt, private/ca.key, etc. to continue working.
func (vs *VersionStore) syncToRoot(versionID string) error {
	versionDir := vs.VersionDir(versionID)

	// Copy ca.crt
	srcCert := filepath.Join(versionDir, "ca.crt")
	dstCert := filepath.Join(vs.basePath, "ca.crt")
	if err := copyFile(srcCert, dstCert); err != nil {
		return fmt.Errorf("failed to sync ca.crt: %w", err)
	}

	// Ensure private directory exists
	dstPrivateDir := filepath.Join(vs.basePath, "private")
	if err := os.MkdirAll(dstPrivateDir, 0755); err != nil {
		return fmt.Errorf("failed to create private directory: %w", err)
	}

	// Copy metadata if it exists
	srcMeta := filepath.Join(versionDir, MetadataFile)
	dstMeta := filepath.Join(vs.basePath, MetadataFile)
	if _, err := os.Stat(srcMeta); err == nil {
		if err := copyFile(srcMeta, dstMeta); err != nil {
			return fmt.Errorf("failed to sync ca.meta.json: %w", err)
		}
	}

	// Try to load metadata to determine key paths
	metadata, _ := LoadCAMetadata(versionDir)
	if metadata != nil && len(metadata.Keys) > 0 {
		// New format: copy keys based on metadata
		for _, keyRef := range metadata.Keys {
			if keyRef.Storage.Type != "software" && keyRef.Storage.Type != "" {
				continue // Skip HSM keys
			}
			srcKey := filepath.Join(versionDir, keyRef.Storage.Path)
			dstKey := filepath.Join(vs.basePath, keyRef.Storage.Path)
			if _, err := os.Stat(srcKey); err == nil {
				if err := copyFile(srcKey, dstKey); err != nil {
					return fmt.Errorf("failed to sync key %s: %w", keyRef.ID, err)
				}
			}
		}
	} else {
		// Legacy format: copy private/ca.key
		srcKey := filepath.Join(versionDir, "private", "ca.key")
		dstKey := filepath.Join(vs.basePath, "private", "ca.key")
		if err := copyFile(srcKey, dstKey); err != nil {
			return fmt.Errorf("failed to sync ca.key: %w", err)
		}

		// Copy PQC key if it exists
		srcPQCKey := filepath.Join(versionDir, "private", "ca.key.pqc")
		if _, err := os.Stat(srcPQCKey); err == nil {
			dstPQCKey := filepath.Join(vs.basePath, "private", "ca.key.pqc")
			if err := copyFile(srcPQCKey, dstPQCKey); err != nil {
				return fmt.Errorf("failed to sync ca.key.pqc: %w", err)
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

// AddCrossSignedBy adds a cross-signer to a version.
func (vs *VersionStore) AddCrossSignedBy(versionID, signerVersionID string) error {
	index, err := vs.LoadIndex()
	if err != nil {
		return err
	}

	for i := range index.Versions {
		if index.Versions[i].ID == versionID {
			// Check if already added
			for _, existing := range index.Versions[i].CrossSignedBy {
				if existing == signerVersionID {
					return nil // Already exists
				}
			}
			index.Versions[i].CrossSignedBy = append(index.Versions[i].CrossSignedBy, signerVersionID)
			return vs.SaveIndex(index)
		}
	}

	return fmt.Errorf("version not found: %s", versionID)
}

// CrossSignedCertPath returns the path for a cross-signed certificate.
func (vs *VersionStore) CrossSignedCertPath(versionID, signerVersionID string) string {
	return filepath.Join(vs.VersionDir(versionID), "cross-signed", fmt.Sprintf("by-%s.crt", signerVersionID))
}

// generateVersionID creates a unique version ID.
// Format: v{YYYYMMDD}_{6-char-random}
func generateVersionID() string {
	date := time.Now().Format("20060102")
	randBytes := make([]byte, 3)
	_, _ = rand.Read(randBytes)
	suffix := hex.EncodeToString(randBytes)
	return fmt.Sprintf("v%s_%s", date, suffix)
}

// copyFile copies a file from src to dst.
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}
