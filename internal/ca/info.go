package ca

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
)

// MetaFile is the name of the CA metadata file.
const MetaFile = "ca.meta.json"

// InfoFile is an alias for MetaFile for backward compatibility.
const InfoFile = MetaFile

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

// KeyRef references a CA key with its storage information.
type KeyRef struct {
	// ID identifies this key within the CA ("default", "classical", "pqc", etc.)
	ID string `json:"id"`

	// Algorithm is the cryptographic algorithm.
	Algorithm pkicrypto.AlgorithmID `json:"algorithm"`

	// Storage describes where the key is stored.
	Storage pkicrypto.StorageRef `json:"storage"`
}

// BuildKeyStorageConfig builds a KeyStorageConfig from this KeyRef.
func (k *KeyRef) BuildKeyStorageConfig(basePath, passphrase string) (pkicrypto.KeyStorageConfig, error) {
	return k.Storage.ToKeyStorageConfig(basePath, passphrase)
}

// Subject holds the CA subject information.
type Subject struct {
	CommonName   string   `json:"common_name"`
	Organization []string `json:"organization,omitempty"`
	Country      []string `json:"country,omitempty"`
}

// CAVersion represents a CA version with its certificates.
type CAVersion struct {
	// Profiles lists all profile names in this version.
	Profiles []string `json:"profiles"`

	// Algos lists the algorithm families present (e.g., "ec", "ml-dsa").
	Algos []string `json:"algos"`

	// Status is the current status of this version.
	Status VersionStatus `json:"status"`

	// Created is when this version was created.
	Created time.Time `json:"created"`

	// ActivatedAt is when this version was activated.
	ActivatedAt *time.Time `json:"activated_at,omitempty"`

	// ArchivedAt is when this version was archived.
	ArchivedAt *time.Time `json:"archived_at,omitempty"`

	// CrossSignedBy lists version IDs that have cross-signed this CA.
	CrossSignedBy []string `json:"cross_signed_by,omitempty"`
}

// CAInfo contains all CA metadata in a single file.
// This replaces ca.meta.json + versions.json.
type CAInfo struct {
	// Subject is the CA subject.
	Subject Subject `json:"subject"`

	// Created is when the CA was initialized.
	Created time.Time `json:"created"`

	// Keys are references to the CA's keys (for HSM support).
	Keys []KeyRef `json:"keys,omitempty"`

	// Active is the ID of the currently active version.
	Active string `json:"active"`

	// Versions maps version IDs to their metadata.
	Versions map[string]CAVersion `json:"versions"`

	// basePath is the CA directory path (not serialized).
	basePath string `json:"-"`
}

// NewCAInfo creates a new CAInfo with default values.
func NewCAInfo(subject Subject) *CAInfo {
	return &CAInfo{
		Subject:  subject,
		Created:  time.Now(),
		Keys:     make([]KeyRef, 0),
		Versions: make(map[string]CAVersion),
	}
}

// ActiveVersion returns the currently active version.
func (c *CAInfo) ActiveVersion() *CAVersion {
	if c.Active == "" {
		return nil
	}
	ver, ok := c.Versions[c.Active]
	if !ok {
		return nil
	}
	return &ver
}

// NextVersionID returns the next version ID.
func (c *CAInfo) NextVersionID() string {
	return fmt.Sprintf("v%d", len(c.Versions)+1)
}

// CreateInitialVersion creates v1 as active.
func (c *CAInfo) CreateInitialVersion(profiles, algos []string) string {
	now := time.Now()
	c.Versions["v1"] = CAVersion{
		Profiles:    profiles,
		Algos:       algos,
		Status:      VersionStatusActive,
		Created:     now,
		ActivatedAt: &now,
	}
	c.Active = "v1"
	return "v1"
}

// CreatePendingVersion creates a new pending version.
func (c *CAInfo) CreatePendingVersion(profiles, algos []string) string {
	id := c.NextVersionID()
	c.Versions[id] = CAVersion{
		Profiles: profiles,
		Algos:    algos,
		Status:   VersionStatusPending,
		Created:  time.Now(),
	}
	return id
}

// Activate activates a pending version.
func (c *CAInfo) Activate(versionID string) error {
	ver, ok := c.Versions[versionID]
	if !ok {
		return fmt.Errorf("version not found: %s", versionID)
	}
	if ver.Status != VersionStatusPending {
		return fmt.Errorf("can only activate pending versions, current status: %s", ver.Status)
	}

	now := time.Now()

	// Archive current active
	if c.Active != "" {
		if active, ok := c.Versions[c.Active]; ok {
			active.Status = VersionStatusArchived
			active.ArchivedAt = &now
			c.Versions[c.Active] = active
		}
	}

	// Activate new version
	ver.Status = VersionStatusActive
	ver.ActivatedAt = &now
	c.Versions[versionID] = ver
	c.Active = versionID

	// Update keys from the new version's metadata
	versionDir := filepath.Join(c.basePath, "versions", versionID)
	versionMetaPath := filepath.Join(versionDir, MetaFile)
	if data, err := os.ReadFile(versionMetaPath); err == nil {
		var versionInfo CAInfo
		if err := json.Unmarshal(data, &versionInfo); err == nil && len(versionInfo.Keys) > 0 {
			// Update key paths to be relative to root CA directory
			newKeys := make([]KeyRef, 0, len(versionInfo.Keys))
			for _, key := range versionInfo.Keys {
				newKey := key
				if key.Storage.Type == "software" && key.Storage.Path != "" {
					// Prepend version path to make it relative from root
					newKey.Storage.Path = filepath.Join("versions", versionID, key.Storage.Path)
				}
				newKeys = append(newKeys, newKey)
			}
			c.Keys = newKeys
		}
	}

	return nil
}

// AddKey adds a key reference.
func (c *CAInfo) AddKey(ref KeyRef) {
	c.Keys = append(c.Keys, ref)
}

// GetKey returns a key by ID.
func (c *CAInfo) GetKey(id string) *KeyRef {
	for i, k := range c.Keys {
		if k.ID == id {
			return &c.Keys[i]
		}
	}
	return nil
}

// GetDefaultKey returns the default key.
func (c *CAInfo) GetDefaultKey() *KeyRef {
	if len(c.Keys) == 0 {
		return nil
	}
	if k := c.GetKey("default"); k != nil {
		return k
	}
	return &c.Keys[0]
}

// Path helpers

// VersionDir returns the directory for a version.
func (c *CAInfo) VersionDir(versionID string) string {
	return filepath.Join(c.basePath, "versions", versionID)
}

// KeysDir returns the keys directory for a version.
func (c *CAInfo) KeysDir(versionID string) string {
	return filepath.Join(c.VersionDir(versionID), "keys")
}

// CertsDir returns the certs directory for a version.
func (c *CAInfo) CertsDir(versionID string) string {
	return filepath.Join(c.VersionDir(versionID), "certs")
}

// CertPath returns the certificate path for a specific algorithm.
// Format: versions/{versionID}/certs/ca.{algorithm}.pem
// The algorithm should be the full algorithm ID (e.g., "ecdsa-p384", "ml-dsa-87").
func (c *CAInfo) CertPath(versionID, algorithm string) string {
	return filepath.Join(c.CertsDir(versionID), fmt.Sprintf("ca.%s.pem", algorithm))
}

// KeyPath returns the private key path for a specific algorithm.
// Format: versions/{versionID}/keys/ca.{algorithm}.key
// The algorithm should be the full algorithm ID (e.g., "ecdsa-p384", "ml-dsa-87").
func (c *CAInfo) KeyPath(versionID, algorithm string) string {
	return filepath.Join(c.KeysDir(versionID), fmt.Sprintf("ca.%s.key", algorithm))
}

// ActiveCertPath returns the active certificate path for an algorithm.
func (c *CAInfo) ActiveCertPath(algorithm string) string {
	return c.CertPath(c.Active, algorithm)
}

// ActiveKeyPath returns the active key path for an algorithm.
func (c *CAInfo) ActiveKeyPath(algorithm string) string {
	return c.KeyPath(c.Active, algorithm)
}

// BasePath returns the CA base path.
func (c *CAInfo) BasePath() string {
	return c.basePath
}

// SetBasePath sets the CA base path.
func (c *CAInfo) SetBasePath(path string) {
	c.basePath = path
}

// Save saves the CAInfo to ca.json atomically.
func (c *CAInfo) Save() error {
	return SaveCAInfo(c.basePath, c)
}

// SaveCAInfo saves CAInfo to a file atomically.
func SaveCAInfo(basePath string, info *CAInfo) error {
	path := filepath.Join(basePath, MetaFile)

	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal CA info: %w", err)
	}

	// Atomic write: temp file + rename
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	return nil
}

// LoadCAInfo loads CAInfo from a file.
func LoadCAInfo(basePath string) (*CAInfo, error) {
	path := filepath.Join(basePath, MetaFile)

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read CA info: %w", err)
	}

	var info CAInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return nil, fmt.Errorf("failed to parse CA info: %w", err)
	}

	info.basePath = basePath
	return &info, nil
}

// CAInfoExists checks if ca.meta.json exists.
func CAInfoExists(basePath string) bool {
	path := filepath.Join(basePath, MetaFile)
	_, err := os.Stat(path)
	return err == nil
}

// EnsureVersionDir creates the version directory structure (keys/ and certs/).
func (c *CAInfo) EnsureVersionDir(versionID string) error {
	if err := os.MkdirAll(c.KeysDir(versionID), 0755); err != nil {
		return err
	}
	return os.MkdirAll(c.CertsDir(versionID), 0755)
}

// Helper to build KeyStorageConfig from KeyRef
func (c *CAInfo) BuildKeyStorageConfig(keyID, passphrase string) (pkicrypto.KeyStorageConfig, error) {
	key := c.GetKey(keyID)
	if key == nil {
		return pkicrypto.KeyStorageConfig{}, fmt.Errorf("key not found: %s", keyID)
	}
	return key.Storage.ToKeyStorageConfig(c.basePath, passphrase)
}

// CertRef holds a reference to a certificate within a version.
type CertRef struct {
	// Profile is the profile name used (e.g., "ec/root-ca").
	Profile string `json:"profile"`

	// Algorithm is the cryptographic algorithm (e.g., "ecdsa-p256", "ml-dsa-65").
	Algorithm string `json:"algorithm"`

	// AlgorithmFamily is the algorithm family for CRL grouping (e.g., "ec", "ml-dsa").
	AlgorithmFamily string `json:"algorithm_family"`

	// Subject is the certificate subject DN.
	Subject string `json:"subject"`

	// Serial is the certificate serial number (hex-encoded).
	Serial string `json:"serial,omitempty"`

	// Fingerprint is the SHA-256 fingerprint of the certificate.
	Fingerprint string `json:"fingerprint,omitempty"`

	// NotBefore is the certificate validity start.
	NotBefore time.Time `json:"not_before"`

	// NotAfter is the certificate validity end.
	NotAfter time.Time `json:"not_after"`
}

// ListAlgorithmFamilies returns all algorithm families in the active version.
func (c *CAInfo) ListAlgorithmFamilies() []string {
	if c.Active == "" {
		return nil
	}
	ver, ok := c.Versions[c.Active]
	if !ok {
		return nil
	}
	return ver.Algos
}

// GetActiveVersionID returns the ID of the active version.
func (c *CAInfo) GetActiveVersionID() string {
	return c.Active
}

// Version is an alias for CAVersion for backward compatibility.
// Used by rotate.go and other files during migration.
type Version struct {
	// ID is the unique version identifier (e.g., v1, v2).
	ID string `json:"id"`

	// Status is the current status of this version.
	Status VersionStatus `json:"status"`

	// Profiles lists all profile names in this version.
	Profiles []string `json:"profiles"`

	// Certificates holds references to all certificates in this version.
	Certificates []CertRef `json:"certificates"`

	// Created is when this version was created.
	Created time.Time `json:"created"`

	// ActivatedAt is when this version was activated.
	ActivatedAt *time.Time `json:"activated_at,omitempty"`

	// ArchivedAt is when this version was archived.
	ArchivedAt *time.Time `json:"archived_at,omitempty"`

	// CrossSignedBy lists version IDs that have cross-signed this CA.
	CrossSignedBy []string `json:"cross_signed_by,omitempty"`
}

// VersionStore manages CA version storage.
// Wraps CAInfo for backward compatibility with rotate.go.
type VersionStore struct {
	basePath string
	info     *CAInfo
}

// NewVersionStore creates a version store at the given path.
func NewVersionStore(basePath string) *VersionStore {
	return &VersionStore{basePath: basePath}
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

// CrossSignedCertPath returns the path for a cross-signed certificate.
func (vs *VersionStore) CrossSignedCertPath(versionID, signerVersionID string) string {
	return filepath.Join(vs.VersionDir(versionID), "cross-signed", fmt.Sprintf("by-%s.crt", signerVersionID))
}

// Init initializes the version store.
func (vs *VersionStore) Init() error {
	if err := os.MkdirAll(vs.VersionsDir(), 0755); err != nil {
		return fmt.Errorf("failed to create versions directory: %w", err)
	}
	return nil
}

// IsVersioned returns true if this CA uses versioning.
func (vs *VersionStore) IsVersioned() bool {
	return CAInfoExists(vs.basePath)
}

// loadInfo loads CAInfo if not already loaded.
func (vs *VersionStore) loadInfo() error {
	if vs.info != nil {
		return nil
	}
	info, err := LoadCAInfo(vs.basePath)
	if err != nil {
		return err
	}
	vs.info = info
	return nil
}

// PeekNextVersionID returns the next version ID without creating the version.
func (vs *VersionStore) PeekNextVersionID() (string, error) {
	if err := vs.loadInfo(); err != nil {
		return "", err
	}
	if vs.info == nil {
		return "v2", nil // First rotation
	}
	return vs.info.NextVersionID(), nil
}

// GetActiveVersion returns the active version.
func (vs *VersionStore) GetActiveVersion() (*Version, error) {
	if err := vs.loadInfo(); err != nil {
		return nil, err
	}
	if vs.info == nil || vs.info.Active == "" {
		return nil, fmt.Errorf("no active version")
	}
	return vs.GetVersion(vs.info.Active)
}

// GetVersion returns a version by ID.
func (vs *VersionStore) GetVersion(id string) (*Version, error) {
	if err := vs.loadInfo(); err != nil {
		return nil, err
	}
	if vs.info == nil {
		return nil, fmt.Errorf("version not found: %s", id)
	}
	ver, ok := vs.info.Versions[id]
	if !ok {
		return nil, fmt.Errorf("version not found: %s", id)
	}

	// Build Certificates from Algos for compatibility
	// Algos now contains full algorithm IDs (e.g., "ecdsa-p384", "ml-dsa-87")
	var certs []CertRef
	for _, algo := range ver.Algos {
		// Compute algorithm family from full algorithm ID
		family := GetAlgorithmFamilyFromID(algo)
		certs = append(certs, CertRef{
			Algorithm:       algo,
			AlgorithmFamily: family,
		})
	}

	return &Version{
		ID:            id,
		Status:        ver.Status,
		Profiles:      ver.Profiles,
		Certificates:  certs,
		Created:       ver.Created,
		ActivatedAt:   ver.ActivatedAt,
		ArchivedAt:    ver.ArchivedAt,
		CrossSignedBy: ver.CrossSignedBy,
	}, nil
}

// CreateVersionWithID creates a new version entry with a specific ID.
func (vs *VersionStore) CreateVersionWithID(id string, profiles []string) (*Version, error) {
	if err := vs.loadInfo(); err != nil {
		return nil, err
	}

	// Create info if it doesn't exist
	if vs.info == nil {
		vs.info = NewCAInfo(Subject{CommonName: "CA"})
		vs.info.SetBasePath(vs.basePath)
	}

	// Create version directory
	versionDir := vs.VersionDir(id)
	if err := os.MkdirAll(versionDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create version directory: %w", err)
	}

	// Add version to CAInfo
	vs.info.Versions[id] = CAVersion{
		Profiles: profiles,
		Status:   VersionStatusPending,
		Created:  time.Now(),
	}

	// Save CAInfo
	if err := vs.info.Save(); err != nil {
		return nil, fmt.Errorf("failed to save CA info: %w", err)
	}

	return vs.GetVersion(id)
}

// getActiveVersionID returns the active version ID.
func (vs *VersionStore) getActiveVersionID() string {
	if err := vs.loadInfo(); err != nil || vs.info == nil {
		return ""
	}
	return vs.info.Active
}

// AddCertificateRef adds a certificate reference to a version.
// This updates the version's Algos field with the full algorithm ID.
func (vs *VersionStore) AddCertificateRef(versionID string, certRef CertRef) error {
	if err := vs.loadInfo(); err != nil {
		return err
	}
	if vs.info == nil {
		return fmt.Errorf("CA info not found")
	}

	ver, ok := vs.info.Versions[versionID]
	if !ok {
		return fmt.Errorf("version not found: %s", versionID)
	}

	// Add full algorithm ID if not already present
	algoID := certRef.Algorithm
	for _, existing := range ver.Algos {
		if existing == algoID {
			return nil // Already exists
		}
	}
	ver.Algos = append(ver.Algos, algoID)
	vs.info.Versions[versionID] = ver

	return vs.info.Save()
}

// AddCrossSignedBy adds a cross-signer to a version.
func (vs *VersionStore) AddCrossSignedBy(versionID, signerVersionID string) error {
	if err := vs.loadInfo(); err != nil {
		return err
	}
	if vs.info == nil {
		return fmt.Errorf("CA info not found")
	}
	ver, ok := vs.info.Versions[versionID]
	if !ok {
		return fmt.Errorf("version not found: %s", versionID)
	}
	// Check if already added
	for _, existing := range ver.CrossSignedBy {
		if existing == signerVersionID {
			return nil // Already exists
		}
	}
	ver.CrossSignedBy = append(ver.CrossSignedBy, signerVersionID)
	vs.info.Versions[versionID] = ver
	return vs.info.Save()
}

// CAKeyPathForAlgorithm returns the key path following the new naming convention.
// Example: keys/ca.ecdsa-p384.key
func CAKeyPathForAlgorithm(basePath string, alg pkicrypto.AlgorithmID) string {
	return filepath.Join(basePath, "keys", fmt.Sprintf("ca.%s.key", alg))
}

// RelativeCAKeyPathForAlgorithm returns the relative key path for use in metadata.
// Example: keys/ca.ecdsa-p384.key
func RelativeCAKeyPathForAlgorithm(alg pkicrypto.AlgorithmID) string {
	return fmt.Sprintf("keys/ca.%s.key", alg)
}

// CACertPathForAlgorithm returns the certificate path for a specific algorithm.
// Example: certs/ca.ecdsa-p384.pem
func CACertPathForAlgorithm(basePath string, alg pkicrypto.AlgorithmID) string {
	return filepath.Join(basePath, "certs", fmt.Sprintf("ca.%s.pem", alg))
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

// NewCAMetadata creates a new CAMetadata with default values.
// For backward compatibility during migration.
func NewCAMetadata(profile string) *CAInfo {
	return &CAInfo{
		Created:  time.Now(),
		Keys:     make([]KeyRef, 0),
		Versions: make(map[string]CAVersion),
	}
}

// CAMetadata is an alias for CAInfo for backward compatibility.
type CAMetadata = CAInfo

// SaveCAMetadata saves CA metadata to the given path.
// For backward compatibility during migration.
func SaveCAMetadata(basePath string, metadata *CAMetadata) error {
	metadata.SetBasePath(basePath)
	return metadata.Save()
}

// ListVersions returns all versions sorted by ID.
func (vs *VersionStore) ListVersions() ([]*Version, error) {
	if err := vs.loadInfo(); err != nil {
		return nil, err
	}
	if vs.info == nil {
		return nil, nil
	}

	versions := make([]*Version, 0, len(vs.info.Versions))
	for id, ver := range vs.info.Versions {
		// Build Certificates from Algos for compatibility
		var certs []CertRef
		for _, algo := range ver.Algos {
			certs = append(certs, CertRef{
				AlgorithmFamily: algo,
			})
		}

		versions = append(versions, &Version{
			ID:            id,
			Status:        ver.Status,
			Profiles:      ver.Profiles,
			Certificates:  certs,
			Created:       ver.Created,
			ActivatedAt:   ver.ActivatedAt,
			ArchivedAt:    ver.ArchivedAt,
			CrossSignedBy: ver.CrossSignedBy,
		})
	}
	return versions, nil
}

// Activate activates a pending version.
func (vs *VersionStore) Activate(versionID string) error {
	if err := vs.loadInfo(); err != nil {
		return err
	}
	if vs.info == nil {
		return fmt.Errorf("CA info not found")
	}
	if err := vs.info.Activate(versionID); err != nil {
		return err
	}
	return vs.info.Save()
}

// LoadIndex returns the version index for compatibility.
// This is used by rotate.go.
func (vs *VersionStore) LoadIndex() (*VersionIndex, error) {
	if err := vs.loadInfo(); err != nil {
		return nil, err
	}
	if vs.info == nil {
		return &VersionIndex{}, nil
	}
	return &VersionIndex{
		ActiveVersion: vs.info.Active,
	}, nil
}

// VersionIndex is the version index for compatibility.
type VersionIndex struct {
	ActiveVersion string `json:"active_version"`
}

// GetAlgorithmFamilyName returns the algorithm family name for an algorithm.
// For example: "ecdsa-p256" -> "ec", "ml-dsa-65" -> "ml-dsa"
func GetAlgorithmFamilyName(alg pkicrypto.AlgorithmID) string {
	return GetAlgorithmFamilyFromID(string(alg))
}

// GetAlgorithmFamilyFromID returns the algorithm family from a string algorithm ID.
// For example: "ecdsa-p256" -> "ec", "ml-dsa-65" -> "ml-dsa"
func GetAlgorithmFamilyFromID(algStr string) string {
	switch {
	case algStr == "ecdsa-p256" || algStr == "ecdsa-p384" || algStr == "ecdsa-p521":
		return "ec"
	case algStr == "ed25519":
		return "ed25519"
	case algStr == "rsa-2048" || algStr == "rsa-3072" || algStr == "rsa-4096":
		return "rsa"
	case len(algStr) >= 6 && algStr[:6] == "ml-dsa":
		return "ml-dsa"
	case len(algStr) >= 7 && algStr[:7] == "slh-dsa":
		return "slh-dsa"
	default:
		return algStr
	}
}

// MetadataFile is an alias for MetaFile for backward compatibility.
const MetadataFile = MetaFile

// LoadCAMetadata loads CA metadata from a file.
// For backward compatibility during migration.
func LoadCAMetadata(basePath string) (*CAInfo, error) {
	return LoadCAInfo(basePath)
}

// MetadataExists checks if CA metadata exists.
// For backward compatibility during migration.
func MetadataExists(basePath string) bool {
	return CAInfoExists(basePath)
}

// IsHybrid returns true if the CA has both classical and PQC keys.
func (c *CAInfo) IsHybrid() bool {
	return c.GetKey("classical") != nil && c.GetKey("pqc") != nil
}

// GetClassicalKey returns the classical key reference.
func (c *CAInfo) GetClassicalKey() *KeyRef {
	return c.GetKey("classical")
}

// GetPQCKey returns the PQC key reference.
func (c *CAInfo) GetPQCKey() *KeyRef {
	return c.GetKey("pqc")
}
