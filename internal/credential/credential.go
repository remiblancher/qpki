// Package credential provides certificate credential management for the PKI.
//
// A credential groups related certificates with a coupled lifecycle:
//   - All certificates in a credential share the same validity period
//   - All certificates are renewed together
//   - All certificates are revoked together
//
// Credentials are created from profiles (policy templates) and can contain:
//   - Signature certificates (simple, Catalyst, or linked pair)
//   - Encryption certificates (simple or linked pair)
package credential

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
)

// Status represents the status of a credential.
type Status string

const (
	// StatusValid indicates the credential is active and valid.
	StatusValid Status = "valid"

	// StatusRevoked indicates the credential has been revoked.
	StatusRevoked Status = "revoked"

	// StatusExpired indicates the credential has expired.
	StatusExpired Status = "expired"

	// StatusPending indicates the credential is pending issuance/activation.
	StatusPending Status = "pending"

	// StatusArchived indicates a previously active credential that has been superseded.
	StatusArchived Status = "archived"
)

// CertRole identifies the role of a certificate in a credential.
type CertRole string

const (
	// RoleSignature is for signature certificates.
	RoleSignature CertRole = "signature"

	// RoleSignatureClassical is for classical signature in hybrid-separate.
	RoleSignatureClassical CertRole = "signature-classical"

	// RoleSignaturePQC is for PQC signature in hybrid-separate.
	RoleSignaturePQC CertRole = "signature-pqc"

	// RoleEncryption is for encryption certificates.
	RoleEncryption CertRole = "encryption"

	// RoleEncryptionClassical is for classical encryption in hybrid-separate.
	RoleEncryptionClassical CertRole = "encryption-classical"

	// RoleEncryptionPQC is for PQC encryption in hybrid-separate.
	RoleEncryptionPQC CertRole = "encryption-pqc"
)

// CertificateRef is a reference to a certificate in a credential.
type CertificateRef struct {
	// Serial is the certificate serial number (hex string).
	Serial string `json:"serial"`

	// Role identifies the purpose of this certificate.
	Role CertRole `json:"role"`

	// Profile is the name of the profile used to create this certificate.
	Profile string `json:"profile"`

	// Algorithm is the primary algorithm used.
	Algorithm string `json:"algorithm"`

	// AltAlgorithm is the alternative algorithm (for Catalyst certificates).
	AltAlgorithm string `json:"alt_algorithm,omitempty"`

	// Fingerprint is the SHA-256 fingerprint of the certificate.
	Fingerprint string `json:"fingerprint"`

	// IsCatalyst indicates if this is a Catalyst certificate.
	IsCatalyst bool `json:"is_catalyst,omitempty"`

	// RelatedSerial is the serial of the related certificate (for linked certificates).
	RelatedSerial string `json:"related_serial,omitempty"`

	// Storage references where the private key is stored.
	// For software keys: path to the key file (relative to credential dir).
	// For HSM keys: PKCS#11 config, label, and key ID.
	Storage []pkicrypto.StorageRef `json:"storage,omitempty"`
}

// CredVersion represents a credential version with its certificates.
type CredVersion struct {
	// Profiles lists all profile names in this version.
	Profiles []string `json:"profiles"`

	// Algos lists the algorithm families in this version (e.g., "ec", "ml-dsa").
	Algos []string `json:"algos"`

	// Status is the version status (active, pending, archived).
	Status string `json:"status"`

	// Created is when this version was created.
	Created time.Time `json:"created"`

	// NotBefore is the start of the validity period.
	NotBefore time.Time `json:"not_before,omitempty"`

	// NotAfter is the end of the validity period.
	NotAfter time.Time `json:"not_after,omitempty"`

	// ActivatedAt is when this version was activated.
	ActivatedAt *time.Time `json:"activated_at,omitempty"`

	// ArchivedAt is when this version was archived.
	ArchivedAt *time.Time `json:"archived_at,omitempty"`
}

// Credential represents a group of related certificates with coupled lifecycle.
type Credential struct {
	// ID is the unique identifier for this credential.
	ID string `json:"id"`

	// Subject is the certificate subject.
	Subject Subject `json:"subject"`

	// Created is when the credential was created.
	Created time.Time `json:"created"`

	// RevokedAt is when the credential was revoked (if applicable).
	RevokedAt *time.Time `json:"revoked_at,omitempty"`

	// RevocationReason is why the credential was revoked.
	RevocationReason string `json:"revocation_reason,omitempty"`

	// Active is the ID of the currently active version.
	Active string `json:"active"`

	// Versions maps version IDs to their configuration.
	Versions map[string]CredVersion `json:"versions"`

	// Metadata holds additional custom data.
	Metadata map[string]string `json:"metadata,omitempty"`

	// basePath is the credential directory path (not serialized).
	basePath string `json:"-"`
}

// Subject holds the certificate subject information.
type Subject struct {
	CommonName   string   `json:"common_name"`
	Organization []string `json:"organization,omitempty"`
	Country      []string `json:"country,omitempty"`
	Province     []string `json:"province,omitempty"`
	Locality     []string `json:"locality,omitempty"`
}

// NewCredential creates a new credential with the given parameters.
func NewCredential(id string, subject Subject) *Credential {
	return &Credential{
		ID:       id,
		Subject:  subject,
		Created:  time.Now(),
		Versions: make(map[string]CredVersion),
		Metadata: make(map[string]string),
	}
}

// SetBasePath sets the base path for the credential.
func (c *Credential) SetBasePath(path string) {
	c.basePath = path
}

// BasePath returns the base path of the credential.
func (c *Credential) BasePath() string {
	return c.basePath
}

// VersionsDir returns the path to the versions directory.
func (c *Credential) VersionsDir() string {
	return c.basePath + "/versions"
}

// VersionDir returns the path to a specific version directory.
func (c *Credential) VersionDir(versionID string) string {
	return c.basePath + "/versions/" + versionID
}

// AlgoDir returns the directory for a specific algorithm in a version.
func (c *Credential) AlgoDir(versionID, algo string) string {
	return c.basePath + "/versions/" + versionID + "/" + algo
}

// CertPath returns the path to the certificate file.
func (c *Credential) CertPath(versionID, algo string) string {
	return c.AlgoDir(versionID, algo) + "/certificates.pem"
}

// KeyPath returns the path to the private key file.
func (c *Credential) KeyPath(versionID, algo string) string {
	return c.AlgoDir(versionID, algo) + "/private-keys.pem"
}

// ActiveVersion returns the active version or nil if not set.
func (c *Credential) ActiveVersion() *CredVersion {
	if c.Active == "" {
		return nil
	}
	ver, ok := c.Versions[c.Active]
	if !ok {
		return nil
	}
	return &ver
}

// CreateInitialVersion creates v1 as the initial active version.
func (c *Credential) CreateInitialVersion(profiles, algos []string) {
	now := time.Now()
	c.Active = "v1"
	c.Versions = map[string]CredVersion{
		"v1": {
			Profiles:    profiles,
			Algos:       algos,
			Status:      "active",
			Created:     now,
			ActivatedAt: &now,
		},
	}
}

// NextVersionID returns the next version ID (v2, v3, etc.).
func (c *Credential) NextVersionID() string {
	return fmt.Sprintf("v%d", len(c.Versions)+1)
}

// EnsureVersionDir creates the directory structure for a version/algo.
func (c *Credential) EnsureVersionDir(versionID, algo string) error {
	dir := c.AlgoDir(versionID, algo)
	return createDir(dir)
}

// Save saves the credential to credential.meta.json.
func (c *Credential) Save() error {
	if c.basePath == "" {
		return fmt.Errorf("base path not set")
	}

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal credential: %w", err)
	}

	// Atomic write
	tmpPath := c.basePath + "/credential.meta.json.tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write credential: %w", err)
	}

	jsonPath := c.basePath + "/credential.meta.json"
	if err := os.Rename(tmpPath, jsonPath); err != nil {
		return fmt.Errorf("failed to rename credential file: %w", err)
	}

	return nil
}

// ActivateVersion activates a pending version and archives the previous one.
func (c *Credential) ActivateVersion(versionID string) error {
	ver, ok := c.Versions[versionID]
	if !ok {
		return fmt.Errorf("version not found: %s", versionID)
	}

	if ver.Status != "pending" {
		return fmt.Errorf("can only activate pending versions, current status: %s", ver.Status)
	}

	now := time.Now()

	// Archive the current active version
	if c.Active != "" {
		if oldVer, ok := c.Versions[c.Active]; ok {
			oldVer.Status = "archived"
			oldVer.ArchivedAt = &now
			c.Versions[c.Active] = oldVer
		}
	}

	// Activate the new version
	ver.Status = "active"
	ver.ActivatedAt = &now
	c.Versions[versionID] = ver
	c.Active = versionID

	return nil
}

// createDir creates a directory with 0755 permissions.
func createDir(path string) error {
	return os.MkdirAll(path, 0755)
}

// InfoFile is the name of the credential info file.
const InfoFile = "credential.meta.json"

// CredentialExists checks if a credential.meta.json file exists at the given path.
func CredentialExists(basePath string) bool {
	_, err := os.Stat(basePath + "/" + InfoFile)
	return err == nil
}

// LoadCredential loads a credential from its directory.
func LoadCredential(basePath string) (*Credential, error) {
	jsonPath := basePath + "/" + InfoFile
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read credential file: %w", err)
	}

	var cred Credential
	if err := json.Unmarshal(data, &cred); err != nil {
		return nil, fmt.Errorf("failed to parse credential: %w", err)
	}

	cred.basePath = basePath
	return &cred, nil
}

// GenerateCredentialID creates a unique credential ID from a common name.
// Format: {cn-slug}-{YYYYMMDD}-{6-char-hash}
// Example: alice-20250115-a1b2c3
func GenerateCredentialID(cn string) string {
	// Slugify the common name
	slug := strings.ToLower(cn)
	slug = regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(slug, "-")
	slug = strings.Trim(slug, "-")
	if len(slug) > 20 {
		slug = slug[:20]
	}
	if slug == "" {
		slug = "cred"
	}

	// Add date
	date := time.Now().Format("20060102")

	// Add random suffix
	randBytes := make([]byte, 3)
	_, _ = rand.Read(randBytes)
	suffix := hex.EncodeToString(randBytes)

	return fmt.Sprintf("%s-%s-%s", slug, date, suffix)
}

// Revoke marks the credential as revoked.
func (c *Credential) Revoke(reason string) {
	now := time.Now()
	c.RevokedAt = &now
	c.RevocationReason = reason
}

// IsValid returns true if the credential is currently valid.
func (c *Credential) IsValid() bool {
	if c.RevokedAt != nil {
		return false
	}

	ver := c.ActiveVersion()
	if ver == nil || ver.Status != "active" {
		return false
	}

	now := time.Now()
	return now.After(ver.NotBefore) && now.Before(ver.NotAfter)
}

// IsExpired returns true if the credential has expired.
func (c *Credential) IsExpired() bool {
	ver := c.ActiveVersion()
	if ver == nil {
		return true
	}
	return time.Now().After(ver.NotAfter)
}

// SubjectToPkixName converts Subject to pkix.Name.
func (s Subject) ToPkixName() pkix.Name {
	return pkix.Name{
		CommonName:   s.CommonName,
		Organization: s.Organization,
		Country:      s.Country,
		Province:     s.Province,
		Locality:     s.Locality,
	}
}

// SubjectFromPkixName creates a Subject from pkix.Name.
func SubjectFromPkixName(name pkix.Name) Subject {
	return Subject{
		CommonName:   name.CommonName,
		Organization: name.Organization,
		Country:      name.Country,
		Province:     name.Province,
		Locality:     name.Locality,
	}
}

// SubjectFromCertificate creates a Subject from a certificate.
func SubjectFromCertificate(cert *x509.Certificate) Subject {
	return SubjectFromPkixName(cert.Subject)
}

// CertificateRefFromCert creates a CertificateRef from a certificate.
func CertificateRefFromCert(cert *x509.Certificate, role CertRole, isCatalyst bool, altAlg string, storage ...pkicrypto.StorageRef) CertificateRef {
	fingerprint := fmt.Sprintf("%X", cert.SubjectKeyId)
	if len(fingerprint) == 0 {
		// Fallback to serial if no SKID
		fingerprint = fmt.Sprintf("%X", cert.SerialNumber.Bytes())
	}

	return CertificateRef{
		Serial:       fmt.Sprintf("0x%X", cert.SerialNumber.Bytes()),
		Role:         role,
		Algorithm:    cert.SignatureAlgorithm.String(),
		AltAlgorithm: altAlg,
		Fingerprint:  fingerprint,
		IsCatalyst:   isCatalyst,
		Storage:      storage,
	}
}

// MarshalJSON implements json.Marshaler for Credential.
func (c *Credential) MarshalJSON() ([]byte, error) {
	type credentialAlias Credential
	return json.Marshal((*credentialAlias)(c))
}

// UnmarshalJSON implements json.Unmarshaler for Credential.
func (c *Credential) UnmarshalJSON(data []byte) error {
	type credentialAlias Credential
	if err := json.Unmarshal(data, (*credentialAlias)(c)); err != nil {
		return err
	}
	return nil
}

// Summary returns a human-readable summary of the credential.
func (c *Credential) Summary() string {
	ver := c.ActiveVersion()
	if ver == nil {
		return fmt.Sprintf("Credential[%s]: subject=%s, no active version",
			c.ID, c.Subject.CommonName)
	}

	status := ver.Status
	if c.RevokedAt != nil {
		status = "revoked"
	} else if c.IsExpired() {
		status = "expired"
	}

	return fmt.Sprintf("Credential[%s]: subject=%s, profiles=%v, status=%s, algos=%v, valid=%s to %s",
		c.ID,
		c.Subject.CommonName,
		ver.Profiles,
		status,
		ver.Algos,
		ver.NotBefore.Format("2006-01-02"),
		ver.NotAfter.Format("2006-01-02"))
}
