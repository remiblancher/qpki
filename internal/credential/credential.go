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

// Credential represents a group of related certificates with coupled lifecycle.
type Credential struct {
	// ID is the unique identifier for this credential.
	ID string `json:"id"`

	// Subject is the certificate subject.
	Subject Subject `json:"subject"`

	// Profiles is the list of profiles used to create this credential.
	Profiles []string `json:"profiles"`

	// Status is the current status of the credential.
	Status Status `json:"status"`

	// Created is when the credential was created.
	Created time.Time `json:"created"`

	// NotBefore is the start of the validity period.
	NotBefore time.Time `json:"not_before"`

	// NotAfter is the end of the validity period.
	NotAfter time.Time `json:"not_after"`

	// Certificates are references to the certificates in this credential.
	Certificates []CertificateRef `json:"certificates"`

	// RevokedAt is when the credential was revoked (if applicable).
	RevokedAt *time.Time `json:"revoked_at,omitempty"`

	// RevocationReason is why the credential was revoked.
	RevocationReason string `json:"revocation_reason,omitempty"`

	// Metadata holds additional custom data.
	Metadata map[string]string `json:"metadata,omitempty"`
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
func NewCredential(id string, subject Subject, profiles []string) *Credential {
	now := time.Now()
	return &Credential{
		ID:           id,
		Subject:      subject,
		Profiles:     profiles,
		Status:       StatusPending,
		Created:      now,
		Certificates: make([]CertificateRef, 0),
		Metadata:     make(map[string]string),
	}
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

// AddCertificate adds a certificate reference to the credential.
func (c *Credential) AddCertificate(ref CertificateRef) {
	c.Certificates = append(c.Certificates, ref)
}

// SetValidity sets the validity period for the credential.
func (c *Credential) SetValidity(notBefore, notAfter time.Time) {
	c.NotBefore = notBefore
	c.NotAfter = notAfter
}

// Activate marks the credential as valid/active.
func (c *Credential) Activate() {
	c.Status = StatusValid
}

// Revoke marks the credential as revoked.
func (c *Credential) Revoke(reason string) {
	now := time.Now()
	c.Status = StatusRevoked
	c.RevokedAt = &now
	c.RevocationReason = reason
}

// IsValid returns true if the credential is currently valid.
func (c *Credential) IsValid() bool {
	if c.Status != StatusValid {
		return false
	}

	now := time.Now()
	return now.After(c.NotBefore) && now.Before(c.NotAfter)
}

// IsExpired returns true if the credential has expired.
func (c *Credential) IsExpired() bool {
	return time.Now().After(c.NotAfter)
}

// ContainsCertificate returns true if the credential contains the given serial.
func (c *Credential) ContainsCertificate(serial string) bool {
	for _, cert := range c.Certificates {
		if cert.Serial == serial {
			return true
		}
	}
	return false
}

// GetCertificateByRole returns the certificate reference with the given role.
func (c *Credential) GetCertificateByRole(role CertRole) *CertificateRef {
	for i, cert := range c.Certificates {
		if cert.Role == role {
			return &c.Certificates[i]
		}
	}
	return nil
}

// SignatureCertificates returns all signature-related certificates.
func (c *Credential) SignatureCertificates() []CertificateRef {
	var certs []CertificateRef
	for _, cert := range c.Certificates {
		switch cert.Role {
		case RoleSignature, RoleSignatureClassical, RoleSignaturePQC:
			certs = append(certs, cert)
		}
	}
	return certs
}

// EncryptionCertificates returns all encryption-related certificates.
func (c *Credential) EncryptionCertificates() []CertificateRef {
	var certs []CertificateRef
	for _, cert := range c.Certificates {
		switch cert.Role {
		case RoleEncryption, RoleEncryptionClassical, RoleEncryptionPQC:
			certs = append(certs, cert)
		}
	}
	return certs
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
	status := string(c.Status)
	if c.IsExpired() && c.Status == StatusValid {
		status = "expired"
	}

	return fmt.Sprintf("Credential[%s]: subject=%s, profiles=%v, status=%s, certs=%d, valid=%s to %s",
		c.ID,
		c.Subject.CommonName,
		c.Profiles,
		status,
		len(c.Certificates),
		c.NotBefore.Format("2006-01-02"),
		c.NotAfter.Format("2006-01-02"))
}
