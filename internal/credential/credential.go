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
)

// Status represents the status of a bundle.
type Status string

const (
	// StatusValid indicates the bundle is active and valid.
	StatusValid Status = "valid"

	// StatusRevoked indicates the bundle has been revoked.
	StatusRevoked Status = "revoked"

	// StatusExpired indicates the bundle has expired.
	StatusExpired Status = "expired"

	// StatusPending indicates the bundle is pending issuance.
	StatusPending Status = "pending"
)

// CertRole identifies the role of a certificate in a bundle.
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

// CertificateRef is a reference to a certificate in a bundle.
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
}

// Bundle represents a group of related certificates with coupled lifecycle.
type Bundle struct {
	// ID is the unique identifier for this bundle.
	ID string `json:"id"`

	// Subject is the certificate subject.
	Subject Subject `json:"subject"`

	// Profiles is the list of profiles used to create this bundle.
	Profiles []string `json:"profiles"`

	// Status is the current status of the bundle.
	Status Status `json:"status"`

	// Created is when the bundle was created.
	Created time.Time `json:"created"`

	// NotBefore is the start of the validity period.
	NotBefore time.Time `json:"not_before"`

	// NotAfter is the end of the validity period.
	NotAfter time.Time `json:"not_after"`

	// Certificates are references to the certificates in this bundle.
	Certificates []CertificateRef `json:"certificates"`

	// RevokedAt is when the bundle was revoked (if applicable).
	RevokedAt *time.Time `json:"revoked_at,omitempty"`

	// RevocationReason is why the bundle was revoked.
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

// NewBundle creates a new bundle with the given parameters.
func NewBundle(id string, subject Subject, profiles []string) *Bundle {
	now := time.Now()
	return &Bundle{
		ID:           id,
		Subject:      subject,
		Profiles:     profiles,
		Status:       StatusPending,
		Created:      now,
		Certificates: make([]CertificateRef, 0),
		Metadata:     make(map[string]string),
	}
}

// GenerateBundleID creates a unique bundle ID from a common name.
// Format: {cn-slug}-{YYYYMMDD}-{6-char-hash}
// Example: alice-20250115-a1b2c3
func GenerateBundleID(cn string) string {
	// Slugify the common name
	slug := strings.ToLower(cn)
	slug = regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(slug, "-")
	slug = strings.Trim(slug, "-")
	if len(slug) > 20 {
		slug = slug[:20]
	}
	if slug == "" {
		slug = "bundle"
	}

	// Add date
	date := time.Now().Format("20060102")

	// Add random suffix
	randBytes := make([]byte, 3)
	_, _ = rand.Read(randBytes)
	suffix := hex.EncodeToString(randBytes)

	return fmt.Sprintf("%s-%s-%s", slug, date, suffix)
}

// AddCertificate adds a certificate reference to the bundle.
func (b *Bundle) AddCertificate(ref CertificateRef) {
	b.Certificates = append(b.Certificates, ref)
}

// SetValidity sets the validity period for the bundle.
func (b *Bundle) SetValidity(notBefore, notAfter time.Time) {
	b.NotBefore = notBefore
	b.NotAfter = notAfter
}

// Activate marks the bundle as valid/active.
func (b *Bundle) Activate() {
	b.Status = StatusValid
}

// Revoke marks the bundle as revoked.
func (b *Bundle) Revoke(reason string) {
	now := time.Now()
	b.Status = StatusRevoked
	b.RevokedAt = &now
	b.RevocationReason = reason
}

// IsValid returns true if the bundle is currently valid.
func (b *Bundle) IsValid() bool {
	if b.Status != StatusValid {
		return false
	}

	now := time.Now()
	return now.After(b.NotBefore) && now.Before(b.NotAfter)
}

// IsExpired returns true if the bundle has expired.
func (b *Bundle) IsExpired() bool {
	return time.Now().After(b.NotAfter)
}

// ContainsCertificate returns true if the bundle contains the given serial.
func (b *Bundle) ContainsCertificate(serial string) bool {
	for _, cert := range b.Certificates {
		if cert.Serial == serial {
			return true
		}
	}
	return false
}

// GetCertificateByRole returns the certificate reference with the given role.
func (b *Bundle) GetCertificateByRole(role CertRole) *CertificateRef {
	for i, cert := range b.Certificates {
		if cert.Role == role {
			return &b.Certificates[i]
		}
	}
	return nil
}

// SignatureCertificates returns all signature-related certificates.
func (b *Bundle) SignatureCertificates() []CertificateRef {
	var certs []CertificateRef
	for _, cert := range b.Certificates {
		switch cert.Role {
		case RoleSignature, RoleSignatureClassical, RoleSignaturePQC:
			certs = append(certs, cert)
		}
	}
	return certs
}

// EncryptionCertificates returns all encryption-related certificates.
func (b *Bundle) EncryptionCertificates() []CertificateRef {
	var certs []CertificateRef
	for _, cert := range b.Certificates {
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
func CertificateRefFromCert(cert *x509.Certificate, role CertRole, isCatalyst bool, altAlg string) CertificateRef {
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
	}
}

// MarshalJSON implements json.Marshaler for Bundle.
func (b *Bundle) MarshalJSON() ([]byte, error) {
	type bundleAlias Bundle
	return json.Marshal((*bundleAlias)(b))
}

// UnmarshalJSON implements json.Unmarshaler for Bundle.
func (b *Bundle) UnmarshalJSON(data []byte) error {
	type bundleAlias Bundle
	if err := json.Unmarshal(data, (*bundleAlias)(b)); err != nil {
		return err
	}
	return nil
}

// Summary returns a human-readable summary of the bundle.
func (b *Bundle) Summary() string {
	status := string(b.Status)
	if b.IsExpired() && b.Status == StatusValid {
		status = "expired"
	}

	return fmt.Sprintf("Bundle[%s]: subject=%s, profiles=%v, status=%s, certs=%d, valid=%s to %s",
		b.ID,
		b.Subject.CommonName,
		b.Profiles,
		status,
		len(b.Certificates),
		b.NotBefore.Format("2006-01-02"),
		b.NotAfter.Format("2006-01-02"))
}
