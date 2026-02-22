package pki

import (
	"time"
)

// Algorithm represents a cryptographic algorithm identifier.
type Algorithm string

// Supported algorithms.
const (
	// Classical algorithms
	AlgRSA2048       Algorithm = "rsa-2048"
	AlgRSA3072       Algorithm = "rsa-3072"
	AlgRSA4096       Algorithm = "rsa-4096"
	AlgECDSAP256     Algorithm = "ecdsa-p256"
	AlgECDSAP384     Algorithm = "ecdsa-p384"
	AlgECDSAP521     Algorithm = "ecdsa-p521"
	AlgEd25519       Algorithm = "ed25519"
	AlgEd448         Algorithm = "ed448"

	// Post-quantum algorithms (FIPS 204)
	AlgMLDSA44       Algorithm = "ml-dsa-44"
	AlgMLDSA65       Algorithm = "ml-dsa-65"
	AlgMLDSA87       Algorithm = "ml-dsa-87"

	// Post-quantum algorithms (FIPS 205)
	AlgSLHDSASHA2128s Algorithm = "slh-dsa-sha2-128s"
	AlgSLHDSASHA2128f Algorithm = "slh-dsa-sha2-128f"
	AlgSLHDSASHA2192s Algorithm = "slh-dsa-sha2-192s"
	AlgSLHDSASHA2192f Algorithm = "slh-dsa-sha2-192f"
	AlgSLHDSASHA2256s Algorithm = "slh-dsa-sha2-256s"
	AlgSLHDSASHA2256f Algorithm = "slh-dsa-sha2-256f"
)

// RevocationReason represents the reason for certificate revocation.
type RevocationReason int

// Revocation reasons as defined in RFC 5280.
const (
	ReasonUnspecified          RevocationReason = 0
	ReasonKeyCompromise        RevocationReason = 1
	ReasonCACompromise         RevocationReason = 2
	ReasonAffiliationChanged   RevocationReason = 3
	ReasonSuperseded           RevocationReason = 4
	ReasonCessationOfOperation RevocationReason = 5
	ReasonCertificateHold      RevocationReason = 6
	ReasonRemoveFromCRL        RevocationReason = 8
	ReasonPrivilegeWithdrawn   RevocationReason = 9
	ReasonAACompromise         RevocationReason = 10
)

// String returns the human-readable name of the revocation reason.
func (r RevocationReason) String() string {
	switch r {
	case ReasonUnspecified:
		return "unspecified"
	case ReasonKeyCompromise:
		return "keyCompromise"
	case ReasonCACompromise:
		return "cACompromise"
	case ReasonAffiliationChanged:
		return "affiliationChanged"
	case ReasonSuperseded:
		return "superseded"
	case ReasonCessationOfOperation:
		return "cessationOfOperation"
	case ReasonCertificateHold:
		return "certificateHold"
	case ReasonRemoveFromCRL:
		return "removeFromCRL"
	case ReasonPrivilegeWithdrawn:
		return "privilegeWithdrawn"
	case ReasonAACompromise:
		return "aACompromise"
	default:
		return "unknown"
	}
}

// RevokedCertificate represents a revoked certificate entry for CRL generation.
type RevokedCertificate struct {
	Serial       []byte
	RevokedAt    time.Time
	Reason       RevocationReason
}

// CertificateFilter defines criteria for listing certificates.
type CertificateFilter struct {
	// Subject filters by subject DN (partial match).
	Subject string

	// NotExpired filters to only non-expired certificates.
	NotExpired bool

	// NotRevoked filters to only non-revoked certificates.
	NotRevoked bool

	// IssuedAfter filters to certificates issued after this time.
	IssuedAfter *time.Time

	// IssuedBefore filters to certificates issued before this time.
	IssuedBefore *time.Time

	// Limit limits the number of results.
	Limit int

	// Offset skips the first N results.
	Offset int
}

// ProfileMode defines the certificate issuance mode.
type ProfileMode string

const (
	ModeSimple    ProfileMode = "simple"
	ModeCatalyst  ProfileMode = "catalyst"
	ModeComposite ProfileMode = "composite"
)

// SubjectTemplate defines the certificate subject DN template.
type SubjectTemplate struct {
	CommonName         string
	Organization       []string
	OrganizationalUnit []string
	Country            []string
	Province           []string
	Locality           []string
}

// ExtensionSet defines certificate extensions.
type ExtensionSet struct {
	KeyUsage           []string
	ExtKeyUsage        []string
	BasicConstraints   *BasicConstraints
	SubjectAltName     *SubjectAltName
}

// BasicConstraints defines CA/path length constraints.
type BasicConstraints struct {
	IsCA       bool
	MaxPathLen int
}

// SubjectAltName defines subject alternative names.
type SubjectAltName struct {
	DNSNames       []string
	EmailAddresses []string
	IPAddresses    []string
	URIs           []string
}

// VariableDefinition defines a profile variable.
type VariableDefinition struct {
	Type        string
	Required    bool
	Default     string
	Description string
}

// AuditEvent represents a logged PKI operation.
type AuditEvent struct {
	Timestamp   time.Time
	EventType   AuditEventType
	Actor       string
	Resource    string
	Action      string
	Result      string
	Details     map[string]interface{}
	PrevHash    string
	Hash        string
}

// AuditEventType categorizes audit events.
type AuditEventType string

const (
	EventCertIssued    AuditEventType = "cert.issued"
	EventCertRevoked   AuditEventType = "cert.revoked"
	EventCRLGenerated  AuditEventType = "crl.generated"
	EventCAInitialized AuditEventType = "ca.initialized"
	EventCARotated     AuditEventType = "ca.rotated"
	EventKeyGenerated  AuditEventType = "key.generated"
)

// NOTE: CAInfo is defined in ca.go as an alias for internal/ca.CAInfo
