package cose

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"time"

	gocose "github.com/veraison/go-cose"
)

// MessageType represents the type of COSE message.
type MessageType int

const (
	// TypeCWT is a CBOR Web Token (RFC 8392) - COSE Sign1 with claims payload.
	TypeCWT MessageType = iota
	// TypeSign1 is a COSE Sign1 message (RFC 9052) - single signature.
	TypeSign1
	// TypeSign is a COSE Sign message (RFC 9052) - multiple signatures (hybrid).
	TypeSign
)

// String returns the string representation of the message type.
func (t MessageType) String() string {
	switch t {
	case TypeCWT:
		return "CWT"
	case TypeSign1:
		return "Sign1"
	case TypeSign:
		return "Sign"
	default:
		return "Unknown"
	}
}

// SigningMode represents the cryptographic mode.
type SigningMode int

const (
	// ModeClassical uses only classical cryptography.
	ModeClassical SigningMode = iota
	// ModePQC uses only post-quantum cryptography.
	ModePQC
	// ModeHybrid uses both classical and PQC signatures.
	ModeHybrid
)

// String returns the string representation of the signing mode.
func (m SigningMode) String() string {
	switch m {
	case ModeClassical:
		return "Classical"
	case ModePQC:
		return "PQC"
	case ModeHybrid:
		return "Hybrid"
	default:
		return "Unknown"
	}
}

// SignatureInfo contains information about a signature.
type SignatureInfo struct {
	Algorithm   gocose.Algorithm
	KeyID       []byte
	Certificate *x509.Certificate
}

// Message represents a parsed COSE message (Sign1, Sign, or CWT).
type Message struct {
	Type        MessageType
	Mode        SigningMode
	Payload     []byte
	Claims      *Claims // Only for CWT
	Signatures  []SignatureInfo
	RawMessage  []byte // Original CBOR bytes
	ContentType string
}

// MessageConfig contains options for creating a COSE message.
type MessageConfig struct {
	// Type of message to create (CWT, Sign1, Sign)
	Type MessageType

	// Certificate and signer for classical/single signature
	Certificate *x509.Certificate
	Signer      crypto.Signer

	// Additional certificate and signer for hybrid mode
	PQCCertificate *x509.Certificate
	PQCSigner      crypto.Signer

	// Content type (e.g., "application/cwt", "application/json")
	ContentType string

	// Include certificate chain in the message
	IncludeCertChain bool

	// Serial generator for CWT ID
	SerialGenerator SerialGenerator
}

// Mode returns the signing mode based on the configuration.
func (c *MessageConfig) Mode() SigningMode {
	if c.Signer != nil && c.PQCSigner != nil {
		return ModeHybrid
	}

	signer := c.Signer
	if signer == nil {
		signer = c.PQCSigner
	}
	if signer == nil {
		return ModeClassical
	}

	alg, err := COSEAlgorithmFromKey(signer.Public())
	if err != nil {
		return ModeClassical
	}

	if IsPQCAlgorithm(alg) {
		return ModePQC
	}
	return ModeClassical
}

// CWTConfig contains options for creating a CWT.
type CWTConfig struct {
	MessageConfig

	// CWT claims
	Claims *Claims

	// Auto-set IssuedAt to now if not set
	AutoIssuedAt bool

	// Auto-generate CWT ID if not set
	AutoCWTID bool
}

// COSE Header labels (RFC 9052).
const (
	HeaderAlgorithm   int64 = 1  // alg
	HeaderCritical    int64 = 2  // crit
	HeaderContentType int64 = 3  // content type
	HeaderKeyID       int64 = 4  // kid
	HeaderIV          int64 = 5  // IV
	HeaderPartialIV   int64 = 6  // Partial IV
	HeaderX5Chain     int64 = 33 // x5chain (RFC 9360)
)

// CertificateFingerprint returns the SHA-256 fingerprint of a certificate.
// This is used as the Key ID (kid) in COSE headers.
func CertificateFingerprint(cert *x509.Certificate) []byte {
	if cert == nil {
		return nil
	}
	h := sha256.Sum256(cert.Raw)
	return h[:]
}

// VerifyConfig contains options for verifying a COSE message.
type VerifyConfig struct {
	// Root certificates for chain verification
	Roots *x509.CertPool

	// RootCerts contains parsed root certificates for PQC chain verification.
	// This is needed because Go's x509 package doesn't support PQC signatures.
	RootCerts []*x509.Certificate

	// Intermediate certificates for chain building
	Intermediates *x509.CertPool

	// Expected certificate or public key for signature verification
	Certificate *x509.Certificate
	PublicKey   crypto.PublicKey

	// For hybrid mode: additional certificate/key for PQC verification
	PQCCertificate *x509.Certificate
	PQCPublicKey   crypto.PublicKey

	// Check expiration claims (exp/nbf) for CWT
	CheckExpiration bool

	// Current time for verification (defaults to now)
	CurrentTime time.Time

	// Key usages required (if any)
	KeyUsages []x509.ExtKeyUsage
}

// VerifyResult contains the result of message verification.
type VerifyResult struct {
	// Verification status
	Valid bool

	// Verified certificates (one per signature)
	Certificates []*x509.Certificate

	// Algorithms used
	Algorithms []gocose.Algorithm

	// Signing mode detected
	Mode SigningMode

	// Claims (for CWT)
	Claims *Claims

	// Any warnings (non-fatal issues)
	Warnings []string
}
