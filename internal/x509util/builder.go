package x509util

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"time"
)

// CertificateRequest holds the parameters for creating a certificate.
type CertificateRequest struct {
	// Subject information
	Subject pkix.Name

	// Subject Alternative Names
	DNSNames       []string
	EmailAddresses []string
	IPAddresses    []net.IP
	URIs           []*url.URL

	// Validity period
	NotBefore time.Time
	NotAfter  time.Time

	// Key Usage
	KeyUsage    x509.KeyUsage
	ExtKeyUsage []x509.ExtKeyUsage

	// CA settings
	IsCA                  bool
	MaxPathLen            int
	MaxPathLenZero        bool
	BasicConstraintsValid bool

	// Serial number (if nil, a random one will be generated)
	SerialNumber *big.Int

	// CRL Distribution Points
	CRLDistributionPoints []string

	// OCSP servers
	OCSPServers []string

	// Issuing certificate URL
	IssuingCertificateURL []string

	// Additional extensions
	ExtraExtensions []pkix.Extension

	// Hybrid PQC extension (optional)
	HybridExtension *HybridExtensionRequest
}

// HybridExtensionRequest specifies the hybrid extension to add.
type HybridExtensionRequest struct {
	PublicKey []byte
	Algorithm string // e.g., "ml-dsa-65", "ml-kem-768"
	Policy    HybridPolicy
}

// CertificateBuilder builds X.509 certificates.
type CertificateBuilder struct {
	request *CertificateRequest
}

// NewCertificateBuilder creates a new certificate builder.
func NewCertificateBuilder() *CertificateBuilder {
	return &CertificateBuilder{
		request: &CertificateRequest{
			NotBefore:             time.Now(),
			NotAfter:              time.Now().AddDate(1, 0, 0), // 1 year default
			BasicConstraintsValid: true,
		},
	}
}

// Subject sets the certificate subject.
func (b *CertificateBuilder) Subject(name pkix.Name) *CertificateBuilder {
	b.request.Subject = name
	return b
}

// CommonName sets the subject common name.
func (b *CertificateBuilder) CommonName(cn string) *CertificateBuilder {
	b.request.Subject.CommonName = cn
	return b
}

// Organization sets the subject organization.
func (b *CertificateBuilder) Organization(org string) *CertificateBuilder {
	b.request.Subject.Organization = []string{org}
	return b
}

// Country sets the subject country.
func (b *CertificateBuilder) Country(country string) *CertificateBuilder {
	b.request.Subject.Country = []string{country}
	return b
}

// DNSNames sets the DNS SANs.
func (b *CertificateBuilder) DNSNames(names ...string) *CertificateBuilder {
	b.request.DNSNames = names
	return b
}

// IPAddresses sets the IP SANs.
func (b *CertificateBuilder) IPAddresses(ips ...net.IP) *CertificateBuilder {
	b.request.IPAddresses = ips
	return b
}

// EmailAddresses sets the email SANs.
func (b *CertificateBuilder) EmailAddresses(emails ...string) *CertificateBuilder {
	b.request.EmailAddresses = emails
	return b
}

// URIs sets the URI SANs.
func (b *CertificateBuilder) URIs(uris ...*url.URL) *CertificateBuilder {
	b.request.URIs = uris
	return b
}

// Validity sets the certificate validity period.
func (b *CertificateBuilder) Validity(notBefore, notAfter time.Time) *CertificateBuilder {
	b.request.NotBefore = notBefore
	b.request.NotAfter = notAfter
	return b
}

// ValidFor sets the validity duration from now.
func (b *CertificateBuilder) ValidFor(d time.Duration) *CertificateBuilder {
	b.request.NotBefore = time.Now()
	b.request.NotAfter = time.Now().Add(d)
	return b
}

// ValidForYears sets the validity in years from now.
func (b *CertificateBuilder) ValidForYears(years int) *CertificateBuilder {
	b.request.NotBefore = time.Now()
	b.request.NotAfter = time.Now().AddDate(years, 0, 0)
	return b
}

// KeyUsage sets the key usage flags.
func (b *CertificateBuilder) KeyUsage(usage x509.KeyUsage) *CertificateBuilder {
	b.request.KeyUsage = usage
	return b
}

// ExtKeyUsage sets the extended key usage.
func (b *CertificateBuilder) ExtKeyUsage(usage ...x509.ExtKeyUsage) *CertificateBuilder {
	b.request.ExtKeyUsage = usage
	return b
}

// CA marks this as a CA certificate.
func (b *CertificateBuilder) CA(maxPathLen int) *CertificateBuilder {
	b.request.IsCA = true
	b.request.MaxPathLen = maxPathLen
	b.request.MaxPathLenZero = (maxPathLen == 0)
	b.request.BasicConstraintsValid = true
	b.request.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	return b
}

// EndEntity marks this as an end-entity (non-CA) certificate.
func (b *CertificateBuilder) EndEntity() *CertificateBuilder {
	b.request.IsCA = false
	b.request.MaxPathLen = -1
	b.request.BasicConstraintsValid = true
	return b
}

// TLSServer configures the certificate for TLS server authentication.
func (b *CertificateBuilder) TLSServer() *CertificateBuilder {
	b.request.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	b.request.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	return b.EndEntity()
}

// TLSClient configures the certificate for TLS client authentication.
func (b *CertificateBuilder) TLSClient() *CertificateBuilder {
	b.request.KeyUsage = x509.KeyUsageDigitalSignature
	b.request.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	return b.EndEntity()
}

// CodeSigning configures the certificate for code signing.
func (b *CertificateBuilder) CodeSigning() *CertificateBuilder {
	b.request.KeyUsage = x509.KeyUsageDigitalSignature
	b.request.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
	return b.EndEntity()
}

// SerialNumber sets a specific serial number.
func (b *CertificateBuilder) SerialNumber(sn *big.Int) *CertificateBuilder {
	b.request.SerialNumber = sn
	return b
}

// CRLDistributionPoints sets the CRL distribution points.
func (b *CertificateBuilder) CRLDistributionPoints(urls ...string) *CertificateBuilder {
	b.request.CRLDistributionPoints = urls
	return b
}

// OCSPServers sets the OCSP server URLs.
func (b *CertificateBuilder) OCSPServers(urls ...string) *CertificateBuilder {
	b.request.OCSPServers = urls
	return b
}

// IssuingCertificateURL sets the issuing certificate URL (AIA).
func (b *CertificateBuilder) IssuingCertificateURL(urls ...string) *CertificateBuilder {
	b.request.IssuingCertificateURL = urls
	return b
}

// AddExtension adds a custom extension.
func (b *CertificateBuilder) AddExtension(ext pkix.Extension) *CertificateBuilder {
	b.request.ExtraExtensions = append(b.request.ExtraExtensions, ext)
	return b
}

// HybridPQC adds a hybrid PQC extension.
func (b *CertificateBuilder) HybridPQC(algorithm string, publicKey []byte, policy HybridPolicy) *CertificateBuilder {
	b.request.HybridExtension = &HybridExtensionRequest{
		Algorithm: algorithm,
		PublicKey: publicKey,
		Policy:    policy,
	}
	return b
}

// Build creates an x509.Certificate template from the request.
func (b *CertificateBuilder) Build() (*x509.Certificate, error) {
	serial := b.request.SerialNumber
	if serial == nil {
		var err error
		serial, err = generateSerialNumber()
		if err != nil {
			return nil, fmt.Errorf("failed to generate serial number: %w", err)
		}
	}

	cert := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               b.request.Subject,
		NotBefore:             b.request.NotBefore,
		NotAfter:              b.request.NotAfter,
		KeyUsage:              b.request.KeyUsage,
		ExtKeyUsage:           b.request.ExtKeyUsage,
		IsCA:                  b.request.IsCA,
		MaxPathLen:            b.request.MaxPathLen,
		MaxPathLenZero:        b.request.MaxPathLenZero,
		BasicConstraintsValid: b.request.BasicConstraintsValid,
		DNSNames:              b.request.DNSNames,
		EmailAddresses:        b.request.EmailAddresses,
		IPAddresses:           b.request.IPAddresses,
		URIs:                  b.request.URIs,
		CRLDistributionPoints: b.request.CRLDistributionPoints,
		OCSPServer:            b.request.OCSPServers,
		IssuingCertificateURL: b.request.IssuingCertificateURL,
		ExtraExtensions:       b.request.ExtraExtensions,
	}

	// Add hybrid extension if requested
	if b.request.HybridExtension != nil {
		hybridReq := b.request.HybridExtension
		alg, err := parseHybridAlgorithm(hybridReq.Algorithm)
		if err != nil {
			return nil, fmt.Errorf("invalid hybrid algorithm: %w", err)
		}

		ext, err := encodeHybridExtensionRaw(alg, hybridReq.PublicKey, hybridReq.Policy)
		if err != nil {
			return nil, fmt.Errorf("failed to encode hybrid extension: %w", err)
		}
		cert.ExtraExtensions = append(cert.ExtraExtensions, ext)
	}

	return cert, nil
}

// BuildAndSign creates and signs a certificate.
func (b *CertificateBuilder) BuildAndSign(
	pub crypto.PublicKey,
	issuer *x509.Certificate,
	issuerKey crypto.Signer,
) (*x509.Certificate, []byte, error) {
	template, err := b.Build()
	if err != nil {
		return nil, nil, err
	}

	// If self-signed, issuer is the template itself
	if issuer == nil {
		issuer = template
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, issuer, pub, issuerKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse created certificate: %w", err)
	}

	return cert, certDER, nil
}

// generateSerialNumber generates a random 128-bit serial number.
func generateSerialNumber() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, serialNumberLimit)
}

// parseHybridAlgorithm parses an algorithm string for hybrid extensions.
func parseHybridAlgorithm(alg string) (asn1.ObjectIdentifier, error) {
	switch alg {
	case "ml-dsa-44":
		return OIDMLDSA44, nil
	case "ml-dsa-65":
		return OIDMLDSA65, nil
	case "ml-dsa-87":
		return OIDMLDSA87, nil
	case "ml-kem-512":
		return OIDMLKEM512, nil
	case "ml-kem-768":
		return OIDMLKEM768, nil
	case "ml-kem-1024":
		return OIDMLKEM1024, nil
	default:
		return nil, fmt.Errorf("unknown algorithm: %s", alg)
	}
}

// encodeHybridExtensionRaw encodes a hybrid extension with raw OID.
func encodeHybridExtensionRaw(algOID asn1.ObjectIdentifier, publicKey []byte, policy HybridPolicy) (pkix.Extension, error) {
	info := HybridPublicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: algOID,
		},
		PublicKey: asn1.BitString{
			Bytes:     publicKey,
			BitLength: len(publicKey) * 8,
		},
		Policy: int(policy),
	}

	value, err := asn1.Marshal(info)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("failed to marshal hybrid extension: %w", err)
	}

	return pkix.Extension{
		Id:       OIDHybridPublicKeyExtension,
		Critical: false,
		Value:    value,
	}, nil
}

// SubjectKeyID computes the subject key identifier from a public key.
// Uses SHA-256 hash of the public key bytes.
func SubjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	var pubBytes []byte
	var err error

	// Try standard PKIX marshaling first
	pubBytes, err = x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		// For PQC keys, use the Bytes() method if available
		if bytesGetter, ok := pub.(interface{ Bytes() []byte }); ok {
			pubBytes = bytesGetter.Bytes()
		} else {
			return nil, fmt.Errorf("failed to marshal public key: %w", err)
		}
	}

	hash := sha256.Sum256(pubBytes)
	return hash[:20], nil // Use first 20 bytes (160 bits)
}
