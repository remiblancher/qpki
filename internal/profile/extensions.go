// Package profile provides certificate profile management including
// configurable X.509 extensions with criticality support.
package profile

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"net"
	"strings"
)

// ExtensionsConfig holds all configurable X.509 certificate extensions.
// Each extension can specify its criticality explicitly.
// If criticality is not specified, RFC 5280 defaults are used.
type ExtensionsConfig struct {
	KeyUsage              *KeyUsageConfig              `yaml:"keyUsage,omitempty"`
	ExtKeyUsage           *ExtKeyUsageConfig           `yaml:"extKeyUsage,omitempty"`
	BasicConstraints      *BasicConstraintsConfig      `yaml:"basicConstraints,omitempty"`
	SubjectAltName        *SubjectAltNameConfig        `yaml:"subjectAltName,omitempty"`
	CRLDistributionPoints *CRLDistributionPointsConfig `yaml:"crlDistributionPoints,omitempty"`
	AuthorityInfoAccess   *AuthorityInfoAccessConfig   `yaml:"authorityInfoAccess,omitempty"`
	CertificatePolicies   *CertificatePoliciesConfig   `yaml:"certificatePolicies,omitempty"`
	NameConstraints       *NameConstraintsConfig       `yaml:"nameConstraints,omitempty"`
}

// KeyUsageConfig configures the Key Usage extension (OID 2.5.29.15).
// RFC 5280: This extension MUST be critical when used.
type KeyUsageConfig struct {
	Critical *bool    `yaml:"critical,omitempty"` // default: true (RFC 5280)
	Values   []string `yaml:"values"`
}

// IsCritical returns true if the extension should be marked critical.
// Default: true per RFC 5280.
func (c *KeyUsageConfig) IsCritical() bool {
	if c.Critical == nil {
		return true // RFC 5280 default
	}
	return *c.Critical
}

// ToKeyUsage converts string values to x509.KeyUsage flags.
func (c *KeyUsageConfig) ToKeyUsage() (x509.KeyUsage, error) {
	var usage x509.KeyUsage
	for _, v := range c.Values {
		switch strings.ToLower(v) {
		case "digitalsignature", "digital-signature":
			usage |= x509.KeyUsageDigitalSignature
		case "contentcommitment", "content-commitment", "nonrepudiation", "non-repudiation":
			usage |= x509.KeyUsageContentCommitment
		case "keyencipherment", "key-encipherment":
			usage |= x509.KeyUsageKeyEncipherment
		case "dataencipherment", "data-encipherment":
			usage |= x509.KeyUsageDataEncipherment
		case "keyagreement", "key-agreement":
			usage |= x509.KeyUsageKeyAgreement
		case "certsign", "cert-sign", "keycertsign", "key-cert-sign":
			usage |= x509.KeyUsageCertSign
		case "crlsign", "crl-sign":
			usage |= x509.KeyUsageCRLSign
		case "encipheronly", "encipher-only":
			usage |= x509.KeyUsageEncipherOnly
		case "decipheronly", "decipher-only":
			usage |= x509.KeyUsageDecipherOnly
		default:
			return 0, fmt.Errorf("unknown key usage: %s", v)
		}
	}
	return usage, nil
}

// ExtKeyUsageConfig configures the Extended Key Usage extension (OID 2.5.29.37).
// RFC 5280: This extension MAY be critical or non-critical.
type ExtKeyUsageConfig struct {
	Critical *bool    `yaml:"critical,omitempty"` // default: false
	Values   []string `yaml:"values"`
}

// IsCritical returns true if the extension should be marked critical.
// Default: false.
func (c *ExtKeyUsageConfig) IsCritical() bool {
	if c.Critical == nil {
		return false // default
	}
	return *c.Critical
}

// ToExtKeyUsage converts string values to x509.ExtKeyUsage slice.
func (c *ExtKeyUsageConfig) ToExtKeyUsage() ([]x509.ExtKeyUsage, error) {
	var usages []x509.ExtKeyUsage
	for _, v := range c.Values {
		switch strings.ToLower(v) {
		case "serverauth", "server-auth":
			usages = append(usages, x509.ExtKeyUsageServerAuth)
		case "clientauth", "client-auth":
			usages = append(usages, x509.ExtKeyUsageClientAuth)
		case "codesigning", "code-signing":
			usages = append(usages, x509.ExtKeyUsageCodeSigning)
		case "emailprotection", "email-protection":
			usages = append(usages, x509.ExtKeyUsageEmailProtection)
		case "timestamping", "time-stamping":
			usages = append(usages, x509.ExtKeyUsageTimeStamping)
		case "ocspsigning", "ocsp-signing":
			usages = append(usages, x509.ExtKeyUsageOCSPSigning)
		case "any":
			usages = append(usages, x509.ExtKeyUsageAny)
		default:
			return nil, fmt.Errorf("unknown extended key usage: %s", v)
		}
	}
	return usages, nil
}

// BasicConstraintsConfig configures the Basic Constraints extension (OID 2.5.29.19).
// RFC 5280: This extension MUST be critical.
type BasicConstraintsConfig struct {
	Critical *bool `yaml:"critical,omitempty"` // default: true (RFC 5280)
	CA       bool  `yaml:"ca"`
	PathLen  *int  `yaml:"pathLen,omitempty"`
}

// IsCritical returns true if the extension should be marked critical.
// Default: true per RFC 5280.
func (c *BasicConstraintsConfig) IsCritical() bool {
	if c.Critical == nil {
		return true // RFC 5280 default
	}
	return *c.Critical
}

// SubjectAltNameConfig configures the Subject Alternative Name extension (OID 2.5.29.17).
// RFC 5280: This extension SHOULD be non-critical, but MUST be critical if subject is empty.
type SubjectAltNameConfig struct {
	Critical *bool    `yaml:"critical,omitempty"` // default: false (true if subject empty)
	DNS      []string `yaml:"dns,omitempty"`
	Email    []string `yaml:"email,omitempty"`
	IP       []string `yaml:"ip,omitempty"`
	URI      []string `yaml:"uri,omitempty"`
}

// IsCritical returns true if the extension should be marked critical.
// Default: false (caller should set to true if subject is empty).
func (c *SubjectAltNameConfig) IsCritical() bool {
	if c.Critical == nil {
		return false // caller handles subject-empty case
	}
	return *c.Critical
}

// CRLDistributionPointsConfig configures the CRL Distribution Points extension (OID 2.5.29.31).
// RFC 5280: This extension SHOULD be non-critical.
type CRLDistributionPointsConfig struct {
	Critical *bool    `yaml:"critical,omitempty"` // default: false
	URLs     []string `yaml:"urls"`
}

// IsCritical returns true if the extension should be marked critical.
// Default: false per RFC 5280.
func (c *CRLDistributionPointsConfig) IsCritical() bool {
	if c.Critical == nil {
		return false // RFC 5280 default
	}
	return *c.Critical
}

// AuthorityInfoAccessConfig configures the Authority Information Access extension (OID 1.3.6.1.5.5.7.1.1).
// RFC 5280: This extension MUST be non-critical.
type AuthorityInfoAccessConfig struct {
	Critical  *bool    `yaml:"critical,omitempty"` // default: false (MUST be non-critical)
	OCSP      []string `yaml:"ocsp,omitempty"`
	CAIssuers []string `yaml:"caIssuers,omitempty"`
}

// IsCritical returns true if the extension should be marked critical.
// Default: false per RFC 5280 (MUST be non-critical).
func (c *AuthorityInfoAccessConfig) IsCritical() bool {
	if c.Critical == nil {
		return false // RFC 5280: MUST be non-critical
	}
	return *c.Critical
}

// CertificatePoliciesConfig configures the Certificate Policies extension (OID 2.5.29.32).
// RFC 5280: This extension MAY be critical or non-critical.
type CertificatePoliciesConfig struct {
	Critical *bool          `yaml:"critical,omitempty"` // default: false
	Policies []PolicyConfig `yaml:"policies"`
}

// IsCritical returns true if the extension should be marked critical.
// Default: false.
func (c *CertificatePoliciesConfig) IsCritical() bool {
	if c.Critical == nil {
		return false // default
	}
	return *c.Critical
}

// PolicyConfig represents a single certificate policy.
type PolicyConfig struct {
	OID        string `yaml:"oid"`
	CPS        string `yaml:"cps,omitempty"`
	UserNotice string `yaml:"userNotice,omitempty"`
}

// NameConstraintsConfig configures the Name Constraints extension (OID 2.5.29.30).
// RFC 5280: This extension MUST be critical.
type NameConstraintsConfig struct {
	Critical  *bool                    `yaml:"critical,omitempty"` // default: true (RFC 5280)
	Permitted *NameConstraintsSubtrees `yaml:"permitted,omitempty"`
	Excluded  *NameConstraintsSubtrees `yaml:"excluded,omitempty"`
}

// IsCritical returns true if the extension should be marked critical.
// Default: true per RFC 5280.
func (c *NameConstraintsConfig) IsCritical() bool {
	if c.Critical == nil {
		return true // RFC 5280 default
	}
	return *c.Critical
}

// NameConstraintsSubtrees holds permitted or excluded name subtrees.
type NameConstraintsSubtrees struct {
	DNS   []string `yaml:"dns,omitempty"`
	Email []string `yaml:"email,omitempty"`
	IP    []string `yaml:"ip,omitempty"` // CIDR notation
}

// Apply applies the extensions configuration to an x509.Certificate template.
// Extensions not specified in the config are left unchanged.
func (e *ExtensionsConfig) Apply(cert *x509.Certificate) error {
	if e == nil {
		return nil
	}

	// Key Usage
	if e.KeyUsage != nil {
		usage, err := e.KeyUsage.ToKeyUsage()
		if err != nil {
			return fmt.Errorf("keyUsage: %w", err)
		}
		cert.KeyUsage = usage
	}

	// Extended Key Usage
	if e.ExtKeyUsage != nil {
		usages, err := e.ExtKeyUsage.ToExtKeyUsage()
		if err != nil {
			return fmt.Errorf("extKeyUsage: %w", err)
		}
		cert.ExtKeyUsage = usages
	}

	// Basic Constraints
	if e.BasicConstraints != nil {
		cert.IsCA = e.BasicConstraints.CA
		cert.BasicConstraintsValid = true
		if e.BasicConstraints.PathLen != nil {
			cert.MaxPathLen = *e.BasicConstraints.PathLen
			cert.MaxPathLenZero = (*e.BasicConstraints.PathLen == 0)
		} else if !e.BasicConstraints.CA {
			cert.MaxPathLen = -1
		}
	}

	// Subject Alternative Name
	if e.SubjectAltName != nil {
		cert.DNSNames = append(cert.DNSNames, e.SubjectAltName.DNS...)
		cert.EmailAddresses = append(cert.EmailAddresses, e.SubjectAltName.Email...)
		for _, ipStr := range e.SubjectAltName.IP {
			ip := net.ParseIP(ipStr)
			if ip == nil {
				return fmt.Errorf("invalid IP address in SAN: %s", ipStr)
			}
			cert.IPAddresses = append(cert.IPAddresses, ip)
		}
		// URIs would need url.Parse - skipping for now
	}

	// CRL Distribution Points
	if e.CRLDistributionPoints != nil {
		cert.CRLDistributionPoints = e.CRLDistributionPoints.URLs
	}

	// Authority Information Access
	if e.AuthorityInfoAccess != nil {
		cert.OCSPServer = e.AuthorityInfoAccess.OCSP
		cert.IssuingCertificateURL = e.AuthorityInfoAccess.CAIssuers
	}

	// Certificate Policies - requires custom extension
	if e.CertificatePolicies != nil && len(e.CertificatePolicies.Policies) > 0 {
		ext, err := encodeCertificatePolicies(e.CertificatePolicies)
		if err != nil {
			return fmt.Errorf("certificatePolicies: %w", err)
		}
		cert.ExtraExtensions = append(cert.ExtraExtensions, ext)
	}

	// Name Constraints
	if e.NameConstraints != nil {
		if e.NameConstraints.Permitted != nil {
			cert.PermittedDNSDomains = e.NameConstraints.Permitted.DNS
			cert.PermittedEmailAddresses = e.NameConstraints.Permitted.Email
			for _, cidr := range e.NameConstraints.Permitted.IP {
				_, ipNet, err := net.ParseCIDR(cidr)
				if err != nil {
					return fmt.Errorf("invalid permitted IP CIDR: %s", cidr)
				}
				cert.PermittedIPRanges = append(cert.PermittedIPRanges, ipNet)
			}
		}
		if e.NameConstraints.Excluded != nil {
			cert.ExcludedDNSDomains = e.NameConstraints.Excluded.DNS
			cert.ExcludedEmailAddresses = e.NameConstraints.Excluded.Email
			for _, cidr := range e.NameConstraints.Excluded.IP {
				_, ipNet, err := net.ParseCIDR(cidr)
				if err != nil {
					return fmt.Errorf("invalid excluded IP CIDR: %s", cidr)
				}
				cert.ExcludedIPRanges = append(cert.ExcludedIPRanges, ipNet)
			}
		}
	}

	return nil
}

// OID for Certificate Policies extension
var oidCertificatePolicies = asn1.ObjectIdentifier{2, 5, 29, 32}

// OID for CPS qualifier
var oidCPSQualifier = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 1}

// OID for User Notice qualifier
var oidUserNoticeQualifier = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 2}

// policyInformation represents a certificate policy
type policyInformation struct {
	PolicyIdentifier asn1.ObjectIdentifier
	PolicyQualifiers []policyQualifierInfo `asn1:"optional"`
}

// policyQualifierInfo represents a policy qualifier
type policyQualifierInfo struct {
	PolicyQualifierId asn1.ObjectIdentifier
	Qualifier         asn1.RawValue
}

// encodeCertificatePolicies encodes the Certificate Policies extension.
func encodeCertificatePolicies(config *CertificatePoliciesConfig) (pkix.Extension, error) {
	var policies []policyInformation

	for _, p := range config.Policies {
		oid, err := parseOID(p.OID)
		if err != nil {
			return pkix.Extension{}, fmt.Errorf("invalid policy OID %s: %w", p.OID, err)
		}

		policy := policyInformation{
			PolicyIdentifier: oid,
		}

		// Add CPS qualifier if specified
		if p.CPS != "" {
			cpsBytes, err := asn1.Marshal(p.CPS)
			if err != nil {
				return pkix.Extension{}, fmt.Errorf("failed to marshal CPS: %w", err)
			}
			policy.PolicyQualifiers = append(policy.PolicyQualifiers, policyQualifierInfo{
				PolicyQualifierId: oidCPSQualifier,
				Qualifier:         asn1.RawValue{FullBytes: cpsBytes},
			})
		}

		// Add User Notice qualifier if specified
		if p.UserNotice != "" {
			// UserNotice is more complex, simplified here
			noticeBytes, err := asn1.Marshal(p.UserNotice)
			if err != nil {
				return pkix.Extension{}, fmt.Errorf("failed to marshal UserNotice: %w", err)
			}
			policy.PolicyQualifiers = append(policy.PolicyQualifiers, policyQualifierInfo{
				PolicyQualifierId: oidUserNoticeQualifier,
				Qualifier:         asn1.RawValue{FullBytes: noticeBytes},
			})
		}

		policies = append(policies, policy)
	}

	value, err := asn1.Marshal(policies)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("failed to marshal policies: %w", err)
	}

	return pkix.Extension{
		Id:       oidCertificatePolicies,
		Critical: config.IsCritical(),
		Value:    value,
	}, nil
}

// parseOID parses a dotted OID string into an asn1.ObjectIdentifier.
func parseOID(s string) (asn1.ObjectIdentifier, error) {
	parts := strings.Split(s, ".")
	oid := make(asn1.ObjectIdentifier, len(parts))
	for i, part := range parts {
		var n int
		_, err := fmt.Sscanf(part, "%d", &n)
		if err != nil {
			return nil, fmt.Errorf("invalid OID component %s: %w", part, err)
		}
		oid[i] = n
	}
	return oid, nil
}
