// Package profile provides certificate profile management including
// configurable X.509 extensions with criticality support.
package profile

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"net"
	"regexp"
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
	OCSPNoCheck           *OCSPNoCheckConfig           `yaml:"ocspNoCheck,omitempty"`
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
//
// SAN fields accept either a string template ("{{ variable }}") or a list of strings.
// Examples:
//
//	dns: "{{ dns_names }}"           # template, expanded at runtime
//	dns: ["example.com", "*.example.com"]  # static list
type SubjectAltNameConfig struct {
	Critical *bool         `yaml:"critical,omitempty"` // default: false (true if subject empty)
	DNS      StringOrSlice `yaml:"dns,omitempty"`      // Can be template: "{{ dns_names }}"
	Email    StringOrSlice `yaml:"email,omitempty"`    // Can be template: "{{ email }}"
	IP       StringOrSlice `yaml:"ip,omitempty"`       // Can be template: "{{ ip_addresses }}"
	URI      StringOrSlice `yaml:"uri,omitempty"`

	// DNSIncludeCN automatically adds the CN to DNS SANs if true.
	// Browsers require DNS names in SAN (CN is deprecated for server identity).
	DNSIncludeCN bool `yaml:"dns_include_cn,omitempty" json:"dns_include_cn,omitempty"`
}

// StringOrSlice can unmarshal from either a single string or a string slice.
// This allows profile YAML to use either format:
//
//	dns: "{{ dns_names }}"       # single template string
//	dns: ["a.example.com"]       # explicit list
type StringOrSlice []string

// UnmarshalYAML implements yaml.Unmarshaler for StringOrSlice.
func (s *StringOrSlice) UnmarshalYAML(unmarshal func(interface{}) error) error {
	// Try as string first
	var str string
	if err := unmarshal(&str); err == nil {
		*s = []string{str}
		return nil
	}

	// Try as slice
	var slice []string
	if err := unmarshal(&slice); err != nil {
		return err
	}
	*s = slice
	return nil
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

// OCSPNoCheckConfig configures the OCSP No Check extension (OID 1.3.6.1.5.5.7.48.1.5).
// RFC 6960 §4.2.2.2.1: This extension indicates that the OCSP responder certificate
// should not be checked for revocation status.
type OCSPNoCheckConfig struct {
	Critical *bool `yaml:"critical,omitempty"` // default: false (RFC 6960)
}

// IsCritical returns true if the extension should be marked critical.
// Default: false per RFC 6960.
func (c *OCSPNoCheckConfig) IsCritical() bool {
	if c.Critical == nil {
		return false // RFC 6960 default
	}
	return *c.Critical
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
	// RFC 3161 requires EKU to be critical for TSA certificates
	if e.ExtKeyUsage != nil {
		usages, err := e.ExtKeyUsage.ToExtKeyUsage()
		if err != nil {
			return fmt.Errorf("extKeyUsage: %w", err)
		}

		// Always set ExtKeyUsage for PQC path (buildEndEntityExtensions uses this)
		cert.ExtKeyUsage = usages

		if e.ExtKeyUsage.IsCritical() {
			// For classical path (x509.CreateCertificate), also add to ExtraExtensions
			// with critical flag. This overrides the non-critical version from ExtKeyUsage.
			// (Go's x509.Certificate.ExtKeyUsage doesn't support critical flag)
			ext, err := encodeExtKeyUsage(usages, true)
			if err != nil {
				return fmt.Errorf("extKeyUsage encoding: %w", err)
			}
			cert.ExtraExtensions = append(cert.ExtraExtensions, ext)
		}
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

	// OCSP No Check - requires custom extension (RFC 6960 §4.2.2.2.1)
	if e.OCSPNoCheck != nil {
		ext := encodeOCSPNoCheck(e.OCSPNoCheck)
		cert.ExtraExtensions = append(cert.ExtraExtensions, ext)
	}

	return nil
}

// Validate checks the logical consistency of extension configuration per RFC 5280.
// Returns an error if the configuration violates RFC 5280 requirements.
func (e *ExtensionsConfig) Validate() error {
	if e == nil {
		return nil
	}

	isCA := e.BasicConstraints != nil && e.BasicConstraints.CA

	// Rule 1: CA=true requires keyCertSign in keyUsage (RFC 5280 §4.2.1.9)
	if isCA {
		if e.KeyUsage == nil {
			return fmt.Errorf("CA certificates must have keyUsage extension (RFC 5280 §4.2.1.3)")
		}
		hasKeyCertSign := false
		for _, v := range e.KeyUsage.Values {
			switch strings.ToLower(v) {
			case "certsign", "cert-sign", "keycertsign", "key-cert-sign":
				hasKeyCertSign = true
			}
		}
		if !hasKeyCertSign {
			return fmt.Errorf("CA certificates must have keyCertSign in keyUsage (RFC 5280 §4.2.1.9)")
		}
	}

	// Rule 2: pathLen is only valid for CA certificates (RFC 5280 §4.2.1.9)
	if e.BasicConstraints != nil && e.BasicConstraints.PathLen != nil && !e.BasicConstraints.CA {
		return fmt.Errorf("pathLen is only valid for CA certificates (RFC 5280 §4.2.1.9)")
	}

	// Rule 3: NameConstraints is only valid for CA certificates (RFC 5280 §4.2.1.10)
	if e.NameConstraints != nil && !isCA {
		hasConstraints := false
		if e.NameConstraints.Permitted != nil {
			hasConstraints = len(e.NameConstraints.Permitted.DNS) > 0 ||
				len(e.NameConstraints.Permitted.Email) > 0 ||
				len(e.NameConstraints.Permitted.IP) > 0
		}
		if e.NameConstraints.Excluded != nil {
			hasConstraints = hasConstraints ||
				len(e.NameConstraints.Excluded.DNS) > 0 ||
				len(e.NameConstraints.Excluded.Email) > 0 ||
				len(e.NameConstraints.Excluded.IP) > 0
		}
		if hasConstraints {
			return fmt.Errorf("nameConstraints extension is only valid for CA certificates (RFC 5280 §4.2.1.10)")
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

// OID for OCSP No Check extension (RFC 6960 §4.2.2.2.1)
var oidOCSPNoCheck = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}

// encodeOCSPNoCheck encodes the OCSP No Check extension.
// This extension contains a NULL value.
func encodeOCSPNoCheck(config *OCSPNoCheckConfig) pkix.Extension {
	// OCSP No Check is a NULL extension
	nullValue, _ := asn1.Marshal(asn1.NullRawValue)

	return pkix.Extension{
		Id:       oidOCSPNoCheck,
		Critical: config.IsCritical(),
		Value:    nullValue,
	}
}

// Standard Extended Key Usage OIDs.
var (
	oidExtKeyUsageServerAuth      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	oidExtKeyUsageClientAuth      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
	oidExtKeyUsageCodeSigning     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}
	oidExtKeyUsageEmailProtection = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}
	oidExtKeyUsageTimeStamping    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	oidExtKeyUsageOCSPSigning     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}
	oidExtExtKeyUsage             = asn1.ObjectIdentifier{2, 5, 29, 37}
)

// encodeExtKeyUsage encodes Extended Key Usage as a pkix.Extension.
// This is needed when EKU must be marked as critical (e.g., RFC 3161 TSA).
func encodeExtKeyUsage(usages []x509.ExtKeyUsage, critical bool) (pkix.Extension, error) {
	var oids []asn1.ObjectIdentifier

	for _, usage := range usages {
		switch usage {
		case x509.ExtKeyUsageServerAuth:
			oids = append(oids, oidExtKeyUsageServerAuth)
		case x509.ExtKeyUsageClientAuth:
			oids = append(oids, oidExtKeyUsageClientAuth)
		case x509.ExtKeyUsageCodeSigning:
			oids = append(oids, oidExtKeyUsageCodeSigning)
		case x509.ExtKeyUsageEmailProtection:
			oids = append(oids, oidExtKeyUsageEmailProtection)
		case x509.ExtKeyUsageTimeStamping:
			oids = append(oids, oidExtKeyUsageTimeStamping)
		case x509.ExtKeyUsageOCSPSigning:
			oids = append(oids, oidExtKeyUsageOCSPSigning)
		default:
			return pkix.Extension{}, fmt.Errorf("unsupported ExtKeyUsage: %d", usage)
		}
	}

	ekuBytes, err := asn1.Marshal(oids)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("failed to marshal ExtKeyUsage: %w", err)
	}

	return pkix.Extension{
		Id:       oidExtExtKeyUsage,
		Critical: critical,
		Value:    ekuBytes,
	}, nil
}

// DeepCopy creates a deep copy of the ExtensionsConfig.
func (e *ExtensionsConfig) DeepCopy() *ExtensionsConfig {
	if e == nil {
		return nil
	}

	result := &ExtensionsConfig{}

	// Copy KeyUsage
	if e.KeyUsage != nil {
		result.KeyUsage = &KeyUsageConfig{
			Critical: copyBoolPtr(e.KeyUsage.Critical),
			Values:   copyStringSlice(e.KeyUsage.Values),
		}
	}

	// Copy ExtKeyUsage
	if e.ExtKeyUsage != nil {
		result.ExtKeyUsage = &ExtKeyUsageConfig{
			Critical: copyBoolPtr(e.ExtKeyUsage.Critical),
			Values:   copyStringSlice(e.ExtKeyUsage.Values),
		}
	}

	// Copy BasicConstraints
	if e.BasicConstraints != nil {
		result.BasicConstraints = &BasicConstraintsConfig{
			Critical: copyBoolPtr(e.BasicConstraints.Critical),
			CA:       e.BasicConstraints.CA,
			PathLen:  copyIntPtr(e.BasicConstraints.PathLen),
		}
	}

	// Copy SubjectAltName
	if e.SubjectAltName != nil {
		result.SubjectAltName = &SubjectAltNameConfig{
			Critical:     copyBoolPtr(e.SubjectAltName.Critical),
			DNS:          copyStringSlice(e.SubjectAltName.DNS),
			Email:        copyStringSlice(e.SubjectAltName.Email),
			IP:           copyStringSlice(e.SubjectAltName.IP),
			URI:          copyStringSlice(e.SubjectAltName.URI),
			DNSIncludeCN: e.SubjectAltName.DNSIncludeCN,
		}
	}

	// Copy CRLDistributionPoints
	if e.CRLDistributionPoints != nil {
		result.CRLDistributionPoints = &CRLDistributionPointsConfig{
			Critical: copyBoolPtr(e.CRLDistributionPoints.Critical),
			URLs:     copyStringSlice(e.CRLDistributionPoints.URLs),
		}
	}

	// Copy AuthorityInfoAccess
	if e.AuthorityInfoAccess != nil {
		result.AuthorityInfoAccess = &AuthorityInfoAccessConfig{
			Critical:  copyBoolPtr(e.AuthorityInfoAccess.Critical),
			OCSP:      copyStringSlice(e.AuthorityInfoAccess.OCSP),
			CAIssuers: copyStringSlice(e.AuthorityInfoAccess.CAIssuers),
		}
	}

	// Copy CertificatePolicies
	if e.CertificatePolicies != nil {
		policies := make([]PolicyConfig, len(e.CertificatePolicies.Policies))
		copy(policies, e.CertificatePolicies.Policies)
		result.CertificatePolicies = &CertificatePoliciesConfig{
			Critical: copyBoolPtr(e.CertificatePolicies.Critical),
			Policies: policies,
		}
	}

	// Copy NameConstraints
	if e.NameConstraints != nil {
		result.NameConstraints = &NameConstraintsConfig{
			Critical: copyBoolPtr(e.NameConstraints.Critical),
		}
		if e.NameConstraints.Permitted != nil {
			result.NameConstraints.Permitted = &NameConstraintsSubtrees{
				DNS:   copyStringSlice(e.NameConstraints.Permitted.DNS),
				Email: copyStringSlice(e.NameConstraints.Permitted.Email),
				IP:    copyStringSlice(e.NameConstraints.Permitted.IP),
			}
		}
		if e.NameConstraints.Excluded != nil {
			result.NameConstraints.Excluded = &NameConstraintsSubtrees{
				DNS:   copyStringSlice(e.NameConstraints.Excluded.DNS),
				Email: copyStringSlice(e.NameConstraints.Excluded.Email),
				IP:    copyStringSlice(e.NameConstraints.Excluded.IP),
			}
		}
	}

	// Copy OCSPNoCheck
	if e.OCSPNoCheck != nil {
		result.OCSPNoCheck = &OCSPNoCheckConfig{
			Critical: copyBoolPtr(e.OCSPNoCheck.Critical),
		}
	}

	return result
}

// SubstituteVariables replaces template variables ({{ variable }}) with actual values.
// Returns an error if a required variable is referenced but not provided.
func (e *ExtensionsConfig) SubstituteVariables(vars map[string][]string) (*ExtensionsConfig, error) {
	if e == nil {
		return nil, nil
	}

	result := e.DeepCopy()

	// Substitute variables in SubjectAltName
	if result.SubjectAltName != nil {
		// DNS
		result.SubjectAltName.DNS = substituteStringSlice(result.SubjectAltName.DNS, vars)

		// Email
		result.SubjectAltName.Email = substituteStringSlice(result.SubjectAltName.Email, vars)

		// IP
		result.SubjectAltName.IP = substituteStringSlice(result.SubjectAltName.IP, vars)

		// URI
		result.SubjectAltName.URI = substituteStringSlice(result.SubjectAltName.URI, vars)
	}

	return result, nil
}

// sanVarPattern matches {{ variable_name }} patterns for SAN substitution.
var sanVarPattern = regexp.MustCompile(`^\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\}\}$`)

// substituteStringSlice replaces template variables in a string slice.
// Variables have the form {{ variable_name }}. If a variable is not provided,
// it is silently skipped (variables are optional by default).
func substituteStringSlice(values []string, vars map[string][]string) []string {
	var result []string

	for _, v := range values {
		// Check for {{ variable }} pattern
		if matches := sanVarPattern.FindStringSubmatch(strings.TrimSpace(v)); len(matches) == 2 {
			varName := matches[1]
			if substitutes, ok := vars[varName]; ok && len(substitutes) > 0 {
				result = append(result, substitutes...)
			}
			// If not provided, skip (variable is optional)
		} else {
			// Static value, keep as-is
			result = append(result, v)
		}
	}

	return result
}

// copyBoolPtr creates a copy of a bool pointer.
func copyBoolPtr(p *bool) *bool {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

// copyIntPtr creates a copy of an int pointer.
func copyIntPtr(p *int) *int {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

// copyStringSlice creates a copy of a string slice.
func copyStringSlice(s []string) []string {
	if s == nil {
		return nil
	}
	result := make([]string, len(s))
	copy(result, s)
	return result
}
