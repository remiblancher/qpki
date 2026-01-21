// Package profile provides certificate profile management including
// configurable X.509 extensions with criticality support.
package profile

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
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
	QCStatements          *QCStatementsConfig          `yaml:"qcStatements,omitempty"`
	Custom                []CustomExtensionConfig      `yaml:"custom,omitempty"`
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

// ToExtKeyUsage converts string values to x509.ExtKeyUsage slice and custom OIDs.
// Values can be predefined names (serverAuth, clientAuth, etc.) or custom OIDs
// in dot notation (e.g., "1.3.6.1.5.5.7.3.17").
func (c *ExtKeyUsageConfig) ToExtKeyUsage() ([]x509.ExtKeyUsage, []asn1.ObjectIdentifier, error) {
	var usages []x509.ExtKeyUsage
	var customOIDs []asn1.ObjectIdentifier

	for _, v := range c.Values {
		// Try to parse as OID first (format: "1.2.3.4...")
		if oid, err := parseOID(v); err == nil {
			customOIDs = append(customOIDs, oid)
			continue
		}

		// Otherwise, try predefined values
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
			return nil, nil, fmt.Errorf("unknown extended key usage: %s", v)
		}
	}
	return usages, customOIDs, nil
}

// parseOID parses an OID string in dot notation (e.g., "1.2.3.4.5").
// Returns error if the string is not a valid OID format.
func parseOID(s string) (asn1.ObjectIdentifier, error) {
	// Must contain at least one dot and start with a digit
	if !strings.Contains(s, ".") || len(s) == 0 {
		return nil, fmt.Errorf("not an OID format")
	}

	// First character must be a digit
	if s[0] < '0' || s[0] > '9' {
		return nil, fmt.Errorf("not an OID format")
	}

	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("OID must have at least 2 components")
	}

	oid := make(asn1.ObjectIdentifier, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("invalid OID component %q: %w", p, err)
		}
		if n < 0 {
			return nil, fmt.Errorf("OID component cannot be negative: %d", n)
		}
		oid[i] = n
	}
	return oid, nil
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

// QCStatementsConfig configures the QCStatements extension (ETSI EN 319 412-5).
// Used for eIDAS qualified certificates.
type QCStatementsConfig struct {
	Critical          *bool               `yaml:"critical,omitempty"`          // default: false
	QcCompliance      bool                `yaml:"qcCompliance,omitempty"`      // 0.4.0.1862.1.1 - EU qualified cert
	QcType            string              `yaml:"qcType,omitempty"`            // esign, eseal, web
	QcSSCD            bool                `yaml:"qcSSCD,omitempty"`            // 0.4.0.1862.1.4 - QSCD usage
	QcRetentionPeriod *int                `yaml:"qcRetentionPeriod,omitempty"` // 0.4.0.1862.1.3 - years
	QcPDS             []PDSLocationConfig `yaml:"qcPDS,omitempty"`             // 0.4.0.1862.1.5 - PDS URLs
}

// PDSLocationConfig represents a PKI Disclosure Statement location.
type PDSLocationConfig struct {
	URL      string `yaml:"url"`      // URL to PDS document
	Language string `yaml:"language"` // ISO 639-1 (2 chars)
}

// IsCritical returns true if the extension should be marked critical.
// Default: false (QCStatements are typically non-critical).
func (c *QCStatementsConfig) IsCritical() bool {
	if c.Critical == nil {
		return false
	}
	return *c.Critical
}

// Validate checks the QCStatementsConfig for errors.
func (c *QCStatementsConfig) Validate() error {
	if c == nil {
		return nil
	}

	// Validate QcType
	if c.QcType != "" {
		switch c.QcType {
		case "esign", "eseal", "web":
			// Valid
		default:
			return fmt.Errorf("qcStatements: invalid qcType %q (expected esign, eseal, or web)", c.QcType)
		}
	}

	// Validate QcRetentionPeriod
	if c.QcRetentionPeriod != nil && *c.QcRetentionPeriod < 0 {
		return fmt.Errorf("qcStatements: qcRetentionPeriod must be non-negative")
	}

	// Validate QcPDS (skip template variables - they'll be resolved at runtime)
	for i, pds := range c.QcPDS {
		// Skip URL validation if it's a template variable
		if pds.URL == "" && !containsTemplateVar(pds.URL) {
			return fmt.Errorf("qcStatements: qcPDS[%d].url is required", i)
		}
		// Skip language validation if it's a template variable
		if !containsTemplateVar(pds.Language) && len(pds.Language) != 2 {
			return fmt.Errorf("qcStatements: qcPDS[%d].language must be 2 characters (ISO 639-1), got %q", i, pds.Language)
		}
	}

	return nil
}

// containsTemplateVar returns true if the string contains a template variable like {{ name }}.
func containsTemplateVar(s string) bool {
	return strings.Contains(s, "{{")
}

// HasStatements returns true if at least one QCStatement is configured.
func (c *QCStatementsConfig) HasStatements() bool {
	return c.QcCompliance || c.QcType != "" || c.QcSSCD ||
		c.QcRetentionPeriod != nil || len(c.QcPDS) > 0
}

// CustomExtensionConfig configures a custom X.509 extension with arbitrary OID.
// This allows profiles to define proprietary or industry-specific extensions.
// Value must be provided in either hex or base64 encoding (mutually exclusive).
type CustomExtensionConfig struct {
	OID         string `yaml:"oid"`                    // OID in dot notation (e.g., "1.2.3.4.5")
	Critical    bool   `yaml:"critical,omitempty"`     // default: false
	ValueHex    string `yaml:"value_hex,omitempty"`    // DER value in hex encoding
	ValueBase64 string `yaml:"value_base64,omitempty"` // DER value in base64 encoding
}

// ToExtension converts CustomExtensionConfig to a pkix.Extension.
func (c *CustomExtensionConfig) ToExtension() (pkix.Extension, error) {
	oid, err := parseOID(c.OID)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("invalid OID %q: %w", c.OID, err)
	}

	var value []byte

	// Decode value from hex or base64 (mutually exclusive)
	if c.ValueHex != "" && c.ValueBase64 != "" {
		return pkix.Extension{}, fmt.Errorf("custom extension %s: cannot specify both value_hex and value_base64", c.OID)
	}

	if c.ValueHex != "" {
		value, err = hex.DecodeString(c.ValueHex)
		if err != nil {
			return pkix.Extension{}, fmt.Errorf("custom extension %s: invalid hex value: %w", c.OID, err)
		}
	} else if c.ValueBase64 != "" {
		value, err = base64.StdEncoding.DecodeString(c.ValueBase64)
		if err != nil {
			return pkix.Extension{}, fmt.Errorf("custom extension %s: invalid base64 value: %w", c.OID, err)
		}
	}
	// Note: empty value is valid (e.g., NULL extension)

	return pkix.Extension{
		Id:       oid,
		Critical: c.Critical,
		Value:    value,
	}, nil
}

// Validate checks the CustomExtensionConfig for errors.
func (c *CustomExtensionConfig) Validate() error {
	if c.OID == "" {
		return fmt.Errorf("custom extension: OID is required")
	}

	if _, err := parseOID(c.OID); err != nil {
		return fmt.Errorf("custom extension: invalid OID %q: %w", c.OID, err)
	}

	if c.ValueHex != "" && c.ValueBase64 != "" {
		return fmt.Errorf("custom extension %s: cannot specify both value_hex and value_base64", c.OID)
	}

	if c.ValueHex != "" {
		if _, err := hex.DecodeString(c.ValueHex); err != nil {
			return fmt.Errorf("custom extension %s: invalid hex value: %w", c.OID, err)
		}
	}

	if c.ValueBase64 != "" {
		if _, err := base64.StdEncoding.DecodeString(c.ValueBase64); err != nil {
			return fmt.Errorf("custom extension %s: invalid base64 value: %w", c.OID, err)
		}
	}

	return nil
}

// Apply applies the extensions configuration to an x509.Certificate template.
// Extensions not specified in the config are left unchanged.
func (e *ExtensionsConfig) Apply(cert *x509.Certificate) error {
	if e == nil {
		return nil
	}

	if err := e.applyKeyUsage(cert); err != nil {
		return err
	}
	if err := e.applyExtKeyUsage(cert); err != nil {
		return err
	}
	e.applyBasicConstraints(cert)
	if err := e.applySAN(cert); err != nil {
		return err
	}
	e.applyCRLDistributionPoints(cert)
	e.applyAIA(cert)
	if err := e.applyCertificatePolicies(cert); err != nil {
		return err
	}
	if err := e.applyNameConstraints(cert); err != nil {
		return err
	}
	e.applyOCSPNoCheck(cert)
	if err := e.applyQCStatements(cert); err != nil {
		return err
	}
	if err := e.applyCustomExtensions(cert); err != nil {
		return err
	}

	return nil
}

// applyKeyUsage applies Key Usage extension to the certificate.
func (e *ExtensionsConfig) applyKeyUsage(cert *x509.Certificate) error {
	if e.KeyUsage == nil {
		return nil
	}
	usage, err := e.KeyUsage.ToKeyUsage()
	if err != nil {
		return fmt.Errorf("keyUsage: %w", err)
	}
	cert.KeyUsage = usage
	return nil
}

// applyExtKeyUsage applies Extended Key Usage extension to the certificate.
// RFC 3161 requires EKU to be critical for TSA certificates.
func (e *ExtensionsConfig) applyExtKeyUsage(cert *x509.Certificate) error {
	if e.ExtKeyUsage == nil {
		return nil
	}
	usages, customOIDs, err := e.ExtKeyUsage.ToExtKeyUsage()
	if err != nil {
		return fmt.Errorf("extKeyUsage: %w", err)
	}
	// Always set ExtKeyUsage for PQC path (buildEndEntityExtensions uses this)
	cert.ExtKeyUsage = usages
	cert.UnknownExtKeyUsage = customOIDs

	if e.ExtKeyUsage.IsCritical() {
		// For classical path (x509.CreateCertificate), also add to ExtraExtensions
		// with critical flag. This overrides the non-critical version from ExtKeyUsage.
		// (Go's x509.Certificate.ExtKeyUsage doesn't support critical flag)
		ext, err := encodeExtKeyUsage(usages, customOIDs, true)
		if err != nil {
			return fmt.Errorf("extKeyUsage encoding: %w", err)
		}
		cert.ExtraExtensions = append(cert.ExtraExtensions, ext)
	}
	return nil
}

// applyBasicConstraints applies Basic Constraints extension to the certificate.
func (e *ExtensionsConfig) applyBasicConstraints(cert *x509.Certificate) {
	if e.BasicConstraints == nil {
		return
	}
	cert.IsCA = e.BasicConstraints.CA
	cert.BasicConstraintsValid = true
	if e.BasicConstraints.PathLen != nil {
		cert.MaxPathLen = *e.BasicConstraints.PathLen
		cert.MaxPathLenZero = (*e.BasicConstraints.PathLen == 0)
	} else if !e.BasicConstraints.CA {
		cert.MaxPathLen = -1
	}
}

// applySAN applies Subject Alternative Name extension to the certificate.
func (e *ExtensionsConfig) applySAN(cert *x509.Certificate) error {
	if e.SubjectAltName == nil {
		return nil
	}
	cert.DNSNames = append(cert.DNSNames, e.SubjectAltName.DNS...)
	cert.EmailAddresses = append(cert.EmailAddresses, e.SubjectAltName.Email...)
	if err := e.applySANIPs(cert); err != nil {
		return err
	}
	return e.applySANURIs(cert)
}

// applySANIPs applies IP addresses from SAN config to the certificate.
func (e *ExtensionsConfig) applySANIPs(cert *x509.Certificate) error {
	for _, ipStr := range e.SubjectAltName.IP {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return fmt.Errorf("invalid IP address in SAN: %s", ipStr)
		}
		cert.IPAddresses = append(cert.IPAddresses, ip)
	}
	return nil
}

// applySANURIs applies URIs from SAN config to the certificate.
func (e *ExtensionsConfig) applySANURIs(cert *x509.Certificate) error {
	for _, uriStr := range e.SubjectAltName.URI {
		u, err := url.Parse(uriStr)
		if err != nil {
			return fmt.Errorf("invalid URI in SAN: %s: %w", uriStr, err)
		}
		if u.Scheme == "" {
			return fmt.Errorf("URI in SAN must have a scheme: %s", uriStr)
		}
		cert.URIs = append(cert.URIs, u)
	}
	return nil
}

// applyCRLDistributionPoints applies CRL Distribution Points to the certificate.
func (e *ExtensionsConfig) applyCRLDistributionPoints(cert *x509.Certificate) {
	if e.CRLDistributionPoints != nil {
		cert.CRLDistributionPoints = e.CRLDistributionPoints.URLs
	}
}

// applyAIA applies Authority Information Access extension to the certificate.
func (e *ExtensionsConfig) applyAIA(cert *x509.Certificate) {
	if e.AuthorityInfoAccess != nil {
		cert.OCSPServer = e.AuthorityInfoAccess.OCSP
		cert.IssuingCertificateURL = e.AuthorityInfoAccess.CAIssuers
	}
}

// applyCertificatePolicies applies Certificate Policies extension to the certificate.
func (e *ExtensionsConfig) applyCertificatePolicies(cert *x509.Certificate) error {
	if e.CertificatePolicies == nil || len(e.CertificatePolicies.Policies) == 0 {
		return nil
	}
	ext, err := encodeCertificatePolicies(e.CertificatePolicies)
	if err != nil {
		return fmt.Errorf("certificatePolicies: %w", err)
	}
	cert.ExtraExtensions = append(cert.ExtraExtensions, ext)
	return nil
}

// applyNameConstraints applies Name Constraints extension to the certificate.
func (e *ExtensionsConfig) applyNameConstraints(cert *x509.Certificate) error {
	if e.NameConstraints == nil {
		return nil
	}
	cert.PermittedDNSDomainsCritical = e.NameConstraints.IsCritical()
	if err := e.applyPermittedConstraints(cert); err != nil {
		return err
	}
	return e.applyExcludedConstraints(cert)
}

// applyPermittedConstraints applies permitted name constraints to the certificate.
func (e *ExtensionsConfig) applyPermittedConstraints(cert *x509.Certificate) error {
	if e.NameConstraints.Permitted == nil {
		return nil
	}
	cert.PermittedDNSDomains = e.NameConstraints.Permitted.DNS
	cert.PermittedEmailAddresses = e.NameConstraints.Permitted.Email
	for _, cidr := range e.NameConstraints.Permitted.IP {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("invalid permitted IP CIDR: %s", cidr)
		}
		cert.PermittedIPRanges = append(cert.PermittedIPRanges, ipNet)
	}
	return nil
}

// applyExcludedConstraints applies excluded name constraints to the certificate.
func (e *ExtensionsConfig) applyExcludedConstraints(cert *x509.Certificate) error {
	if e.NameConstraints.Excluded == nil {
		return nil
	}
	cert.ExcludedDNSDomains = e.NameConstraints.Excluded.DNS
	cert.ExcludedEmailAddresses = e.NameConstraints.Excluded.Email
	for _, cidr := range e.NameConstraints.Excluded.IP {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("invalid excluded IP CIDR: %s", cidr)
		}
		cert.ExcludedIPRanges = append(cert.ExcludedIPRanges, ipNet)
	}
	return nil
}

// applyOCSPNoCheck applies OCSP No Check extension to the certificate.
func (e *ExtensionsConfig) applyOCSPNoCheck(cert *x509.Certificate) {
	if e.OCSPNoCheck != nil {
		ext := encodeOCSPNoCheck(e.OCSPNoCheck)
		cert.ExtraExtensions = append(cert.ExtraExtensions, ext)
	}
}

// applyCustomExtensions applies custom X.509 extensions to the certificate.
func (e *ExtensionsConfig) applyCustomExtensions(cert *x509.Certificate) error {
	for i, custom := range e.Custom {
		ext, err := custom.ToExtension()
		if err != nil {
			return fmt.Errorf("custom extension %d: %w", i, err)
		}
		cert.ExtraExtensions = append(cert.ExtraExtensions, ext)
	}
	return nil
}

// applyQCStatements applies QCStatements extension to the certificate.
func (e *ExtensionsConfig) applyQCStatements(cert *x509.Certificate) error {
	if e.QCStatements == nil || !e.QCStatements.HasStatements() {
		return nil
	}
	ext, err := encodeQCStatements(e.QCStatements)
	if err != nil {
		return fmt.Errorf("qcStatements: %w", err)
	}
	cert.ExtraExtensions = append(cert.ExtraExtensions, ext)
	return nil
}

// Validate checks the logical consistency of extension configuration per RFC 5280.
// Returns an error if the configuration violates RFC 5280 requirements.
func (e *ExtensionsConfig) Validate() error {
	if e == nil {
		return nil
	}

	isCA := e.BasicConstraints != nil && e.BasicConstraints.CA

	validators := []func(bool) error{
		e.validateCAKeyUsage,
		e.validatePathLen,
		e.validateNameConstraintsForCA,
		e.validateBasicConstraintsCritical,
		e.validateNameConstraintsCritical,
		e.validateAIACritical,
	}

	for _, v := range validators {
		if err := v(isCA); err != nil {
			return err
		}
	}

	// Validate QCStatements
	if e.QCStatements != nil {
		if err := e.QCStatements.Validate(); err != nil {
			return err
		}
	}

	// Validate custom extensions
	for i, custom := range e.Custom {
		if err := custom.Validate(); err != nil {
			return fmt.Errorf("custom extension %d: %w", i, err)
		}
	}

	return nil
}

// validateCAKeyUsage checks RFC 5280 §4.2.1.9: CA=true requires keyCertSign in keyUsage.
func (e *ExtensionsConfig) validateCAKeyUsage(isCA bool) error {
	if !isCA {
		return nil
	}
	if e.KeyUsage == nil {
		return fmt.Errorf("CA certificates must have keyUsage extension (RFC 5280 §4.2.1.3)")
	}
	for _, v := range e.KeyUsage.Values {
		switch strings.ToLower(v) {
		case "certsign", "cert-sign", "keycertsign", "key-cert-sign":
			return nil
		}
	}
	return fmt.Errorf("CA certificates must have keyCertSign in keyUsage (RFC 5280 §4.2.1.9)")
}

// validatePathLen checks RFC 5280 §4.2.1.9: pathLen is only valid for CA certificates.
func (e *ExtensionsConfig) validatePathLen(isCA bool) error {
	if e.BasicConstraints != nil && e.BasicConstraints.PathLen != nil && !e.BasicConstraints.CA {
		return fmt.Errorf("pathLen is only valid for CA certificates (RFC 5280 §4.2.1.9)")
	}
	return nil
}

// validateNameConstraintsForCA checks RFC 5280 §4.2.1.10: NameConstraints is only valid for CA certificates.
func (e *ExtensionsConfig) validateNameConstraintsForCA(isCA bool) error {
	if e.NameConstraints == nil || isCA {
		return nil
	}
	if e.hasNameConstraints() {
		return fmt.Errorf("nameConstraints extension is only valid for CA certificates (RFC 5280 §4.2.1.10)")
	}
	return nil
}

// hasNameConstraints returns true if any name constraints are defined.
func (e *ExtensionsConfig) hasNameConstraints() bool {
	if e.NameConstraints.Permitted != nil {
		if len(e.NameConstraints.Permitted.DNS) > 0 ||
			len(e.NameConstraints.Permitted.Email) > 0 ||
			len(e.NameConstraints.Permitted.IP) > 0 {
			return true
		}
	}
	if e.NameConstraints.Excluded != nil {
		if len(e.NameConstraints.Excluded.DNS) > 0 ||
			len(e.NameConstraints.Excluded.Email) > 0 ||
			len(e.NameConstraints.Excluded.IP) > 0 {
			return true
		}
	}
	return false
}

// validateBasicConstraintsCritical checks RFC 5280 §4.2.1.9: BasicConstraints MUST be critical for CA.
func (e *ExtensionsConfig) validateBasicConstraintsCritical(isCA bool) error {
	if isCA && e.BasicConstraints.Critical != nil && !*e.BasicConstraints.Critical {
		return fmt.Errorf("basicConstraints MUST be critical for CA certificates (RFC 5280 §4.2.1.9)")
	}
	return nil
}

// validateNameConstraintsCritical checks RFC 5280 §4.2.1.10: NameConstraints MUST be critical.
func (e *ExtensionsConfig) validateNameConstraintsCritical(_ bool) error {
	if e.NameConstraints != nil && e.NameConstraints.Critical != nil && !*e.NameConstraints.Critical {
		return fmt.Errorf("nameConstraints MUST be critical (RFC 5280 §4.2.1.10)")
	}
	return nil
}

// validateAIACritical checks RFC 5280 §4.2.2.1: AuthorityInfoAccess MUST NOT be critical.
func (e *ExtensionsConfig) validateAIACritical(_ bool) error {
	if e.AuthorityInfoAccess != nil && e.AuthorityInfoAccess.Critical != nil && *e.AuthorityInfoAccess.Critical {
		return fmt.Errorf("authorityInfoAccess MUST NOT be critical (RFC 5280 §4.2.2.1)")
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

// userNotice represents RFC 5280 UserNotice structure
// UserNotice ::= SEQUENCE {
//
//	noticeRef        NoticeReference OPTIONAL,
//	explicitText     DisplayText OPTIONAL }
type userNotice struct {
	// NoticeRef is optional, we don't support it currently
	// explicitText is a DisplayText CHOICE, we use UTF8String
	ExplicitText string `asn1:"optional,utf8"`
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
			cpsBytes, err := asn1.Marshal(asn1.RawValue{Tag: asn1.TagIA5String, Bytes: []byte(p.CPS)})
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
			// RFC 5280: UserNotice is a SEQUENCE with optional explicitText
			notice := userNotice{
				ExplicitText: p.UserNotice,
			}
			noticeBytes, err := asn1.Marshal(notice)
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

// QCStatements OIDs (RFC 3739 / ETSI EN 319 412-5)
var (
	oidQCStatements      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 3}
	oidQcCompliance      = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 1}
	oidQcRetentionPeriod = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 3}
	oidQcSSCD            = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 4}
	oidQcPDS             = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 5}
	oidQcType            = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 6}
	oidQcTypeESign       = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 6, 1}
	oidQcTypeESeal       = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 6, 2}
	oidQcTypeWeb         = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 6, 3}
)

// qcStatement is the ASN.1 structure for a single QCStatement.
type qcStatement struct {
	StatementID   asn1.ObjectIdentifier
	StatementInfo asn1.RawValue `asn1:"optional"`
}

// pdsLocation is the ASN.1 structure for a PDS location entry.
type pdsLocation struct {
	URL      string `asn1:"ia5"`
	Language string `asn1:"printable"`
}

// encodeQCStatements encodes the QCStatements extension.
func encodeQCStatements(config *QCStatementsConfig) (pkix.Extension, error) {
	var statements []qcStatement

	// QcCompliance (0.4.0.1862.1.1) - no statementInfo
	if config.QcCompliance {
		statements = append(statements, qcStatement{
			StatementID: oidQcCompliance,
		})
	}

	// QcType (0.4.0.1862.1.6) - SEQUENCE OF OID
	if config.QcType != "" {
		var typeOID asn1.ObjectIdentifier
		switch config.QcType {
		case "esign":
			typeOID = oidQcTypeESign
		case "eseal":
			typeOID = oidQcTypeESeal
		case "web":
			typeOID = oidQcTypeWeb
		default:
			return pkix.Extension{}, fmt.Errorf("invalid QcType: %q", config.QcType)
		}

		typeOIDs := []asn1.ObjectIdentifier{typeOID}
		infoBytes, err := asn1.Marshal(typeOIDs)
		if err != nil {
			return pkix.Extension{}, fmt.Errorf("failed to marshal QcType: %w", err)
		}
		statements = append(statements, qcStatement{
			StatementID:   oidQcType,
			StatementInfo: asn1.RawValue{FullBytes: infoBytes},
		})
	}

	// QcSSCD (0.4.0.1862.1.4) - no statementInfo
	if config.QcSSCD {
		statements = append(statements, qcStatement{
			StatementID: oidQcSSCD,
		})
	}

	// QcRetentionPeriod (0.4.0.1862.1.3) - INTEGER (years)
	if config.QcRetentionPeriod != nil {
		infoBytes, err := asn1.Marshal(*config.QcRetentionPeriod)
		if err != nil {
			return pkix.Extension{}, fmt.Errorf("failed to marshal QcRetentionPeriod: %w", err)
		}
		statements = append(statements, qcStatement{
			StatementID:   oidQcRetentionPeriod,
			StatementInfo: asn1.RawValue{FullBytes: infoBytes},
		})
	}

	// QcPDS (0.4.0.1862.1.5) - SEQUENCE OF PDSLocation
	// Filter out entries containing template variables (they'll be resolved at runtime)
	if len(config.QcPDS) > 0 {
		var pdsLocations []pdsLocation
		for _, pds := range config.QcPDS {
			// Skip entries with template variables
			if containsTemplateVar(pds.URL) || containsTemplateVar(pds.Language) {
				continue
			}
			pdsLocations = append(pdsLocations, pdsLocation(pds))
		}
		// Only add QcPDS statement if there are non-template entries
		if len(pdsLocations) > 0 {
			infoBytes, err := asn1.Marshal(pdsLocations)
			if err != nil {
				return pkix.Extension{}, fmt.Errorf("failed to marshal QcPDS: %w", err)
			}
			statements = append(statements, qcStatement{
				StatementID:   oidQcPDS,
				StatementInfo: asn1.RawValue{FullBytes: infoBytes},
			})
		}
	}

	// Marshal the QCStatements sequence
	value, err := asn1.Marshal(statements)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("failed to marshal QCStatements: %w", err)
	}

	return pkix.Extension{
		Id:       oidQCStatements,
		Critical: config.IsCritical(),
		Value:    value,
	}, nil
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
func encodeExtKeyUsage(usages []x509.ExtKeyUsage, customOIDs []asn1.ObjectIdentifier, critical bool) (pkix.Extension, error) {
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

	// Append custom OIDs
	oids = append(oids, customOIDs...)

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

	// Copy QCStatements
	if e.QCStatements != nil {
		result.QCStatements = &QCStatementsConfig{
			Critical:          copyBoolPtr(e.QCStatements.Critical),
			QcCompliance:      e.QCStatements.QcCompliance,
			QcType:            e.QCStatements.QcType,
			QcSSCD:            e.QCStatements.QcSSCD,
			QcRetentionPeriod: copyIntPtr(e.QCStatements.QcRetentionPeriod),
		}
		if len(e.QCStatements.QcPDS) > 0 {
			result.QCStatements.QcPDS = make([]PDSLocationConfig, len(e.QCStatements.QcPDS))
			copy(result.QCStatements.QcPDS, e.QCStatements.QcPDS)
		}
	}

	// Copy Custom extensions
	if len(e.Custom) > 0 {
		result.Custom = make([]CustomExtensionConfig, len(e.Custom))
		copy(result.Custom, e.Custom)
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

	// Substitute variables in CRL Distribution Points
	if result.CRLDistributionPoints != nil {
		result.CRLDistributionPoints.URLs = substituteStringSlice(result.CRLDistributionPoints.URLs, vars)
	}

	// Substitute variables in Authority Info Access
	if result.AuthorityInfoAccess != nil {
		result.AuthorityInfoAccess.CAIssuers = substituteStringSlice(result.AuthorityInfoAccess.CAIssuers, vars)
		result.AuthorityInfoAccess.OCSP = substituteStringSlice(result.AuthorityInfoAccess.OCSP, vars)
	}

	// Substitute variables in Certificate Policies
	if result.CertificatePolicies != nil {
		for i, policy := range result.CertificatePolicies.Policies {
			if policy.CPS != "" {
				result.CertificatePolicies.Policies[i].CPS = substituteString(policy.CPS, vars)
			}
		}
	}

	// Substitute variables in QCStatements
	if result.QCStatements != nil && len(result.QCStatements.QcPDS) > 0 {
		for i, pds := range result.QCStatements.QcPDS {
			result.QCStatements.QcPDS[i].URL = substituteString(pds.URL, vars)
			result.QCStatements.QcPDS[i].Language = substituteString(pds.Language, vars)
		}
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

// substituteString replaces a single template variable in a string.
// If the string is a {{ variable }} pattern, returns the first value from vars.
// Otherwise returns the original string unchanged.
func substituteString(s string, vars map[string][]string) string {
	if matches := sanVarPattern.FindStringSubmatch(strings.TrimSpace(s)); len(matches) == 2 {
		varName := matches[1]
		if substitutes, ok := vars[varName]; ok && len(substitutes) > 0 {
			return substitutes[0]
		}
		// If not provided, return empty string (variable not resolved)
		return ""
	}
	// Static value, keep as-is
	return s
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
