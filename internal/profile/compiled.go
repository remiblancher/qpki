// Package profile provides compiled certificate profiles optimized for high-throughput.
package profile

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

// CompiledProfile is a pre-parsed, immutable profile optimized for high-throughput.
// All expensive parsing (KeyUsage strings, CIDR blocks, etc.) is done once at load time.
// The hot path (ApplyToTemplate) only does shallow copies and slice appends.
type CompiledProfile struct {
	*Profile

	// Pre-parsed extensions (computed once at load time)
	keyUsage    x509.KeyUsage
	extKeyUsage []x509.ExtKeyUsage

	// Pre-parsed basic constraints
	isCA                  bool
	maxPathLen            int
	maxPathLenZero        bool
	basicConstraintsValid bool

	// Pre-parsed name constraints
	permittedDNSDomains     []string
	permittedEmailAddresses []string
	permittedIPRanges       []*net.IPNet
	excludedDNSDomains      []string
	excludedEmailAddresses  []string
	excludedIPRanges        []*net.IPNet

	// Pre-parsed SANs from profile (fixed SANs defined in profile)
	fixedDNSNames []string
	fixedIPs      []net.IP
	fixedEmails   []string
	fixedURIs     []*url.URL

	// Pre-parsed AIA and CDP
	ocspServers           []string
	issuingCertificateURL []string
	crlDistributionPoints []string

	// Pre-built extra extensions (CertificatePolicies, OCSPNoCheck)
	extraExtensions []pkix.Extension
}

// Compile transforms a Profile into a CompiledProfile.
// All parsing happens here, not at certificate creation time.
// This should be called once at startup for each profile.
func (p *Profile) Compile() (*CompiledProfile, error) {
	cp := &CompiledProfile{Profile: p}

	if p.Extensions == nil {
		return cp, nil
	}

	// Pre-parse KeyUsage
	if p.Extensions.KeyUsage != nil {
		ku, err := p.Extensions.KeyUsage.ToKeyUsage()
		if err != nil {
			return nil, fmt.Errorf("compile keyUsage: %w", err)
		}
		cp.keyUsage = ku
	}

	// Pre-parse ExtKeyUsage
	if p.Extensions.ExtKeyUsage != nil {
		eku, err := p.Extensions.ExtKeyUsage.ToExtKeyUsage()
		if err != nil {
			return nil, fmt.Errorf("compile extKeyUsage: %w", err)
		}
		cp.extKeyUsage = eku
	}

	// Pre-parse BasicConstraints
	if p.Extensions.BasicConstraints != nil {
		cp.isCA = p.Extensions.BasicConstraints.CA
		cp.basicConstraintsValid = true
		if p.Extensions.BasicConstraints.PathLen != nil {
			cp.maxPathLen = *p.Extensions.BasicConstraints.PathLen
			cp.maxPathLenZero = (*p.Extensions.BasicConstraints.PathLen == 0)
		} else if !cp.isCA {
			cp.maxPathLen = -1
		}
	}

	// Pre-parse NameConstraints (expensive CIDR parsing)
	if err := cp.compileNameConstraints(); err != nil {
		return nil, err
	}

	// Pre-parse SubjectAltName (fixed SANs from profile)
	if err := cp.compileSANs(); err != nil {
		return nil, err
	}

	// Pre-parse AIA
	if p.Extensions.AuthorityInfoAccess != nil {
		cp.ocspServers = p.Extensions.AuthorityInfoAccess.OCSP
		cp.issuingCertificateURL = p.Extensions.AuthorityInfoAccess.CAIssuers
	}

	// Pre-parse CDP
	if p.Extensions.CRLDistributionPoints != nil {
		cp.crlDistributionPoints = p.Extensions.CRLDistributionPoints.URLs
	}

	// Pre-build extra extensions (CertificatePolicies, OCSPNoCheck)
	if err := cp.compileExtraExtensions(); err != nil {
		return nil, err
	}

	return cp, nil
}

// compileNameConstraints pre-parses CIDR blocks for name constraints.
func (cp *CompiledProfile) compileNameConstraints() error {
	ext := cp.Extensions
	if ext == nil || ext.NameConstraints == nil {
		return nil
	}

	nc := ext.NameConstraints

	// Permitted subtrees
	if nc.Permitted != nil {
		cp.permittedDNSDomains = nc.Permitted.DNS
		cp.permittedEmailAddresses = nc.Permitted.Email

		for _, cidr := range nc.Permitted.IP {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				return fmt.Errorf("compile permitted IP CIDR %q: %w", cidr, err)
			}
			cp.permittedIPRanges = append(cp.permittedIPRanges, ipNet)
		}
	}

	// Excluded subtrees
	if nc.Excluded != nil {
		cp.excludedDNSDomains = nc.Excluded.DNS
		cp.excludedEmailAddresses = nc.Excluded.Email

		for _, cidr := range nc.Excluded.IP {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				return fmt.Errorf("compile excluded IP CIDR %q: %w", cidr, err)
			}
			cp.excludedIPRanges = append(cp.excludedIPRanges, ipNet)
		}
	}

	return nil
}

// compileSANs pre-parses fixed SANs from the profile.
// Template strings ({{ variable }}) are skipped and resolved at enrollment time.
func (cp *CompiledProfile) compileSANs() error {
	ext := cp.Extensions
	if ext == nil || ext.SubjectAltName == nil {
		return nil
	}

	san := ext.SubjectAltName

	// DNS names - filter out templates, keep static values
	for _, dns := range san.DNS {
		if !isTemplateVar(dns) {
			cp.fixedDNSNames = append(cp.fixedDNSNames, dns)
		}
	}

	// Email addresses - filter out templates
	for _, email := range san.Email {
		if !isTemplateVar(email) {
			cp.fixedEmails = append(cp.fixedEmails, email)
		}
	}

	// IP addresses - filter out templates, parse static IPs
	for _, ipStr := range san.IP {
		if isTemplateVar(ipStr) {
			continue // Skip templates
		}
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return fmt.Errorf("compile SAN IP %q: invalid IP address", ipStr)
		}
		cp.fixedIPs = append(cp.fixedIPs, ip)
	}

	// URIs - filter out templates, parse static URIs
	for _, uriStr := range san.URI {
		if isTemplateVar(uriStr) {
			continue // Skip templates
		}
		u, err := url.Parse(uriStr)
		if err != nil {
			return fmt.Errorf("compile SAN URI %q: %w", uriStr, err)
		}
		cp.fixedURIs = append(cp.fixedURIs, u)
	}

	return nil
}

// isTemplateVar returns true if the string is a template variable like {{ name }}.
func isTemplateVar(s string) bool {
	s = strings.TrimSpace(s)
	return strings.HasPrefix(s, "{{") && strings.HasSuffix(s, "}}")
}

// compileExtraExtensions pre-builds CertificatePolicies and OCSPNoCheck extensions.
func (cp *CompiledProfile) compileExtraExtensions() error {
	ext := cp.Extensions
	if ext == nil {
		return nil
	}

	// Certificate Policies
	if ext.CertificatePolicies != nil && len(ext.CertificatePolicies.Policies) > 0 {
		policyExt, err := encodeCertificatePolicies(ext.CertificatePolicies)
		if err != nil {
			return fmt.Errorf("compile certificatePolicies: %w", err)
		}
		cp.extraExtensions = append(cp.extraExtensions, policyExt)
	}

	// OCSP No Check
	if ext.OCSPNoCheck != nil {
		ocspExt := encodeOCSPNoCheck(ext.OCSPNoCheck)
		cp.extraExtensions = append(cp.extraExtensions, ocspExt)
	}

	return nil
}

// ApplyToTemplate creates a certificate template by merging the pre-compiled
// profile data with user-provided data. This is the hot path - it avoids
// any parsing or expensive operations.
//
// The returned template is ready for x509.CreateCertificate().
func (cp *CompiledProfile) ApplyToTemplate(
	subject pkix.Name,
	dnsNames []string,
	ips []net.IP,
	emails []string,
) *x509.Certificate {
	// Start with pre-computed values
	tmpl := &x509.Certificate{
		// Extensions from profile (pre-parsed)
		KeyUsage:    cp.keyUsage,
		ExtKeyUsage: cp.extKeyUsage,

		// Basic constraints (pre-parsed)
		IsCA:                  cp.isCA,
		MaxPathLen:            cp.maxPathLen,
		MaxPathLenZero:        cp.maxPathLenZero,
		BasicConstraintsValid: cp.basicConstraintsValid,

		// Name constraints (pre-parsed)
		PermittedDNSDomains:     cp.permittedDNSDomains,
		PermittedEmailAddresses: cp.permittedEmailAddresses,
		PermittedIPRanges:       cp.permittedIPRanges,
		ExcludedDNSDomains:      cp.excludedDNSDomains,
		ExcludedEmailAddresses:  cp.excludedEmailAddresses,
		ExcludedIPRanges:        cp.excludedIPRanges,

		// AIA and CDP (pre-stored)
		OCSPServer:            cp.ocspServers,
		IssuingCertificateURL: cp.issuingCertificateURL,
		CRLDistributionPoints: cp.crlDistributionPoints,

		// Extra extensions (pre-built)
		ExtraExtensions: cp.extraExtensions,
	}

	// User-provided data
	tmpl.Subject = subject

	// Merge fixed SANs with user-provided SANs
	if len(cp.fixedDNSNames) > 0 || len(dnsNames) > 0 {
		tmpl.DNSNames = append(append([]string{}, cp.fixedDNSNames...), dnsNames...)
	}
	if len(cp.fixedIPs) > 0 || len(ips) > 0 {
		tmpl.IPAddresses = append(append([]net.IP{}, cp.fixedIPs...), ips...)
	}
	if len(cp.fixedEmails) > 0 || len(emails) > 0 {
		tmpl.EmailAddresses = append(append([]string{}, cp.fixedEmails...), emails...)
	}
	if len(cp.fixedURIs) > 0 {
		tmpl.URIs = cp.fixedURIs
	}

	return tmpl
}

// BuildTemplateWithValidity creates a complete certificate template including
// serial number, validity period, and all profile settings.
func (cp *CompiledProfile) BuildTemplateWithValidity(
	subject pkix.Name,
	dnsNames []string,
	ips []net.IP,
	emails []string,
	notBefore time.Time,
	serialNumber []byte,
) *x509.Certificate {
	tmpl := cp.ApplyToTemplate(subject, dnsNames, ips, emails)

	// Set validity
	tmpl.NotBefore = notBefore
	tmpl.NotAfter = notBefore.Add(cp.Validity)

	// Set serial number
	tmpl.SerialNumber = new(big.Int).SetBytes(serialNumber)

	return tmpl
}

// KeyUsage returns the pre-parsed key usage flags.
func (cp *CompiledProfile) KeyUsage() x509.KeyUsage {
	return cp.keyUsage
}

// ExtKeyUsage returns the pre-parsed extended key usage list.
func (cp *CompiledProfile) ExtKeyUsage() []x509.ExtKeyUsage {
	return cp.extKeyUsage
}

// IsCA returns whether this profile is for a CA certificate.
func (cp *CompiledProfile) IsCAProfile() bool {
	return cp.isCA
}

// CompiledStore provides thread-safe access to compiled profiles.
type CompiledStore interface {
	Load() error
	Get(name string) (*CompiledProfile, bool)
	List() []string
	All() map[string]*CompiledProfile
	Count() int
}

// FileCompiledStore implements CompiledStore using the filesystem.
type FileCompiledStore struct {
	mu       sync.RWMutex
	profiles map[string]*CompiledProfile
	basePath string
}

// Compile-time interface check.
var _ CompiledStore = (*FileCompiledStore)(nil)

// NewFileCompiledStore creates a new file-based compiled profile store.
func NewFileCompiledStore(caPath string) *FileCompiledStore {
	return &FileCompiledStore{
		profiles: make(map[string]*CompiledProfile),
		basePath: caPath,
	}
}

// NewCompiledProfileStore creates a new compiled profile store (alias for NewFileCompiledStore).
// Deprecated: Use NewFileCompiledStore for explicit type.
func NewCompiledProfileStore(caPath string) *FileCompiledStore {
	return NewFileCompiledStore(caPath)
}

// Load loads and compiles all profiles from builtin profiles and CA's profiles directory.
func (s *FileCompiledStore) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Load raw YAML profiles using existing ProfileStore
	rawStore := NewProfileStore(s.basePath)
	if err := rawStore.Load(); err != nil {
		return fmt.Errorf("load profiles: %w", err)
	}

	// Compile each profile
	s.profiles = make(map[string]*CompiledProfile, len(rawStore.profiles))
	for name, p := range rawStore.profiles {
		compiled, err := p.Compile()
		if err != nil {
			return fmt.Errorf("compile profile %s: %w", name, err)
		}
		s.profiles[name] = compiled
	}

	return nil
}

// Get returns a compiled profile by name (thread-safe).
func (s *FileCompiledStore) Get(name string) (*CompiledProfile, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.profiles[name]
	return p, ok
}

// List returns all compiled profile names.
func (s *FileCompiledStore) List() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	names := make([]string, 0, len(s.profiles))
	for name := range s.profiles {
		names = append(names, name)
	}
	return names
}

// All returns all compiled profiles.
func (s *FileCompiledStore) All() map[string]*CompiledProfile {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Return a copy to avoid race conditions
	result := make(map[string]*CompiledProfile, len(s.profiles))
	for k, v := range s.profiles {
		result[k] = v
	}
	return result
}

// Count returns the number of compiled profiles.
func (s *FileCompiledStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.profiles)
}
