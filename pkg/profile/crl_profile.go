// Package profile provides certificate and CRL profile management.
package profile

import (
	"time"
)

// CRLProfile defines the configuration for CRL generation.
// Automatic fields (not configurable):
//   - issuer: DN of the CA
//   - thisUpdate: current time
//   - nextUpdate: thisUpdate + validity
//   - crlNumber: auto-incremented
//   - authorityKeyIdentifier: derived from CA's SKI
//   - signature: uses CA's algorithm
type CRLProfile struct {
	Name        string               `yaml:"name"`
	Description string               `yaml:"description"`
	Validity    time.Duration        `yaml:"validity"`
	Extensions  *CRLExtensionsConfig `yaml:"extensions,omitempty"`
}

// CRLExtensionsConfig holds configurable CRL extensions.
type CRLExtensionsConfig struct {
	// IssuingDistributionPoint identifies the CRL distribution point.
	// RFC 5280: This extension is critical.
	IssuingDistributionPoint *IssuingDistributionPointConfig `yaml:"issuingDistributionPoint,omitempty"`

	// DeltaCRLIndicator is used for delta CRLs only.
	// RFC 5280: This extension MUST be critical.
	DeltaCRLIndicator *DeltaCRLIndicatorConfig `yaml:"deltaCRLIndicator,omitempty"`
}

// IssuingDistributionPointConfig configures the Issuing Distribution Point extension.
// OID: 2.5.29.28
// RFC 5280: This extension is critical.
type IssuingDistributionPointConfig struct {
	Critical *bool `yaml:"critical,omitempty"` // default: true (RFC 5280)

	// FullName is the URI of this CRL distribution point.
	FullName string `yaml:"fullName,omitempty"`

	// OnlyContainsUserCerts indicates the CRL only contains end-entity certificates.
	OnlyContainsUserCerts bool `yaml:"onlyContainsUserCerts,omitempty"`

	// OnlyContainsCACerts indicates the CRL only contains CA certificates.
	OnlyContainsCACerts bool `yaml:"onlyContainsCACerts,omitempty"`

	// OnlyContainsAttributeCerts indicates the CRL only contains attribute certificates.
	OnlyContainsAttributeCerts bool `yaml:"onlyContainsAttributeCerts,omitempty"`

	// IndirectCRL indicates this is an indirect CRL.
	IndirectCRL bool `yaml:"indirectCRL,omitempty"`
}

// IsCritical returns true if the extension should be marked critical.
// Default: true per RFC 5280.
func (c *IssuingDistributionPointConfig) IsCritical() bool {
	if c.Critical == nil {
		return true // RFC 5280 default
	}
	return *c.Critical
}

// DeltaCRLIndicatorConfig configures the Delta CRL Indicator extension.
// OID: 2.5.29.27
// RFC 5280: This extension MUST be critical.
type DeltaCRLIndicatorConfig struct {
	Critical *bool `yaml:"critical,omitempty"` // default: true (RFC 5280 MUST)

	// BaseCRLNumber is the CRL number of the base CRL.
	BaseCRLNumber int64 `yaml:"baseCRLNumber"`
}

// IsCritical returns true if the extension should be marked critical.
// Default: true per RFC 5280 (MUST be critical).
func (c *DeltaCRLIndicatorConfig) IsCritical() bool {
	if c.Critical == nil {
		return true // RFC 5280: MUST be critical
	}
	return *c.Critical
}

// DefaultCRLProfile returns a default CRL profile.
func DefaultCRLProfile() *CRLProfile {
	return &CRLProfile{
		Name:        "default",
		Description: "Default CRL profile",
		Validity:    7 * 24 * time.Hour, // 7 days
	}
}

// CRLProfileStore manages CRL profiles.
type CRLProfileStore struct {
	profiles map[string]*CRLProfile
}

// NewCRLProfileStore creates a new CRL profile store.
func NewCRLProfileStore() *CRLProfileStore {
	return &CRLProfileStore{
		profiles: make(map[string]*CRLProfile),
	}
}

// Add adds a CRL profile to the store.
func (s *CRLProfileStore) Add(profile *CRLProfile) {
	s.profiles[profile.Name] = profile
}

// Get retrieves a CRL profile by name.
func (s *CRLProfileStore) Get(name string) (*CRLProfile, bool) {
	p, ok := s.profiles[name]
	return p, ok
}

// GetOrDefault retrieves a CRL profile by name, or returns the default profile.
func (s *CRLProfileStore) GetOrDefault(name string) *CRLProfile {
	if p, ok := s.profiles[name]; ok {
		return p
	}
	return DefaultCRLProfile()
}

// List returns all profile names.
func (s *CRLProfileStore) List() []string {
	names := make([]string, 0, len(s.profiles))
	for name := range s.profiles {
		names = append(names, name)
	}
	return names
}
