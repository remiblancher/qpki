// Package profiles defines certificate profiles for common use cases.
// Profiles encapsulate the Key Usage, Extended Key Usage, and other
// settings appropriate for specific certificate types.
package profiles

import (
	"crypto/x509"
	"fmt"
	"time"
)

// Profile defines the interface for certificate profiles.
// A profile applies specific settings to a certificate template.
type Profile interface {
	// Name returns the profile name (e.g., "tls-server", "root-ca").
	Name() string

	// Description returns a human-readable description.
	Description() string

	// Apply applies the profile settings to a certificate template.
	Apply(template *x509.Certificate) error

	// Validate checks if the template is valid for this profile.
	Validate(template *x509.Certificate) error

	// DefaultValidity returns the default validity period for this profile.
	DefaultValidity() time.Duration
}

// Registry holds available profiles.
var registry = make(map[string]Profile)

// Register adds a profile to the registry.
func Register(p Profile) {
	registry[p.Name()] = p
}

// Get returns a profile by name.
func Get(name string) (Profile, error) {
	p, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("unknown profile: %s", name)
	}
	return p, nil
}

// List returns all registered profile names.
func List() []string {
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	return names
}

// All returns all registered profiles.
func All() []Profile {
	profiles := make([]Profile, 0, len(registry))
	for _, p := range registry {
		profiles = append(profiles, p)
	}
	return profiles
}

// BaseProfile provides common functionality for profiles.
type BaseProfile struct {
	name            string
	description     string
	keyUsage        x509.KeyUsage
	extKeyUsage     []x509.ExtKeyUsage
	isCA            bool
	maxPathLen      int
	defaultValidity time.Duration
}

// Name returns the profile name.
func (p *BaseProfile) Name() string {
	return p.name
}

// Description returns the profile description.
func (p *BaseProfile) Description() string {
	return p.description
}

// DefaultValidity returns the default validity period.
func (p *BaseProfile) DefaultValidity() time.Duration {
	return p.defaultValidity
}

// Apply applies the profile to a certificate template.
func (p *BaseProfile) Apply(template *x509.Certificate) error {
	template.KeyUsage = p.keyUsage
	template.ExtKeyUsage = p.extKeyUsage
	template.IsCA = p.isCA
	template.BasicConstraintsValid = true

	if p.isCA {
		template.MaxPathLen = p.maxPathLen
		template.MaxPathLenZero = (p.maxPathLen == 0)
	} else {
		template.MaxPathLen = -1
	}

	// Set default validity if not already set
	if template.NotBefore.IsZero() {
		template.NotBefore = time.Now()
	}
	if template.NotAfter.IsZero() {
		template.NotAfter = template.NotBefore.Add(p.defaultValidity)
	}

	return nil
}

// Validate validates the certificate template for this profile.
func (p *BaseProfile) Validate(template *x509.Certificate) error {
	if template.Subject.CommonName == "" && len(template.DNSNames) == 0 {
		return fmt.Errorf("certificate must have a CommonName or at least one DNS SAN")
	}

	if template.NotBefore.After(template.NotAfter) {
		return fmt.Errorf("NotBefore must be before NotAfter")
	}

	return nil
}
