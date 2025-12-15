package profiles

import (
	"crypto/x509"
	"fmt"
	"time"
)

// RootCAProfile is the profile for root CA certificates.
type RootCAProfile struct {
	BaseProfile
}

// NewRootCAProfile creates a new root CA profile.
func NewRootCAProfile() *RootCAProfile {
	return &RootCAProfile{
		BaseProfile: BaseProfile{
			name:        "root-ca",
			description: "Root Certificate Authority",
			keyUsage:    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			extKeyUsage: nil, // CAs typically don't have EKU
			isCA:        true,
			maxPathLen:  1, // Allow one level of subordinate CAs
			defaultValidity: 10 * 365 * 24 * time.Hour, // 10 years
		},
	}
}

// Validate validates the certificate for root CA use.
func (p *RootCAProfile) Validate(template *x509.Certificate) error {
	if template.Subject.CommonName == "" {
		return fmt.Errorf("root CA certificate must have a CommonName")
	}
	return nil
}

// IssuingCAProfile is the profile for intermediate/issuing CA certificates.
type IssuingCAProfile struct {
	BaseProfile
}

// NewIssuingCAProfile creates a new issuing CA profile.
func NewIssuingCAProfile() *IssuingCAProfile {
	return &IssuingCAProfile{
		BaseProfile: BaseProfile{
			name:        "issuing-ca",
			description: "Issuing (Intermediate) Certificate Authority",
			keyUsage:    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			extKeyUsage: nil,
			isCA:        true,
			maxPathLen:  0, // Cannot issue subordinate CAs
			defaultValidity: 5 * 365 * 24 * time.Hour, // 5 years
		},
	}
}

// Validate validates the certificate for issuing CA use.
func (p *IssuingCAProfile) Validate(template *x509.Certificate) error {
	if template.Subject.CommonName == "" {
		return fmt.Errorf("issuing CA certificate must have a CommonName")
	}
	return nil
}

func init() {
	Register(NewRootCAProfile())
	Register(NewIssuingCAProfile())
}
