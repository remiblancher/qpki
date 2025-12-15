package profiles

import (
	"crypto/x509"
	"fmt"
	"time"
)

// TLSServerProfile is the profile for TLS server certificates.
type TLSServerProfile struct {
	BaseProfile
}

// NewTLSServerProfile creates a new TLS server profile.
func NewTLSServerProfile() *TLSServerProfile {
	return &TLSServerProfile{
		BaseProfile: BaseProfile{
			name:        "tls-server",
			description: "TLS server authentication certificate",
			keyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			isCA:        false,
			maxPathLen:  -1,
			defaultValidity: 365 * 24 * time.Hour, // 1 year
		},
	}
}

// Validate validates the certificate for TLS server use.
func (p *TLSServerProfile) Validate(template *x509.Certificate) error {
	if err := p.BaseProfile.Validate(template); err != nil {
		return err
	}

	// TLS server certificates should have at least one SAN
	if len(template.DNSNames) == 0 && len(template.IPAddresses) == 0 {
		return fmt.Errorf("TLS server certificate must have at least one DNS or IP SAN")
	}

	return nil
}

func init() {
	Register(NewTLSServerProfile())
}
