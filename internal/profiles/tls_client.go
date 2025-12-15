package profiles

import (
	"crypto/x509"
	"time"
)

// TLSClientProfile is the profile for TLS client certificates.
type TLSClientProfile struct {
	BaseProfile
}

// NewTLSClientProfile creates a new TLS client profile.
func NewTLSClientProfile() *TLSClientProfile {
	return &TLSClientProfile{
		BaseProfile: BaseProfile{
			name:        "tls-client",
			description: "TLS client authentication certificate",
			keyUsage:    x509.KeyUsageDigitalSignature,
			extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			isCA:        false,
			maxPathLen:  -1,
			defaultValidity: 365 * 24 * time.Hour, // 1 year
		},
	}
}

func init() {
	Register(NewTLSClientProfile())
}
