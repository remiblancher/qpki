package ca

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"time"

	"github.com/remiblancher/qpki/pkg/profile"
)

// =============================================================================
// Test Helpers (shared across test files)
// =============================================================================

// tlsServerExtensions returns common TLS server extensions for testing
func tlsServerExtensions() *profile.ExtensionsConfig {
	criticalTrue := true
	criticalFalse := false
	return &profile.ExtensionsConfig{
		KeyUsage: &profile.KeyUsageConfig{
			Critical: &criticalTrue,
			Values:   []string{"digitalSignature", "keyEncipherment"},
		},
		ExtKeyUsage: &profile.ExtKeyUsageConfig{
			Critical: &criticalFalse,
			Values:   []string{"serverAuth"},
		},
		BasicConstraints: &profile.BasicConstraintsConfig{
			Critical: &criticalTrue,
			CA:       false,
		},
	}
}

// issueTLSServerCert is a helper for tests to issue TLS server certificates
func issueTLSServerCert(ca *CA, cn string, dnsNames []string, pubKey interface{}) (*x509.Certificate, error) {
	template := &x509.Certificate{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: dnsNames,
	}
	return ca.Issue(context.Background(), IssueRequest{
		Template:   template,
		PublicKey:  pubKey,
		Extensions: tlsServerExtensions(),
		Validity:   365 * 24 * time.Hour,
	})
}
