package profiles

import (
	"crypto/x509"
	"testing"
	"time"
)

func TestTLSServerProfile(t *testing.T) {
	profile := NewTLSServerProfile()

	if profile.Name() != "tls-server" {
		t.Errorf("Name() = %v, want tls-server", profile.Name())
	}

	cert := &x509.Certificate{}
	if err := profile.Apply(cert); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	if cert.IsCA {
		t.Error("TLS server should not be CA")
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("should have DigitalSignature key usage")
	}
	if cert.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
		t.Error("should have KeyEncipherment key usage")
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Error("should have only ServerAuth extended key usage")
	}

	// Validate should fail without DNS names
	if err := profile.Validate(cert); err == nil {
		t.Error("should fail validation without DNS names or IP addresses")
	}

	// Validate should pass with DNS name
	cert.DNSNames = []string{"example.com"}
	if err := profile.Validate(cert); err != nil {
		t.Errorf("unexpected validation error: %v", err)
	}

	// Check default validity
	if profile.DefaultValidity() != 365*24*time.Hour {
		t.Errorf("DefaultValidity() = %v, want 1 year", profile.DefaultValidity())
	}
}

func TestTLSClientProfile(t *testing.T) {
	profile := NewTLSClientProfile()

	if profile.Name() != "tls-client" {
		t.Errorf("Name() = %v, want tls-client", profile.Name())
	}

	cert := &x509.Certificate{}
	if err := profile.Apply(cert); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	if cert.IsCA {
		t.Error("TLS client should not be CA")
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("should have DigitalSignature key usage")
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Error("should have only ClientAuth extended key usage")
	}

	// Validate should fail without CommonName or DNSNames
	if err := profile.Validate(cert); err == nil {
		t.Error("should fail validation without CommonName or DNSNames")
	}

	// Validate should pass with CommonName
	cert.Subject.CommonName = "test-client"
	if err := profile.Validate(cert); err != nil {
		t.Errorf("unexpected validation error: %v", err)
	}
}

func TestRootCAProfile(t *testing.T) {
	profile := NewRootCAProfile()

	if profile.Name() != "root-ca" {
		t.Errorf("Name() = %v, want root-ca", profile.Name())
	}

	cert := &x509.Certificate{}
	if err := profile.Apply(cert); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	if !cert.IsCA {
		t.Error("Root CA should be CA")
	}
	if cert.MaxPathLen != 1 {
		t.Errorf("MaxPathLen = %d, want 1", cert.MaxPathLen)
	}
	if cert.MaxPathLenZero {
		t.Error("MaxPathLenZero should be false (maxPathLen is 1, not 0)")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("should have CertSign key usage")
	}
	if cert.KeyUsage&x509.KeyUsageCRLSign == 0 {
		t.Error("should have CRLSign key usage")
	}
	if !cert.BasicConstraintsValid {
		t.Error("BasicConstraintsValid should be true")
	}

	// Validate should fail without CommonName
	if err := profile.Validate(cert); err == nil {
		t.Error("should fail validation without CommonName")
	}

	// Validate should pass with CommonName
	cert.Subject.CommonName = "Test Root CA"
	if err := profile.Validate(cert); err != nil {
		t.Errorf("unexpected validation error: %v", err)
	}

	// Check default validity
	if profile.DefaultValidity() != 10*365*24*time.Hour {
		t.Errorf("DefaultValidity() = %v, want 10 years", profile.DefaultValidity())
	}
}

func TestIssuingCAProfile(t *testing.T) {
	profile := NewIssuingCAProfile()

	if profile.Name() != "issuing-ca" {
		t.Errorf("Name() = %v, want issuing-ca", profile.Name())
	}

	cert := &x509.Certificate{}
	if err := profile.Apply(cert); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	if !cert.IsCA {
		t.Error("Issuing CA should be CA")
	}
	if cert.MaxPathLen != 0 {
		t.Errorf("MaxPathLen = %d, want 0", cert.MaxPathLen)
	}
	if !cert.MaxPathLenZero {
		t.Error("MaxPathLenZero should be true")
	}

	// Check default validity
	if profile.DefaultValidity() != 5*365*24*time.Hour {
		t.Errorf("DefaultValidity() = %v, want 5 years", profile.DefaultValidity())
	}
}

func TestProfileRegistry(t *testing.T) {
	// Clear registry
	registry = make(map[string]Profile)

	// Create and register profiles
	tlsServer := NewTLSServerProfile()
	Register(tlsServer)

	// Get profile
	got, err := Get("tls-server")
	if err != nil {
		t.Fatalf("tls-server profile not found: %v", err)
	}
	if got.Name() != tlsServer.Name() {
		t.Errorf("got different profile: %v", got.Name())
	}

	// List profiles
	list := List()
	if len(list) != 1 {
		t.Errorf("List() returned %d profiles, want 1", len(list))
	}

	// Register all standard profiles
	Register(NewTLSClientProfile())
	Register(NewRootCAProfile())
	Register(NewIssuingCAProfile())

	list = List()
	if len(list) != 4 {
		t.Errorf("List() returned %d profiles, want 4", len(list))
	}

	// Unknown profile
	_, err = Get("unknown")
	if err == nil {
		t.Error("should return error for unknown profile")
	}
}
