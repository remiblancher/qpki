package ca

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/remiblancher/post-quantum-pki/internal/crypto"
	"github.com/remiblancher/post-quantum-pki/internal/profile"
)

// =============================================================================
// Catalyst Hybrid Certificate Functional Tests
// =============================================================================

func TestF_CatalystCertificateIssuanceAndVerification(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize Hybrid CA (ECDSA + ML-DSA)
	cfg := HybridCAConfig{
		CommonName:         "Catalyst Test CA",
		Organization:       "Test Org",
		Country:            "US",
		ClassicalAlgorithm: crypto.AlgECDSAP384,
		PQCAlgorithm:       crypto.AlgMLDSA87,
		ValidityYears:      10,
		PathLen:            1,
	}

	ca, err := InitializeHybridCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeHybridCA() error = %v", err)
	}

	// Generate keys for end-entity certificate
	classicalKP, err := crypto.GenerateKeyPair(crypto.AlgECDSAP256)
	if err != nil {
		t.Fatalf("GenerateKeyPair (classical) error = %v", err)
	}
	pqcKP, err := crypto.GenerateKeyPair(crypto.AlgMLDSA65)
	if err != nil {
		t.Fatalf("GenerateKeyPair (PQC) error = %v", err)
	}

	// Issue Catalyst certificate
	criticalTrue := true
	criticalFalse := false
	extensions := &profile.ExtensionsConfig{
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

	template := &x509.Certificate{
		Subject:  pkix.Name{CommonName: "catalyst.example.com"},
		DNSNames: []string{"catalyst.example.com"},
	}

	cert, err := ca.IssueCatalyst(context.Background(), CatalystRequest{
		Template:           template,
		ClassicalPublicKey: classicalKP.PublicKey,
		PQCPublicKey:       pqcKP.PublicKey,
		PQCAlgorithm:       crypto.AlgMLDSA65,
		Extensions:         extensions,
		Validity:           365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("IssueCatalyst() error = %v", err)
	}

	// Verify certificate has Catalyst extensions
	if cert == nil {
		t.Fatal("certificate should not be nil")
	}
	if cert.Subject.CommonName != "catalyst.example.com" {
		t.Errorf("Subject.CommonName = %v, want catalyst.example.com", cert.Subject.CommonName)
	}

	// Verify both signatures
	valid, err := VerifyCatalystSignatures(cert, ca.Certificate())
	if err != nil {
		t.Fatalf("VerifyCatalystSignatures() error = %v", err)
	}
	if !valid {
		t.Error("Catalyst certificate signatures should be valid")
	}

	// Verify classical signature also works with standard Go verification
	roots := x509.NewCertPool()
	roots.AddCert(ca.Certificate())
	opts := x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: time.Now(),
	}
	if _, err := cert.Verify(opts); err != nil {
		t.Errorf("Standard X.509 verification failed: %v", err)
	}
}
