package ca

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/remiblancher/post-quantum-pki/pkg/crypto"
	"github.com/remiblancher/post-quantum-pki/pkg/profile"
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

// =============================================================================
// IssueCatalyst Error Path Tests
// =============================================================================

func TestF_IssueCatalyst_NoSigner(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize Hybrid CA with passphrase
	cfg := HybridCAConfig{
		CommonName:         "Catalyst Test CA",
		ClassicalAlgorithm: crypto.AlgECDSAP384,
		PQCAlgorithm:       crypto.AlgMLDSA87,
		ValidityYears:      10,
		PathLen:            1,
		Passphrase:         "test",
	}

	_, err := InitializeHybridCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeHybridCA() error = %v", err)
	}

	// Load CA without signer
	ca, err := New(store)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	classicalKP, _ := crypto.GenerateKeyPair(crypto.AlgECDSAP256)
	pqcKP, _ := crypto.GenerateKeyPair(crypto.AlgMLDSA65)

	// Try to issue without signer loaded
	_, err = ca.IssueCatalyst(context.Background(), CatalystRequest{
		ClassicalPublicKey: classicalKP.PublicKey,
		PQCPublicKey:       pqcKP.PublicKey,
		PQCAlgorithm:       crypto.AlgMLDSA65,
	})
	if err == nil {
		t.Error("IssueCatalyst() should fail when signer not loaded")
	}
}

func TestF_IssueCatalyst_NonHybridSigner(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize classical CA (not hybrid)
	cfg := Config{
		CommonName:    "Classical CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	classicalKP, _ := crypto.GenerateKeyPair(crypto.AlgECDSAP256)
	pqcKP, _ := crypto.GenerateKeyPair(crypto.AlgMLDSA65)

	// Try to issue Catalyst with non-hybrid CA
	_, err = ca.IssueCatalyst(context.Background(), CatalystRequest{
		ClassicalPublicKey: classicalKP.PublicKey,
		PQCPublicKey:       pqcKP.PublicKey,
		PQCAlgorithm:       crypto.AlgMLDSA65,
	})
	if err == nil {
		t.Error("IssueCatalyst() should fail with non-hybrid signer")
	}
}

func TestF_IssueCatalyst_NilTemplate(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := HybridCAConfig{
		CommonName:         "Catalyst Test CA",
		ClassicalAlgorithm: crypto.AlgECDSAP384,
		PQCAlgorithm:       crypto.AlgMLDSA87,
		ValidityYears:      10,
		PathLen:            1,
	}

	ca, err := InitializeHybridCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeHybridCA() error = %v", err)
	}

	classicalKP, _ := crypto.GenerateKeyPair(crypto.AlgECDSAP256)
	pqcKP, _ := crypto.GenerateKeyPair(crypto.AlgMLDSA65)

	// Issue with nil template
	cert, err := ca.IssueCatalyst(context.Background(), CatalystRequest{
		Template:           nil, // nil template
		ClassicalPublicKey: classicalKP.PublicKey,
		PQCPublicKey:       pqcKP.PublicKey,
		PQCAlgorithm:       crypto.AlgMLDSA65,
		Validity:           365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("IssueCatalyst() error = %v", err)
	}

	if cert == nil {
		t.Error("Certificate should not be nil")
	}
}

func TestF_IssueCatalyst_DefaultValidity(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := HybridCAConfig{
		CommonName:         "Catalyst Test CA",
		ClassicalAlgorithm: crypto.AlgECDSAP384,
		PQCAlgorithm:       crypto.AlgMLDSA87,
		ValidityYears:      10,
		PathLen:            1,
	}

	ca, err := InitializeHybridCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeHybridCA() error = %v", err)
	}

	classicalKP, _ := crypto.GenerateKeyPair(crypto.AlgECDSAP256)
	pqcKP, _ := crypto.GenerateKeyPair(crypto.AlgMLDSA65)

	// Issue with zero validity (should default to 1 year)
	cert, err := ca.IssueCatalyst(context.Background(), CatalystRequest{
		ClassicalPublicKey: classicalKP.PublicKey,
		PQCPublicKey:       pqcKP.PublicKey,
		PQCAlgorithm:       crypto.AlgMLDSA65,
		Validity:           0, // zero validity
	})
	if err != nil {
		t.Fatalf("IssueCatalyst() error = %v", err)
	}

	// Check validity is approximately 1 year
	validity := cert.NotAfter.Sub(cert.NotBefore)
	expectedValidity := 365 * 24 * time.Hour
	tolerance := 24 * time.Hour

	if validity < expectedValidity-tolerance || validity > expectedValidity+tolerance {
		t.Errorf("Validity = %v, want ~1 year", validity)
	}
}

func TestF_IssueCatalyst_WithExistingSubjectKeyId(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := HybridCAConfig{
		CommonName:         "Catalyst Test CA",
		ClassicalAlgorithm: crypto.AlgECDSAP384,
		PQCAlgorithm:       crypto.AlgMLDSA87,
		ValidityYears:      10,
		PathLen:            1,
	}

	ca, err := InitializeHybridCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeHybridCA() error = %v", err)
	}

	classicalKP, _ := crypto.GenerateKeyPair(crypto.AlgECDSAP256)
	pqcKP, _ := crypto.GenerateKeyPair(crypto.AlgMLDSA65)

	customSKID := []byte{0x01, 0x02, 0x03, 0x04, 0x05}

	template := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "test.example.com"},
		SubjectKeyId: customSKID,
	}

	cert, err := ca.IssueCatalyst(context.Background(), CatalystRequest{
		Template:           template,
		ClassicalPublicKey: classicalKP.PublicKey,
		PQCPublicKey:       pqcKP.PublicKey,
		PQCAlgorithm:       crypto.AlgMLDSA65,
		Validity:           365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("IssueCatalyst() error = %v", err)
	}

	// Should preserve the custom SKID
	if len(cert.SubjectKeyId) != len(customSKID) {
		t.Errorf("SubjectKeyId = %v, want %v", cert.SubjectKeyId, customSKID)
	}
}

// =============================================================================
// VerifyCatalystSignatures Error Path Tests
// =============================================================================

func TestF_VerifyCatalystSignatures_NonCatalystCert(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create classical CA
	cfg := Config{
		CommonName:    "Classical CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Issue classical certificate (no Catalyst extensions)
	classicalKP, _ := crypto.GenerateKeyPair(crypto.AlgECDSAP256)
	template := &x509.Certificate{
		Subject: pkix.Name{CommonName: "test.example.com"},
	}

	cert, err := ca.Issue(context.Background(), IssueRequest{
		Template:  template,
		PublicKey: classicalKP.PublicKey,
		Validity:  365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	// Try to verify as Catalyst (should fail - no Catalyst extensions)
	_, err = VerifyCatalystSignatures(cert, ca.Certificate())
	if err == nil {
		t.Error("VerifyCatalystSignatures() should fail for non-Catalyst certificate")
	}
}

func TestF_VerifyCatalystSignatures_NonCatalystIssuer(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create hybrid CA
	hybridCfg := HybridCAConfig{
		CommonName:         "Catalyst CA",
		ClassicalAlgorithm: crypto.AlgECDSAP384,
		PQCAlgorithm:       crypto.AlgMLDSA87,
		ValidityYears:      10,
		PathLen:            1,
	}

	hybridCA, err := InitializeHybridCA(store, hybridCfg)
	if err != nil {
		t.Fatalf("InitializeHybridCA() error = %v", err)
	}

	// Issue Catalyst certificate
	classicalKP, _ := crypto.GenerateKeyPair(crypto.AlgECDSAP256)
	pqcKP, _ := crypto.GenerateKeyPair(crypto.AlgMLDSA65)

	cert, err := hybridCA.IssueCatalyst(context.Background(), CatalystRequest{
		ClassicalPublicKey: classicalKP.PublicKey,
		PQCPublicKey:       pqcKP.PublicKey,
		PQCAlgorithm:       crypto.AlgMLDSA65,
		Validity:           365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("IssueCatalyst() error = %v", err)
	}

	// Create a different classical CA (non-Catalyst issuer)
	tmpDir2 := t.TempDir()
	store2 := NewFileStore(tmpDir2)
	classicalCfg := Config{
		CommonName:    "Classical CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	classicalCA, err := Initialize(store2, classicalCfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Try to verify Catalyst cert against non-Catalyst issuer
	// The classical signature will fail first (wrong issuer), returning (false, nil)
	// OR the issuer check for Catalyst extensions will fail with an error
	valid, err := VerifyCatalystSignatures(cert, classicalCA.Certificate())

	// Either we get an error (issuer doesn't have Catalyst extensions)
	// or we get valid=false (classical signature fails first)
	if err == nil && valid {
		t.Error("VerifyCatalystSignatures() should fail (error or valid=false) with wrong issuer")
	}
}

// =============================================================================
// setCatalystValidity Unit Tests
// =============================================================================

func TestU_SetCatalystValidity_PreservesExistingDates(t *testing.T) {
	now := time.Now().UTC()
	future := now.AddDate(2, 0, 0)

	template := &x509.Certificate{
		NotBefore: now,
		NotAfter:  future,
	}

	req := CatalystRequest{
		Validity: 30 * 24 * time.Hour, // 30 days
	}

	setCatalystValidity(template, req)

	// Should preserve existing dates
	if !template.NotBefore.Equal(now) {
		t.Error("NotBefore should be preserved")
	}
	if !template.NotAfter.Equal(future) {
		t.Error("NotAfter should be preserved")
	}
}
