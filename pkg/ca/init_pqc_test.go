package ca

import (
	"context"
	"testing"

	pkicrypto "github.com/remiblancher/post-quantum-pki/pkg/crypto"
)

// =============================================================================
// PQCCAConfig Unit Tests
// =============================================================================

func TestU_PQCCAConfig_Fields(t *testing.T) {
	cfg := PQCCAConfig{
		CommonName:    "Test PQC CA",
		Organization:  "Test Org",
		Country:       "US",
		Algorithm:     pkicrypto.AlgMLDSA65,
		ValidityYears: 10,
		PathLen:       1,
		Passphrase:    "testpass",
	}

	if cfg.CommonName != "Test PQC CA" {
		t.Errorf("CommonName = %s, want Test PQC CA", cfg.CommonName)
	}
	if cfg.Organization != "Test Org" {
		t.Errorf("Organization = %s, want Test Org", cfg.Organization)
	}
	if cfg.Country != "US" {
		t.Errorf("Country = %s, want US", cfg.Country)
	}
	if cfg.Algorithm != pkicrypto.AlgMLDSA65 {
		t.Errorf("Algorithm = %s, want ML-DSA-65", cfg.Algorithm)
	}
	if cfg.ValidityYears != 10 {
		t.Errorf("ValidityYears = %d, want 10", cfg.ValidityYears)
	}
	if cfg.PathLen != 1 {
		t.Errorf("PathLen = %d, want 1", cfg.PathLen)
	}
}

// =============================================================================
// InitializePQCCA Functional Tests
// =============================================================================

func TestF_InitializePQCCA_MLDSA65(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := PQCCAConfig{
		CommonName:    "Test ML-DSA-65 CA",
		Organization:  "Test Org",
		Country:       "US",
		Algorithm:     pkicrypto.AlgMLDSA65,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := InitializePQCCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializePQCCA() error = %v", err)
	}

	if ca == nil {
		t.Fatal("InitializePQCCA() returned nil CA")
	}

	cert := ca.Certificate()
	if cert == nil {
		t.Fatal("CA certificate is nil")
	}

	if cert.Subject.CommonName != "Test ML-DSA-65 CA" {
		t.Errorf("CN = %s, want Test ML-DSA-65 CA", cert.Subject.CommonName)
	}

	if !cert.IsCA {
		t.Error("certificate should be a CA")
	}
}

func TestF_InitializePQCCA_MLDSA87(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := PQCCAConfig{
		CommonName:    "Test ML-DSA-87 CA",
		Algorithm:     pkicrypto.AlgMLDSA87,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := InitializePQCCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializePQCCA() error = %v", err)
	}

	if ca == nil {
		t.Fatal("InitializePQCCA() returned nil CA")
	}
}

func TestF_InitializePQCCA_AlreadyExists(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := PQCCAConfig{
		CommonName:    "Test PQC CA",
		Algorithm:     pkicrypto.AlgMLDSA65,
		ValidityYears: 10,
		PathLen:       1,
	}

	// Initialize first time
	_, err := InitializePQCCA(store, cfg)
	if err != nil {
		t.Fatalf("First InitializePQCCA() error = %v", err)
	}

	// Try to initialize again - should fail
	_, err = InitializePQCCA(store, cfg)
	if err == nil {
		t.Error("Second InitializePQCCA() should fail")
	}
}

func TestF_InitializePQCCA_AlgorithmInvalid(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := PQCCAConfig{
		CommonName:    "Test CA",
		Algorithm:     pkicrypto.AlgECDSAP256, // Classical algorithm
		ValidityYears: 10,
		PathLen:       1,
	}

	_, err := InitializePQCCA(store, cfg)
	if err == nil {
		t.Error("InitializePQCCA() should fail for non-PQC algorithm")
	}
}

func TestF_InitializePQCCA_WithPassphrase(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := PQCCAConfig{
		CommonName:    "Test PQC CA",
		Algorithm:     pkicrypto.AlgMLDSA65,
		ValidityYears: 10,
		PathLen:       1,
		Passphrase:    "testpass",
	}

	ca, err := InitializePQCCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializePQCCA() error = %v", err)
	}

	if ca == nil {
		t.Fatal("InitializePQCCA() returned nil CA")
	}
}

func TestF_InitializePQCCA(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := PQCCAConfig{
		CommonName:    "Test PQC Root CA",
		Organization:  "Test Org",
		Country:       "US",
		Algorithm:     pkicrypto.AlgMLDSA87,
		ValidityYears: 10,
		PathLen:       1,
		Passphrase:    "test-password",
	}

	ca, err := InitializePQCCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializePQCCA() error = %v", err)
	}

	cert := ca.Certificate()
	if cert.Subject.CommonName != "Test PQC Root CA" {
		t.Errorf("CommonName = %v, want Test PQC Root CA", cert.Subject.CommonName)
	}
	if !cert.IsCA {
		t.Error("certificate should be CA")
	}
	if cert.MaxPathLen != 1 {
		t.Errorf("MaxPathLen = %d, want 1", cert.MaxPathLen)
	}

	// Verify store has certificate
	if !store.Exists() {
		t.Error("store should show CA exists")
	}

	// Verify we can reload
	loadedCert, err := store.LoadCACert(context.Background())
	if err != nil {
		t.Fatalf("LoadCACert() error = %v", err)
	}
	if loadedCert.Subject.CommonName != cert.Subject.CommonName {
		t.Error("loaded certificate doesn't match")
	}

	// Verify the certificate using our PQC verification
	certDER := cert.Raw
	valid, err := VerifyPQCCertificateRaw(certDER, cert)
	if err != nil {
		t.Fatalf("VerifyPQCCertificateRaw() error = %v", err)
	}
	if !valid {
		t.Error("PQC certificate signature should be valid")
	}
}

func TestF_InitializePQCCA_AllAlgorithms(t *testing.T) {
	algorithms := []pkicrypto.AlgorithmID{
		// ML-DSA (FIPS 204)
		pkicrypto.AlgMLDSA44,
		pkicrypto.AlgMLDSA65,
		pkicrypto.AlgMLDSA87,
		// SLH-DSA (FIPS 205) - note: these are slower
		pkicrypto.AlgSLHDSA128s,
		pkicrypto.AlgSLHDSA128f,
		pkicrypto.AlgSLHDSA256f, // Also test 256f variant
	}

	for _, alg := range algorithms {
		t.Run("[Functional] PQC CA Init: "+string(alg), func(t *testing.T) {
			tmpDir := t.TempDir()
			store := NewFileStore(tmpDir)

			cfg := PQCCAConfig{
				CommonName:    "Test " + string(alg) + " CA",
				Algorithm:     alg,
				ValidityYears: 10,
				PathLen:       1,
			}

			ca, err := InitializePQCCA(store, cfg)
			if err != nil {
				t.Fatalf("InitializePQCCA(%s) error = %v", alg, err)
			}

			cert := ca.Certificate()
			if !cert.IsCA {
				t.Errorf("%s: certificate should be CA", alg)
			}

			// Verify signature
			valid, err := VerifyPQCCertificateRaw(cert.Raw, cert)
			if err != nil {
				t.Fatalf("%s: VerifyPQCCertificateRaw() error = %v", alg, err)
			}
			if !valid {
				t.Errorf("%s: signature should be valid", alg)
			}
		})
	}
}

func TestF_InitializePQCCA_RejectsClassicalAlgorithm(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := PQCCAConfig{
		CommonName:    "Test Classical CA",
		Algorithm:     pkicrypto.AlgECDSAP256, // Classical algorithm
		ValidityYears: 10,
		PathLen:       1,
	}

	_, err := InitializePQCCA(store, cfg)
	if err == nil {
		t.Error("InitializePQCCA should reject classical algorithms")
	}
}
