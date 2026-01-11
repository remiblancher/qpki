package ca

import (
	"testing"

	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
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
