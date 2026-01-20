package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/remiblancher/post-quantum-pki/internal/crypto"
	"github.com/remiblancher/post-quantum-pki/internal/profile"
)

// =============================================================================
// CA Signer Loading Functional Tests
// =============================================================================

func TestF_CA_LoadSigner(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
		Passphrase:    "test-password",
	}

	_, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Load CA without signer
	ca, err := New(store)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Try to issue without loading signer (should fail)
	subjectKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

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
		Subject:  pkix.Name{CommonName: "server.example.com"},
		DNSNames: []string{"server.example.com"},
	}

	_, err = ca.Issue(context.Background(), IssueRequest{
		Template:   template,
		PublicKey:  &subjectKey.PublicKey,
		Extensions: extensions,
		Validity:   365 * 24 * time.Hour,
	})
	if err == nil {
		t.Error("Issue should fail without signer loaded")
	}

	// Load signer
	if err := ca.LoadSigner("test-password"); err != nil {
		t.Fatalf("LoadSigner() error = %v", err)
	}

	// Now issue should work
	cert, err := ca.Issue(context.Background(), IssueRequest{
		Template:   template,
		PublicKey:  &subjectKey.PublicKey,
		Extensions: extensions,
		Validity:   365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if cert == nil {
		t.Error("certificate should not be nil")
	}
}

// =============================================================================
// Crypto-Agility Tests: LoadAllCACerts and LoadCrossSignedCerts
// =============================================================================

func TestA_LoadAllCACerts_SingleAlgo(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize single-algo CA
	cfg := Config{
		CommonName:    "Single Algo CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	_, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// LoadAllCACerts should return exactly 1 certificate
	certs, err := store.LoadAllCACerts(context.Background())
	if err != nil {
		t.Fatalf("LoadAllCACerts() error = %v", err)
	}
	if len(certs) != 1 {
		t.Errorf("LoadAllCACerts() returned %d certs, want 1", len(certs))
	}
	if certs[0].Subject.CommonName != "Single Algo CA" {
		t.Errorf("Subject.CommonName = %v, want Single Algo CA", certs[0].Subject.CommonName)
	}
}

func TestA_LoadAllCACerts_Versioned(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize CA
	cfg := Config{
		CommonName:    "Versioned CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
		Passphrase:    "test",
	}

	_, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// LoadAllCACerts should work with versioned CAs
	certs, err := store.LoadAllCACerts(context.Background())
	if err != nil {
		t.Fatalf("LoadAllCACerts() error = %v", err)
	}
	if len(certs) != 1 {
		t.Errorf("LoadAllCACerts() returned %d certs, want 1", len(certs))
	}
	if certs[0].Subject.CommonName != "Versioned CA" {
		t.Errorf("Subject.CommonName = %v, want Versioned CA", certs[0].Subject.CommonName)
	}
}

// Note: TestA_LoadAllCACerts_HybridCA is tested via CLI integration tests
// in cmd/qpki/credential_test.go:TestA_Credential_Export_Chain_HybridCA

func TestA_LoadCrossSignedCerts_NoCrossSign(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize CA without rotation/cross-signing
	cfg := Config{
		CommonName:    "No CrossSign CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	_, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// LoadCrossSignedCerts should return empty slice (not error)
	certs, err := store.LoadCrossSignedCerts(context.Background())
	if err != nil {
		t.Fatalf("LoadCrossSignedCerts() error = %v", err)
	}
	if len(certs) != 0 {
		t.Errorf("LoadCrossSignedCerts() returned %d certs, want 0", len(certs))
	}
}

// =============================================================================
// LoadSigner Error Path Tests
// =============================================================================

func TestF_CA_LoadSigner_WrongPassphrase(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
		Passphrase:    "correct-password",
	}

	_, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	ca, err := New(store)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Try to load with wrong passphrase
	err = ca.LoadSigner("wrong-password")
	if err == nil {
		t.Error("LoadSigner() should fail with wrong passphrase")
	}
}

func TestF_CA_LoadSigner_RSA(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test RSA CA",
		Algorithm:     crypto.AlgRSA4096,
		ValidityYears: 10,
		PathLen:       1,
		Passphrase:    "test-password",
	}

	_, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	ca, err := New(store)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Load signer
	if err := ca.LoadSigner("test-password"); err != nil {
		t.Fatalf("LoadSigner() error = %v", err)
	}

	// Verify we can issue certificates
	subjectKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		Subject: pkix.Name{CommonName: "test.example.com"},
	}

	cert, err := ca.Issue(context.Background(), IssueRequest{
		Template:  template,
		PublicKey: &subjectKey.PublicKey,
		Validity:  365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if cert == nil {
		t.Error("Certificate should not be nil")
	}
}

func TestF_CA_LoadSigner_Ed25519(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Ed25519 CA",
		Algorithm:     crypto.AlgEd25519,
		ValidityYears: 10,
		PathLen:       1,
		Passphrase:    "test-password",
	}

	_, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	ca, err := New(store)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Load signer
	if err := ca.LoadSigner("test-password"); err != nil {
		t.Fatalf("LoadSigner() error = %v", err)
	}

	// Verify we can issue certificates
	subjectKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		Subject: pkix.Name{CommonName: "test.example.com"},
	}

	cert, err := ca.Issue(context.Background(), IssueRequest{
		Template:  template,
		PublicKey: &subjectKey.PublicKey,
		Validity:  365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if cert == nil {
		t.Error("Certificate should not be nil")
	}
}

func TestF_CA_LoadSigner_Hybrid(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize Hybrid CA
	cfg := HybridCAConfig{
		CommonName:         "Hybrid CA",
		ClassicalAlgorithm: crypto.AlgECDSAP384,
		PQCAlgorithm:       crypto.AlgMLDSA87,
		ValidityYears:      10,
		PathLen:            1,
		Passphrase:         "test-password",
	}

	_, err := InitializeHybridCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeHybridCA() error = %v", err)
	}

	ca, err := New(store)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Load signer (should auto-detect hybrid)
	if err := ca.LoadSigner("test-password"); err != nil {
		t.Fatalf("LoadSigner() error = %v", err)
	}

	// Verify we can issue Catalyst certificates
	classicalKP, _ := crypto.GenerateKeyPair(crypto.AlgECDSAP256)
	pqcKP, _ := crypto.GenerateKeyPair(crypto.AlgMLDSA65)

	cert, err := ca.IssueCatalyst(context.Background(), CatalystRequest{
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

// =============================================================================
// isClassicalAlgo Unit Tests
// =============================================================================

func TestU_isClassicalAlgo(t *testing.T) {
	testCases := []struct {
		algo     string
		expected bool
	}{
		// Families
		{"ec", true},
		{"rsa", true},
		{"ed25519", true},
		// Full algorithm IDs - EC
		{"ecdsa-p256", true},
		{"ecdsa-p384", true},
		{"ecdsa-p521", true},
		// Full algorithm IDs - RSA
		{"rsa-2048", true},
		{"rsa-4096", true},
		// PQC algorithms (not classical)
		{"ml-dsa-44", false},
		{"ml-dsa-65", false},
		{"ml-dsa-87", false},
		{"slh-dsa-128f", false},
		// Unknown
		{"unknown", false},
		{"", false},
	}

	for _, tc := range testCases {
		t.Run(tc.algo, func(t *testing.T) {
			result := isClassicalAlgo(tc.algo)
			if result != tc.expected {
				t.Errorf("isClassicalAlgo(%s) = %v, want %v", tc.algo, result, tc.expected)
			}
		})
	}
}

// =============================================================================
// LoadHybridSigner and LoadCompositeSigner Tests
// =============================================================================

func TestF_CA_LoadHybridSigner_NotHybridCA(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize classical CA
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

	// Try to load as hybrid signer (should fail)
	err = ca.LoadHybridSigner("pass", "pass")
	if err == nil {
		t.Error("LoadHybridSigner() should fail for non-hybrid CA")
	}
}

func TestF_CA_LoadCompositeSigner_NotHybridCA(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize classical CA
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

	// Try to load as composite signer (should fail)
	err = ca.LoadCompositeSigner("pass", "pass")
	if err == nil {
		t.Error("LoadCompositeSigner() should fail for non-hybrid CA")
	}
}

func TestF_CA_LoadHybridSigner_Success(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize Hybrid CA
	cfg := HybridCAConfig{
		CommonName:         "Hybrid CA",
		ClassicalAlgorithm: crypto.AlgECDSAP384,
		PQCAlgorithm:       crypto.AlgMLDSA87,
		ValidityYears:      10,
		PathLen:            1,
		Passphrase:         "test-password",
	}

	_, err := InitializeHybridCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeHybridCA() error = %v", err)
	}

	ca, err := New(store)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Load hybrid signer
	if err := ca.LoadHybridSigner("test-password", "test-password"); err != nil {
		t.Fatalf("LoadHybridSigner() error = %v", err)
	}

	// Verify signer is loaded
	if ca.Signer() == nil {
		t.Error("Signer should be loaded")
	}
}

func TestF_CA_LoadCompositeSigner_Success(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize Hybrid CA
	cfg := HybridCAConfig{
		CommonName:         "Composite CA",
		ClassicalAlgorithm: crypto.AlgECDSAP384,
		PQCAlgorithm:       crypto.AlgMLDSA87,
		ValidityYears:      10,
		PathLen:            1,
		Passphrase:         "test-password",
	}

	_, err := InitializeHybridCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeHybridCA() error = %v", err)
	}

	ca, err := New(store)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Load composite signer
	if err := ca.LoadCompositeSigner("test-password", "test-password"); err != nil {
		t.Fatalf("LoadCompositeSigner() error = %v", err)
	}

	// Verify signer is loaded
	if ca.Signer() == nil {
		t.Error("Signer should be loaded")
	}
}

// =============================================================================
// isHybridFromInfo Unit Tests
// =============================================================================

func TestU_isHybridFromInfo_NilInfo(t *testing.T) {
	ca := &CA{info: nil}
	if ca.isHybridFromInfo() {
		t.Error("isHybridFromInfo() should return false for nil info")
	}
}

func TestU_isHybridFromInfo_SingleAlgo(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize single-algo CA
	cfg := Config{
		CommonName:    "Single Algo CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	if ca.isHybridFromInfo() {
		t.Error("isHybridFromInfo() should return false for single-algo CA")
	}
}
