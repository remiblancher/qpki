package ca

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/remiblancher/post-quantum-pki/internal/crypto"
)

// =============================================================================
// CA Initialization Functional Tests
// =============================================================================

func TestF_CA_Initialize(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Organization:  "Test Org",
		Country:       "US",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
		Passphrase:    "test-password",
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	cert := ca.Certificate()
	if cert.Subject.CommonName != "Test Root CA" {
		t.Errorf("CommonName = %v, want Test Root CA", cert.Subject.CommonName)
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
}

func TestF_CA_Initialize_AlreadyExists(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	// Initialize first time
	_, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Try to initialize again
	_, err = Initialize(store, cfg)
	if err == nil {
		t.Error("Initialize() should fail when CA already exists")
	}
}

// =============================================================================
// Config Validation Tests
// =============================================================================

func TestU_Config_Validate(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		cfg := Config{
			CommonName:    "Test CA",
			Algorithm:     crypto.AlgECDSAP256,
			ValidityYears: 10,
		}
		if err := cfg.Validate(); err != nil {
			t.Errorf("Validate() error = %v, want nil", err)
		}
	})

	t.Run("missing common name", func(t *testing.T) {
		cfg := Config{
			Algorithm:     crypto.AlgECDSAP256,
			ValidityYears: 10,
		}
		if err := cfg.Validate(); err == nil {
			t.Error("Validate() should fail for missing common name")
		}
	})

	t.Run("missing algorithm", func(t *testing.T) {
		cfg := Config{
			CommonName:    "Test CA",
			ValidityYears: 10,
		}
		if err := cfg.Validate(); err == nil {
			t.Error("Validate() should fail for missing algorithm")
		}
	})

	t.Run("invalid validity years", func(t *testing.T) {
		cfg := Config{
			CommonName: "Test CA",
			Algorithm:  crypto.AlgECDSAP256,
		}
		if err := cfg.Validate(); err == nil {
			t.Error("Validate() should fail for zero validity years")
		}
	})

	t.Run("negative validity years", func(t *testing.T) {
		cfg := Config{
			CommonName:    "Test CA",
			Algorithm:     crypto.AlgECDSAP256,
			ValidityYears: -1,
		}
		if err := cfg.Validate(); err == nil {
			t.Error("Validate() should fail for negative validity years")
		}
	})
}

// =============================================================================
// getAlgorithmFamily Tests
// =============================================================================

func TestU_getAlgorithmFamily(t *testing.T) {
	testCases := []struct {
		algorithm crypto.AlgorithmID
		expected  string
	}{
		// EC algorithms
		{crypto.AlgECDSAP256, "ec"},
		{crypto.AlgECDSAP384, "ec"},
		{crypto.AlgorithmID("ecdsa-p521"), "ec"},

		// RSA algorithms
		{crypto.AlgorithmID("rsa-2048"), "rsa"},
		{crypto.AlgorithmID("rsa-3072"), "rsa"},
		{crypto.AlgRSA4096, "rsa"},

		// Ed25519
		{crypto.AlgEd25519, "ed25519"},

		// ML-DSA (post-quantum)
		{crypto.AlgMLDSA44, "ml-dsa"},
		{crypto.AlgMLDSA65, "ml-dsa"},
		{crypto.AlgMLDSA87, "ml-dsa"},

		// SLH-DSA (post-quantum) - note: function expects "slh-dsa-sha2-*" format
		{crypto.AlgorithmID("slh-dsa-sha2-128f"), "slh-dsa"},
		{crypto.AlgorithmID("slh-dsa-sha2-128s"), "slh-dsa"},

		// Unknown algorithm - returns as-is
		{crypto.AlgorithmID("unknown-algorithm"), "unknown-algorithm"},
		// Note: "slh-dsa-128f" (without sha2) is not recognized, returns as-is
		{crypto.AlgSLHDSA128f, "slh-dsa-128f"},
	}

	for _, tc := range testCases {
		t.Run(string(tc.algorithm), func(t *testing.T) {
			result := getAlgorithmFamily(tc.algorithm)
			if result != tc.expected {
				t.Errorf("getAlgorithmFamily(%s) = %s, want %s", tc.algorithm, result, tc.expected)
			}
		})
	}
}

// =============================================================================
// Initialize with different algorithms Tests
// =============================================================================

func TestF_CA_Initialize_RSA(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test RSA CA",
		Organization:  "Test Org",
		Country:       "US",
		Algorithm:     crypto.AlgRSA4096,
		ValidityYears: 5,
		PathLen:       0,
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	cert := ca.Certificate()
	if cert.Subject.CommonName != "Test RSA CA" {
		t.Errorf("CommonName = %v, want Test RSA CA", cert.Subject.CommonName)
	}
	if !cert.IsCA {
		t.Error("certificate should be CA")
	}
}

func TestF_CA_Initialize_Ed25519(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Ed25519 CA",
		Organization:  "Test Org",
		Country:       "US",
		Algorithm:     crypto.AlgEd25519,
		ValidityYears: 5,
		PathLen:       0,
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	cert := ca.Certificate()
	if cert.Subject.CommonName != "Test Ed25519 CA" {
		t.Errorf("CommonName = %v, want Test Ed25519 CA", cert.Subject.CommonName)
	}
}

// =============================================================================
// InitializeWithSigner Tests
// =============================================================================

func TestF_InitializeWithSigner_ECDSA(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate signer externally (simulating HSM)
	kp := crypto.NewSoftwareKeyProvider()
	keyPath := filepath.Join(tmpDir, "hsm-key.pem")
	keyCfg := crypto.KeyStorageConfig{
		Type:    crypto.KeyProviderTypeSoftware,
		KeyPath: keyPath,
	}
	signer, err := kp.Generate(crypto.AlgECDSAP256, keyCfg)
	if err != nil {
		t.Fatalf("Generate signer error = %v", err)
	}

	cfg := Config{
		CommonName:    "Test HSM CA",
		Organization:  "Test Org",
		Country:       "US",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	caDir := filepath.Join(tmpDir, "ca")
	store := NewFileStore(caDir)
	ca, err := InitializeWithSigner(store, cfg, signer)
	if err != nil {
		t.Fatalf("InitializeWithSigner() error = %v", err)
	}

	cert := ca.Certificate()
	if cert.Subject.CommonName != "Test HSM CA" {
		t.Errorf("CommonName = %v, want Test HSM CA", cert.Subject.CommonName)
	}
	if !cert.IsCA {
		t.Error("certificate should be CA")
	}
	if cert.MaxPathLen != 1 {
		t.Errorf("MaxPathLen = %d, want 1", cert.MaxPathLen)
	}

	// InitializeWithSigner does NOT save CAInfo - caller is responsible
	// Verify info is set but needs to be saved by caller
	if ca.Info() == nil {
		t.Error("CA info should be set")
	}

	// After caller saves info, store.Exists() should return true
	if err := ca.Info().Save(); err != nil {
		t.Fatalf("Info.Save() error = %v", err)
	}
	if !store.Exists() {
		t.Error("store should show CA exists after saving info")
	}
}

func TestF_InitializeWithSigner_RSA(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate RSA signer
	kp := crypto.NewSoftwareKeyProvider()
	keyPath := filepath.Join(tmpDir, "hsm-key.pem")
	keyCfg := crypto.KeyStorageConfig{
		Type:    crypto.KeyProviderTypeSoftware,
		KeyPath: keyPath,
	}
	signer, err := kp.Generate(crypto.AlgRSA4096, keyCfg)
	if err != nil {
		t.Fatalf("Generate signer error = %v", err)
	}

	cfg := Config{
		CommonName:    "Test RSA HSM CA",
		Organization:  "Test Org",
		Country:       "US",
		Algorithm:     crypto.AlgRSA4096,
		ValidityYears: 5,
		PathLen:       0,
	}

	caDir := filepath.Join(tmpDir, "ca")
	store := NewFileStore(caDir)
	ca, err := InitializeWithSigner(store, cfg, signer)
	if err != nil {
		t.Fatalf("InitializeWithSigner() error = %v", err)
	}

	cert := ca.Certificate()
	if cert.Subject.CommonName != "Test RSA HSM CA" {
		t.Errorf("CommonName = %v, want Test RSA HSM CA", cert.Subject.CommonName)
	}
	if !cert.IsCA {
		t.Error("certificate should be CA")
	}
}

func TestF_InitializeWithSigner_AlreadyExists(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate signer
	kp := crypto.NewSoftwareKeyProvider()
	keyPath := filepath.Join(tmpDir, "hsm-key.pem")
	keyCfg := crypto.KeyStorageConfig{
		Type:    crypto.KeyProviderTypeSoftware,
		KeyPath: keyPath,
	}
	signer, err := kp.Generate(crypto.AlgECDSAP256, keyCfg)
	if err != nil {
		t.Fatalf("Generate signer error = %v", err)
	}

	cfg := Config{
		CommonName:    "Test CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	caDir := filepath.Join(tmpDir, "ca")
	store := NewFileStore(caDir)

	// First initialization should succeed
	ca, err := InitializeWithSigner(store, cfg, signer)
	if err != nil {
		t.Fatalf("First InitializeWithSigner() error = %v", err)
	}

	// Save CAInfo to mark the CA as existing
	if err := ca.Info().Save(); err != nil {
		t.Fatalf("Info.Save() error = %v", err)
	}

	// Second initialization should fail (CA now exists)
	_, err = InitializeWithSigner(store, cfg, signer)
	if err == nil {
		t.Error("InitializeWithSigner() should fail when CA already exists")
	}
}

func TestF_InitializeWithSigner_InvalidConfig(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate signer
	kp := crypto.NewSoftwareKeyProvider()
	keyPath := filepath.Join(tmpDir, "hsm-key.pem")
	keyCfg := crypto.KeyStorageConfig{
		Type:    crypto.KeyProviderTypeSoftware,
		KeyPath: keyPath,
	}
	signer, err := kp.Generate(crypto.AlgECDSAP256, keyCfg)
	if err != nil {
		t.Fatalf("Generate signer error = %v", err)
	}

	// Missing common name
	cfg := Config{
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
	}

	caDir := filepath.Join(tmpDir, "ca")
	store := NewFileStore(caDir)
	_, err = InitializeWithSigner(store, cfg, signer)
	if err == nil {
		t.Error("InitializeWithSigner() should fail with invalid config")
	}
}

func TestF_InitializeWithSigner_Ed25519(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate Ed25519 signer
	kp := crypto.NewSoftwareKeyProvider()
	keyPath := filepath.Join(tmpDir, "hsm-key.pem")
	keyCfg := crypto.KeyStorageConfig{
		Type:    crypto.KeyProviderTypeSoftware,
		KeyPath: keyPath,
	}
	signer, err := kp.Generate(crypto.AlgEd25519, keyCfg)
	if err != nil {
		t.Fatalf("Generate signer error = %v", err)
	}

	cfg := Config{
		CommonName:    "Test Ed25519 HSM CA",
		Organization:  "Test Org",
		Country:       "US",
		Algorithm:     crypto.AlgEd25519,
		ValidityYears: 5,
		PathLen:       0,
	}

	caDir := filepath.Join(tmpDir, "ca")
	store := NewFileStore(caDir)
	ca, err := InitializeWithSigner(store, cfg, signer)
	if err != nil {
		t.Fatalf("InitializeWithSigner() error = %v", err)
	}

	cert := ca.Certificate()
	if cert.Subject.CommonName != "Test Ed25519 HSM CA" {
		t.Errorf("CommonName = %v, want Test Ed25519 HSM CA", cert.Subject.CommonName)
	}
}
