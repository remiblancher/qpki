package ca

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/remiblancher/post-quantum-pki/pkg/crypto"
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

		// EdDSA
		{crypto.AlgEd25519, "ed"},
		{crypto.AlgEd448, "ed"},

		// ML-DSA (post-quantum)
		{crypto.AlgMLDSA44, "ml-dsa"},
		{crypto.AlgMLDSA65, "ml-dsa"},
		{crypto.AlgMLDSA87, "ml-dsa"},

		// SLH-DSA SHA2 variants (post-quantum)
		{crypto.AlgSLHDSASHA2128f, "slh-dsa"},
		{crypto.AlgSLHDSASHA2128s, "slh-dsa"},
		{crypto.AlgSLHDSASHA2192f, "slh-dsa"},
		{crypto.AlgSLHDSASHA2192s, "slh-dsa"},
		{crypto.AlgSLHDSASHA2256f, "slh-dsa"},
		{crypto.AlgSLHDSASHA2256s, "slh-dsa"},

		// SLH-DSA SHAKE variants (post-quantum)
		{crypto.AlgSLHDSASHAKE128f, "slh-dsa"},
		{crypto.AlgSLHDSASHAKE128s, "slh-dsa"},
		{crypto.AlgSLHDSASHAKE192f, "slh-dsa"},
		{crypto.AlgSLHDSASHAKE192s, "slh-dsa"},
		{crypto.AlgSLHDSASHAKE256f, "slh-dsa"},
		{crypto.AlgSLHDSASHAKE256s, "slh-dsa"},

		// Unknown algorithm - returns as-is
		{crypto.AlgorithmID("unknown-algorithm"), "unknown-algorithm"},
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

// =============================================================================
// Initialize Error Path Tests
// =============================================================================

func TestF_Initialize_InvalidConfig_MissingCommonName(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		// CommonName missing
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	_, err := Initialize(store, cfg)
	if err == nil {
		t.Error("Initialize() should fail with missing common name")
	}
}

func TestF_Initialize_InvalidConfig_MissingAlgorithm(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test CA",
		ValidityYears: 10,
		PathLen:       1,
	}

	_, err := Initialize(store, cfg)
	if err == nil {
		t.Error("Initialize() should fail with missing algorithm")
	}
}

func TestF_Initialize_InvalidConfig_InvalidValidity(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 0,
		PathLen:       1,
	}

	_, err := Initialize(store, cfg)
	if err == nil {
		t.Error("Initialize() should fail with zero validity years")
	}
}

func TestF_Initialize_WithKeyProvider(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Provide custom key provider
	kp := crypto.NewSoftwareKeyProvider()

	cfg := Config{
		CommonName:    "Test CA with KeyProvider",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
		KeyProvider:   kp,
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	cert := ca.Certificate()
	if cert.Subject.CommonName != "Test CA with KeyProvider" {
		t.Errorf("CommonName = %v, want Test CA with KeyProvider", cert.Subject.CommonName)
	}
}

func TestF_Initialize_WithKeyStorageConfig(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Provide custom key storage config
	keyPath := filepath.Join(tmpDir, "custom-key-path.pem")
	keyCfg := crypto.KeyStorageConfig{
		Type:       crypto.KeyProviderTypeSoftware,
		KeyPath:    keyPath,
		Passphrase: "custom-pass",
	}

	cfg := Config{
		CommonName:       "Test CA with KeyStorage",
		Algorithm:        crypto.AlgECDSAP256,
		ValidityYears:    10,
		PathLen:          1,
		KeyStorageConfig: keyCfg,
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	cert := ca.Certificate()
	if cert.Subject.CommonName != "Test CA with KeyStorage" {
		t.Errorf("CommonName = %v, want Test CA with KeyStorage", cert.Subject.CommonName)
	}
}

// =============================================================================
// saveCertToPath Unit Tests
// =============================================================================

func TestU_saveCertToPath(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a simple test CA to get a certificate
	store := NewFileStore(tmpDir)
	cfg := Config{
		CommonName:    "Test CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 1,
		PathLen:       0,
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	cert := ca.Certificate()

	// Test saving to valid path
	validPath := filepath.Join(tmpDir, "test-cert.pem")
	err = saveCertToPath(validPath, cert)
	if err != nil {
		t.Errorf("saveCertToPath() error = %v", err)
	}

	// Verify file was created
	_, err = loadCertFromPath(validPath)
	if err != nil {
		t.Errorf("Failed to load saved cert: %v", err)
	}
}

func TestU_saveCertToPath_InvalidPath(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a test CA to get a certificate
	store := NewFileStore(tmpDir)
	cfg := Config{
		CommonName:    "Test CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 1,
		PathLen:       0,
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	cert := ca.Certificate()

	// Test saving to invalid path (directory doesn't exist)
	invalidPath := filepath.Join(tmpDir, "nonexistent", "nested", "path", "cert.pem")
	err = saveCertToPath(invalidPath, cert)
	if err == nil {
		t.Error("saveCertToPath() should fail with invalid path")
	}
}
