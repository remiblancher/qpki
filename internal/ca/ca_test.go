package ca

import (
	"testing"

	"github.com/remiblancher/post-quantum-pki/internal/crypto"
)

// =============================================================================
// CA Store Method Unit Tests
// =============================================================================

func TestU_CA_Store(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Test Store() method returns the same store
	if ca.Store() != store {
		t.Error("Store() should return the same store instance")
	}
	if ca.Store().BasePath() != tmpDir {
		t.Errorf("Store().BasePath() = %v, want %v", ca.Store().BasePath(), tmpDir)
	}
}

// =============================================================================
// NewWithSigner Functional Tests
// =============================================================================

func TestF_NewWithSigner(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	// Initialize the CA first
	initCA, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Get the signer from the initialized CA (it's loaded during init with no passphrase)
	// For this test, we just verify NewWithSigner works correctly
	signer, err := crypto.GenerateSoftwareSigner(crypto.AlgECDSAP256)
	if err != nil {
		t.Fatalf("GenerateSoftwareSigner() error = %v", err)
	}

	// Create CA with pre-loaded signer (different signer, just testing the path)
	ca, err := NewWithSigner(store, signer)
	if err != nil {
		t.Fatalf("NewWithSigner() error = %v", err)
	}

	// Verify CA was loaded correctly
	if ca.Certificate().Subject.CommonName != "Test Root CA" {
		t.Errorf("CommonName = %v, want Test Root CA", ca.Certificate().Subject.CommonName)
	}

	// The signer should be set (even if it's a different key)
	// We just verify the function path, not that we can issue
	_ = initCA // Suppress unused warning
}

func TestF_NewWithSigner_CANotExists(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	signer, _ := crypto.GenerateSoftwareSigner(crypto.AlgECDSAP256)

	// Should fail because CA doesn't exist
	_, err := NewWithSigner(store, signer)
	if err == nil {
		t.Error("NewWithSigner() should fail when CA doesn't exist")
	}
}

// =============================================================================
// CA Accessor Unit Tests
// =============================================================================

func TestU_CA_Metadata(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
		Profile:       "root-ca",
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Test Metadata() accessor
	metadata := ca.Metadata()
	if metadata == nil {
		t.Fatal("Metadata() should not return nil for newly initialized CA")
	}
	// Verify CAInfo has Subject info
	if metadata.Subject.CommonName == "" {
		t.Error("Metadata().Subject.CommonName should not be empty")
	}
}

func TestU_CA_Metadata_LegacyCA(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
		// No Profile set - simulates legacy CA
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Metadata should still exist
	metadata := ca.Metadata()
	if metadata == nil {
		t.Error("Metadata() should not return nil")
	}
}

func TestU_CA_KeyPaths(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	paths := ca.KeyPaths()
	if len(paths) == 0 {
		t.Error("KeyPaths() should return at least one path")
	}

	// Should have the full algorithm ID key for ECDSA algorithm
	ecPath, ok := paths["ecdsa-p256"]
	if !ok {
		t.Errorf("KeyPaths() should include 'ecdsa-p256' key, got keys: %v", paths)
	}
	if ecPath == "" {
		t.Error("KeyPaths()['ecdsa-p256'] should not be empty")
	}
}

func TestU_CA_DefaultKeyPath(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	keyPath := ca.DefaultKeyPath()
	if keyPath == "" {
		t.Error("DefaultKeyPath() should not return empty string")
	}

	// Should be an absolute path containing the temp dir
	if keyPath[0] != '/' {
		t.Errorf("DefaultKeyPath() should return absolute path, got %v", keyPath)
	}
}

func TestU_CA_SetKeyProvider(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	_, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Load CA
	ca, err := New(store)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Default should return software provider
	initialKP := ca.KeyProvider()
	if initialKP == nil {
		t.Error("KeyProvider() should not return nil")
	}

	// Set custom key provider
	customKP := crypto.NewSoftwareKeyProvider()
	customCfg := crypto.KeyStorageConfig{
		Type:    crypto.KeyProviderTypeSoftware,
		KeyPath: "/custom/path/key.pem",
	}

	ca.SetKeyProvider(customKP, customCfg)

	// KeyProvider should return our custom provider
	kp := ca.KeyProvider()
	if kp == nil {
		t.Error("KeyProvider() should not return nil after SetKeyProvider")
	}

	// KeyStorageConfig should return our custom config
	retrievedCfg := ca.KeyStorageConfig()
	if retrievedCfg.KeyPath != "/custom/path/key.pem" {
		t.Errorf("KeyStorageConfig().KeyPath = %v, want /custom/path/key.pem", retrievedCfg.KeyPath)
	}
}

func TestU_CA_KeyProvider_Default(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	_, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Load CA fresh (no key provider set)
	ca, err := New(store)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Default KeyProvider should return a SoftwareKeyProvider
	kp := ca.KeyProvider()
	if kp == nil {
		t.Error("KeyProvider() should return default provider when none set")
	}
}

func TestU_CA_KeyStorageConfig_Empty(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	_, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Load CA fresh (no config set)
	ca, err := New(store)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Should return empty config
	config := ca.KeyStorageConfig()
	if config.Type != "" && config.Type != crypto.KeyProviderTypeSoftware {
		t.Errorf("KeyStorageConfig().Type = %v, want empty or software", config.Type)
	}
}

func TestU_CA_KeyPaths_HybridCA(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize Hybrid CA
	cfg := HybridCAConfig{
		CommonName:         "Hybrid Test CA",
		ClassicalAlgorithm: crypto.AlgECDSAP384,
		PQCAlgorithm:       crypto.AlgMLDSA87,
		ValidityYears:      10,
		PathLen:            1,
	}

	ca, err := InitializeHybridCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeHybridCA() error = %v", err)
	}

	paths := ca.KeyPaths()
	if len(paths) < 2 {
		t.Errorf("KeyPaths() for hybrid CA should return at least 2 paths, got %d: %v", len(paths), paths)
	}

	// Should have full algorithm ID keys (ecdsa-p384 for classical, ml-dsa-87 for PQC)
	if _, ok := paths["ecdsa-p384"]; !ok {
		t.Errorf("KeyPaths() for hybrid CA should include 'ecdsa-p384' key, got: %v", paths)
	}
	if _, ok := paths["ml-dsa-87"]; !ok {
		t.Errorf("KeyPaths() for hybrid CA should include 'ml-dsa-87' key, got: %v", paths)
	}
}

func TestU_CA_IsHybridCA(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(t *testing.T) *CA
		expected bool
	}{
		{
			name: "Classical CA is not hybrid",
			setup: func(t *testing.T) *CA {
				tmpDir := t.TempDir()
				store := NewFileStore(tmpDir)
				cfg := Config{
					CommonName:    "Test CA",
					Algorithm:     crypto.AlgECDSAP256,
					ValidityYears: 10,
					PathLen:       1,
				}
				ca, err := Initialize(store, cfg)
				if err != nil {
					t.Fatalf("Initialize() error = %v", err)
				}
				return ca
			},
			expected: false,
		},
		{
			name: "Hybrid CA is hybrid",
			setup: func(t *testing.T) *CA {
				tmpDir := t.TempDir()
				store := NewFileStore(tmpDir)
				cfg := HybridCAConfig{
					CommonName:         "Hybrid CA",
					ClassicalAlgorithm: crypto.AlgECDSAP384,
					PQCAlgorithm:       crypto.AlgMLDSA87,
					ValidityYears:      10,
					PathLen:            1,
				}
				ca, err := InitializeHybridCA(store, cfg)
				if err != nil {
					t.Fatalf("InitializeHybridCA() error = %v", err)
				}
				return ca
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ca := tt.setup(t)
			if ca.IsHybridCA() != tt.expected {
				t.Errorf("IsHybridCA() = %v, want %v", ca.IsHybridCA(), tt.expected)
			}
		})
	}
}
