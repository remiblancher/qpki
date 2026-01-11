package ca

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
)

func TestNewCAMetadata(t *testing.T) {
	meta := NewCAMetadata("ec/root-ca")

	if meta.Created.IsZero() {
		t.Error("Created should not be zero")
	}

	if len(meta.Keys) != 0 {
		t.Errorf("Keys should be empty, got %d keys", len(meta.Keys))
	}
}

func TestCAMetadataAddKey(t *testing.T) {
	meta := NewCAMetadata("test/profile")

	keyRef := KeyRef{
		ID:        "default",
		Algorithm: pkicrypto.AlgECDSAP384,
		Storage: pkicrypto.StorageRef{
			Type: "software",
			Path: "keys/ca.ecdsa-p384.key",
		},
	}

	meta.AddKey(keyRef)

	if len(meta.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(meta.Keys))
	}

	if meta.Keys[0].ID != "default" {
		t.Errorf("key ID = %s, want default", meta.Keys[0].ID)
	}

	if meta.Keys[0].Algorithm != pkicrypto.AlgECDSAP384 {
		t.Errorf("algorithm = %s, want %s", meta.Keys[0].Algorithm, pkicrypto.AlgECDSAP384)
	}
}

func TestCAMetadataGetKey(t *testing.T) {
	meta := NewCAMetadata("test/profile")

	meta.AddKey(KeyRef{ID: "classical", Algorithm: pkicrypto.AlgECDSAP384})
	meta.AddKey(KeyRef{ID: "pqc", Algorithm: pkicrypto.AlgMLDSA65})

	t.Run("existing key", func(t *testing.T) {
		key := meta.GetKey("classical")
		if key == nil {
			t.Fatal("GetKey(classical) returned nil")
		}
		if key.ID != "classical" {
			t.Errorf("key ID = %s, want classical", key.ID)
		}
	})

	t.Run("non-existing key", func(t *testing.T) {
		key := meta.GetKey("nonexistent")
		if key != nil {
			t.Error("GetKey(nonexistent) should return nil")
		}
	})
}

func TestCAMetadataGetDefaultKey(t *testing.T) {
	t.Run("empty keys", func(t *testing.T) {
		meta := NewCAMetadata("test/profile")
		key := meta.GetDefaultKey()
		if key != nil {
			t.Error("GetDefaultKey() should return nil for empty keys")
		}
	})

	t.Run("with default key", func(t *testing.T) {
		meta := NewCAMetadata("test/profile")
		meta.AddKey(KeyRef{ID: "other", Algorithm: pkicrypto.AlgECDSAP256})
		meta.AddKey(KeyRef{ID: "default", Algorithm: pkicrypto.AlgECDSAP384})

		key := meta.GetDefaultKey()
		if key == nil {
			t.Fatal("GetDefaultKey() returned nil")
		}
		if key.ID != "default" {
			t.Errorf("key ID = %s, want default", key.ID)
		}
	})

	t.Run("without default key", func(t *testing.T) {
		meta := NewCAMetadata("test/profile")
		meta.AddKey(KeyRef{ID: "first", Algorithm: pkicrypto.AlgECDSAP256})
		meta.AddKey(KeyRef{ID: "second", Algorithm: pkicrypto.AlgECDSAP384})

		key := meta.GetDefaultKey()
		if key == nil {
			t.Fatal("GetDefaultKey() returned nil")
		}
		if key.ID != "first" {
			t.Errorf("key ID = %s, want first (fallback to first key)", key.ID)
		}
	})
}

func TestCAMetadataIsHybrid(t *testing.T) {
	t.Run("non-hybrid", func(t *testing.T) {
		meta := NewCAMetadata("test/profile")
		meta.AddKey(KeyRef{ID: "default", Algorithm: pkicrypto.AlgECDSAP384})

		if meta.IsHybrid() {
			t.Error("IsHybrid() should return false for non-hybrid CA")
		}
	})

	t.Run("hybrid", func(t *testing.T) {
		meta := NewCAMetadata("test/profile")
		meta.AddKey(KeyRef{ID: "classical", Algorithm: pkicrypto.AlgECDSAP384})
		meta.AddKey(KeyRef{ID: "pqc", Algorithm: pkicrypto.AlgMLDSA65})

		if !meta.IsHybrid() {
			t.Error("IsHybrid() should return true for hybrid CA")
		}
	})
}

func TestSaveLoadCAMetadata(t *testing.T) {
	tmpDir := t.TempDir()

	original := NewCAInfo(Subject{CommonName: "Test CA"})
	original.AddKey(KeyRef{
		ID:        "default",
		Algorithm: pkicrypto.AlgECDSAP384,
		Storage: pkicrypto.StorageRef{
			Type: "software",
			Path: "keys/ca.ecdsa-p384.key",
		},
	})

	// Save
	if err := SaveCAMetadata(tmpDir, original); err != nil {
		t.Fatalf("SaveCAMetadata() failed: %v", err)
	}

	// Verify file exists
	metaPath := filepath.Join(tmpDir, MetadataFile)
	if _, err := os.Stat(metaPath); os.IsNotExist(err) {
		t.Fatalf("metadata file was not created at %s", metaPath)
	}

	// Load
	loaded, err := LoadCAMetadata(tmpDir)
	if err != nil {
		t.Fatalf("LoadCAMetadata() failed: %v", err)
	}

	if loaded == nil {
		t.Fatal("LoadCAMetadata() returned nil")
	}

	// Compare
	if loaded.Subject.CommonName != original.Subject.CommonName {
		t.Errorf("Subject.CommonName = %s, want %s", loaded.Subject.CommonName, original.Subject.CommonName)
	}

	if len(loaded.Keys) != len(original.Keys) {
		t.Errorf("len(Keys) = %d, want %d", len(loaded.Keys), len(original.Keys))
	}

	if len(loaded.Keys) > 0 {
		if loaded.Keys[0].ID != original.Keys[0].ID {
			t.Errorf("Keys[0].ID = %s, want %s", loaded.Keys[0].ID, original.Keys[0].ID)
		}
		if loaded.Keys[0].Algorithm != original.Keys[0].Algorithm {
			t.Errorf("Keys[0].Algorithm = %s, want %s", loaded.Keys[0].Algorithm, original.Keys[0].Algorithm)
		}
		if loaded.Keys[0].Storage.Path != original.Keys[0].Storage.Path {
			t.Errorf("Keys[0].Storage.Path = %s, want %s", loaded.Keys[0].Storage.Path, original.Keys[0].Storage.Path)
		}
	}
}

func TestLoadCAMetadataNotFound(t *testing.T) {
	tmpDir := t.TempDir()

	// Load from directory without metadata
	meta, err := LoadCAMetadata(tmpDir)
	if err != nil {
		t.Fatalf("LoadCAMetadata() failed: %v", err)
	}

	if meta != nil {
		t.Error("LoadCAMetadata() should return nil for non-existent file")
	}
}

func TestMetadataExists(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("not exists", func(t *testing.T) {
		if MetadataExists(tmpDir) {
			t.Error("MetadataExists() should return false")
		}
	})

	t.Run("exists", func(t *testing.T) {
		meta := NewCAMetadata("test/profile")
		if err := SaveCAMetadata(tmpDir, meta); err != nil {
			t.Fatalf("SaveCAMetadata() failed: %v", err)
		}

		if !MetadataExists(tmpDir) {
			t.Error("MetadataExists() should return true")
		}
	})
}

func TestCreateSoftwareKeyRef(t *testing.T) {
	keyPath := "keys/ca.ecdsa-p384.key"
	ref := CreateSoftwareKeyRef(keyPath)

	if ref.Type != "software" {
		t.Errorf("Type = %s, want software", ref.Type)
	}
	if ref.Path != keyPath {
		t.Errorf("Path = %s, want %s", ref.Path, keyPath)
	}
}

func TestCreatePKCS11KeyRef(t *testing.T) {
	ref := CreatePKCS11KeyRef("./hsm.yaml", "ca-key", "0x01")

	if ref.Type != "pkcs11" {
		t.Errorf("Type = %s, want pkcs11", ref.Type)
	}
	if ref.Config != "./hsm.yaml" {
		t.Errorf("Config = %s, want ./hsm.yaml", ref.Config)
	}
	if ref.Label != "ca-key" {
		t.Errorf("Label = %s, want ca-key", ref.Label)
	}
	if ref.KeyID != "0x01" {
		t.Errorf("KeyID = %s, want 0x01", ref.KeyID)
	}
}

func TestCAKeyPathForAlgorithm(t *testing.T) {
	tests := []struct {
		basePath string
		alg      pkicrypto.AlgorithmID
		want     string
	}{
		{"/ca", pkicrypto.AlgECDSAP384, "/ca/keys/ca.ecdsa-p384.key"},
		{"/ca", pkicrypto.AlgMLDSA65, "/ca/keys/ca.ml-dsa-65.key"},
		{"/ca", pkicrypto.AlgRSA4096, "/ca/keys/ca.rsa-4096.key"},
	}

	for _, tt := range tests {
		t.Run(string(tt.alg), func(t *testing.T) {
			got := CAKeyPathForAlgorithm(tt.basePath, tt.alg)
			if got != tt.want {
				t.Errorf("CAKeyPathForAlgorithm() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestRelativeCAKeyPathForAlgorithm(t *testing.T) {
	tests := []struct {
		alg  pkicrypto.AlgorithmID
		want string
	}{
		{pkicrypto.AlgECDSAP384, "keys/ca.ecdsa-p384.key"},
		{pkicrypto.AlgMLDSA65, "keys/ca.ml-dsa-65.key"},
	}

	for _, tt := range tests {
		t.Run(string(tt.alg), func(t *testing.T) {
			got := RelativeCAKeyPathForAlgorithm(tt.alg)
			if got != tt.want {
				t.Errorf("RelativeCAKeyPathForAlgorithm() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestKeyRefBuildKeyStorageConfig(t *testing.T) {
	t.Run("software key", func(t *testing.T) {
		keyRef := KeyRef{
			ID:        "default",
			Algorithm: pkicrypto.AlgECDSAP384,
			Storage: pkicrypto.StorageRef{
				Type: "software",
				Path: "keys/ca.ecdsa-p384.key",
			},
		}

		cfg, err := keyRef.BuildKeyStorageConfig("/ca", "test-pass")
		if err != nil {
			t.Fatalf("BuildKeyStorageConfig() failed: %v", err)
		}

		if cfg.Type != pkicrypto.KeyProviderTypeSoftware {
			t.Errorf("Type = %s, want software", cfg.Type)
		}
		if cfg.KeyPath != "/ca/keys/ca.ecdsa-p384.key" {
			t.Errorf("KeyPath = %s, want /ca/keys/ca.ecdsa-p384.key", cfg.KeyPath)
		}
		if cfg.Passphrase != "test-pass" {
			t.Errorf("Passphrase = %s, want test-pass", cfg.Passphrase)
		}
	})
}

func TestCAMetadataHybridKeys(t *testing.T) {
	meta := NewCAMetadata("hybrid/root-ca")

	meta.AddKey(KeyRef{
		ID:        "classical",
		Algorithm: pkicrypto.AlgECDSAP384,
		Storage: pkicrypto.StorageRef{
			Type: "software",
			Path: "keys/ca.ecdsa-p384.key",
		},
	})

	meta.AddKey(KeyRef{
		ID:        "pqc",
		Algorithm: pkicrypto.AlgMLDSA65,
		Storage: pkicrypto.StorageRef{
			Type: "software",
			Path: "keys/ca.ml-dsa-65.key",
		},
	})

	t.Run("GetClassicalKey", func(t *testing.T) {
		key := meta.GetClassicalKey()
		if key == nil {
			t.Fatal("GetClassicalKey() returned nil")
		}
		if key.ID != "classical" {
			t.Errorf("key ID = %s, want classical", key.ID)
		}
	})

	t.Run("GetPQCKey", func(t *testing.T) {
		key := meta.GetPQCKey()
		if key == nil {
			t.Fatal("GetPQCKey() returned nil")
		}
		if key.ID != "pqc" {
			t.Errorf("key ID = %s, want pqc", key.ID)
		}
	})
}

func TestCAMetadataJSON(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a complete metadata structure
	meta := &CAMetadata{
		Subject: Subject{CommonName: "Test CA"},
		Created: time.Date(2025, 1, 2, 10, 30, 0, 0, time.UTC),
		Keys: []KeyRef{
			{
				ID:        "default",
				Algorithm: pkicrypto.AlgECDSAP384,
				Storage: pkicrypto.StorageRef{
					Type: "software",
					Path: "keys/ca.ecdsa-p384.key",
				},
			},
		},
		Versions: make(map[string]CAVersion),
	}

	// Save and verify JSON format
	if err := SaveCAMetadata(tmpDir, meta); err != nil {
		t.Fatalf("SaveCAMetadata() failed: %v", err)
	}

	// Read the raw JSON
	data, err := os.ReadFile(filepath.Join(tmpDir, MetadataFile))
	if err != nil {
		t.Fatalf("failed to read metadata file: %v", err)
	}

	// Verify JSON contains expected fields
	jsonStr := string(data)
	expectedFields := []string{
		`"subject"`,
		`"created"`,
		`"keys"`,
		`"id"`,
		`"algorithm"`,
		`"storage"`,
		`"type"`,
		`"path"`,
	}

	for _, field := range expectedFields {
		if !contains(jsonStr, field) {
			t.Errorf("JSON should contain %s", field)
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr, 0))
}

func containsAt(s, substr string, start int) bool {
	for i := start; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// =============================================================================
// CAInfo CreatePendingVersion and Activate Tests
// =============================================================================

func TestCAInfo_CreatePendingVersion(t *testing.T) {
	tmpDir := t.TempDir()
	info := NewCAInfo(Subject{CommonName: "Test CA"})
	info.SetBasePath(tmpDir)
	info.CreateInitialVersion([]string{"default"}, []string{"ecdsa-p256"})

	// Create pending version
	pendingVersionID := info.CreatePendingVersion([]string{"ec-profile"}, []string{"ecdsa-p384"})

	// Verify pending version was created
	if pendingVersionID == "" {
		t.Error("Pending version ID should not be empty")
	}

	// Verify version is in Versions map
	if _, ok := info.Versions[pendingVersionID]; !ok {
		t.Error("Pending version should exist in Versions map")
	}

	// Verify status is pending
	if info.Versions[pendingVersionID].Status != VersionStatusPending {
		t.Error("Version status should be pending")
	}
}

func TestCAInfo_Activate(t *testing.T) {
	tmpDir := t.TempDir()
	info := NewCAInfo(Subject{CommonName: "Test CA"})
	info.SetBasePath(tmpDir)
	info.CreateInitialVersion([]string{"default"}, []string{"ecdsa-p256"})

	// Create pending version
	pendingVersion := info.CreatePendingVersion([]string{"ec-profile"}, []string{"ecdsa-p384"})

	// Activate pending version
	err := info.Activate(pendingVersion)
	if err != nil {
		t.Fatalf("Activate() error = %v", err)
	}

	// Verify active version changed
	if info.Active != pendingVersion {
		t.Errorf("Active = %s, want %s", info.Active, pendingVersion)
	}

	// Verify status changed to active
	if info.Versions[pendingVersion].Status != VersionStatusActive {
		t.Error("Version status should be active after activation")
	}
}

func TestCAInfo_Activate_NoPending(t *testing.T) {
	tmpDir := t.TempDir()
	info := NewCAInfo(Subject{CommonName: "Test CA"})
	info.SetBasePath(tmpDir)
	info.CreateInitialVersion([]string{"default"}, []string{"ecdsa-p256"})

	// Try to activate non-existent version
	err := info.Activate("v999")
	if err == nil {
		t.Error("Activate() should fail for non-existent version")
	}
}

// =============================================================================
// CAInfo Path Tests
// =============================================================================

func TestCAInfo_ActiveCertPath(t *testing.T) {
	info := NewCAInfo(Subject{CommonName: "Test CA"})
	info.SetBasePath("/tmp/test-ca")
	info.CreateInitialVersion([]string{"default"}, []string{"ecdsa-p256"})

	path := info.ActiveCertPath("ecdsa-p256")
	if path == "" {
		t.Error("ActiveCertPath should not be empty")
	}
	if !contains(path, info.Active) {
		t.Errorf("ActiveCertPath should contain active version, got %s", path)
	}
}

func TestCAInfo_ActiveKeyPath(t *testing.T) {
	info := NewCAInfo(Subject{CommonName: "Test CA"})
	info.SetBasePath("/tmp/test-ca")
	info.CreateInitialVersion([]string{"default"}, []string{"ecdsa-p256"})

	path := info.ActiveKeyPath("ecdsa-p256")
	if path == "" {
		t.Error("ActiveKeyPath should not be empty")
	}
	if !contains(path, info.Active) {
		t.Errorf("ActiveKeyPath should contain active version, got %s", path)
	}
}

// =============================================================================
// KeyRef BuildKeyStorageConfig Tests
// =============================================================================

func TestKeyRef_BuildKeyStorageConfig_Software(t *testing.T) {
	keyRef := KeyRef{
		ID:        "default",
		Algorithm: pkicrypto.AlgECDSAP256,
		Storage: pkicrypto.StorageRef{
			Type: "software",
			Path: "keys/ca.key",
		},
	}

	config, err := keyRef.BuildKeyStorageConfig("/tmp/ca", "")
	if err != nil {
		t.Fatalf("BuildKeyStorageConfig() error = %v", err)
	}
	if config.Type != "software" {
		t.Errorf("Type = %s, want software", config.Type)
	}
}

// =============================================================================
// VersionStore Tests
// =============================================================================

func TestVersionStore_Init(t *testing.T) {
	tmpDir := t.TempDir()
	vs := NewVersionStore(tmpDir)

	err := vs.Init()
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	// Verify versions directory was created
	if _, err := os.Stat(vs.VersionsDir()); os.IsNotExist(err) {
		t.Error("Versions directory should exist after Init")
	}
}

func TestVersionStore_CrossSignedCertPath(t *testing.T) {
	vs := NewVersionStore("/tmp/test-ca")

	path := vs.CrossSignedCertPath("v1", "ecdsa-p256")
	expected := "/tmp/test-ca/versions/v1/cross-signed/by-ecdsa-p256.crt"
	if path != expected {
		t.Errorf("CrossSignedCertPath() = %s, want %s", path, expected)
	}
}

func TestVersionStore_ListVersions(t *testing.T) {
	tmpDir := t.TempDir()
	vs := NewVersionStore(tmpDir)

	// Create info with versions
	info := NewCAInfo(Subject{CommonName: "Test CA"})
	info.SetBasePath(tmpDir)
	info.CreateInitialVersion([]string{"default"}, []string{"ecdsa-p256"})
	info.CreatePendingVersion([]string{"ec"}, []string{"ecdsa-p384"})

	// Save info
	if err := info.Save(); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// List versions
	versions, err := vs.ListVersions()
	if err != nil {
		t.Fatalf("ListVersions() error = %v", err)
	}

	if len(versions) != 2 {
		t.Errorf("ListVersions() returned %d versions, want 2", len(versions))
	}
}

func TestVersionStore_Activate(t *testing.T) {
	tmpDir := t.TempDir()
	vs := NewVersionStore(tmpDir)

	// Create info with versions
	info := NewCAInfo(Subject{CommonName: "Test CA"})
	info.SetBasePath(tmpDir)
	info.CreateInitialVersion([]string{"default"}, []string{"ecdsa-p256"})
	pendingVersion := info.CreatePendingVersion([]string{"ec"}, []string{"ecdsa-p384"})

	if err := info.Save(); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Activate via VersionStore
	err := vs.Activate(pendingVersion)
	if err != nil {
		t.Fatalf("Activate() error = %v", err)
	}

	// Reload and verify
	loadedInfo, err := LoadCAInfo(tmpDir)
	if err != nil {
		t.Fatalf("LoadCAInfo() error = %v", err)
	}

	if loadedInfo.Active != pendingVersion {
		t.Errorf("Active = %s, want %s", loadedInfo.Active, pendingVersion)
	}
}

func TestVersionStore_LoadIndex(t *testing.T) {
	tmpDir := t.TempDir()
	vs := NewVersionStore(tmpDir)

	// Create info
	info := NewCAInfo(Subject{CommonName: "Test CA"})
	info.SetBasePath(tmpDir)
	info.CreateInitialVersion([]string{"default"}, []string{"ecdsa-p256"})

	if err := info.Save(); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Load index
	index, err := vs.LoadIndex()
	if err != nil {
		t.Fatalf("LoadIndex() error = %v", err)
	}

	if index == nil {
		t.Fatal("LoadIndex() returned nil")
	}
}

// =============================================================================
// GetAlgorithmFamilyName Tests
// =============================================================================

func TestGetAlgorithmFamilyName(t *testing.T) {
	testCases := []struct {
		algorithm pkicrypto.AlgorithmID
		expected  string
	}{
		{pkicrypto.AlgECDSAP256, "ec"},
		{pkicrypto.AlgECDSAP384, "ec"},
		{pkicrypto.AlgMLDSA65, "ml-dsa"},
		{pkicrypto.AlgMLDSA87, "ml-dsa"},
		{pkicrypto.AlgSLHDSA128f, "slh-dsa"},
		{pkicrypto.AlgorithmID("unknown"), "unknown"},
	}

	for _, tc := range testCases {
		result := GetAlgorithmFamilyName(tc.algorithm)
		if result != tc.expected {
			t.Errorf("GetAlgorithmFamilyName(%s) = %s, want %s", tc.algorithm, result, tc.expected)
		}
	}
}

// =============================================================================
// CAInfo ListAlgorithmFamilies Tests
// =============================================================================

func TestCAInfo_ListAlgorithmFamilies(t *testing.T) {
	info := NewCAInfo(Subject{CommonName: "Test CA"})
	info.SetBasePath("/tmp/test-ca")
	info.CreateInitialVersion([]string{"default"}, []string{"ecdsa-p256", "ml-dsa-65"})

	families := info.ListAlgorithmFamilies()
	if len(families) != 2 {
		t.Errorf("ListAlgorithmFamilies() returned %d families, want 2", len(families))
	}
}

// =============================================================================
// CAInfo GetActiveVersionID Tests
// =============================================================================

func TestCAInfo_GetActiveVersionID(t *testing.T) {
	info := NewCAInfo(Subject{CommonName: "Test CA"})
	info.SetBasePath("/tmp/test-ca")
	info.CreateInitialVersion([]string{"default"}, []string{"ecdsa-p256"})

	versionID := info.GetActiveVersionID()
	if versionID != info.Active {
		t.Errorf("GetActiveVersionID() = %s, want %s", versionID, info.Active)
	}
}

// =============================================================================
// AddCrossSignedBy Tests
// =============================================================================

func TestVersionStore_AddCrossSignedBy(t *testing.T) {
	tmpDir := t.TempDir()
	vs := NewVersionStore(tmpDir)

	// Create info with versions
	info := NewCAInfo(Subject{CommonName: "Test CA"})
	info.SetBasePath(tmpDir)
	info.CreateInitialVersion([]string{"default"}, []string{"ecdsa-p256"})
	pendingVersion := info.CreatePendingVersion([]string{"ec"}, []string{"ecdsa-p384"})

	if err := info.Save(); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Add cross-signed by reference
	err := vs.AddCrossSignedBy(info.Active, pendingVersion)
	if err != nil {
		t.Fatalf("AddCrossSignedBy() error = %v", err)
	}

	// Reload and verify
	loadedInfo, err := LoadCAInfo(tmpDir)
	if err != nil {
		t.Fatalf("LoadCAInfo() error = %v", err)
	}

	// Check if cross-signed info was added
	version, ok := loadedInfo.Versions[info.Active]
	if !ok {
		t.Fatal("Active version not found")
	}

	found := false
	for _, xsign := range version.CrossSignedBy {
		if xsign == pendingVersion {
			found = true
			break
		}
	}
	if !found {
		t.Error("CrossSignedBy should contain pending version")
	}
}
