package credential

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// =============================================================================
// VersionStore Tests
// =============================================================================

func TestU_NewVersionStore_Creation(t *testing.T) {
	vs := NewVersionStore("/tmp/test-cred")

	if vs == nil {
		t.Fatal("NewVersionStore returned nil")
	}
	if vs.basePath != "/tmp/test-cred" {
		t.Errorf("expected basePath '/tmp/test-cred', got '%s'", vs.basePath)
	}
}

func TestU_VersionStore_VersionsDir(t *testing.T) {
	vs := NewVersionStore("/tmp/test-cred")

	expected := "/tmp/test-cred/versions"
	if vs.VersionsDir() != expected {
		t.Errorf("expected VersionsDir '%s', got '%s'", expected, vs.VersionsDir())
	}
}

func TestU_VersionStore_IndexPath(t *testing.T) {
	vs := NewVersionStore("/tmp/test-cred")

	expected := "/tmp/test-cred/versions.json"
	if vs.IndexPath() != expected {
		t.Errorf("expected IndexPath '%s', got '%s'", expected, vs.IndexPath())
	}
}

func TestU_VersionStore_VersionDir(t *testing.T) {
	vs := NewVersionStore("/tmp/test-cred")

	expected := "/tmp/test-cred/versions/v20250101_abc123"
	result := vs.VersionDir("v20250101_abc123")
	if result != expected {
		t.Errorf("expected VersionDir '%s', got '%s'", expected, result)
	}
}

func TestU_VersionStore_ProfileDir(t *testing.T) {
	vs := NewVersionStore("/tmp/test-cred")

	expected := "/tmp/test-cred/versions/v20250101_abc123/ec"
	result := vs.ProfileDir("v20250101_abc123", "ec")
	if result != expected {
		t.Errorf("expected ProfileDir '%s', got '%s'", expected, result)
	}
}

func TestU_VersionStore_CurrentLink(t *testing.T) {
	vs := NewVersionStore("/tmp/test-cred")

	expected := "/tmp/test-cred/current"
	if vs.CurrentLink() != expected {
		t.Errorf("expected CurrentLink '%s', got '%s'", expected, vs.CurrentLink())
	}
}

func TestU_VersionStore_Init(t *testing.T) {
	tmpDir := t.TempDir()
	credPath := filepath.Join(tmpDir, "test-cred")
	vs := NewVersionStore(credPath)

	// Versions directory shouldn't exist yet
	versionsDir := vs.VersionsDir()
	if _, err := os.Stat(versionsDir); !os.IsNotExist(err) {
		t.Error("versions directory should not exist before Init")
	}

	// Init
	if err := vs.Init(); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Versions directory should exist now
	if _, err := os.Stat(versionsDir); err != nil {
		t.Errorf("versions directory should exist after Init: %v", err)
	}
}

func TestU_VersionStore_IsVersioned_False(t *testing.T) {
	tmpDir := t.TempDir()
	credPath := filepath.Join(tmpDir, "test-cred")
	vs := NewVersionStore(credPath)

	if vs.IsVersioned() {
		t.Error("should not be versioned when no index file exists")
	}
}

func TestU_VersionStore_IsVersioned_True(t *testing.T) {
	tmpDir := t.TempDir()
	credPath := filepath.Join(tmpDir, "test-cred")
	vs := NewVersionStore(credPath)

	// Create the index file
	if err := os.MkdirAll(credPath, 0755); err != nil {
		t.Fatalf("failed to create directory: %v", err)
	}
	if err := os.WriteFile(vs.IndexPath(), []byte("{}"), 0644); err != nil {
		t.Fatalf("failed to create index file: %v", err)
	}

	if !vs.IsVersioned() {
		t.Error("should be versioned when index file exists")
	}
}

func TestU_VersionStore_LoadIndex_Empty(t *testing.T) {
	tmpDir := t.TempDir()
	credPath := filepath.Join(tmpDir, "test-cred")
	vs := NewVersionStore(credPath)

	// Load index when file doesn't exist
	index, err := vs.LoadIndex()
	if err != nil {
		t.Fatalf("LoadIndex failed: %v", err)
	}

	if index == nil {
		t.Fatal("index should not be nil")
	}
	if len(index.Versions) != 0 {
		t.Errorf("expected 0 versions, got %d", len(index.Versions))
	}
}

func TestU_VersionStore_LoadIndex_Existing(t *testing.T) {
	tmpDir := t.TempDir()
	credPath := filepath.Join(tmpDir, "test-cred")
	vs := NewVersionStore(credPath)

	// Create index file with data
	if err := os.MkdirAll(credPath, 0755); err != nil {
		t.Fatalf("failed to create directory: %v", err)
	}

	index := &VersionIndex{
		ActiveVersion: "v20250101_abc123",
		Versions: []Version{
			{
				ID:       "v20250101_abc123",
				Status:   VersionStatusActive,
				Profiles: []string{"ec/tls-server"},
				Created:  time.Now(),
			},
		},
	}
	data, _ := json.MarshalIndent(index, "", "  ")
	if err := os.WriteFile(vs.IndexPath(), data, 0644); err != nil {
		t.Fatalf("failed to create index file: %v", err)
	}

	// Load index
	loaded, err := vs.LoadIndex()
	if err != nil {
		t.Fatalf("LoadIndex failed: %v", err)
	}

	if loaded.ActiveVersion != "v20250101_abc123" {
		t.Errorf("expected ActiveVersion 'v20250101_abc123', got '%s'", loaded.ActiveVersion)
	}
	if len(loaded.Versions) != 1 {
		t.Errorf("expected 1 version, got %d", len(loaded.Versions))
	}
}

func TestU_VersionStore_LoadIndex_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	credPath := filepath.Join(tmpDir, "test-cred")
	vs := NewVersionStore(credPath)

	// Create invalid JSON file
	if err := os.MkdirAll(credPath, 0755); err != nil {
		t.Fatalf("failed to create directory: %v", err)
	}
	if err := os.WriteFile(vs.IndexPath(), []byte("invalid json"), 0644); err != nil {
		t.Fatalf("failed to create index file: %v", err)
	}

	_, err := vs.LoadIndex()
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "failed to parse") {
		t.Errorf("expected 'failed to parse' error, got: %v", err)
	}
}

func TestU_VersionStore_SaveIndex(t *testing.T) {
	tmpDir := t.TempDir()
	credPath := filepath.Join(tmpDir, "test-cred")
	vs := NewVersionStore(credPath)

	// Create directory
	if err := os.MkdirAll(credPath, 0755); err != nil {
		t.Fatalf("failed to create directory: %v", err)
	}

	// Create and save index
	now := time.Now()
	index := &VersionIndex{
		ActiveVersion: "v1",
		Versions: []Version{
			{ID: "v2", Status: VersionStatusPending, Created: now.Add(time.Hour)},
			{ID: "v1", Status: VersionStatusActive, Created: now},
		},
	}

	if err := vs.SaveIndex(index); err != nil {
		t.Fatalf("SaveIndex failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(vs.IndexPath()); os.IsNotExist(err) {
		t.Error("index file should exist after SaveIndex")
	}

	// Load and verify order (should be sorted by creation time, newest first)
	loaded, _ := vs.LoadIndex()
	if len(loaded.Versions) != 2 {
		t.Fatalf("expected 2 versions, got %d", len(loaded.Versions))
	}
	if loaded.Versions[0].ID != "v2" {
		t.Errorf("expected first version to be 'v2' (newest), got '%s'", loaded.Versions[0].ID)
	}
}

func TestU_VersionStore_CreateVersion(t *testing.T) {
	tmpDir := t.TempDir()
	credPath := filepath.Join(tmpDir, "test-cred")
	vs := NewVersionStore(credPath)

	// Create version
	version, err := vs.CreateVersion([]string{"ec/tls-server", "ml-dsa/tls-server"})
	if err != nil {
		t.Fatalf("CreateVersion failed: %v", err)
	}

	if version == nil {
		t.Fatal("version should not be nil")
	}
	if version.ID == "" {
		t.Error("version ID should not be empty")
	}
	if version.Status != VersionStatusPending {
		t.Errorf("expected status pending, got '%s'", version.Status)
	}
	if len(version.Profiles) != 2 {
		t.Errorf("expected 2 profiles, got %d", len(version.Profiles))
	}

	// Verify version directory was created
	if _, err := os.Stat(vs.VersionDir(version.ID)); os.IsNotExist(err) {
		t.Error("version directory should exist")
	}

	// Verify index was updated
	index, _ := vs.LoadIndex()
	if len(index.Versions) != 1 {
		t.Errorf("expected 1 version in index, got %d", len(index.Versions))
	}
}

func TestU_VersionStore_CreateVersion_NoProfiles(t *testing.T) {
	tmpDir := t.TempDir()
	credPath := filepath.Join(tmpDir, "test-cred")
	vs := NewVersionStore(credPath)

	_, err := vs.CreateVersion([]string{})
	if err == nil {
		t.Error("expected error when creating version with no profiles")
	}
	if !strings.Contains(err.Error(), "at least one profile") {
		t.Errorf("expected 'at least one profile' error, got: %v", err)
	}
}

func TestU_VersionStore_AddCertificate(t *testing.T) {
	tmpDir := t.TempDir()
	credPath := filepath.Join(tmpDir, "test-cred")
	vs := NewVersionStore(credPath)

	// Create version first
	version, err := vs.CreateVersion([]string{"ec/tls-server"})
	if err != nil {
		t.Fatalf("CreateVersion failed: %v", err)
	}

	// Add certificate
	certRef := VersionCertRef{
		Profile:         "ec/tls-server",
		Algorithm:       "ecdsa-p256",
		AlgorithmFamily: "ec",
		Serial:          "0x01",
		Fingerprint:     "ABC123",
		NotBefore:       time.Now(),
		NotAfter:        time.Now().Add(365 * 24 * time.Hour),
	}

	if err := vs.AddCertificate(version.ID, certRef); err != nil {
		t.Fatalf("AddCertificate failed: %v", err)
	}

	// Verify certificate was added
	loadedVersion, _ := vs.GetVersion(version.ID)
	if len(loadedVersion.Certificates) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(loadedVersion.Certificates))
	}
	if loadedVersion.Certificates[0].Serial != "0x01" {
		t.Errorf("expected serial '0x01', got '%s'", loadedVersion.Certificates[0].Serial)
	}
}

func TestU_VersionStore_AddCertificate_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	credPath := filepath.Join(tmpDir, "test-cred")
	vs := NewVersionStore(credPath)

	// Create a version first so index exists
	_, _ = vs.CreateVersion([]string{"ec/tls-server"})

	// Try to add certificate to non-existent version
	certRef := VersionCertRef{Profile: "ec/tls-server"}
	err := vs.AddCertificate("nonexistent", certRef)
	if err == nil {
		t.Error("expected error for non-existent version")
	}
	if !strings.Contains(err.Error(), "version not found") {
		t.Errorf("expected 'version not found' error, got: %v", err)
	}
}

func TestU_VersionStore_GetVersion(t *testing.T) {
	tmpDir := t.TempDir()
	credPath := filepath.Join(tmpDir, "test-cred")
	vs := NewVersionStore(credPath)

	// Create version
	version, _ := vs.CreateVersion([]string{"ec/tls-server"})

	// Get version
	loaded, err := vs.GetVersion(version.ID)
	if err != nil {
		t.Fatalf("GetVersion failed: %v", err)
	}

	if loaded.ID != version.ID {
		t.Errorf("expected ID '%s', got '%s'", version.ID, loaded.ID)
	}
}

func TestU_VersionStore_GetVersion_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	credPath := filepath.Join(tmpDir, "test-cred")
	vs := NewVersionStore(credPath)

	// Create a version first so index exists
	_, _ = vs.CreateVersion([]string{"ec/tls-server"})

	_, err := vs.GetVersion("nonexistent")
	if err == nil {
		t.Error("expected error for non-existent version")
	}
	if !strings.Contains(err.Error(), "version not found") {
		t.Errorf("expected 'version not found' error, got: %v", err)
	}
}

func TestU_VersionStore_GetActiveVersion(t *testing.T) {
	tmpDir := t.TempDir()
	credPath := filepath.Join(tmpDir, "test-cred")
	vs := NewVersionStore(credPath)

	// Create and activate version
	version, _ := vs.CreateVersion([]string{"ec/tls-server"})

	// Add a certificate (required for activation sync)
	certRef := VersionCertRef{
		Profile:         "ec/tls-server",
		Algorithm:       "ecdsa-p256",
		AlgorithmFamily: "ec",
	}
	_ = vs.AddCertificate(version.ID, certRef)

	if err := vs.Activate(version.ID); err != nil {
		t.Fatalf("Activate failed: %v", err)
	}

	// Get active version
	active, err := vs.GetActiveVersion()
	if err != nil {
		t.Fatalf("GetActiveVersion failed: %v", err)
	}

	if active.ID != version.ID {
		t.Errorf("expected active version '%s', got '%s'", version.ID, active.ID)
	}
}

func TestU_VersionStore_GetActiveVersion_NoActive(t *testing.T) {
	tmpDir := t.TempDir()
	credPath := filepath.Join(tmpDir, "test-cred")
	vs := NewVersionStore(credPath)

	// Create version but don't activate
	_, _ = vs.CreateVersion([]string{"ec/tls-server"})

	_, err := vs.GetActiveVersion()
	if err == nil {
		t.Error("expected error when no active version")
	}
	if !strings.Contains(err.Error(), "no active version") {
		t.Errorf("expected 'no active version' error, got: %v", err)
	}
}

func TestU_VersionStore_GetCertForAlgo(t *testing.T) {
	tmpDir := t.TempDir()
	credPath := filepath.Join(tmpDir, "test-cred")
	vs := NewVersionStore(credPath)

	// Create version with certificates
	version, _ := vs.CreateVersion([]string{"ec/tls-server", "ml-dsa/tls-server"})

	// Add certificates for different algorithm families
	_ = vs.AddCertificate(version.ID, VersionCertRef{
		Profile:         "ec/tls-server",
		Algorithm:       "ecdsa-p256",
		AlgorithmFamily: "ec",
		Serial:          "0x01",
	})
	_ = vs.AddCertificate(version.ID, VersionCertRef{
		Profile:         "ml-dsa/tls-server",
		Algorithm:       "ml-dsa-65",
		AlgorithmFamily: "ml-dsa",
		Serial:          "0x02",
	})

	// Get EC certificate
	ecCert, err := vs.GetCertForAlgo(version.ID, "ec")
	if err != nil {
		t.Fatalf("GetCertForAlgo failed: %v", err)
	}
	if ecCert.Serial != "0x01" {
		t.Errorf("expected serial '0x01', got '%s'", ecCert.Serial)
	}

	// Get ML-DSA certificate
	mldsaCert, err := vs.GetCertForAlgo(version.ID, "ml-dsa")
	if err != nil {
		t.Fatalf("GetCertForAlgo failed: %v", err)
	}
	if mldsaCert.Serial != "0x02" {
		t.Errorf("expected serial '0x02', got '%s'", mldsaCert.Serial)
	}
}

func TestU_VersionStore_GetCertForAlgo_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	credPath := filepath.Join(tmpDir, "test-cred")
	vs := NewVersionStore(credPath)

	// Create version with one certificate
	version, _ := vs.CreateVersion([]string{"ec/tls-server"})
	_ = vs.AddCertificate(version.ID, VersionCertRef{
		Profile:         "ec/tls-server",
		Algorithm:       "ecdsa-p256",
		AlgorithmFamily: "ec",
	})

	// Try to get non-existent algorithm family
	_, err := vs.GetCertForAlgo(version.ID, "rsa")
	if err == nil {
		t.Error("expected error for non-existent algorithm family")
	}
	if !strings.Contains(err.Error(), "no certificate found for algorithm family") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestU_VersionStore_GetActiveCertForAlgo(t *testing.T) {
	tmpDir := t.TempDir()
	credPath := filepath.Join(tmpDir, "test-cred")
	vs := NewVersionStore(credPath)

	// Create and activate version
	version, _ := vs.CreateVersion([]string{"ec/tls-server"})
	_ = vs.AddCertificate(version.ID, VersionCertRef{
		Profile:         "ec/tls-server",
		Algorithm:       "ecdsa-p256",
		AlgorithmFamily: "ec",
		Serial:          "0x01",
	})
	_ = vs.Activate(version.ID)

	// Get active certificate for algorithm
	cert, err := vs.GetActiveCertForAlgo("ec")
	if err != nil {
		t.Fatalf("GetActiveCertForAlgo failed: %v", err)
	}
	if cert.Serial != "0x01" {
		t.Errorf("expected serial '0x01', got '%s'", cert.Serial)
	}
}

func TestU_VersionStore_ListAlgorithmFamilies(t *testing.T) {
	tmpDir := t.TempDir()
	credPath := filepath.Join(tmpDir, "test-cred")
	vs := NewVersionStore(credPath)

	// Create and activate version with multiple algorithms
	version, _ := vs.CreateVersion([]string{"ec/tls-server", "ml-dsa/tls-server"})
	_ = vs.AddCertificate(version.ID, VersionCertRef{AlgorithmFamily: "ec"})
	_ = vs.AddCertificate(version.ID, VersionCertRef{AlgorithmFamily: "ml-dsa"})
	_ = vs.Activate(version.ID)

	// List algorithm families
	families, err := vs.ListAlgorithmFamilies()
	if err != nil {
		t.Fatalf("ListAlgorithmFamilies failed: %v", err)
	}
	if len(families) != 2 {
		t.Errorf("expected 2 families, got %d", len(families))
	}
}

func TestU_VersionStore_Activate(t *testing.T) {
	tmpDir := t.TempDir()
	credPath := filepath.Join(tmpDir, "test-cred")
	vs := NewVersionStore(credPath)

	// Create version
	version, _ := vs.CreateVersion([]string{"ec/tls-server"})
	_ = vs.AddCertificate(version.ID, VersionCertRef{
		AlgorithmFamily: "ec",
	})

	// Verify initial status
	loadedBefore, _ := vs.GetVersion(version.ID)
	if loadedBefore.Status != VersionStatusPending {
		t.Errorf("expected pending status before activation, got '%s'", loadedBefore.Status)
	}

	// Activate
	if err := vs.Activate(version.ID); err != nil {
		t.Fatalf("Activate failed: %v", err)
	}

	// Verify status changed
	loadedAfter, _ := vs.GetVersion(version.ID)
	if loadedAfter.Status != VersionStatusActive {
		t.Errorf("expected active status after activation, got '%s'", loadedAfter.Status)
	}
	if loadedAfter.ActivatedAt == nil {
		t.Error("ActivatedAt should not be nil after activation")
	}

	// Verify current symlink was created
	linkPath := vs.CurrentLink()
	if _, err := os.Lstat(linkPath); os.IsNotExist(err) {
		t.Error("current symlink should exist after activation")
	}
}

func TestU_VersionStore_Activate_Archives_Previous(t *testing.T) {
	tmpDir := t.TempDir()
	credPath := filepath.Join(tmpDir, "test-cred")
	vs := NewVersionStore(credPath)

	// Create and activate first version
	v1, _ := vs.CreateVersion([]string{"ec/tls-server"})
	_ = vs.AddCertificate(v1.ID, VersionCertRef{AlgorithmFamily: "ec"})
	_ = vs.Activate(v1.ID)

	// Create and activate second version
	v2, _ := vs.CreateVersion([]string{"ec/tls-server"})
	_ = vs.AddCertificate(v2.ID, VersionCertRef{AlgorithmFamily: "ec"})
	_ = vs.Activate(v2.ID)

	// Verify first version is now archived
	loadedV1, _ := vs.GetVersion(v1.ID)
	if loadedV1.Status != VersionStatusArchived {
		t.Errorf("expected first version to be archived, got '%s'", loadedV1.Status)
	}
	if loadedV1.ArchivedAt == nil {
		t.Error("ArchivedAt should not be nil for archived version")
	}

	// Verify second version is active
	loadedV2, _ := vs.GetVersion(v2.ID)
	if loadedV2.Status != VersionStatusActive {
		t.Errorf("expected second version to be active, got '%s'", loadedV2.Status)
	}
}

func TestU_VersionStore_Activate_NotPending(t *testing.T) {
	tmpDir := t.TempDir()
	credPath := filepath.Join(tmpDir, "test-cred")
	vs := NewVersionStore(credPath)

	// Create and activate version
	version, _ := vs.CreateVersion([]string{"ec/tls-server"})
	_ = vs.AddCertificate(version.ID, VersionCertRef{AlgorithmFamily: "ec"})
	_ = vs.Activate(version.ID)

	// Try to activate again
	err := vs.Activate(version.ID)
	if err == nil {
		t.Error("expected error when activating non-pending version")
	}
	if !strings.Contains(err.Error(), "can only activate pending versions") {
		t.Errorf("expected 'can only activate pending versions' error, got: %v", err)
	}
}

func TestU_VersionStore_Activate_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	credPath := filepath.Join(tmpDir, "test-cred")
	vs := NewVersionStore(credPath)

	// Create a version so index exists
	_, _ = vs.CreateVersion([]string{"ec/tls-server"})

	err := vs.Activate("nonexistent")
	if err == nil {
		t.Error("expected error for non-existent version")
	}
	if !strings.Contains(err.Error(), "version not found") {
		t.Errorf("expected 'version not found' error, got: %v", err)
	}
}

func TestU_VersionStore_ListVersions(t *testing.T) {
	tmpDir := t.TempDir()
	credPath := filepath.Join(tmpDir, "test-cred")
	vs := NewVersionStore(credPath)

	// Create multiple versions
	v1, _ := vs.CreateVersion([]string{"ec/tls-server"})
	time.Sleep(10 * time.Millisecond) // Ensure different creation times
	v2, _ := vs.CreateVersion([]string{"ml-dsa/tls-server"})

	// List versions
	versions, err := vs.ListVersions()
	if err != nil {
		t.Fatalf("ListVersions failed: %v", err)
	}

	if len(versions) != 2 {
		t.Errorf("expected 2 versions, got %d", len(versions))
	}

	// Versions should be sorted by creation time, newest first
	if versions[0].ID != v2.ID {
		t.Errorf("expected first version to be '%s' (newest), got '%s'", v2.ID, versions[0].ID)
	}
	if versions[1].ID != v1.ID {
		t.Errorf("expected second version to be '%s' (oldest), got '%s'", v1.ID, versions[1].ID)
	}
}

func TestU_VersionStore_ListVersions_Empty(t *testing.T) {
	tmpDir := t.TempDir()
	credPath := filepath.Join(tmpDir, "test-cred")
	vs := NewVersionStore(credPath)

	versions, err := vs.ListVersions()
	if err != nil {
		t.Fatalf("ListVersions failed: %v", err)
	}

	if len(versions) != 0 {
		t.Errorf("expected 0 versions, got %d", len(versions))
	}
}

// =============================================================================
// generateVersionID Tests
// =============================================================================

func TestU_GenerateVersionID_Format(t *testing.T) {
	id := generateVersionID()

	// Format should be v{YYYYMMDD}_{6-char-hex}
	if !strings.HasPrefix(id, "v") {
		t.Errorf("version ID should start with 'v', got '%s'", id)
	}

	parts := strings.Split(id, "_")
	if len(parts) != 2 {
		t.Errorf("expected 2 parts separated by '_', got %d: %s", len(parts), id)
		return
	}

	// Check date part (vYYYYMMDD)
	datePart := parts[0][1:] // Remove 'v' prefix
	if len(datePart) != 8 {
		t.Errorf("expected date part to be 8 chars, got %d: %s", len(datePart), datePart)
	}

	// Check random suffix (6 hex chars)
	if len(parts[1]) != 6 {
		t.Errorf("expected random suffix to be 6 chars, got %d: %s", len(parts[1]), parts[1])
	}
}

func TestU_GenerateVersionID_Unique(t *testing.T) {
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := generateVersionID()
		if ids[id] {
			t.Errorf("duplicate version ID generated: %s", id)
		}
		ids[id] = true
	}
}

// =============================================================================
// copyFile Tests
// =============================================================================

func TestU_CopyFile_Success(t *testing.T) {
	tmpDir := t.TempDir()
	srcPath := filepath.Join(tmpDir, "source.txt")
	dstPath := filepath.Join(tmpDir, "dest.txt")

	// Create source file
	content := []byte("test content")
	if err := os.WriteFile(srcPath, content, 0644); err != nil {
		t.Fatalf("failed to create source file: %v", err)
	}

	// Copy file
	if err := copyFile(srcPath, dstPath); err != nil {
		t.Fatalf("copyFile failed: %v", err)
	}

	// Verify destination file
	data, err := os.ReadFile(dstPath)
	if err != nil {
		t.Fatalf("failed to read destination file: %v", err)
	}
	if string(data) != string(content) {
		t.Errorf("content mismatch: expected '%s', got '%s'", content, data)
	}
}

func TestU_CopyFile_SourceNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	dstPath := filepath.Join(tmpDir, "dest.txt")

	err := copyFile("/nonexistent/source.txt", dstPath)
	if err == nil {
		t.Error("expected error for non-existent source file")
	}
}

// =============================================================================
// VersionStatus Tests
// =============================================================================

func TestU_VersionStatus_Constants(t *testing.T) {
	if VersionStatusActive != "active" {
		t.Errorf("expected VersionStatusActive 'active', got '%s'", VersionStatusActive)
	}
	if VersionStatusPending != "pending" {
		t.Errorf("expected VersionStatusPending 'pending', got '%s'", VersionStatusPending)
	}
	if VersionStatusArchived != "archived" {
		t.Errorf("expected VersionStatusArchived 'archived', got '%s'", VersionStatusArchived)
	}
}

// =============================================================================
// syncToRoot Tests
// =============================================================================

func TestU_VersionStore_SyncToRoot(t *testing.T) {
	tmpDir := t.TempDir()
	credPath := filepath.Join(tmpDir, "test-cred")
	vs := NewVersionStore(credPath)

	// Create version with EC certificate
	version, _ := vs.CreateVersion([]string{"ec/tls-server"})
	_ = vs.AddCertificate(version.ID, VersionCertRef{
		AlgorithmFamily: "ec",
	})

	// Create profile directory and files
	profileDir := vs.ProfileDir(version.ID, "ec")
	if err := os.MkdirAll(profileDir, 0755); err != nil {
		t.Fatalf("failed to create profile dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(profileDir, "certificates.pem"), []byte("cert data"), 0644); err != nil {
		t.Fatalf("failed to create cert file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(profileDir, "private-keys.pem"), []byte("key data"), 0600); err != nil {
		t.Fatalf("failed to create key file: %v", err)
	}

	// Activate (which triggers syncToRoot)
	if err := vs.Activate(version.ID); err != nil {
		t.Fatalf("Activate failed: %v", err)
	}

	// Verify files were synced to root
	rootCertPath := filepath.Join(credPath, "certificates.pem")
	if _, err := os.Stat(rootCertPath); os.IsNotExist(err) {
		t.Error("root certificates.pem should exist after sync")
	}

	rootKeyPath := filepath.Join(credPath, "private-keys.pem")
	if _, err := os.Stat(rootKeyPath); os.IsNotExist(err) {
		t.Error("root private-keys.pem should exist after sync")
	}

	// Verify algorithm family directory was created
	ecDir := filepath.Join(credPath, "ec")
	if _, err := os.Stat(ecDir); os.IsNotExist(err) {
		t.Error("ec directory should exist after sync")
	}
}

func TestU_VersionStore_SyncToRoot_PreferEC(t *testing.T) {
	tmpDir := t.TempDir()
	credPath := filepath.Join(tmpDir, "test-cred")
	vs := NewVersionStore(credPath)

	// Create version with both RSA and EC certificates
	version, _ := vs.CreateVersion([]string{"rsa/tls-server", "ec/tls-server"})

	// Add RSA first, then EC
	_ = vs.AddCertificate(version.ID, VersionCertRef{AlgorithmFamily: "rsa"})
	_ = vs.AddCertificate(version.ID, VersionCertRef{AlgorithmFamily: "ec"})

	// Create profile directories and files
	for _, algo := range []string{"rsa", "ec"} {
		profileDir := vs.ProfileDir(version.ID, algo)
		if err := os.MkdirAll(profileDir, 0755); err != nil {
			t.Fatalf("failed to create profile dir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(profileDir, "certificates.pem"), []byte(algo+" cert"), 0644); err != nil {
			t.Fatalf("failed to create cert file: %v", err)
		}
	}

	// Activate
	if err := vs.Activate(version.ID); err != nil {
		t.Fatalf("Activate failed: %v", err)
	}

	// Root certificates.pem should contain EC cert (preferred)
	rootCertData, err := os.ReadFile(filepath.Join(credPath, "certificates.pem"))
	if err != nil {
		t.Fatalf("failed to read root cert: %v", err)
	}
	if string(rootCertData) != "ec cert" {
		t.Errorf("expected root cert to be EC, got '%s'", string(rootCertData))
	}
}

// =============================================================================
// Integration Tests
// =============================================================================

func TestI_VersionStore_FullWorkflow(t *testing.T) {
	tmpDir := t.TempDir()
	credPath := filepath.Join(tmpDir, "test-cred")
	vs := NewVersionStore(credPath)

	// Step 1: Create first version
	v1, err := vs.CreateVersion([]string{"ec/tls-server"})
	if err != nil {
		t.Fatalf("CreateVersion v1 failed: %v", err)
	}

	// Step 2: Add certificate to v1
	_ = vs.AddCertificate(v1.ID, VersionCertRef{
		Profile:         "ec/tls-server",
		Algorithm:       "ecdsa-p256",
		AlgorithmFamily: "ec",
		Serial:          "0x01",
	})

	// Create profile files for v1
	profileDir := vs.ProfileDir(v1.ID, "ec")
	_ = os.MkdirAll(profileDir, 0755)
	_ = os.WriteFile(filepath.Join(profileDir, "certificates.pem"), []byte("v1 cert"), 0644)

	// Step 3: Activate v1
	if err := vs.Activate(v1.ID); err != nil {
		t.Fatalf("Activate v1 failed: %v", err)
	}

	// Verify v1 is active
	active, _ := vs.GetActiveVersion()
	if active.ID != v1.ID {
		t.Errorf("expected active version '%s', got '%s'", v1.ID, active.ID)
	}

	// Step 4: Create second version (rotation)
	v2, err := vs.CreateVersion([]string{"ec/tls-server"})
	if err != nil {
		t.Fatalf("CreateVersion v2 failed: %v", err)
	}

	// Step 5: Add certificate to v2
	_ = vs.AddCertificate(v2.ID, VersionCertRef{
		Profile:         "ec/tls-server",
		Algorithm:       "ecdsa-p256",
		AlgorithmFamily: "ec",
		Serial:          "0x02",
	})

	// Create profile files for v2
	profileDir2 := vs.ProfileDir(v2.ID, "ec")
	_ = os.MkdirAll(profileDir2, 0755)
	_ = os.WriteFile(filepath.Join(profileDir2, "certificates.pem"), []byte("v2 cert"), 0644)

	// Step 6: Activate v2
	if err := vs.Activate(v2.ID); err != nil {
		t.Fatalf("Activate v2 failed: %v", err)
	}

	// Verify v2 is now active
	active, _ = vs.GetActiveVersion()
	if active.ID != v2.ID {
		t.Errorf("expected active version '%s', got '%s'", v2.ID, active.ID)
	}

	// Verify v1 is archived
	v1Loaded, _ := vs.GetVersion(v1.ID)
	if v1Loaded.Status != VersionStatusArchived {
		t.Errorf("expected v1 to be archived, got '%s'", v1Loaded.Status)
	}

	// Verify all versions are listed
	versions, _ := vs.ListVersions()
	if len(versions) != 2 {
		t.Errorf("expected 2 versions, got %d", len(versions))
	}

	// Verify root cert was updated to v2
	rootCert, _ := os.ReadFile(filepath.Join(credPath, "certificates.pem"))
	if string(rootCert) != "v2 cert" {
		t.Errorf("expected root cert to be 'v2 cert', got '%s'", string(rootCert))
	}
}
