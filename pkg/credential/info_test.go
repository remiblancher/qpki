package credential

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pkicrypto "github.com/remiblancher/qpki/pkg/crypto"
)

// =============================================================================
// Helper Functions
// =============================================================================

// createTestCredential creates a credential with the given ID at the given path.
func createTestCredential(t *testing.T, basePath, credID string) *Credential {
	t.Helper()
	credPath := filepath.Join(basePath, credID)
	if err := os.MkdirAll(credPath, 0755); err != nil {
		t.Fatalf("failed to create cred path: %v", err)
	}
	cred := NewCredential(credID, Subject{CommonName: "Test"})
	cred.SetBasePath(credPath)
	if err := cred.Save(); err != nil {
		t.Fatalf("failed to save credential: %v", err)
	}
	return cred
}

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
		t.Error("should not be versioned when no credential with versions exists")
	}
}

func TestU_VersionStore_IsVersioned_True(t *testing.T) {
	tmpDir := t.TempDir()
	_ = createTestCredential(t, tmpDir, "test-cred")
	credPath := filepath.Join(tmpDir, "test-cred")
	vs := NewVersionStore(credPath)

	// Create initial version
	_, err := vs.CreateInitialVersion([]string{"ec/tls-server"})
	if err != nil {
		t.Fatalf("CreateInitialVersion failed: %v", err)
	}

	if !vs.IsVersioned() {
		t.Error("should be versioned when credential has versions")
	}
}

func TestU_VersionStore_LoadIndex_Empty(t *testing.T) {
	tmpDir := t.TempDir()
	credPath := filepath.Join(tmpDir, "test-cred")
	vs := NewVersionStore(credPath)

	// Load index when credential doesn't exist (backward compatibility)
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
	_ = createTestCredential(t, tmpDir, "test-cred")
	credPath := filepath.Join(tmpDir, "test-cred")
	vs := NewVersionStore(credPath)

	// Create initial version
	_, err := vs.CreateInitialVersion([]string{"ec/tls-server"})
	if err != nil {
		t.Fatalf("CreateInitialVersion failed: %v", err)
	}

	// Load index
	loaded, err := vs.LoadIndex()
	if err != nil {
		t.Fatalf("LoadIndex failed: %v", err)
	}

	if loaded.ActiveVersion != "v1" {
		t.Errorf("expected ActiveVersion 'v1', got '%s'", loaded.ActiveVersion)
	}
	if len(loaded.Versions) != 1 {
		t.Errorf("expected 1 version, got %d", len(loaded.Versions))
	}
}

func TestU_VersionStore_CreateVersion(t *testing.T) {
	tmpDir := t.TempDir()
	_ = createTestCredential(t, tmpDir, "test-cred")
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
	// Status is computed from credential, check via LoadIndex
	index, _ := vs.LoadIndex()
	if index.GetVersionStatus(version.ID) != VersionStatusPending {
		t.Errorf("expected status pending, got '%s'", index.GetVersionStatus(version.ID))
	}
	if len(version.Profiles) != 2 {
		t.Errorf("expected 2 profiles, got %d", len(version.Profiles))
	}

	// Verify version directory was created
	if _, err := os.Stat(vs.VersionDir(version.ID)); os.IsNotExist(err) {
		t.Error("version directory should exist")
	}

	// Verify credential was updated
	if len(index.Versions) != 1 {
		t.Errorf("expected 1 version in index, got %d", len(index.Versions))
	}
}

func TestU_VersionStore_CreateVersion_NoProfiles(t *testing.T) {
	tmpDir := t.TempDir()
	_ = createTestCredential(t, tmpDir, "test-cred")
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
	_ = createTestCredential(t, tmpDir, "test-cred")
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

	// Verify certificate was added (via algos)
	loadedVersion, _ := vs.GetVersion(version.ID)
	if len(loadedVersion.Certificates) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(loadedVersion.Certificates))
	}
	if loadedVersion.Certificates[0].AlgorithmFamily != "ec" {
		t.Errorf("expected algorithm family 'ec', got '%s'", loadedVersion.Certificates[0].AlgorithmFamily)
	}
}

func TestU_VersionStore_AddCertificate_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	_ = createTestCredential(t, tmpDir, "test-cred")
	credPath := filepath.Join(tmpDir, "test-cred")
	vs := NewVersionStore(credPath)

	// Create a version first so credential exists
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
	_ = createTestCredential(t, tmpDir, "test-cred")
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
	_ = createTestCredential(t, tmpDir, "test-cred")
	credPath := filepath.Join(tmpDir, "test-cred")
	vs := NewVersionStore(credPath)

	// Create a version first so credential exists
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
	_ = createTestCredential(t, tmpDir, "test-cred")
	credPath := filepath.Join(tmpDir, "test-cred")
	vs := NewVersionStore(credPath)

	// Create and activate version
	version, _ := vs.CreateVersion([]string{"ec/tls-server"})

	// Add a certificate (required for activation)
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
	_ = createTestCredential(t, tmpDir, "test-cred")
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
	_ = createTestCredential(t, tmpDir, "test-cred")
	credPath := filepath.Join(tmpDir, "test-cred")
	vs := NewVersionStore(credPath)

	// Create version with certificates
	version, _ := vs.CreateVersion([]string{"ec/tls-server", "ml-dsa/tls-server"})

	// Add certificates for different algorithm families
	_ = vs.AddCertificate(version.ID, VersionCertRef{
		Profile:         "ec/tls-server",
		Algorithm:       "ecdsa-p256",
		AlgorithmFamily: "ec",
	})
	_ = vs.AddCertificate(version.ID, VersionCertRef{
		Profile:         "ml-dsa/tls-server",
		Algorithm:       "ml-dsa-65",
		AlgorithmFamily: "ml-dsa",
	})

	// Get EC certificate
	ecCert, err := vs.GetCertForAlgo(version.ID, "ec")
	if err != nil {
		t.Fatalf("GetCertForAlgo failed: %v", err)
	}
	if ecCert.AlgorithmFamily != "ec" {
		t.Errorf("expected algorithm family 'ec', got '%s'", ecCert.AlgorithmFamily)
	}

	// Get ML-DSA certificate
	mldsaCert, err := vs.GetCertForAlgo(version.ID, "ml-dsa")
	if err != nil {
		t.Fatalf("GetCertForAlgo failed: %v", err)
	}
	if mldsaCert.AlgorithmFamily != "ml-dsa" {
		t.Errorf("expected algorithm family 'ml-dsa', got '%s'", mldsaCert.AlgorithmFamily)
	}
}

func TestU_VersionStore_GetCertForAlgo_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	_ = createTestCredential(t, tmpDir, "test-cred")
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
	_ = createTestCredential(t, tmpDir, "test-cred")
	credPath := filepath.Join(tmpDir, "test-cred")
	vs := NewVersionStore(credPath)

	// Create and activate version
	version, _ := vs.CreateVersion([]string{"ec/tls-server"})
	_ = vs.AddCertificate(version.ID, VersionCertRef{
		Profile:         "ec/tls-server",
		Algorithm:       "ecdsa-p256",
		AlgorithmFamily: "ec",
	})
	_ = vs.Activate(version.ID)

	// Get active certificate for algorithm
	cert, err := vs.GetActiveCertForAlgo("ec")
	if err != nil {
		t.Fatalf("GetActiveCertForAlgo failed: %v", err)
	}
	if cert.AlgorithmFamily != "ec" {
		t.Errorf("expected algorithm family 'ec', got '%s'", cert.AlgorithmFamily)
	}
}

func TestU_VersionStore_ListAlgorithmFamilies(t *testing.T) {
	tmpDir := t.TempDir()
	_ = createTestCredential(t, tmpDir, "test-cred")
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
	_ = createTestCredential(t, tmpDir, "test-cred")
	credPath := filepath.Join(tmpDir, "test-cred")
	vs := NewVersionStore(credPath)

	// Create version
	version, _ := vs.CreateVersion([]string{"ec/tls-server"})
	_ = vs.AddCertificate(version.ID, VersionCertRef{
		AlgorithmFamily: "ec",
	})

	// Verify initial status (computed from credential)
	indexBefore, _ := vs.LoadIndex()
	if indexBefore.GetVersionStatus(version.ID) != VersionStatusPending {
		t.Errorf("expected pending status before activation, got '%s'", indexBefore.GetVersionStatus(version.ID))
	}

	// Activate
	if err := vs.Activate(version.ID); err != nil {
		t.Fatalf("Activate failed: %v", err)
	}

	// Verify status changed (computed from credential)
	indexAfter, _ := vs.LoadIndex()
	if indexAfter.GetVersionStatus(version.ID) != VersionStatusActive {
		t.Errorf("expected active status after activation, got '%s'", indexAfter.GetVersionStatus(version.ID))
	}
	loadedAfter, _ := vs.GetVersion(version.ID)
	if loadedAfter.ActivatedAt == nil {
		t.Error("ActivatedAt should not be nil after activation")
	}

	// Verify ActiveVersionDir points to the version directory
	activeDir, err := vs.ActiveVersionDir()
	if err != nil {
		t.Fatalf("ActiveVersionDir failed: %v", err)
	}
	expectedDir := vs.VersionDir(version.ID)
	if activeDir != expectedDir {
		t.Errorf("expected ActiveVersionDir '%s', got '%s'", expectedDir, activeDir)
	}
}

func TestU_VersionStore_Activate_Archives_Previous(t *testing.T) {
	tmpDir := t.TempDir()
	_ = createTestCredential(t, tmpDir, "test-cred")
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

	// Verify first version is now archived (status computed from credential)
	index, _ := vs.LoadIndex()
	if index.GetVersionStatus(v1.ID) != VersionStatusArchived {
		t.Errorf("expected first version to be archived, got '%s'", index.GetVersionStatus(v1.ID))
	}
	loadedV1, _ := vs.GetVersion(v1.ID)
	if loadedV1.ArchivedAt == nil {
		t.Error("ArchivedAt should not be nil for archived version")
	}

	// Verify second version is active
	if index.GetVersionStatus(v2.ID) != VersionStatusActive {
		t.Errorf("expected second version to be active, got '%s'", index.GetVersionStatus(v2.ID))
	}
}

func TestU_VersionStore_Activate_AlreadyActive(t *testing.T) {
	tmpDir := t.TempDir()
	_ = createTestCredential(t, tmpDir, "test-cred")
	credPath := filepath.Join(tmpDir, "test-cred")
	vs := NewVersionStore(credPath)

	// Create and activate version
	version, _ := vs.CreateVersion([]string{"ec/tls-server"})
	_ = vs.AddCertificate(version.ID, VersionCertRef{AlgorithmFamily: "ec"})
	_ = vs.Activate(version.ID)

	// Try to activate again - should fail because already active
	err := vs.Activate(version.ID)
	if err == nil {
		t.Error("expected error when activating already active version")
	}
	if !strings.Contains(err.Error(), "already active") {
		t.Errorf("expected 'already active' error, got: %v", err)
	}
}

func TestU_VersionStore_Activate_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	_ = createTestCredential(t, tmpDir, "test-cred")
	credPath := filepath.Join(tmpDir, "test-cred")
	vs := NewVersionStore(credPath)

	// Create a version so credential exists
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
	_ = createTestCredential(t, tmpDir, "test-cred")
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
	testCases := []struct {
		input    int
		expected string
	}{
		{1, "v1"},
		{2, "v2"},
		{10, "v10"},
		{100, "v100"},
	}

	for _, tc := range testCases {
		id := generateVersionID(tc.input)
		if id != tc.expected {
			t.Errorf("generateVersionID(%d) = %s, expected %s", tc.input, id, tc.expected)
		}
	}
}

func TestU_VersionStore_SequentialVersionIDs(t *testing.T) {
	tmpDir := t.TempDir()
	_ = createTestCredential(t, tmpDir, "test-cred")
	credPath := filepath.Join(tmpDir, "test-cred")
	vs := NewVersionStore(credPath)

	// Create first version - should be v2 (since we use NextVersionID which is len+1)
	v1, err := vs.CreateVersion([]string{"ec/tls-server"})
	if err != nil {
		t.Fatalf("CreateVersion failed: %v", err)
	}
	if v1.ID != "v1" {
		t.Errorf("first version should be 'v1', got '%s'", v1.ID)
	}

	// Create second version - should be v2
	v2, err := vs.CreateVersion([]string{"ec/tls-server"})
	if err != nil {
		t.Fatalf("CreateVersion failed: %v", err)
	}
	if v2.ID != "v2" {
		t.Errorf("second version should be 'v2', got '%s'", v2.ID)
	}

	// Create third version - should be v3
	v3, err := vs.CreateVersion([]string{"ec/tls-server"})
	if err != nil {
		t.Fatalf("CreateVersion failed: %v", err)
	}
	if v3.ID != "v3" {
		t.Errorf("third version should be 'v3', got '%s'", v3.ID)
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
// Integration Tests
// =============================================================================

func TestU_Credential_VersionStore_FullWorkflow(t *testing.T) {
	tmpDir := t.TempDir()
	_ = createTestCredential(t, tmpDir, "test-cred")
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

	// Verify v1 is archived (status computed from credential)
	index, _ := vs.LoadIndex()
	if index.GetVersionStatus(v1.ID) != VersionStatusArchived {
		t.Errorf("expected v1 to be archived, got '%s'", index.GetVersionStatus(v1.ID))
	}

	// Verify all versions are listed
	versions, _ := vs.ListVersions()
	if len(versions) != 2 {
		t.Errorf("expected 2 versions, got %d", len(versions))
	}

	// Verify ActiveVersionDir now points to v2
	activeDir, _ := vs.ActiveVersionDir()
	if activeDir != vs.VersionDir(v2.ID) {
		t.Errorf("expected ActiveVersionDir to be v2 directory, got '%s'", activeDir)
	}

	// Verify version directories still contain original files (no data loss)
	v1Cert, _ := os.ReadFile(filepath.Join(vs.VersionDir(v1.ID), "ec", "certificates.pem"))
	if string(v1Cert) != "v1 cert" {
		t.Errorf("v1 version directory should still contain 'v1 cert', got '%s'", string(v1Cert))
	}
	v2Cert, _ := os.ReadFile(filepath.Join(vs.VersionDir(v2.ID), "ec", "certificates.pem"))
	if string(v2Cert) != "v2 cert" {
		t.Errorf("v2 version directory should still contain 'v2 cert', got '%s'", string(v2Cert))
	}
}

// =============================================================================
// Standalone Function Tests
// =============================================================================

func TestU_NewVersionStore(t *testing.T) {
	tmpDir := t.TempDir()
	credentialsDir := filepath.Join(tmpDir, "credentials")

	vs := NewVersionStore(CredentialPath(credentialsDir, "test-cred"))
	if vs == nil {
		t.Fatal("NewVersionStore returned nil")
	}

	expectedBase := filepath.Join(credentialsDir, "test-cred")
	if vs.basePath != expectedBase {
		t.Errorf("expected basePath '%s', got '%s'", expectedBase, vs.basePath)
	}
}

func TestU_FileStore_SaveVersion(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create credential first
	cred := NewCredential("version-test", Subject{CommonName: "Test"})
	if err := store.Save(context.Background(), cred, nil, nil, nil); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Create version store and version
	vs := NewVersionStore(CredentialPath(tmpDir, cred.ID))
	version, err := vs.CreateVersion([]string{"ec/tls-server"})
	if err != nil {
		t.Fatalf("CreateVersion failed: %v", err)
	}

	// Generate test certificate and signer
	cert := generateTestCertificate(t)
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := pkicrypto.NewSoftwareSigner(&pkicrypto.KeyPair{
		Algorithm:  pkicrypto.AlgECDSAP256,
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	})

	// Save version
	err = SaveVersion(tmpDir, cred.ID, version.ID, "ec", []*x509.Certificate{cert}, []pkicrypto.Signer{signer}, nil)
	if err != nil {
		t.Fatalf("SaveVersion failed: %v", err)
	}

	// Verify files were created with new structure
	certPath := vs.CertPath(version.ID, "ec")
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Errorf("certificate file should exist at %s", certPath)
	}
	keyPath := vs.KeyPath(version.ID, "ec")
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Errorf("private key file should exist at %s", keyPath)
	}
}

func TestU_FileStore_SaveVersion_CertsOnly(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create credential and version
	cred := NewCredential("version-certs", Subject{CommonName: "Test"})
	_ = store.Save(context.Background(), cred, nil, nil, nil)

	vs := NewVersionStore(CredentialPath(tmpDir, cred.ID))
	version, _ := vs.CreateVersion([]string{"ec/tls-server"})

	cert := generateTestCertificate(t)

	// Save version with certs only
	err := SaveVersion(tmpDir, cred.ID, version.ID, "ec", []*x509.Certificate{cert}, nil, nil)
	if err != nil {
		t.Fatalf("SaveVersion failed: %v", err)
	}

	// Verify cert file exists but key file doesn't
	certPath := vs.CertPath(version.ID, "ec")
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Errorf("certificate file should exist at %s", certPath)
	}
	keyPath := vs.KeyPath(version.ID, "ec")
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Error("private key file should not exist when no signers provided")
	}
}

func TestU_FileStore_LoadVersionCertificates(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Setup credential and version
	cred := NewCredential("load-version-certs", Subject{CommonName: "Test"})
	_ = store.Save(context.Background(), cred, nil, nil, nil)

	vs := NewVersionStore(CredentialPath(tmpDir, cred.ID))
	version, _ := vs.CreateVersion([]string{"ec/tls-server"})

	cert := generateTestCertificate(t)
	_ = SaveVersion(tmpDir, cred.ID, version.ID, "ec", []*x509.Certificate{cert}, nil, nil)

	// Load version certificates
	certs, err := LoadVersionCertificates(tmpDir, cred.ID, version.ID, "ec")
	if err != nil {
		t.Fatalf("LoadVersionCertificates failed: %v", err)
	}

	if len(certs) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(certs))
	}
}

func TestU_FileStore_LoadVersionCertificates_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Setup credential and version but don't save certs
	cred := NewCredential("load-no-certs", Subject{CommonName: "Test"})
	_ = store.Save(context.Background(), cred, nil, nil, nil)

	vs := NewVersionStore(CredentialPath(tmpDir, cred.ID))
	version, _ := vs.CreateVersion([]string{"ec/tls-server"})

	// Load non-existent certs
	certs, err := LoadVersionCertificates(tmpDir, cred.ID, version.ID, "ec")
	if err != nil {
		t.Fatalf("LoadVersionCertificates should not error for missing file: %v", err)
	}
	if certs != nil {
		t.Errorf("expected nil for missing file, got %d certs", len(certs))
	}
}

func TestU_FileStore_LoadVersionKeys(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Setup credential and version
	cred := NewCredential("load-version-keys", Subject{CommonName: "Test"})
	_ = store.Save(context.Background(), cred, nil, nil, nil)

	vs := NewVersionStore(CredentialPath(tmpDir, cred.ID))
	version, _ := vs.CreateVersion([]string{"ec/tls-server"})

	// Save with keys
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := pkicrypto.NewSoftwareSigner(&pkicrypto.KeyPair{
		Algorithm:  pkicrypto.AlgECDSAP256,
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	})
	_ = SaveVersion(tmpDir, cred.ID, version.ID, "ec", nil, []pkicrypto.Signer{signer}, nil)

	// Load version keys
	signers, err := LoadVersionKeys(tmpDir, cred.ID, version.ID, "ec", nil)
	if err != nil {
		t.Fatalf("LoadVersionKeys failed: %v", err)
	}

	if len(signers) != 1 {
		t.Errorf("expected 1 signer, got %d", len(signers))
	}
}

func TestU_FileStore_LoadVersionKeys_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Setup credential and version but don't save keys
	cred := NewCredential("load-no-keys", Subject{CommonName: "Test"})
	_ = store.Save(context.Background(), cred, nil, nil, nil)

	vs := NewVersionStore(CredentialPath(tmpDir, cred.ID))
	version, _ := vs.CreateVersion([]string{"ec/tls-server"})

	// Load non-existent keys
	signers, err := LoadVersionKeys(tmpDir, cred.ID, version.ID, "ec", nil)
	if err != nil {
		t.Fatalf("LoadVersionKeys should not error for missing file: %v", err)
	}
	if signers != nil {
		t.Errorf("expected nil for missing file, got %d signers", len(signers))
	}
}

func TestU_FileStore_ActivateVersion(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Setup credential and version
	cred := NewCredential("activate-version", Subject{CommonName: "Test"})
	_ = store.Save(context.Background(), cred, nil, nil, nil)

	vs := NewVersionStore(CredentialPath(tmpDir, cred.ID))
	version, _ := vs.CreateVersion([]string{"ec/tls-server"})
	_ = vs.AddCertificate(version.ID, VersionCertRef{AlgorithmFamily: "ec"})

	// Activate via standalone function
	err := ActivateVersion(tmpDir, cred.ID, version.ID)
	if err != nil {
		t.Fatalf("ActivateVersion failed: %v", err)
	}

	// Verify activation (status computed from credential)
	// Create a fresh VersionStore to reload from disk
	vsReloaded := NewVersionStore(CredentialPath(tmpDir, cred.ID))
	index, _ := vsReloaded.LoadIndex()
	if index.GetVersionStatus(version.ID) != VersionStatusActive {
		t.Errorf("expected active status, got '%s'", index.GetVersionStatus(version.ID))
	}
}

func TestU_FileStore_ListVersions(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Setup credential and versions
	cred := NewCredential("list-versions", Subject{CommonName: "Test"})
	_ = store.Save(context.Background(), cred, nil, nil, nil)

	vs := NewVersionStore(CredentialPath(tmpDir, cred.ID))
	_, _ = vs.CreateVersion([]string{"ec/tls-server"})
	_, _ = vs.CreateVersion([]string{"ml-dsa/tls-server"})

	// List via standalone function
	versions, err := ListVersions(tmpDir, cred.ID)
	if err != nil {
		t.Fatalf("ListVersions failed: %v", err)
	}

	if len(versions) != 2 {
		t.Errorf("expected 2 versions, got %d", len(versions))
	}
}

func TestU_FileStore_IsVersioned_False(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create non-versioned credential
	cred := NewCredential("non-versioned", Subject{CommonName: "Test"})
	_ = store.Save(context.Background(), cred, nil, nil, nil)

	if IsVersioned(tmpDir, cred.ID) {
		t.Error("credential should not be versioned")
	}
}

func TestU_FileStore_IsVersioned_True(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create versioned credential
	cred := NewCredential("versioned", Subject{CommonName: "Test"})
	_ = store.Save(context.Background(), cred, nil, nil, nil)

	vs := NewVersionStore(CredentialPath(tmpDir, cred.ID))
	_, _ = vs.CreateVersion([]string{"ec/tls-server"})

	if !IsVersioned(tmpDir, cred.ID) {
		t.Error("credential should be versioned after creating version")
	}
}

// =============================================================================
// CreateInitialVersion Tests
// =============================================================================

func TestU_VersionStore_CreateInitialVersion(t *testing.T) {
	tmpDir := t.TempDir()
	_ = createTestCredential(t, tmpDir, "test-cred")
	credPath := filepath.Join(tmpDir, "test-cred")
	vs := NewVersionStore(credPath)

	// Create initial version
	version, err := vs.CreateInitialVersion([]string{"ec/tls-server"})
	if err != nil {
		t.Fatalf("CreateInitialVersion failed: %v", err)
	}

	// Verify version is v1
	if version.ID != "v1" {
		t.Errorf("expected version ID 'v1', got '%s'", version.ID)
	}

	// Verify status is active (not pending) - computed from credential
	index, _ := vs.LoadIndex()
	if index.GetVersionStatus(version.ID) != VersionStatusActive {
		t.Errorf("expected status active, got '%s'", index.GetVersionStatus(version.ID))
	}

	// Verify ActivatedAt is set
	if version.ActivatedAt == nil {
		t.Error("ActivatedAt should be set for initial version")
	}

	// Verify index was created
	if index.ActiveVersion != "v1" {
		t.Errorf("expected ActiveVersion 'v1', got '%s'", index.ActiveVersion)
	}

	if index.NextVersion != 2 {
		t.Errorf("expected NextVersion 2, got %d", index.NextVersion)
	}
}

func TestU_VersionStore_CreateInitialVersion_NoProfiles(t *testing.T) {
	tmpDir := t.TempDir()
	_ = createTestCredential(t, tmpDir, "test-cred")
	credPath := filepath.Join(tmpDir, "test-cred")
	vs := NewVersionStore(credPath)

	_, err := vs.CreateInitialVersion([]string{})
	if err == nil {
		t.Error("expected error when creating initial version with no profiles")
	}
	if !strings.Contains(err.Error(), "at least one profile") {
		t.Errorf("expected 'at least one profile' error, got: %v", err)
	}
}

// =============================================================================
// MigrateIfNeeded Tests
// =============================================================================

func TestU_VersionStore_MigrateIfNeeded_AlreadyVersioned(t *testing.T) {
	tmpDir := t.TempDir()
	cred := createTestCredential(t, tmpDir, "test-cred")
	credPath := filepath.Join(tmpDir, "test-cred")
	vs := NewVersionStore(credPath)

	// Create versioned credential
	_, _ = vs.CreateInitialVersion([]string{"ec/tls-server"})

	// MigrateIfNeeded should be a no-op
	err := vs.MigrateIfNeeded()
	if err != nil {
		t.Fatalf("MigrateIfNeeded failed: %v", err)
	}

	// Should still be versioned
	if !vs.IsVersioned() {
		t.Error("credential should still be versioned")
	}

	_ = cred // silence unused
}

func TestU_VersionStore_MigrateIfNeeded_NoRootFiles(t *testing.T) {
	tmpDir := t.TempDir()
	_ = createTestCredential(t, tmpDir, "test-cred")
	credPath := filepath.Join(tmpDir, "test-cred")
	vs := NewVersionStore(credPath)

	// MigrateIfNeeded should be a no-op (no root algo dirs)
	err := vs.MigrateIfNeeded()
	if err != nil {
		t.Fatalf("MigrateIfNeeded failed: %v", err)
	}

	// Should not be versioned (no versions created)
	if vs.IsVersioned() {
		t.Error("credential should not be versioned after migrating empty dir")
	}
}

func TestU_VersionStore_MigrateIfNeeded_WithAlgoFamilyDirs(t *testing.T) {
	tmpDir := t.TempDir()
	cred := createTestCredential(t, tmpDir, "test-cred")
	credPath := filepath.Join(tmpDir, "test-cred")
	vs := NewVersionStore(credPath)

	// Create old-style credential with algorithm family directories
	ecDir := filepath.Join(credPath, "ec")
	if err := os.MkdirAll(ecDir, 0755); err != nil {
		t.Fatalf("failed to create ec dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(ecDir, "certificates.pem"), []byte("cert data"), 0644); err != nil {
		t.Fatalf("failed to create cert file: %v", err)
	}

	// Migrate
	err := vs.MigrateIfNeeded()
	if err != nil {
		t.Fatalf("MigrateIfNeeded failed: %v", err)
	}

	// Verify credential is now versioned
	if !vs.IsVersioned() {
		t.Error("credential should be versioned after migration")
	}

	// Verify v1 directory was created
	v1Dir := vs.VersionDir("v1")
	if _, err := os.Stat(v1Dir); os.IsNotExist(err) {
		t.Error("v1 directory should exist after migration")
	}

	// After both migrations (root algo dirs -> versioned, then versioned -> keys/certs),
	// files should be in the new keys/certs structure
	certsDir := vs.CertsDir("v1")
	if _, err := os.Stat(certsDir); os.IsNotExist(err) {
		t.Error("certs directory should exist after migration")
	}

	// Verify certificate file was migrated to new location
	certFile := vs.CertPath("v1", "ec")
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		t.Errorf("certificate file should exist at %s", certFile)
	}

	// Verify original ec dir no longer exists
	if _, err := os.Stat(ecDir); !os.IsNotExist(err) {
		t.Error("original ec directory should be removed after migration")
	}

	// Verify credential has v1 as active
	index, _ := vs.LoadIndex()
	if index.ActiveVersion != "v1" {
		t.Errorf("expected ActiveVersion 'v1', got '%s'", index.ActiveVersion)
	}

	_ = cred // silence unused
}

func TestU_VersionStore_MigrateIfNeeded_MultipleAlgoFamilies(t *testing.T) {
	tmpDir := t.TempDir()
	cred := createTestCredential(t, tmpDir, "test-cred")
	credPath := filepath.Join(tmpDir, "test-cred")
	vs := NewVersionStore(credPath)

	// Create old-style credential with multiple algorithm family directories
	for _, algo := range []string{"ec", "rsa", "ml-dsa"} {
		algoDir := filepath.Join(credPath, algo)
		if err := os.MkdirAll(algoDir, 0755); err != nil {
			t.Fatalf("failed to create %s dir: %v", algo, err)
		}
		if err := os.WriteFile(filepath.Join(algoDir, "certificates.pem"), []byte(algo+" cert"), 0644); err != nil {
			t.Fatalf("failed to create cert file: %v", err)
		}
	}

	// Migrate
	err := vs.MigrateIfNeeded()
	if err != nil {
		t.Fatalf("MigrateIfNeeded failed: %v", err)
	}

	// After both migrations (root algo dirs -> versioned, then versioned -> keys/certs),
	// files should be in the new keys/certs structure
	for _, algo := range []string{"ec", "rsa", "ml-dsa"} {
		certFile := vs.CertPath("v1", algo)
		if _, err := os.Stat(certFile); os.IsNotExist(err) {
			t.Errorf("certificate file for %s should exist at %s", algo, certFile)
		}
	}

	_ = cred // silence unused
}

// =============================================================================
// copyDir Tests
// =============================================================================

func TestU_CopyDir_Success(t *testing.T) {
	tmpDir := t.TempDir()
	srcDir := filepath.Join(tmpDir, "src")
	dstDir := filepath.Join(tmpDir, "dst")

	// Create source directory with files
	if err := os.MkdirAll(filepath.Join(srcDir, "subdir"), 0755); err != nil {
		t.Fatalf("failed to create src dirs: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "file1.txt"), []byte("content1"), 0644); err != nil {
		t.Fatalf("failed to create file1: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "subdir", "file2.txt"), []byte("content2"), 0644); err != nil {
		t.Fatalf("failed to create file2: %v", err)
	}

	// Copy directory
	if err := copyDir(srcDir, dstDir); err != nil {
		t.Fatalf("copyDir failed: %v", err)
	}

	// Verify destination structure
	if _, err := os.Stat(filepath.Join(dstDir, "file1.txt")); os.IsNotExist(err) {
		t.Error("file1.txt should exist in destination")
	}
	if _, err := os.Stat(filepath.Join(dstDir, "subdir", "file2.txt")); os.IsNotExist(err) {
		t.Error("subdir/file2.txt should exist in destination")
	}

	// Verify content
	data, _ := os.ReadFile(filepath.Join(dstDir, "file1.txt"))
	if string(data) != "content1" {
		t.Errorf("expected 'content1', got '%s'", string(data))
	}
}

func TestU_CopyDir_SourceNotFound(t *testing.T) {
	tmpDir := t.TempDir()

	err := copyDir("/nonexistent/source", filepath.Join(tmpDir, "dst"))
	if err == nil {
		t.Error("expected error for non-existent source directory")
	}
}

// =============================================================================
// ActiveDir Path Tests (now reads from versions/{active})
// =============================================================================

func TestU_VersionStore_ActiveDir(t *testing.T) {
	tmpDir := t.TempDir()
	_ = createTestCredential(t, tmpDir, "test-cred")
	credPath := filepath.Join(tmpDir, "test-cred")
	vs := NewVersionStore(credPath)

	// Create and activate v1
	_, _ = vs.CreateInitialVersion([]string{"ec/tls-server"})

	// ActiveDir should return versions/v1 (the active version directory)
	expected := filepath.Join(credPath, "versions", "v1")
	if vs.ActiveDir() != expected {
		t.Errorf("expected ActiveDir '%s', got '%s'", expected, vs.ActiveDir())
	}
}

func TestU_VersionStore_ActiveVersionDir(t *testing.T) {
	tmpDir := t.TempDir()
	_ = createTestCredential(t, tmpDir, "test-cred")
	credPath := filepath.Join(tmpDir, "test-cred")
	vs := NewVersionStore(credPath)

	// Create and activate v1
	_, _ = vs.CreateInitialVersion([]string{"ec/tls-server"})

	// ActiveVersionDir should return versions/v1
	activeDir, err := vs.ActiveVersionDir()
	if err != nil {
		t.Fatalf("ActiveVersionDir failed: %v", err)
	}

	expected := filepath.Join(credPath, "versions", "v1")
	if activeDir != expected {
		t.Errorf("expected ActiveVersionDir '%s', got '%s'", expected, activeDir)
	}
}

func TestU_VersionStore_ActiveVersionDir_NoActive(t *testing.T) {
	tmpDir := t.TempDir()
	credPath := filepath.Join(tmpDir, "test-cred")
	vs := NewVersionStore(credPath)

	// No credential, no active version
	_, err := vs.ActiveVersionDir()
	if err == nil {
		t.Error("expected error when no active version")
	}
	if !strings.Contains(err.Error(), "no active version") {
		t.Errorf("expected 'no active version' error, got: %v", err)
	}
}

// =============================================================================
// Migration from versions.json Tests
// =============================================================================

func TestU_VersionStore_MigrateFromVersionsJSON(t *testing.T) {
	tmpDir := t.TempDir()
	cred := createTestCredential(t, tmpDir, "test-cred")
	credPath := filepath.Join(tmpDir, "test-cred")

	// Create old versions.json file
	versionsJSON := `{
		"versions": [
			{"id": "v1", "profiles": ["ec/tls-server"], "certificates": [{"algorithm_family": "ec"}]}
		],
		"active_version": "v1",
		"next_version": 2
	}`
	if err := os.WriteFile(filepath.Join(credPath, "versions.json"), []byte(versionsJSON), 0644); err != nil {
		t.Fatalf("failed to create versions.json: %v", err)
	}

	// Create old active/ directory (should be removed)
	activeDir := filepath.Join(credPath, "active")
	if err := os.MkdirAll(activeDir, 0755); err != nil {
		t.Fatalf("failed to create active dir: %v", err)
	}

	// Run migration
	vs := NewVersionStore(credPath)
	err := vs.MigrateIfNeeded()
	if err != nil {
		t.Fatalf("MigrateIfNeeded failed: %v", err)
	}

	// Verify versions.json was removed
	if _, err := os.Stat(filepath.Join(credPath, "versions.json")); !os.IsNotExist(err) {
		t.Error("versions.json should be removed after migration")
	}

	// Verify active/ directory was removed
	if _, err := os.Stat(activeDir); !os.IsNotExist(err) {
		t.Error("active/ directory should be removed after migration")
	}

	// Verify credential now has versions
	if !vs.IsVersioned() {
		t.Error("credential should be versioned after migration")
	}

	// Verify v1 is active
	index, _ := vs.LoadIndex()
	if index.ActiveVersion != "v1" {
		t.Errorf("expected ActiveVersion 'v1', got '%s'", index.ActiveVersion)
	}

	_ = cred // silence unused
}
