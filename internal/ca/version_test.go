package ca

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewVersionStore(t *testing.T) {
	tmpDir := t.TempDir()
	vs := NewVersionStore(tmpDir)

	if vs.basePath != tmpDir {
		t.Errorf("basePath = %v, want %v", vs.basePath, tmpDir)
	}
}

func TestVersionStore_Paths(t *testing.T) {
	tmpDir := t.TempDir()
	vs := NewVersionStore(tmpDir)

	// Test VersionsDir
	expectedVersionsDir := filepath.Join(tmpDir, "versions")
	if got := vs.VersionsDir(); got != expectedVersionsDir {
		t.Errorf("VersionsDir() = %v, want %v", got, expectedVersionsDir)
	}

	// Test IndexPath
	expectedIndexPath := filepath.Join(tmpDir, "versions.json")
	if got := vs.IndexPath(); got != expectedIndexPath {
		t.Errorf("IndexPath() = %v, want %v", got, expectedIndexPath)
	}

	// Test VersionDir
	versionID := "v20251228_abc123"
	expectedVersionDir := filepath.Join(tmpDir, "versions", versionID)
	if got := vs.VersionDir(versionID); got != expectedVersionDir {
		t.Errorf("VersionDir(%s) = %v, want %v", versionID, got, expectedVersionDir)
	}

	// Test CurrentLink
	expectedCurrentLink := filepath.Join(tmpDir, "current")
	if got := vs.CurrentLink(); got != expectedCurrentLink {
		t.Errorf("CurrentLink() = %v, want %v", got, expectedCurrentLink)
	}
}

func TestVersionStore_Init(t *testing.T) {
	tmpDir := t.TempDir()
	vs := NewVersionStore(tmpDir)

	if err := vs.Init(); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	// Check versions directory exists
	if _, err := os.Stat(vs.VersionsDir()); os.IsNotExist(err) {
		t.Error("versions directory should exist after Init()")
	}
}

func TestVersionStore_IsVersioned(t *testing.T) {
	tmpDir := t.TempDir()
	vs := NewVersionStore(tmpDir)

	// Initially not versioned
	if vs.IsVersioned() {
		t.Error("IsVersioned() should return false when no index file exists")
	}

	// Create index file
	if err := os.WriteFile(vs.IndexPath(), []byte(`{"versions":[]}`), 0644); err != nil {
		t.Fatalf("Failed to create index file: %v", err)
	}

	// Now versioned
	if !vs.IsVersioned() {
		t.Error("IsVersioned() should return true when index file exists")
	}
}

func TestVersionStore_LoadIndex_Empty(t *testing.T) {
	tmpDir := t.TempDir()
	vs := NewVersionStore(tmpDir)

	// Load when file doesn't exist - should return empty index
	index, err := vs.LoadIndex()
	if err != nil {
		t.Fatalf("LoadIndex() error = %v", err)
	}

	if len(index.Versions) != 0 {
		t.Errorf("expected empty versions, got %d", len(index.Versions))
	}
	if index.ActiveVersion != "" {
		t.Errorf("expected empty ActiveVersion, got %s", index.ActiveVersion)
	}
}

func TestVersionStore_SaveAndLoadIndex(t *testing.T) {
	tmpDir := t.TempDir()
	vs := NewVersionStore(tmpDir)

	now := time.Now()
	activatedAt := now.Add(-24 * time.Hour)

	index := &VersionIndex{
		ActiveVersion: "v20251228_abc123",
		Versions: []Version{
			{
				ID:          "v20251228_abc123",
				Status:      VersionStatusActive,
				Profiles:    []string{"ml-dsa/root-ca"},
				Certificates: []CertRef{
					{
						Profile:         "ml-dsa/root-ca",
						Algorithm:       "ml-dsa-65",
						AlgorithmFamily: "ml-dsa",
						Subject:         "CN=Test CA",
						NotBefore:       now.Add(-48 * time.Hour),
						NotAfter:        now.Add(365 * 24 * time.Hour),
					},
				},
				Created:     now.Add(-48 * time.Hour),
				ActivatedAt: &activatedAt,
			},
			{
				ID:       "v20251227_def456",
				Status:   VersionStatusArchived,
				Profiles: []string{"ec/root-ca"},
				Certificates: []CertRef{
					{
						Profile:         "ec/root-ca",
						Algorithm:       "ecdsa-p256",
						AlgorithmFamily: "ec",
						Subject:         "CN=Old CA",
						NotBefore:       now.Add(-72 * time.Hour),
						NotAfter:        now.Add(300 * 24 * time.Hour),
					},
				},
				Created: now.Add(-72 * time.Hour),
			},
		},
	}

	if err := vs.SaveIndex(index); err != nil {
		t.Fatalf("SaveIndex() error = %v", err)
	}

	// Verify file was created
	if _, err := os.Stat(vs.IndexPath()); os.IsNotExist(err) {
		t.Error("index file should exist after SaveIndex()")
	}

	// Load and verify
	loaded, err := vs.LoadIndex()
	if err != nil {
		t.Fatalf("LoadIndex() error = %v", err)
	}

	if loaded.ActiveVersion != index.ActiveVersion {
		t.Errorf("ActiveVersion = %v, want %v", loaded.ActiveVersion, index.ActiveVersion)
	}
	if len(loaded.Versions) != 2 {
		t.Errorf("len(Versions) = %d, want 2", len(loaded.Versions))
	}

	// Versions should be sorted by creation time (newest first)
	if loaded.Versions[0].ID != "v20251228_abc123" {
		t.Errorf("first version should be newest, got %s", loaded.Versions[0].ID)
	}
}

func TestVersionStore_CreateVersion(t *testing.T) {
	tmpDir := t.TempDir()
	vs := NewVersionStore(tmpDir)

	version, err := vs.CreateVersion([]string{"ml-dsa/root-ca"})
	if err != nil {
		t.Fatalf("CreateVersion() error = %v", err)
	}

	// Check version properties
	if version.ID == "" {
		t.Error("version ID should not be empty")
	}
	if version.Status != VersionStatusPending {
		t.Errorf("Status = %v, want pending", version.Status)
	}
	if len(version.Profiles) != 1 || version.Profiles[0] != "ml-dsa/root-ca" {
		t.Errorf("Profiles = %v, want [ml-dsa/root-ca]", version.Profiles)
	}

	// Check directories were created
	versionDir := vs.VersionDir(version.ID)
	dirs := []string{
		filepath.Join(versionDir, "cross-signed"),
	}
	for _, dir := range dirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			t.Errorf("directory %s should exist", dir)
		}
	}

	// Check version is in index
	index, err := vs.LoadIndex()
	if err != nil {
		t.Fatalf("LoadIndex() error = %v", err)
	}
	if len(index.Versions) != 1 {
		t.Errorf("len(Versions) = %d, want 1", len(index.Versions))
	}
}

func TestVersionStore_GetVersion(t *testing.T) {
	tmpDir := t.TempDir()
	vs := NewVersionStore(tmpDir)

	// Create a version
	created, err := vs.CreateVersion([]string{"ml-dsa/root-ca"})
	if err != nil {
		t.Fatalf("CreateVersion() error = %v", err)
	}

	// Get by ID
	version, err := vs.GetVersion(created.ID)
	if err != nil {
		t.Fatalf("GetVersion() error = %v", err)
	}
	if version.ID != created.ID {
		t.Errorf("ID = %v, want %v", version.ID, created.ID)
	}

	// Get non-existent
	_, err = vs.GetVersion("non-existent")
	if err == nil {
		t.Error("GetVersion() should fail for non-existent version")
	}
}

func TestVersionStore_GetActiveVersion(t *testing.T) {
	tmpDir := t.TempDir()
	vs := NewVersionStore(tmpDir)

	// No active version initially
	_, err := vs.GetActiveVersion()
	if err == nil {
		t.Error("GetActiveVersion() should fail when no active version")
	}

	// Create and set active version manually for this test
	created, err := vs.CreateVersion([]string{"ml-dsa/root-ca"})
	if err != nil {
		t.Fatalf("CreateVersion() error = %v", err)
	}

	// Update index to set active version
	index, _ := vs.LoadIndex()
	index.ActiveVersion = created.ID
	for i := range index.Versions {
		if index.Versions[i].ID == created.ID {
			index.Versions[i].Status = VersionStatusActive
		}
	}
	if err := vs.SaveIndex(index); err != nil {
		t.Fatalf("SaveIndex() error = %v", err)
	}

	// Now should work
	active, err := vs.GetActiveVersion()
	if err != nil {
		t.Fatalf("GetActiveVersion() error = %v", err)
	}
	if active.ID != created.ID {
		t.Errorf("ActiveVersion ID = %v, want %v", active.ID, created.ID)
	}
}

func TestVersionStore_ListVersions(t *testing.T) {
	tmpDir := t.TempDir()
	vs := NewVersionStore(tmpDir)

	// Create multiple versions
	for i := 0; i < 3; i++ {
		_, err := vs.CreateVersion([]string{"ml-dsa/root-ca"})
		if err != nil {
			t.Fatalf("CreateVersion() error = %v", err)
		}
		time.Sleep(10 * time.Millisecond) // Ensure different creation times
	}

	versions, err := vs.ListVersions()
	if err != nil {
		t.Fatalf("ListVersions() error = %v", err)
	}

	if len(versions) != 3 {
		t.Errorf("len(versions) = %d, want 3", len(versions))
	}
}

func TestVersionStore_AddCrossSignedBy(t *testing.T) {
	tmpDir := t.TempDir()
	vs := NewVersionStore(tmpDir)

	// Create two versions
	v1, err := vs.CreateVersion([]string{"ec/root-ca"})
	if err != nil {
		t.Fatalf("CreateVersion(v1) error = %v", err)
	}

	v2, err := vs.CreateVersion([]string{"ml-dsa/root-ca"})
	if err != nil {
		t.Fatalf("CreateVersion(v2) error = %v", err)
	}

	// Add cross-signing
	if err := vs.AddCrossSignedBy(v2.ID, v1.ID); err != nil {
		t.Fatalf("AddCrossSignedBy() error = %v", err)
	}

	// Verify
	updated, err := vs.GetVersion(v2.ID)
	if err != nil {
		t.Fatalf("GetVersion() error = %v", err)
	}
	if len(updated.CrossSignedBy) != 1 {
		t.Errorf("len(CrossSignedBy) = %d, want 1", len(updated.CrossSignedBy))
	}
	if updated.CrossSignedBy[0] != v1.ID {
		t.Errorf("CrossSignedBy[0] = %v, want %v", updated.CrossSignedBy[0], v1.ID)
	}

	// Adding same signer again should be idempotent
	if err := vs.AddCrossSignedBy(v2.ID, v1.ID); err != nil {
		t.Fatalf("AddCrossSignedBy() (duplicate) error = %v", err)
	}
	updated, _ = vs.GetVersion(v2.ID)
	if len(updated.CrossSignedBy) != 1 {
		t.Errorf("after duplicate: len(CrossSignedBy) = %d, want 1", len(updated.CrossSignedBy))
	}

	// Adding to non-existent version should fail
	if err := vs.AddCrossSignedBy("non-existent", v1.ID); err == nil {
		t.Error("AddCrossSignedBy() should fail for non-existent version")
	}
}

func TestVersionStore_CrossSignedCertPath(t *testing.T) {
	tmpDir := t.TempDir()
	vs := NewVersionStore(tmpDir)

	path := vs.CrossSignedCertPath("v20251228_abc123", "v20251227_def456")
	expected := filepath.Join(tmpDir, "versions", "v20251228_abc123", "cross-signed", "by-v20251227_def456.crt")

	if path != expected {
		t.Errorf("CrossSignedCertPath() = %v, want %v", path, expected)
	}
}

func TestGenerateVersionID(t *testing.T) {
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

func TestVersionStore_SequentialVersionIDs(t *testing.T) {
	tmpDir := t.TempDir()
	vs := NewVersionStore(tmpDir)

	// Create first version - should be v2 (v1 = original CA)
	v1, err := vs.CreateVersion([]string{"ec/root-ca"})
	if err != nil {
		t.Fatalf("CreateVersion failed: %v", err)
	}
	if v1.ID != "v2" {
		t.Errorf("first version should be 'v2', got '%s'", v1.ID)
	}

	// Create second version - should be v3
	v2, err := vs.CreateVersion([]string{"ec/root-ca"})
	if err != nil {
		t.Fatalf("CreateVersion failed: %v", err)
	}
	if v2.ID != "v3" {
		t.Errorf("second version should be 'v3', got '%s'", v2.ID)
	}

	// Verify NextVersion in index
	index, _ := vs.LoadIndex()
	if index.NextVersion != 4 {
		t.Errorf("expected NextVersion 4, got %d", index.NextVersion)
	}
}

func TestCopyFile(t *testing.T) {
	tmpDir := t.TempDir()

	srcPath := filepath.Join(tmpDir, "src.txt")
	dstPath := filepath.Join(tmpDir, "dst.txt")

	content := []byte("test content")
	if err := os.WriteFile(srcPath, content, 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	if err := copyFile(srcPath, dstPath); err != nil {
		t.Fatalf("copyFile() error = %v", err)
	}

	// Verify content
	copied, err := os.ReadFile(dstPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(copied) != string(content) {
		t.Errorf("copied content = %q, want %q", copied, content)
	}

	// Test copying non-existent file
	if err := copyFile(filepath.Join(tmpDir, "nonexistent"), dstPath); err == nil {
		t.Error("copyFile() should fail for non-existent source")
	}
}

func TestVersionStore_Activate(t *testing.T) {
	tmpDir := t.TempDir()
	vs := NewVersionStore(tmpDir)

	// Create a version with a profile
	version, err := vs.CreateVersion([]string{"ml-dsa/root-ca"})
	if err != nil {
		t.Fatalf("CreateVersion() error = %v", err)
	}

	// Add a certificate reference (needed for syncToRoot to work)
	now := time.Now()
	certRef := CertRef{
		Profile:         "ml-dsa/root-ca",
		Algorithm:       "ml-dsa-65",
		AlgorithmFamily: "ml-dsa",
		Subject:         "CN=Test CA",
		NotBefore:       now,
		NotAfter:        now.Add(365 * 24 * time.Hour),
	}
	if err := vs.AddCertificate(version.ID, certRef); err != nil {
		t.Fatalf("AddCertificate() error = %v", err)
	}

	// Create required files in the profile directory (multi-profile structure)
	profileDir := vs.ProfileDir(version.ID, "ml-dsa")
	caContent := []byte("FAKE CA CERT")
	keyContent := []byte("FAKE CA KEY")

	if err := os.MkdirAll(profileDir, 0755); err != nil {
		t.Fatalf("MkdirAll(profileDir) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(profileDir, "ca.crt"), caContent, 0644); err != nil {
		t.Fatalf("WriteFile(ca.crt) error = %v", err)
	}
	if err := os.MkdirAll(filepath.Join(profileDir, "private"), 0755); err != nil {
		t.Fatalf("MkdirAll(private) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(profileDir, "private", "ca.key"), keyContent, 0600); err != nil {
		t.Fatalf("WriteFile(ca.key) error = %v", err)
	}

	// Activate
	if err := vs.Activate(version.ID); err != nil {
		t.Fatalf("Activate() error = %v", err)
	}

	// Verify status changed
	index, err := vs.LoadIndex()
	if err != nil {
		t.Fatalf("LoadIndex() error = %v", err)
	}
	if index.ActiveVersion != version.ID {
		t.Errorf("ActiveVersion = %v, want %v", index.ActiveVersion, version.ID)
	}

	for _, v := range index.Versions {
		if v.ID == version.ID {
			if v.Status != VersionStatusActive {
				t.Errorf("version status = %v, want active", v.Status)
			}
			if v.ActivatedAt == nil {
				t.Error("ActivatedAt should be set")
			}
		}
	}

	// Files should be in the active/ directory
	if _, err := os.Stat(filepath.Join(vs.ActiveDir(), "ml-dsa", "ca.crt")); os.IsNotExist(err) {
		t.Error("active/ml-dsa/ca.crt should exist after activation")
	}
	if _, err := os.Stat(filepath.Join(vs.ActiveDir(), "ml-dsa", "private", "ca.key")); os.IsNotExist(err) {
		t.Error("active/ml-dsa/private/ca.key should exist after activation")
	}

	// Current link should exist
	if _, err := os.Lstat(vs.CurrentLink()); os.IsNotExist(err) {
		t.Error("current symlink should exist")
	}

	// Can't activate an already active version
	if err := vs.Activate(version.ID); err == nil {
		t.Error("Activate() should fail for already active version")
	}

	// Can't activate non-existent version
	if err := vs.Activate("non-existent"); err == nil {
		t.Error("Activate() should fail for non-existent version")
	}
}

func TestVersionStore_Activate_SyncsMetadataToRoot(t *testing.T) {
	tmpDir := t.TempDir()
	vs := NewVersionStore(tmpDir)

	// Create a version
	version, err := vs.CreateVersion([]string{"ml-dsa/root-ca"})
	if err != nil {
		t.Fatalf("CreateVersion() error = %v", err)
	}

	// Add a certificate reference
	now := time.Now()
	certRef := CertRef{
		Profile:         "ml-dsa/root-ca",
		Algorithm:       "ml-dsa-65",
		AlgorithmFamily: "ml-dsa",
		Subject:         "CN=Test CA",
		NotBefore:       now,
		NotAfter:        now.Add(365 * 24 * time.Hour),
	}
	if err := vs.AddCertificate(version.ID, certRef); err != nil {
		t.Fatalf("AddCertificate() error = %v", err)
	}

	// Create required files in the profile directory including metadata
	profileDir := vs.ProfileDir(version.ID, "ml-dsa")
	caContent := []byte("FAKE CA CERT")
	keyContent := []byte("FAKE CA KEY")
	metaContent := []byte(`{"version":1,"profiles":["ml-dsa/root-ca"],"keys":[{"algorithm":"ml-dsa-65"}]}`)

	if err := os.MkdirAll(profileDir, 0755); err != nil {
		t.Fatalf("MkdirAll(profileDir) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(profileDir, "ca.crt"), caContent, 0644); err != nil {
		t.Fatalf("WriteFile(ca.crt) error = %v", err)
	}
	if err := os.MkdirAll(filepath.Join(profileDir, "private"), 0755); err != nil {
		t.Fatalf("MkdirAll(private) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(profileDir, "private", "ca.key"), keyContent, 0600); err != nil {
		t.Fatalf("WriteFile(ca.key) error = %v", err)
	}
	// Create metadata file in profile directory
	if err := os.WriteFile(filepath.Join(profileDir, MetadataFile), metaContent, 0644); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", MetadataFile, err)
	}

	// Activate the version
	if err := vs.Activate(version.ID); err != nil {
		t.Fatalf("Activate() error = %v", err)
	}

	// Verify metadata was copied to active/ directory (critical for crypto-agility)
	activeMeta := filepath.Join(vs.ActiveDir(), "ml-dsa", MetadataFile)
	if _, err := os.Stat(activeMeta); os.IsNotExist(err) {
		t.Errorf("active/ml-dsa/%s should exist after activation", MetadataFile)
	}

	// Verify content matches
	gotContent, err := os.ReadFile(activeMeta)
	if err != nil {
		t.Fatalf("ReadFile(active metadata) error = %v", err)
	}
	if string(gotContent) != string(metaContent) {
		t.Errorf("Active metadata content mismatch:\ngot: %s\nwant: %s", gotContent, metaContent)
	}
}

func TestVersionStore_LoadIndex_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	vs := NewVersionStore(tmpDir)

	// Write invalid JSON
	if err := os.WriteFile(vs.IndexPath(), []byte("invalid json"), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, err := vs.LoadIndex()
	if err == nil {
		t.Error("LoadIndex() should fail for invalid JSON")
	}
}

// =============================================================================
// GetCertForAlgo Unit Tests
// =============================================================================

func TestVersionStore_GetCertForAlgo(t *testing.T) {
	tmpDir := t.TempDir()
	vs := NewVersionStore(tmpDir)

	// Create a version with multiple certificates
	version, err := vs.CreateVersion([]string{"ec/root-ca", "ml-dsa/root-ca"})
	if err != nil {
		t.Fatalf("CreateVersion() error = %v", err)
	}

	now := time.Now()
	// Add EC certificate
	ecCertRef := CertRef{
		Profile:         "ec/root-ca",
		Algorithm:       "ecdsa-p256",
		AlgorithmFamily: "ec",
		Subject:         "CN=EC Root CA",
		NotBefore:       now,
		NotAfter:        now.Add(365 * 24 * time.Hour),
	}
	if err := vs.AddCertificate(version.ID, ecCertRef); err != nil {
		t.Fatalf("AddCertificate(ec) error = %v", err)
	}

	// Add ML-DSA certificate
	pqcCertRef := CertRef{
		Profile:         "ml-dsa/root-ca",
		Algorithm:       "ml-dsa-65",
		AlgorithmFamily: "ml-dsa",
		Subject:         "CN=ML-DSA Root CA",
		NotBefore:       now,
		NotAfter:        now.Add(365 * 24 * time.Hour),
	}
	if err := vs.AddCertificate(version.ID, pqcCertRef); err != nil {
		t.Fatalf("AddCertificate(ml-dsa) error = %v", err)
	}

	// Test GetCertForAlgo for EC
	ecCert, err := vs.GetCertForAlgo(version.ID, "ec")
	if err != nil {
		t.Fatalf("GetCertForAlgo(ec) error = %v", err)
	}
	if ecCert.AlgorithmFamily != "ec" {
		t.Errorf("GetCertForAlgo(ec) returned %s, want ec", ecCert.AlgorithmFamily)
	}

	// Test GetCertForAlgo for ML-DSA
	pqcCert, err := vs.GetCertForAlgo(version.ID, "ml-dsa")
	if err != nil {
		t.Fatalf("GetCertForAlgo(ml-dsa) error = %v", err)
	}
	if pqcCert.AlgorithmFamily != "ml-dsa" {
		t.Errorf("GetCertForAlgo(ml-dsa) returned %s, want ml-dsa", pqcCert.AlgorithmFamily)
	}

	// Test GetCertForAlgo for non-existent algorithm
	_, err = vs.GetCertForAlgo(version.ID, "rsa")
	if err == nil {
		t.Error("GetCertForAlgo(rsa) should fail for non-existent algorithm")
	}
}

func TestVersionStore_GetCertForAlgo_NonExistentVersion(t *testing.T) {
	tmpDir := t.TempDir()
	vs := NewVersionStore(tmpDir)

	_, err := vs.GetCertForAlgo("non-existent", "ec")
	if err == nil {
		t.Error("GetCertForAlgo() should fail for non-existent version")
	}
}

func TestVersionStore_GetActiveCertForAlgo(t *testing.T) {
	tmpDir := t.TempDir()
	vs := NewVersionStore(tmpDir)

	// Create and activate a version
	version, err := vs.CreateVersion([]string{"ec/root-ca"})
	if err != nil {
		t.Fatalf("CreateVersion() error = %v", err)
	}

	now := time.Now()
	ecCertRef := CertRef{
		Profile:         "ec/root-ca",
		Algorithm:       "ecdsa-p256",
		AlgorithmFamily: "ec",
		Subject:         "CN=EC Root CA",
		NotBefore:       now,
		NotAfter:        now.Add(365 * 24 * time.Hour),
	}
	if err := vs.AddCertificate(version.ID, ecCertRef); err != nil {
		t.Fatalf("AddCertificate() error = %v", err)
	}

	// Setup files for activation
	profileDir := vs.ProfileDir(version.ID, "ec")
	if err := os.MkdirAll(profileDir, 0755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(profileDir, "ca.crt"), []byte("FAKE"), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.MkdirAll(filepath.Join(profileDir, "private"), 0755); err != nil {
		t.Fatalf("MkdirAll(private) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(profileDir, "private", "ca.key"), []byte("KEY"), 0600); err != nil {
		t.Fatalf("WriteFile(key) error = %v", err)
	}

	// Activate version
	if err := vs.Activate(version.ID); err != nil {
		t.Fatalf("Activate() error = %v", err)
	}

	// Test GetActiveCertForAlgo
	cert, err := vs.GetActiveCertForAlgo("ec")
	if err != nil {
		t.Fatalf("GetActiveCertForAlgo() error = %v", err)
	}
	if cert.AlgorithmFamily != "ec" {
		t.Errorf("GetActiveCertForAlgo() returned %s, want ec", cert.AlgorithmFamily)
	}

	// Test for non-existent algorithm
	_, err = vs.GetActiveCertForAlgo("rsa")
	if err == nil {
		t.Error("GetActiveCertForAlgo(rsa) should fail for non-existent algorithm")
	}
}

func TestVersionStore_GetActiveCertForAlgo_NoActiveVersion(t *testing.T) {
	tmpDir := t.TempDir()
	vs := NewVersionStore(tmpDir)

	// Create but don't activate
	_, err := vs.CreateVersion([]string{"ec/root-ca"})
	if err != nil {
		t.Fatalf("CreateVersion() error = %v", err)
	}

	_, err = vs.GetActiveCertForAlgo("ec")
	if err == nil {
		t.Error("GetActiveCertForAlgo() should fail when no active version")
	}
}

// =============================================================================
// ListAlgorithmFamilies Unit Tests
// =============================================================================

func TestVersionStore_ListAlgorithmFamilies(t *testing.T) {
	tmpDir := t.TempDir()
	vs := NewVersionStore(tmpDir)

	// Create a version with multiple algorithm families
	version, err := vs.CreateVersion([]string{"ec/root-ca", "ml-dsa/root-ca", "rsa/root-ca"})
	if err != nil {
		t.Fatalf("CreateVersion() error = %v", err)
	}

	now := time.Now()
	families := []string{"ec", "ml-dsa", "rsa"}
	for _, family := range families {
		certRef := CertRef{
			Profile:         family + "/root-ca",
			Algorithm:       family + "-algo",
			AlgorithmFamily: family,
			Subject:         "CN=" + family + " Root CA",
			NotBefore:       now,
			NotAfter:        now.Add(365 * 24 * time.Hour),
		}
		if err := vs.AddCertificate(version.ID, certRef); err != nil {
			t.Fatalf("AddCertificate(%s) error = %v", family, err)
		}
	}

	// Setup files for activation
	for _, family := range families {
		profileDir := vs.ProfileDir(version.ID, family)
		if err := os.MkdirAll(profileDir, 0755); err != nil {
			t.Fatalf("MkdirAll() error = %v", err)
		}
		if err := os.WriteFile(filepath.Join(profileDir, "ca.crt"), []byte("FAKE"), 0644); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}
		if err := os.MkdirAll(filepath.Join(profileDir, "private"), 0755); err != nil {
			t.Fatalf("MkdirAll(private) error = %v", err)
		}
		if err := os.WriteFile(filepath.Join(profileDir, "private", "ca.key"), []byte("KEY"), 0600); err != nil {
			t.Fatalf("WriteFile(key) error = %v", err)
		}
	}

	// Activate version
	if err := vs.Activate(version.ID); err != nil {
		t.Fatalf("Activate() error = %v", err)
	}

	// Test ListAlgorithmFamilies
	listedFamilies, err := vs.ListAlgorithmFamilies()
	if err != nil {
		t.Fatalf("ListAlgorithmFamilies() error = %v", err)
	}
	if len(listedFamilies) != 3 {
		t.Errorf("ListAlgorithmFamilies() returned %d families, want 3", len(listedFamilies))
	}

	// Check that all expected families are present
	for _, expected := range families {
		found := false
		for _, actual := range listedFamilies {
			if actual == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("ListAlgorithmFamilies() missing expected family %s", expected)
		}
	}
}

func TestVersionStore_ListAlgorithmFamilies_NoActiveVersion(t *testing.T) {
	tmpDir := t.TempDir()
	vs := NewVersionStore(tmpDir)

	// Create but don't activate
	_, err := vs.CreateVersion([]string{"ec/root-ca"})
	if err != nil {
		t.Fatalf("CreateVersion() error = %v", err)
	}

	_, err = vs.ListAlgorithmFamilies()
	if err == nil {
		t.Error("ListAlgorithmFamilies() should fail when no active version")
	}
}

// =============================================================================
// AddCertificateRef Unit Tests
// =============================================================================

func TestVersionStore_AddCertificateRef(t *testing.T) {
	tmpDir := t.TempDir()
	vs := NewVersionStore(tmpDir)

	version, err := vs.CreateVersion([]string{"hybrid/root-ca"})
	if err != nil {
		t.Fatalf("CreateVersion() error = %v", err)
	}

	now := time.Now()
	certRef := CertRef{
		Profile:         "hybrid/root-ca",
		Algorithm:       "hybrid-ecdsa-mldsa",
		AlgorithmFamily: "hybrid",
		Subject:         "CN=Hybrid Root CA",
		NotBefore:       now,
		NotAfter:        now.Add(365 * 24 * time.Hour),
		Serial:          "0102030405",
	}

	// Add certificate reference
	if err := vs.AddCertificateRef(version.ID, certRef); err != nil {
		t.Fatalf("AddCertificateRef() error = %v", err)
	}

	// Verify it was added
	v, err := vs.GetVersion(version.ID)
	if err != nil {
		t.Fatalf("GetVersion() error = %v", err)
	}
	if len(v.Certificates) != 1 {
		t.Errorf("Version should have 1 certificate, got %d", len(v.Certificates))
	}
	if v.Certificates[0].AlgorithmFamily != "hybrid" {
		t.Errorf("Certificate AlgorithmFamily = %s, want hybrid", v.Certificates[0].AlgorithmFamily)
	}
}

func TestVersionStore_AddCertificateRef_NonExistentVersion(t *testing.T) {
	tmpDir := t.TempDir()
	vs := NewVersionStore(tmpDir)

	now := time.Now()
	certRef := CertRef{
		Profile:         "ec/root-ca",
		Algorithm:       "ecdsa-p256",
		AlgorithmFamily: "ec",
		Subject:         "CN=EC Root CA",
		NotBefore:       now,
		NotAfter:        now.Add(365 * 24 * time.Hour),
	}

	err := vs.AddCertificateRef("non-existent", certRef)
	if err == nil {
		t.Error("AddCertificateRef() should fail for non-existent version")
	}
}
