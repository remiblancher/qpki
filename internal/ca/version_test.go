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
				Profile:     "root-ca",
				Algorithm:   "ml-dsa-65",
				Created:     now.Add(-48 * time.Hour),
				ActivatedAt: &activatedAt,
				Subject:     "CN=Test CA",
				NotBefore:   now.Add(-48 * time.Hour),
				NotAfter:    now.Add(365 * 24 * time.Hour),
			},
			{
				ID:        "v20251227_def456",
				Status:    VersionStatusArchived,
				Profile:   "root-ca",
				Algorithm: "ecdsa-p256",
				Created:   now.Add(-72 * time.Hour),
				Subject:   "CN=Old CA",
				NotBefore: now.Add(-72 * time.Hour),
				NotAfter:  now.Add(300 * 24 * time.Hour),
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

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	version, err := vs.CreateVersion("root-ca", "ml-dsa-65", "CN=Test CA", notBefore, notAfter)
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
	if version.Profile != "root-ca" {
		t.Errorf("Profile = %v, want root-ca", version.Profile)
	}
	if version.Algorithm != "ml-dsa-65" {
		t.Errorf("Algorithm = %v, want ml-dsa-65", version.Algorithm)
	}

	// Check directories were created
	versionDir := vs.VersionDir(version.ID)
	dirs := []string{
		filepath.Join(versionDir, "private"),
		filepath.Join(versionDir, "certs"),
		filepath.Join(versionDir, "crl"),
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
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)
	created, err := vs.CreateVersion("root-ca", "ml-dsa-65", "CN=Test CA", notBefore, notAfter)
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
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)
	created, err := vs.CreateVersion("root-ca", "ml-dsa-65", "CN=Test CA", notBefore, notAfter)
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
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	for i := 0; i < 3; i++ {
		_, err := vs.CreateVersion("root-ca", "ml-dsa-65", "CN=Test CA", notBefore, notAfter)
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

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	// Create two versions
	v1, err := vs.CreateVersion("root-ca", "ecdsa-p256", "CN=Old CA", notBefore, notAfter)
	if err != nil {
		t.Fatalf("CreateVersion(v1) error = %v", err)
	}

	v2, err := vs.CreateVersion("root-ca", "ml-dsa-65", "CN=New CA", notBefore, notAfter)
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
	id1 := generateVersionID()
	id2 := generateVersionID()

	// Check format: v{YYYYMMDD}_{6-char}
	if len(id1) < 16 {
		t.Errorf("version ID too short: %s", id1)
	}
	if id1[0] != 'v' {
		t.Errorf("version ID should start with 'v': %s", id1)
	}

	// IDs should be unique (with high probability)
	if id1 == id2 {
		t.Errorf("generated IDs should be unique: %s == %s", id1, id2)
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

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	// Create a version
	version, err := vs.CreateVersion("root-ca", "ml-dsa-65", "CN=Test CA", notBefore, notAfter)
	if err != nil {
		t.Fatalf("CreateVersion() error = %v", err)
	}

	// Create required files in version directory
	versionDir := vs.VersionDir(version.ID)
	caContent := []byte("FAKE CA CERT")
	keyContent := []byte("FAKE CA KEY")

	if err := os.WriteFile(filepath.Join(versionDir, "ca.crt"), caContent, 0644); err != nil {
		t.Fatalf("WriteFile(ca.crt) error = %v", err)
	}
	if err := os.MkdirAll(filepath.Join(vs.basePath, "private"), 0755); err != nil {
		t.Fatalf("MkdirAll(private) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(versionDir, "private", "ca.key"), keyContent, 0600); err != nil {
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

	// Files should be synced to root
	if _, err := os.Stat(filepath.Join(vs.basePath, "ca.crt")); os.IsNotExist(err) {
		t.Error("ca.crt should be synced to root")
	}
	if _, err := os.Stat(filepath.Join(vs.basePath, "private", "ca.key")); os.IsNotExist(err) {
		t.Error("private/ca.key should be synced to root")
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
