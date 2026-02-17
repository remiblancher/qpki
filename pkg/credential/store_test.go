package credential

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	pkicrypto "github.com/remiblancher/post-quantum-pki/pkg/crypto"
)

// =============================================================================
// FileStore Tests
// =============================================================================

func TestU_FileStore_SaveAndLoad(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cred := NewCredential("test-save", Subject{CommonName: "Save Test"})
	cred.CreateInitialVersion([]string{"ec/tls-server"}, []string{"ec"})
	ver := cred.Versions["v1"]
	ver.NotBefore = testNow()
	ver.NotAfter = testNow().AddDate(1, 0, 0)
	cred.Versions["v1"] = ver

	// Generate test certificate
	cert := generateTestCertificate(t)

	// Save
	if err := store.Save(context.Background(), cred, []*x509.Certificate{cert}, nil, nil); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Load
	loaded, err := store.Load(context.Background(), "test-save")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if loaded.ID != cred.ID {
		t.Errorf("ID mismatch: %s vs %s", loaded.ID, cred.ID)
	}
	if loaded.Subject.CommonName != cred.Subject.CommonName {
		t.Errorf("Subject mismatch")
	}
}

func TestU_FileStore_LoadCertificates(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cred := NewCredential("test-certs", Subject{CommonName: "Certs Test"})
	cert := generateTestCertificate(t)

	if err := store.Save(context.Background(), cred, []*x509.Certificate{cert}, nil, nil); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	certs, err := store.LoadCertificates(context.Background(), "test-certs")
	if err != nil {
		t.Fatalf("LoadCertificates failed: %v", err)
	}

	if len(certs) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(certs))
	}
}

func TestU_FileStore_ListAll(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create multiple credentials
	for i := 1; i <= 3; i++ {
		cred := NewCredential(
			"credential-"+string(rune('a'+i-1)),
			Subject{CommonName: "Test"},
		)
		cred.CreateInitialVersion([]string{"ec/tls-server"}, []string{"ec"})
		if err := store.Save(context.Background(), cred, nil, nil, nil); err != nil {
			t.Fatalf("Save failed: %v", err)
		}
	}

	credentials, err := store.ListAll(context.Background())
	if err != nil {
		t.Fatalf("ListAll failed: %v", err)
	}

	if len(credentials) != 3 {
		t.Errorf("expected 3 credentials, got %d", len(credentials))
	}
}

func TestU_FileStore_List(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create credentials with different subjects
	cred1 := NewCredential("credential-alice", Subject{CommonName: "Alice"})
	cred2 := NewCredential("credential-bob", Subject{CommonName: "Bob"})
	cred3 := NewCredential("credential-alice2", Subject{CommonName: "Alice Smith"})

	_ = store.Save(context.Background(), cred1, nil, nil, nil)
	_ = store.Save(context.Background(), cred2, nil, nil, nil)
	_ = store.Save(context.Background(), cred3, nil, nil, nil)

	// List with filter
	ids, err := store.List(context.Background(), "Alice")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if len(ids) != 2 {
		t.Errorf("expected 2 credentials matching 'Alice', got %d", len(ids))
	}

	// List all
	allIds, err := store.List(context.Background(), "")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if len(allIds) != 3 {
		t.Errorf("expected 3 credentials, got %d", len(allIds))
	}
}

func TestU_FileStore_UpdateStatus(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cred := NewCredential("test-status", Subject{CommonName: "Status Test"})
	cred.CreateInitialVersion([]string{"ec/tls-server"}, []string{"ec"})

	if err := store.Save(context.Background(), cred, nil, nil, nil); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Update status
	if err := store.UpdateStatus(context.Background(), "test-status", StatusRevoked, "keyCompromise"); err != nil {
		t.Fatalf("UpdateStatus failed: %v", err)
	}

	// Reload and verify
	loaded, err := store.Load(context.Background(), "test-status")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if loaded.RevokedAt == nil {
		t.Errorf("expected credential to be revoked, but RevokedAt is nil")
	}
	if loaded.RevocationReason != "keyCompromise" {
		t.Errorf("expected reason 'keyCompromise', got '%s'", loaded.RevocationReason)
	}
}

func TestU_FileStore_Delete(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cred := NewCredential("test-delete", Subject{CommonName: "Delete Test"})

	if err := store.Save(context.Background(), cred, nil, nil, nil); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	if !store.Exists(context.Background(), "test-delete") {
		t.Error("credential should exist after save")
	}

	if err := store.Delete(context.Background(), "test-delete"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	if store.Exists(context.Background(), "test-delete") {
		t.Error("credential should not exist after delete")
	}
}

func TestU_FileStore_Exists(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	if store.Exists(context.Background(), "nonexistent") {
		t.Error("should return false for nonexistent credential")
	}

	cred := NewCredential("test-exists", Subject{CommonName: "Exists Test"})
	_ = store.Save(context.Background(), cred, nil, nil, nil)

	if !store.Exists(context.Background(), "test-exists") {
		t.Error("should return true for existing credential")
	}
}

func TestU_FileStore_Load_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	_, err := store.Load(context.Background(), "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent credential")
	}
}

func TestU_FileStore_BasePath(t *testing.T) {
	tmpDir := t.TempDir()
	credentialsDir := filepath.Join(tmpDir, "credentials")
	store := NewFileStore(credentialsDir)

	if store.BasePath() != credentialsDir {
		t.Errorf("expected basePath '%s', got '%s'", credentialsDir, store.BasePath())
	}
}

func TestU_FileStore_Init(t *testing.T) {
	tmpDir := t.TempDir()
	credentialsDir := filepath.Join(tmpDir, "credentials")
	store := NewFileStore(credentialsDir)

	// Directory shouldn't exist yet
	if _, err := os.Stat(credentialsDir); !os.IsNotExist(err) {
		t.Error("credentials directory should not exist before Init")
	}

	if err := store.Init(); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Directory should exist now
	if _, err := os.Stat(credentialsDir); err != nil {
		t.Error("credentials directory should exist after Init")
	}
}

func TestU_FileStore_ListAll_EmptyDir(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	credentials, err := store.ListAll(context.Background())
	if err != nil {
		t.Fatalf("ListAll failed: %v", err)
	}

	if len(credentials) != 0 {
		t.Errorf("expected 0 credentials for empty directory, got %d", len(credentials))
	}
}

func TestU_FileStore_KeysPath(t *testing.T) {
	tmpDir := t.TempDir()
	credentialsDir := filepath.Join(tmpDir, "credentials")
	store := NewFileStore(credentialsDir)

	expected := filepath.Join(credentialsDir, "test-id", "private-keys.pem")
	actual := store.keysPath("test-id")

	if actual != expected {
		t.Errorf("keysPath mismatch: expected %s, got %s", expected, actual)
	}
}

func TestFileStore_LoadKeys_NoFile(t *testing.T) {
	tmpDir := t.TempDir()
	credentialsDir := filepath.Join(tmpDir, "credentials")
	store := NewFileStore(credentialsDir)

	// Create credential directory without keys file
	credDir := filepath.Join(credentialsDir, "test-cred")
	_ = os.MkdirAll(credDir, 0700)

	signers, err := store.LoadKeys(context.Background(), "test-cred", nil)
	if err != nil {
		t.Fatalf("LoadKeys should not error for missing file: %v", err)
	}
	if signers != nil {
		t.Errorf("expected nil signers for missing file, got %d", len(signers))
	}
}

func TestFileStore_LoadKeys_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	credentialsDir := filepath.Join(tmpDir, "credentials")
	store := NewFileStore(credentialsDir)

	// Create credential directory with empty keys file
	credDir := filepath.Join(credentialsDir, "test-cred")
	_ = os.MkdirAll(credDir, 0700)
	_ = os.WriteFile(filepath.Join(credDir, "private-keys.pem"), []byte{}, 0600)

	signers, err := store.LoadKeys(context.Background(), "test-cred", nil)
	if err != nil {
		t.Fatalf("LoadKeys failed: %v", err)
	}
	if len(signers) != 0 {
		t.Errorf("expected 0 signers for empty file, got %d", len(signers))
	}
}

func TestFileStore_Save_Full(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cred := NewCredential("save-test", Subject{CommonName: "Test"})
	cert := generateTestCertificate(t)
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := pkicrypto.NewSoftwareSigner(&pkicrypto.KeyPair{
		Algorithm:  pkicrypto.AlgECDSAP256,
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	})

	err := store.Save(context.Background(), cred, []*x509.Certificate{cert}, []pkicrypto.Signer{signer}, []byte("password"))
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Verify files exist
	if _, err := os.Stat(store.metadataPath(cred.ID)); os.IsNotExist(err) {
		t.Error("metadata file should exist")
	}
	if _, err := os.Stat(store.certsPath(cred.ID)); os.IsNotExist(err) {
		t.Error("certificates file should exist")
	}
	if _, err := os.Stat(store.keysPath(cred.ID)); os.IsNotExist(err) {
		t.Error("keys file should exist")
	}
}

func TestFileStore_Save_NoCerts(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cred := NewCredential("save-nocerts", Subject{CommonName: "Test"})

	err := store.Save(context.Background(), cred, nil, nil, nil)
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Verify metadata exists but certs file does not
	if _, err := os.Stat(store.metadataPath(cred.ID)); os.IsNotExist(err) {
		t.Error("metadata file should exist")
	}
	if _, err := os.Stat(store.certsPath(cred.ID)); !os.IsNotExist(err) {
		t.Error("certificates file should not exist when no certs provided")
	}
}

func TestFileStore_Load_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	credentialsDir := filepath.Join(tmpDir, "credentials")
	store := NewFileStore(credentialsDir)

	// Create credential directory with invalid JSON
	credDir := filepath.Join(credentialsDir, "bad-json")
	_ = os.MkdirAll(credDir, 0700)
	_ = os.WriteFile(filepath.Join(credDir, "credential.meta.json"), []byte("not json"), 0644)

	_, err := store.Load(context.Background(), "bad-json")
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
	if !contains(err.Error(), "failed to parse") {
		t.Errorf("expected 'failed to parse' error, got: %v", err)
	}
}

func TestFileStore_LoadCertificates_InvalidPEM(t *testing.T) {
	tmpDir := t.TempDir()
	credentialsDir := filepath.Join(tmpDir, "credentials")
	store := NewFileStore(credentialsDir)

	// Create credential directory with invalid PEM
	credDir := filepath.Join(credentialsDir, "bad-pem")
	_ = os.MkdirAll(credDir, 0700)
	_ = os.WriteFile(filepath.Join(credDir, "certificates.pem"), []byte("not a pem"), 0644)

	certs, err := store.LoadCertificates(context.Background(), "bad-pem")
	// Should return empty slice, not error for invalid PEM
	if err != nil {
		t.Fatalf("LoadCertificates failed: %v", err)
	}
	if len(certs) != 0 {
		t.Errorf("expected 0 certs for invalid PEM, got %d", len(certs))
	}
}

func TestFileStore_Delete_Success(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create a credential
	cred := NewCredential("delete-test", Subject{CommonName: "Test"})
	_ = store.Save(context.Background(), cred, nil, nil, nil)

	// Verify it exists
	if !store.Exists(context.Background(), cred.ID) {
		t.Fatal("credential should exist before delete")
	}

	// Delete
	err := store.Delete(context.Background(), cred.ID)
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Verify it's gone
	if store.Exists(context.Background(), cred.ID) {
		t.Error("credential should not exist after delete")
	}
}

func TestFileStore_Delete_NotExists(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Delete non-existent should not error
	err := store.Delete(context.Background(), "nonexistent")
	if err != nil {
		t.Errorf("Delete non-existent should not error: %v", err)
	}
}

func TestFileStore_UpdateStatus_Revoke(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create a credential
	cred := NewCredential("status-test", Subject{CommonName: "Test"})
	cred.CreateInitialVersion([]string{"ec/tls-server"}, []string{"ec"})
	_ = store.Save(context.Background(), cred, nil, nil, nil)

	// Revoke
	err := store.UpdateStatus(context.Background(), cred.ID, StatusRevoked, "key compromise")
	if err != nil {
		t.Fatalf("UpdateStatus failed: %v", err)
	}

	// Verify status
	loaded, _ := store.Load(context.Background(), cred.ID)
	if loaded.RevokedAt == nil {
		t.Errorf("expected credential to be revoked, but RevokedAt is nil")
	}
	if loaded.RevocationReason != "key compromise" {
		t.Errorf("expected revoke reason 'key compromise', got %s", loaded.RevocationReason)
	}
}

func TestFileStore_UpdateStatus_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	err := store.UpdateStatus(context.Background(), "nonexistent", StatusRevoked, "test")
	if err == nil {
		t.Error("expected error for non-existent credential")
	}
}

func TestFileStore_List_WithFilter(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create credentials with different subjects
	cred1 := NewCredential("alice-1", Subject{CommonName: "Alice Smith"})
	cred2 := NewCredential("bob-1", Subject{CommonName: "Bob Jones"})
	_ = store.Save(context.Background(), cred1, nil, nil, nil)
	_ = store.Save(context.Background(), cred2, nil, nil, nil)

	// Filter by "alice"
	ids, err := store.List(context.Background(), "alice")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(ids) != 1 || ids[0] != "alice-1" {
		t.Errorf("expected [alice-1], got %v", ids)
	}
}

func TestFileStore_List_NoMatch(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create a credential
	cred := NewCredential("test-1", Subject{CommonName: "Test"})
	_ = store.Save(context.Background(), cred, nil, nil, nil)

	// Filter that matches nothing
	ids, err := store.List(context.Background(), "nonexistent")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(ids) != 0 {
		t.Errorf("expected no matches, got %v", ids)
	}
}

func TestFileStore_List_EmptyDir(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// List on non-existent directory
	ids, err := store.List(context.Background(), "")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(ids) != 0 {
		t.Errorf("expected empty list, got %v", ids)
	}
}

func TestU_FileStore_Save_ContextCancelled(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	cred := NewCredential("test", Subject{CommonName: "Test"})
	err := store.Save(ctx, cred, nil, nil, nil)
	if err == nil {
		t.Error("Save should fail with cancelled context")
	}
	if err != context.Canceled {
		t.Errorf("expected context.Canceled error, got: %v", err)
	}
}

func TestU_FileStore_Load_ContextCancelled(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := store.Load(ctx, "test")
	if err == nil {
		t.Error("Load should fail with cancelled context")
	}
	if err != context.Canceled {
		t.Errorf("expected context.Canceled error, got: %v", err)
	}
}

func TestU_FileStore_LoadCertificates_ContextCancelled(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := store.LoadCertificates(ctx, "test")
	if err == nil {
		t.Error("LoadCertificates should fail with cancelled context")
	}
	if err != context.Canceled {
		t.Errorf("expected context.Canceled error, got: %v", err)
	}
}

func TestU_FileStore_LoadKeys_ContextCancelled(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := store.LoadKeys(ctx, "test", nil)
	if err == nil {
		t.Error("LoadKeys should fail with cancelled context")
	}
	if err != context.Canceled {
		t.Errorf("expected context.Canceled error, got: %v", err)
	}
}

func TestU_FileStore_List_ContextCancelled(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := store.List(ctx, "")
	if err == nil {
		t.Error("List should fail with cancelled context")
	}
	if err != context.Canceled {
		t.Errorf("expected context.Canceled error, got: %v", err)
	}
}

func TestU_FileStore_ListAll_ContextCancelled(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := store.ListAll(ctx)
	if err == nil {
		t.Error("ListAll should fail with cancelled context")
	}
	if err != context.Canceled {
		t.Errorf("expected context.Canceled error, got: %v", err)
	}
}

func TestU_FileStore_Delete_ContextCancelled(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := store.Delete(ctx, "test")
	if err == nil {
		t.Error("Delete should fail with cancelled context")
	}
	if err != context.Canceled {
		t.Errorf("expected context.Canceled error, got: %v", err)
	}
}

func TestU_FileStore_UpdateStatus_ContextCancelled(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := store.UpdateStatus(ctx, "test", StatusRevoked, "test")
	if err == nil {
		t.Error("UpdateStatus should fail with cancelled context")
	}
	if err != context.Canceled {
		t.Errorf("expected context.Canceled error, got: %v", err)
	}
}

func TestU_FileStore_Exists_ContextCancelled(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	exists := store.Exists(ctx, "test")
	if exists {
		t.Error("Exists should return false with cancelled context")
	}
}

func TestU_FileStore_UpdateStatus_Expired(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cred := NewCredential("status-expired", Subject{CommonName: "Test"})
	cred.CreateInitialVersion([]string{"ec/tls-server"}, []string{"ec"})
	_ = store.Save(context.Background(), cred, nil, nil, nil)

	err := store.UpdateStatus(context.Background(), cred.ID, StatusExpired, "")
	if err != nil {
		t.Fatalf("UpdateStatus failed: %v", err)
	}

	loaded, _ := store.Load(context.Background(), cred.ID)
	if ver, ok := loaded.Versions[loaded.Active]; ok {
		// Status is computed from ArchivedAt - verify it's archived
		if ver.ArchivedAt == nil {
			t.Error("expected ArchivedAt to be set for expired status")
		}
	} else {
		t.Error("active version not found")
	}
}

func TestU_FileStore_UpdateStatus_Archived(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cred := NewCredential("status-archived", Subject{CommonName: "Test"})
	cred.CreateInitialVersion([]string{"ec/tls-server"}, []string{"ec"})
	_ = store.Save(context.Background(), cred, nil, nil, nil)

	err := store.UpdateStatus(context.Background(), cred.ID, StatusArchived, "")
	if err != nil {
		t.Fatalf("UpdateStatus failed: %v", err)
	}

	loaded, _ := store.Load(context.Background(), cred.ID)
	if ver, ok := loaded.Versions[loaded.Active]; ok {
		// Status is computed from ArchivedAt - verify it's archived
		if ver.ArchivedAt == nil {
			t.Error("expected ArchivedAt to be set for archived status")
		}
	} else {
		t.Error("active version not found")
	}
}

func TestU_FileStore_LoadCertificates_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create credential directory without certificates file
	credDir := filepath.Join(tmpDir, "no-certs")
	_ = os.MkdirAll(credDir, 0700)

	certs, err := store.LoadCertificates(context.Background(), "no-certs")
	if err != nil {
		t.Fatalf("LoadCertificates should not error for missing file: %v", err)
	}
	if certs != nil {
		t.Errorf("expected nil certs for missing file, got %d", len(certs))
	}
}

func TestU_FileStore_ListAll_NonExistentDir(t *testing.T) {
	tmpDir := t.TempDir()
	nonExistent := filepath.Join(tmpDir, "nonexistent")
	store := NewFileStore(nonExistent)

	credentials, err := store.ListAll(context.Background())
	if err != nil {
		t.Fatalf("ListAll failed: %v", err)
	}
	if len(credentials) != 0 {
		t.Errorf("expected empty credentials, got %d", len(credentials))
	}
}

func TestU_FileStore_List_NonExistentDir(t *testing.T) {
	tmpDir := t.TempDir()
	nonExistent := filepath.Join(tmpDir, "nonexistent")
	store := NewFileStore(nonExistent)

	ids, err := store.List(context.Background(), "")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(ids) != 0 {
		t.Errorf("expected empty ids, got %d", len(ids))
	}
}

func TestU_FileStore_LoadCertificates_Versioned(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create credential
	cred := NewCredential("versioned-certs", Subject{CommonName: "Test"})
	_ = store.Save(context.Background(), cred, nil, nil, nil)

	// Set up versioned structure
	credPath := filepath.Join(tmpDir, cred.ID)
	vs := NewVersionStore(credPath)
	version, _ := vs.CreateVersion([]string{"ec/tls-server"})
	_ = vs.AddCertificate(version.ID, VersionCertRef{AlgorithmFamily: "ec"})
	_ = vs.Activate(version.ID) // Activate the version

	// Create certificates in the new structure (certs/credential.ec.pem)
	certsDir := vs.CertsDir(version.ID)
	_ = os.MkdirAll(certsDir, 0755)

	// Write a valid certificate PEM
	cert := generateTestCertificate(t)
	certPEM, _ := EncodeCertificatesPEM([]*x509.Certificate{cert})
	_ = os.WriteFile(vs.CertPath(version.ID, "ec"), certPEM, 0644)

	// Load certificates through versioned path
	certs, err := store.LoadCertificates(context.Background(), cred.ID)
	if err != nil {
		t.Fatalf("LoadCertificates failed: %v", err)
	}

	if len(certs) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(certs))
	}
}

func TestU_FileStore_LoadKeys_Versioned(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create credential
	cred := NewCredential("versioned-keys", Subject{CommonName: "Test"})
	_ = store.Save(context.Background(), cred, nil, nil, nil)

	// Set up versioned structure
	credPath := filepath.Join(tmpDir, cred.ID)
	vs := NewVersionStore(credPath)
	version, _ := vs.CreateVersion([]string{"ec/tls-server"})
	_ = vs.AddCertificate(version.ID, VersionCertRef{AlgorithmFamily: "ec"})
	_ = vs.Activate(version.ID) // Activate the version

	// Create keys in the new structure (keys/credential.ec.key)
	keysDir := vs.KeysDir(version.ID)
	_ = os.MkdirAll(keysDir, 0700)

	// Write a valid key PEM
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := pkicrypto.NewSoftwareSigner(&pkicrypto.KeyPair{
		Algorithm:  pkicrypto.AlgECDSAP256,
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	})
	keyPEM, _ := EncodePrivateKeysPEM([]pkicrypto.Signer{signer}, nil)
	_ = os.WriteFile(vs.KeyPath(version.ID, "ec"), keyPEM, 0600)

	// Load keys through versioned path
	signers, err := store.LoadKeys(context.Background(), cred.ID, nil)
	if err != nil {
		t.Fatalf("LoadKeys failed: %v", err)
	}

	if len(signers) != 1 {
		t.Errorf("expected 1 signer, got %d", len(signers))
	}
}

func TestU_FileStore_LoadCertificates_Versioned_EmptyActive(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create credential
	cred := NewCredential("versioned-empty", Subject{CommonName: "Test"})
	_ = store.Save(context.Background(), cred, nil, nil, nil)

	// Set up versioned structure with active version but no certificate files
	credPath := filepath.Join(tmpDir, cred.ID)
	vs := NewVersionStore(credPath)
	version, _ := vs.CreateVersion([]string{"ec/tls-server"})
	_ = vs.Activate(version.ID) // Activate but don't write any cert files

	// Load certificates - should return nil for versioned with no cert files
	certs, err := store.LoadCertificates(context.Background(), cred.ID)
	if err != nil {
		t.Fatalf("LoadCertificates failed: %v", err)
	}

	if certs != nil {
		t.Errorf("expected nil certs for empty versioned, got %d", len(certs))
	}
}

func TestU_FileStore_LoadKeys_Versioned_EmptyActive(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create credential
	cred := NewCredential("versioned-keys-empty", Subject{CommonName: "Test"})
	_ = store.Save(context.Background(), cred, nil, nil, nil)

	// Set up versioned structure with active version but no key files
	credPath := filepath.Join(tmpDir, cred.ID)
	vs := NewVersionStore(credPath)
	version, _ := vs.CreateVersion([]string{"ec/tls-server"})
	_ = vs.Activate(version.ID) // Activate but don't write any key files

	// Load keys - should return nil for versioned with no key files
	signers, err := store.LoadKeys(context.Background(), cred.ID, nil)
	if err != nil {
		t.Fatalf("LoadKeys failed: %v", err)
	}

	if signers != nil {
		t.Errorf("expected nil signers for empty versioned, got %d", len(signers))
	}
}

func TestU_FileStore_CertsPath_Versioned(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create credential with version
	cred := NewCredential("certs-path-versioned", Subject{CommonName: "Test"})
	cred.CreateInitialVersion([]string{"ec/tls-server"}, []string{"ec"})
	_ = store.Save(context.Background(), cred, nil, nil, nil)

	// Get certsPath - for versioned credentials, returns versions/{active}/certificates.pem (fallback)
	credPath := filepath.Join(tmpDir, cred.ID)
	path := store.certsPath(cred.ID)
	expected := filepath.Join(credPath, "versions", "v1", "certificates.pem")
	if path != expected {
		t.Errorf("expected certsPath '%s', got '%s'", expected, path)
	}
}

func TestU_FileStore_KeysPath_Versioned(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create credential with version
	cred := NewCredential("keys-path-versioned", Subject{CommonName: "Test"})
	cred.CreateInitialVersion([]string{"ec/tls-server"}, []string{"ec"})
	_ = store.Save(context.Background(), cred, nil, nil, nil)

	// Get keysPath - for versioned credentials, returns versions/{active}/private-keys.pem (fallback)
	credPath := filepath.Join(tmpDir, cred.ID)
	path := store.keysPath(cred.ID)
	expected := filepath.Join(credPath, "versions", "v1", "private-keys.pem")
	if path != expected {
		t.Errorf("expected keysPath '%s', got '%s'", expected, path)
	}
}

func TestU_FileStore_LoadCertificates_Versioned_MultipleAlgos(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create credential with active version containing multiple algos
	cred := NewCredential("versioned-multi-algo", Subject{CommonName: "Test"})
	cred.CreateInitialVersion([]string{"ec/tls-server", "rsa/tls-server"}, []string{"ec", "rsa"})
	_ = store.Save(context.Background(), cred, nil, nil, nil)

	// Create certificate files in new structure (certs/ directory)
	credPath := filepath.Join(tmpDir, cred.ID)
	certsDir := filepath.Join(credPath, "versions", "v1", "certs")
	_ = os.MkdirAll(certsDir, 0755)

	cert := generateTestCertificate(t)
	certPEM, _ := EncodeCertificatesPEM([]*x509.Certificate{cert})

	for _, algo := range []string{"ec", "rsa"} {
		certPath := filepath.Join(certsDir, fmt.Sprintf("credential.%s.pem", algo))
		_ = os.WriteFile(certPath, certPEM, 0644)
	}

	// Load certificates - should get certs from both files
	certs, err := store.LoadCertificates(context.Background(), cred.ID)
	if err != nil {
		t.Fatalf("LoadCertificates failed: %v", err)
	}

	if len(certs) != 2 {
		t.Errorf("expected 2 certificates (one from each algo), got %d", len(certs))
	}
}
