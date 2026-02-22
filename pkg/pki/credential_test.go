package pki

import (
	"context"
	"path/filepath"
	"testing"
)

// =============================================================================
// NewCredentialFileStore Tests
// =============================================================================

func TestU_NewCredentialFileStore(t *testing.T) {
	t.Run("[Unit] NewCredentialFileStore: creates store", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := NewCredentialFileStore(tmpDir)
		if store == nil {
			t.Error("NewCredentialFileStore() returned nil")
		}
	})
}

// =============================================================================
// NewCredential Tests
// =============================================================================

func TestU_NewCredential(t *testing.T) {
	t.Run("[Unit] NewCredential: creates credential with ID", func(t *testing.T) {
		subject := CredentialSubject{
			CommonName:   "Test User",
			Organization: []string{"Test Org"},
		}

		cred := NewCredential("test-id", subject)
		if cred == nil {
			t.Fatal("NewCredential() returned nil")
		}
		if cred.ID != "test-id" {
			t.Errorf("NewCredential() ID = %s, want test-id", cred.ID)
		}
	})

	t.Run("[Unit] NewCredential: preserves subject", func(t *testing.T) {
		subject := CredentialSubject{
			CommonName:   "John Doe",
			Organization: []string{"ACME Corp"},
			Country:      []string{"US"},
		}

		cred := NewCredential("user-123", subject)
		if cred.Subject.CommonName != "John Doe" {
			t.Errorf("NewCredential() CommonName = %s, want John Doe", cred.Subject.CommonName)
		}
		if len(cred.Subject.Organization) != 1 || cred.Subject.Organization[0] != "ACME Corp" {
			t.Errorf("NewCredential() Organization = %v, want [ACME Corp]", cred.Subject.Organization)
		}
	})
}

// =============================================================================
// CredentialExists Tests
// =============================================================================

func TestU_CredentialExists(t *testing.T) {
	t.Run("[Unit] CredentialExists: returns false for non-existent path", func(t *testing.T) {
		tmpDir := t.TempDir()
		exists := CredentialExists(filepath.Join(tmpDir, "nonexistent"))
		if exists {
			t.Error("CredentialExists() should return false for non-existent path")
		}
	})

	t.Run("[Unit] CredentialExists: returns false for empty directory", func(t *testing.T) {
		tmpDir := t.TempDir()
		exists := CredentialExists(tmpDir)
		if exists {
			t.Error("CredentialExists() should return false for empty directory")
		}
	})
}

// =============================================================================
// LoadCredential Tests
// =============================================================================

func TestU_LoadCredential(t *testing.T) {
	t.Run("[Unit] LoadCredential: fails for non-existent path", func(t *testing.T) {
		_, err := LoadCredential("/nonexistent/credential/path")
		if err == nil {
			t.Error("LoadCredential() should fail for non-existent path")
		}
	})

	t.Run("[Unit] LoadCredential: fails for empty directory", func(t *testing.T) {
		tmpDir := t.TempDir()
		_, err := LoadCredential(tmpDir)
		if err == nil {
			t.Error("LoadCredential() should fail for empty directory")
		}
	})
}

// =============================================================================
// CredentialLoad Tests (alias)
// =============================================================================

func TestU_CredentialLoad(t *testing.T) {
	t.Run("[Unit] CredentialLoad: fails for non-existent path", func(t *testing.T) {
		_, err := CredentialLoad("/nonexistent/credential/path")
		if err == nil {
			t.Error("CredentialLoad() should fail for non-existent path")
		}
	})
}

// =============================================================================
// CredentialSubject Tests
// =============================================================================

func TestU_CredentialSubject(t *testing.T) {
	t.Run("[Unit] CredentialSubject: can be created with all fields", func(t *testing.T) {
		subject := CredentialSubject{
			CommonName:   "Test User",
			Organization: []string{"Test Org"},
			Country:      []string{"US"},
			Province:     []string{"CA"},
			Locality:     []string{"San Francisco"},
		}

		if subject.CommonName != "Test User" {
			t.Error("CredentialSubject.CommonName mismatch")
		}
		if len(subject.Organization) != 1 || subject.Organization[0] != "Test Org" {
			t.Error("CredentialSubject.Organization mismatch")
		}
	})
}

// =============================================================================
// Type Aliases Tests
// =============================================================================

func TestU_CredentialTypes(t *testing.T) {
	t.Run("[Unit] CredentialTypes: EnrollmentRequest can be instantiated", func(t *testing.T) {
		req := &EnrollmentRequest{}
		_ = req // verify it compiles
	})

	t.Run("[Unit] CredentialTypes: MultiProfileEnrollRequest can be instantiated", func(t *testing.T) {
		req := &MultiProfileEnrollRequest{}
		_ = req // verify it compiles
	})

	t.Run("[Unit] CredentialTypes: CertificateRef can be instantiated", func(t *testing.T) {
		ref := &CertificateRef{}
		_ = ref // verify it compiles
	})
}

// =============================================================================
// CredentialLoadSigner Tests
// =============================================================================

func TestU_CredentialLoadSigner(t *testing.T) {
	t.Run("[Unit] CredentialLoadSigner: fails for non-existent credential", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := NewCredentialFileStore(tmpDir)

		_, _, err := CredentialLoadSigner(context.Background(), store, "nonexistent", []byte("pass"))
		if err == nil {
			t.Error("CredentialLoadSigner() should fail for non-existent credential")
		}
	})
}

// =============================================================================
// CredentialLoadDecryptionKey Tests
// =============================================================================

func TestU_CredentialLoadDecryptionKey(t *testing.T) {
	t.Run("[Unit] CredentialLoadDecryptionKey: fails for non-existent credential", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := NewCredentialFileStore(tmpDir)

		_, _, err := CredentialLoadDecryptionKey(context.Background(), store, "nonexistent", []byte("pass"))
		if err == nil {
			t.Error("CredentialLoadDecryptionKey() should fail for non-existent credential")
		}
	})
}
