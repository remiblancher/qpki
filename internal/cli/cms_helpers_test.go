package cli

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

// =============================================================================
// LoadSigningCert Tests
// =============================================================================

func TestU_LoadSigningCert(t *testing.T) {
	t.Run("[Unit] LoadSigningCert: valid certificate", func(t *testing.T) {
		tmpDir := t.TempDir()
		certPath := filepath.Join(tmpDir, "cert.pem")

		cert := generateTestCert(t)
		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
			t.Fatalf("failed to write cert file: %v", err)
		}

		loaded, err := LoadSigningCert(certPath)
		if err != nil {
			t.Fatalf("LoadSigningCert() error = %v", err)
		}

		if loaded.Subject.CommonName != cert.Subject.CommonName {
			t.Errorf("LoadSigningCert() CN = %s, want %s", loaded.Subject.CommonName, cert.Subject.CommonName)
		}
	})

	t.Run("[Unit] LoadSigningCert: file not found", func(t *testing.T) {
		_, err := LoadSigningCert("/nonexistent/path/cert.pem")
		if err == nil {
			t.Error("LoadSigningCert() should fail for non-existent file")
		}
	})

	t.Run("[Unit] LoadSigningCert: invalid PEM", func(t *testing.T) {
		tmpDir := t.TempDir()
		certPath := filepath.Join(tmpDir, "invalid.pem")

		if err := os.WriteFile(certPath, []byte("not a valid PEM"), 0644); err != nil {
			t.Fatalf("failed to write file: %v", err)
		}

		_, err := LoadSigningCert(certPath)
		if err == nil {
			t.Error("LoadSigningCert() should fail for invalid PEM")
		}
	})

	t.Run("[Unit] LoadSigningCert: wrong PEM type", func(t *testing.T) {
		tmpDir := t.TempDir()
		certPath := filepath.Join(tmpDir, "key.pem")

		keyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: []byte("fake key data"),
		})
		if err := os.WriteFile(certPath, keyPEM, 0644); err != nil {
			t.Fatalf("failed to write file: %v", err)
		}

		_, err := LoadSigningCert(certPath)
		if err == nil {
			t.Error("LoadSigningCert() should fail for non-certificate PEM")
		}
	})
}

// =============================================================================
// LoadDecryptionCert Tests
// =============================================================================

func TestU_LoadDecryptionCert(t *testing.T) {
	t.Run("[Unit] LoadDecryptionCert: valid certificate", func(t *testing.T) {
		tmpDir := t.TempDir()
		certPath := filepath.Join(tmpDir, "cert.pem")

		cert := generateTestCert(t)
		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
			t.Fatalf("failed to write cert file: %v", err)
		}

		loaded, err := LoadDecryptionCert(certPath)
		if err != nil {
			t.Fatalf("LoadDecryptionCert() error = %v", err)
		}

		if loaded.Subject.CommonName != cert.Subject.CommonName {
			t.Errorf("LoadDecryptionCert() CN = %s, want %s", loaded.Subject.CommonName, cert.Subject.CommonName)
		}
	})

	t.Run("[Unit] LoadDecryptionCert: file not found", func(t *testing.T) {
		_, err := LoadDecryptionCert("/nonexistent/path/cert.pem")
		if err == nil {
			t.Error("LoadDecryptionCert() should fail for non-existent file")
		}
	})

	t.Run("[Unit] LoadDecryptionCert: invalid PEM", func(t *testing.T) {
		tmpDir := t.TempDir()
		certPath := filepath.Join(tmpDir, "invalid.pem")

		if err := os.WriteFile(certPath, []byte("not a valid PEM"), 0644); err != nil {
			t.Fatalf("failed to write file: %v", err)
		}

		_, err := LoadDecryptionCert(certPath)
		if err == nil {
			t.Error("LoadDecryptionCert() should fail for invalid PEM")
		}
	})
}

// =============================================================================
// LoadDecryptionKey Tests
// =============================================================================

func TestU_LoadDecryptionKey(t *testing.T) {
	t.Run("[Unit] LoadDecryptionKey: file not found", func(t *testing.T) {
		_, err := LoadDecryptionKey("/nonexistent/path/key.pem", "")
		if err == nil {
			t.Error("LoadDecryptionKey() should fail for non-existent file")
		}
	})

	t.Run("[Unit] LoadDecryptionKey: invalid PEM", func(t *testing.T) {
		tmpDir := t.TempDir()
		keyPath := filepath.Join(tmpDir, "invalid.pem")

		if err := os.WriteFile(keyPath, []byte("not a valid PEM"), 0644); err != nil {
			t.Fatalf("failed to write file: %v", err)
		}

		_, err := LoadDecryptionKey(keyPath, "")
		if err == nil {
			t.Error("LoadDecryptionKey() should fail for invalid PEM")
		}
	})
}

