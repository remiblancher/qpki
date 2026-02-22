package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/remiblancher/qpki/internal/credential"
)

// =============================================================================
// Test Helpers
// =============================================================================

// generateTestCertificate creates a self-signed test certificate.
func generateTestCertificate(t *testing.T, cn string) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

// setupTestCredential creates a test credential directory structure.
func setupTestCredential(t *testing.T) (string, *credential.VersionStore, *credential.FileStore) {
	t.Helper()

	tmpDir := t.TempDir()
	credID := "test-credential"
	credPath := filepath.Join(tmpDir, credID)

	// Create credential directory
	if err := os.MkdirAll(credPath, 0755); err != nil {
		t.Fatalf("Failed to create credential directory: %v", err)
	}

	// Create credential metadata
	now := time.Now()
	credMeta := map[string]interface{}{
		"id": credID,
		"subject": map[string]interface{}{
			"common_name":  "Test User",
			"organization": []string{"Test Org"},
		},
		"active": "v1",
		"versions": map[string]interface{}{
			"v1": map[string]interface{}{
				"profiles":     []string{"ec/tls-client"},
				"algos":        []string{"ec"},
				"created":      now.Format(time.RFC3339),
				"activated_at": now.Format(time.RFC3339),
			},
		},
	}

	metaJSON, err := json.MarshalIndent(credMeta, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal credential metadata: %v", err)
	}

	if err := os.WriteFile(filepath.Join(credPath, "credential.meta.json"), metaJSON, 0644); err != nil {
		t.Fatalf("Failed to write credential metadata: %v", err)
	}

	// Create stores
	versionStore := credential.NewVersionStore(credPath)
	credStore := credential.NewFileStore(tmpDir)

	return credPath, versionStore, credStore
}

// writeCertificatePEM writes a certificate to a PEM file.
func writeCertificatePEM(t *testing.T, certPath string, cert *x509.Certificate) {
	t.Helper()

	pemData, err := credential.EncodeCertificatesPEM([]*x509.Certificate{cert})
	if err != nil {
		t.Fatalf("Failed to encode certificate: %v", err)
	}

	if err := os.WriteFile(certPath, pemData, 0644); err != nil {
		t.Fatalf("Failed to write certificate: %v", err)
	}
}

// =============================================================================
// LoadCredentialVersionCerts Tests
// =============================================================================

func TestU_LoadCredentialVersionCerts(t *testing.T) {
	t.Run("[Unit] LoadCredentialVersionCerts: loads certs from new structure", func(t *testing.T) {
		credPath, versionStore, credStore := setupTestCredential(t)

		// Create new structure: versions/v1/certs/credential.ec.pem
		certsDir := filepath.Join(credPath, "versions", "v1", "certs")
		if err := os.MkdirAll(certsDir, 0755); err != nil {
			t.Fatalf("Failed to create certs directory: %v", err)
		}

		cert := generateTestCertificate(t, "New Structure Test")
		writeCertificatePEM(t, filepath.Join(certsDir, "credential.ec.pem"), cert)

		// Load certificates
		certs, err := LoadCredentialVersionCerts("test-credential", "v1", versionStore, credStore)
		if err != nil {
			t.Fatalf("LoadCredentialVersionCerts() error = %v", err)
		}

		if len(certs) != 1 {
			t.Errorf("LoadCredentialVersionCerts() got %d certs, want 1", len(certs))
		}

		if certs[0].Subject.CommonName != "New Structure Test" {
			t.Errorf("LoadCredentialVersionCerts() CN = %s, want 'New Structure Test'", certs[0].Subject.CommonName)
		}
	})

	t.Run("[Unit] LoadCredentialVersionCerts: loads certs from old structure", func(t *testing.T) {
		credPath, versionStore, credStore := setupTestCredential(t)

		// Create old structure: versions/v1/ec/certificates.pem
		algoDir := filepath.Join(credPath, "versions", "v1", "ec")
		if err := os.MkdirAll(algoDir, 0755); err != nil {
			t.Fatalf("Failed to create algo directory: %v", err)
		}

		cert := generateTestCertificate(t, "Old Structure Test")
		writeCertificatePEM(t, filepath.Join(algoDir, "certificates.pem"), cert)

		// Load certificates
		certs, err := LoadCredentialVersionCerts("test-credential", "v1", versionStore, credStore)
		if err != nil {
			t.Fatalf("LoadCredentialVersionCerts() error = %v", err)
		}

		if len(certs) != 1 {
			t.Errorf("LoadCredentialVersionCerts() got %d certs, want 1", len(certs))
		}

		if certs[0].Subject.CommonName != "Old Structure Test" {
			t.Errorf("LoadCredentialVersionCerts() CN = %s, want 'Old Structure Test'", certs[0].Subject.CommonName)
		}
	})

	t.Run("[Unit] LoadCredentialVersionCerts: loads multiple certs from new structure", func(t *testing.T) {
		credPath, versionStore, credStore := setupTestCredential(t)

		// Create new structure with multiple algorithm files
		certsDir := filepath.Join(credPath, "versions", "v1", "certs")
		if err := os.MkdirAll(certsDir, 0755); err != nil {
			t.Fatalf("Failed to create certs directory: %v", err)
		}

		cert1 := generateTestCertificate(t, "EC Cert")
		cert2 := generateTestCertificate(t, "ML-DSA Cert")
		writeCertificatePEM(t, filepath.Join(certsDir, "credential.ec.pem"), cert1)
		writeCertificatePEM(t, filepath.Join(certsDir, "credential.ml-dsa.pem"), cert2)

		// Load certificates
		certs, err := LoadCredentialVersionCerts("test-credential", "v1", versionStore, credStore)
		if err != nil {
			t.Fatalf("LoadCredentialVersionCerts() error = %v", err)
		}

		if len(certs) != 2 {
			t.Errorf("LoadCredentialVersionCerts() got %d certs, want 2", len(certs))
		}
	})

	t.Run("[Unit] LoadCredentialVersionCerts: prefers new structure over old", func(t *testing.T) {
		credPath, versionStore, credStore := setupTestCredential(t)

		// Create both structures
		certsDir := filepath.Join(credPath, "versions", "v1", "certs")
		if err := os.MkdirAll(certsDir, 0755); err != nil {
			t.Fatalf("Failed to create certs directory: %v", err)
		}

		algoDir := filepath.Join(credPath, "versions", "v1", "ec")
		if err := os.MkdirAll(algoDir, 0755); err != nil {
			t.Fatalf("Failed to create algo directory: %v", err)
		}

		newCert := generateTestCertificate(t, "New Structure")
		oldCert := generateTestCertificate(t, "Old Structure")
		writeCertificatePEM(t, filepath.Join(certsDir, "credential.ec.pem"), newCert)
		writeCertificatePEM(t, filepath.Join(algoDir, "certificates.pem"), oldCert)

		// Load certificates - should prefer new structure
		certs, err := LoadCredentialVersionCerts("test-credential", "v1", versionStore, credStore)
		if err != nil {
			t.Fatalf("LoadCredentialVersionCerts() error = %v", err)
		}

		if len(certs) != 1 {
			t.Errorf("LoadCredentialVersionCerts() got %d certs, want 1", len(certs))
		}

		if certs[0].Subject.CommonName != "New Structure" {
			t.Errorf("LoadCredentialVersionCerts() should prefer new structure, got CN = %s", certs[0].Subject.CommonName)
		}
	})

	t.Run("[Unit] LoadCredentialVersionCerts: fails for non-existent version", func(t *testing.T) {
		_, versionStore, credStore := setupTestCredential(t)

		_, err := LoadCredentialVersionCerts("test-credential", "v999", versionStore, credStore)
		if err == nil {
			t.Error("LoadCredentialVersionCerts() should fail for non-existent version")
		}
	})

	t.Run("[Unit] LoadCredentialVersionCerts: fails when no certificates found", func(t *testing.T) {
		credPath, versionStore, credStore := setupTestCredential(t)

		// Create version directory but no certificates
		versionDir := filepath.Join(credPath, "versions", "v1")
		if err := os.MkdirAll(versionDir, 0755); err != nil {
			t.Fatalf("Failed to create version directory: %v", err)
		}

		_, err := LoadCredentialVersionCerts("test-credential", "v1", versionStore, credStore)
		if err == nil {
			t.Error("LoadCredentialVersionCerts() should fail when no certificates found")
		}
	})

	t.Run("[Unit] LoadCredentialVersionCerts: skips non-credential files in certs dir", func(t *testing.T) {
		credPath, versionStore, credStore := setupTestCredential(t)

		// Create new structure with mixed files
		certsDir := filepath.Join(credPath, "versions", "v1", "certs")
		if err := os.MkdirAll(certsDir, 0755); err != nil {
			t.Fatalf("Failed to create certs directory: %v", err)
		}

		cert := generateTestCertificate(t, "Valid Cert")
		writeCertificatePEM(t, filepath.Join(certsDir, "credential.ec.pem"), cert)

		// Create files that should be skipped
		if err := os.WriteFile(filepath.Join(certsDir, "other.pem"), []byte("data"), 0644); err != nil {
			t.Fatalf("Failed to write other.pem: %v", err)
		}
		if err := os.WriteFile(filepath.Join(certsDir, "credential.ec.txt"), []byte("data"), 0644); err != nil {
			t.Fatalf("Failed to write credential.ec.txt: %v", err)
		}

		// Load certificates - should only get the valid one
		certs, err := LoadCredentialVersionCerts("test-credential", "v1", versionStore, credStore)
		if err != nil {
			t.Fatalf("LoadCredentialVersionCerts() error = %v", err)
		}

		if len(certs) != 1 {
			t.Errorf("LoadCredentialVersionCerts() got %d certs, want 1 (should skip non-credential files)", len(certs))
		}
	})

	t.Run("[Unit] LoadCredentialVersionCerts: skips subdirectories in certs dir", func(t *testing.T) {
		credPath, versionStore, credStore := setupTestCredential(t)

		// Create new structure with subdirectory
		certsDir := filepath.Join(credPath, "versions", "v1", "certs")
		subDir := filepath.Join(certsDir, "subdir")
		if err := os.MkdirAll(subDir, 0755); err != nil {
			t.Fatalf("Failed to create subdirectory: %v", err)
		}

		cert := generateTestCertificate(t, "Valid Cert")
		writeCertificatePEM(t, filepath.Join(certsDir, "credential.ec.pem"), cert)

		// Put cert in subdirectory (should be ignored)
		subCert := generateTestCertificate(t, "Sub Cert")
		writeCertificatePEM(t, filepath.Join(subDir, "credential.rsa.pem"), subCert)

		// Load certificates - should only get the top-level one
		certs, err := LoadCredentialVersionCerts("test-credential", "v1", versionStore, credStore)
		if err != nil {
			t.Fatalf("LoadCredentialVersionCerts() error = %v", err)
		}

		if len(certs) != 1 {
			t.Errorf("LoadCredentialVersionCerts() got %d certs, want 1 (should skip subdirectories)", len(certs))
		}
	})
}

// =============================================================================
// LoadCredentialVersionCerts with Multiple Algorithms
// =============================================================================

func TestU_LoadCredentialVersionCerts_MultipleAlgorithms(t *testing.T) {
	t.Run("[Unit] LoadCredentialVersionCerts: loads from multiple old algo dirs", func(t *testing.T) {
		credPath, _, credStore := setupTestCredential(t)

		// Update metadata to have multiple algos
		now := time.Now()
		credMeta := map[string]interface{}{
			"id": "test-credential",
			"subject": map[string]interface{}{
				"common_name":  "Test User",
				"organization": []string{"Test Org"},
			},
			"active": "v1",
			"versions": map[string]interface{}{
				"v1": map[string]interface{}{
					"profiles":     []string{"ec/tls-client", "ml-dsa/tls-client"},
					"algos":        []string{"ec", "ml-dsa"},
					"created":      now.Format(time.RFC3339),
					"activated_at": now.Format(time.RFC3339),
				},
			},
		}

		metaJSON, _ := json.MarshalIndent(credMeta, "", "  ")
		if err := os.WriteFile(filepath.Join(credPath, "credential.meta.json"), metaJSON, 0644); err != nil {
			t.Fatalf("Failed to write metadata: %v", err)
		}

		// Create old structure with multiple algo directories
		ecDir := filepath.Join(credPath, "versions", "v1", "ec")
		mldsaDir := filepath.Join(credPath, "versions", "v1", "ml-dsa")
		if err := os.MkdirAll(ecDir, 0755); err != nil {
			t.Fatalf("Failed to create ec dir: %v", err)
		}
		if err := os.MkdirAll(mldsaDir, 0755); err != nil {
			t.Fatalf("Failed to create ml-dsa dir: %v", err)
		}

		ecCert := generateTestCertificate(t, "EC Cert")
		mldsaCert := generateTestCertificate(t, "ML-DSA Cert")
		writeCertificatePEM(t, filepath.Join(ecDir, "certificates.pem"), ecCert)
		writeCertificatePEM(t, filepath.Join(mldsaDir, "certificates.pem"), mldsaCert)

		// Reload version store to pick up metadata changes
		versionStore := credential.NewVersionStore(credPath)

		// Load certificates
		certs, err := LoadCredentialVersionCerts("test-credential", "v1", versionStore, credStore)
		if err != nil {
			t.Fatalf("LoadCredentialVersionCerts() error = %v", err)
		}

		if len(certs) != 2 {
			t.Errorf("LoadCredentialVersionCerts() got %d certs, want 2", len(certs))
		}
	})
}
