package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// =============================================================================
// CRLInfo Tests
// =============================================================================

func TestU_CRLInfo_Structure(t *testing.T) {
	now := time.Now()
	info := CRLInfo{
		Name:       "test.crl",
		Algorithm:  "ecdsa-p256",
		ThisUpdate: now,
		NextUpdate: now.Add(7 * 24 * time.Hour),
		Revoked:    5,
		Status:     "valid",
	}

	if info.Name != "test.crl" {
		t.Errorf("CRLInfo.Name = %s, want test.crl", info.Name)
	}
	if info.Revoked != 5 {
		t.Errorf("CRLInfo.Revoked = %d, want 5", info.Revoked)
	}
}

// =============================================================================
// ParseCRLFile Tests
// =============================================================================

func generateTestCRL(t *testing.T) ([]byte, *x509.Certificate) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Create CA certificate
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create CA certificate: %v", err)
	}

	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("failed to parse CA certificate: %v", err)
	}

	// Create CRL
	now := time.Now()
	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now,
		NextUpdate: now.Add(7 * 24 * time.Hour),
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, crlTemplate, caCert, key)
	if err != nil {
		t.Fatalf("failed to create CRL: %v", err)
	}

	return crlDER, caCert
}

func TestU_ParseCRLFile_DER(t *testing.T) {
	tmpDir := t.TempDir()
	crlPath := filepath.Join(tmpDir, "test.crl")

	crlDER, _ := generateTestCRL(t)
	if err := os.WriteFile(crlPath, crlDER, 0644); err != nil {
		t.Fatalf("failed to write CRL file: %v", err)
	}

	now := time.Now()
	info, err := ParseCRLFile(crlPath, now)
	if err != nil {
		t.Fatalf("ParseCRLFile() error = %v", err)
	}

	if info == nil {
		t.Fatal("ParseCRLFile() returned nil info")
	}

	if info.Status != "valid" {
		t.Errorf("ParseCRLFile() status = %s, want valid", info.Status)
	}
}

func TestU_ParseCRLFile_PEM(t *testing.T) {
	tmpDir := t.TempDir()
	crlPath := filepath.Join(tmpDir, "test.crl")

	crlDER, _ := generateTestCRL(t)
	crlPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "X509 CRL",
		Bytes: crlDER,
	})
	if err := os.WriteFile(crlPath, crlPEM, 0644); err != nil {
		t.Fatalf("failed to write CRL file: %v", err)
	}

	now := time.Now()
	info, err := ParseCRLFile(crlPath, now)
	if err != nil {
		t.Fatalf("ParseCRLFile() error = %v", err)
	}

	if info == nil {
		t.Fatal("ParseCRLFile() returned nil info")
	}
}

func TestU_ParseCRLFile_Expired(t *testing.T) {
	tmpDir := t.TempDir()
	crlPath := filepath.Join(tmpDir, "test.crl")

	crlDER, _ := generateTestCRL(t)
	if err := os.WriteFile(crlPath, crlDER, 0644); err != nil {
		t.Fatalf("failed to write CRL file: %v", err)
	}

	// Use future time to make CRL appear expired
	futureTime := time.Now().Add(30 * 24 * time.Hour)
	info, err := ParseCRLFile(crlPath, futureTime)
	if err != nil {
		t.Fatalf("ParseCRLFile() error = %v", err)
	}

	if info.Status != "EXPIRED" {
		t.Errorf("ParseCRLFile() status = %s, want EXPIRED", info.Status)
	}
}

func TestU_ParseCRLFile_NotFound(t *testing.T) {
	_, err := ParseCRLFile("/nonexistent/path/test.crl", time.Now())
	if err == nil {
		t.Error("ParseCRLFile() should fail for non-existent file")
	}
}

func TestU_ParseCRLFile_InvalidData(t *testing.T) {
	tmpDir := t.TempDir()
	crlPath := filepath.Join(tmpDir, "invalid.crl")

	if err := os.WriteFile(crlPath, []byte("invalid CRL data"), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	_, err := ParseCRLFile(crlPath, time.Now())
	if err == nil {
		t.Error("ParseCRLFile() should fail for invalid CRL data")
	}
}

// =============================================================================
// ScanCRLDirectory Tests
// =============================================================================

func TestU_ScanCRLDirectory_Empty(t *testing.T) {
	tmpDir := t.TempDir()

	crls, err := ScanCRLDirectory(tmpDir, time.Now())
	if err != nil {
		t.Fatalf("ScanCRLDirectory() error = %v", err)
	}

	if len(crls) != 0 {
		t.Errorf("ScanCRLDirectory() returned %d CRLs, want 0", len(crls))
	}
}

func TestU_ScanCRLDirectory_NonExistent(t *testing.T) {
	crls, err := ScanCRLDirectory("/nonexistent/path", time.Now())
	if err != nil {
		t.Fatalf("ScanCRLDirectory() error = %v", err)
	}

	if len(crls) != 0 {
		t.Errorf("ScanCRLDirectory() returned %d CRLs, want 0", len(crls))
	}
}

func TestU_ScanCRLDirectory_WithCRLs(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a CRL file
	crlDER, _ := generateTestCRL(t)
	crlPath := filepath.Join(tmpDir, "ca.crl")
	if err := os.WriteFile(crlPath, crlDER, 0644); err != nil {
		t.Fatalf("failed to write CRL file: %v", err)
	}

	crls, err := ScanCRLDirectory(tmpDir, time.Now())
	if err != nil {
		t.Fatalf("ScanCRLDirectory() error = %v", err)
	}

	if len(crls) != 1 {
		t.Errorf("ScanCRLDirectory() returned %d CRLs, want 1", len(crls))
	}

	if crls[0].Name != "ca.crl" {
		t.Errorf("ScanCRLDirectory() CRL name = %s, want ca.crl", crls[0].Name)
	}
}

func TestU_ScanCRLDirectory_WithSubdirectory(t *testing.T) {
	tmpDir := t.TempDir()

	// Create algorithm subdirectory
	algoDir := filepath.Join(tmpDir, "ecdsa-p256")
	if err := os.MkdirAll(algoDir, 0755); err != nil {
		t.Fatalf("failed to create directory: %v", err)
	}

	// Create a CRL file in the subdirectory
	crlDER, _ := generateTestCRL(t)
	crlPath := filepath.Join(algoDir, "ca.crl")
	if err := os.WriteFile(crlPath, crlDER, 0644); err != nil {
		t.Fatalf("failed to write CRL file: %v", err)
	}

	crls, err := ScanCRLDirectory(tmpDir, time.Now())
	if err != nil {
		t.Fatalf("ScanCRLDirectory() error = %v", err)
	}

	if len(crls) != 1 {
		t.Errorf("ScanCRLDirectory() returned %d CRLs, want 1", len(crls))
	}

	if crls[0].Algorithm != "ecdsa-p256" {
		t.Errorf("ScanCRLDirectory() CRL algorithm = %s, want ecdsa-p256", crls[0].Algorithm)
	}
}

// =============================================================================
// ScanAlgorithmCRLDir Tests
// =============================================================================

func TestU_ScanAlgorithmCRLDir_Empty(t *testing.T) {
	tmpDir := t.TempDir()

	crls := ScanAlgorithmCRLDir(tmpDir, "test-algo", time.Now())
	if len(crls) != 0 {
		t.Errorf("ScanAlgorithmCRLDir() returned %d CRLs, want 0", len(crls))
	}
}

func TestU_ScanAlgorithmCRLDir_NonExistent(t *testing.T) {
	crls := ScanAlgorithmCRLDir("/nonexistent/path", "test-algo", time.Now())
	if len(crls) != 0 {
		t.Errorf("ScanAlgorithmCRLDir() returned %d CRLs, want 0", len(crls))
	}
}

func TestU_ScanAlgorithmCRLDir_SkipsNonCRL(t *testing.T) {
	tmpDir := t.TempDir()

	// Create non-CRL files
	if err := os.WriteFile(filepath.Join(tmpDir, "readme.txt"), []byte("test"), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	crls := ScanAlgorithmCRLDir(tmpDir, "test-algo", time.Now())
	if len(crls) != 0 {
		t.Errorf("ScanAlgorithmCRLDir() returned %d CRLs, want 0", len(crls))
	}
}
