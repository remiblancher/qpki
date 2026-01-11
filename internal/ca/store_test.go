package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/remiblancher/post-quantum-pki/internal/crypto"
	"github.com/remiblancher/post-quantum-pki/internal/profile"
)

// createTestSerial generates a random serial number for testing.
func createTestSerial() *big.Int {
	serial, _ := rand.Int(rand.Reader, big.NewInt(1000000))
	return serial
}

// =============================================================================
// Store Unit Tests
// =============================================================================

func TestU_Store_Init(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	if err := store.Init(context.Background()); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	// Check directories exist
	dirs := []string{
		tmpDir,
		filepath.Join(tmpDir, "certs"),
		filepath.Join(tmpDir, "crl"),
		filepath.Join(tmpDir, "private"),
	}
	for _, dir := range dirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			t.Errorf("directory %s does not exist", dir)
		}
	}

	// Check files exist
	files := []string{
		filepath.Join(tmpDir, "serial"),
		filepath.Join(tmpDir, "index.txt"),
	}
	for _, f := range files {
		if _, err := os.Stat(f); os.IsNotExist(err) {
			t.Errorf("file %s does not exist", f)
		}
	}
}

func TestU_Store_NextSerial(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	if err := store.Init(context.Background()); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	// Get first serial
	serial1, err := store.NextSerial(context.Background())
	if err != nil {
		t.Fatalf("NextSerial() error = %v", err)
	}
	if len(serial1) != 1 || serial1[0] != 0x01 {
		t.Errorf("first serial = %x, want 01", serial1)
	}

	// Get second serial
	serial2, err := store.NextSerial(context.Background())
	if err != nil {
		t.Fatalf("NextSerial() error = %v", err)
	}
	if len(serial2) != 1 || serial2[0] != 0x02 {
		t.Errorf("second serial = %x, want 02", serial2)
	}
}

func TestU_IncrementSerial(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		output []byte
	}{
		{"[Unit] Serial Increment: Simple", []byte{0x01}, []byte{0x02}},
		{"[Unit] Serial Increment: Carry", []byte{0xFF}, []byte{0x01, 0x00}},
		{"[Unit] Serial Increment: MultiByte", []byte{0x01, 0xFF}, []byte{0x02, 0x00}},
		{"[Unit] Serial Increment: MultiCarry", []byte{0xFF, 0xFF}, []byte{0x01, 0x00, 0x00}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := incrementSerial(tt.input)
			if len(result) != len(tt.output) {
				t.Errorf("length = %d, want %d", len(result), len(tt.output))
				return
			}
			for i := range result {
				if result[i] != tt.output[i] {
					t.Errorf("result[%d] = %x, want %x", i, result[i], tt.output[i])
				}
			}
		})
	}
}

// =============================================================================
// Store Index Functional Tests
// =============================================================================

// =============================================================================
// CAKeyPath and CACertPath Tests
// =============================================================================

func TestU_Store_CACertPath_Legacy(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// No cert.pem exists, should return ca.crt path
	expected := filepath.Join(tmpDir, "ca.crt")
	result := store.CACertPath()
	if result != expected {
		t.Errorf("CACertPath() = %s, want %s", result, expected)
	}
}

func TestU_Store_CACertPath_NewFormat(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create cert.pem
	certPem := filepath.Join(tmpDir, "cert.pem")
	if err := os.WriteFile(certPem, []byte("dummy"), 0644); err != nil {
		t.Fatalf("failed to create cert.pem: %v", err)
	}

	result := store.CACertPath()
	if result != certPem {
		t.Errorf("CACertPath() = %s, want %s", result, certPem)
	}
}

func TestU_Store_CAKeyPath_Legacy(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// No key.pem exists, should return private/ca.key path
	expected := filepath.Join(tmpDir, "private", "ca.key")
	result := store.CAKeyPath()
	if result != expected {
		t.Errorf("CAKeyPath() = %s, want %s", result, expected)
	}
}

func TestU_Store_CAKeyPath_NewFormat(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create key.pem
	keyPem := filepath.Join(tmpDir, "key.pem")
	if err := os.WriteFile(keyPem, []byte("dummy"), 0644); err != nil {
		t.Fatalf("failed to create key.pem: %v", err)
	}

	result := store.CAKeyPath()
	if result != keyPem {
		t.Errorf("CAKeyPath() = %s, want %s", result, keyPem)
	}
}

func TestU_Store_CertPath(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	serial := []byte{0x01, 0x02, 0x03}
	expected := filepath.Join(tmpDir, "certs", "010203.crt")
	result := store.CertPath(serial)
	if result != expected {
		t.Errorf("CertPath() = %s, want %s", result, expected)
	}
}

func TestU_Store_BasePath(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	if store.BasePath() != tmpDir {
		t.Errorf("BasePath() = %s, want %s", store.BasePath(), tmpDir)
	}
}

// =============================================================================
// SaveCACert and SaveCertAt Tests
// =============================================================================

func TestU_Store_SaveCACert(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create a test certificate
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: createTestSerial(),
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	cert, _ := x509.ParseCertificate(certDER)

	// Save CA cert
	err = store.SaveCACert(context.Background(), cert)
	if err != nil {
		t.Fatalf("SaveCACert() error = %v", err)
	}

	// Verify file exists
	certPath := filepath.Join(tmpDir, "cert.pem")
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Error("SaveCACert() did not create cert.pem")
	}
}

func TestU_Store_SaveCertAt(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create a test certificate
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: createTestSerial(),
		Subject:      pkix.Name{CommonName: "Test Cert"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	cert, _ := x509.ParseCertificate(certDER)

	// Save at custom path
	customPath := filepath.Join(tmpDir, "custom", "test.crt")
	if err := os.MkdirAll(filepath.Dir(customPath), 0755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	err = store.SaveCertAt(context.Background(), customPath, cert)
	if err != nil {
		t.Fatalf("SaveCertAt() error = %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(customPath); os.IsNotExist(err) {
		t.Error("SaveCertAt() did not create file")
	}
}

// =============================================================================
// LoadAllCACerts Tests
// =============================================================================

func TestU_Store_LoadAllCACerts_Legacy(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize CA
	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}
	_, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Load all CA certs
	certs, err := store.LoadAllCACerts(context.Background())
	if err != nil {
		t.Fatalf("LoadAllCACerts() error = %v", err)
	}

	if len(certs) != 1 {
		t.Errorf("LoadAllCACerts() returned %d certs, want 1", len(certs))
	}
}

func TestU_Store_LoadAllCACerts_Versioned(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize CA
	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}
	_, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Create CAInfo to make it versioned
	info := NewCAInfo(Subject{CommonName: "Test Root CA"})
	info.SetBasePath(tmpDir)
	info.CreateInitialVersion([]string{"default"}, []string{"ecdsa-p256"})
	if err := info.Save(); err != nil {
		t.Fatalf("SaveCAInfo() error = %v", err)
	}

	// Create version directory and cert
	versionDir := filepath.Join(tmpDir, "versions", info.Active, "certs")
	if err := os.MkdirAll(versionDir, 0755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	// Copy cert to version directory
	certData, _ := os.ReadFile(store.CACertPath())
	certPath := filepath.Join(versionDir, "ecdsa-p256.crt")
	if err := os.WriteFile(certPath, certData, 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	// Load all CA certs
	certs, err := store.LoadAllCACerts(context.Background())
	if err != nil {
		t.Fatalf("LoadAllCACerts() error = %v", err)
	}

	if len(certs) != 1 {
		t.Errorf("LoadAllCACerts() returned %d certs, want 1", len(certs))
	}
}

// =============================================================================
// LoadCrossSignedCerts Tests
// =============================================================================

func TestU_Store_LoadCrossSignedCerts_NoCA(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// No CA exists
	certs, err := store.LoadCrossSignedCerts(context.Background())
	if err != nil {
		t.Fatalf("LoadCrossSignedCerts() error = %v", err)
	}
	if certs != nil {
		t.Error("LoadCrossSignedCerts() should return nil for non-versioned CA")
	}
}

func TestU_Store_LoadCrossSignedCerts_NoCrossDir(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create CAInfo without cross-signed dir
	info := NewCAInfo(Subject{CommonName: "Test Root CA"})
	info.SetBasePath(tmpDir)
	info.CreateInitialVersion([]string{"default"}, []string{"ecdsa-p256"})
	if err := info.Save(); err != nil {
		t.Fatalf("SaveCAInfo() error = %v", err)
	}

	certs, err := store.LoadCrossSignedCerts(context.Background())
	if err != nil {
		t.Fatalf("LoadCrossSignedCerts() error = %v", err)
	}
	if certs != nil {
		t.Error("LoadCrossSignedCerts() should return nil when no cross-signed dir")
	}
}

func TestU_Store_LoadCrossSignedCerts_WithCerts(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create CAInfo
	info := NewCAInfo(Subject{CommonName: "Test Root CA"})
	info.SetBasePath(tmpDir)
	info.CreateInitialVersion([]string{"default"}, []string{"ecdsa-p256"})
	if err := info.Save(); err != nil {
		t.Fatalf("SaveCAInfo() error = %v", err)
	}

	// Create cross-signed directory with a cert
	crossDir := filepath.Join(tmpDir, "versions", info.Active, "cross-signed")
	if err := os.MkdirAll(crossDir, 0755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	// Create a test cross-signed cert
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: createTestSerial(),
		Subject:      pkix.Name{CommonName: "Cross-Signed CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		IsCA:         true,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	// Save cross-signed cert
	crossCertPath := filepath.Join(crossDir, "cross-ecdsa.crt")
	if err := store.SaveCertAt(context.Background(), crossCertPath, cert); err != nil {
		t.Fatalf("SaveCertAt() error = %v", err)
	}

	// Load cross-signed certs
	certs, err := store.LoadCrossSignedCerts(context.Background())
	if err != nil {
		t.Fatalf("LoadCrossSignedCerts() error = %v", err)
	}
	if len(certs) != 1 {
		t.Errorf("LoadCrossSignedCerts() returned %d certs, want 1", len(certs))
	}
}

// =============================================================================
// Exists Tests
// =============================================================================

func TestU_Store_Exists_NoCA(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	if store.Exists() {
		t.Error("Exists() should return false for empty directory")
	}
}

func TestU_Store_Exists_LegacyCA(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create legacy ca.crt
	caCrt := filepath.Join(tmpDir, "ca.crt")
	if err := os.WriteFile(caCrt, []byte("dummy"), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	if !store.Exists() {
		t.Error("Exists() should return true for legacy CA")
	}
}

func TestU_Store_Exists_VersionedCA(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create CAInfo
	info := NewCAInfo(Subject{CommonName: "Test Root CA"})
	info.SetBasePath(tmpDir)
	info.CreateInitialVersion([]string{"default"}, []string{"ecdsa-p256"})
	if err := info.Save(); err != nil {
		t.Fatalf("SaveCAInfo() error = %v", err)
	}

	if !store.Exists() {
		t.Error("Exists() should return true for versioned CA")
	}
}

func TestU_Store_Exists_OldVersioned(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create old versioned structure (active/ca.crt)
	activeDir := filepath.Join(tmpDir, "active")
	if err := os.MkdirAll(activeDir, 0755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	activeCert := filepath.Join(activeDir, "ca.crt")
	if err := os.WriteFile(activeCert, []byte("dummy"), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	if !store.Exists() {
		t.Error("Exists() should return true for old versioned CA")
	}
}

// =============================================================================
// getHybridCertPath Tests
// =============================================================================

func TestU_Store_GetHybridCertPath_SingleAlgo(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create CAInfo with single algorithm
	info := NewCAInfo(Subject{CommonName: "Test Root CA"})
	info.SetBasePath(tmpDir)
	info.CreateInitialVersion([]string{"default"}, []string{"ecdsa-p256"})

	activeVer := info.ActiveVersion()
	if activeVer == nil {
		t.Fatal("ActiveVersion() returned nil")
	}

	// getHybridCertPath is a method on FileStore
	result := store.getHybridCertPath(info, activeVer)
	expected := info.CertPath(info.Active, "ecdsa-p256")

	if result != expected {
		t.Errorf("getHybridCertPath() = %s, want %s", result, expected)
	}
}

func TestU_Store_GetHybridCertPath_CompositeProfile(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create CAInfo with composite profile
	info := NewCAInfo(Subject{CommonName: "Test Root CA"})
	info.SetBasePath(tmpDir)
	info.CreateInitialVersion([]string{"composite"}, []string{"ecdsa-p256", "ml-dsa-65"})

	// Add keys to info
	info.Keys = append(info.Keys, KeyRef{
		ID:        "classical",
		Algorithm: crypto.AlgECDSAP256,
		Storage:   crypto.StorageRef{Type: "software", Path: "keys/ecdsa-p256.pem"},
	})
	info.Keys = append(info.Keys, KeyRef{
		ID:        "pqc",
		Algorithm: crypto.AlgMLDSA65,
		Storage:   crypto.StorageRef{Type: "software", Path: "keys/ml-dsa-65.pem"},
	})

	activeVer := info.ActiveVersion()
	if activeVer == nil {
		t.Fatal("ActiveVersion() returned nil")
	}

	// Should return hybrid cert path
	result := store.getHybridCertPath(info, activeVer)

	// Result should contain "composite" in path
	if result == "" {
		t.Error("getHybridCertPath() returned empty string")
	}
}

// =============================================================================
// Index Parsing Tests
// =============================================================================

func TestU_ParseIndexLine_Valid(t *testing.T) {
	line := "V\t351231235959Z\t\t01\tunknown\tCN=Test"
	entry, err := parseIndexLine(line)
	if err != nil {
		t.Fatalf("parseIndexLine() error = %v", err)
	}

	if entry.Status != "V" {
		t.Errorf("Status = %s, want V", entry.Status)
	}
	if entry.Subject != "CN=Test" {
		t.Errorf("Subject = %s, want CN=Test", entry.Subject)
	}
}

func TestU_ParseIndexLine_Revoked(t *testing.T) {
	line := "R\t351231235959Z\t250101120000Z\t01\tunknown\tCN=Revoked"
	entry, err := parseIndexLine(line)
	if err != nil {
		t.Fatalf("parseIndexLine() error = %v", err)
	}

	if entry.Status != "R" {
		t.Errorf("Status = %s, want R", entry.Status)
	}
	if entry.Revocation.IsZero() {
		t.Error("Revocation should be set")
	}
}

func TestU_ParseIndexLine_Malformed(t *testing.T) {
	line := "V\t351231235959Z"
	_, err := parseIndexLine(line)
	if err == nil {
		t.Error("parseIndexLine() should fail for malformed line")
	}
}

func TestU_SplitLines(t *testing.T) {
	input := "line1\nline2\nline3"
	result := splitLines(input)
	if len(result) != 3 {
		t.Errorf("splitLines() returned %d lines, want 3", len(result))
	}
}

func TestU_SplitTabs(t *testing.T) {
	input := "a\tb\tc"
	result := splitTabs(input)
	if len(result) != 3 {
		t.Errorf("splitTabs() returned %d parts, want 3", len(result))
	}
}

// =============================================================================
// Context Cancellation Tests
// =============================================================================

func TestU_Store_Init_ContextCanceled(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := store.Init(ctx)
	if err == nil {
		t.Error("Init() should fail with canceled context")
	}
}

func TestU_Store_NextSerial_ContextCanceled(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Init first
	if err := store.Init(context.Background()); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := store.NextSerial(ctx)
	if err == nil {
		t.Error("NextSerial() should fail with canceled context")
	}
}

func TestU_Store_LoadCert_ContextCanceled(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := store.LoadCert(ctx, []byte{0x01})
	if err == nil {
		t.Error("LoadCert() should fail with canceled context")
	}
}

func TestU_Store_ReadIndex_ContextCanceled(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Init first
	if err := store.Init(context.Background()); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := store.ReadIndex(ctx)
	if err == nil {
		t.Error("ReadIndex() should fail with canceled context")
	}
}

// =============================================================================
// Store Index Functional Tests
// =============================================================================

func TestF_Store_ReadIndex(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
		Passphrase:    "test-password",
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Build extensions for TLS server
	criticalTrue := true
	criticalFalse := false
	extensions := &profile.ExtensionsConfig{
		KeyUsage: &profile.KeyUsageConfig{
			Critical: &criticalTrue,
			Values:   []string{"digitalSignature", "keyEncipherment"},
		},
		ExtKeyUsage: &profile.ExtKeyUsageConfig{
			Critical: &criticalFalse,
			Values:   []string{"serverAuth"},
		},
		BasicConstraints: &profile.BasicConstraintsConfig{
			Critical: &criticalTrue,
			CA:       false,
		},
	}

	// Issue a few certificates
	for i := 0; i < 3; i++ {
		subjectKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		template := &x509.Certificate{
			Subject:  pkix.Name{CommonName: "server.example.com"},
			DNSNames: []string{"server.example.com"},
		}
		_, err = ca.Issue(context.Background(), IssueRequest{
			Template:   template,
			PublicKey:  &subjectKey.PublicKey,
			Extensions: extensions,
			Validity:   365 * 24 * time.Hour,
		})
		if err != nil {
			t.Fatalf("Issue() error = %v", err)
		}
	}

	// Read index
	entries, err := store.ReadIndex(context.Background())
	if err != nil {
		t.Fatalf("ReadIndex() error = %v", err)
	}

	if len(entries) != 3 {
		t.Errorf("entries count = %d, want 3", len(entries))
	}

	for _, entry := range entries {
		if entry.Status != "V" {
			t.Errorf("entry status = %v, want V", entry.Status)
		}
	}
}
