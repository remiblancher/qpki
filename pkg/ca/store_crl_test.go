package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"testing"
	"time"

	"github.com/remiblancher/qpki/pkg/crypto"
)

// =============================================================================
// Store Revocation Functional Tests
// =============================================================================

func TestF_Store_ListRevoked(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Issue 3 certificates, revoke 2
	for i := 0; i < 3; i++ {
		subjectKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		cert, _ := issueTLSServerCert(ca, "server.example.com", []string{"server.example.com"}, &subjectKey.PublicKey)
		if i < 2 {
			_ = ca.Revoke(cert.SerialNumber.Bytes(), ReasonUnspecified)
		}
	}

	revoked, err := store.ListRevoked(context.Background())
	if err != nil {
		t.Fatalf("ListRevoked() error = %v", err)
	}

	if len(revoked) != 2 {
		t.Errorf("ListRevoked() returned %d, want 2", len(revoked))
	}
}

func TestF_Store_LoadCRL(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// No CRL yet - should return nil, nil
	crl, err := store.LoadCRL()
	if err != nil {
		t.Fatalf("LoadCRL() error = %v (expected nil for non-existent)", err)
	}
	if crl != nil {
		t.Error("LoadCRL() should return nil when no CRL exists")
	}

	// Initialize CA and generate CRL
	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Generate CRL
	nextUpdate := time.Now().AddDate(0, 0, 7)
	_, err = ca.GenerateCRL(nextUpdate)
	if err != nil {
		t.Fatalf("GenerateCRL() error = %v", err)
	}

	// Now LoadCRL should work
	crl, err = store.LoadCRL()
	if err != nil {
		t.Fatalf("LoadCRL() error = %v", err)
	}
	if crl == nil {
		t.Fatal("LoadCRL() should return CRL after generation")
	}
	if crl.Issuer.CommonName != "Test Root CA" {
		t.Errorf("CRL issuer = %v, want Test Root CA", crl.Issuer.CommonName)
	}
}

func TestF_Store_LoadCRL_InvalidPEM(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)
	if err := store.Init(context.Background()); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	// Create crl directory and write invalid PEM
	crlDir := tmpDir + "/crl"
	if err := os.MkdirAll(crlDir, 0755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(store.CRLPath(), []byte("not a valid PEM"), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, err := store.LoadCRL()
	if err == nil {
		t.Error("LoadCRL() should fail for invalid PEM")
	}
}

// =============================================================================
// Store CRL Path Unit Tests
// =============================================================================

func TestU_Store_CRLPath(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	path := store.CRLPath()
	expected := tmpDir + "/crl/ca.crl"

	if path != expected {
		t.Errorf("CRLPath() = %v, want %v", path, expected)
	}
}

func TestU_Store_CRLDir(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	path := store.CRLDir()
	expected := tmpDir + "/crl"
	if path != expected {
		t.Errorf("CRLDir() = %v, want %v", path, expected)
	}
}

func TestU_Store_CRLPathForAlgorithm(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	tests := []struct {
		name       string
		algorithm  string
		wantSuffix string
	}{
		{"[Unit] CRL Path: ECDSA-P256", "ecdsa-p256", "/crl/ca.ecdsa-p256.crl"},
		{"[Unit] CRL Path: ECDSA-P384", "ecdsa-p384", "/crl/ca.ecdsa-p384.crl"},
		{"[Unit] CRL Path: ML-DSA-65", "ml-dsa-65", "/crl/ca.ml-dsa-65.crl"},
		{"[Unit] CRL Path: ML-DSA-87", "ml-dsa-87", "/crl/ca.ml-dsa-87.crl"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := store.CRLPathForAlgorithm(tt.algorithm)
			if path != tmpDir+tt.wantSuffix {
				t.Errorf("CRLPathForAlgorithm(%s) = %v, want suffix %v", tt.algorithm, path, tt.wantSuffix)
			}
		})
	}
}

func TestU_Store_NextCRLNumber_Shared(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// First call should return 01
	num1, err := store.NextCRLNumber(context.Background())
	if err != nil {
		t.Fatalf("NextCRLNumber() error = %v", err)
	}
	if len(num1) == 0 || num1[0] != 0x01 {
		t.Errorf("First CRL number should be 01, got %x", num1)
	}

	// Second call should return 02 (shared across algorithms)
	num2, err := store.NextCRLNumber(context.Background())
	if err != nil {
		t.Fatalf("NextCRLNumber() second call error = %v", err)
	}
	if len(num2) == 0 || num2[0] != 0x02 {
		t.Errorf("Second CRL number should be 02, got %x", num2)
	}

	// Third call should return 03 (crlnumber is shared, not per-algorithm)
	num3, err := store.NextCRLNumber(context.Background())
	if err != nil {
		t.Fatalf("NextCRLNumber() third call error = %v", err)
	}
	if len(num3) == 0 || num3[0] != 0x03 {
		t.Errorf("Third CRL number should be 03, got %x", num3)
	}
}

func TestU_Store_SaveAndLoadCRLForAlgorithm(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize a CA to create CRL
	cfg := Config{
		CommonName:    "Test CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Generate a CRL
	nextUpdate := time.Now().Add(24 * time.Hour)
	crlDER, err := ca.GenerateCRL(nextUpdate)
	if err != nil {
		t.Fatalf("GenerateCRL() error = %v", err)
	}

	// Save it for ecdsa-p256 algorithm
	err = store.SaveCRLForAlgorithm(context.Background(), crlDER, "ecdsa-p256")
	if err != nil {
		t.Fatalf("SaveCRLForAlgorithm() error = %v", err)
	}

	// Verify both PEM and DER files exist
	pemPath := store.CRLPathForAlgorithm("ecdsa-p256")
	if _, err := os.Stat(pemPath); os.IsNotExist(err) {
		t.Error("CRL PEM file should exist")
	}

	derPath := store.CRLDERPathForAlgorithm("ecdsa-p256")
	if _, err := os.Stat(derPath); os.IsNotExist(err) {
		t.Error("CRL DER file should exist")
	}

	// Load it back
	loadedCRL, err := store.LoadCRLForAlgorithm("ecdsa-p256")
	if err != nil {
		t.Fatalf("LoadCRLForAlgorithm() error = %v", err)
	}
	if loadedCRL == nil {
		t.Fatal("LoadCRLForAlgorithm() returned nil")
	}
}

func TestU_Store_LoadCRLForAlgorithm_NotExist(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Should return nil, nil for non-existent CRL
	crl, err := store.LoadCRLForAlgorithm("nonexistent")
	if err != nil {
		t.Fatalf("LoadCRLForAlgorithm() error = %v", err)
	}
	if crl != nil {
		t.Error("LoadCRLForAlgorithm() should return nil for non-existent CRL")
	}
}

func TestU_Store_ListCRLAlgorithms(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initially should return empty list
	algos, err := store.ListCRLAlgorithms()
	if err != nil {
		t.Fatalf("ListCRLAlgorithms() error = %v", err)
	}
	if len(algos) != 0 {
		t.Errorf("ListCRLAlgorithms() should be empty initially, got %v", algos)
	}

	// Initialize CA and save CRLs for different algorithms
	cfg := Config{
		CommonName:    "Test CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	nextUpdate := time.Now().Add(24 * time.Hour)
	crlDER, err := ca.GenerateCRL(nextUpdate)
	if err != nil {
		t.Fatalf("GenerateCRL() error = %v", err)
	}

	// Save CRLs for multiple algorithms
	if err := store.SaveCRLForAlgorithm(context.Background(), crlDER, "ecdsa-p256"); err != nil {
		t.Fatalf("SaveCRLForAlgorithm(ecdsa-p256) error = %v", err)
	}
	if err := store.SaveCRLForAlgorithm(context.Background(), crlDER, "rsa-2048"); err != nil {
		t.Fatalf("SaveCRLForAlgorithm(rsa-2048) error = %v", err)
	}

	// List should now contain both
	algos, err = store.ListCRLAlgorithms()
	if err != nil {
		t.Fatalf("ListCRLAlgorithms() error = %v", err)
	}
	if len(algos) != 2 {
		t.Errorf("ListCRLAlgorithms() should return 2 algorithms, got %d: %v", len(algos), algos)
	}
}

// =============================================================================
// Context Cancellation Tests
// =============================================================================

func TestU_Store_MarkRevoked_ContextCancelled(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Issue a certificate
	subjectKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert, _ := issueTLSServerCert(ca, "server.example.com", []string{"server.example.com"}, &subjectKey.PublicKey)

	// Create cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Try to mark revoked with cancelled context
	err = store.MarkRevoked(ctx, cert.SerialNumber.Bytes(), ReasonKeyCompromise)
	if err == nil {
		t.Error("MarkRevoked() should fail with cancelled context")
	}
	if err != context.Canceled {
		t.Errorf("MarkRevoked() error = %v, want context.Canceled", err)
	}
}

func TestU_Store_NextCRLNumber_ContextCancelled(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Try to get next CRL number with cancelled context
	_, err := store.NextCRLNumber(ctx)
	if err == nil {
		t.Error("NextCRLNumber() should fail with cancelled context")
	}
	if err != context.Canceled {
		t.Errorf("NextCRLNumber() error = %v, want context.Canceled", err)
	}
}

func TestU_Store_NextCRLNumber_InvalidHex(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create crlnumber file with invalid hex
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	crlNumPath := tmpDir + "/crlnumber"
	if err := os.WriteFile(crlNumPath, []byte("not_valid_hex\n"), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	// Try to get next CRL number
	_, err := store.NextCRLNumber(context.Background())
	if err == nil {
		t.Error("NextCRLNumber() should fail with invalid hex")
	}
}

func TestU_Store_SaveCRL_ContextCancelled(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize store to create directories
	if err := store.Init(context.Background()); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	// Create cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Try to save CRL with cancelled context
	err := store.SaveCRL(ctx, []byte("dummy crl"))
	if err == nil {
		t.Error("SaveCRL() should fail with cancelled context")
	}
	if err != context.Canceled {
		t.Errorf("SaveCRL() error = %v, want context.Canceled", err)
	}
}

func TestU_Store_SaveCRLForAlgorithm_ContextCancelled(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Try to save CRL with cancelled context
	err := store.SaveCRLForAlgorithm(ctx, []byte("dummy crl"), "ecdsa-p256")
	if err == nil {
		t.Error("SaveCRLForAlgorithm() should fail with cancelled context")
	}
	if err != context.Canceled {
		t.Errorf("SaveCRLForAlgorithm() error = %v, want context.Canceled", err)
	}
}

// =============================================================================
// Edge Case Tests
// =============================================================================

func TestU_Store_IsRevoked_NotRevoked(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Issue a certificate but don't revoke it
	subjectKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert, _ := issueTLSServerCert(ca, "server.example.com", []string{"server.example.com"}, &subjectKey.PublicKey)

	// Check if it's revoked - should be false
	revoked, err := store.IsRevoked(context.Background(), cert.SerialNumber.Bytes())
	if err != nil {
		t.Fatalf("IsRevoked() error = %v", err)
	}
	if revoked {
		t.Error("IsRevoked() = true for non-revoked certificate, want false")
	}
}

func TestU_Store_IsRevoked_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	_, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Check for a serial that doesn't exist
	_, err = store.IsRevoked(context.Background(), []byte{0x99, 0x99, 0x99})
	if err == nil {
		t.Error("IsRevoked() should fail for non-existent certificate")
	}
}

func TestU_Store_LoadCRLForAlgorithm_InvalidPEM(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create crl directory and write invalid PEM
	crlDir := tmpDir + "/crl"
	if err := os.MkdirAll(crlDir, 0755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	crlPath := store.CRLPathForAlgorithm("ecdsa-p256")
	if err := os.WriteFile(crlPath, []byte("not a valid PEM"), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, err := store.LoadCRLForAlgorithm("ecdsa-p256")
	if err == nil {
		t.Error("LoadCRLForAlgorithm() should fail for invalid PEM")
	}
}

func TestU_Store_MarkRevoked_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	_, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Try to revoke a certificate that doesn't exist
	err = store.MarkRevoked(context.Background(), []byte{0x99, 0x99, 0x99}, ReasonKeyCompromise)
	if err == nil {
		t.Error("MarkRevoked() should fail for non-existent certificate")
	}
}

func TestU_Store_CRLDERPathForAlgorithm(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	path := store.CRLDERPathForAlgorithm("ml-dsa-65")
	expected := tmpDir + "/crl/ca.ml-dsa-65.crl.der"

	if path != expected {
		t.Errorf("CRLDERPathForAlgorithm() = %v, want %v", path, expected)
	}
}

// =============================================================================
// Revocation Reason Tests
// =============================================================================

func TestU_Store_MarkRevoked_StoresReason(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Issue a certificate
	subjectKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert, _ := issueTLSServerCert(ca, "server.example.com", []string{"server.example.com"}, &subjectKey.PublicKey)

	// Revoke with keyCompromise reason
	err = store.MarkRevoked(context.Background(), cert.SerialNumber.Bytes(), ReasonKeyCompromise)
	if err != nil {
		t.Fatalf("MarkRevoked() error = %v", err)
	}

	// Read index and verify reason is stored
	entries, err := store.ReadIndex(context.Background())
	if err != nil {
		t.Fatalf("ReadIndex() error = %v", err)
	}

	var found bool
	for _, entry := range entries {
		if entry.Status == "R" {
			found = true
			if entry.RevocationReason != ReasonKeyCompromise {
				t.Errorf("RevocationReason = %v, want %v", entry.RevocationReason, ReasonKeyCompromise)
			}
		}
	}

	if !found {
		t.Error("No revoked entry found in index")
	}
}

func TestU_Store_MarkRevoked_UnspecifiedReason(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Issue a certificate
	subjectKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert, _ := issueTLSServerCert(ca, "server.example.com", []string{"server.example.com"}, &subjectKey.PublicKey)

	// Revoke with unspecified reason (should not append reason to date)
	err = store.MarkRevoked(context.Background(), cert.SerialNumber.Bytes(), ReasonUnspecified)
	if err != nil {
		t.Fatalf("MarkRevoked() error = %v", err)
	}

	// Read index and verify reason is unspecified (default)
	entries, err := store.ReadIndex(context.Background())
	if err != nil {
		t.Fatalf("ReadIndex() error = %v", err)
	}

	var found bool
	for _, entry := range entries {
		if entry.Status == "R" {
			found = true
			if entry.RevocationReason != ReasonUnspecified {
				t.Errorf("RevocationReason = %v, want %v (unspecified)", entry.RevocationReason, ReasonUnspecified)
			}
		}
	}

	if !found {
		t.Error("No revoked entry found in index")
	}
}

func TestU_Store_ParseIndexLine_WithReason(t *testing.T) {
	tests := []struct {
		name           string
		line           string
		wantStatus     string
		wantReason     RevocationReason
		wantRevocation bool
	}{
		{
			name:           "revoked with keyCompromise",
			line:           "R\t301231235959Z\t260127120000Z,keyCompromise\t01\tunknown\tCN=Test",
			wantStatus:     "R",
			wantReason:     ReasonKeyCompromise,
			wantRevocation: true,
		},
		{
			name:           "revoked with superseded",
			line:           "R\t301231235959Z\t260127120000Z,superseded\t02\tunknown\tCN=Test",
			wantStatus:     "R",
			wantReason:     ReasonSuperseded,
			wantRevocation: true,
		},
		{
			name:           "revoked without reason (legacy)",
			line:           "R\t301231235959Z\t260127120000Z\t03\tunknown\tCN=Test",
			wantStatus:     "R",
			wantReason:     ReasonUnspecified,
			wantRevocation: true,
		},
		{
			name:           "valid certificate",
			line:           "V\t301231235959Z\t\t04\tunknown\tCN=Valid",
			wantStatus:     "V",
			wantReason:     ReasonUnspecified,
			wantRevocation: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry, err := parseIndexLine(tt.line)
			if err != nil {
				t.Fatalf("parseIndexLine() error = %v", err)
			}

			if entry.Status != tt.wantStatus {
				t.Errorf("Status = %v, want %v", entry.Status, tt.wantStatus)
			}

			if entry.RevocationReason != tt.wantReason {
				t.Errorf("RevocationReason = %v, want %v", entry.RevocationReason, tt.wantReason)
			}

			if tt.wantRevocation && entry.Revocation.IsZero() {
				t.Error("Revocation time should not be zero")
			}
		})
	}
}

func TestU_Store_AllRevocationReasons(t *testing.T) {
	tests := []struct {
		reason     RevocationReason
		wantString string
	}{
		{ReasonUnspecified, "unspecified"},
		{ReasonKeyCompromise, "keyCompromise"},
		{ReasonCACompromise, "caCompromise"},
		{ReasonAffiliationChanged, "affiliationChanged"},
		{ReasonSuperseded, "superseded"},
		{ReasonCessationOfOperation, "cessationOfOperation"},
		{ReasonCertificateHold, "certificateHold"},
		{ReasonPrivilegeWithdrawn, "privilegeWithdrawn"},
	}

	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	for _, tt := range tests {
		t.Run(tt.wantString, func(t *testing.T) {
			// Issue a certificate
			subjectKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			cert, _ := issueTLSServerCert(ca, "server.example.com", []string{"server.example.com"}, &subjectKey.PublicKey)

			// Revoke with this reason
			err = store.MarkRevoked(context.Background(), cert.SerialNumber.Bytes(), tt.reason)
			if err != nil {
				t.Fatalf("MarkRevoked() error = %v", err)
			}

			// Read index and find this entry
			entries, err := store.ReadIndex(context.Background())
			if err != nil {
				t.Fatalf("ReadIndex() error = %v", err)
			}

			// Find the entry with matching serial
			var found bool
			for _, entry := range entries {
				if string(entry.Serial) == string(cert.SerialNumber.Bytes()) {
					found = true
					if entry.RevocationReason != tt.reason {
						t.Errorf("RevocationReason = %v (%s), want %v (%s)",
							entry.RevocationReason, entry.RevocationReason.String(),
							tt.reason, tt.wantString)
					}
					break
				}
			}

			if !found {
				t.Error("Entry not found in index")
			}
		})
	}
}
