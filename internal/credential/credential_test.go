package credential

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
)

// =============================================================================
// Credential Tests
// =============================================================================

func TestU_NewCredential_Creation(t *testing.T) {
	subject := Subject{
		CommonName:   "Test User",
		Organization: []string{"Test Org"},
	}

	cred := NewCredential("test-credential-001", subject)

	if cred.ID != "test-credential-001" {
		t.Errorf("expected ID 'test-credential-001', got '%s'", cred.ID)
	}
	if cred.Subject.CommonName != "Test User" {
		t.Errorf("expected CommonName 'Test User', got '%s'", cred.Subject.CommonName)
	}
	if cred.Created.IsZero() {
		t.Error("Created should not be zero")
	}
	if cred.Versions == nil {
		t.Error("Versions should be initialized")
	}
}

func TestU_Credential_CreateInitialVersion(t *testing.T) {
	cred := NewCredential("test", Subject{CommonName: "Test"})

	cred.CreateInitialVersion([]string{"classic"}, []string{"ec"})

	if cred.Active != "v1" {
		t.Errorf("expected Active 'v1', got '%s'", cred.Active)
	}
	ver := cred.ActiveVersion()
	if ver == nil {
		t.Fatal("expected active version")
	}
	if len(ver.Profiles) != 1 || ver.Profiles[0] != "classic" {
		t.Errorf("expected Profiles ['classic'], got '%v'", ver.Profiles)
	}
	if cred.GetVersionStatus(cred.Active) != "active" {
		t.Errorf("expected Status 'active', got '%s'", cred.GetVersionStatus(cred.Active))
	}
}

func TestU_Credential_VersionValidity(t *testing.T) {
	cred := NewCredential("test", Subject{CommonName: "Test"})

	notBefore := testNow()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	cred.CreateInitialVersion([]string{"classic"}, []string{"ec"})
	ver := cred.Versions[cred.Active]
	ver.NotBefore = notBefore
	ver.NotAfter = notAfter
	cred.Versions[cred.Active] = ver

	activeVer := cred.ActiveVersion()
	if !activeVer.NotBefore.Equal(notBefore) {
		t.Errorf("NotBefore mismatch")
	}
	if !activeVer.NotAfter.Equal(notAfter) {
		t.Errorf("NotAfter mismatch")
	}
}

func TestU_Credential_ActivateVersion(t *testing.T) {
	cred := NewCredential("test", Subject{CommonName: "Test"})

	// Create initial version (active)
	cred.CreateInitialVersion([]string{"classic"}, []string{"ec"})

	// Create pending version (no Status field - it's computed)
	cred.Versions["v2"] = CredVersion{
		Profiles: []string{"pqc"},
		Algos:    []string{"ml-dsa"},
		Created:  testNow(),
	}

	// Activate v2
	if err := cred.ActivateVersion("v2"); err != nil {
		t.Fatalf("ActivateVersion failed: %v", err)
	}

	if cred.Active != "v2" {
		t.Errorf("expected Active 'v2', got '%s'", cred.Active)
	}

	// Check status via GetVersionStatus (status is computed, not stored)
	if cred.GetVersionStatus("v1") != "archived" {
		t.Errorf("expected v1 Status 'archived', got '%s'", cred.GetVersionStatus("v1"))
	}

	if cred.GetVersionStatus("v2") != "active" {
		t.Errorf("expected v2 Status 'active', got '%s'", cred.GetVersionStatus("v2"))
	}
}

func TestU_Credential_Revoke(t *testing.T) {
	cred := NewCredential("test", Subject{CommonName: "Test"})
	cred.CreateInitialVersion([]string{"classic"}, []string{"ec"})

	cred.Revoke("keyCompromise")

	if cred.RevokedAt == nil {
		t.Error("RevokedAt should not be nil")
	}
	if cred.RevocationReason != "keyCompromise" {
		t.Errorf("expected reason 'keyCompromise', got '%s'", cred.RevocationReason)
	}
}

func TestU_Credential_IsValid(t *testing.T) {
	cred := NewCredential("test", Subject{CommonName: "Test"})

	// Not valid without active version
	if cred.IsValid() {
		t.Error("should not be valid without active version")
	}

	// Create version with current validity
	cred.CreateInitialVersion([]string{"classic"}, []string{"ec"})
	ver := cred.Versions[cred.Active]
	ver.NotBefore = testNow().Add(-1 * time.Hour)
	ver.NotAfter = testNow().Add(1 * time.Hour)
	cred.Versions[cred.Active] = ver

	if !cred.IsValid() {
		t.Error("should be valid with current validity")
	}

	// Test with future validity
	ver.NotBefore = testNow().Add(1 * time.Hour)
	ver.NotAfter = testNow().Add(2 * time.Hour)
	cred.Versions[cred.Active] = ver
	if cred.IsValid() {
		t.Error("should not be valid when NotBefore is in the future")
	}
}

func TestU_Credential_IsExpired(t *testing.T) {
	cred := NewCredential("test", Subject{CommonName: "Test"})
	cred.CreateInitialVersion([]string{"classic"}, []string{"ec"})

	// Set past validity
	ver := cred.Versions[cred.Active]
	ver.NotBefore = testNow().Add(-2 * time.Hour)
	ver.NotAfter = testNow().Add(-1 * time.Hour)
	cred.Versions[cred.Active] = ver

	if !cred.IsExpired() {
		t.Error("should be expired when NotAfter is in the past")
	}

	// Set future validity
	ver.NotBefore = testNow().Add(-1 * time.Hour)
	ver.NotAfter = testNow().Add(1 * time.Hour)
	cred.Versions[cred.Active] = ver

	if cred.IsExpired() {
		t.Error("should not be expired when NotAfter is in the future")
	}
}

func TestU_Credential_NextVersionID(t *testing.T) {
	cred := NewCredential("test", Subject{CommonName: "Test"})
	cred.CreateInitialVersion([]string{"classic"}, []string{"ec"})

	nextID := cred.NextVersionID()
	if nextID != "v2" {
		t.Errorf("expected 'v2', got '%s'", nextID)
	}
}

func TestU_Subject_ToPkixName(t *testing.T) {
	s := Subject{
		CommonName:   "Test User",
		Organization: []string{"Test Org"},
		Country:      []string{"US"},
		Province:     []string{"CA"},
		Locality:     []string{"San Francisco"},
	}

	name := s.ToPkixName()

	if name.CommonName != "Test User" {
		t.Errorf("expected CommonName 'Test User', got '%s'", name.CommonName)
	}
	if len(name.Organization) != 1 || name.Organization[0] != "Test Org" {
		t.Errorf("unexpected Organization: %v", name.Organization)
	}
}

func TestU_SubjectFromPkixName_Conversion(t *testing.T) {
	name := pkix.Name{
		CommonName:   "Test User",
		Organization: []string{"Test Org"},
		Country:      []string{"US"},
	}

	s := SubjectFromPkixName(name)

	if s.CommonName != "Test User" {
		t.Errorf("expected CommonName 'Test User', got '%s'", s.CommonName)
	}
	if len(s.Organization) != 1 || s.Organization[0] != "Test Org" {
		t.Errorf("unexpected Organization: %v", s.Organization)
	}
}

func TestU_Credential_JSONMarshalUnmarshal(t *testing.T) {
	original := NewCredential("test-json", Subject{
		CommonName:   "JSON Test",
		Organization: []string{"Test Org"},
	})
	original.CreateInitialVersion([]string{"hybrid-catalyst"}, []string{"ec", "ml-dsa"})

	ver := original.Versions[original.Active]
	ver.NotBefore = testNow()
	ver.NotAfter = testNow().Add(365 * 24 * time.Hour)
	original.Versions[original.Active] = ver

	// Marshal
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	// Unmarshal
	var loaded Credential
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	// Compare
	if loaded.ID != original.ID {
		t.Errorf("ID mismatch: %s vs %s", loaded.ID, original.ID)
	}
	if loaded.Subject.CommonName != original.Subject.CommonName {
		t.Errorf("Subject mismatch")
	}
	if loaded.Active != original.Active {
		t.Errorf("Active mismatch: %s vs %s", loaded.Active, original.Active)
	}
	loadedVer := loaded.ActiveVersion()
	origVer := original.ActiveVersion()
	if loadedVer == nil || origVer == nil {
		t.Fatal("version should not be nil")
	}
	if len(loadedVer.Profiles) != len(origVer.Profiles) {
		t.Errorf("Profiles length mismatch")
	}
	if len(loadedVer.Algos) != len(origVer.Algos) {
		t.Errorf("Algos length mismatch")
	}
}

func TestU_Credential_Summary(t *testing.T) {
	cred := NewCredential("test-summary", Subject{CommonName: "Summary Test"})
	cred.CreateInitialVersion([]string{"classic"}, []string{"ec"})

	ver := cred.Versions[cred.Active]
	ver.NotBefore = testNow()
	ver.NotAfter = testNow().Add(365 * 24 * time.Hour)
	cred.Versions[cred.Active] = ver

	summary := cred.Summary()

	if summary == "" {
		t.Error("Summary should not be empty")
	}
	if !contains(summary, "test-summary") {
		t.Error("Summary should contain credential ID")
	}
	if !contains(summary, "Summary Test") {
		t.Error("Summary should contain subject")
	}
}

// =============================================================================
// CertificateRef Tests
// =============================================================================

func TestU_CertificateRefFromCert_Creation(t *testing.T) {
	cert := generateTestCertificate(t)

	ref := CertificateRefFromCert(cert, RoleSignature, true, "ML-DSA-65")

	if ref.Role != RoleSignature {
		t.Errorf("expected role RoleSignature, got '%s'", ref.Role)
	}
	if !ref.IsCatalyst {
		t.Error("expected IsCatalyst to be true")
	}
	if ref.AltAlgorithm != "ML-DSA-65" {
		t.Errorf("expected AltAlgorithm 'ML-DSA-65', got '%s'", ref.AltAlgorithm)
	}
	if ref.Serial == "" {
		t.Error("Serial should not be empty")
	}
}

// =============================================================================
// GenerateCredentialID Tests
// =============================================================================

func TestU_GenerateCredentialID_Formats(t *testing.T) {
	tests := []struct {
		name     string
		cn       string
		wantSlug string // Expected prefix (before date)
	}{
		{"[Unit] GenerateCredentialID: simple name", "Alice", "alice"},
		{"[Unit] GenerateCredentialID: with spaces", "Alice Smith", "alice-smith"},
		{"[Unit] GenerateCredentialID: email style", "alice@example.com", "alice-example-com"},
		{"[Unit] GenerateCredentialID: uppercase", "ALICE", "alice"},
		{"[Unit] GenerateCredentialID: with numbers", "User123", "user123"},
		{"[Unit] GenerateCredentialID: empty", "", "cred"},
		{"[Unit] GenerateCredentialID: special chars", "User!@#$%^&*()", "user"},
		{"[Unit] GenerateCredentialID: long name", "This Is A Very Long Common Name That Exceeds The Limit", "this-is-a-very-long-"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := GenerateCredentialID(tt.cn)

			// Check format: {slug}-{YYYYMMDD}-{hash}
			parts := strings.Split(id, "-")
			if len(parts) < 3 {
				t.Errorf("expected at least 3 parts separated by '-', got %d: %s", len(parts), id)
				return
			}

			// Check slug prefix
			if !strings.HasPrefix(id, tt.wantSlug) {
				t.Errorf("expected ID to start with '%s', got '%s'", tt.wantSlug, id)
			}

			// Check date format (YYYYMMDD)
			dateIdx := len(parts) - 2
			if len(parts[dateIdx]) != 8 {
				t.Errorf("expected date part to be 8 chars, got %d: %s", len(parts[dateIdx]), parts[dateIdx])
			}

			// Check hash suffix
			hashIdx := len(parts) - 1
			if len(parts[hashIdx]) != 6 {
				t.Errorf("expected hash to be 6 chars, got %d: %s", len(parts[hashIdx]), parts[hashIdx])
			}
		})
	}
}

func TestU_GenerateCredentialID_Unique(t *testing.T) {
	// Generate multiple IDs and ensure they're unique
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := GenerateCredentialID("Test")
		if ids[id] {
			t.Errorf("duplicate ID generated: %s", id)
		}
		ids[id] = true
	}
}

// =============================================================================
// Status Tests
// =============================================================================

func TestU_Status_Constants(t *testing.T) {
	// Verify status constants exist and have expected values
	if StatusValid != "valid" {
		t.Errorf("unexpected StatusValid value: %s", StatusValid)
	}
	if StatusRevoked != "revoked" {
		t.Errorf("unexpected StatusRevoked value: %s", StatusRevoked)
	}
	if StatusExpired != "expired" {
		t.Errorf("unexpected StatusExpired value: %s", StatusExpired)
	}
	if StatusPending != "pending" {
		t.Errorf("unexpected StatusPending value: %s", StatusPending)
	}
}

// =============================================================================
// CertRole Tests
// =============================================================================

func TestU_CertRole_Constants(t *testing.T) {
	roles := []CertRole{
		RoleSignature,
		RoleSignatureClassical,
		RoleSignaturePQC,
		RoleEncryption,
		RoleEncryptionClassical,
		RoleEncryptionPQC,
	}

	for _, role := range roles {
		if role == "" {
			t.Error("role should not be empty")
		}
	}
}

// =============================================================================
// SubjectFromCertificate Tests
// =============================================================================

func TestU_SubjectFromCertificate_Conversion(t *testing.T) {
	cert := generateTestCertificate(t)

	subject := SubjectFromCertificate(cert)

	if subject.CommonName != cert.Subject.CommonName {
		t.Errorf("CommonName mismatch: expected %s, got %s", cert.Subject.CommonName, subject.CommonName)
	}
}

// =============================================================================
// Helper Functions
// =============================================================================

func generateTestCertificate(t *testing.T) *x509.Certificate {
	t.Helper()

	// Generate key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Create certificate template
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "Test Certificate",
			Organization: []string{"Test Org"},
		},
		NotBefore:             testNow(),
		NotAfter:              testNow().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		SubjectKeyId:          []byte{1, 2, 3, 4},
	}

	// Self-sign
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// testNow returns a consistent time for testing to avoid flaky tests
func testNow() time.Time {
	return time.Now()
}

// =============================================================================
// Path Helper Tests
// =============================================================================

func TestU_Credential_SetBasePath_BasePath(t *testing.T) {
	cred := NewCredential("test", Subject{CommonName: "Test"})

	cred.SetBasePath("/tmp/credentials/test")

	if cred.BasePath() != "/tmp/credentials/test" {
		t.Errorf("BasePath() = %s, want /tmp/credentials/test", cred.BasePath())
	}
}

func TestU_Credential_VersionsDir(t *testing.T) {
	cred := NewCredential("test", Subject{CommonName: "Test"})
	cred.SetBasePath("/tmp/credentials/test")

	versionsDir := cred.VersionsDir()

	expected := "/tmp/credentials/test/versions"
	if versionsDir != expected {
		t.Errorf("VersionsDir() = %s, want %s", versionsDir, expected)
	}
}

func TestU_Credential_VersionDir(t *testing.T) {
	cred := NewCredential("test", Subject{CommonName: "Test"})
	cred.SetBasePath("/tmp/credentials/test")

	versionDir := cred.VersionDir("v1")

	expected := "/tmp/credentials/test/versions/v1"
	if versionDir != expected {
		t.Errorf("VersionDir() = %s, want %s", versionDir, expected)
	}
}

func TestU_Credential_AlgoDir(t *testing.T) {
	cred := NewCredential("test", Subject{CommonName: "Test"})
	cred.SetBasePath("/tmp/credentials/test")

	algoDir := cred.AlgoDir("v1", "ec")

	expected := "/tmp/credentials/test/versions/v1/ec"
	if algoDir != expected {
		t.Errorf("AlgoDir() = %s, want %s", algoDir, expected)
	}
}

func TestU_Credential_CertPath(t *testing.T) {
	cred := NewCredential("test", Subject{CommonName: "Test"})
	cred.SetBasePath("/tmp/credentials/test")

	certPath := cred.CertPath("v1", "ec")

	expected := "/tmp/credentials/test/versions/v1/ec/certificates.pem"
	if certPath != expected {
		t.Errorf("CertPath() = %s, want %s", certPath, expected)
	}
}

func TestU_Credential_KeyPath(t *testing.T) {
	cred := NewCredential("test", Subject{CommonName: "Test"})
	cred.SetBasePath("/tmp/credentials/test")

	keyPath := cred.KeyPath("v1", "ec")

	expected := "/tmp/credentials/test/versions/v1/ec/private-keys.pem"
	if keyPath != expected {
		t.Errorf("KeyPath() = %s, want %s", keyPath, expected)
	}
}

func TestU_Credential_EnsureVersionDir(t *testing.T) {
	tmpDir := t.TempDir()
	cred := NewCredential("test", Subject{CommonName: "Test"})
	cred.SetBasePath(tmpDir)

	// Create directories for each algo
	for _, algo := range []string{"ec", "ml-dsa"} {
		err := cred.EnsureVersionDir("v1", algo)
		if err != nil {
			t.Fatalf("EnsureVersionDir(%s) error = %v", algo, err)
		}
	}

	// Verify directories were created
	for _, algo := range []string{"ec", "ml-dsa"} {
		dir := cred.AlgoDir("v1", algo)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			t.Errorf("EnsureVersionDir() did not create %s", dir)
		}
	}
}

// =============================================================================
// CredentialExists and LoadCredential Tests
// =============================================================================

func TestU_CredentialExists_NotFound(t *testing.T) {
	tmpDir := t.TempDir()

	exists := CredentialExists(tmpDir)
	if exists {
		t.Error("CredentialExists() = true for non-existent credential, want false")
	}
}

func TestU_LoadCredential_NotFound(t *testing.T) {
	tmpDir := t.TempDir()

	_, err := LoadCredential(tmpDir)
	if err == nil {
		t.Error("LoadCredential() should fail for non-existent credential")
	}
}

func TestU_Credential_Save_Success(t *testing.T) {
	tmpDir := t.TempDir()
	cred := NewCredential("test-save", Subject{CommonName: "Save Test"})
	cred.SetBasePath(tmpDir)
	cred.CreateInitialVersion([]string{"classic"}, []string{"ec"})

	err := cred.Save()
	if err != nil {
		t.Fatalf("Save() failed: %v", err)
	}

	// Verify file exists
	if !CredentialExists(tmpDir) {
		t.Error("credential file should exist after Save()")
	}
}

func TestU_Credential_Save_NoBasePath(t *testing.T) {
	cred := NewCredential("test", Subject{CommonName: "Test"})

	err := cred.Save()
	if err == nil {
		t.Error("Save() should fail when basePath is not set")
	}
	if !strings.Contains(err.Error(), "base path not set") {
		t.Errorf("expected 'base path not set' error, got: %v", err)
	}
}

func TestU_LoadCredential_Success(t *testing.T) {
	tmpDir := t.TempDir()

	// Create and save a credential
	original := NewCredential("test-load", Subject{
		CommonName:   "Load Test",
		Organization: []string{"Test Org"},
		Country:      []string{"US"},
	})
	original.SetBasePath(tmpDir)
	original.CreateInitialVersion([]string{"classic"}, []string{"ec"})
	original.Metadata["key1"] = "value1"

	ver := original.Versions[original.Active]
	ver.NotBefore = time.Now().Truncate(time.Second)
	ver.NotAfter = time.Now().Add(365 * 24 * time.Hour).Truncate(time.Second)
	original.Versions[original.Active] = ver

	if err := original.Save(); err != nil {
		t.Fatalf("Save() failed: %v", err)
	}

	// Load it back
	loaded, err := LoadCredential(tmpDir)
	if err != nil {
		t.Fatalf("LoadCredential() failed: %v", err)
	}

	// Verify fields
	if loaded.ID != original.ID {
		t.Errorf("ID mismatch: %s vs %s", loaded.ID, original.ID)
	}
	if loaded.Subject.CommonName != original.Subject.CommonName {
		t.Errorf("CommonName mismatch: %s vs %s", loaded.Subject.CommonName, original.Subject.CommonName)
	}
	if loaded.BasePath() != tmpDir {
		t.Errorf("BasePath mismatch: %s vs %s", loaded.BasePath(), tmpDir)
	}
	if loaded.Metadata["key1"] != "value1" {
		t.Errorf("Metadata mismatch: %v", loaded.Metadata)
	}
}

func TestU_LoadCredential_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()

	// Write invalid JSON
	jsonPath := tmpDir + "/" + InfoFile
	if err := os.WriteFile(jsonPath, []byte("invalid json{"), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	_, err := LoadCredential(tmpDir)
	if err == nil {
		t.Error("LoadCredential() should fail for invalid JSON")
	}
	if !strings.Contains(err.Error(), "failed to parse credential") {
		t.Errorf("expected 'failed to parse credential' error, got: %v", err)
	}
}

func TestU_CredentialExists_Found(t *testing.T) {
	tmpDir := t.TempDir()

	// Create credential file
	cred := NewCredential("test", Subject{CommonName: "Test"})
	cred.SetBasePath(tmpDir)
	if err := cred.Save(); err != nil {
		t.Fatalf("Save() failed: %v", err)
	}

	exists := CredentialExists(tmpDir)
	if !exists {
		t.Error("CredentialExists() = false for existing credential, want true")
	}
}

func TestU_Credential_ActiveVersion_NotFound(t *testing.T) {
	cred := NewCredential("test", Subject{CommonName: "Test"})
	cred.Active = "nonexistent"
	now := time.Now()
	cred.Versions = map[string]CredVersion{
		"v1": {Created: now, ActivatedAt: &now},
	}

	ver := cred.ActiveVersion()
	if ver != nil {
		t.Error("ActiveVersion() should return nil when active version not in map")
	}
}

func TestU_Credential_ActiveVersion_NoActive(t *testing.T) {
	cred := NewCredential("test", Subject{CommonName: "Test"})
	cred.Active = ""

	ver := cred.ActiveVersion()
	if ver != nil {
		t.Error("ActiveVersion() should return nil when no active version set")
	}
}

func TestU_Credential_ActivateVersion_NotFound(t *testing.T) {
	cred := NewCredential("test", Subject{CommonName: "Test"})
	cred.CreateInitialVersion([]string{"classic"}, []string{"ec"})

	err := cred.ActivateVersion("v999")
	if err == nil {
		t.Error("ActivateVersion() should fail for non-existent version")
	}
	if !strings.Contains(err.Error(), "version not found") {
		t.Errorf("expected 'version not found' error, got: %v", err)
	}
}

func TestU_Credential_ActivateVersion_AlreadyActive(t *testing.T) {
	cred := NewCredential("test", Subject{CommonName: "Test"})
	cred.CreateInitialVersion([]string{"classic"}, []string{"ec"})

	// Try to activate already active version
	err := cred.ActivateVersion("v1")
	if err == nil {
		t.Error("ActivateVersion() should fail for already active version")
	}
	if !strings.Contains(err.Error(), "already active") {
		t.Errorf("expected 'already active' error, got: %v", err)
	}
}

func TestU_Credential_ActivateVersion_Rollback(t *testing.T) {
	cred := NewCredential("test", Subject{CommonName: "Test"})
	cred.CreateInitialVersion([]string{"classic"}, []string{"ec"})

	// Create and archive v1 by activating v2
	now := time.Now()
	cred.Versions["v2"] = CredVersion{
		Profiles: []string{"pqc"},
		Algos:    []string{"ml-dsa"},
		Created:  now,
	}
	_ = cred.ActivateVersion("v2")

	// Verify v1 is now archived
	if cred.Versions["v1"].ArchivedAt == nil {
		t.Error("v1 should be archived after activating v2")
	}

	// Rollback: activate archived version v1
	err := cred.ActivateVersion("v1")
	if err != nil {
		t.Errorf("ActivateVersion() should succeed for rollback, got: %v", err)
	}

	// Verify v1 is now active and ArchivedAt is cleared
	if cred.Active != "v1" {
		t.Errorf("Active should be v1, got: %s", cred.Active)
	}
	if cred.Versions["v1"].ArchivedAt != nil {
		t.Error("v1 ArchivedAt should be nil after rollback")
	}

	// Verify v2 is now archived
	if cred.Versions["v2"].ArchivedAt == nil {
		t.Error("v2 should be archived after rollback")
	}
}

func TestU_Credential_Summary_NoActiveVersion(t *testing.T) {
	cred := NewCredential("test-summary", Subject{CommonName: "Summary Test"})

	summary := cred.Summary()
	if !strings.Contains(summary, "no active version") {
		t.Errorf("Summary should mention 'no active version', got: %s", summary)
	}
}

func TestU_Credential_Summary_Revoked(t *testing.T) {
	cred := NewCredential("test-summary", Subject{CommonName: "Summary Test"})
	cred.CreateInitialVersion([]string{"classic"}, []string{"ec"})

	ver := cred.Versions[cred.Active]
	ver.NotBefore = testNow().Add(-1 * time.Hour)
	ver.NotAfter = testNow().Add(1 * time.Hour)
	cred.Versions[cred.Active] = ver

	cred.Revoke("keyCompromise")

	summary := cred.Summary()
	if !strings.Contains(summary, "revoked") {
		t.Errorf("Summary should contain 'revoked', got: %s", summary)
	}
}

func TestU_Credential_Summary_Expired(t *testing.T) {
	cred := NewCredential("test-summary", Subject{CommonName: "Summary Test"})
	cred.CreateInitialVersion([]string{"classic"}, []string{"ec"})

	ver := cred.Versions[cred.Active]
	ver.NotBefore = testNow().Add(-2 * time.Hour)
	ver.NotAfter = testNow().Add(-1 * time.Hour)
	cred.Versions[cred.Active] = ver

	summary := cred.Summary()
	if !strings.Contains(summary, "expired") {
		t.Errorf("Summary should contain 'expired', got: %s", summary)
	}
}

func TestU_Credential_IsExpired_NoActiveVersion(t *testing.T) {
	cred := NewCredential("test", Subject{CommonName: "Test"})

	expired := cred.IsExpired()
	if !expired {
		t.Error("IsExpired() should return true when no active version")
	}
}

func TestU_Credential_IsValid_Revoked(t *testing.T) {
	cred := NewCredential("test", Subject{CommonName: "Test"})
	cred.CreateInitialVersion([]string{"classic"}, []string{"ec"})

	ver := cred.Versions[cred.Active]
	ver.NotBefore = testNow().Add(-1 * time.Hour)
	ver.NotAfter = testNow().Add(1 * time.Hour)
	cred.Versions[cred.Active] = ver

	cred.Revoke("test")

	if cred.IsValid() {
		t.Error("IsValid() should return false when credential is revoked")
	}
}

func TestU_CertificateRefFromCert_NoSKID(t *testing.T) {
	// Generate key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Create certificate template without SubjectKeyId
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "Test Certificate",
		},
		NotBefore:             testNow(),
		NotAfter:              testNow().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		// No SubjectKeyId
	}

	// Self-sign
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	ref := CertificateRefFromCert(cert, RoleSignature, false, "")

	// Should use serial as fingerprint since no SKID
	if ref.Fingerprint == "" {
		t.Error("Fingerprint should not be empty")
	}
	// Fingerprint should be based on serial number (hex encoded)
	if len(ref.Fingerprint) < 2 {
		t.Errorf("Fingerprint too short: %s", ref.Fingerprint)
	}
}
