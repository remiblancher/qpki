package credential

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
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
	if ver.Status != "active" {
		t.Errorf("expected Status 'active', got '%s'", ver.Status)
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

	// Create pending version
	cred.Versions["v2"] = CredVersion{
		Profiles: []string{"pqc"},
		Algos:    []string{"ml-dsa"},
		Status:   "pending",
		Created:  testNow(),
	}

	// Activate v2
	if err := cred.ActivateVersion("v2"); err != nil {
		t.Fatalf("ActivateVersion failed: %v", err)
	}

	if cred.Active != "v2" {
		t.Errorf("expected Active 'v2', got '%s'", cred.Active)
	}

	v1 := cred.Versions["v1"]
	if v1.Status != "archived" {
		t.Errorf("expected v1 Status 'archived', got '%s'", v1.Status)
	}

	v2 := cred.Versions["v2"]
	if v2.Status != "active" {
		t.Errorf("expected v2 Status 'active', got '%s'", v2.Status)
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
