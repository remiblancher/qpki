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
	"path/filepath"
	"strings"
	"testing"
	"time"

	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
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

	notBefore := time.Now()
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
		Created:  time.Now(),
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
	ver.NotBefore = time.Now().Add(-1 * time.Hour)
	ver.NotAfter = time.Now().Add(1 * time.Hour)
	cred.Versions[cred.Active] = ver

	if !cred.IsValid() {
		t.Error("should be valid with current validity")
	}

	// Test with future validity
	ver.NotBefore = time.Now().Add(1 * time.Hour)
	ver.NotAfter = time.Now().Add(2 * time.Hour)
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
	ver.NotBefore = time.Now().Add(-2 * time.Hour)
	ver.NotAfter = time.Now().Add(-1 * time.Hour)
	cred.Versions[cred.Active] = ver

	if !cred.IsExpired() {
		t.Error("should be expired when NotAfter is in the past")
	}

	// Set future validity
	ver.NotBefore = time.Now().Add(-1 * time.Hour)
	ver.NotAfter = time.Now().Add(1 * time.Hour)
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
	ver.NotBefore = time.Now()
	ver.NotAfter = time.Now().Add(365 * 24 * time.Hour)
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
	ver.NotBefore = time.Now()
	ver.NotAfter = time.Now().Add(365 * 24 * time.Hour)
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
// PEM Tests
// =============================================================================

func TestU_EncodeCertificatesPEM_Single(t *testing.T) {
	cert := generateTestCertificate(t)

	pem, err := EncodeCertificatesPEM([]*x509.Certificate{cert})
	if err != nil {
		t.Fatalf("failed to encode: %v", err)
	}

	if len(pem) == 0 {
		t.Error("PEM should not be empty")
	}
	if !contains(string(pem), "-----BEGIN CERTIFICATE-----") {
		t.Error("PEM should contain certificate header")
	}
}

func TestU_DecodeCertificatesPEM_Single(t *testing.T) {
	cert := generateTestCertificate(t)

	// Encode
	pemData, err := EncodeCertificatesPEM([]*x509.Certificate{cert})
	if err != nil {
		t.Fatalf("failed to encode: %v", err)
	}

	// Decode
	certs, err := DecodeCertificatesPEM(pemData)
	if err != nil {
		t.Fatalf("failed to decode: %v", err)
	}

	if len(certs) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(certs))
	}
	if certs[0].Subject.CommonName != cert.Subject.CommonName {
		t.Errorf("certificate subject mismatch")
	}
}

func TestU_EncodeCertificatesPEM_Multiple(t *testing.T) {
	cert1 := generateTestCertificate(t)
	cert2 := generateTestCertificate(t)

	pemData, err := EncodeCertificatesPEM([]*x509.Certificate{cert1, cert2})
	if err != nil {
		t.Fatalf("failed to encode: %v", err)
	}

	certs, err := DecodeCertificatesPEM(pemData)
	if err != nil {
		t.Fatalf("failed to decode: %v", err)
	}

	if len(certs) != 2 {
		t.Errorf("expected 2 certificates, got %d", len(certs))
	}
}

func TestU_DecodeCertificatesPEM_Empty(t *testing.T) {
	certs, err := DecodeCertificatesPEM([]byte{})
	if err != nil {
		t.Fatalf("unexpected error for empty data: %v", err)
	}
	if len(certs) != 0 {
		t.Errorf("expected 0 certificates, got %d", len(certs))
	}
}

// =============================================================================
// FileStore Tests
// =============================================================================

func TestU_FileStore_SaveAndLoad(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cred := NewCredential("test-save", Subject{CommonName: "Save Test"})
	cred.CreateInitialVersion([]string{"ec/tls-server"}, []string{"ec"})
	ver := cred.Versions["v1"]
	ver.NotBefore = time.Now()
	ver.NotAfter = time.Now().Add(365 * 24 * time.Hour)
	cred.Versions["v1"] = ver

	// Generate test certificate
	cert := generateTestCertificate(t)

	// Save
	if err := store.Save(cred, []*x509.Certificate{cert}, nil, nil); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Load
	loaded, err := store.Load("test-save")
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

	if err := store.Save(cred, []*x509.Certificate{cert}, nil, nil); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	certs, err := store.LoadCertificates("test-certs")
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
		if err := store.Save(cred, nil, nil, nil); err != nil {
			t.Fatalf("Save failed: %v", err)
		}
	}

	credentials, err := store.ListAll()
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

	_ = store.Save(cred1, nil, nil, nil)
	_ = store.Save(cred2, nil, nil, nil)
	_ = store.Save(cred3, nil, nil, nil)

	// List with filter
	ids, err := store.List("Alice")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if len(ids) != 2 {
		t.Errorf("expected 2 credentials matching 'Alice', got %d", len(ids))
	}

	// List all
	allIds, err := store.List("")
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

	if err := store.Save(cred, nil, nil, nil); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Update status
	if err := store.UpdateStatus("test-status", StatusRevoked, "keyCompromise"); err != nil {
		t.Fatalf("UpdateStatus failed: %v", err)
	}

	// Reload and verify
	loaded, err := store.Load("test-status")
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

	if err := store.Save(cred, nil, nil, nil); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	if !store.Exists("test-delete") {
		t.Error("credential should exist after save")
	}

	if err := store.Delete("test-delete"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	if store.Exists("test-delete") {
		t.Error("credential should not exist after delete")
	}
}

func TestU_FileStore_Exists(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	if store.Exists("nonexistent") {
		t.Error("should return false for nonexistent credential")
	}

	cred := NewCredential("test-exists", Subject{CommonName: "Exists Test"})
	_ = store.Save(cred, nil, nil, nil)

	if !store.Exists("test-exists") {
		t.Error("should return true for existing credential")
	}
}

func TestU_FileStore_Load_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	_, err := store.Load("nonexistent")
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

	credentials, err := store.ListAll()
	if err != nil {
		t.Fatalf("ListAll failed: %v", err)
	}

	if len(credentials) != 0 {
		t.Errorf("expected 0 credentials for empty directory, got %d", len(credentials))
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
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
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

// =============================================================================
// EncodePrivateKeysPEM Tests
// =============================================================================

func TestU_EncodePrivateKeysPEM_ECDSA(t *testing.T) {
	// Generate ECDSA key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Create a software signer
	signer, err := pkicrypto.NewSoftwareSigner(&pkicrypto.KeyPair{
		Algorithm:  pkicrypto.AlgECDSAP256,
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	})
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	// Encode without passphrase
	pemData, err := EncodePrivateKeysPEM([]pkicrypto.Signer{signer}, nil)
	if err != nil {
		t.Fatalf("EncodePrivateKeysPEM failed: %v", err)
	}

	if len(pemData) == 0 {
		t.Error("PEM data should not be empty")
	}
	if !contains(string(pemData), "-----BEGIN PRIVATE KEY-----") {
		t.Error("PEM should contain private key header")
	}
}

func TestU_EncodePrivateKeysPEM_WithPassphrase(t *testing.T) {
	// Generate ECDSA key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	signer, err := pkicrypto.NewSoftwareSigner(&pkicrypto.KeyPair{
		Algorithm:  pkicrypto.AlgECDSAP256,
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	})
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	// Encode with passphrase
	passphrase := []byte("testpassword")
	pemData, err := EncodePrivateKeysPEM([]pkicrypto.Signer{signer}, passphrase)
	if err != nil {
		t.Fatalf("EncodePrivateKeysPEM with passphrase failed: %v", err)
	}

	if len(pemData) == 0 {
		t.Error("PEM data should not be empty")
	}
	// Encrypted PEM should contain DEK-Info header
	if !contains(string(pemData), "DEK-Info") && !contains(string(pemData), "ENCRYPTED") {
		t.Error("PEM should be encrypted")
	}
}

func TestU_EncodePrivateKeysPEM_MultipleKeys(t *testing.T) {
	var signers []pkicrypto.Signer

	// Generate two ECDSA keys
	for i := 0; i < 2; i++ {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate key %d: %v", i, err)
		}

		signer, err := pkicrypto.NewSoftwareSigner(&pkicrypto.KeyPair{
			Algorithm:  pkicrypto.AlgECDSAP256,
			PrivateKey: privateKey,
			PublicKey:  &privateKey.PublicKey,
		})
		if err != nil {
			t.Fatalf("failed to create signer %d: %v", i, err)
		}
		signers = append(signers, signer)
	}

	pemData, err := EncodePrivateKeysPEM(signers, nil)
	if err != nil {
		t.Fatalf("EncodePrivateKeysPEM failed: %v", err)
	}

	// Count PEM blocks
	count := strings.Count(string(pemData), "-----BEGIN PRIVATE KEY-----")
	if count != 2 {
		t.Errorf("expected 2 private key blocks, got %d", count)
	}
}

func TestU_EncodePrivateKeysPEM_MLDSA(t *testing.T) {
	// Generate ML-DSA key
	signer, err := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgMLDSA65)
	if err != nil {
		t.Fatalf("failed to generate ML-DSA key: %v", err)
	}

	pemData, err := EncodePrivateKeysPEM([]pkicrypto.Signer{signer}, nil)
	if err != nil {
		t.Fatalf("EncodePrivateKeysPEM failed: %v", err)
	}

	if len(pemData) == 0 {
		t.Error("PEM data should not be empty")
	}
	if !contains(string(pemData), "ML-DSA-65 PRIVATE KEY") {
		t.Error("PEM should contain ML-DSA-65 private key header")
	}
}

// =============================================================================
// SaveCredentialPEM and LoadCredentialPEM Tests
// =============================================================================

func TestU_SaveCredentialPEM_Basic(t *testing.T) {
	tmpDir := t.TempDir()
	certsPath := filepath.Join(tmpDir, "certs.pem")
	keysPath := filepath.Join(tmpDir, "keys.pem")

	// Generate certificate and key
	cert := generateTestCertificate(t)
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, err := pkicrypto.NewSoftwareSigner(&pkicrypto.KeyPair{
		Algorithm:  pkicrypto.AlgECDSAP256,
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	})
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	// Save
	err = SaveCredentialPEM(certsPath, keysPath, []*x509.Certificate{cert}, []pkicrypto.Signer{signer}, nil)
	if err != nil {
		t.Fatalf("SaveCredentialPEM failed: %v", err)
	}

	// Verify files exist
	if _, err := os.Stat(certsPath); os.IsNotExist(err) {
		t.Error("certificates file should exist")
	}
	if _, err := os.Stat(keysPath); os.IsNotExist(err) {
		t.Error("keys file should exist")
	}
}

func TestU_SaveCredentialPEM_WithPassphrase(t *testing.T) {
	tmpDir := t.TempDir()
	certsPath := filepath.Join(tmpDir, "certs.pem")
	keysPath := filepath.Join(tmpDir, "keys.pem")

	cert := generateTestCertificate(t)
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := pkicrypto.NewSoftwareSigner(&pkicrypto.KeyPair{
		Algorithm:  pkicrypto.AlgECDSAP256,
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	})

	passphrase := []byte("secretpassword")
	err := SaveCredentialPEM(certsPath, keysPath, []*x509.Certificate{cert}, []pkicrypto.Signer{signer}, passphrase)
	if err != nil {
		t.Fatalf("SaveCredentialPEM with passphrase failed: %v", err)
	}

	// Verify keys file is encrypted
	keysData, _ := os.ReadFile(keysPath)
	if !contains(string(keysData), "DEK-Info") && !contains(string(keysData), "ENCRYPTED") {
		t.Error("keys file should be encrypted")
	}
}

func TestU_SaveCredentialPEM_CertsOnly(t *testing.T) {
	tmpDir := t.TempDir()
	certsPath := filepath.Join(tmpDir, "certs.pem")

	cert := generateTestCertificate(t)

	// Save with no keys
	err := SaveCredentialPEM(certsPath, "", []*x509.Certificate{cert}, nil, nil)
	if err != nil {
		t.Fatalf("SaveCredentialPEM failed: %v", err)
	}

	// Verify certs file exists
	if _, err := os.Stat(certsPath); os.IsNotExist(err) {
		t.Error("certificates file should exist")
	}
}

func TestU_LoadCredentialPEM_Basic(t *testing.T) {
	tmpDir := t.TempDir()
	certsPath := filepath.Join(tmpDir, "certs.pem")

	// Create and save a certificate
	cert := generateTestCertificate(t)
	certsPEM, _ := EncodeCertificatesPEM([]*x509.Certificate{cert})
	_ = os.WriteFile(certsPath, certsPEM, 0644)

	// Load
	certs, signers, err := LoadCredentialPEM(certsPath, "", nil)
	if err != nil {
		t.Fatalf("LoadCredentialPEM failed: %v", err)
	}

	if len(certs) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(certs))
	}
	if len(signers) != 0 {
		t.Errorf("expected 0 signers when no keys path provided, got %d", len(signers))
	}
}

func TestU_LoadCredentialPEM_NotFound(t *testing.T) {
	_, _, err := LoadCredentialPEM("/nonexistent/path.pem", "", nil)
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestU_LoadCredentialPEM_MultipleCerts(t *testing.T) {
	tmpDir := t.TempDir()
	certsPath := filepath.Join(tmpDir, "certs.pem")

	// Create and save multiple certificates
	cert1 := generateTestCertificate(t)
	cert2 := generateTestCertificate(t)
	certsPEM, _ := EncodeCertificatesPEM([]*x509.Certificate{cert1, cert2})
	_ = os.WriteFile(certsPath, certsPEM, 0644)

	// Load
	certs, _, err := LoadCredentialPEM(certsPath, "", nil)
	if err != nil {
		t.Fatalf("LoadCredentialPEM failed: %v", err)
	}

	if len(certs) != 2 {
		t.Errorf("expected 2 certificates, got %d", len(certs))
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
// FileStore Internal Methods Tests
// =============================================================================

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

// =============================================================================
// DecodePrivateKeysPEM Tests
// =============================================================================

func TestDecodePrivateKeysPEM_Empty(t *testing.T) {
	// Empty data should return empty slice
	signers, err := DecodePrivateKeysPEM([]byte{}, nil)
	if err != nil {
		t.Fatalf("DecodePrivateKeysPEM failed: %v", err)
	}
	if len(signers) != 0 {
		t.Errorf("expected 0 signers, got %d", len(signers))
	}
}

func TestDecodePrivateKeysPEM_InvalidPEM(t *testing.T) {
	// Non-PEM data should return empty slice
	signers, err := DecodePrivateKeysPEM([]byte("not a pem file"), nil)
	if err != nil {
		t.Fatalf("DecodePrivateKeysPEM failed: %v", err)
	}
	if len(signers) != 0 {
		t.Errorf("expected 0 signers, got %d", len(signers))
	}
}

// =============================================================================
// FileStore.LoadKeys Tests
// =============================================================================

func TestFileStore_LoadKeys_NoFile(t *testing.T) {
	tmpDir := t.TempDir()
	credentialsDir := filepath.Join(tmpDir, "credentials")
	store := NewFileStore(credentialsDir)

	// Create credential directory without keys file
	credDir := filepath.Join(credentialsDir, "test-cred")
	_ = os.MkdirAll(credDir, 0700)

	signers, err := store.LoadKeys("test-cred", nil)
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

	signers, err := store.LoadKeys("test-cred", nil)
	if err != nil {
		t.Fatalf("LoadKeys failed: %v", err)
	}
	if len(signers) != 0 {
		t.Errorf("expected 0 signers for empty file, got %d", len(signers))
	}
}

// =============================================================================
// FileStore.Save Tests
// =============================================================================

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

	err := store.Save(cred, []*x509.Certificate{cert}, []pkicrypto.Signer{signer}, []byte("password"))
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

	err := store.Save(cred, nil, nil, nil)
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

// =============================================================================
// FileStore.Load Error Cases Tests
// =============================================================================

func TestFileStore_Load_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	credentialsDir := filepath.Join(tmpDir, "credentials")
	store := NewFileStore(credentialsDir)

	// Create credential directory with invalid JSON
	credDir := filepath.Join(credentialsDir, "bad-json")
	_ = os.MkdirAll(credDir, 0700)
	_ = os.WriteFile(filepath.Join(credDir, "credential.meta.json"), []byte("not json"), 0644)

	_, err := store.Load("bad-json")
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

	certs, err := store.LoadCertificates("bad-pem")
	// Should return empty slice, not error for invalid PEM
	if err != nil {
		t.Fatalf("LoadCertificates failed: %v", err)
	}
	if len(certs) != 0 {
		t.Errorf("expected 0 certs for invalid PEM, got %d", len(certs))
	}
}

// =============================================================================
// FileStore.Delete Tests
// =============================================================================

func TestFileStore_Delete_Success(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create a credential
	cred := NewCredential("delete-test", Subject{CommonName: "Test"})
	_ = store.Save(cred, nil, nil, nil)

	// Verify it exists
	if !store.Exists(cred.ID) {
		t.Fatal("credential should exist before delete")
	}

	// Delete
	err := store.Delete(cred.ID)
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Verify it's gone
	if store.Exists(cred.ID) {
		t.Error("credential should not exist after delete")
	}
}

func TestFileStore_Delete_NotExists(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Delete non-existent should not error
	err := store.Delete("nonexistent")
	if err != nil {
		t.Errorf("Delete non-existent should not error: %v", err)
	}
}

// =============================================================================
// FileStore.UpdateStatus Tests
// =============================================================================

func TestFileStore_UpdateStatus_Revoke(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create a credential
	cred := NewCredential("status-test", Subject{CommonName: "Test"})
	cred.CreateInitialVersion([]string{"ec/tls-server"}, []string{"ec"})
	_ = store.Save(cred, nil, nil, nil)

	// Revoke
	err := store.UpdateStatus(cred.ID, StatusRevoked, "key compromise")
	if err != nil {
		t.Fatalf("UpdateStatus failed: %v", err)
	}

	// Verify status
	loaded, _ := store.Load(cred.ID)
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

	err := store.UpdateStatus("nonexistent", StatusRevoked, "test")
	if err == nil {
		t.Error("expected error for non-existent credential")
	}
}

// =============================================================================
// FileStore.List Tests
// =============================================================================

func TestFileStore_List_WithFilter(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create credentials with different subjects
	cred1 := NewCredential("alice-1", Subject{CommonName: "Alice Smith"})
	cred2 := NewCredential("bob-1", Subject{CommonName: "Bob Jones"})
	_ = store.Save(cred1, nil, nil, nil)
	_ = store.Save(cred2, nil, nil, nil)

	// Filter by "alice"
	ids, err := store.List("alice")
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
	_ = store.Save(cred, nil, nil, nil)

	// Filter that matches nothing
	ids, err := store.List("nonexistent")
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
	ids, err := store.List("")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(ids) != 0 {
		t.Errorf("expected empty list, got %v", ids)
	}
}

// =============================================================================
// FileStore Version Functions Tests
// =============================================================================

func TestU_FileStore_GetVersionStore(t *testing.T) {
	tmpDir := t.TempDir()
	credentialsDir := filepath.Join(tmpDir, "credentials")
	store := NewFileStore(credentialsDir)

	vs := store.GetVersionStore("test-cred")
	if vs == nil {
		t.Fatal("GetVersionStore returned nil")
	}

	expectedBase := filepath.Join(credentialsDir, "test-cred")
	if vs.basePath != expectedBase {
		t.Errorf("expected basePath '%s', got '%s'", expectedBase, vs.basePath)
	}
}

func TestU_FileStore_SaveVersion(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create credential first
	cred := NewCredential("version-test", Subject{CommonName: "Test"})
	if err := store.Save(cred, nil, nil, nil); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Create version store and version
	vs := store.GetVersionStore(cred.ID)
	version, err := vs.CreateVersion([]string{"ec/tls-server"})
	if err != nil {
		t.Fatalf("CreateVersion failed: %v", err)
	}

	// Generate test certificate and signer
	cert := generateTestCertificate(t)
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := pkicrypto.NewSoftwareSigner(&pkicrypto.KeyPair{
		Algorithm:  pkicrypto.AlgECDSAP256,
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	})

	// Save version
	err = store.SaveVersion(cred.ID, version.ID, "ec", []*x509.Certificate{cert}, []pkicrypto.Signer{signer}, nil)
	if err != nil {
		t.Fatalf("SaveVersion failed: %v", err)
	}

	// Verify files were created
	profileDir := vs.ProfileDir(version.ID, "ec")
	if _, err := os.Stat(filepath.Join(profileDir, "certificates.pem")); os.IsNotExist(err) {
		t.Error("certificates.pem should exist")
	}
	if _, err := os.Stat(filepath.Join(profileDir, "private-keys.pem")); os.IsNotExist(err) {
		t.Error("private-keys.pem should exist")
	}
}

func TestU_FileStore_SaveVersion_CertsOnly(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create credential and version
	cred := NewCredential("version-certs", Subject{CommonName: "Test"})
	_ = store.Save(cred, nil, nil, nil)

	vs := store.GetVersionStore(cred.ID)
	version, _ := vs.CreateVersion([]string{"ec/tls-server"})

	cert := generateTestCertificate(t)

	// Save version with certs only
	err := store.SaveVersion(cred.ID, version.ID, "ec", []*x509.Certificate{cert}, nil, nil)
	if err != nil {
		t.Fatalf("SaveVersion failed: %v", err)
	}

	// Verify cert file exists but key file doesn't
	profileDir := vs.ProfileDir(version.ID, "ec")
	if _, err := os.Stat(filepath.Join(profileDir, "certificates.pem")); os.IsNotExist(err) {
		t.Error("certificates.pem should exist")
	}
	if _, err := os.Stat(filepath.Join(profileDir, "private-keys.pem")); !os.IsNotExist(err) {
		t.Error("private-keys.pem should not exist when no signers provided")
	}
}

func TestU_FileStore_LoadVersionCertificates(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Setup credential and version
	cred := NewCredential("load-version-certs", Subject{CommonName: "Test"})
	_ = store.Save(cred, nil, nil, nil)

	vs := store.GetVersionStore(cred.ID)
	version, _ := vs.CreateVersion([]string{"ec/tls-server"})

	cert := generateTestCertificate(t)
	_ = store.SaveVersion(cred.ID, version.ID, "ec", []*x509.Certificate{cert}, nil, nil)

	// Load version certificates
	certs, err := store.LoadVersionCertificates(cred.ID, version.ID, "ec")
	if err != nil {
		t.Fatalf("LoadVersionCertificates failed: %v", err)
	}

	if len(certs) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(certs))
	}
}

func TestU_FileStore_LoadVersionCertificates_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Setup credential and version but don't save certs
	cred := NewCredential("load-no-certs", Subject{CommonName: "Test"})
	_ = store.Save(cred, nil, nil, nil)

	vs := store.GetVersionStore(cred.ID)
	version, _ := vs.CreateVersion([]string{"ec/tls-server"})

	// Load non-existent certs
	certs, err := store.LoadVersionCertificates(cred.ID, version.ID, "ec")
	if err != nil {
		t.Fatalf("LoadVersionCertificates should not error for missing file: %v", err)
	}
	if certs != nil {
		t.Errorf("expected nil for missing file, got %d certs", len(certs))
	}
}

func TestU_FileStore_LoadVersionKeys(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Setup credential and version
	cred := NewCredential("load-version-keys", Subject{CommonName: "Test"})
	_ = store.Save(cred, nil, nil, nil)

	vs := store.GetVersionStore(cred.ID)
	version, _ := vs.CreateVersion([]string{"ec/tls-server"})

	// Save with keys
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := pkicrypto.NewSoftwareSigner(&pkicrypto.KeyPair{
		Algorithm:  pkicrypto.AlgECDSAP256,
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	})
	_ = store.SaveVersion(cred.ID, version.ID, "ec", nil, []pkicrypto.Signer{signer}, nil)

	// Load version keys
	signers, err := store.LoadVersionKeys(cred.ID, version.ID, "ec", nil)
	if err != nil {
		t.Fatalf("LoadVersionKeys failed: %v", err)
	}

	if len(signers) != 1 {
		t.Errorf("expected 1 signer, got %d", len(signers))
	}
}

func TestU_FileStore_LoadVersionKeys_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Setup credential and version but don't save keys
	cred := NewCredential("load-no-keys", Subject{CommonName: "Test"})
	_ = store.Save(cred, nil, nil, nil)

	vs := store.GetVersionStore(cred.ID)
	version, _ := vs.CreateVersion([]string{"ec/tls-server"})

	// Load non-existent keys
	signers, err := store.LoadVersionKeys(cred.ID, version.ID, "ec", nil)
	if err != nil {
		t.Fatalf("LoadVersionKeys should not error for missing file: %v", err)
	}
	if signers != nil {
		t.Errorf("expected nil for missing file, got %d signers", len(signers))
	}
}

func TestU_FileStore_ActivateVersion(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Setup credential and version
	cred := NewCredential("activate-version", Subject{CommonName: "Test"})
	_ = store.Save(cred, nil, nil, nil)

	vs := store.GetVersionStore(cred.ID)
	version, _ := vs.CreateVersion([]string{"ec/tls-server"})
	_ = vs.AddCertificate(version.ID, VersionCertRef{AlgorithmFamily: "ec"})

	// Activate via store
	err := store.ActivateVersion(cred.ID, version.ID)
	if err != nil {
		t.Fatalf("ActivateVersion failed: %v", err)
	}

	// Verify activation
	loadedVersion, _ := vs.GetVersion(version.ID)
	if loadedVersion.Status != VersionStatusActive {
		t.Errorf("expected active status, got '%s'", loadedVersion.Status)
	}
}

func TestU_FileStore_ListVersions(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Setup credential and versions
	cred := NewCredential("list-versions", Subject{CommonName: "Test"})
	_ = store.Save(cred, nil, nil, nil)

	vs := store.GetVersionStore(cred.ID)
	_, _ = vs.CreateVersion([]string{"ec/tls-server"})
	_, _ = vs.CreateVersion([]string{"ml-dsa/tls-server"})

	// List via store
	versions, err := store.ListVersions(cred.ID)
	if err != nil {
		t.Fatalf("ListVersions failed: %v", err)
	}

	if len(versions) != 2 {
		t.Errorf("expected 2 versions, got %d", len(versions))
	}
}

func TestU_FileStore_IsVersioned_False(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create non-versioned credential
	cred := NewCredential("non-versioned", Subject{CommonName: "Test"})
	_ = store.Save(cred, nil, nil, nil)

	if store.IsVersioned(cred.ID) {
		t.Error("credential should not be versioned")
	}
}

func TestU_FileStore_IsVersioned_True(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create versioned credential
	cred := NewCredential("versioned", Subject{CommonName: "Test"})
	_ = store.Save(cred, nil, nil, nil)

	vs := store.GetVersionStore(cred.ID)
	_, _ = vs.CreateVersion([]string{"ec/tls-server"})

	if !store.IsVersioned(cred.ID) {
		t.Error("credential should be versioned after creating version")
	}
}
