package bundle

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
)

// =============================================================================
// Bundle Tests
// =============================================================================

func TestNewBundle(t *testing.T) {
	subject := Subject{
		CommonName:   "Test User",
		Organization: []string{"Test Org"},
	}

	b := NewBundle("test-bundle-001", subject, "classic")

	if b.ID != "test-bundle-001" {
		t.Errorf("expected ID 'test-bundle-001', got '%s'", b.ID)
	}
	if b.Subject.CommonName != "Test User" {
		t.Errorf("expected CommonName 'Test User', got '%s'", b.Subject.CommonName)
	}
	if b.Gamme != "classic" {
		t.Errorf("expected Gamme 'classic', got '%s'", b.Gamme)
	}
	if b.Status != StatusPending {
		t.Errorf("expected Status StatusPending, got '%s'", b.Status)
	}
	if b.Created.IsZero() {
		t.Error("Created should not be zero")
	}
	if len(b.Certificates) != 0 {
		t.Errorf("expected 0 certificates, got %d", len(b.Certificates))
	}
}

func TestBundle_AddCertificate(t *testing.T) {
	b := NewBundle("test", Subject{CommonName: "Test"}, "classic")

	ref := CertificateRef{
		Serial:      "0x01",
		Role:        RoleSignature,
		Algorithm:   "ECDSA-SHA256",
		Fingerprint: "ABC123",
	}

	b.AddCertificate(ref)

	if len(b.Certificates) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(b.Certificates))
	}
	if b.Certificates[0].Serial != "0x01" {
		t.Errorf("expected serial '0x01', got '%s'", b.Certificates[0].Serial)
	}
}

func TestBundle_SetValidity(t *testing.T) {
	b := NewBundle("test", Subject{CommonName: "Test"}, "classic")

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	b.SetValidity(notBefore, notAfter)

	if !b.NotBefore.Equal(notBefore) {
		t.Errorf("NotBefore mismatch")
	}
	if !b.NotAfter.Equal(notAfter) {
		t.Errorf("NotAfter mismatch")
	}
}

func TestBundle_Activate(t *testing.T) {
	b := NewBundle("test", Subject{CommonName: "Test"}, "classic")

	if b.Status != StatusPending {
		t.Errorf("expected StatusPending before Activate")
	}

	b.Activate()

	if b.Status != StatusValid {
		t.Errorf("expected StatusValid after Activate, got '%s'", b.Status)
	}
}

func TestBundle_Revoke(t *testing.T) {
	b := NewBundle("test", Subject{CommonName: "Test"}, "classic")
	b.Activate()

	b.Revoke("keyCompromise")

	if b.Status != StatusRevoked {
		t.Errorf("expected StatusRevoked, got '%s'", b.Status)
	}
	if b.RevokedAt == nil {
		t.Error("RevokedAt should not be nil")
	}
	if b.RevocationReason != "keyCompromise" {
		t.Errorf("expected reason 'keyCompromise', got '%s'", b.RevocationReason)
	}
}

func TestBundle_IsValid(t *testing.T) {
	b := NewBundle("test", Subject{CommonName: "Test"}, "classic")

	// Not valid before Activate
	if b.IsValid() {
		t.Error("should not be valid before Activate")
	}

	// Activate and set validity
	b.Activate()
	b.SetValidity(time.Now().Add(-1*time.Hour), time.Now().Add(1*time.Hour))

	if !b.IsValid() {
		t.Error("should be valid after Activate with current validity")
	}

	// Test with future validity
	b.SetValidity(time.Now().Add(1*time.Hour), time.Now().Add(2*time.Hour))
	if b.IsValid() {
		t.Error("should not be valid when NotBefore is in the future")
	}
}

func TestBundle_IsExpired(t *testing.T) {
	b := NewBundle("test", Subject{CommonName: "Test"}, "classic")

	// Set past validity
	b.SetValidity(time.Now().Add(-2*time.Hour), time.Now().Add(-1*time.Hour))

	if !b.IsExpired() {
		t.Error("should be expired when NotAfter is in the past")
	}

	// Set future validity
	b.SetValidity(time.Now().Add(-1*time.Hour), time.Now().Add(1*time.Hour))

	if b.IsExpired() {
		t.Error("should not be expired when NotAfter is in the future")
	}
}

func TestBundle_ContainsCertificate(t *testing.T) {
	b := NewBundle("test", Subject{CommonName: "Test"}, "classic")

	b.AddCertificate(CertificateRef{Serial: "0x01", Role: RoleSignature})
	b.AddCertificate(CertificateRef{Serial: "0x02", Role: RoleEncryption})

	if !b.ContainsCertificate("0x01") {
		t.Error("should contain certificate 0x01")
	}
	if !b.ContainsCertificate("0x02") {
		t.Error("should contain certificate 0x02")
	}
	if b.ContainsCertificate("0x03") {
		t.Error("should not contain certificate 0x03")
	}
}

func TestBundle_GetCertificateByRole(t *testing.T) {
	b := NewBundle("test", Subject{CommonName: "Test"}, "classic")

	b.AddCertificate(CertificateRef{Serial: "0x01", Role: RoleSignature})
	b.AddCertificate(CertificateRef{Serial: "0x02", Role: RoleEncryption})

	sigRef := b.GetCertificateByRole(RoleSignature)
	if sigRef == nil {
		t.Fatal("expected to find signature certificate")
	}
	if sigRef.Serial != "0x01" {
		t.Errorf("expected serial '0x01', got '%s'", sigRef.Serial)
	}

	encRef := b.GetCertificateByRole(RoleEncryption)
	if encRef == nil {
		t.Fatal("expected to find encryption certificate")
	}
	if encRef.Serial != "0x02" {
		t.Errorf("expected serial '0x02', got '%s'", encRef.Serial)
	}

	unknownRef := b.GetCertificateByRole(RoleSignaturePQC)
	if unknownRef != nil {
		t.Error("should not find non-existent role")
	}
}

func TestBundle_SignatureCertificates(t *testing.T) {
	b := NewBundle("test", Subject{CommonName: "Test"}, "classic")

	b.AddCertificate(CertificateRef{Serial: "0x01", Role: RoleSignature})
	b.AddCertificate(CertificateRef{Serial: "0x02", Role: RoleSignatureClassical})
	b.AddCertificate(CertificateRef{Serial: "0x03", Role: RoleSignaturePQC})
	b.AddCertificate(CertificateRef{Serial: "0x04", Role: RoleEncryption})

	sigCerts := b.SignatureCertificates()

	if len(sigCerts) != 3 {
		t.Errorf("expected 3 signature certificates, got %d", len(sigCerts))
	}
}

func TestBundle_EncryptionCertificates(t *testing.T) {
	b := NewBundle("test", Subject{CommonName: "Test"}, "classic")

	b.AddCertificate(CertificateRef{Serial: "0x01", Role: RoleSignature})
	b.AddCertificate(CertificateRef{Serial: "0x02", Role: RoleEncryption})
	b.AddCertificate(CertificateRef{Serial: "0x03", Role: RoleEncryptionClassical})
	b.AddCertificate(CertificateRef{Serial: "0x04", Role: RoleEncryptionPQC})

	encCerts := b.EncryptionCertificates()

	if len(encCerts) != 3 {
		t.Errorf("expected 3 encryption certificates, got %d", len(encCerts))
	}
}

func TestSubject_ToPkixName(t *testing.T) {
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

func TestSubjectFromPkixName(t *testing.T) {
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

func TestBundle_JSONMarshalUnmarshal(t *testing.T) {
	original := NewBundle("test-json", Subject{
		CommonName:   "JSON Test",
		Organization: []string{"Test Org"},
	}, "hybrid-catalyst")

	original.Activate()
	original.SetValidity(time.Now(), time.Now().Add(365*24*time.Hour))
	original.AddCertificate(CertificateRef{
		Serial:       "0x01",
		Role:         RoleSignature,
		Algorithm:    "ECDSA-SHA256",
		AltAlgorithm: "ML-DSA-65",
		IsCatalyst:   true,
		Fingerprint:  "ABC123",
	})

	// Marshal
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	// Unmarshal
	var loaded Bundle
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
	if loaded.Gamme != original.Gamme {
		t.Errorf("Gamme mismatch")
	}
	if loaded.Status != original.Status {
		t.Errorf("Status mismatch")
	}
	if len(loaded.Certificates) != len(original.Certificates) {
		t.Errorf("Certificates count mismatch")
	}
	if loaded.Certificates[0].IsCatalyst != original.Certificates[0].IsCatalyst {
		t.Errorf("IsCatalyst mismatch")
	}
}

func TestBundle_Summary(t *testing.T) {
	b := NewBundle("test-summary", Subject{CommonName: "Summary Test"}, "classic")
	b.Activate()
	b.SetValidity(time.Now(), time.Now().Add(365*24*time.Hour))
	b.AddCertificate(CertificateRef{Serial: "0x01", Role: RoleSignature})

	summary := b.Summary()

	if summary == "" {
		t.Error("Summary should not be empty")
	}
	if !contains(summary, "test-summary") {
		t.Error("Summary should contain bundle ID")
	}
	if !contains(summary, "Summary Test") {
		t.Error("Summary should contain subject")
	}
}

// =============================================================================
// PEM Tests
// =============================================================================

func TestEncodeCertificatesPEM(t *testing.T) {
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

func TestDecodeCertificatesPEM(t *testing.T) {
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

func TestEncodeCertificatesPEM_Multiple(t *testing.T) {
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

func TestDecodeCertificatesPEM_Empty(t *testing.T) {
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

func TestFileStore_SaveAndLoad(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	bundle := NewBundle("test-save", Subject{CommonName: "Save Test"}, "classic")
	bundle.Activate()
	bundle.SetValidity(time.Now(), time.Now().Add(365*24*time.Hour))

	// Generate test certificate
	cert := generateTestCertificate(t)
	bundle.AddCertificate(CertificateRef{
		Serial:      "0x01",
		Role:        RoleSignature,
		Algorithm:   cert.SignatureAlgorithm.String(),
		Fingerprint: "TEST",
	})

	// Save
	if err := store.Save(bundle, []*x509.Certificate{cert}, nil, nil); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Load
	loaded, err := store.Load("test-save")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if loaded.ID != bundle.ID {
		t.Errorf("ID mismatch: %s vs %s", loaded.ID, bundle.ID)
	}
	if loaded.Subject.CommonName != bundle.Subject.CommonName {
		t.Errorf("Subject mismatch")
	}
}

func TestFileStore_LoadCertificates(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	bundle := NewBundle("test-certs", Subject{CommonName: "Certs Test"}, "classic")
	cert := generateTestCertificate(t)

	if err := store.Save(bundle, []*x509.Certificate{cert}, nil, nil); err != nil {
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

func TestFileStore_ListAll(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create multiple bundles
	for i := 1; i <= 3; i++ {
		b := NewBundle(
			"bundle-"+string(rune('a'+i-1)),
			Subject{CommonName: "Test"},
			"classic",
		)
		if err := store.Save(b, nil, nil, nil); err != nil {
			t.Fatalf("Save failed: %v", err)
		}
	}

	bundles, err := store.ListAll()
	if err != nil {
		t.Fatalf("ListAll failed: %v", err)
	}

	if len(bundles) != 3 {
		t.Errorf("expected 3 bundles, got %d", len(bundles))
	}
}

func TestFileStore_List(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create bundles with different subjects
	b1 := NewBundle("bundle-alice", Subject{CommonName: "Alice"}, "classic")
	b2 := NewBundle("bundle-bob", Subject{CommonName: "Bob"}, "classic")
	b3 := NewBundle("bundle-alice2", Subject{CommonName: "Alice Smith"}, "classic")

	_ = store.Save(b1, nil, nil, nil)
	_ = store.Save(b2, nil, nil, nil)
	_ = store.Save(b3, nil, nil, nil)

	// List with filter
	ids, err := store.List("Alice")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if len(ids) != 2 {
		t.Errorf("expected 2 bundles matching 'Alice', got %d", len(ids))
	}

	// List all
	allIds, err := store.List("")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if len(allIds) != 3 {
		t.Errorf("expected 3 bundles, got %d", len(allIds))
	}
}

func TestFileStore_UpdateStatus(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	bundle := NewBundle("test-status", Subject{CommonName: "Status Test"}, "classic")
	bundle.Activate()

	if err := store.Save(bundle, nil, nil, nil); err != nil {
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

	if loaded.Status != StatusRevoked {
		t.Errorf("expected StatusRevoked, got '%s'", loaded.Status)
	}
	if loaded.RevocationReason != "keyCompromise" {
		t.Errorf("expected reason 'keyCompromise', got '%s'", loaded.RevocationReason)
	}
}

func TestFileStore_Delete(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	bundle := NewBundle("test-delete", Subject{CommonName: "Delete Test"}, "classic")

	if err := store.Save(bundle, nil, nil, nil); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	if !store.Exists("test-delete") {
		t.Error("bundle should exist after save")
	}

	if err := store.Delete("test-delete"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	if store.Exists("test-delete") {
		t.Error("bundle should not exist after delete")
	}
}

func TestFileStore_Exists(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	if store.Exists("nonexistent") {
		t.Error("should return false for nonexistent bundle")
	}

	bundle := NewBundle("test-exists", Subject{CommonName: "Exists Test"}, "classic")
	_ = store.Save(bundle, nil, nil, nil)

	if !store.Exists("test-exists") {
		t.Error("should return true for existing bundle")
	}
}

func TestFileStore_Load_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	_, err := store.Load("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent bundle")
	}
}

func TestFileStore_BasePath(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	expected := filepath.Join(tmpDir, "bundles")
	if store.BasePath() != expected {
		t.Errorf("expected basePath '%s', got '%s'", expected, store.BasePath())
	}
}

func TestFileStore_Init(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	bundlesDir := filepath.Join(tmpDir, "bundles")

	// Directory shouldn't exist yet
	if _, err := os.Stat(bundlesDir); !os.IsNotExist(err) {
		t.Error("bundles directory should not exist before Init")
	}

	if err := store.Init(); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Directory should exist now
	if _, err := os.Stat(bundlesDir); err != nil {
		t.Error("bundles directory should exist after Init")
	}
}

func TestFileStore_ListAll_EmptyDir(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	bundles, err := store.ListAll()
	if err != nil {
		t.Fatalf("ListAll failed: %v", err)
	}

	if len(bundles) != 0 {
		t.Errorf("expected 0 bundles for empty directory, got %d", len(bundles))
	}
}

// =============================================================================
// CertificateRef Tests
// =============================================================================

func TestCertificateRefFromCert(t *testing.T) {
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
// Status Tests
// =============================================================================

func TestStatus_Constants(t *testing.T) {
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

func TestCertRole_Constants(t *testing.T) {
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
