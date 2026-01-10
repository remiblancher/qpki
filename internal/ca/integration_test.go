package ca

import (
	"context"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/remiblancher/post-quantum-pki/internal/credential"
	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
)

// =============================================================================
// Integration Tests: CA → Credential Workflow
// =============================================================================

// TestIntegration_CAInitAndStore tests the CA initialization and store interaction.
func TestIntegration_CAInitAndStore(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create temp directories for CA and credentials
	tempDir := t.TempDir()
	caDir := filepath.Join(tempDir, "ca")
	credDir := filepath.Join(tempDir, "credentials")

	// Initialize CA store
	caStore := NewFileStore(caDir)
	if err := caStore.Init(context.Background()); err != nil {
		t.Fatalf("Failed to init CA store: %v", err)
	}

	// Create CA with ECDSA P-256
	cfg := Config{
		CommonName:    "Test Integration CA",
		Organization:  "Test Org",
		Country:       "US",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		Profile:       "ec/root-ca",
	}

	_, err := Initialize(caStore, cfg)
	if err != nil {
		t.Fatalf("Failed to init CA: %v", err)
	}

	// Verify CA was created
	if !caStore.Exists() {
		t.Error("CA store should exist after initialization")
	}

	// Load CA certificate
	caCert, err := caStore.LoadCACert(context.Background())
	if err != nil {
		t.Fatalf("Failed to load CA cert: %v", err)
	}

	if caCert.Subject.CommonName != cfg.CommonName {
		t.Errorf("CA CN mismatch: got %s, want %s", caCert.Subject.CommonName, cfg.CommonName)
	}

	// Initialize credential store
	credStore := credential.NewFileStore(credDir)
	if err := credStore.Init(); err != nil {
		t.Fatalf("Failed to init credential store: %v", err)
	}

	// Test that we can create and save a credential
	cred := credential.NewCredential("test-cred-1", credential.Subject{
		CommonName: "test.example.com",
	})
	cred.CreateInitialVersion([]string{"ec/tls-server"}, []string{"ec"})

	// Create a self-signed test cert (simulating what enrollment would produce)
	testCert := createMockTestCert(t, 100, "test.example.com")

	err = credStore.Save(context.Background(), cred, []*x509.Certificate{testCert}, nil, nil)
	if err != nil {
		t.Fatalf("Failed to save credential: %v", err)
	}

	// Verify credential was saved
	if !credStore.Exists(context.Background(), "test-cred-1") {
		t.Error("Credential should exist after save")
	}

	// Load and verify credential
	loadedCred, err := credStore.Load(context.Background(), "test-cred-1")
	if err != nil {
		t.Fatalf("Failed to load credential: %v", err)
	}

	if loadedCred.Subject.CommonName != cred.Subject.CommonName {
		t.Errorf("CN mismatch: got %s, want %s", loadedCred.Subject.CommonName, cred.Subject.CommonName)
	}

	// Load and verify certificates
	loadedCerts, err := credStore.LoadCertificates(context.Background(), "test-cred-1")
	if err != nil {
		t.Fatalf("Failed to load certificates: %v", err)
	}

	if len(loadedCerts) != 1 {
		t.Errorf("Certificate count mismatch: got %d, want 1", len(loadedCerts))
	}
}

// TestIntegration_CAStoreAndCredentialStore tests the interaction between CA and credential stores.
func TestIntegration_CAStoreAndCredentialStore(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tempDir := t.TempDir()
	caDir := filepath.Join(tempDir, "ca")
	credDir := filepath.Join(tempDir, "credentials")

	// Initialize both stores
	caStore := NewFileStore(caDir)
	if err := caStore.Init(context.Background()); err != nil {
		t.Fatalf("Failed to init CA store: %v", err)
	}

	credStore := credential.NewFileStore(credDir)
	if err := credStore.Init(); err != nil {
		t.Fatalf("Failed to init credential store: %v", err)
	}

	// Create multiple test certificates
	certs := []*x509.Certificate{
		createMockTestCert(t, 1, "cert1.example.com"),
		createMockTestCert(t, 2, "cert2.example.com"),
		createMockTestCert(t, 3, "cert3.example.com"),
	}

	// Save certificates to CA store
	ctx := context.Background()
	for _, cert := range certs {
		if err := caStore.SaveCert(ctx, cert); err != nil {
			t.Fatalf("SaveCert failed: %v", err)
		}
	}

	// Verify CA store index
	index, err := caStore.ReadIndex(ctx)
	if err != nil {
		t.Fatalf("ReadIndex failed: %v", err)
	}

	if len(index) != 3 {
		t.Errorf("Expected 3 index entries, got %d", len(index))
	}

	// Create credentials for each cert
	for _, cert := range certs {
		credID := credential.GenerateCredentialID(cert.Subject.CommonName)
		cred := credential.NewCredential(credID, credential.Subject{
			CommonName: cert.Subject.CommonName,
		})
		cred.CreateInitialVersion([]string{"ec/tls-server"}, []string{"ec"})

		if err := credStore.Save(ctx, cred, []*x509.Certificate{cert}, nil, nil); err != nil {
			t.Fatalf("Credential save failed: %v", err)
		}
	}

	// Verify all credentials exist
	allCreds, err := credStore.ListAll(ctx)
	if err != nil {
		t.Fatalf("ListAll failed: %v", err)
	}

	if len(allCreds) != 3 {
		t.Errorf("Expected 3 credentials, got %d", len(allCreds))
	}

	// Delete one credential and verify
	credToDelete := allCreds[0].ID
	if err := credStore.Delete(ctx, credToDelete); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	if credStore.Exists(ctx, credToDelete) {
		t.Error("Deleted credential should not exist")
	}

	remaining, _ := credStore.ListAll(ctx)
	if len(remaining) != 2 {
		t.Errorf("Expected 2 remaining credentials, got %d", len(remaining))
	}
}

// TestIntegration_CredentialWithMockCAStore tests using MockStore for CA operations.
func TestIntegration_CredentialWithMockCAStore(t *testing.T) {
	mockCAStore := NewMockStore()

	// Test basic workflow with mock CA store
	if err := mockCAStore.Init(context.Background()); err != nil {
		t.Fatalf("Mock CA store init failed: %v", err)
	}

	// Simulate saving a certificate
	cert := createMockTestCert(t, 100, "mock.example.com")
	if err := mockCAStore.SaveCert(context.Background(), cert); err != nil {
		t.Fatalf("Mock save cert failed: %v", err)
	}

	// Verify mock store states
	if !mockCAStore.WasCalled("SaveCert") {
		t.Error("SaveCert should have been called")
	}

	// Verify data is stored
	loadedCert, err := mockCAStore.LoadCert(context.Background(), cert.SerialNumber.Bytes())
	if err != nil {
		t.Fatalf("Mock load cert failed: %v", err)
	}

	if loadedCert.Subject.CommonName != cert.Subject.CommonName {
		t.Error("Loaded cert CN mismatch")
	}

	// Verify index was updated
	index, err := mockCAStore.ReadIndex(context.Background())
	if err != nil {
		t.Fatalf("ReadIndex failed: %v", err)
	}

	if len(index) != 1 {
		t.Errorf("Expected 1 index entry, got %d", len(index))
	}
}

// TestIntegration_ContextCancellation tests that context cancellation works.
func TestIntegration_ContextCancellation(t *testing.T) {
	mockCAStore := NewMockStore()

	_ = mockCAStore.Init(context.Background())

	// Create a cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// All operations should fail with context.Canceled
	cert := createMockTestCert(t, 1, "test")
	err := mockCAStore.SaveCert(ctx, cert)
	if err != context.Canceled {
		t.Errorf("CA SaveCert: expected context.Canceled, got %v", err)
	}

	_, err = mockCAStore.LoadCert(ctx, []byte{0x01})
	if err != context.Canceled {
		t.Errorf("CA LoadCert: expected context.Canceled, got %v", err)
	}

	_, err = mockCAStore.NextSerial(ctx)
	if err != context.Canceled {
		t.Errorf("CA NextSerial: expected context.Canceled, got %v", err)
	}
}

// TestIntegration_ContextTimeout tests timeout handling.
func TestIntegration_ContextTimeout(t *testing.T) {
	mockCAStore := NewMockStore()

	// Create a context that times out immediately
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	// Wait a tiny bit to ensure timeout
	time.Sleep(1 * time.Millisecond)

	cert := createMockTestCert(t, 1, "test")
	err := mockCAStore.SaveCert(ctx, cert)
	if err != context.DeadlineExceeded {
		t.Errorf("Expected context.DeadlineExceeded, got %v", err)
	}
}

// TestIntegration_ErrorPropagation tests that errors are properly propagated.
func TestIntegration_ErrorPropagation(t *testing.T) {
	mockCAStore := NewMockStore()

	_ = mockCAStore.Init(context.Background())

	// Inject errors
	mockCAStore.SaveCertErr = os.ErrPermission
	mockCAStore.LoadCertErr = os.ErrPermission
	mockCAStore.NextSerialErr = os.ErrPermission

	cert := createMockTestCert(t, 1, "test")
	err := mockCAStore.SaveCert(context.Background(), cert)
	if err != os.ErrPermission {
		t.Errorf("CA SaveCert: expected ErrPermission, got %v", err)
	}

	_, err = mockCAStore.LoadCert(context.Background(), []byte{0x01})
	if err != os.ErrPermission {
		t.Errorf("CA LoadCert: expected ErrPermission, got %v", err)
	}

	_, err = mockCAStore.NextSerial(context.Background())
	if err != os.ErrPermission {
		t.Errorf("CA NextSerial: expected ErrPermission, got %v", err)
	}
}

// TestIntegration_MockStoreOperations tests the CA mock store with multiple certificates.
func TestIntegration_MockStoreOperations(t *testing.T) {
	mockCAStore := NewMockStore()

	ctx := context.Background()
	_ = mockCAStore.Init(ctx)

	// Create and save certificates
	certs := []*x509.Certificate{
		createMockTestCert(t, 1, "cert1.example.com"),
		createMockTestCert(t, 2, "cert2.example.com"),
		createMockTestCert(t, 3, "cert3.example.com"),
	}

	for _, cert := range certs {
		if err := mockCAStore.SaveCert(ctx, cert); err != nil {
			t.Fatalf("SaveCert failed: %v", err)
		}
	}

	// Verify CA store index has all certificates
	index, err := mockCAStore.ReadIndex(ctx)
	if err != nil {
		t.Fatalf("ReadIndex failed: %v", err)
	}

	if len(index) != 3 {
		t.Errorf("Expected 3 index entries, got %d", len(index))
	}

	// Verify all certificates can be loaded
	for _, cert := range certs {
		loaded, err := mockCAStore.LoadCert(ctx, cert.SerialNumber.Bytes())
		if err != nil {
			t.Fatalf("LoadCert failed: %v", err)
		}
		if loaded.Subject.CommonName != cert.Subject.CommonName {
			t.Errorf("Certificate CN mismatch")
		}
	}

	// Verify serial number generation
	serial1, err := mockCAStore.NextSerial(ctx)
	if err != nil {
		t.Fatalf("NextSerial failed: %v", err)
	}

	serial2, err := mockCAStore.NextSerial(ctx)
	if err != nil {
		t.Fatalf("NextSerial failed: %v", err)
	}

	// Serials should be different
	if string(serial1) == string(serial2) {
		t.Error("Serial numbers should be different")
	}

	// Test revocation
	if err := mockCAStore.MarkRevoked(ctx, certs[0].SerialNumber.Bytes(), ReasonKeyCompromise); err != nil {
		t.Fatalf("MarkRevoked failed: %v", err)
	}

	// Verify revocation in index
	index, _ = mockCAStore.ReadIndex(ctx)
	revokedCount := 0
	for _, entry := range index {
		if entry.Status == "R" {
			revokedCount++
		}
	}

	if revokedCount != 1 {
		t.Errorf("Expected 1 revoked entry, got %d", revokedCount)
	}
}
