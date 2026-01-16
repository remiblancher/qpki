package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/remiblancher/post-quantum-pki/internal/crypto"
)

// =============================================================================
// Composite CRL Functional Tests
// =============================================================================

func TestF_CA_GenerateCompositeCRL(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize Composite CA (ECDSA-P256 + ML-DSA-65)
	cfg := CompositeCAConfig{
		CommonName:         "Composite CRL Test CA",
		Organization:       "Test Org",
		Country:            "US",
		ClassicalAlgorithm: crypto.AlgECDSAP256,
		PQCAlgorithm:       crypto.AlgMLDSA65,
		ValidityYears:      10,
		PathLen:            1,
	}

	ca, err := InitializeCompositeCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeCompositeCA() error = %v", err)
	}

	// Generate CRL without any revoked certificates
	nextUpdate := time.Now().AddDate(0, 0, 7)
	crlDER, err := ca.GenerateCompositeCRL(nextUpdate)
	if err != nil {
		t.Fatalf("GenerateCompositeCRL() error = %v", err)
	}

	if len(crlDER) == 0 {
		t.Error("Composite CRL should not be empty")
	}

	// Verify CRL using the CA's raw certificate
	valid, err := VerifyCompositeCRL(crlDER, ca.Certificate().Raw)
	if err != nil {
		t.Fatalf("VerifyCompositeCRL() error = %v", err)
	}
	if !valid {
		t.Error("Composite CRL signatures should be valid")
	}
}

func TestF_CA_GenerateCompositeCRL_WithRevokedCerts(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize Composite CA
	cfg := CompositeCAConfig{
		CommonName:         "Composite CRL Test CA",
		Organization:       "Test Org",
		Country:            "US",
		ClassicalAlgorithm: crypto.AlgECDSAP256,
		PQCAlgorithm:       crypto.AlgMLDSA65,
		ValidityYears:      10,
		PathLen:            1,
	}

	ca, err := InitializeCompositeCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeCompositeCA() error = %v", err)
	}

	// Issue and revoke a certificate
	subjectKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert, err := issueTLSServerCert(ca, "server.example.com", []string{"server.example.com"}, &subjectKey.PublicKey)
	if err != nil {
		t.Fatalf("issueTLSServerCert() error = %v", err)
	}

	// Revoke the certificate
	if err := ca.Revoke(cert.SerialNumber.Bytes(), ReasonKeyCompromise); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}

	// Generate CRL with revoked certificate
	nextUpdate := time.Now().AddDate(0, 0, 7)
	crlDER, err := ca.GenerateCompositeCRL(nextUpdate)
	if err != nil {
		t.Fatalf("GenerateCompositeCRL() error = %v", err)
	}

	// Verify CRL
	valid, err := VerifyCompositeCRL(crlDER, ca.Certificate().Raw)
	if err != nil {
		t.Fatalf("VerifyCompositeCRL() error = %v", err)
	}
	if !valid {
		t.Error("Composite CRL signatures should be valid")
	}
}

func TestF_CA_GenerateCompositeCRL_NoSigner(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize Composite CA with passphrase
	cfg := CompositeCAConfig{
		CommonName:         "Composite CRL Test CA",
		Organization:       "Test Org",
		Country:            "US",
		ClassicalAlgorithm: crypto.AlgECDSAP256,
		PQCAlgorithm:       crypto.AlgMLDSA65,
		ValidityYears:      10,
		PathLen:            1,
		Passphrase:         "testpass",
	}

	_, err := InitializeCompositeCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeCompositeCA() error = %v", err)
	}

	// Load CA without signer
	ca, err := New(store)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Try to generate CRL without signer loaded
	_, err = ca.GenerateCompositeCRL(time.Now().AddDate(0, 0, 7))
	if err == nil {
		t.Error("GenerateCompositeCRL() should fail when signer not loaded")
	}
}

func TestF_CA_GenerateCompositeCRL_NonCompositeCA(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize non-composite CA
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

	// Try to generate Composite CRL with non-composite CA
	_, err = ca.GenerateCompositeCRL(time.Now().AddDate(0, 0, 7))
	if err == nil {
		t.Error("GenerateCompositeCRL() should fail with non-composite CA")
	}
}

// =============================================================================
// Composite CRL Verification Tests
// =============================================================================

func TestF_VerifyCompositeCRL_InvalidCRL(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize Composite CA
	cfg := CompositeCAConfig{
		CommonName:         "Composite CRL Test CA",
		ClassicalAlgorithm: crypto.AlgECDSAP256,
		PQCAlgorithm:       crypto.AlgMLDSA65,
		ValidityYears:      10,
		PathLen:            1,
	}

	ca, err := InitializeCompositeCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeCompositeCA() error = %v", err)
	}

	// Try to verify invalid CRL data
	_, err = VerifyCompositeCRL([]byte{0xff, 0xff, 0xff}, ca.Certificate().Raw)
	if err == nil {
		t.Error("VerifyCompositeCRL() should fail with invalid CRL data")
	}
}

func TestF_VerifyCompositeCRL_NonCompositeCRL(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize regular CA
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

	// Generate a standard CRL (without composite signature)
	crlDER, err := ca.GenerateCRL(time.Now().AddDate(0, 0, 7))
	if err != nil {
		t.Fatalf("GenerateCRL() error = %v", err)
	}

	// Try to verify as Composite CRL - should fail because not a composite algorithm
	_, err = VerifyCompositeCRL(crlDER, ca.Certificate().Raw)
	if err == nil {
		t.Error("VerifyCompositeCRL() should fail with non-Composite CRL")
	}
}

// =============================================================================
// extractCompositePublicKeys Tests
// =============================================================================

func TestU_extractCompositePublicKeys(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize Composite CA
	cfg := CompositeCAConfig{
		CommonName:         "Composite Test CA",
		ClassicalAlgorithm: crypto.AlgECDSAP256,
		PQCAlgorithm:       crypto.AlgMLDSA65,
		ValidityYears:      10,
		PathLen:            1,
	}

	ca, err := InitializeCompositeCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeCompositeCA() error = %v", err)
	}

	// Extract public keys from the certificate
	pqcPubBytes, classicalPubBytes, err := extractCompositePublicKeys(ca.Certificate().Raw)
	if err != nil {
		t.Fatalf("extractCompositePublicKeys() error = %v", err)
	}

	// ML-DSA-65 public key should be 1952 bytes
	if len(pqcPubBytes) == 0 {
		t.Error("PQC public key should not be empty")
	}
	if len(pqcPubBytes) != 1952 {
		t.Errorf("PQC public key should be 1952 bytes for ML-DSA-65, got %d", len(pqcPubBytes))
	}

	// ECDSA-P256 public key should be 65 bytes (uncompressed point)
	if len(classicalPubBytes) == 0 {
		t.Error("Classical public key should not be empty")
	}
	if len(classicalPubBytes) != 65 {
		t.Errorf("Classical public key should be 65 bytes for ECDSA-P256, got %d", len(classicalPubBytes))
	}
}

func TestU_extractCompositePublicKeys_InvalidCert(t *testing.T) {
	_, _, err := extractCompositePublicKeys([]byte{0xff, 0xff, 0xff})
	if err == nil {
		t.Error("extractCompositePublicKeys() should fail with invalid certificate")
	}
}

func TestU_extractCompositePublicKeys_NonCompositeCert(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize regular CA (not composite)
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

	// Try to extract composite public keys from non-composite certificate
	_, _, err = extractCompositePublicKeys(ca.Certificate().Raw)
	if err == nil {
		t.Error("extractCompositePublicKeys() should fail with non-composite certificate")
	}
}

// =============================================================================
// Additional Composite Algorithm Tests
// =============================================================================

func TestF_CA_GenerateCompositeCRL_MLDSA87ECDSAP521(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize Composite CA with different algorithms (ECDSA-P521 + ML-DSA-87)
	cfg := CompositeCAConfig{
		CommonName:         "Composite CRL Test CA MLDSA87",
		Organization:       "Test Org",
		Country:            "US",
		ClassicalAlgorithm: crypto.AlgECDSAP521,
		PQCAlgorithm:       crypto.AlgMLDSA87,
		ValidityYears:      10,
		PathLen:            1,
	}

	ca, err := InitializeCompositeCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeCompositeCA() error = %v", err)
	}

	// Generate CRL
	nextUpdate := time.Now().AddDate(0, 0, 7)
	crlDER, err := ca.GenerateCompositeCRL(nextUpdate)
	if err != nil {
		t.Fatalf("GenerateCompositeCRL() error = %v", err)
	}

	// Verify CRL
	valid, err := VerifyCompositeCRL(crlDER, ca.Certificate().Raw)
	if err != nil {
		t.Fatalf("VerifyCompositeCRL() error = %v", err)
	}
	if !valid {
		t.Error("Composite CRL signatures should be valid")
	}
}
