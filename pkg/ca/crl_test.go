package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"

	"github.com/remiblancher/qpki/pkg/crypto"
)

// =============================================================================
// CRL Generation Functional Tests
// =============================================================================

func TestF_CA_GenerateCRL(t *testing.T) {
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

	// Issue and revoke a certificate
	subjectKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert, _ := issueTLSServerCert(ca, "server.example.com", []string{"server.example.com"}, &subjectKey.PublicKey)
	_ = ca.Revoke(cert.SerialNumber.Bytes(), ReasonKeyCompromise)

	// Generate CRL
	nextUpdate := time.Now().AddDate(0, 0, 7)
	crlDER, err := ca.GenerateCRL(nextUpdate)
	if err != nil {
		t.Fatalf("GenerateCRL() error = %v", err)
	}

	if len(crlDER) == 0 {
		t.Error("CRL should not be empty")
	}

	// Parse and verify CRL
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatalf("ParseRevocationList() error = %v", err)
	}

	if len(crl.RevokedCertificateEntries) != 1 {
		t.Errorf("CRL should have 1 revoked cert, got %d", len(crl.RevokedCertificateEntries))
	}

	// Verify CRL signature
	if err := crl.CheckSignatureFrom(ca.Certificate()); err != nil {
		t.Errorf("CRL signature verification failed: %v", err)
	}
}

func TestF_CA_GenerateCRL_SignerMissing(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
		Passphrase:    "test",
	}

	_, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Load CA without signer
	ca, err := New(store)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Try to generate CRL without signer loaded
	_, err = ca.GenerateCRL(time.Now().AddDate(0, 0, 7))
	if err == nil {
		t.Error("GenerateCRL() should fail when signer not loaded")
	}
}

// =============================================================================
// GetCertificateAlgorithmFamily Unit Tests
// =============================================================================

func TestU_GetCertificateAlgorithmFamily(t *testing.T) {
	// Create test certificates with different algorithms
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Test with ECDSA certificate
	cfg := Config{
		CommonName:    "Test EC CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 1,
		PathLen:       0,
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	ecCert := ca.Certificate()
	family := GetCertificateAlgorithmFamily(ecCert)
	if family != "ec" {
		t.Errorf("GetCertificateAlgorithmFamily(ECDSA) = %s, want ec", family)
	}
}

func TestU_GetCertificateAlgorithmFamily_RSA(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test RSA CA",
		Algorithm:     crypto.AlgRSA2048,
		ValidityYears: 1,
		PathLen:       0,
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	rsaCert := ca.Certificate()
	family := GetCertificateAlgorithmFamily(rsaCert)
	if family != "rsa" {
		t.Errorf("GetCertificateAlgorithmFamily(RSA) = %s, want rsa", family)
	}
}

func TestU_GetCertificateAlgorithmFamily_Ed25519(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Ed25519 CA",
		Algorithm:     crypto.AlgEd25519,
		ValidityYears: 1,
		PathLen:       0,
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	edCert := ca.Certificate()
	family := GetCertificateAlgorithmFamily(edCert)
	if family != "ed" {
		t.Errorf("GetCertificateAlgorithmFamily(Ed25519) = %s, want ed", family)
	}
}

func TestU_GetCertificateAlgorithmFamily_MLDSA(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := PQCCAConfig{
		CommonName:    "Test ML-DSA CA",
		Algorithm:     crypto.AlgMLDSA65,
		ValidityYears: 1,
		PathLen:       0,
	}

	ca, err := InitializePQCCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializePQCCA() error = %v", err)
	}

	cert := ca.Certificate()
	family := GetCertificateAlgorithmFamily(cert)
	// PQC certificates have UnknownSignatureAlgorithm, so they fall through to public key check
	// The public key is also unknown to standard x509, so it returns "unknown"
	// This validates the unknown fallback path works correctly
	if family != "unknown" && family != "ml-dsa" {
		t.Errorf("GetCertificateAlgorithmFamily(ML-DSA) = %s, want ml-dsa or unknown", family)
	}
}

func TestU_GetCertificateAlgorithmFamily_SLHDSA(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := PQCCAConfig{
		CommonName:    "Test SLH-DSA CA",
		Algorithm:     crypto.AlgSLHDSA128f,
		ValidityYears: 1,
		PathLen:       0,
	}

	ca, err := InitializePQCCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializePQCCA() error = %v", err)
	}

	cert := ca.Certificate()
	family := GetCertificateAlgorithmFamily(cert)
	// PQC certificates have UnknownSignatureAlgorithm
	if family != "unknown" && family != "slh-dsa" {
		t.Errorf("GetCertificateAlgorithmFamily(SLH-DSA) = %s, want slh-dsa or unknown", family)
	}
}

func TestU_GetCertificateAlgorithmFamily_UnknownFallback(t *testing.T) {
	// Test that the function returns correct fallback for standard algorithms
	// when signature algorithm string doesn't match but public key does
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Test ECDSA fallback via public key
	cfg := Config{
		CommonName:    "Test EC CA",
		Algorithm:     crypto.AlgECDSAP384,
		ValidityYears: 1,
		PathLen:       0,
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	cert := ca.Certificate()
	family := GetCertificateAlgorithmFamily(cert)
	if family != "ec" {
		t.Errorf("GetCertificateAlgorithmFamily(ECDSA-P384) = %s, want ec", family)
	}
}
