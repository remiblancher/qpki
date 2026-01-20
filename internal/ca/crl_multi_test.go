package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/remiblancher/post-quantum-pki/internal/crypto"
)

// =============================================================================
// Multi-Algorithm CRL Functional Tests
// =============================================================================

func TestF_CA_GenerateCRLForAlgorithm(t *testing.T) {
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

	// Issue and revoke an EC certificate
	subjectKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert, err := issueTLSServerCert(ca, "server.example.com", []string{"server.example.com"}, &subjectKey.PublicKey)
	if err != nil {
		t.Fatalf("issueTLSServerCert() error = %v", err)
	}

	if err := ca.Revoke(cert.SerialNumber.Bytes(), ReasonKeyCompromise); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}

	// Generate CRL for EC algorithm family
	nextUpdate := time.Now().AddDate(0, 0, 7)
	crlDER, err := ca.GenerateCRLForAlgorithm("ec", nextUpdate)
	if err != nil {
		t.Fatalf("GenerateCRLForAlgorithm() error = %v", err)
	}

	if len(crlDER) == 0 {
		t.Error("CRL should not be empty")
	}
}

func TestF_CA_GenerateCRLForAlgorithm_NoSigner(t *testing.T) {
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
	_, err = ca.GenerateCRLForAlgorithm("ec", time.Now().AddDate(0, 0, 7))
	if err == nil {
		t.Error("GenerateCRLForAlgorithm() should fail when signer not loaded")
	}
}

func TestF_CA_GenerateCRLForAlgorithm_EmptyFamily(t *testing.T) {
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

	// Issue and revoke an EC certificate
	subjectKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert, err := issueTLSServerCert(ca, "server.example.com", []string{"server.example.com"}, &subjectKey.PublicKey)
	if err != nil {
		t.Fatalf("issueTLSServerCert() error = %v", err)
	}

	if err := ca.Revoke(cert.SerialNumber.Bytes(), ReasonKeyCompromise); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}

	// Generate CRL for RSA algorithm family (no RSA certs revoked)
	nextUpdate := time.Now().AddDate(0, 0, 7)
	crlDER, err := ca.GenerateCRLForAlgorithm("rsa", nextUpdate)
	if err != nil {
		t.Fatalf("GenerateCRLForAlgorithm() error = %v", err)
	}

	// Should succeed but have empty revocation list
	if len(crlDER) == 0 {
		t.Error("CRL should not be empty even for different algorithm family")
	}
}

func TestF_CA_GenerateAllCRLs(t *testing.T) {
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

	// Issue and revoke some certificates
	subjectKey1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert1, err := issueTLSServerCert(ca, "server1.example.com", []string{"server1.example.com"}, &subjectKey1.PublicKey)
	if err != nil {
		t.Fatalf("issueTLSServerCert() error = %v", err)
	}

	subjectKey2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert2, err := issueTLSServerCert(ca, "server2.example.com", []string{"server2.example.com"}, &subjectKey2.PublicKey)
	if err != nil {
		t.Fatalf("issueTLSServerCert() error = %v", err)
	}

	// Revoke both
	if err := ca.Revoke(cert1.SerialNumber.Bytes(), ReasonKeyCompromise); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	if err := ca.Revoke(cert2.SerialNumber.Bytes(), ReasonCessationOfOperation); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}

	// Generate all CRLs
	nextUpdate := time.Now().AddDate(0, 0, 7)
	results, err := ca.GenerateAllCRLs(nextUpdate)
	if err != nil {
		t.Fatalf("GenerateAllCRLs() error = %v", err)
	}

	// Should have at least the legacy CRL
	if _, ok := results["legacy"]; !ok {
		t.Error("GenerateAllCRLs() should always include 'legacy' CRL")
	}

	// Should have the EC CRL (since we revoked EC certificates)
	if _, ok := results["ec"]; !ok {
		t.Error("GenerateAllCRLs() should include 'ec' CRL for revoked EC certificates")
	}
}

func TestF_CA_GenerateAllCRLs_NoSigner(t *testing.T) {
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

	// Try to generate all CRLs without signer loaded
	_, err = ca.GenerateAllCRLs(time.Now().AddDate(0, 0, 7))
	if err == nil {
		t.Error("GenerateAllCRLs() should fail when signer not loaded")
	}
}

func TestF_CA_GenerateAllCRLs_NoRevocations(t *testing.T) {
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

	// Generate all CRLs without any revocations
	nextUpdate := time.Now().AddDate(0, 0, 7)
	results, err := ca.GenerateAllCRLs(nextUpdate)
	if err != nil {
		t.Fatalf("GenerateAllCRLs() error = %v", err)
	}

	// Should still have the legacy CRL even with no revocations
	if _, ok := results["legacy"]; !ok {
		t.Error("GenerateAllCRLs() should always include 'legacy' CRL")
	}

	// Should only have the legacy CRL
	if len(results) != 1 {
		t.Errorf("GenerateAllCRLs() expected 1 CRL (legacy only), got %d", len(results))
	}
}

// =============================================================================
// PQC Multi-CRL Tests
// =============================================================================

func TestF_CA_GenerateCRLForAlgorithm_PQC(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize PQC CA
	cfg := PQCCAConfig{
		CommonName:    "Test PQC CA",
		Algorithm:     crypto.AlgMLDSA65,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := InitializePQCCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializePQCCA() error = %v", err)
	}

	// Issue a certificate using PQC key
	pqcKey, err := crypto.GenerateKeyPair(crypto.AlgMLDSA65)
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	cert, err := issuePQCCert(ca, "server.example.com", pqcKey.PublicKey)
	if err != nil {
		t.Fatalf("issuePQCCert() error = %v", err)
	}

	// Revoke the certificate
	if err := ca.Revoke(cert.serial, ReasonKeyCompromise); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}

	// Generate CRL for ml-dsa algorithm family
	nextUpdate := time.Now().AddDate(0, 0, 7)
	crlDER, err := ca.GenerateCRLForAlgorithm("ml-dsa", nextUpdate)
	if err != nil {
		t.Fatalf("GenerateCRLForAlgorithm() error = %v", err)
	}

	if len(crlDER) == 0 {
		t.Error("PQC CRL should not be empty")
	}
}

// =============================================================================
// Helper functions
// =============================================================================

// pqcCertResult wraps a PQC certificate result for testing.
type pqcCertResult struct {
	serial []byte
}

func (r *pqcCertResult) SerialNumber() *serialBytes {
	return &serialBytes{r.serial}
}

type serialBytes struct {
	data []byte
}

func (s *serialBytes) Bytes() []byte {
	return s.data
}

// issuePQCCert issues a certificate using PQC key.
func issuePQCCert(ca *CA, cn string, pubKey interface{}) (*pqcCertResult, error) {
	template := &x509.Certificate{
		Subject:  pkix.Name{CommonName: cn},
		KeyUsage: x509.KeyUsageDigitalSignature,
	}

	cert, err := ca.Issue(context.Background(), IssueRequest{
		Template:  template,
		PublicKey: pubKey,
		Validity:  365 * 24 * time.Hour,
	})
	if err != nil {
		return nil, err
	}
	return &pqcCertResult{serial: cert.SerialNumber.Bytes()}, nil
}

// =============================================================================
// PQC CRL for Algorithm Error Path Tests
// =============================================================================

func TestF_CA_GenerateCRLForAlgorithm_PQC_NoSigner(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize PQC CA with passphrase to enable separate loading
	cfg := PQCCAConfig{
		CommonName:    "Test PQC CA",
		Algorithm:     crypto.AlgMLDSA65,
		ValidityYears: 10,
		PathLen:       1,
		Passphrase:    "testpass",
	}

	_, err := InitializePQCCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializePQCCA() error = %v", err)
	}

	// Load CA without signer
	ca, err := New(store)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Try to generate CRL without signer
	_, err = ca.GenerateCRLForAlgorithm("ml-dsa", time.Now().AddDate(0, 0, 7))
	if err == nil {
		t.Error("GenerateCRLForAlgorithm() should fail when PQC signer not loaded")
	}
}

func TestF_CA_GenerateCRLForAlgorithm_PQC_DifferentFamily(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize PQC CA
	cfg := PQCCAConfig{
		CommonName:    "Test PQC CA",
		Algorithm:     crypto.AlgMLDSA65,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := InitializePQCCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializePQCCA() error = %v", err)
	}

	// Issue and revoke a certificate
	pqcKey, err := crypto.GenerateKeyPair(crypto.AlgMLDSA65)
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	cert, err := issuePQCCert(ca, "server.example.com", pqcKey.PublicKey)
	if err != nil {
		t.Fatalf("issuePQCCert() error = %v", err)
	}

	if err := ca.Revoke(cert.serial, ReasonKeyCompromise); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}

	// Generate CRL for different algorithm family (ec, not ml-dsa)
	// Should succeed but with empty revocation list
	nextUpdate := time.Now().AddDate(0, 0, 7)
	crlDER, err := ca.GenerateCRLForAlgorithm("ec", nextUpdate)
	if err != nil {
		t.Fatalf("GenerateCRLForAlgorithm() error = %v", err)
	}

	if len(crlDER) == 0 {
		t.Error("CRL should not be empty even for different family")
	}
}

func TestF_CA_GenerateAllCRLs_PQC(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize PQC CA
	cfg := PQCCAConfig{
		CommonName:    "Test PQC CA",
		Algorithm:     crypto.AlgMLDSA65,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := InitializePQCCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializePQCCA() error = %v", err)
	}

	// Issue and revoke certificates
	pqcKey1, _ := crypto.GenerateKeyPair(crypto.AlgMLDSA65)
	cert1, err := issuePQCCert(ca, "server1.example.com", pqcKey1.PublicKey)
	if err != nil {
		t.Fatalf("issuePQCCert() error = %v", err)
	}

	pqcKey2, _ := crypto.GenerateKeyPair(crypto.AlgMLDSA65)
	cert2, err := issuePQCCert(ca, "server2.example.com", pqcKey2.PublicKey)
	if err != nil {
		t.Fatalf("issuePQCCert() error = %v", err)
	}

	// Revoke both
	if err := ca.Revoke(cert1.serial, ReasonKeyCompromise); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	if err := ca.Revoke(cert2.serial, ReasonCessationOfOperation); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}

	// Generate all CRLs
	nextUpdate := time.Now().AddDate(0, 0, 7)
	results, err := ca.GenerateAllCRLs(nextUpdate)
	if err != nil {
		t.Fatalf("GenerateAllCRLs() error = %v", err)
	}

	// Should have the legacy CRL
	if _, ok := results["legacy"]; !ok {
		t.Error("GenerateAllCRLs() should include 'legacy' CRL")
	}

	// Should have the unknown/ml-dsa CRL (PQC certs may be classified as "unknown")
	hasPQCFamily := false
	for family := range results {
		if family == "unknown" || family == "ml-dsa" {
			hasPQCFamily = true
			break
		}
	}
	if !hasPQCFamily {
		t.Errorf("GenerateAllCRLs() expected 'unknown' or 'ml-dsa' family CRL, got: %v", results)
	}
}

func TestF_CA_GenerateCRLForAlgorithm_MultipleCerts(t *testing.T) {
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

	// Issue and revoke multiple certificates
	for i := 0; i < 3; i++ {
		subjectKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		cert, err := issueTLSServerCert(ca, "server.example.com", []string{"server.example.com"}, &subjectKey.PublicKey)
		if err != nil {
			t.Fatalf("issueTLSServerCert() error = %v", err)
		}

		if err := ca.Revoke(cert.SerialNumber.Bytes(), ReasonKeyCompromise); err != nil {
			t.Fatalf("Revoke() error = %v", err)
		}
	}

	// Generate CRL for EC algorithm family
	nextUpdate := time.Now().AddDate(0, 0, 7)
	crlDER, err := ca.GenerateCRLForAlgorithm("ec", nextUpdate)
	if err != nil {
		t.Fatalf("GenerateCRLForAlgorithm() error = %v", err)
	}

	// Parse and verify CRL has 3 entries
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatalf("ParseRevocationList() error = %v", err)
	}

	if len(crl.RevokedCertificateEntries) != 3 {
		t.Errorf("CRL should have 3 revoked certs, got %d", len(crl.RevokedCertificateEntries))
	}
}
