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
	"github.com/remiblancher/post-quantum-pki/internal/profile"
)

// =============================================================================
// CA Signer Loading Functional Tests
// =============================================================================

func TestF_CA_LoadSigner(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
		Passphrase:    "test-password",
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

	// Try to issue without loading signer (should fail)
	subjectKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

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
	if err == nil {
		t.Error("Issue should fail without signer loaded")
	}

	// Load signer
	if err := ca.LoadSigner("test-password"); err != nil {
		t.Fatalf("LoadSigner() error = %v", err)
	}

	// Now issue should work
	cert, err := ca.Issue(context.Background(), IssueRequest{
		Template:   template,
		PublicKey:  &subjectKey.PublicKey,
		Extensions: extensions,
		Validity:   365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if cert == nil {
		t.Error("certificate should not be nil")
	}
}

// =============================================================================
// Crypto-Agility Tests: LoadAllCACerts and LoadCrossSignedCerts
// =============================================================================

func TestA_LoadAllCACerts_SingleAlgo(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize single-algo CA
	cfg := Config{
		CommonName:    "Single Algo CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	_, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// LoadAllCACerts should return exactly 1 certificate
	certs, err := store.LoadAllCACerts(context.Background())
	if err != nil {
		t.Fatalf("LoadAllCACerts() error = %v", err)
	}
	if len(certs) != 1 {
		t.Errorf("LoadAllCACerts() returned %d certs, want 1", len(certs))
	}
	if certs[0].Subject.CommonName != "Single Algo CA" {
		t.Errorf("Subject.CommonName = %v, want Single Algo CA", certs[0].Subject.CommonName)
	}
}

func TestA_LoadAllCACerts_Versioned(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize CA
	cfg := Config{
		CommonName:    "Versioned CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
		Passphrase:    "test",
	}

	_, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// LoadAllCACerts should work with versioned CAs
	certs, err := store.LoadAllCACerts(context.Background())
	if err != nil {
		t.Fatalf("LoadAllCACerts() error = %v", err)
	}
	if len(certs) != 1 {
		t.Errorf("LoadAllCACerts() returned %d certs, want 1", len(certs))
	}
	if certs[0].Subject.CommonName != "Versioned CA" {
		t.Errorf("Subject.CommonName = %v, want Versioned CA", certs[0].Subject.CommonName)
	}
}

// Note: TestA_LoadAllCACerts_HybridCA is tested via CLI integration tests
// in cmd/qpki/credential_test.go:TestA_Credential_Export_Chain_HybridCA

func TestA_LoadCrossSignedCerts_NoCrossSign(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize CA without rotation/cross-signing
	cfg := Config{
		CommonName:    "No CrossSign CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	_, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// LoadCrossSignedCerts should return empty slice (not error)
	certs, err := store.LoadCrossSignedCerts(context.Background())
	if err != nil {
		t.Fatalf("LoadCrossSignedCerts() error = %v", err)
	}
	if len(certs) != 0 {
		t.Errorf("LoadCrossSignedCerts() returned %d certs, want 0", len(certs))
	}
}
