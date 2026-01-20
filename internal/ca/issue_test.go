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
// CA Issue Certificate Functional Tests
// =============================================================================

func TestF_CA_IssueTLSServer(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize CA
	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
		Passphrase:    "test-password",
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Generate subject key
	subjectKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	// Issue TLS server certificate using Issue with explicit extensions
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
		DNSNames: []string{"server.example.com", "www.example.com"},
	}

	cert, err := ca.Issue(context.Background(), IssueRequest{
		Template:   template,
		PublicKey:  &subjectKey.PublicKey,
		Extensions: extensions,
		Validity:   365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	if cert.Subject.CommonName != "server.example.com" {
		t.Errorf("CommonName = %v, want server.example.com", cert.Subject.CommonName)
	}
	if len(cert.DNSNames) != 2 {
		t.Errorf("DNSNames count = %d, want 2", len(cert.DNSNames))
	}
	if cert.IsCA {
		t.Error("TLS server certificate should not be CA")
	}

	// Verify certificate is signed by CA
	if err := cert.CheckSignatureFrom(ca.Certificate()); err != nil {
		t.Errorf("certificate signature verification failed: %v", err)
	}

	// Verify certificate is stored
	loadedCert, err := store.LoadCert(context.Background(), cert.SerialNumber.Bytes())
	if err != nil {
		t.Fatalf("LoadCert() error = %v", err)
	}
	if loadedCert.Subject.CommonName != cert.Subject.CommonName {
		t.Error("loaded certificate doesn't match")
	}
}

func TestF_CA_IssueTLSClient(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
		Passphrase:    "test-password",
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	subjectKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Issue TLS client certificate using Issue with explicit extensions
	criticalTrue := true
	criticalFalse := false
	extensions := &profile.ExtensionsConfig{
		KeyUsage: &profile.KeyUsageConfig{
			Critical: &criticalTrue,
			Values:   []string{"digitalSignature"},
		},
		ExtKeyUsage: &profile.ExtKeyUsageConfig{
			Critical: &criticalFalse,
			Values:   []string{"clientAuth"},
		},
		BasicConstraints: &profile.BasicConstraintsConfig{
			Critical: &criticalTrue,
			CA:       false,
		},
	}

	template := &x509.Certificate{
		Subject: pkix.Name{CommonName: "client@example.com"},
	}

	cert, err := ca.Issue(context.Background(), IssueRequest{
		Template:   template,
		PublicKey:  &subjectKey.PublicKey,
		Extensions: extensions,
		Validity:   365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	if cert.Subject.CommonName != "client@example.com" {
		t.Errorf("CommonName = %v, want client@example.com", cert.Subject.CommonName)
	}

	if err := cert.CheckSignatureFrom(ca.Certificate()); err != nil {
		t.Errorf("certificate signature verification failed: %v", err)
	}
}

func TestF_CA_IssueSubordinateCA(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
		Passphrase:    "test-password",
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	subCAKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Issue subordinate CA certificate using Issue with explicit extensions
	criticalTrue := true
	pathLen := 0
	extensions := &profile.ExtensionsConfig{
		KeyUsage: &profile.KeyUsageConfig{
			Critical: &criticalTrue,
			Values:   []string{"keyCertSign", "cRLSign"},
		},
		BasicConstraints: &profile.BasicConstraintsConfig{
			Critical: &criticalTrue,
			CA:       true,
			PathLen:  &pathLen,
		},
	}

	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:   "Test Issuing CA",
			Organization: []string{"Test Org"},
		},
	}

	cert, err := ca.Issue(context.Background(), IssueRequest{
		Template:   template,
		PublicKey:  &subCAKey.PublicKey,
		Extensions: extensions,
		Validity:   5 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	if cert.Subject.CommonName != "Test Issuing CA" {
		t.Errorf("CommonName = %v, want Test Issuing CA", cert.Subject.CommonName)
	}
	if !cert.IsCA {
		t.Error("subordinate CA certificate should be CA")
	}
	if cert.MaxPathLen != 0 {
		t.Errorf("MaxPathLen = %d, want 0", cert.MaxPathLen)
	}

	if err := cert.CheckSignatureFrom(ca.Certificate()); err != nil {
		t.Errorf("certificate signature verification failed: %v", err)
	}
}

// =============================================================================
// addHybridExtension Unit Tests
// =============================================================================

func TestU_AddHybridExtension_NoHybridKey(t *testing.T) {
	template := &x509.Certificate{}
	req := IssueRequest{
		HybridPQCKey: nil, // No hybrid key
	}

	err := addHybridExtension(template, req)
	if err != nil {
		t.Fatalf("addHybridExtension() error = %v", err)
	}

	// Should not add any extensions
	if len(template.ExtraExtensions) != 0 {
		t.Errorf("ExtraExtensions count = %d, want 0", len(template.ExtraExtensions))
	}
}

func TestU_AddHybridExtension_EmptyHybridKey(t *testing.T) {
	template := &x509.Certificate{}
	req := IssueRequest{
		HybridPQCKey: []byte{}, // Empty hybrid key
	}

	err := addHybridExtension(template, req)
	if err != nil {
		t.Fatalf("addHybridExtension() error = %v", err)
	}

	// Should not add any extensions since len is 0
	if len(template.ExtraExtensions) != 0 {
		t.Errorf("ExtraExtensions count = %d, want 0", len(template.ExtraExtensions))
	}
}

func TestU_AddHybridExtension_WithHybridKey(t *testing.T) {
	template := &x509.Certificate{}

	// Generate a dummy PQC public key for testing
	dummyPQCKey := make([]byte, 32)
	for i := range dummyPQCKey {
		dummyPQCKey[i] = byte(i)
	}

	req := IssueRequest{
		HybridPQCKey:    dummyPQCKey,
		HybridAlgorithm: crypto.AlgMLDSA65,
	}

	err := addHybridExtension(template, req)
	if err != nil {
		t.Fatalf("addHybridExtension() error = %v", err)
	}

	// Should add one extension
	if len(template.ExtraExtensions) != 1 {
		t.Errorf("ExtraExtensions count = %d, want 1", len(template.ExtraExtensions))
	}
}

func TestU_AddHybridExtension_PreservesExistingExtensions(t *testing.T) {
	// Create template with existing extensions
	template := &x509.Certificate{
		ExtraExtensions: []pkix.Extension{
			{Id: []int{1, 2, 3}, Value: []byte("existing")},
		},
	}

	dummyPQCKey := make([]byte, 32)
	for i := range dummyPQCKey {
		dummyPQCKey[i] = byte(i)
	}

	req := IssueRequest{
		HybridPQCKey:    dummyPQCKey,
		HybridAlgorithm: crypto.AlgMLDSA65,
	}

	err := addHybridExtension(template, req)
	if err != nil {
		t.Fatalf("addHybridExtension() error = %v", err)
	}

	// Should have both existing and new extension
	if len(template.ExtraExtensions) != 2 {
		t.Errorf("ExtraExtensions count = %d, want 2", len(template.ExtraExtensions))
	}
}

// =============================================================================
// setValidity Unit Tests
// =============================================================================

func TestU_SetValidity_EmptyTemplate(t *testing.T) {
	template := &x509.Certificate{}
	validity := 365 * 24 * time.Hour

	setValidity(template, validity)

	if template.NotBefore.IsZero() {
		t.Error("NotBefore should be set")
	}
	if template.NotAfter.IsZero() {
		t.Error("NotAfter should be set")
	}

	// Check NotAfter is approximately NotBefore + validity
	diff := template.NotAfter.Sub(template.NotBefore)
	if diff < 364*24*time.Hour || diff > 366*24*time.Hour {
		t.Errorf("Validity period = %v, want ~365 days", diff)
	}
}

func TestU_SetValidity_ZeroValidity(t *testing.T) {
	template := &x509.Certificate{}

	setValidity(template, 0) // Zero validity defaults to 1 year

	if template.NotBefore.IsZero() {
		t.Error("NotBefore should be set")
	}
	if template.NotAfter.IsZero() {
		t.Error("NotAfter should be set")
	}

	// Check NotAfter is approximately NotBefore + 1 year (365 days)
	diff := template.NotAfter.Sub(template.NotBefore)
	if diff < 364*24*time.Hour || diff > 366*24*time.Hour {
		t.Errorf("Validity period = %v, want ~1 year", diff)
	}
}

func TestU_SetValidity_PreservesExistingDates(t *testing.T) {
	now := time.Now().UTC()
	future := now.AddDate(2, 0, 0)

	template := &x509.Certificate{
		NotBefore: now,
		NotAfter:  future,
	}

	setValidity(template, 30*24*time.Hour) // 30 days

	// Should preserve existing dates
	if !template.NotBefore.Equal(now) {
		t.Error("NotBefore should be preserved")
	}
	if !template.NotAfter.Equal(future) {
		t.Error("NotAfter should be preserved")
	}
}
