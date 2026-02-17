package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	pkicrypto "github.com/remiblancher/post-quantum-pki/pkg/crypto"
)

// =============================================================================
// Test Helpers
// =============================================================================

// createTestCertificate creates a test certificate signed by the issuer.
// If issuer is nil, creates a self-signed certificate.
func createTestCertificate(t *testing.T, template *x509.Certificate, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	if template.SerialNumber == nil {
		template.SerialNumber = big.NewInt(time.Now().UnixNano())
	}

	// Self-signed if no issuer
	signingCert := template
	signingKey := key
	if issuer != nil {
		signingCert = issuer
		signingKey = issuerKey
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, signingCert, &key.PublicKey, signingKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert, key
}

// =============================================================================
// VerifyChain Tests
// =============================================================================

func TestU_CA_VerifyChain_DirectSignature(t *testing.T) {
	// Root CA
	rootTemplate := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootCert, rootKey := createTestCertificate(t, rootTemplate, nil, nil)

	// Leaf certificate signed by root
	leafTemplate := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Test Leaf"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	leafCert, _ := createTestCertificate(t, leafTemplate, rootCert, rootKey)

	// Verify chain (no intermediates)
	err := VerifyChain(VerifyChainConfig{
		Leaf: leafCert,
		Root: rootCert,
		Time: time.Now(),
	})
	if err != nil {
		t.Errorf("VerifyChain() error = %v, want nil", err)
	}
}

func TestU_CA_VerifyChain_WithIntermediate(t *testing.T) {
	// Root CA
	rootTemplate := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootCert, rootKey := createTestCertificate(t, rootTemplate, nil, nil)

	// Intermediate CA signed by root
	intermediateTemplate := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Test Intermediate CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(180 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	intermediateCert, intermediateKey := createTestCertificate(t, intermediateTemplate, rootCert, rootKey)

	// Leaf certificate signed by intermediate
	leafTemplate := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Test Leaf"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	leafCert, _ := createTestCertificate(t, leafTemplate, intermediateCert, intermediateKey)

	// Verify chain with intermediate
	err := VerifyChain(VerifyChainConfig{
		Leaf:          leafCert,
		Intermediates: []*x509.Certificate{intermediateCert},
		Root:          rootCert,
		Time:          time.Now(),
	})
	if err != nil {
		t.Errorf("VerifyChain() error = %v, want nil", err)
	}
}

func TestU_CA_VerifyChain_WrongOrder(t *testing.T) {
	// Root CA
	rootTemplate := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootCert, rootKey := createTestCertificate(t, rootTemplate, nil, nil)

	// Intermediate CA signed by root
	intermediateTemplate := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Test Intermediate CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(180 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	intermediateCert, intermediateKey := createTestCertificate(t, intermediateTemplate, rootCert, rootKey)

	// Leaf certificate signed by intermediate
	leafTemplate := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Test Leaf"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	leafCert, _ := createTestCertificate(t, leafTemplate, intermediateCert, intermediateKey)

	// Wrong order: leaf signed by intermediate, but we pass root as intermediate
	// This should fail because leaf is not signed by root
	err := VerifyChain(VerifyChainConfig{
		Leaf:          leafCert,
		Intermediates: []*x509.Certificate{rootCert}, // Wrong! Should be intermediateCert
		Root:          intermediateCert,              // Wrong! Should be rootCert
		Time:          time.Now(),
	})
	if err == nil {
		t.Error("VerifyChain() error = nil, want error for wrong order")
	}
}

func TestU_CA_VerifyChain_ExpiredCertificate(t *testing.T) {
	// Root CA
	rootTemplate := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootCert, rootKey := createTestCertificate(t, rootTemplate, nil, nil)

	// Expired leaf certificate
	leafTemplate := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Test Leaf"},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(-24 * time.Hour), // Expired!
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	leafCert, _ := createTestCertificate(t, leafTemplate, rootCert, rootKey)

	// Should fail due to expired certificate
	err := VerifyChain(VerifyChainConfig{
		Leaf: leafCert,
		Root: rootCert,
		Time: time.Now(),
	})
	if err == nil {
		t.Error("VerifyChain() error = nil, want error for expired certificate")
	}
}

func TestU_CA_VerifyChain_NotYetValidCertificate(t *testing.T) {
	// Root CA
	rootTemplate := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootCert, rootKey := createTestCertificate(t, rootTemplate, nil, nil)

	// Not yet valid leaf certificate
	leafTemplate := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Test Leaf"},
		NotBefore:             time.Now().Add(24 * time.Hour), // Future!
		NotAfter:              time.Now().Add(48 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	leafCert, _ := createTestCertificate(t, leafTemplate, rootCert, rootKey)

	// Should fail due to not yet valid certificate
	err := VerifyChain(VerifyChainConfig{
		Leaf: leafCert,
		Root: rootCert,
		Time: time.Now(),
	})
	if err == nil {
		t.Error("VerifyChain() error = nil, want error for not yet valid certificate")
	}
}

func TestU_CA_VerifyChain_IssuerNotCA(t *testing.T) {
	// Root that is NOT a CA
	rootTemplate := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Test Not CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  false, // Not a CA!
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
	}
	rootCert, rootKey := createTestCertificate(t, rootTemplate, nil, nil)

	// Leaf certificate
	leafTemplate := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Test Leaf"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	leafCert, _ := createTestCertificate(t, leafTemplate, rootCert, rootKey)

	// Should fail because issuer is not a CA
	err := VerifyChain(VerifyChainConfig{
		Leaf: leafCert,
		Root: rootCert,
		Time: time.Now(),
	})
	if err == nil {
		t.Error("VerifyChain() error = nil, want error for issuer not being a CA")
	}
}

func TestU_CA_VerifyChain_MissingKeyUsageCertSign(t *testing.T) {
	// Root CA without KeyUsageCertSign
	rootTemplate := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature, // Missing CertSign!
	}
	rootCert, rootKey := createTestCertificate(t, rootTemplate, nil, nil)

	// Leaf certificate
	leafTemplate := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Test Leaf"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	leafCert, _ := createTestCertificate(t, leafTemplate, rootCert, rootKey)

	// Should fail because issuer cannot sign certificates
	err := VerifyChain(VerifyChainConfig{
		Leaf: leafCert,
		Root: rootCert,
		Time: time.Now(),
	})
	if err == nil {
		t.Error("VerifyChain() error = nil, want error for missing KeyUsageCertSign")
	}
}

func TestU_CA_VerifyChain_NilLeaf(t *testing.T) {
	rootTemplate := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootCert, _ := createTestCertificate(t, rootTemplate, nil, nil)

	err := VerifyChain(VerifyChainConfig{
		Leaf: nil,
		Root: rootCert,
		Time: time.Now(),
	})
	if err == nil {
		t.Error("VerifyChain() error = nil, want error for nil leaf")
	}
}

func TestU_CA_VerifyChain_NilRoot(t *testing.T) {
	rootTemplate := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Test Leaf"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	leafCert, _ := createTestCertificate(t, rootTemplate, nil, nil)

	err := VerifyChain(VerifyChainConfig{
		Leaf: leafCert,
		Root: nil,
		Time: time.Now(),
	})
	if err == nil {
		t.Error("VerifyChain() error = nil, want error for nil root")
	}
}

func TestU_CA_VerifyChain_DefaultTime(t *testing.T) {
	// Root CA
	rootTemplate := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootCert, rootKey := createTestCertificate(t, rootTemplate, nil, nil)

	// Leaf certificate
	leafTemplate := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Test Leaf"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	leafCert, _ := createTestCertificate(t, leafTemplate, rootCert, rootKey)

	// Verify with zero time (should use time.Now())
	err := VerifyChain(VerifyChainConfig{
		Leaf: leafCert,
		Root: rootCert,
		// Time is zero value
	})
	if err != nil {
		t.Errorf("VerifyChain() error = %v, want nil", err)
	}
}

// =============================================================================
// VerifySignature Tests
// =============================================================================

func TestU_CA_VerifySignature_Classical(t *testing.T) {
	// Root CA
	rootTemplate := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootCert, rootKey := createTestCertificate(t, rootTemplate, nil, nil)

	// Leaf certificate
	leafTemplate := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Test Leaf"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	leafCert, _ := createTestCertificate(t, leafTemplate, rootCert, rootKey)

	err := VerifySignature(leafCert, rootCert)
	if err != nil {
		t.Errorf("VerifySignature() error = %v, want nil", err)
	}
}

func TestU_CA_VerifySignature_WrongIssuer(t *testing.T) {
	// Root CA 1
	root1Template := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Test Root CA 1"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	root1Cert, root1Key := createTestCertificate(t, root1Template, nil, nil)

	// Root CA 2 (different CA)
	root2Template := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Test Root CA 2"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	root2Cert, _ := createTestCertificate(t, root2Template, nil, nil)

	// Leaf certificate signed by root1
	leafTemplate := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Test Leaf"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	leafCert, _ := createTestCertificate(t, leafTemplate, root1Cert, root1Key)

	// Try to verify with wrong issuer (root2)
	err := VerifySignature(leafCert, root2Cert)
	if err == nil {
		t.Error("VerifySignature() error = nil, want error for wrong issuer")
	}
}

// =============================================================================
// IsPQCCertificate / IsCatalystCertificate Tests
// =============================================================================

func TestU_CA_IsPQCCertificate_Classical(t *testing.T) {
	template := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
	}
	cert, _ := createTestCertificate(t, template, nil, nil)

	if IsPQCCertificate(cert) {
		t.Error("IsPQCCertificate() = true for classical certificate, want false")
	}
}

func TestU_CA_IsCatalystCertificate_Classical(t *testing.T) {
	template := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
	}
	cert, _ := createTestCertificate(t, template, nil, nil)

	if IsCatalystCertificate(cert) {
		t.Error("IsCatalystCertificate() = true for classical certificate, want false")
	}
}

// =============================================================================
// VerifySignature PQC Tests
// =============================================================================

func TestU_CA_VerifySignature_PQC_MLDSA(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create PQC CA
	cfg := PQCCAConfig{
		CommonName:    "Test ML-DSA CA",
		Algorithm:     pkicrypto.AlgMLDSA65,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := InitializePQCCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializePQCCA() error = %v", err)
	}

	// Verify self-signed certificate signature
	caCert := ca.Certificate()
	err = VerifySignature(caCert, caCert)
	if err != nil {
		t.Errorf("VerifySignature(PQC self-signed) error = %v, want nil", err)
	}
}

func TestU_CA_VerifySignature_PQC_MLDSA87(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create PQC CA with ML-DSA-87
	cfg := PQCCAConfig{
		CommonName:    "Test ML-DSA-87 CA",
		Algorithm:     pkicrypto.AlgMLDSA87,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := InitializePQCCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializePQCCA(ML-DSA-87) error = %v", err)
	}

	// Verify self-signed certificate
	caCert := ca.Certificate()
	err = VerifySignature(caCert, caCert)
	if err != nil {
		t.Errorf("VerifySignature(ML-DSA-87) error = %v, want nil", err)
	}
}

func TestU_CA_VerifySignature_PQC_SLHDSA(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create PQC CA with SLH-DSA
	cfg := PQCCAConfig{
		CommonName:    "Test SLH-DSA CA",
		Algorithm:     pkicrypto.AlgSLHDSA128f,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := InitializePQCCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializePQCCA(SLH-DSA) error = %v", err)
	}

	// Verify self-signed certificate
	caCert := ca.Certificate()
	err = VerifySignature(caCert, caCert)
	if err != nil {
		t.Errorf("VerifySignature(SLH-DSA) error = %v, want nil", err)
	}
}

// =============================================================================
// VerifySignature Catalyst Tests
// =============================================================================

func TestU_CA_VerifySignature_Catalyst(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create Catalyst (hybrid) CA
	cfg := HybridCAConfig{
		CommonName:         "Test Catalyst CA",
		ClassicalAlgorithm: pkicrypto.AlgECDSAP384,
		PQCAlgorithm:       pkicrypto.AlgMLDSA87,
		ValidityYears:      10,
		PathLen:            1,
	}

	ca, err := InitializeHybridCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeHybridCA() error = %v", err)
	}

	// Verify self-signed certificate
	caCert := ca.Certificate()
	err = VerifySignature(caCert, caCert)
	if err != nil {
		t.Errorf("VerifySignature(Catalyst) error = %v, want nil", err)
	}
}

func TestU_CA_VerifySignature_Catalyst_ECDSAandMLDSA65(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create Catalyst CA with different algorithms
	cfg := HybridCAConfig{
		CommonName:         "Test Catalyst CA P256",
		ClassicalAlgorithm: pkicrypto.AlgECDSAP256,
		PQCAlgorithm:       pkicrypto.AlgMLDSA65,
		ValidityYears:      10,
		PathLen:            1,
	}

	ca, err := InitializeHybridCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeHybridCA(P256+ML-DSA-65) error = %v", err)
	}

	// Verify self-signed certificate
	caCert := ca.Certificate()
	err = VerifySignature(caCert, caCert)
	if err != nil {
		t.Errorf("VerifySignature(Catalyst P256+ML-DSA-65) error = %v, want nil", err)
	}
}

// =============================================================================
// IsPQCCertificate Tests
// =============================================================================

func TestU_CA_IsPQCCertificate_MLDSA(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := PQCCAConfig{
		CommonName:    "Test ML-DSA CA",
		Algorithm:     pkicrypto.AlgMLDSA65,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := InitializePQCCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializePQCCA() error = %v", err)
	}

	caCert := ca.Certificate()
	if !IsPQCCertificate(caCert) {
		t.Error("IsPQCCertificate() = false for ML-DSA certificate, want true")
	}
}

// =============================================================================
// IsCatalystCertificate Tests
// =============================================================================

func TestU_CA_IsCatalystCertificate_Hybrid(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := HybridCAConfig{
		CommonName:         "Test Catalyst CA",
		ClassicalAlgorithm: pkicrypto.AlgECDSAP384,
		PQCAlgorithm:       pkicrypto.AlgMLDSA87,
		ValidityYears:      10,
		PathLen:            1,
	}

	ca, err := InitializeHybridCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeHybridCA() error = %v", err)
	}

	caCert := ca.Certificate()
	if !IsCatalystCertificate(caCert) {
		t.Error("IsCatalystCertificate() = false for Catalyst certificate, want true")
	}
}

// =============================================================================
// VerifyChain with Real CAs Tests
// =============================================================================

func TestU_CA_VerifyChain_Classical_RealCA(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create classical CA
	cfg := Config{
		CommonName:    "Test Classical CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Verify self-signed root
	caCert := ca.Certificate()
	err = VerifyChain(VerifyChainConfig{
		Leaf: caCert,
		Root: caCert,
		Time: time.Now(),
	})
	if err != nil {
		t.Errorf("VerifyChain(Classical self-signed) error = %v, want nil", err)
	}
}

func TestU_CA_VerifyChain_PQC_RealCA(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create PQC CA
	cfg := PQCCAConfig{
		CommonName:    "Test PQC CA",
		Algorithm:     pkicrypto.AlgMLDSA65,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := InitializePQCCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializePQCCA() error = %v", err)
	}

	// Verify self-signed root
	caCert := ca.Certificate()
	err = VerifyChain(VerifyChainConfig{
		Leaf: caCert,
		Root: caCert,
		Time: time.Now(),
	})
	if err != nil {
		t.Errorf("VerifyChain(PQC self-signed) error = %v, want nil", err)
	}
}

func TestU_CA_VerifyChain_Catalyst_RealCA(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create Catalyst CA
	cfg := HybridCAConfig{
		CommonName:         "Test Catalyst CA",
		ClassicalAlgorithm: pkicrypto.AlgECDSAP384,
		PQCAlgorithm:       pkicrypto.AlgMLDSA87,
		ValidityYears:      10,
		PathLen:            1,
	}

	ca, err := InitializeHybridCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeHybridCA() error = %v", err)
	}

	// Verify self-signed root
	caCert := ca.Certificate()
	err = VerifyChain(VerifyChainConfig{
		Leaf: caCert,
		Root: caCert,
		Time: time.Now(),
	})
	if err != nil {
		t.Errorf("VerifyChain(Catalyst self-signed) error = %v, want nil", err)
	}
}

// =============================================================================
// VerifySignature Composite Tests
// =============================================================================

func TestU_CA_VerifySignature_Composite(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create Composite CA
	cfg := CompositeCAConfig{
		CommonName:         "Test Composite CA",
		ClassicalAlgorithm: pkicrypto.AlgECDSAP384,
		PQCAlgorithm:       pkicrypto.AlgMLDSA65,
		ValidityYears:      10,
		PathLen:            1,
	}

	ca, err := InitializeCompositeCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeCompositeCA() error = %v", err)
	}

	// Verify self-signed certificate
	caCert := ca.Certificate()
	err = VerifySignature(caCert, caCert)
	if err != nil {
		t.Errorf("VerifySignature(Composite) error = %v, want nil", err)
	}
}

func TestU_CA_VerifySignature_Composite_P521andMLDSA87(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create Composite CA with ML-DSA-87 + P-521 (valid combination)
	cfg := CompositeCAConfig{
		CommonName:         "Test Composite CA P521",
		ClassicalAlgorithm: pkicrypto.AlgECDSAP521,
		PQCAlgorithm:       pkicrypto.AlgMLDSA87,
		ValidityYears:      10,
		PathLen:            1,
	}

	ca, err := InitializeCompositeCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeCompositeCA(P521+ML-DSA-87) error = %v", err)
	}

	// Verify self-signed certificate
	caCert := ca.Certificate()
	err = VerifySignature(caCert, caCert)
	if err != nil {
		t.Errorf("VerifySignature(Composite P521+ML-DSA-87) error = %v, want nil", err)
	}
}

// =============================================================================
// IsCompositeCertificate Tests
// =============================================================================

func TestU_CA_IsCompositeCertificate_Classical(t *testing.T) {
	template := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
	}
	cert, _ := createTestCertificate(t, template, nil, nil)

	if IsCompositeCertificate(cert) {
		t.Error("IsCompositeCertificate() = true for classical certificate, want false")
	}
}

func TestU_CA_IsCompositeCertificate_CompositeVerify(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := CompositeCAConfig{
		CommonName:         "Test Composite CA Verify",
		ClassicalAlgorithm: pkicrypto.AlgECDSAP384,
		PQCAlgorithm:       pkicrypto.AlgMLDSA65,
		ValidityYears:      10,
		PathLen:            1,
	}

	ca, err := InitializeCompositeCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeCompositeCA() error = %v", err)
	}

	caCert := ca.Certificate()
	if !IsCompositeCertificate(caCert) {
		t.Error("IsCompositeCertificate() = false for Composite certificate, want true")
	}
}

// =============================================================================
// VerifyChain Composite Tests
// =============================================================================

func TestU_CA_VerifyChain_Composite_RealCA(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create Composite CA with valid combination: P-384 + ML-DSA-65
	cfg := CompositeCAConfig{
		CommonName:         "Test Composite CA",
		ClassicalAlgorithm: pkicrypto.AlgECDSAP384,
		PQCAlgorithm:       pkicrypto.AlgMLDSA65,
		ValidityYears:      10,
		PathLen:            1,
	}

	ca, err := InitializeCompositeCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeCompositeCA() error = %v", err)
	}

	// Verify self-signed root
	caCert := ca.Certificate()
	err = VerifyChain(VerifyChainConfig{
		Leaf: caCert,
		Root: caCert,
		Time: time.Now(),
	})
	if err != nil {
		t.Errorf("VerifyChain(Composite self-signed) error = %v, want nil", err)
	}
}
