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

func TestVerifyChain_DirectSignature(t *testing.T) {
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

func TestVerifyChain_WithIntermediate(t *testing.T) {
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

func TestVerifyChain_WrongOrder(t *testing.T) {
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

func TestVerifyChain_ExpiredCertificate(t *testing.T) {
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

func TestVerifyChain_NotYetValidCertificate(t *testing.T) {
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

func TestVerifyChain_IssuerNotCA(t *testing.T) {
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

func TestVerifyChain_MissingKeyUsageCertSign(t *testing.T) {
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

func TestVerifyChain_NilLeaf(t *testing.T) {
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

func TestVerifyChain_NilRoot(t *testing.T) {
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

func TestVerifyChain_DefaultTime(t *testing.T) {
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

func TestVerifySignature_Classical(t *testing.T) {
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

func TestVerifySignature_WrongIssuer(t *testing.T) {
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

func TestIsPQCCertificate_Classical(t *testing.T) {
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

func TestIsCatalystCertificate_Classical(t *testing.T) {
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
