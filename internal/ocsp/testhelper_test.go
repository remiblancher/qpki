package ocsp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// testKeyPair holds a key pair for testing.
type testKeyPair struct {
	PrivateKey crypto.Signer
	PublicKey  crypto.PublicKey
	Algorithm  string
}

// generateECDSAKeyPair generates an ECDSA key pair for testing.
func generateECDSAKeyPair(t *testing.T, curve elliptic.Curve) *testKeyPair {
	t.Helper()
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}
	return &testKeyPair{
		PrivateKey: priv,
		PublicKey:  &priv.PublicKey,
		Algorithm:  "ECDSA",
	}
}

// generateRSAKeyPair generates an RSA key pair for testing.
func generateRSAKeyPair(t *testing.T, bits int) *testKeyPair {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	return &testKeyPair{
		PrivateKey: priv,
		PublicKey:  &priv.PublicKey,
		Algorithm:  "RSA",
	}
}

// generateEd25519KeyPair generates an Ed25519 key pair for testing.
func generateEd25519KeyPair(t *testing.T) *testKeyPair {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}
	return &testKeyPair{
		PrivateKey: priv,
		PublicKey:  pub,
		Algorithm:  "Ed25519",
	}
}

// generateTestCA creates a test CA certificate and key pair.
func generateTestCA(t *testing.T) (*x509.Certificate, crypto.Signer) {
	t.Helper()

	kp := generateECDSAKeyPair(t, elliptic.P256())

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("Failed to generate serial number: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, kp.PublicKey, kp.PrivateKey)
	if err != nil {
		t.Fatalf("Failed to create CA certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse CA certificate: %v", err)
	}

	return cert, kp.PrivateKey
}

// generateTestCAWithKey creates a test CA with a specified key type.
func generateTestCAWithKey(t *testing.T, kp *testKeyPair) (*x509.Certificate, crypto.Signer) {
	t.Helper()

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("Failed to generate serial number: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, kp.PublicKey, kp.PrivateKey)
	if err != nil {
		t.Fatalf("Failed to create CA certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse CA certificate: %v", err)
	}

	return cert, kp.PrivateKey
}

// issueTestCertificate issues a certificate signed by a CA.
func issueTestCertificate(t *testing.T, caCert *x509.Certificate, caKey crypto.Signer, kp *testKeyPair) *x509.Certificate {
	t.Helper()

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("Failed to generate serial number: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "Test End Entity",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, kp.PublicKey, caKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

// generateOCSPResponderCert creates an OCSP responder certificate.
func generateOCSPResponderCert(t *testing.T, caCert *x509.Certificate, caKey crypto.Signer, kp *testKeyPair) *x509.Certificate {
	t.Helper()

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("Failed to generate serial number: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "Test OCSP Responder",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, kp.PublicKey, caKey)
	if err != nil {
		t.Fatalf("Failed to create OCSP responder certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse OCSP responder certificate: %v", err)
	}

	return cert
}

