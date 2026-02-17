package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/remiblancher/post-quantum-pki/pkg/ca"
	"github.com/spf13/cobra"
)

// executeCommand executes a Cobra command with the given args and returns output.
func executeCommand(root *cobra.Command, args ...string) (output string, err error) {
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs(args)

	err = root.Execute()
	return buf.String(), err
}

// testContext holds test resources.
type testContext struct {
	t       *testing.T
	tempDir string
}

// newTestContext creates a new test context with a temp directory.
func newTestContext(t *testing.T) *testContext {
	t.Helper()
	dir, err := os.MkdirTemp("", "pki-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return &testContext{t: t, tempDir: dir}
}

// path returns a path within the temp directory.
func (tc *testContext) path(name string) string {
	return filepath.Join(tc.tempDir, name)
}

// writeFile writes content to a file in the temp directory.
func (tc *testContext) writeFile(name, content string) string {
	tc.t.Helper()
	path := tc.path(name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		tc.t.Fatalf("Failed to write file %s: %v", name, err)
	}
	return path
}

// generateECDSAKeyPair generates an ECDSA key pair.
func generateECDSAKeyPair(t *testing.T) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}
	return priv, &priv.PublicKey
}

// generateRSAKeyPair generates an RSA key pair.
func generateRSAKeyPair(t *testing.T, bits int) (*rsa.PrivateKey, *rsa.PublicKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	return priv, &priv.PublicKey
}

// generateSelfSignedCert generates a self-signed certificate.
func generateSelfSignedCert(t *testing.T, priv crypto.Signer, pub crypto.PublicKey) *x509.Certificate {
	t.Helper()

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("Failed to generate serial number: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "Test Certificate",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

// writeCertPEM writes a certificate to a PEM file.
func (tc *testContext) writeCertPEM(name string, cert *x509.Certificate) string {
	tc.t.Helper()
	path := tc.path(name)
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	if err := os.WriteFile(path, pemData, 0644); err != nil {
		tc.t.Fatalf("Failed to write certificate: %v", err)
	}
	return path
}

// writeKeyPEM writes a private key to a PEM file.
func (tc *testContext) writeKeyPEM(name string, key crypto.Signer) string {
	tc.t.Helper()
	path := tc.path(name)

	var pemData []byte
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		der, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			tc.t.Fatalf("Failed to marshal ECDSA key: %v", err)
		}
		pemData = pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: der,
		})
	case *rsa.PrivateKey:
		der := x509.MarshalPKCS1PrivateKey(k)
		pemData = pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: der,
		})
	default:
		tc.t.Fatalf("Unsupported key type: %T", key)
	}

	if err := os.WriteFile(path, pemData, 0600); err != nil {
		tc.t.Fatalf("Failed to write key: %v", err)
	}
	return path
}

// setupSigningPair creates a key pair and certificate for signing tests.
func (tc *testContext) setupSigningPair() (certPath, keyPath string) {
	tc.t.Helper()
	priv, pub := generateECDSAKeyPair(tc.t)
	cert := generateSelfSignedCert(tc.t, priv, pub)
	certPath = tc.writeCertPEM("signer.crt", cert)
	keyPath = tc.writeKeyPEM("signer.key", priv)
	return
}

// resetCommandFlags resets all flags to their default values.
// This is needed because Cobra retains flag values between test runs.
func resetCMSFlags() {
	cmsSignData = ""
	cmsSignCert = ""
	cmsSignKey = ""
	cmsSignPassphrase = ""
	cmsSignHash = "sha256"
	cmsSignOutput = ""
	cmsSignDetached = true
	cmsSignIncludeCerts = true

	cmsVerifySignature = ""
	cmsVerifyData = ""
	cmsVerifyCA = ""

	cmsEncryptRecipients = nil
	cmsEncryptInput = ""
	cmsEncryptOutput = ""
	cmsEncryptContentEnc = "aes-256-gcm"

	cmsDecryptKey = ""
	cmsDecryptCert = ""
	cmsDecryptPassphrase = ""
	cmsDecryptInput = ""
	cmsDecryptOutput = ""
}

// =============================================================================
// Path Helpers
// =============================================================================

// getCACertPath returns the path to the active CA certificate.
// Uses the versioned structure: versions/v1/{algo}/cert.pem
func getCACertPath(t *testing.T, caDir string) string {
	t.Helper()
	info, err := ca.LoadCAInfo(caDir)
	if err != nil || info == nil {
		t.Fatalf("failed to load CA info from %s", caDir)
	}
	if info.Active == "" {
		t.Fatalf("no active version in CA at %s", caDir)
	}
	activeVer := info.ActiveVersion()
	if activeVer == nil || len(activeVer.Algos) == 0 {
		t.Fatalf("no algos in active version at %s", caDir)
	}
	return info.CertPath(info.Active, activeVer.Algos[0])
}

// =============================================================================
// Assertion Helpers
// =============================================================================

// assertFileExists verifies that a file exists at the given path.
func assertFileExists(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Errorf("file %s does not exist", path)
	}
}

// assertFileNotEmpty verifies that a file exists and is not empty.
func assertFileNotEmpty(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read %s: %v", path, err)
	}
	if len(data) == 0 {
		t.Errorf("file %s is empty", path)
	}
}

// assertNoError fails the test if err is not nil.
func assertNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// assertError fails the test if err is nil.
func assertError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// =============================================================================
// Certificate Generation Helpers
// =============================================================================

// generateSelfSignedCACert generates a self-signed CA certificate.
func generateSelfSignedCACert(t *testing.T, priv crypto.Signer, pub crypto.PublicKey) *x509.Certificate {
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
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatalf("Failed to create CA certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse CA certificate: %v", err)
	}

	return cert
}

// generateCertSignedBy generates a certificate signed by a CA.
func generateCertSignedBy(t *testing.T, priv crypto.Signer, pub crypto.PublicKey, caCert *x509.Certificate, caKey crypto.Signer) *x509.Certificate {
	t.Helper()

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("Failed to generate serial number: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "Test Signer",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection, x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, pub, caKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

// generateIntermediateCACert generates an intermediate CA certificate signed by a root CA.
func generateIntermediateCACert(t *testing.T, priv crypto.Signer, pub crypto.PublicKey, rootCert *x509.Certificate, rootKey crypto.Signer) *x509.Certificate {
	t.Helper()

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("Failed to generate serial number: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "Test Intermediate CA",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, rootCert, pub, rootKey)
	if err != nil {
		t.Fatalf("Failed to create intermediate CA certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse intermediate CA certificate: %v", err)
	}

	return cert
}

// certToPEM converts a certificate to PEM format.
func certToPEM(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}))
}
