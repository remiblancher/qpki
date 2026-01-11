package credential

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
)

// =============================================================================
// EncodeCertificatesPEM / DecodeCertificatesPEM Tests
// =============================================================================

func TestU_EncodeCertificatesPEM_Single(t *testing.T) {
	cert := generateTestCertificate(t)

	pem, err := EncodeCertificatesPEM([]*x509.Certificate{cert})
	if err != nil {
		t.Fatalf("failed to encode: %v", err)
	}

	if len(pem) == 0 {
		t.Error("PEM should not be empty")
	}
	if !contains(string(pem), "-----BEGIN CERTIFICATE-----") {
		t.Error("PEM should contain certificate header")
	}
}

func TestU_DecodeCertificatesPEM_Single(t *testing.T) {
	cert := generateTestCertificate(t)

	// Encode
	pemData, err := EncodeCertificatesPEM([]*x509.Certificate{cert})
	if err != nil {
		t.Fatalf("failed to encode: %v", err)
	}

	// Decode
	certs, err := DecodeCertificatesPEM(pemData)
	if err != nil {
		t.Fatalf("failed to decode: %v", err)
	}

	if len(certs) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(certs))
	}
	if certs[0].Subject.CommonName != cert.Subject.CommonName {
		t.Errorf("certificate subject mismatch")
	}
}

func TestU_EncodeCertificatesPEM_Multiple(t *testing.T) {
	cert1 := generateTestCertificate(t)
	cert2 := generateTestCertificate(t)

	pemData, err := EncodeCertificatesPEM([]*x509.Certificate{cert1, cert2})
	if err != nil {
		t.Fatalf("failed to encode: %v", err)
	}

	certs, err := DecodeCertificatesPEM(pemData)
	if err != nil {
		t.Fatalf("failed to decode: %v", err)
	}

	if len(certs) != 2 {
		t.Errorf("expected 2 certificates, got %d", len(certs))
	}
}

func TestU_DecodeCertificatesPEM_Empty(t *testing.T) {
	certs, err := DecodeCertificatesPEM([]byte{})
	if err != nil {
		t.Fatalf("unexpected error for empty data: %v", err)
	}
	if len(certs) != 0 {
		t.Errorf("expected 0 certificates, got %d", len(certs))
	}
}

// =============================================================================
// EncodePrivateKeysPEM Tests
// =============================================================================

func TestU_EncodePrivateKeysPEM_ECDSA(t *testing.T) {
	// Generate ECDSA key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Create a software signer
	signer, err := pkicrypto.NewSoftwareSigner(&pkicrypto.KeyPair{
		Algorithm:  pkicrypto.AlgECDSAP256,
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	})
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	// Encode without passphrase
	pemData, err := EncodePrivateKeysPEM([]pkicrypto.Signer{signer}, nil)
	if err != nil {
		t.Fatalf("EncodePrivateKeysPEM failed: %v", err)
	}

	if len(pemData) == 0 {
		t.Error("PEM data should not be empty")
	}
	if !contains(string(pemData), "-----BEGIN PRIVATE KEY-----") {
		t.Error("PEM should contain private key header")
	}
}

func TestU_EncodePrivateKeysPEM_WithPassphrase(t *testing.T) {
	// Generate ECDSA key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	signer, err := pkicrypto.NewSoftwareSigner(&pkicrypto.KeyPair{
		Algorithm:  pkicrypto.AlgECDSAP256,
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	})
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	// Encode with passphrase
	passphrase := []byte("testpassword")
	pemData, err := EncodePrivateKeysPEM([]pkicrypto.Signer{signer}, passphrase)
	if err != nil {
		t.Fatalf("EncodePrivateKeysPEM with passphrase failed: %v", err)
	}

	if len(pemData) == 0 {
		t.Error("PEM data should not be empty")
	}
	// Encrypted PEM should contain DEK-Info header
	if !contains(string(pemData), "DEK-Info") && !contains(string(pemData), "ENCRYPTED") {
		t.Error("PEM should be encrypted")
	}
}

func TestU_EncodePrivateKeysPEM_MultipleKeys(t *testing.T) {
	var signers []pkicrypto.Signer

	// Generate two ECDSA keys
	for i := 0; i < 2; i++ {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate key %d: %v", i, err)
		}

		signer, err := pkicrypto.NewSoftwareSigner(&pkicrypto.KeyPair{
			Algorithm:  pkicrypto.AlgECDSAP256,
			PrivateKey: privateKey,
			PublicKey:  &privateKey.PublicKey,
		})
		if err != nil {
			t.Fatalf("failed to create signer %d: %v", i, err)
		}
		signers = append(signers, signer)
	}

	pemData, err := EncodePrivateKeysPEM(signers, nil)
	if err != nil {
		t.Fatalf("EncodePrivateKeysPEM failed: %v", err)
	}

	// Count PEM blocks
	count := strings.Count(string(pemData), "-----BEGIN PRIVATE KEY-----")
	if count != 2 {
		t.Errorf("expected 2 private key blocks, got %d", count)
	}
}

func TestU_EncodePrivateKeysPEM_MLDSA(t *testing.T) {
	// Generate ML-DSA key
	signer, err := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgMLDSA65)
	if err != nil {
		t.Fatalf("failed to generate ML-DSA key: %v", err)
	}

	pemData, err := EncodePrivateKeysPEM([]pkicrypto.Signer{signer}, nil)
	if err != nil {
		t.Fatalf("EncodePrivateKeysPEM failed: %v", err)
	}

	if len(pemData) == 0 {
		t.Error("PEM data should not be empty")
	}
	if !contains(string(pemData), "ML-DSA-65 PRIVATE KEY") {
		t.Error("PEM should contain ML-DSA-65 private key header")
	}
}

// =============================================================================
// DecodePrivateKeysPEM Tests
// =============================================================================

func TestDecodePrivateKeysPEM_Empty(t *testing.T) {
	// Empty data should return empty slice
	signers, err := DecodePrivateKeysPEM([]byte{}, nil)
	if err != nil {
		t.Fatalf("DecodePrivateKeysPEM failed: %v", err)
	}
	if len(signers) != 0 {
		t.Errorf("expected 0 signers, got %d", len(signers))
	}
}

func TestDecodePrivateKeysPEM_InvalidPEM(t *testing.T) {
	// Non-PEM data should return empty slice
	signers, err := DecodePrivateKeysPEM([]byte("not a pem file"), nil)
	if err != nil {
		t.Fatalf("DecodePrivateKeysPEM failed: %v", err)
	}
	if len(signers) != 0 {
		t.Errorf("expected 0 signers, got %d", len(signers))
	}
}

// =============================================================================
// SaveCredentialPEM Tests
// =============================================================================

func TestU_SaveCredentialPEM_Basic(t *testing.T) {
	tmpDir := t.TempDir()
	certsPath := filepath.Join(tmpDir, "certs.pem")
	keysPath := filepath.Join(tmpDir, "keys.pem")

	// Generate certificate and key
	cert := generateTestCertificate(t)
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, err := pkicrypto.NewSoftwareSigner(&pkicrypto.KeyPair{
		Algorithm:  pkicrypto.AlgECDSAP256,
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	})
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	// Save
	err = SaveCredentialPEM(certsPath, keysPath, []*x509.Certificate{cert}, []pkicrypto.Signer{signer}, nil)
	if err != nil {
		t.Fatalf("SaveCredentialPEM failed: %v", err)
	}

	// Verify files exist
	if _, err := os.Stat(certsPath); os.IsNotExist(err) {
		t.Error("certificates file should exist")
	}
	if _, err := os.Stat(keysPath); os.IsNotExist(err) {
		t.Error("keys file should exist")
	}
}

func TestU_SaveCredentialPEM_WithPassphrase(t *testing.T) {
	tmpDir := t.TempDir()
	certsPath := filepath.Join(tmpDir, "certs.pem")
	keysPath := filepath.Join(tmpDir, "keys.pem")

	cert := generateTestCertificate(t)
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := pkicrypto.NewSoftwareSigner(&pkicrypto.KeyPair{
		Algorithm:  pkicrypto.AlgECDSAP256,
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	})

	passphrase := []byte("secretpassword")
	err := SaveCredentialPEM(certsPath, keysPath, []*x509.Certificate{cert}, []pkicrypto.Signer{signer}, passphrase)
	if err != nil {
		t.Fatalf("SaveCredentialPEM with passphrase failed: %v", err)
	}

	// Verify keys file is encrypted
	keysData, _ := os.ReadFile(keysPath)
	if !contains(string(keysData), "DEK-Info") && !contains(string(keysData), "ENCRYPTED") {
		t.Error("keys file should be encrypted")
	}
}

func TestU_SaveCredentialPEM_CertsOnly(t *testing.T) {
	tmpDir := t.TempDir()
	certsPath := filepath.Join(tmpDir, "certs.pem")

	cert := generateTestCertificate(t)

	// Save with no keys
	err := SaveCredentialPEM(certsPath, "", []*x509.Certificate{cert}, nil, nil)
	if err != nil {
		t.Fatalf("SaveCredentialPEM failed: %v", err)
	}

	// Verify certs file exists
	if _, err := os.Stat(certsPath); os.IsNotExist(err) {
		t.Error("certificates file should exist")
	}
}

// =============================================================================
// LoadCredentialPEM Tests
// =============================================================================

func TestU_LoadCredentialPEM_Basic(t *testing.T) {
	tmpDir := t.TempDir()
	certsPath := filepath.Join(tmpDir, "certs.pem")

	// Create and save a certificate
	cert := generateTestCertificate(t)
	certsPEM, _ := EncodeCertificatesPEM([]*x509.Certificate{cert})
	_ = os.WriteFile(certsPath, certsPEM, 0644)

	// Load
	certs, signers, err := LoadCredentialPEM(certsPath, "", nil)
	if err != nil {
		t.Fatalf("LoadCredentialPEM failed: %v", err)
	}

	if len(certs) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(certs))
	}
	if len(signers) != 0 {
		t.Errorf("expected 0 signers when no keys path provided, got %d", len(signers))
	}
}

func TestU_LoadCredentialPEM_NotFound(t *testing.T) {
	_, _, err := LoadCredentialPEM("/nonexistent/path.pem", "", nil)
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestU_LoadCredentialPEM_MultipleCerts(t *testing.T) {
	tmpDir := t.TempDir()
	certsPath := filepath.Join(tmpDir, "certs.pem")

	// Create and save multiple certificates
	cert1 := generateTestCertificate(t)
	cert2 := generateTestCertificate(t)
	certsPEM, _ := EncodeCertificatesPEM([]*x509.Certificate{cert1, cert2})
	_ = os.WriteFile(certsPath, certsPEM, 0644)

	// Load
	certs, _, err := LoadCredentialPEM(certsPath, "", nil)
	if err != nil {
		t.Fatalf("LoadCredentialPEM failed: %v", err)
	}

	if len(certs) != 2 {
		t.Errorf("expected 2 certificates, got %d", len(certs))
	}
}
