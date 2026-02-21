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

	pkicrypto "github.com/remiblancher/qpki/pkg/crypto"
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

func TestU_Credential_DecodePrivateKeysPEM_Empty(t *testing.T) {
	// Empty data should return empty slice
	signers, err := DecodePrivateKeysPEM([]byte{}, nil)
	if err != nil {
		t.Fatalf("DecodePrivateKeysPEM failed: %v", err)
	}
	if len(signers) != 0 {
		t.Errorf("expected 0 signers, got %d", len(signers))
	}
}

func TestU_Credential_DecodePrivateKeysPEM_InvalidPEM(t *testing.T) {
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

// =============================================================================
// marshalMLKEMPrivateKeyPKCS8 Tests
// =============================================================================

func TestU_MarshalMLKEMPrivateKeyPKCS8_MLKEM512(t *testing.T) {
	// Generate ML-KEM-512 key
	signer, err := pkicrypto.GenerateKEMSigner(pkicrypto.AlgMLKEM512)
	if err != nil {
		t.Fatalf("failed to generate ML-KEM-512 key: %v", err)
	}

	// Get private key
	priv := signer.PrivateKey()

	// Marshal to PKCS#8
	der, err := marshalMLKEMPrivateKeyPKCS8(priv)
	if err != nil {
		t.Fatalf("marshalMLKEMPrivateKeyPKCS8 failed: %v", err)
	}

	if len(der) == 0 {
		t.Error("DER output should not be empty")
	}
}

func TestU_MarshalMLKEMPrivateKeyPKCS8_MLKEM768(t *testing.T) {
	// Generate ML-KEM-768 key
	signer, err := pkicrypto.GenerateKEMSigner(pkicrypto.AlgMLKEM768)
	if err != nil {
		t.Fatalf("failed to generate ML-KEM-768 key: %v", err)
	}

	// Get private key
	priv := signer.PrivateKey()

	// Marshal to PKCS#8
	der, err := marshalMLKEMPrivateKeyPKCS8(priv)
	if err != nil {
		t.Fatalf("marshalMLKEMPrivateKeyPKCS8 failed: %v", err)
	}

	if len(der) == 0 {
		t.Error("DER output should not be empty")
	}
}

func TestU_MarshalMLKEMPrivateKeyPKCS8_MLKEM1024(t *testing.T) {
	// Generate ML-KEM-1024 key
	signer, err := pkicrypto.GenerateKEMSigner(pkicrypto.AlgMLKEM1024)
	if err != nil {
		t.Fatalf("failed to generate ML-KEM-1024 key: %v", err)
	}

	// Get private key
	priv := signer.PrivateKey()

	// Marshal to PKCS#8
	der, err := marshalMLKEMPrivateKeyPKCS8(priv)
	if err != nil {
		t.Fatalf("marshalMLKEMPrivateKeyPKCS8 failed: %v", err)
	}

	if len(der) == 0 {
		t.Error("DER output should not be empty")
	}
}

func TestU_MarshalMLKEMPrivateKeyPKCS8_UnsupportedType(t *testing.T) {
	// Try with unsupported key type
	_, err := marshalMLKEMPrivateKeyPKCS8("not a key")
	if err == nil {
		t.Error("expected error for unsupported key type")
	}
	if !contains(err.Error(), "unsupported ML-KEM key type") {
		t.Errorf("expected 'unsupported ML-KEM key type' error, got: %v", err)
	}
}

// =============================================================================
// privateKeyToPEMBlock Tests for Various Key Types
// =============================================================================

func TestU_PrivateKeyToPEMBlock_ECDSA_P384(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	block, err := privateKeyToPEMBlock(privateKey, pkicrypto.AlgECDSAP384, nil)
	if err != nil {
		t.Fatalf("privateKeyToPEMBlock failed: %v", err)
	}

	if block.Type != "PRIVATE KEY" {
		t.Errorf("expected 'PRIVATE KEY' type, got '%s'", block.Type)
	}
}

func TestU_PrivateKeyToPEMBlock_MLDSA44(t *testing.T) {
	signer, err := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgMLDSA44)
	if err != nil {
		t.Fatalf("failed to generate ML-DSA-44 key: %v", err)
	}

	// Get private key from signer
	priv := signer.PrivateKey()

	block, err := privateKeyToPEMBlock(priv, pkicrypto.AlgMLDSA44, nil)
	if err != nil {
		t.Fatalf("privateKeyToPEMBlock failed: %v", err)
	}

	if block.Type != "ML-DSA-44 PRIVATE KEY" {
		t.Errorf("expected 'ML-DSA-44 PRIVATE KEY' type, got '%s'", block.Type)
	}
}

func TestU_PrivateKeyToPEMBlock_MLDSA87(t *testing.T) {
	signer, err := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgMLDSA87)
	if err != nil {
		t.Fatalf("failed to generate ML-DSA-87 key: %v", err)
	}

	priv := signer.PrivateKey()

	block, err := privateKeyToPEMBlock(priv, pkicrypto.AlgMLDSA87, nil)
	if err != nil {
		t.Fatalf("privateKeyToPEMBlock failed: %v", err)
	}

	if block.Type != "ML-DSA-87 PRIVATE KEY" {
		t.Errorf("expected 'ML-DSA-87 PRIVATE KEY' type, got '%s'", block.Type)
	}
}

func TestU_PrivateKeyToPEMBlock_SLHDSA(t *testing.T) {
	signer, err := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgSLHDSA128f)
	if err != nil {
		t.Fatalf("failed to generate SLH-DSA key: %v", err)
	}

	priv := signer.PrivateKey()

	block, err := privateKeyToPEMBlock(priv, pkicrypto.AlgSLHDSA128f, nil)
	if err != nil {
		t.Fatalf("privateKeyToPEMBlock failed: %v", err)
	}

	// SLH-DSA PEM type includes mode ID
	if !contains(block.Type, "PRIVATE KEY") {
		t.Errorf("expected PEM type containing 'PRIVATE KEY', got '%s'", block.Type)
	}
}

func TestU_PrivateKeyToPEMBlock_MLKEM(t *testing.T) {
	signer, err := pkicrypto.GenerateKEMSigner(pkicrypto.AlgMLKEM768)
	if err != nil {
		t.Fatalf("failed to generate ML-KEM key: %v", err)
	}

	priv := signer.PrivateKey()

	block, err := privateKeyToPEMBlock(priv, pkicrypto.AlgMLKEM768, nil)
	if err != nil {
		t.Fatalf("privateKeyToPEMBlock failed: %v", err)
	}

	// ML-KEM uses PKCS#8 format
	if block.Type != "PRIVATE KEY" {
		t.Errorf("expected 'PRIVATE KEY' type for ML-KEM, got '%s'", block.Type)
	}
}

func TestU_PrivateKeyToPEMBlock_WithPassphrase(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	passphrase := []byte("testpassword")
	block, err := privateKeyToPEMBlock(privateKey, pkicrypto.AlgECDSAP256, passphrase)
	if err != nil {
		t.Fatalf("privateKeyToPEMBlock failed: %v", err)
	}

	// Encrypted PEM should have headers
	if len(block.Headers) == 0 {
		t.Error("encrypted PEM should have headers")
	}
}

// =============================================================================
// EncodePrivateKeysPEM Tests for KEM Signers
// =============================================================================

func TestU_EncodePrivateKeysPEM_KEMSigner(t *testing.T) {
	// Generate KEM signer
	signer, err := pkicrypto.GenerateKEMSigner(pkicrypto.AlgMLKEM768)
	if err != nil {
		t.Fatalf("failed to generate KEM signer: %v", err)
	}

	// Encode
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

func TestU_EncodePrivateKeysPEM_MixedSigners(t *testing.T) {
	// Generate ECDSA signer
	ecdsaSigner, err := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgECDSAP256)
	if err != nil {
		t.Fatalf("failed to generate ECDSA signer: %v", err)
	}

	// Generate ML-DSA signer
	mldsaSigner, err := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgMLDSA65)
	if err != nil {
		t.Fatalf("failed to generate ML-DSA signer: %v", err)
	}

	// Encode both
	pemData, err := EncodePrivateKeysPEM([]pkicrypto.Signer{ecdsaSigner, mldsaSigner}, nil)
	if err != nil {
		t.Fatalf("EncodePrivateKeysPEM failed: %v", err)
	}

	// Should have both key types
	if !contains(string(pemData), "-----BEGIN PRIVATE KEY-----") {
		t.Error("PEM should contain ECDSA private key")
	}
	if !contains(string(pemData), "ML-DSA-65 PRIVATE KEY") {
		t.Error("PEM should contain ML-DSA private key")
	}
}

// =============================================================================
// classicalKeyInfo Tests
// =============================================================================

func TestU_ClassicalKeyInfo_ECDSA(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	alg, pub := classicalKeyInfo(privateKey)
	// Should return a valid algorithm and public key
	if alg == "" {
		t.Error("algorithm should not be empty")
	}
	if pub == nil {
		t.Error("public key should not be nil")
	}
}

// =============================================================================
// Full Roundtrip Tests
// =============================================================================

func TestU_SaveLoadCredentialPEM_Roundtrip(t *testing.T) {
	tmpDir := t.TempDir()
	certsPath := filepath.Join(tmpDir, "certs.pem")
	keysPath := filepath.Join(tmpDir, "keys.pem")

	// Generate certificate and key
	cert := generateTestCertificate(t)
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := pkicrypto.NewSoftwareSigner(&pkicrypto.KeyPair{
		Algorithm:  pkicrypto.AlgECDSAP256,
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	})

	// Save
	err := SaveCredentialPEM(certsPath, keysPath, []*x509.Certificate{cert}, []pkicrypto.Signer{signer}, nil)
	if err != nil {
		t.Fatalf("SaveCredentialPEM failed: %v", err)
	}

	// Load
	certs, signers, err := LoadCredentialPEM(certsPath, keysPath, nil)
	if err != nil {
		t.Fatalf("LoadCredentialPEM failed: %v", err)
	}

	// Verify
	if len(certs) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(certs))
	}
	if len(signers) != 1 {
		t.Errorf("expected 1 signer, got %d", len(signers))
	}
	if certs[0].Subject.CommonName != cert.Subject.CommonName {
		t.Error("certificate subject mismatch after roundtrip")
	}
}

func TestU_SaveLoadCredentialPEM_WithEncryption_Roundtrip(t *testing.T) {
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

	// Save with encryption
	err := SaveCredentialPEM(certsPath, keysPath, []*x509.Certificate{cert}, []pkicrypto.Signer{signer}, passphrase)
	if err != nil {
		t.Fatalf("SaveCredentialPEM failed: %v", err)
	}

	// Load with passphrase
	certs, signers, err := LoadCredentialPEM(certsPath, keysPath, passphrase)
	if err != nil {
		t.Fatalf("LoadCredentialPEM failed: %v", err)
	}

	if len(certs) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(certs))
	}
	if len(signers) != 1 {
		t.Errorf("expected 1 signer, got %d", len(signers))
	}
}

// =============================================================================
// SaveCredentialPEM Error Cases
// =============================================================================

func TestU_SaveCredentialPEM_InvalidCertsPath(t *testing.T) {
	// Try to write to a path with non-existent parent directory
	err := SaveCredentialPEM("/nonexistent/dir/certs.pem", "", []*x509.Certificate{generateTestCertificate(t)}, nil, nil)
	if err == nil {
		t.Error("SaveCredentialPEM should fail for invalid certs path")
	}
}

func TestU_SaveCredentialPEM_InvalidKeysPath(t *testing.T) {
	tmpDir := t.TempDir()
	certsPath := filepath.Join(tmpDir, "certs.pem")

	cert := generateTestCertificate(t)
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := pkicrypto.NewSoftwareSigner(&pkicrypto.KeyPair{
		Algorithm:  pkicrypto.AlgECDSAP256,
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	})

	// Try to write keys to invalid path
	err := SaveCredentialPEM(certsPath, "/nonexistent/dir/keys.pem", []*x509.Certificate{cert}, []pkicrypto.Signer{signer}, nil)
	if err == nil {
		t.Error("SaveCredentialPEM should fail for invalid keys path")
	}
}

func TestU_SaveCredentialPEM_NilCerts(t *testing.T) {
	tmpDir := t.TempDir()
	certsPath := filepath.Join(tmpDir, "certs.pem")

	err := SaveCredentialPEM(certsPath, "", nil, nil, nil)
	if err != nil {
		t.Fatalf("SaveCredentialPEM should succeed with nil certs: %v", err)
	}
}

func TestU_SaveCredentialPEM_EmptySigners(t *testing.T) {
	tmpDir := t.TempDir()
	certsPath := filepath.Join(tmpDir, "certs.pem")
	keysPath := filepath.Join(tmpDir, "keys.pem")

	cert := generateTestCertificate(t)

	// Save with empty signers slice - should not create keys file
	err := SaveCredentialPEM(certsPath, keysPath, []*x509.Certificate{cert}, []pkicrypto.Signer{}, nil)
	if err != nil {
		t.Fatalf("SaveCredentialPEM failed: %v", err)
	}

	// Keys file should not be created when signers is empty
	if _, err := os.Stat(keysPath); !os.IsNotExist(err) {
		t.Error("keys file should not be created when signers is empty")
	}
}

// =============================================================================
// LoadCredentialPEM Error Cases
// =============================================================================

func TestU_LoadCredentialPEM_KeysNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	certsPath := filepath.Join(tmpDir, "certs.pem")

	// Create and save a certificate
	cert := generateTestCertificate(t)
	certsPEM, _ := EncodeCertificatesPEM([]*x509.Certificate{cert})
	_ = os.WriteFile(certsPath, certsPEM, 0644)

	// Try to load with non-existent keys path
	_, _, err := LoadCredentialPEM(certsPath, "/nonexistent/keys.pem", nil)
	if err == nil {
		t.Error("LoadCredentialPEM should fail for nonexistent keys file")
	}
}

func TestU_LoadCredentialPEM_WrongPassphrase(t *testing.T) {
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

	// Save with encryption
	err := SaveCredentialPEM(certsPath, keysPath, []*x509.Certificate{cert}, []pkicrypto.Signer{signer}, []byte("correctpassword"))
	if err != nil {
		t.Fatalf("SaveCredentialPEM failed: %v", err)
	}

	// Try to load with wrong passphrase
	_, _, err = LoadCredentialPEM(certsPath, keysPath, []byte("wrongpassword"))
	if err == nil {
		t.Error("LoadCredentialPEM should fail with wrong passphrase")
	}
}
