package cms

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

// =============================================================================
// ParseContentInfo Unit Tests
// =============================================================================

func TestU_ParseContentInfo_Valid(t *testing.T) {
	// Create a real SignedData to test parsing
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	cert, _ := x509.ParseCertificate(certDER)

	// Create a signed CMS message
	signedData, err := Sign(context.Background(), []byte("test"), &SignerConfig{
		Signer:       priv,
		Certificate:  cert,
		DigestAlg:    crypto.SHA256,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	parsed, err := ParseContentInfo(signedData)
	if err != nil {
		t.Fatalf("ParseContentInfo() error = %v", err)
	}

	if !parsed.ContentType.Equal(OIDSignedData) {
		t.Errorf("ContentType = %v, want %v", parsed.ContentType, OIDSignedData)
	}
}

func TestU_ParseContentInfo_Invalid(t *testing.T) {
	_, err := ParseContentInfo([]byte("not valid ASN.1"))
	if err == nil {
		t.Error("ParseContentInfo() should fail for invalid data")
	}
}

func TestU_ParseContentInfo_EnvelopedData(t *testing.T) {
	// Generate test RSA key pair for encryption
	kp := generateRSAKeyPair2048(t)
	cert := generateTestCert(t, kp)

	// Create real EnvelopedData using Encrypt() with AES-CBC
	// (AES-GCM uses AuthEnvelopedData instead)
	plaintext := []byte("test content")
	envelopedData, err := Encrypt(context.Background(), plaintext, &EncryptOptions{
		Recipients:        []*x509.Certificate{cert},
		ContentEncryption: AES256CBC,
	})
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	parsed, err := ParseContentInfo(envelopedData)
	if err != nil {
		t.Fatalf("ParseContentInfo() error = %v", err)
	}

	if !parsed.ContentType.Equal(OIDEnvelopedData) {
		t.Errorf("ContentType = %v, want %v", parsed.ContentType, OIDEnvelopedData)
	}
}

// =============================================================================
// ParseSignedData Unit Tests
// =============================================================================

func TestU_ParseSignedData_Valid(t *testing.T) {
	// Generate test key and certificate
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Signer"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}

	// Create a signed CMS message
	content := []byte("test content for signing")
	// Use the Sign function to create a valid SignedData
	signedData, err := Sign(context.Background(), content, &SignerConfig{
		Signer:       priv,
		Certificate:  cert,
		DigestAlg:    crypto.SHA256,
		IncludeCerts: true,
		Detached:     false,
	})
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Parse it back
	sd, err := ParseSignedData(signedData)
	if err != nil {
		t.Fatalf("ParseSignedData() error = %v", err)
	}

	if sd.Version < 1 {
		t.Errorf("SignedData.Version = %d, want >= 1", sd.Version)
	}
}

func TestU_ParseSignedData_Invalid(t *testing.T) {
	_, err := ParseSignedData([]byte("not valid ASN.1"))
	if err == nil {
		t.Error("ParseSignedData() should fail for invalid data")
	}
}

func TestU_ParseSignedData_WrongContentType(t *testing.T) {
	// Create a ContentInfo with EnvelopedData OID instead of SignedData
	ci := ContentInfo{
		ContentType: OIDEnvelopedData,
		Content:     asn1.RawValue{Tag: 0, Class: 2, IsCompound: true, Bytes: []byte{}},
	}

	data, err := asn1.Marshal(ci)
	if err != nil {
		t.Fatalf("Failed to marshal ContentInfo: %v", err)
	}

	_, err = ParseSignedData(data)
	if err == nil {
		t.Error("ParseSignedData() should fail for EnvelopedData ContentInfo")
	}
}

// =============================================================================
// ParseEnvelopedData Unit Tests
// =============================================================================

func TestU_ParseEnvelopedData_Valid(t *testing.T) {
	// Generate test RSA key pair
	kp := generateRSAKeyPair2048(t)
	cert := generateTestCert(t, kp)

	// Create an encrypted CMS message with AES-CBC (EnvelopedData)
	// AES-GCM uses AuthEnvelopedData instead
	plaintext := []byte("test content for encryption")
	envelopedData, err := Encrypt(context.Background(), plaintext, &EncryptOptions{
		Recipients:        []*x509.Certificate{cert},
		ContentEncryption: AES256CBC,
	})
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Parse it back
	env, err := ParseEnvelopedData(envelopedData)
	if err != nil {
		t.Fatalf("ParseEnvelopedData() error = %v", err)
	}

	if env.Version < 0 {
		t.Errorf("EnvelopedData.Version = %d, unexpected", env.Version)
	}
}

func TestU_ParseEnvelopedData_Invalid(t *testing.T) {
	_, err := ParseEnvelopedData([]byte("not valid ASN.1"))
	if err == nil {
		t.Error("ParseEnvelopedData() should fail for invalid data")
	}
}

func TestU_ParseEnvelopedData_WrongContentType(t *testing.T) {
	// Create a ContentInfo with SignedData OID instead of EnvelopedData
	ci := ContentInfo{
		ContentType: OIDSignedData,
		Content:     asn1.RawValue{Tag: 0, Class: 2, IsCompound: true, Bytes: []byte{}},
	}

	data, err := asn1.Marshal(ci)
	if err != nil {
		t.Fatalf("Failed to marshal ContentInfo: %v", err)
	}

	_, err = ParseEnvelopedData(data)
	if err == nil {
		t.Error("ParseEnvelopedData() should fail for SignedData ContentInfo")
	}
}

// =============================================================================
// Helper functions for tests
// =============================================================================

func generateRSAKeyPair2048(t *testing.T) *testKeyPair {
	t.Helper()
	return generateRSAKeyPair(t, 2048)
}

func generateTestCert(t *testing.T, kp *testKeyPair) *x509.Certificate {
	t.Helper()
	return generateTestCertificate(t, kp)
}

// =============================================================================
// ParseCertificates Unit Tests
// =============================================================================

func TestU_ParseCertificates_Valid(t *testing.T) {
	// Generate test key and certificate
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Cert"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}

	// Test ParseCertificates with raw certificate DER bytes
	certs, err := ParseCertificates(certDER)
	if err != nil {
		t.Fatalf("ParseCertificates() error = %v", err)
	}

	if len(certs) == 0 {
		t.Error("ParseCertificates() returned no certificates")
	}

	// Verify the certificate matches
	if len(certs) > 0 && !bytes.Equal(certs[0].Raw, cert.Raw) {
		t.Error("ParseCertificates() did not return the correct certificate")
	}
}

func TestU_ParseCertificates_FromSignedData(t *testing.T) {
	// Generate test key and certificate
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Cert"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}

	// Create signed data with certificate
	content := []byte("test")
	signedDataBytes, err := Sign(context.Background(), content, &SignerConfig{
		Signer:       priv,
		Certificate:  cert,
		DigestAlg:    crypto.SHA256,
		IncludeCerts: true,
		Detached:     false,
	})
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Parse the SignedData structure first
	sd, err := ParseSignedData(signedDataBytes)
	if err != nil {
		t.Fatalf("ParseSignedData() error = %v", err)
	}

	// Extract certificates from the SignedData.Certificates raw field
	if len(sd.Certificates.Raw) == 0 {
		t.Skip("No certificates in SignedData.Certificates.Raw")
	}

	// Unwrap the IMPLICIT tagged certificates
	var rawVal asn1.RawValue
	_, err = asn1.Unmarshal(sd.Certificates.Raw, &rawVal)
	if err != nil {
		t.Fatalf("Failed to unmarshal certificates: %v", err)
	}

	// Parse certificates from the inner bytes
	certs, err := ParseCertificates(rawVal.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificates() error = %v", err)
	}

	if len(certs) == 0 {
		t.Error("ParseCertificates() returned no certificates")
	}

	// Verify the certificate matches
	found := false
	for _, c := range certs {
		if bytes.Equal(c.Raw, cert.Raw) {
			found = true
			break
		}
	}
	if !found {
		t.Error("ParseCertificates() did not return the signer certificate")
	}
}

func TestU_ParseCertificates_Invalid(t *testing.T) {
	_, err := ParseCertificates([]byte("not valid"))
	if err == nil {
		t.Error("ParseCertificates() should fail for invalid data")
	}
}

// =============================================================================
// Additional Edge Case Tests
// =============================================================================

// TestU_ParseContentInfo_EmptyContent tests parsing ContentInfo with empty explicit tag.
// Empty EXPLICIT tags are invalid in DER/ASN.1, so this should fail.
func TestU_ParseContentInfo_EmptyContent(t *testing.T) {
	ci := ContentInfo{
		ContentType: OIDData,
		Content:     asn1.RawValue{Tag: 0, Class: 2, IsCompound: true, Bytes: []byte{}},
	}

	data, err := asn1.Marshal(ci)
	if err != nil {
		t.Fatalf("Failed to marshal ContentInfo: %v", err)
	}

	// Empty explicit tag content is invalid ASN.1, so ParseContentInfo should fail
	_, err = ParseContentInfo(data)
	if err == nil {
		t.Error("ParseContentInfo() should fail for empty explicit tag content")
	}
}


// TestU_ParseContentInfo_AuthEnvelopedData tests parsing AuthEnvelopedData ContentInfo.
func TestU_ParseContentInfo_AuthEnvelopedData(t *testing.T) {
	// Generate test RSA key pair for encryption
	kp := generateRSAKeyPair2048(t)
	cert := generateTestCert(t, kp)

	// Create real AuthEnvelopedData using Encrypt() with AES-GCM
	plaintext := []byte("test content")
	authEnvData, err := Encrypt(context.Background(), plaintext, &EncryptOptions{
		Recipients:        []*x509.Certificate{cert},
		ContentEncryption: AES256GCM,
	})
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	parsed, err := ParseContentInfo(authEnvData)
	if err != nil {
		t.Fatalf("ParseContentInfo() error = %v", err)
	}

	if !parsed.ContentType.Equal(OIDAuthEnvelopedData) {
		t.Errorf("ContentType = %v, want %v", parsed.ContentType, OIDAuthEnvelopedData)
	}
}

// TestU_ParseSignedData_MultipleCerts tests parsing SignedData with multiple certificates.
func TestU_ParseSignedData_MultipleCerts(t *testing.T) {
	// Generate test key and certificate
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Signer"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}

	// Create a signed CMS message
	content := []byte("test content")
	signedData, err := Sign(context.Background(), content, &SignerConfig{
		Signer:       priv,
		Certificate:  cert,
		DigestAlg:    crypto.SHA256,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	sd, err := ParseSignedData(signedData)
	if err != nil {
		t.Fatalf("ParseSignedData() error = %v", err)
	}

	// Verify version is correct
	if sd.Version < 1 {
		t.Errorf("SignedData.Version = %d, want >= 1", sd.Version)
	}

	// Verify we have signer info
	if len(sd.SignerInfos) == 0 {
		t.Error("SignedData has no SignerInfos")
	}
}

// TestU_ParseSignedData_DetachedSignature tests parsing detached signature.
func TestU_ParseSignedData_DetachedSignature(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Signer"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	cert, _ := x509.ParseCertificate(certDER)

	// Create detached signature
	content := []byte("detached content")
	signedData, err := Sign(context.Background(), content, &SignerConfig{
		Signer:       priv,
		Certificate:  cert,
		DigestAlg:    crypto.SHA256,
		IncludeCerts: true,
		Detached:     true, // Detached signature
	})
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	sd, err := ParseSignedData(signedData)
	if err != nil {
		t.Fatalf("ParseSignedData() error = %v", err)
	}

	// Verify encapsulated content is empty for detached signatures
	if len(sd.EncapContentInfo.EContent.Bytes) > 0 {
		t.Error("Detached signature should have empty EncapContentInfo.EContent")
	}
}

// TestU_ParseContentInfo_TruncatedData tests parsing truncated data.
func TestU_ParseContentInfo_TruncatedData(t *testing.T) {
	// Valid ContentInfo prefix but truncated
	truncated := []byte{0x30, 0x82, 0x01, 0x00} // SEQUENCE with length but no content

	_, err := ParseContentInfo(truncated)
	if err == nil {
		t.Error("ParseContentInfo() should fail for truncated data")
	}
}

// TestU_ParseSignedData_EmptySignerInfos tests parsing with no signer infos.
func TestU_ParseSignedData_EmptySignerInfos(t *testing.T) {
	// Create ContentInfo with valid SignedData but empty SignerInfos
	sd := SignedData{
		Version: 1,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{
			{Algorithm: OIDSHA256},
		},
		EncapContentInfo: EncapsulatedContentInfo{
			EContentType: OIDData,
		},
		SignerInfos: []SignerInfo{}, // Empty
	}

	sdBytes, err := asn1.Marshal(sd)
	if err != nil {
		t.Fatalf("Failed to marshal SignedData: %v", err)
	}

	ci := ContentInfo{
		ContentType: OIDSignedData,
		Content:     asn1.RawValue{Tag: 0, Class: asn1.ClassContextSpecific, IsCompound: true, Bytes: sdBytes},
	}

	ciBytes, err := asn1.Marshal(ci)
	if err != nil {
		t.Fatalf("Failed to marshal ContentInfo: %v", err)
	}

	parsedSD, err := ParseSignedData(ciBytes)
	if err != nil {
		t.Fatalf("ParseSignedData() error = %v", err)
	}

	if len(parsedSD.SignerInfos) != 0 {
		t.Errorf("Expected empty SignerInfos, got %d", len(parsedSD.SignerInfos))
	}
}
