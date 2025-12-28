package cms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
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

// generateTestCertificate creates a self-signed certificate for testing.
func generateTestCertificate(t *testing.T, kp *testKeyPair) *x509.Certificate {
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
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, kp.PublicKey, kp.PrivateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
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

// extractSignerInfoOID extracts the SignatureAlgorithm OID from a signed CMS structure.
func extractSignerInfoOID(t *testing.T, signedDataDER []byte) asn1.ObjectIdentifier {
	t.Helper()

	// Parse ContentInfo
	var contentInfo ContentInfo
	_, err := asn1.Unmarshal(signedDataDER, &contentInfo)
	if err != nil {
		t.Fatalf("Failed to parse ContentInfo: %v", err)
	}

	// Parse SignedData
	var signedData SignedData
	_, err = asn1.Unmarshal(contentInfo.Content.Bytes, &signedData)
	if err != nil {
		t.Fatalf("Failed to parse SignedData: %v", err)
	}

	if len(signedData.SignerInfos) == 0 {
		t.Fatal("No signer info in SignedData")
	}

	return signedData.SignerInfos[0].SignatureAlgorithm.Algorithm
}

// modifySignedDataOID modifies the SignatureAlgorithm OID in a CMS structure.
// This is used to test algorithm confusion attacks.
func modifySignedDataOID(t *testing.T, signedDataDER []byte, newOID asn1.ObjectIdentifier) []byte {
	t.Helper()

	// Parse ContentInfo
	var contentInfo ContentInfo
	_, err := asn1.Unmarshal(signedDataDER, &contentInfo)
	if err != nil {
		t.Fatalf("Failed to parse ContentInfo: %v", err)
	}

	// Parse SignedData
	var signedData SignedData
	_, err = asn1.Unmarshal(contentInfo.Content.Bytes, &signedData)
	if err != nil {
		t.Fatalf("Failed to parse SignedData: %v", err)
	}

	if len(signedData.SignerInfos) == 0 {
		t.Fatal("No signer info in SignedData")
	}

	// Modify the OID
	signedData.SignerInfos[0].SignatureAlgorithm.Algorithm = newOID

	// Re-marshal SignedData
	signedDataBytes, err := asn1.Marshal(signedData)
	if err != nil {
		t.Fatalf("Failed to marshal modified SignedData: %v", err)
	}

	// Wrap in ContentInfo
	contentInfo.Content = asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      signedDataBytes,
	}

	result, err := asn1.Marshal(contentInfo)
	if err != nil {
		t.Fatalf("Failed to marshal ContentInfo: %v", err)
	}

	return result
}

// modifySignature modifies the signature bytes in a CMS structure.
// This is used to test signature verification failure.
func modifySignature(t *testing.T, signedDataDER []byte) []byte {
	t.Helper()

	// Parse ContentInfo
	var contentInfo ContentInfo
	_, err := asn1.Unmarshal(signedDataDER, &contentInfo)
	if err != nil {
		t.Fatalf("Failed to parse ContentInfo: %v", err)
	}

	// Parse SignedData
	var signedData SignedData
	_, err = asn1.Unmarshal(contentInfo.Content.Bytes, &signedData)
	if err != nil {
		t.Fatalf("Failed to parse SignedData: %v", err)
	}

	if len(signedData.SignerInfos) == 0 {
		t.Fatal("No signer info in SignedData")
	}

	// Modify signature (flip first byte)
	if len(signedData.SignerInfos[0].Signature) > 0 {
		signedData.SignerInfos[0].Signature[0] ^= 0xFF
	}

	// Re-marshal SignedData
	signedDataBytes, err := asn1.Marshal(signedData)
	if err != nil {
		t.Fatalf("Failed to marshal modified SignedData: %v", err)
	}

	// Wrap in ContentInfo
	contentInfo.Content = asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      signedDataBytes,
	}

	result, err := asn1.Marshal(contentInfo)
	if err != nil {
		t.Fatalf("Failed to marshal ContentInfo: %v", err)
	}

	return result
}

// modifyMessageDigest modifies the message digest attribute in a CMS structure.
func modifyMessageDigest(t *testing.T, signedDataDER []byte) []byte {
	t.Helper()

	// Parse ContentInfo
	var contentInfo ContentInfo
	_, err := asn1.Unmarshal(signedDataDER, &contentInfo)
	if err != nil {
		t.Fatalf("Failed to parse ContentInfo: %v", err)
	}

	// Parse SignedData
	var signedData SignedData
	_, err = asn1.Unmarshal(contentInfo.Content.Bytes, &signedData)
	if err != nil {
		t.Fatalf("Failed to parse SignedData: %v", err)
	}

	if len(signedData.SignerInfos) == 0 {
		t.Fatal("No signer info in SignedData")
	}

	// Find and modify message digest attribute
	for i, attr := range signedData.SignerInfos[0].SignedAttrs {
		if attr.Type.Equal(OIDMessageDigest) && len(attr.Values) > 0 {
			var md []byte
			_, err := asn1.Unmarshal(attr.Values[0].FullBytes, &md)
			if err == nil && len(md) > 0 {
				// Modify the digest
				md[0] ^= 0xFF
				newMD, _ := asn1.Marshal(md)
				signedData.SignerInfos[0].SignedAttrs[i].Values[0] = asn1.RawValue{FullBytes: newMD}
			}
			break
		}
	}

	// Re-marshal SignedData
	signedDataBytes, err := asn1.Marshal(signedData)
	if err != nil {
		t.Fatalf("Failed to marshal modified SignedData: %v", err)
	}

	// Wrap in ContentInfo
	contentInfo.Content = asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      signedDataBytes,
	}

	result, err := asn1.Marshal(contentInfo)
	if err != nil {
		t.Fatalf("Failed to marshal ContentInfo: %v", err)
	}

	return result
}
