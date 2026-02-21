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

	pkicrypto "github.com/remiblancher/qpki/pkg/crypto"
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

// issueIntermediateCA issues an intermediate CA certificate.
func issueIntermediateCA(t *testing.T, caCert *x509.Certificate, caKey crypto.Signer, kp *testKeyPair) *x509.Certificate {
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
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, kp.PublicKey, caKey)
	if err != nil {
		t.Fatalf("Failed to create intermediate CA certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse intermediate CA certificate: %v", err)
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

// =============================================================================
// ML-DSA Test Helpers
// =============================================================================

// generateMLDSAKeyPair generates an ML-DSA key pair for testing.
func generateMLDSAKeyPair(t *testing.T, alg pkicrypto.AlgorithmID) *testKeyPair {
	t.Helper()
	kp, err := pkicrypto.GenerateKeyPair(alg)
	if err != nil {
		t.Fatalf("Failed to generate ML-DSA key pair: %v", err)
	}
	signer, ok := kp.PrivateKey.(crypto.Signer)
	if !ok {
		t.Fatalf("ML-DSA private key does not implement crypto.Signer")
	}
	return &testKeyPair{
		PrivateKey: signer,
		PublicKey:  kp.PublicKey,
		Algorithm:  string(alg),
	}
}

// generateMLDSACertificate creates a self-signed certificate using ML-DSA.
func generateMLDSACertificate(t *testing.T, kp *testKeyPair, alg pkicrypto.AlgorithmID) *x509.Certificate {
	t.Helper()

	// Get the ML-DSA OID
	var sigOID asn1.ObjectIdentifier
	switch alg {
	case pkicrypto.AlgMLDSA44:
		sigOID = OIDMLDSA44
	case pkicrypto.AlgMLDSA65:
		sigOID = OIDMLDSA65
	case pkicrypto.AlgMLDSA87:
		sigOID = OIDMLDSA87
	default:
		t.Fatalf("Unsupported ML-DSA algorithm: %s", alg)
	}

	// Marshal ML-DSA public key bytes
	pubBytes, err := pkicrypto.PublicKeyBytes(kp.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal ML-DSA public key: %v", err)
	}

	// Build SubjectPublicKeyInfo with ML-DSA
	spki := struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: sigOID,
		},
		PublicKey: asn1.BitString{
			Bytes:     pubBytes,
			BitLength: len(pubBytes) * 8,
		},
	}

	spkiBytes, err := asn1.Marshal(spki)
	if err != nil {
		t.Fatalf("Failed to marshal SPKI: %v", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("Failed to generate serial number: %v", err)
	}

	// Build TBSCertificate manually for ML-DSA
	tbs := struct {
		Version            int `asn1:"optional,explicit,default:0,tag:0"`
		SerialNumber       *big.Int
		SignatureAlgorithm pkix.AlgorithmIdentifier
		Issuer             pkix.RDNSequence
		Validity           struct {
			NotBefore, NotAfter time.Time
		}
		Subject               pkix.RDNSequence
		SubjectPublicKeyInfo  asn1.RawValue
		BasicConstraintsValid bool `asn1:"optional"`
	}{
		Version:            2, // v3
		SerialNumber:       serialNumber,
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: sigOID},
		Issuer: pkix.RDNSequence{
			pkix.RelativeDistinguishedNameSET{
				pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "ML-DSA Test Certificate"},
				pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "Test Org"},
			},
		},
		Validity: struct {
			NotBefore, NotAfter time.Time
		}{
			NotBefore: time.Now().Add(-1 * time.Hour),
			NotAfter:  time.Now().Add(24 * time.Hour),
		},
		Subject: pkix.RDNSequence{
			pkix.RelativeDistinguishedNameSET{
				pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "ML-DSA Test Certificate"},
				pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "Test Org"},
			},
		},
		SubjectPublicKeyInfo: asn1.RawValue{FullBytes: spkiBytes},
	}

	tbsBytes, err := asn1.Marshal(tbs)
	if err != nil {
		t.Fatalf("Failed to marshal TBSCertificate: %v", err)
	}

	// Sign TBS with ML-DSA (must pass crypto.Hash(0) not nil)
	signature, err := kp.PrivateKey.Sign(rand.Reader, tbsBytes, crypto.Hash(0))
	if err != nil {
		t.Fatalf("Failed to sign TBSCertificate: %v", err)
	}

	// Build full certificate
	certStruct := struct {
		TBSCertificate     asn1.RawValue
		SignatureAlgorithm pkix.AlgorithmIdentifier
		SignatureValue     asn1.BitString
	}{
		TBSCertificate:     asn1.RawValue{FullBytes: tbsBytes},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: sigOID},
		SignatureValue: asn1.BitString{
			Bytes:     signature,
			BitLength: len(signature) * 8,
		},
	}

	certDER, err := asn1.Marshal(certStruct)
	if err != nil {
		t.Fatalf("Failed to marshal certificate: %v", err)
	}

	// Parse it back (Go's x509 will parse it but won't verify ML-DSA)
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

// =============================================================================
// SLH-DSA Test Helpers
// =============================================================================

// generateSLHDSAKeyPair generates an SLH-DSA key pair for testing.
func generateSLHDSAKeyPair(t *testing.T, alg pkicrypto.AlgorithmID) *testKeyPair {
	t.Helper()
	kp, err := pkicrypto.GenerateKeyPair(alg)
	if err != nil {
		t.Fatalf("Failed to generate SLH-DSA key pair: %v", err)
	}
	signer, ok := kp.PrivateKey.(crypto.Signer)
	if !ok {
		t.Fatalf("SLH-DSA private key does not implement crypto.Signer")
	}
	return &testKeyPair{
		PrivateKey: signer,
		PublicKey:  kp.PublicKey,
		Algorithm:  string(alg),
	}
}

// generateSLHDSACertificate creates a self-signed certificate using SLH-DSA.
func generateSLHDSACertificate(t *testing.T, kp *testKeyPair, alg pkicrypto.AlgorithmID) *x509.Certificate {
	t.Helper()

	// Get the SLH-DSA OID (SHA2 and SHAKE variants)
	// Note: AlgSLHDSA*s/f are aliases for AlgSLHDSASHA2*s/f
	var sigOID asn1.ObjectIdentifier
	switch alg {
	// SHA2 variants (includes backwards-compatible aliases)
	case pkicrypto.AlgSLHDSASHA2128s:
		sigOID = OIDSLHDSASHA2128s
	case pkicrypto.AlgSLHDSASHA2128f:
		sigOID = OIDSLHDSASHA2128f
	case pkicrypto.AlgSLHDSASHA2192s:
		sigOID = OIDSLHDSASHA2192s
	case pkicrypto.AlgSLHDSASHA2192f:
		sigOID = OIDSLHDSASHA2192f
	case pkicrypto.AlgSLHDSASHA2256s:
		sigOID = OIDSLHDSASHA2256s
	case pkicrypto.AlgSLHDSASHA2256f:
		sigOID = OIDSLHDSASHA2256f
	// SHAKE variants (RFC 9814)
	case pkicrypto.AlgSLHDSASHAKE128s:
		sigOID = OIDSLHDSASHAKE128s
	case pkicrypto.AlgSLHDSASHAKE128f:
		sigOID = OIDSLHDSASHAKE128f
	case pkicrypto.AlgSLHDSASHAKE192s:
		sigOID = OIDSLHDSASHAKE192s
	case pkicrypto.AlgSLHDSASHAKE192f:
		sigOID = OIDSLHDSASHAKE192f
	case pkicrypto.AlgSLHDSASHAKE256s:
		sigOID = OIDSLHDSASHAKE256s
	case pkicrypto.AlgSLHDSASHAKE256f:
		sigOID = OIDSLHDSASHAKE256f
	default:
		t.Fatalf("Unsupported SLH-DSA algorithm: %s", alg)
	}

	// Marshal SLH-DSA public key bytes
	pubBytes, err := pkicrypto.PublicKeyBytes(kp.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal SLH-DSA public key: %v", err)
	}

	// Build SubjectPublicKeyInfo with SLH-DSA
	spki := struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: sigOID,
		},
		PublicKey: asn1.BitString{
			Bytes:     pubBytes,
			BitLength: len(pubBytes) * 8,
		},
	}

	spkiBytes, err := asn1.Marshal(spki)
	if err != nil {
		t.Fatalf("Failed to marshal SPKI: %v", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("Failed to generate serial number: %v", err)
	}

	// Build TBSCertificate manually for SLH-DSA
	tbs := struct {
		Version            int `asn1:"optional,explicit,default:0,tag:0"`
		SerialNumber       *big.Int
		SignatureAlgorithm pkix.AlgorithmIdentifier
		Issuer             pkix.RDNSequence
		Validity           struct {
			NotBefore, NotAfter time.Time
		}
		Subject               pkix.RDNSequence
		SubjectPublicKeyInfo  asn1.RawValue
		BasicConstraintsValid bool `asn1:"optional"`
	}{
		Version:            2, // v3
		SerialNumber:       serialNumber,
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: sigOID},
		Issuer: pkix.RDNSequence{
			pkix.RelativeDistinguishedNameSET{
				pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "SLH-DSA Test Certificate"},
				pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "Test Org"},
			},
		},
		Validity: struct {
			NotBefore, NotAfter time.Time
		}{
			NotBefore: time.Now().Add(-1 * time.Hour),
			NotAfter:  time.Now().Add(24 * time.Hour),
		},
		Subject: pkix.RDNSequence{
			pkix.RelativeDistinguishedNameSET{
				pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "SLH-DSA Test Certificate"},
				pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "Test Org"},
			},
		},
		SubjectPublicKeyInfo: asn1.RawValue{FullBytes: spkiBytes},
	}

	tbsBytes, err := asn1.Marshal(tbs)
	if err != nil {
		t.Fatalf("Failed to marshal TBSCertificate: %v", err)
	}

	// Sign TBS with SLH-DSA
	signature, err := kp.PrivateKey.Sign(rand.Reader, tbsBytes, nil)
	if err != nil {
		t.Fatalf("Failed to sign TBSCertificate: %v", err)
	}

	// Build full certificate
	certStruct := struct {
		TBSCertificate     asn1.RawValue
		SignatureAlgorithm pkix.AlgorithmIdentifier
		SignatureValue     asn1.BitString
	}{
		TBSCertificate:     asn1.RawValue{FullBytes: tbsBytes},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: sigOID},
		SignatureValue: asn1.BitString{
			Bytes:     signature,
			BitLength: len(signature) * 8,
		},
	}

	certDER, err := asn1.Marshal(certStruct)
	if err != nil {
		t.Fatalf("Failed to marshal certificate: %v", err)
	}

	// Parse it back (Go's x509 will parse it but won't verify SLH-DSA)
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

// =============================================================================
// ML-KEM Test Helpers
// =============================================================================

// testKEMKeyPair holds a KEM key pair for testing.
type testKEMKeyPair struct {
	PrivateKey crypto.PrivateKey
	PublicKey  crypto.PublicKey
	Algorithm  pkicrypto.AlgorithmID
}

// generateMLKEMKeyPair generates an ML-KEM key pair for testing.
func generateMLKEMKeyPair(t *testing.T, alg pkicrypto.AlgorithmID) *testKEMKeyPair {
	t.Helper()
	kp, err := pkicrypto.GenerateKEMKeyPair(alg)
	if err != nil {
		t.Fatalf("Failed to generate ML-KEM key pair: %v", err)
	}
	return &testKEMKeyPair{
		PrivateKey: kp.PrivateKey,
		PublicKey:  kp.PublicKey,
		Algorithm:  alg,
	}
}

// generateMLKEMCertificate creates a certificate with an ML-KEM public key.
// The certificate is signed with ECDSA (since ML-KEM is not a signing algorithm).
// This creates a "hybrid" style certificate where the SPKI contains ML-KEM.
func generateMLKEMCertificate(t *testing.T, kemKP *testKEMKeyPair) *x509.Certificate {
	t.Helper()

	// Get the ML-KEM OID
	var kemOID asn1.ObjectIdentifier
	switch kemKP.Algorithm {
	case pkicrypto.AlgMLKEM512:
		kemOID = OIDMLKEM512
	case pkicrypto.AlgMLKEM768:
		kemOID = OIDMLKEM768
	case pkicrypto.AlgMLKEM1024:
		kemOID = OIDMLKEM1024
	default:
		t.Fatalf("Unsupported KEM algorithm: %s", kemKP.Algorithm)
	}

	// Marshal ML-KEM public key bytes
	pubBytes, err := pkicrypto.MLKEMPublicKeyBytes(kemKP.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal ML-KEM public key: %v", err)
	}

	// Build SubjectPublicKeyInfo with ML-KEM
	spki := struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: kemOID,
		},
		PublicKey: asn1.BitString{
			Bytes:     pubBytes,
			BitLength: len(pubBytes) * 8,
		},
	}

	spkiBytes, err := asn1.Marshal(spki)
	if err != nil {
		t.Fatalf("Failed to marshal SPKI: %v", err)
	}

	// Create signing key (ECDSA P-256)
	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate signing key: %v", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("Failed to generate serial number: %v", err)
	}

	// Create a basic certificate template
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "ML-KEM Test Certificate",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement,
		BasicConstraintsValid: true,
	}

	// Create the certificate DER (signed with ECDSA, but we'll replace SPKI)
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &signingKey.PublicKey, signingKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	// Parse it back
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Replace RawSubjectPublicKeyInfo with ML-KEM SPKI
	// Note: This creates a certificate that won't verify, but works for CMS encryption tests
	cert.RawSubjectPublicKeyInfo = spkiBytes

	return cert
}
