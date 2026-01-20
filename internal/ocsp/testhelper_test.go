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
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
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

// =============================================================================
// PQC Test Helpers
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

// generatePQCOCSPResponderCert creates an OCSP responder certificate with PQC key.
// Since Go's x509 doesn't support PQC, we build the certificate manually.
func generatePQCOCSPResponderCert(t *testing.T, caCert *x509.Certificate, caKey crypto.Signer, kp *testKeyPair, alg pkicrypto.AlgorithmID) *x509.Certificate {
	t.Helper()

	// Get the signature algorithm OID
	sigOID := pqcAlgorithmToOID(t, alg)

	// Get public key bytes
	pubBytes, err := pkicrypto.PublicKeyBytes(kp.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}

	// Build SubjectPublicKeyInfo
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

	// Build ExtKeyUsage extension with id-kp-OCSPSigning
	// OID: 1.3.6.1.5.5.7.3.9
	ocspSigningOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}
	ekuValue, err := asn1.Marshal([]asn1.ObjectIdentifier{ocspSigningOID})
	if err != nil {
		t.Fatalf("Failed to marshal EKU: %v", err)
	}
	ekuExtension := pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 37}, // id-ce-extKeyUsage
		Critical: false,
		Value:    ekuValue,
	}

	// Build extensions - wrap in EXPLICIT [3] tag
	extensions := []pkix.Extension{ekuExtension}
	extensionsBytes, err := asn1.Marshal(extensions)
	if err != nil {
		t.Fatalf("Failed to marshal extensions: %v", err)
	}

	// Build TBSCertificate with extensions
	tbs := struct {
		Version            int `asn1:"optional,explicit,default:0,tag:0"`
		SerialNumber       *big.Int
		SignatureAlgorithm pkix.AlgorithmIdentifier
		Issuer             pkix.RDNSequence
		Validity           struct {
			NotBefore, NotAfter time.Time
		}
		Subject              pkix.RDNSequence
		SubjectPublicKeyInfo asn1.RawValue
		Extensions           asn1.RawValue `asn1:"optional,explicit,tag:3"`
	}{
		Version:            2, // v3
		SerialNumber:       serialNumber,
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: sigOID},
		Issuer: pkix.RDNSequence{
			pkix.RelativeDistinguishedNameSET{
				pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: caCert.Subject.CommonName},
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
				pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "Test OCSP Responder - " + string(alg)},
				pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "Test Org"},
			},
		},
		SubjectPublicKeyInfo: asn1.RawValue{FullBytes: spkiBytes},
		Extensions:           asn1.RawValue{FullBytes: extensionsBytes},
	}

	tbsBytes, err := asn1.Marshal(tbs)
	if err != nil {
		t.Fatalf("Failed to marshal TBSCertificate: %v", err)
	}

	// Sign TBS with PQC key
	var signOpts crypto.SignerOpts
	switch alg {
	case pkicrypto.AlgMLDSA44, pkicrypto.AlgMLDSA65, pkicrypto.AlgMLDSA87:
		signOpts = crypto.Hash(0)
	default:
		signOpts = nil
	}

	signature, err := kp.PrivateKey.Sign(rand.Reader, tbsBytes, signOpts)
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

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

// pqcAlgorithmToOID returns the ASN.1 OID for a PQC algorithm.
func pqcAlgorithmToOID(t *testing.T, alg pkicrypto.AlgorithmID) asn1.ObjectIdentifier {
	t.Helper()
	switch alg {
	case pkicrypto.AlgMLDSA44:
		return OIDMLDSA44
	case pkicrypto.AlgMLDSA65:
		return OIDMLDSA65
	case pkicrypto.AlgMLDSA87:
		return OIDMLDSA87
	case pkicrypto.AlgSLHDSA128s:
		return OIDSLHDSA128s
	case pkicrypto.AlgSLHDSA128f:
		return OIDSLHDSA128f
	case pkicrypto.AlgSLHDSA192s:
		return OIDSLHDSA192s
	case pkicrypto.AlgSLHDSA192f:
		return OIDSLHDSA192f
	case pkicrypto.AlgSLHDSA256s:
		return OIDSLHDSA256s
	case pkicrypto.AlgSLHDSA256f:
		return OIDSLHDSA256f
	default:
		t.Fatalf("Unsupported PQC algorithm: %s", alg)
		return nil
	}
}

// OIDAltSubjectPublicKeyInfo is the OID for Catalyst certificates.
// Reference: draft-lamps-x509-hybrid-certs.
var OIDAltSubjectPublicKeyInfo = asn1.ObjectIdentifier{2, 5, 29, 72}

// generateCatalystOCSPResponderCert creates a Catalyst OCSP responder certificate.
// Catalyst certificates have a classical key in the standard SubjectPublicKeyInfo
// and a PQC key in the AltSubjectPublicKeyInfo extension.
func generateCatalystOCSPResponderCert(t *testing.T, caCert *x509.Certificate, caKey crypto.Signer, hybridSigner pkicrypto.HybridSigner) *x509.Certificate {
	t.Helper()

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("Failed to generate serial number: %v", err)
	}

	// Get PQC public key bytes for the AltSubjectPublicKeyInfo extension
	pqcSigner := hybridSigner.PQCSigner()
	pqcPubBytes, err := pkicrypto.PublicKeyBytes(pqcSigner.Public())
	if err != nil {
		t.Fatalf("Failed to get PQC public key bytes: %v", err)
	}

	// Build AltSubjectPublicKeyInfo extension
	// This is a SubjectPublicKeyInfo structure with the PQC public key
	pqcAlg := pqcSigner.Algorithm()
	pqcOID := pqcAlgorithmToOID(t, pqcAlg)

	altSpki := struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: pqcOID,
		},
		PublicKey: asn1.BitString{
			Bytes:     pqcPubBytes,
			BitLength: len(pqcPubBytes) * 8,
		},
	}

	altSpkiBytes, err := asn1.Marshal(altSpki)
	if err != nil {
		t.Fatalf("Failed to marshal AltSubjectPublicKeyInfo: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "Test Catalyst OCSP Responder",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
		BasicConstraintsValid: true,
		ExtraExtensions: []pkix.Extension{
			{
				Id:       OIDAltSubjectPublicKeyInfo,
				Critical: false,
				Value:    altSpkiBytes,
			},
		},
	}

	// Get the classical public key
	classicalPub := hybridSigner.ClassicalSigner().Public()

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, classicalPub, caKey)
	if err != nil {
		t.Fatalf("Failed to create Catalyst OCSP responder certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse Catalyst OCSP responder certificate: %v", err)
	}

	return cert
}

// generateOCSPResponderCertWithUnknownEKU creates an OCSP responder certificate
// where the OCSPSigning EKU is in UnknownExtKeyUsage (e.g., for PQC certificates
// where Go might not parse the EKU correctly).
func generateOCSPResponderCertWithUnknownEKU(t *testing.T, caCert *x509.Certificate, caKey crypto.Signer, kp *testKeyPair) *x509.Certificate {
	t.Helper()

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("Failed to generate serial number: %v", err)
	}

	// id-kp-OCSPSigning OID: 1.3.6.1.5.5.7.3.9
	ocspSigningOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}

	// Create EKU extension manually with the OCSP signing OID
	ekuValue, err := asn1.Marshal([]asn1.ObjectIdentifier{ocspSigningOID})
	if err != nil {
		t.Fatalf("Failed to marshal EKU: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "Test OCSP Responder (UnknownEKU)",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		// Don't set ExtKeyUsage directly - add it as an extra extension
		ExtraExtensions: []pkix.Extension{
			{
				Id:       asn1.ObjectIdentifier{2, 5, 29, 37}, // id-ce-extKeyUsage
				Critical: false,
				Value:    ekuValue,
			},
		},
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
