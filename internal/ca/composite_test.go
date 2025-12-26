package ca

import (
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

	"github.com/cloudflare/circl/sign/dilithium/mode5"
	pkicrypto "github.com/remiblancher/pki/internal/crypto"
	"github.com/remiblancher/pki/internal/x509util"
)

func TestMLDSASignVerify(t *testing.T) {
	// Generate ML-DSA-87 key pair
	pub, priv, err := mode5.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Key generation failed: %v", err)
	}

	// Create a test message
	testMessage := []byte("Hello, composite signatures!")

	// Build domain separator
	oid := x509util.OIDMLDSA87ECDSAP384SHA512
	domainSep, err := asn1.Marshal(oid)
	if err != nil {
		t.Fatalf("Domain separator failed: %v", err)
	}

	// Full message
	message := append(domainSep, testMessage...)
	t.Logf("Message length: %d", len(message))
	t.Logf("Domain separator length: %d", len(domainSep))

	// Sign
	sig := make([]byte, mode5.SignatureSize)
	mode5.SignTo(priv, message, sig)
	t.Logf("Signature length: %d", len(sig))

	// Verify
	valid := mode5.Verify(pub, message, sig)
	t.Logf("ML-DSA-87 signature valid: %v", valid)
	if !valid {
		t.Error("ML-DSA-87 signature verification failed")
	}

	// Marshal and unmarshal public key
	pubBytes := pub.Bytes()
	t.Logf("Public key size: %d", len(pubBytes))

	var pub2 mode5.PublicKey
	if err := pub2.UnmarshalBinary(pubBytes); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	// Verify with unmarshaled key
	valid2 := mode5.Verify(&pub2, message, sig)
	t.Logf("ML-DSA-87 after unmarshal valid: %v", valid2)
	if !valid2 {
		t.Error("ML-DSA-87 verification after unmarshal failed")
	}
}

func TestCompositeSignatureRoundTrip(t *testing.T) {
	// Generate classical key
	classicalSigner, err := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgECDSAP384)
	if err != nil {
		t.Fatalf("Failed to generate classical key: %v", err)
	}

	// Generate PQC key
	pqcSigner, err := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgMLDSA87)
	if err != nil {
		t.Fatalf("Failed to generate PQC key: %v", err)
	}

	// Get composite algorithm
	compAlg, err := GetCompositeAlgorithm(pkicrypto.AlgECDSAP384, pkicrypto.AlgMLDSA87)
	if err != nil {
		t.Fatalf("Failed to get composite algorithm: %v", err)
	}
	t.Logf("Composite algorithm: %s", compAlg.Name)

	// Create test TBS bytes
	tbsBytes := []byte("This is a test TBS certificate content for signature testing")

	// Create composite signature
	signature, err := CreateCompositeSignature(tbsBytes, compAlg, pqcSigner, classicalSigner)
	if err != nil {
		t.Fatalf("Failed to create composite signature: %v", err)
	}
	t.Logf("Composite signature length: %d", len(signature))

	// Parse the signature
	var compSig CompositeSignatureValue
	_, err = asn1.Unmarshal(signature, &compSig)
	if err != nil {
		t.Fatalf("Failed to parse composite signature: %v", err)
	}
	t.Logf("ML-DSA signature length: %d", len(compSig.MLDSASig.Bytes))
	t.Logf("Classical signature length: %d", len(compSig.ClassicalSig.Bytes))

	// Build domain separator
	domainSep, err := BuildDomainSeparator(compAlg.OID)
	if err != nil {
		t.Fatalf("Failed to build domain separator: %v", err)
	}

	// Reconstruct message
	messageToVerify := append(domainSep, tbsBytes...)

	// Verify ML-DSA signature directly
	pqcPub := pqcSigner.Public()
	pqcKey, ok := pqcPub.(*mode5.PublicKey)
	if !ok {
		t.Fatalf("PQC public key is not *mode5.PublicKey, got %T", pqcPub)
	}

	mldsaValid := mode5.Verify(pqcKey, messageToVerify, compSig.MLDSASig.Bytes)
	t.Logf("ML-DSA verification: %v", mldsaValid)
	if !mldsaValid {
		t.Error("ML-DSA signature verification failed")
	}

	// Verify ECDSA signature
	classicalPub := classicalSigner.Public()
	h := sha512.New()
	h.Write(messageToVerify)
	digest := h.Sum(nil)

	ecdsaValid := verifyECDSA(classicalPub, digest, compSig.ClassicalSig.Bytes)
	t.Logf("ECDSA verification: %v", ecdsaValid)
	if !ecdsaValid {
		t.Error("ECDSA signature verification failed")
	}
}

func TestCertificateRawValuePreservation(t *testing.T) {
	// Create some test TBS bytes
	tbsBytes := []byte("test TBS bytes that should be preserved exactly")
	
	// Create a certificate structure with raw TBS
	cert := compositeCertificate{
		TBSCertificate: asn1.RawValue{FullBytes: tbsBytes},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: x509util.OIDMLDSA87ECDSAP384SHA512,
		},
		SignatureValue: asn1.BitString{
			Bytes:     []byte("fake signature"),
			BitLength: len("fake signature") * 8,
		},
	}
	
	// Marshal the certificate
	certDER, err := asn1.Marshal(cert)
	if err != nil {
		t.Fatalf("Failed to marshal certificate: %v", err)
	}
	t.Logf("Certificate DER length: %d", len(certDER))
	
	// Check if TBS bytes are in the certificate DER
	// They should be embedded exactly
	found := false
	for i := 0; i <= len(certDER)-len(tbsBytes); i++ {
		if string(certDER[i:i+len(tbsBytes)]) == string(tbsBytes) {
			found = true
			t.Logf("TBS bytes found at offset %d", i)
			break
		}
	}
	
	if !found {
		t.Error("TBS bytes not found in certificate DER")
	}
}

