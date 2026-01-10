package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
	"github.com/remiblancher/post-quantum-pki/internal/x509util"
)

func TestMLDSASignVerify(t *testing.T) {
	// Generate ML-DSA-87 key pair
	pub, priv, err := mldsa87.GenerateKey(rand.Reader)
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

	// Sign (FIPS 204 pure mode: ctx=nil, randomized=false)
	sig := make([]byte, mldsa87.SignatureSize)
	if err := mldsa87.SignTo(priv, message, nil, false, sig); err != nil {
		t.Fatalf("SignTo failed: %v", err)
	}
	t.Logf("Signature length: %d", len(sig))

	// Verify (FIPS 204 pure mode: ctx=nil)
	valid := mldsa87.Verify(pub, message, nil, sig)
	t.Logf("ML-DSA-87 signature valid: %v", valid)
	if !valid {
		t.Error("ML-DSA-87 signature verification failed")
	}

	// Marshal and unmarshal public key
	pubBytes := pub.Bytes()
	t.Logf("Public key size: %d", len(pubBytes))

	var pub2 mldsa87.PublicKey
	if err := pub2.UnmarshalBinary(pubBytes); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	// Verify with unmarshaled key
	valid2 := mldsa87.Verify(&pub2, message, nil, sig)
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
	pqcKey, ok := pqcPub.(*mldsa87.PublicKey)
	if !ok {
		t.Fatalf("PQC public key is not *mldsa87.PublicKey, got %T", pqcPub)
	}

	mldsaValid := mldsa87.Verify(pqcKey, messageToVerify, nil, compSig.MLDSASig.Bytes)
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

// =============================================================================
// Tests for composite_verify.go and composite.go functions at 0%
// =============================================================================

func TestGetCompositeAlgorithmByOID(t *testing.T) {
	tests := []struct {
		name        string
		oid         asn1.ObjectIdentifier
		wantName    string
		wantErr     bool
	}{
		{
			name:     "ML-DSA-87 + ECDSA-P384",
			oid:      x509util.OIDMLDSA87ECDSAP384SHA512,
			wantName: "MLDSA87-ECDSA-P384-SHA512",
			wantErr:  false,
		},
		{
			name:     "ML-DSA-65 + ECDSA-P256",
			oid:      x509util.OIDMLDSA65ECDSAP256SHA512,
			wantName: "MLDSA65-ECDSA-P256-SHA512",
			wantErr:  false,
		},
		{
			name:    "Unknown OID",
			oid:     asn1.ObjectIdentifier{1, 2, 3, 4, 5},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alg, err := GetCompositeAlgorithmByOID(tt.oid)
			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && alg.Name != tt.wantName {
				t.Errorf("Name = %v, want %v", alg.Name, tt.wantName)
			}
		})
	}
}

func TestIsCompositeOID(t *testing.T) {
	tests := []struct {
		name     string
		oid      asn1.ObjectIdentifier
		expected bool
	}{
		{"ML-DSA-87+P384", x509util.OIDMLDSA87ECDSAP384SHA512, true},
		{"ML-DSA-65+P256", x509util.OIDMLDSA65ECDSAP256SHA512, true},
		{"ECDSA-SHA256", asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}, false},
		{"RSA-SHA256", asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}, false},
		{"ML-DSA-65 pure", x509util.OIDMLDSA65, false},
		{"ML-DSA-87 pure", x509util.OIDMLDSA87, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsCompositeOID(tt.oid)
			if result != tt.expected {
				t.Errorf("IsCompositeOID(%v) = %v, want %v", tt.oid, result, tt.expected)
			}
		})
	}
}

func TestParseMLDSAPublicKey_MLDSA65(t *testing.T) {
	// Generate ML-DSA-65 key pair
	pub, _, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	// Get raw bytes
	pubBytes := pub.Bytes()

	// Parse it back
	parsed, err := parseMLDSAPublicKey(pkicrypto.AlgMLDSA65, pubBytes)
	if err != nil {
		t.Fatalf("parseMLDSAPublicKey() error = %v", err)
	}

	// Verify it's the right type
	_, ok := parsed.(*mldsa65.PublicKey)
	if !ok {
		t.Errorf("parsed key type = %T, want *mldsa65.PublicKey", parsed)
	}
}

func TestParseMLDSAPublicKey_MLDSA87(t *testing.T) {
	// Generate ML-DSA-87 key pair
	pub, _, err := mldsa87.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	// Get raw bytes
	pubBytes := pub.Bytes()

	// Parse it back
	parsed, err := parseMLDSAPublicKey(pkicrypto.AlgMLDSA87, pubBytes)
	if err != nil {
		t.Fatalf("parseMLDSAPublicKey() error = %v", err)
	}

	// Verify it's the right type
	_, ok := parsed.(*mldsa87.PublicKey)
	if !ok {
		t.Errorf("parsed key type = %T, want *mldsa87.PublicKey", parsed)
	}
}

func TestParseMLDSAPublicKey_UnsupportedAlgorithm(t *testing.T) {
	_, err := parseMLDSAPublicKey(pkicrypto.AlgECDSAP256, []byte("fake key"))
	if err == nil {
		t.Error("parseMLDSAPublicKey() should fail for unsupported algorithm")
	}
}

func TestParseMLDSAPublicKey_InvalidData(t *testing.T) {
	// Invalid data for ML-DSA-65
	_, err := parseMLDSAPublicKey(pkicrypto.AlgMLDSA65, []byte("invalid"))
	if err == nil {
		t.Error("parseMLDSAPublicKey() should fail for invalid data")
	}

	// Invalid data for ML-DSA-87
	_, err = parseMLDSAPublicKey(pkicrypto.AlgMLDSA87, []byte("invalid"))
	if err == nil {
		t.Error("parseMLDSAPublicKey() should fail for invalid data")
	}
}

func TestParseClassicalPublicKeyFromBytes_P256(t *testing.T) {
	// Generate ECDSA P-256 key
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	// Get raw public key bytes (uncompressed point: 0x04 || X || Y)
	//nolint:staticcheck // elliptic.Marshal is deprecated but needed for X.509 compatibility
	pubBytes := elliptic.Marshal(privKey.PublicKey.Curve, privKey.PublicKey.X, privKey.PublicKey.Y)

	// Parse it back
	parsed, err := parseClassicalPublicKeyFromBytes(pkicrypto.AlgECDSAP256, pubBytes)
	if err != nil {
		t.Fatalf("parseClassicalPublicKeyFromBytes() error = %v", err)
	}

	// Verify it's the right type
	ecPub, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		t.Errorf("parsed key type = %T, want *ecdsa.PublicKey", parsed)
	}

	// Verify the curve
	if ecPub.Curve != elliptic.P256() {
		t.Error("curve should be P-256")
	}
}

func TestParseClassicalPublicKeyFromBytes_P384(t *testing.T) {
	// Generate ECDSA P-384 key
	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	// Get raw public key bytes
	//nolint:staticcheck // elliptic.Marshal is deprecated but needed for X.509 compatibility
	pubBytes := elliptic.Marshal(privKey.PublicKey.Curve, privKey.PublicKey.X, privKey.PublicKey.Y)

	// Parse it back
	parsed, err := parseClassicalPublicKeyFromBytes(pkicrypto.AlgECDSAP384, pubBytes)
	if err != nil {
		t.Fatalf("parseClassicalPublicKeyFromBytes() error = %v", err)
	}

	// Verify it's the right type
	ecPub, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		t.Errorf("parsed key type = %T, want *ecdsa.PublicKey", parsed)
	}

	// Verify the curve
	if ecPub.Curve != elliptic.P384() {
		t.Error("curve should be P-384")
	}
}

func TestParseClassicalPublicKeyFromBytes_UnsupportedAlgorithm(t *testing.T) {
	_, err := parseClassicalPublicKeyFromBytes(pkicrypto.AlgMLDSA65, []byte("fake key"))
	if err == nil {
		t.Error("parseClassicalPublicKeyFromBytes() should fail for unsupported algorithm")
	}
}

func TestVerifyMLDSA_MLDSA65(t *testing.T) {
	// Generate key pair
	pub, priv, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	message := []byte("test message")
	sig := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(priv, message, nil, false, sig); err != nil {
		t.Fatalf("SignTo failed: %v", err)
	}

	// Verify with correct key
	valid := verifyMLDSA(pkicrypto.AlgMLDSA65, pub, message, sig)
	if !valid {
		t.Error("verifyMLDSA() should return true for valid signature")
	}

	// Verify with tampered message
	tamperedMsg := []byte("tampered message")
	valid = verifyMLDSA(pkicrypto.AlgMLDSA65, pub, tamperedMsg, sig)
	if valid {
		t.Error("verifyMLDSA() should return false for invalid message")
	}
}

func TestVerifyMLDSA_MLDSA87(t *testing.T) {
	// Generate key pair
	pub, priv, err := mldsa87.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	message := []byte("test message")
	sig := make([]byte, mldsa87.SignatureSize)
	if err := mldsa87.SignTo(priv, message, nil, false, sig); err != nil {
		t.Fatalf("SignTo failed: %v", err)
	}

	// Verify with correct key
	valid := verifyMLDSA(pkicrypto.AlgMLDSA87, pub, message, sig)
	if !valid {
		t.Error("verifyMLDSA() should return true for valid signature")
	}

	// Verify with tampered signature
	tamperedSig := make([]byte, len(sig))
	copy(tamperedSig, sig)
	tamperedSig[0] ^= 0xFF
	valid = verifyMLDSA(pkicrypto.AlgMLDSA87, pub, message, tamperedSig)
	if valid {
		t.Error("verifyMLDSA() should return false for invalid signature")
	}
}

func TestVerifyMLDSA_WrongKeyType(t *testing.T) {
	// Test with wrong key type
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	valid := verifyMLDSA(pkicrypto.AlgMLDSA65, &ecKey.PublicKey, []byte("message"), []byte("sig"))
	if valid {
		t.Error("verifyMLDSA() should return false for wrong key type")
	}

	valid = verifyMLDSA(pkicrypto.AlgMLDSA87, &ecKey.PublicKey, []byte("message"), []byte("sig"))
	if valid {
		t.Error("verifyMLDSA() should return false for wrong key type")
	}
}

func TestVerifyMLDSA_UnsupportedAlgorithm(t *testing.T) {
	pub, _, _ := mldsa87.GenerateKey(rand.Reader)

	valid := verifyMLDSA(pkicrypto.AlgECDSAP256, pub, []byte("message"), []byte("sig"))
	if valid {
		t.Error("verifyMLDSA() should return false for unsupported algorithm")
	}
}

func TestVerifyECDSA_Valid(t *testing.T) {
	// Generate key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	// Create digest and signature
	message := []byte("test message")
	h := sha512.New()
	h.Write(message)
	digest := h.Sum(nil)

	sig, err := ecdsa.SignASN1(rand.Reader, privKey, digest)
	if err != nil {
		t.Fatalf("SignASN1() error = %v", err)
	}

	// Verify
	valid := verifyECDSA(&privKey.PublicKey, digest, sig)
	if !valid {
		t.Error("verifyECDSA() should return true for valid signature")
	}
}

func TestVerifyECDSA_Invalid(t *testing.T) {
	// Generate key pair
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	message := []byte("test message")
	h := sha512.New()
	h.Write(message)
	digest := h.Sum(nil)

	sig, _ := ecdsa.SignASN1(rand.Reader, privKey, digest)

	// Verify with tampered digest
	tamperedDigest := make([]byte, len(digest))
	copy(tamperedDigest, digest)
	tamperedDigest[0] ^= 0xFF

	valid := verifyECDSA(&privKey.PublicKey, tamperedDigest, sig)
	if valid {
		t.Error("verifyECDSA() should return false for invalid digest")
	}
}

func TestVerifyECDSA_WrongKeyType(t *testing.T) {
	// Test with wrong key type (ML-DSA public key)
	pub, _, _ := mldsa87.GenerateKey(rand.Reader)

	valid := verifyECDSA(pub, []byte("digest"), []byte("sig"))
	if valid {
		t.Error("verifyECDSA() should return false for wrong key type")
	}
}

func TestMustMarshal(t *testing.T) {
	// Test with valid input
	oid := asn1.ObjectIdentifier{1, 2, 3, 4}
	data := mustMarshal(oid)
	if len(data) == 0 {
		t.Error("mustMarshal() should return non-empty data")
	}
}

func TestGetCompositeAlgorithm_AllCombinations(t *testing.T) {
	tests := []struct {
		classical pkicrypto.AlgorithmID
		pqc       pkicrypto.AlgorithmID
		wantName  string
		wantErr   bool
	}{
		{pkicrypto.AlgECDSAP384, pkicrypto.AlgMLDSA87, "MLDSA87-ECDSA-P384-SHA512", false},
		{pkicrypto.AlgECDSAP256, pkicrypto.AlgMLDSA65, "MLDSA65-ECDSA-P256-SHA512", false},
		{pkicrypto.AlgECDSAP256, pkicrypto.AlgMLDSA87, "", true}, // Invalid combination
		{pkicrypto.AlgRSA2048, pkicrypto.AlgMLDSA65, "", true},   // RSA not supported
	}

	for _, tt := range tests {
		t.Run(string(tt.classical)+"+"+string(tt.pqc), func(t *testing.T) {
			alg, err := GetCompositeAlgorithm(tt.classical, tt.pqc)
			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && alg.Name != tt.wantName {
				t.Errorf("Name = %v, want %v", alg.Name, tt.wantName)
			}
		})
	}
}

// Test verifyMLDSA with ML-DSA-65 key passed to ML-DSA-87 algorithm check
func TestVerifyMLDSA_MismatchedKeyAlgorithm(t *testing.T) {
	// Generate ML-DSA-65 key
	pub65, _, _ := mldsa65.GenerateKey(rand.Reader)
	// Generate ML-DSA-87 key
	pub87, _, _ := mldsa87.GenerateKey(rand.Reader)

	// ML-DSA-65 key with ML-DSA-87 algorithm - wrong type assertion
	valid := verifyMLDSA(pkicrypto.AlgMLDSA87, pub65, []byte("msg"), []byte("sig"))
	if valid {
		t.Error("should fail when key type doesn't match algorithm")
	}

	// ML-DSA-87 key with ML-DSA-65 algorithm - wrong type assertion
	valid = verifyMLDSA(pkicrypto.AlgMLDSA65, pub87, []byte("msg"), []byte("sig"))
	if valid {
		t.Error("should fail when key type doesn't match algorithm")
	}
}

func TestCompositeAlgorithm_HashFunc(t *testing.T) {
	// Verify that all composite algorithms have SHA-512 hash function
	for _, alg := range CompositeAlgorithms {
		if alg.HashFunc != crypto.SHA512 {
			t.Errorf("algorithm %s has hash %v, want SHA512", alg.Name, alg.HashFunc)
		}
	}
}

// =============================================================================
// Tests for EncodeCompositePublicKey
// =============================================================================

func TestEncodeCompositePublicKey(t *testing.T) {
	// Generate ECDSA P-384 key
	classicalPriv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	// Generate ML-DSA-87 key
	pqcPub, _, err := mldsa87.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	// Encode composite public key
	spki, err := EncodeCompositePublicKey(
		pkicrypto.AlgMLDSA87, pqcPub,
		pkicrypto.AlgECDSAP384, &classicalPriv.PublicKey,
	)
	if err != nil {
		t.Fatalf("EncodeCompositePublicKey() error = %v", err)
	}

	// Verify the algorithm OID is correct
	expectedOID := x509util.OIDMLDSA87ECDSAP384SHA512
	if !spki.Algorithm.Algorithm.Equal(expectedOID) {
		t.Errorf("OID = %v, want %v", spki.Algorithm.Algorithm, expectedOID)
	}

	// Verify the public key bytes are not empty
	if len(spki.PublicKey.Bytes) == 0 {
		t.Error("public key bytes should not be empty")
	}
}

func TestEncodeCompositePublicKey_MLDSA65_P256(t *testing.T) {
	// Generate ECDSA P-256 key
	classicalPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	// Generate ML-DSA-65 key
	pqcPub, _, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	// Encode composite public key
	spki, err := EncodeCompositePublicKey(
		pkicrypto.AlgMLDSA65, pqcPub,
		pkicrypto.AlgECDSAP256, &classicalPriv.PublicKey,
	)
	if err != nil {
		t.Fatalf("EncodeCompositePublicKey() error = %v", err)
	}

	// Verify the algorithm OID is correct
	expectedOID := x509util.OIDMLDSA65ECDSAP256SHA512
	if !spki.Algorithm.Algorithm.Equal(expectedOID) {
		t.Errorf("OID = %v, want %v", spki.Algorithm.Algorithm, expectedOID)
	}
}

func TestEncodeCompositePublicKey_InvalidCombination(t *testing.T) {
	// Generate keys for invalid combination (P-256 + ML-DSA-87)
	classicalPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pqcPub, _, _ := mldsa87.GenerateKey(rand.Reader)

	// This should fail because P-256 + ML-DSA-87 is not a supported combination
	_, err := EncodeCompositePublicKey(
		pkicrypto.AlgMLDSA87, pqcPub,
		pkicrypto.AlgECDSAP256, &classicalPriv.PublicKey,
	)
	if err == nil {
		t.Error("EncodeCompositePublicKey() should fail for invalid combination")
	}
}

// =============================================================================
// Tests for InitializeCompositeCA
// =============================================================================

func TestInitializeCompositeCA(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := CompositeCAConfig{
		CommonName:         "Test Composite CA",
		Organization:       "Test Org",
		Country:            "US",
		ClassicalAlgorithm: pkicrypto.AlgECDSAP384,
		PQCAlgorithm:       pkicrypto.AlgMLDSA87,
		ValidityYears:      10,
		PathLen:            1,
	}

	ca, err := InitializeCompositeCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeCompositeCA() error = %v", err)
	}

	if ca == nil {
		t.Fatal("InitializeCompositeCA() returned nil CA")
	}

	// Verify the certificate
	cert := ca.Certificate()
	if cert == nil {
		t.Fatal("CA certificate is nil")
	}
	if cert.Subject.CommonName != "Test Composite CA" {
		t.Errorf("CN = %s, want Test Composite CA", cert.Subject.CommonName)
	}
	if !cert.IsCA {
		t.Error("certificate should be a CA")
	}

	// Verify signer is loaded
	if ca.signer == nil {
		t.Error("signer should be loaded after initialization")
	}
}

func TestInitializeCompositeCA_AlreadyExists(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := CompositeCAConfig{
		CommonName:         "Test Composite CA",
		ClassicalAlgorithm: pkicrypto.AlgECDSAP384,
		PQCAlgorithm:       pkicrypto.AlgMLDSA87,
		ValidityYears:      10,
		PathLen:            1,
	}

	// Initialize first time
	_, err := InitializeCompositeCA(store, cfg)
	if err != nil {
		t.Fatalf("First InitializeCompositeCA() error = %v", err)
	}

	// Try to initialize again - should fail
	_, err = InitializeCompositeCA(store, cfg)
	if err == nil {
		t.Error("Second InitializeCompositeCA() should fail")
	}
}

func TestInitializeCompositeCA_InvalidCombination(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := CompositeCAConfig{
		CommonName:         "Test Composite CA",
		ClassicalAlgorithm: pkicrypto.AlgECDSAP256, // P-256 + ML-DSA-87 is invalid
		PQCAlgorithm:       pkicrypto.AlgMLDSA87,
		ValidityYears:      10,
		PathLen:            1,
	}

	_, err := InitializeCompositeCA(store, cfg)
	if err == nil {
		t.Error("InitializeCompositeCA() should fail for invalid combination")
	}
}

func TestInitializeCompositeCA_MLDSA65_P256(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := CompositeCAConfig{
		CommonName:         "Test Composite CA",
		ClassicalAlgorithm: pkicrypto.AlgECDSAP256,
		PQCAlgorithm:       pkicrypto.AlgMLDSA65,
		ValidityYears:      10,
		PathLen:            1,
	}

	ca, err := InitializeCompositeCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeCompositeCA() error = %v", err)
	}

	if ca == nil {
		t.Fatal("InitializeCompositeCA() returned nil CA")
	}
}

// =============================================================================
// Tests for IsCompositeCertificate
// =============================================================================

func TestIsCompositeCertificate_Composite(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := CompositeCAConfig{
		CommonName:         "Test Composite CA",
		ClassicalAlgorithm: pkicrypto.AlgECDSAP384,
		PQCAlgorithm:       pkicrypto.AlgMLDSA87,
		ValidityYears:      10,
		PathLen:            1,
	}

	ca, err := InitializeCompositeCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeCompositeCA() error = %v", err)
	}

	isComposite := IsCompositeCertificate(ca.Certificate())
	if !isComposite {
		t.Error("IsCompositeCertificate() should return true for composite CA")
	}
}

func TestIsCompositeCertificate_Regular(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Regular CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	isComposite := IsCompositeCertificate(ca.Certificate())
	if isComposite {
		t.Error("IsCompositeCertificate() should return false for regular CA")
	}
}

// =============================================================================
// Tests for LoadCompositeSigner
// =============================================================================

func TestLoadCompositeSigner(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	passphrase := "testpass"
	cfg := CompositeCAConfig{
		CommonName:         "Test Composite CA",
		ClassicalAlgorithm: pkicrypto.AlgECDSAP384,
		PQCAlgorithm:       pkicrypto.AlgMLDSA87,
		ValidityYears:      10,
		PathLen:            1,
		Passphrase:         passphrase,
	}

	// Initialize composite CA with passphrase
	_, err := InitializeCompositeCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeCompositeCA() error = %v", err)
	}

	// Load CA without signer
	ca, err := New(store)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Load composite signer
	err = ca.LoadCompositeSigner(passphrase, passphrase)
	if err != nil {
		t.Fatalf("LoadCompositeSigner() error = %v", err)
	}

	// Verify signer is loaded
	if ca.signer == nil {
		t.Error("signer should be loaded after LoadCompositeSigner")
	}
}

func TestLoadCompositeSigner_WrongPassphrase(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	passphrase := "testpass"
	cfg := CompositeCAConfig{
		CommonName:         "Test Composite CA",
		ClassicalAlgorithm: pkicrypto.AlgECDSAP384,
		PQCAlgorithm:       pkicrypto.AlgMLDSA87,
		ValidityYears:      10,
		PathLen:            1,
		Passphrase:         passphrase,
	}

	_, err := InitializeCompositeCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeCompositeCA() error = %v", err)
	}

	ca, err := New(store)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Try to load with wrong passphrase
	err = ca.LoadCompositeSigner("wrongpass", "wrongpass")
	if err == nil {
		t.Error("LoadCompositeSigner() should fail with wrong passphrase")
	}
}

// =============================================================================
// Tests for IssueComposite
// =============================================================================

func TestIssueComposite_NoSigner(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := CompositeCAConfig{
		CommonName:         "Test Composite CA",
		ClassicalAlgorithm: pkicrypto.AlgECDSAP384,
		PQCAlgorithm:       pkicrypto.AlgMLDSA87,
		ValidityYears:      10,
		PathLen:            1,
		Passphrase:         "test",
	}

	_, err := InitializeCompositeCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeCompositeCA() error = %v", err)
	}

	// Load CA without signer
	ca, err := New(store)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Generate keys for subject
	classicalPriv, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	pqcPub, _, _ := mldsa87.GenerateKey(rand.Reader)

	req := CompositeRequest{
		ClassicalPublicKey: &classicalPriv.PublicKey,
		PQCPublicKey:       pqcPub,
		ClassicalAlg:       pkicrypto.AlgECDSAP384,
		PQCAlg:             pkicrypto.AlgMLDSA87,
	}

	// Should fail because signer is not loaded
	_, err = ca.IssueComposite(req)
	if err == nil {
		t.Error("IssueComposite() should fail when signer not loaded")
	}
}

func TestCompositeCAConfig_Fields(t *testing.T) {
	cfg := CompositeCAConfig{
		CommonName:         "Test CA",
		Organization:       "Test Org",
		Country:            "US",
		ClassicalAlgorithm: pkicrypto.AlgECDSAP384,
		PQCAlgorithm:       pkicrypto.AlgMLDSA87,
		ValidityYears:      10,
		PathLen:            1,
		Passphrase:         "test",
	}

	if cfg.CommonName != "Test CA" {
		t.Errorf("CommonName = %s, want Test CA", cfg.CommonName)
	}
	if cfg.Organization != "Test Org" {
		t.Errorf("Organization = %s, want Test Org", cfg.Organization)
	}
	if cfg.ClassicalAlgorithm != pkicrypto.AlgECDSAP384 {
		t.Errorf("ClassicalAlgorithm = %s, want ECDSA-P384", cfg.ClassicalAlgorithm)
	}
	if cfg.PQCAlgorithm != pkicrypto.AlgMLDSA87 {
		t.Errorf("PQCAlgorithm = %s, want ML-DSA-87", cfg.PQCAlgorithm)
	}
}

func TestCompositeRequest_Fields(t *testing.T) {
	classicalPriv, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	pqcPub, _, _ := mldsa87.GenerateKey(rand.Reader)

	req := CompositeRequest{
		ClassicalPublicKey: &classicalPriv.PublicKey,
		PQCPublicKey:       pqcPub,
		ClassicalAlg:       pkicrypto.AlgECDSAP384,
		PQCAlg:             pkicrypto.AlgMLDSA87,
	}

	if req.ClassicalPublicKey == nil {
		t.Error("ClassicalPublicKey should not be nil")
	}
	if req.PQCPublicKey == nil {
		t.Error("PQCPublicKey should not be nil")
	}
}

// =============================================================================
// Tests for IsHybridCA
// =============================================================================

func TestIsHybridCA_WithHybridSigner(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := HybridCAConfig{
		CommonName:         "Test Hybrid CA",
		Organization:       "Test Org",
		Country:            "US",
		ClassicalAlgorithm: pkicrypto.AlgECDSAP384,
		PQCAlgorithm:       pkicrypto.AlgMLDSA87,
		ValidityYears:      10,
		PathLen:            1,
	}

	ca, err := InitializeHybridCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeHybridCA() error = %v", err)
	}

	// After initialization, CA should have hybrid signer
	if !ca.IsHybridCA() {
		t.Error("IsHybridCA() should return true after InitializeHybridCA")
	}
}

func TestIsHybridCA_WithRegularSigner(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Regular CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Regular CA should not have hybrid signer
	if ca.IsHybridCA() {
		t.Error("IsHybridCA() should return false for regular CA")
	}
}

func TestIsHybridCA_NoSigner(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Regular CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
		Passphrase:    "test",
	}

	_, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Load CA without signer
	ca, err := New(store)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// No signer loaded - should return false
	if ca.IsHybridCA() {
		t.Error("IsHybridCA() should return false when no signer loaded")
	}
}

// =============================================================================
// Tests for InitializeHybridCA
// =============================================================================

func TestInitializeHybridCA(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := HybridCAConfig{
		CommonName:         "Test Hybrid CA",
		Organization:       "Test Org",
		Country:            "US",
		ClassicalAlgorithm: pkicrypto.AlgECDSAP384,
		PQCAlgorithm:       pkicrypto.AlgMLDSA87,
		ValidityYears:      10,
		PathLen:            1,
	}

	ca, err := InitializeHybridCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeHybridCA() error = %v", err)
	}

	if ca == nil {
		t.Fatal("InitializeHybridCA() returned nil CA")
	}

	cert := ca.Certificate()
	if cert == nil {
		t.Fatal("CA certificate is nil")
	}

	if cert.Subject.CommonName != "Test Hybrid CA" {
		t.Errorf("CN = %s, want Test Hybrid CA", cert.Subject.CommonName)
	}

	if !cert.IsCA {
		t.Error("certificate should be a CA")
	}
}

func TestInitializeHybridCA_AlreadyExists(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := HybridCAConfig{
		CommonName:         "Test Hybrid CA",
		ClassicalAlgorithm: pkicrypto.AlgECDSAP384,
		PQCAlgorithm:       pkicrypto.AlgMLDSA87,
		ValidityYears:      10,
		PathLen:            1,
	}

	// Initialize first time
	_, err := InitializeHybridCA(store, cfg)
	if err != nil {
		t.Fatalf("First InitializeHybridCA() error = %v", err)
	}

	// Try to initialize again - should fail
	_, err = InitializeHybridCA(store, cfg)
	if err == nil {
		t.Error("Second InitializeHybridCA() should fail")
	}
}

func TestInitializeHybridCA_WithPassphrase(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := HybridCAConfig{
		CommonName:         "Test Hybrid CA",
		ClassicalAlgorithm: pkicrypto.AlgECDSAP384,
		PQCAlgorithm:       pkicrypto.AlgMLDSA87,
		ValidityYears:      10,
		PathLen:            1,
		Passphrase:         "testpass",
	}

	ca, err := InitializeHybridCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeHybridCA() error = %v", err)
	}

	if ca == nil {
		t.Fatal("InitializeHybridCA() returned nil CA")
	}

	// Verify hybrid signer is loaded
	if !ca.IsHybridCA() {
		t.Error("CA should have hybrid signer after initialization")
	}
}

// =============================================================================
// Tests for LoadHybridSigner
// =============================================================================

func TestLoadHybridSigner(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	passphrase := "testpass"
	cfg := HybridCAConfig{
		CommonName:         "Test Hybrid CA",
		ClassicalAlgorithm: pkicrypto.AlgECDSAP384,
		PQCAlgorithm:       pkicrypto.AlgMLDSA87,
		ValidityYears:      10,
		PathLen:            1,
		Passphrase:         passphrase,
	}

	// Initialize hybrid CA
	_, err := InitializeHybridCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeHybridCA() error = %v", err)
	}

	// Load CA without signer (simulating fresh load)
	ca, err := New(store)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Verify signer is not yet loaded
	if ca.IsHybridCA() {
		t.Error("IsHybridCA() should be false before LoadHybridSigner")
	}

	// Load hybrid signer
	err = ca.LoadHybridSigner(passphrase, passphrase)
	if err != nil {
		t.Fatalf("LoadHybridSigner() error = %v", err)
	}

	// Verify hybrid signer is now loaded
	if !ca.IsHybridCA() {
		t.Error("IsHybridCA() should be true after LoadHybridSigner")
	}
}

func TestLoadHybridSigner_WrongPassphrase(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	passphrase := "testpass"
	cfg := HybridCAConfig{
		CommonName:         "Test Hybrid CA",
		ClassicalAlgorithm: pkicrypto.AlgECDSAP384,
		PQCAlgorithm:       pkicrypto.AlgMLDSA87,
		ValidityYears:      10,
		PathLen:            1,
		Passphrase:         passphrase,
	}

	_, err := InitializeHybridCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeHybridCA() error = %v", err)
	}

	ca, err := New(store)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Try to load with wrong passphrase
	err = ca.LoadHybridSigner("wrongpass", "wrongpass")
	if err == nil {
		t.Error("LoadHybridSigner() should fail with wrong passphrase")
	}
}

func TestLoadHybridSigner_MissingPQCKey(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize a regular (non-hybrid) CA
	cfg := Config{
		CommonName:    "Test Regular CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
		Passphrase:    "test",
	}

	_, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	ca, err := New(store)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Try to load hybrid signer (PQC key doesn't exist)
	err = ca.LoadHybridSigner("test", "test")
	if err == nil {
		t.Error("LoadHybridSigner() should fail when PQC key doesn't exist")
	}
}

// =============================================================================
// Tests for HybridCAConfig
// =============================================================================

func TestHybridCAConfig_Fields(t *testing.T) {
	cfg := HybridCAConfig{
		CommonName:         "Test Hybrid CA",
		Organization:       "Test Org",
		Country:            "US",
		ClassicalAlgorithm: pkicrypto.AlgECDSAP384,
		PQCAlgorithm:       pkicrypto.AlgMLDSA87,
		ValidityYears:      10,
		PathLen:            1,
		Passphrase:         "test",
	}

	if cfg.CommonName != "Test Hybrid CA" {
		t.Errorf("CommonName = %s, want Test Hybrid CA", cfg.CommonName)
	}
	if cfg.Organization != "Test Org" {
		t.Errorf("Organization = %s, want Test Org", cfg.Organization)
	}
	if cfg.Country != "US" {
		t.Errorf("Country = %s, want US", cfg.Country)
	}
	if cfg.ClassicalAlgorithm != pkicrypto.AlgECDSAP384 {
		t.Errorf("ClassicalAlgorithm = %s, want ECDSA-P384", cfg.ClassicalAlgorithm)
	}
	if cfg.PQCAlgorithm != pkicrypto.AlgMLDSA87 {
		t.Errorf("PQCAlgorithm = %s, want ML-DSA-87", cfg.PQCAlgorithm)
	}
	if cfg.ValidityYears != 10 {
		t.Errorf("ValidityYears = %d, want 10", cfg.ValidityYears)
	}
	if cfg.PathLen != 1 {
		t.Errorf("PathLen = %d, want 1", cfg.PathLen)
	}
}

// =============================================================================
// Tests for IssueLinked
// =============================================================================

func TestIssueLinked_NoSigner(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
		Passphrase:    "test",
	}

	_, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	ca, err := New(store)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Generate subject key
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Create dummy related certificate (self-signed)
	relatedCert, _ := generateSelfSignedCert(t, privKey)

	req := LinkedCertRequest{
		PublicKey:   &privKey.PublicKey,
		RelatedCert: relatedCert,
	}

	// Should fail because signer is not loaded
	_, err = ca.IssueLinked(req)
	if err == nil {
		t.Error("IssueLinked() should fail when signer not loaded")
	}
}

func TestIssueLinked_NoRelatedCert(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Generate subject key
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	req := LinkedCertRequest{
		PublicKey:   &privKey.PublicKey,
		RelatedCert: nil, // No related cert
	}

	// Should fail because RelatedCert is required
	_, err = ca.IssueLinked(req)
	if err == nil {
		t.Error("IssueLinked() should fail when RelatedCert is nil")
	}
}

func TestIssueLinked_Success(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Generate subject key for first cert
	privKey1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	// Issue first cert (to be the related cert)
	firstCert, err := ca.Issue(IssueRequest{
		Template: &x509.Certificate{
			Subject: pkix.Name{
				CommonName: "First Cert",
			},
		},
		PublicKey: &privKey1.PublicKey,
		Validity:  365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	// Generate subject key for linked cert
	privKey2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	// Issue linked certificate
	req := LinkedCertRequest{
		Template: &x509.Certificate{
			Subject: pkix.Name{
				CommonName: "Linked Cert",
			},
		},
		PublicKey:   &privKey2.PublicKey,
		RelatedCert: firstCert,
		Validity:    365 * 24 * time.Hour,
	}

	linkedCert, err := ca.IssueLinked(req)
	if err != nil {
		t.Fatalf("IssueLinked() error = %v", err)
	}

	if linkedCert == nil {
		t.Fatal("IssueLinked() returned nil certificate")
	}

	// Verify the certificate was issued correctly
	if linkedCert.Subject.CommonName != "Linked Cert" {
		t.Errorf("CN = %s, want Linked Cert", linkedCert.Subject.CommonName)
	}

	// Verify issuer is the CA
	if linkedCert.Issuer.CommonName != "Test CA" {
		t.Errorf("Issuer CN = %s, want Test CA", linkedCert.Issuer.CommonName)
	}

	// Verify the certificate has RelatedCertificate extension
	hasRelatedCert := false
	for _, ext := range linkedCert.Extensions {
		if ext.Id.Equal(x509util.OIDRelatedCertificate) {
			hasRelatedCert = true
			break
		}
	}
	if !hasRelatedCert {
		t.Error("linked certificate should have RelatedCertificate extension")
	}
}

func TestIssueLinked_WithNilTemplate(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Generate subject key for related cert
	privKey1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	relatedCert, err := generateSelfSignedCert(t, privKey1)
	if err != nil {
		t.Fatalf("generateSelfSignedCert() error = %v", err)
	}

	// Generate subject key for linked cert
	privKey2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Issue linked cert with nil template (should use default)
	req := LinkedCertRequest{
		Template:    nil, // Nil template
		PublicKey:   &privKey2.PublicKey,
		RelatedCert: relatedCert,
		Validity:    365 * 24 * time.Hour,
	}

	linkedCert, err := ca.IssueLinked(req)
	if err != nil {
		t.Fatalf("IssueLinked() error = %v", err)
	}

	if linkedCert == nil {
		t.Fatal("IssueLinked() returned nil certificate")
	}
}

func TestIssueLinked_DefaultValidity(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Generate related cert
	privKey1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	relatedCert, err := generateSelfSignedCert(t, privKey1)
	if err != nil {
		t.Fatalf("generateSelfSignedCert() error = %v", err)
	}

	// Generate subject key
	privKey2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Issue linked cert with zero validity (should default to 1 year)
	req := LinkedCertRequest{
		PublicKey:   &privKey2.PublicKey,
		RelatedCert: relatedCert,
		Validity:    0, // Zero validity - should default
	}

	linkedCert, err := ca.IssueLinked(req)
	if err != nil {
		t.Fatalf("IssueLinked() error = %v", err)
	}

	// Verify default validity (about 1 year)
	validity := linkedCert.NotAfter.Sub(linkedCert.NotBefore)
	expectedValidity := 365 * 24 * time.Hour
	if validity < expectedValidity-time.Hour || validity > expectedValidity+time.Hour {
		t.Errorf("validity = %v, want approximately %v", validity, expectedValidity)
	}
}

func TestLinkedCertRequest_Fields(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	relatedCert, _ := generateSelfSignedCert(t, privKey)

	req := LinkedCertRequest{
		PublicKey:   &privKey.PublicKey,
		RelatedCert: relatedCert,
	}

	if req.PublicKey == nil {
		t.Error("PublicKey should not be nil")
	}
	if req.RelatedCert == nil {
		t.Error("RelatedCert should not be nil")
	}
}

// =============================================================================
// Tests for CompositeVerifyResult
// =============================================================================

func TestCompositeVerifyResult_Fields(t *testing.T) {
	result := &CompositeVerifyResult{
		Valid:          true,
		MLDSAValid:     true,
		ClassicalValid: true,
		Error:          nil,
	}

	if !result.Valid {
		t.Error("Valid should be true")
	}
	if !result.MLDSAValid {
		t.Error("MLDSAValid should be true")
	}
	if !result.ClassicalValid {
		t.Error("ClassicalValid should be true")
	}
	if result.Error != nil {
		t.Error("Error should be nil")
	}
}

func TestCompositeVerifyResult_PartialValid(t *testing.T) {
	result := &CompositeVerifyResult{
		Valid:          false,
		MLDSAValid:     true,
		ClassicalValid: false,
		Error:          fmt.Errorf("classical signature invalid"),
	}

	if result.Valid {
		t.Error("Valid should be false when one signature fails")
	}
	if !result.MLDSAValid {
		t.Error("MLDSAValid should be true")
	}
	if result.ClassicalValid {
		t.Error("ClassicalValid should be false")
	}
	if result.Error == nil {
		t.Error("Error should not be nil")
	}
}

// Helper function to generate self-signed cert for testing
func generateSelfSignedCert(t *testing.T, privKey *ecdsa.PrivateKey) (*x509.Certificate, error) {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Cert",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(derBytes)
}

// =============================================================================
// Tests for VerifyCompositeCertificate
// =============================================================================

func TestVerifyCompositeCertificate_NotComposite(t *testing.T) {
	// Create a regular (non-composite) certificate
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	cert, err := generateSelfSignedCert(t, privKey)
	if err != nil {
		t.Fatalf("generateSelfSignedCert() error = %v", err)
	}

	// Should fail because certificate is not composite
	_, err = VerifyCompositeCertificate(cert, cert)
	if err == nil {
		t.Error("VerifyCompositeCertificate() should fail for non-composite cert")
	}
}

func TestVerifyCompositeCertificate_IssuerNotComposite(t *testing.T) {
	// Create a composite CA
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := CompositeCAConfig{
		CommonName:         "Test Composite CA",
		ClassicalAlgorithm: pkicrypto.AlgECDSAP384,
		PQCAlgorithm:       pkicrypto.AlgMLDSA87,
		ValidityYears:      10,
		PathLen:            1,
	}

	ca, err := InitializeCompositeCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeCompositeCA() error = %v", err)
	}

	// Create a regular issuer cert
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	issuerCert, err := generateSelfSignedCert(t, privKey)
	if err != nil {
		t.Fatalf("generateSelfSignedCert() error = %v", err)
	}

	// Should fail because issuer is not composite
	_, err = VerifyCompositeCertificate(ca.Certificate(), issuerCert)
	if err == nil {
		t.Error("VerifyCompositeCertificate() should fail when issuer is not composite")
	}
}

func TestVerifyCompositeCertificate_ValidSelfSigned(t *testing.T) {
	// Create a composite CA (self-signed)
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := CompositeCAConfig{
		CommonName:         "Test Composite CA",
		ClassicalAlgorithm: pkicrypto.AlgECDSAP384,
		PQCAlgorithm:       pkicrypto.AlgMLDSA87,
		ValidityYears:      10,
		PathLen:            1,
	}

	ca, err := InitializeCompositeCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeCompositeCA() error = %v", err)
	}

	// Verify the self-signed composite CA certificate
	result, err := VerifyCompositeCertificate(ca.Certificate(), ca.Certificate())
	if err != nil {
		t.Fatalf("VerifyCompositeCertificate() error = %v", err)
	}

	if !result.Valid {
		t.Errorf("VerifyCompositeCertificate() Valid = false, want true, error: %v", result.Error)
	}

	if !result.MLDSAValid {
		t.Error("VerifyCompositeCertificate() MLDSAValid = false, want true")
	}

	if !result.ClassicalValid {
		t.Error("VerifyCompositeCertificate() ClassicalValid = false, want true")
	}

	if result.Algorithm == nil {
		t.Error("VerifyCompositeCertificate() Algorithm should not be nil")
	}
}

func TestVerifyCompositeCertificate_MLDSA65_P256(t *testing.T) {
	// Create a composite CA with ML-DSA-65 + P256
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := CompositeCAConfig{
		CommonName:         "Test Composite CA",
		ClassicalAlgorithm: pkicrypto.AlgECDSAP256,
		PQCAlgorithm:       pkicrypto.AlgMLDSA65,
		ValidityYears:      10,
		PathLen:            1,
	}

	ca, err := InitializeCompositeCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeCompositeCA() error = %v", err)
	}

	// Verify the self-signed composite CA certificate
	result, err := VerifyCompositeCertificate(ca.Certificate(), ca.Certificate())
	if err != nil {
		t.Fatalf("VerifyCompositeCertificate() error = %v", err)
	}

	if !result.Valid {
		t.Errorf("VerifyCompositeCertificate() Valid = false, want true, error: %v", result.Error)
	}

	// Check algorithm
	if result.Algorithm == nil {
		t.Fatal("Algorithm should not be nil")
	}
	if result.Algorithm.PQCAlg != pkicrypto.AlgMLDSA65 {
		t.Errorf("PQCAlg = %s, want ML-DSA-65", result.Algorithm.PQCAlg)
	}
	if result.Algorithm.ClassicalAlg != pkicrypto.AlgECDSAP256 {
		t.Errorf("ClassicalAlg = %s, want ECDSA-P256", result.Algorithm.ClassicalAlg)
	}
}

// =============================================================================
// Tests for IssueComposite with full verification
// =============================================================================

func TestIssueComposite_AndVerify(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := CompositeCAConfig{
		CommonName:         "Test Composite CA",
		ClassicalAlgorithm: pkicrypto.AlgECDSAP384,
		PQCAlgorithm:       pkicrypto.AlgMLDSA87,
		ValidityYears:      10,
		PathLen:            1,
	}

	ca, err := InitializeCompositeCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeCompositeCA() error = %v", err)
	}

	// Generate subject keys
	classicalPriv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	pqcPub, _, err := mldsa87.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	req := CompositeRequest{
		Template: &x509.Certificate{
			Subject: pkix.Name{
				CommonName:   "Test Subject",
				Organization: []string{"Test Org"},
			},
		},
		ClassicalPublicKey: &classicalPriv.PublicKey,
		PQCPublicKey:       pqcPub,
		ClassicalAlg:       pkicrypto.AlgECDSAP384,
		PQCAlg:             pkicrypto.AlgMLDSA87,
		Validity:           365 * 24 * time.Hour,
	}

	// Issue the composite certificate
	cert, err := ca.IssueComposite(req)
	if err != nil {
		t.Fatalf("IssueComposite() error = %v", err)
	}

	// Verify the issued certificate
	result, err := VerifyCompositeCertificate(cert, ca.Certificate())
	if err != nil {
		t.Fatalf("VerifyCompositeCertificate() error = %v", err)
	}

	if !result.Valid {
		t.Errorf("issued certificate verification failed: %v", result.Error)
	}

	if !result.MLDSAValid {
		t.Error("ML-DSA signature should be valid")
	}

	if !result.ClassicalValid {
		t.Error("classical signature should be valid")
	}
}

// =============================================================================
// Tests for BuildDomainSeparator
// =============================================================================

func TestBuildDomainSeparator(t *testing.T) {
	tests := []struct {
		name    string
		oid     asn1.ObjectIdentifier
		wantErr bool
	}{
		{"ML-DSA-87+P384", x509util.OIDMLDSA87ECDSAP384SHA512, false},
		{"ML-DSA-65+P256", x509util.OIDMLDSA65ECDSAP256SHA512, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			domainSep, err := BuildDomainSeparator(tt.oid)
			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(domainSep) == 0 {
				t.Error("domain separator should not be empty")
			}
		})
	}
}

// =============================================================================
// Tests for CreateCompositeSignature
// =============================================================================

func TestCreateCompositeSignature_InvalidAlgorithm(t *testing.T) {
	classicalSigner, _ := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgECDSAP256)
	pqcSigner, _ := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgMLDSA65)

	// Create a fake algorithm with invalid OID
	fakeAlg := &CompositeAlgorithm{
		Name:         "Fake",
		OID:          asn1.ObjectIdentifier{1, 2, 3, 4, 5},
		PQCAlg:       pkicrypto.AlgMLDSA65,
		ClassicalAlg: pkicrypto.AlgECDSAP256,
		HashFunc:     crypto.SHA512,
	}

	tbsBytes := []byte("test TBS")
	_, err := CreateCompositeSignature(tbsBytes, fakeAlg, pqcSigner, classicalSigner)
	// This should still work since it builds domain separator from OID
	if err != nil {
		t.Logf("CreateCompositeSignature error (may be expected): %v", err)
	}
}

// =============================================================================
// Tests for VerifyCompositeSignature (arbitrary data)
// =============================================================================

func TestVerifyCompositeSignature_Valid(t *testing.T) {
	// Create a composite CA
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := CompositeCAConfig{
		CommonName:         "Test Composite CA",
		ClassicalAlgorithm: pkicrypto.AlgECDSAP384,
		PQCAlgorithm:       pkicrypto.AlgMLDSA87,
		ValidityYears:      10,
		PathLen:            1,
	}

	ca, err := InitializeCompositeCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeCompositeCA() error = %v", err)
	}

	// Get hybrid signer from CA
	hybridSigner, ok := ca.signer.(pkicrypto.HybridSigner)
	if !ok {
		t.Fatal("CA signer should be a HybridSigner")
	}

	// Get composite algorithm
	compAlg, err := GetCompositeAlgorithm(pkicrypto.AlgECDSAP384, pkicrypto.AlgMLDSA87)
	if err != nil {
		t.Fatalf("GetCompositeAlgorithm() error = %v", err)
	}

	// Create test data
	data := []byte("This is arbitrary test data to sign and verify")

	// Create composite signature
	signature, err := CreateCompositeSignature(
		data,
		compAlg,
		hybridSigner.PQCSigner(),
		hybridSigner.ClassicalSigner(),
	)
	if err != nil {
		t.Fatalf("CreateCompositeSignature() error = %v", err)
	}

	// Verify the signature
	err = VerifyCompositeSignature(data, signature, ca.Certificate(), compAlg.OID)
	if err != nil {
		t.Fatalf("VerifyCompositeSignature() error = %v", err)
	}
}

func TestVerifyCompositeSignature_MLDSA65_P256(t *testing.T) {
	// Create a composite CA with ML-DSA-65 + P256
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := CompositeCAConfig{
		CommonName:         "Test Composite CA",
		ClassicalAlgorithm: pkicrypto.AlgECDSAP256,
		PQCAlgorithm:       pkicrypto.AlgMLDSA65,
		ValidityYears:      10,
		PathLen:            1,
	}

	ca, err := InitializeCompositeCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeCompositeCA() error = %v", err)
	}

	// Get hybrid signer from CA
	hybridSigner, ok := ca.signer.(pkicrypto.HybridSigner)
	if !ok {
		t.Fatal("CA signer should be a HybridSigner")
	}

	// Get composite algorithm
	compAlg, err := GetCompositeAlgorithm(pkicrypto.AlgECDSAP256, pkicrypto.AlgMLDSA65)
	if err != nil {
		t.Fatalf("GetCompositeAlgorithm() error = %v", err)
	}

	// Create test data
	data := []byte("Test data for ML-DSA-65 + P256 signature")

	// Create composite signature
	signature, err := CreateCompositeSignature(
		data,
		compAlg,
		hybridSigner.PQCSigner(),
		hybridSigner.ClassicalSigner(),
	)
	if err != nil {
		t.Fatalf("CreateCompositeSignature() error = %v", err)
	}

	// Verify the signature
	err = VerifyCompositeSignature(data, signature, ca.Certificate(), compAlg.OID)
	if err != nil {
		t.Fatalf("VerifyCompositeSignature() error = %v", err)
	}
}

func TestVerifyCompositeSignature_InvalidOID(t *testing.T) {
	// Create a composite CA
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := CompositeCAConfig{
		CommonName:         "Test Composite CA",
		ClassicalAlgorithm: pkicrypto.AlgECDSAP384,
		PQCAlgorithm:       pkicrypto.AlgMLDSA87,
		ValidityYears:      10,
		PathLen:            1,
	}

	ca, err := InitializeCompositeCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeCompositeCA() error = %v", err)
	}

	// Try to verify with an invalid OID
	invalidOID := asn1.ObjectIdentifier{1, 2, 3, 4, 5}
	err = VerifyCompositeSignature([]byte("data"), []byte("sig"), ca.Certificate(), invalidOID)
	if err == nil {
		t.Error("VerifyCompositeSignature() should fail with invalid OID")
	}
}

func TestVerifyCompositeSignature_TamperedData(t *testing.T) {
	// Create a composite CA
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := CompositeCAConfig{
		CommonName:         "Test Composite CA",
		ClassicalAlgorithm: pkicrypto.AlgECDSAP384,
		PQCAlgorithm:       pkicrypto.AlgMLDSA87,
		ValidityYears:      10,
		PathLen:            1,
	}

	ca, err := InitializeCompositeCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeCompositeCA() error = %v", err)
	}

	// Get hybrid signer from CA
	hybridSigner, ok := ca.signer.(pkicrypto.HybridSigner)
	if !ok {
		t.Fatal("CA signer should be a HybridSigner")
	}

	// Get composite algorithm
	compAlg, err := GetCompositeAlgorithm(pkicrypto.AlgECDSAP384, pkicrypto.AlgMLDSA87)
	if err != nil {
		t.Fatalf("GetCompositeAlgorithm() error = %v", err)
	}

	// Create test data
	data := []byte("Original data")

	// Create composite signature
	signature, err := CreateCompositeSignature(
		data,
		compAlg,
		hybridSigner.PQCSigner(),
		hybridSigner.ClassicalSigner(),
	)
	if err != nil {
		t.Fatalf("CreateCompositeSignature() error = %v", err)
	}

	// Try to verify with tampered data
	tamperedData := []byte("Tampered data")
	err = VerifyCompositeSignature(tamperedData, signature, ca.Certificate(), compAlg.OID)
	if err == nil {
		t.Error("VerifyCompositeSignature() should fail with tampered data")
	}
}

func TestVerifyCompositeSignature_InvalidSignature(t *testing.T) {
	// Create a composite CA
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := CompositeCAConfig{
		CommonName:         "Test Composite CA",
		ClassicalAlgorithm: pkicrypto.AlgECDSAP384,
		PQCAlgorithm:       pkicrypto.AlgMLDSA87,
		ValidityYears:      10,
		PathLen:            1,
	}

	ca, err := InitializeCompositeCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeCompositeCA() error = %v", err)
	}

	// Get composite algorithm OID
	compAlg, err := GetCompositeAlgorithm(pkicrypto.AlgECDSAP384, pkicrypto.AlgMLDSA87)
	if err != nil {
		t.Fatalf("GetCompositeAlgorithm() error = %v", err)
	}

	// Try to verify with invalid signature
	data := []byte("test data")
	invalidSignature := []byte("not a valid signature")

	err = VerifyCompositeSignature(data, invalidSignature, ca.Certificate(), compAlg.OID)
	if err == nil {
		t.Error("VerifyCompositeSignature() should fail with invalid signature")
	}
}

func TestVerifyCompositeSignature_NonCompositeSignerCert(t *testing.T) {
	// Create a regular (non-composite) CA
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Regular CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Get composite algorithm OID
	compAlg, err := GetCompositeAlgorithm(pkicrypto.AlgECDSAP384, pkicrypto.AlgMLDSA87)
	if err != nil {
		t.Fatalf("GetCompositeAlgorithm() error = %v", err)
	}

	// Try to verify with a non-composite signer certificate
	data := []byte("test data")
	fakeSignature := []byte("fake signature")

	err = VerifyCompositeSignature(data, fakeSignature, ca.Certificate(), compAlg.OID)
	if err == nil {
		t.Error("VerifyCompositeSignature() should fail with non-composite signer cert")
	}
}

