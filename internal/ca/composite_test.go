package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/cloudflare/circl/sign/dilithium/mode5"
	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
	"github.com/remiblancher/post-quantum-pki/internal/x509util"
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
	pub, _, err := mode3.GenerateKey(rand.Reader)
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
	_, ok := parsed.(*mode3.PublicKey)
	if !ok {
		t.Errorf("parsed key type = %T, want *mode3.PublicKey", parsed)
	}
}

func TestParseMLDSAPublicKey_MLDSA87(t *testing.T) {
	// Generate ML-DSA-87 key pair
	pub, _, err := mode5.GenerateKey(rand.Reader)
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
	_, ok := parsed.(*mode5.PublicKey)
	if !ok {
		t.Errorf("parsed key type = %T, want *mode5.PublicKey", parsed)
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
	pub, priv, err := mode3.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	message := []byte("test message")
	sig := make([]byte, mode3.SignatureSize)
	mode3.SignTo(priv, message, sig)

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
	pub, priv, err := mode5.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	message := []byte("test message")
	sig := make([]byte, mode5.SignatureSize)
	mode5.SignTo(priv, message, sig)

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
	pub, _, _ := mode5.GenerateKey(rand.Reader)

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
	pub, _, _ := mode5.GenerateKey(rand.Reader)

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
	pub65, _, _ := mode3.GenerateKey(rand.Reader)
	// Generate ML-DSA-87 key
	pub87, _, _ := mode5.GenerateKey(rand.Reader)

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

