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
	pqcPub, _, err := mode5.GenerateKey(rand.Reader)
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
	pqcPub, _, err := mode3.GenerateKey(rand.Reader)
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
	pqcPub, _, _ := mode5.GenerateKey(rand.Reader)

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
	store := NewStore(tmpDir)

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
	store := NewStore(tmpDir)

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
	store := NewStore(tmpDir)

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
	store := NewStore(tmpDir)

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
	store := NewStore(tmpDir)

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
	store := NewStore(tmpDir)

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
	store := NewStore(tmpDir)

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
	store := NewStore(tmpDir)

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
	store := NewStore(tmpDir)

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
	pqcPub, _, _ := mode5.GenerateKey(rand.Reader)

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
	pqcPub, _, _ := mode5.GenerateKey(rand.Reader)

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

