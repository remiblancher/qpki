package x509util

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/remiblancher/pki/internal/crypto"
)

// =============================================================================
// Hybrid Extension Tests (Legacy)
// =============================================================================

func TestEncodeHybridExtension_Valid(t *testing.T) {
	pubKey := make([]byte, 1952) // ML-DSA-65 public key size
	rand.Read(pubKey)

	ext, err := EncodeHybridExtension(crypto.AlgMLDSA65, pubKey, HybridPolicyInformational)
	if err != nil {
		t.Fatalf("EncodeHybridExtension failed: %v", err)
	}

	if ext.Critical {
		t.Error("extension should not be critical")
	}
	if !OIDEqual(ext.Id, OIDHybridPublicKeyExtension) {
		t.Error("wrong extension OID")
	}
}

func TestEncodeHybridExtension_NonPQCAlgorithm(t *testing.T) {
	pubKey := make([]byte, 100)

	_, err := EncodeHybridExtension(crypto.AlgECDSAP256, pubKey, HybridPolicyInformational)
	if err == nil {
		t.Error("expected error for non-PQC algorithm")
	}
}

func TestDecodeHybridExtension(t *testing.T) {
	originalPubKey := make([]byte, 1952)
	rand.Read(originalPubKey)
	originalPolicy := HybridPolicyMustVerifyBoth

	ext, err := EncodeHybridExtension(crypto.AlgMLDSA65, originalPubKey, originalPolicy)
	if err != nil {
		t.Fatalf("EncodeHybridExtension failed: %v", err)
	}

	alg, pubKey, policy, err := DecodeHybridExtension(ext)
	if err != nil {
		t.Fatalf("DecodeHybridExtension failed: %v", err)
	}

	if alg != crypto.AlgMLDSA65 {
		t.Errorf("algorithm mismatch: got %s, want %s", alg, crypto.AlgMLDSA65)
	}
	if len(pubKey) != len(originalPubKey) {
		t.Errorf("public key length mismatch: got %d, want %d", len(pubKey), len(originalPubKey))
	}
	if policy != originalPolicy {
		t.Errorf("policy mismatch: got %v, want %v", policy, originalPolicy)
	}
}

func TestDecodeHybridExtension_WrongOID(t *testing.T) {
	ext := pkix.Extension{
		Id:    OIDExtKeyUsage, // Wrong OID
		Value: []byte{0x30, 0x00},
	}

	_, _, _, err := DecodeHybridExtension(ext)
	if err == nil {
		t.Error("expected error for wrong OID")
	}
}

func TestFindHybridExtension_NotFound(t *testing.T) {
	extensions := []pkix.Extension{
		{Id: OIDExtKeyUsage, Value: []byte{0x00}},
	}

	found := FindHybridExtension(extensions)
	if found != nil {
		t.Error("should not find hybrid extension")
	}
}

func TestHasHybridExtension(t *testing.T) {
	pubKey := make([]byte, 100)
	rand.Read(pubKey)

	hybridExt, _ := EncodeHybridExtension(crypto.AlgMLDSA65, pubKey, HybridPolicyInformational)

	withHybrid := []pkix.Extension{hybridExt}
	withoutHybrid := []pkix.Extension{{Id: OIDExtKeyUsage, Value: []byte{0x00}}}

	if !HasHybridExtension(withHybrid) {
		t.Error("should have hybrid extension")
	}
	if HasHybridExtension(withoutHybrid) {
		t.Error("should not have hybrid extension")
	}
}

func TestParseHybridExtension(t *testing.T) {
	pubKey := make([]byte, 100)
	rand.Read(pubKey)

	hybridExt, _ := EncodeHybridExtension(crypto.AlgMLDSA65, pubKey, HybridPolicyPQCPreferred)
	extensions := []pkix.Extension{hybridExt}

	info, err := ParseHybridExtension(extensions)
	if err != nil {
		t.Fatalf("ParseHybridExtension failed: %v", err)
	}

	if info == nil {
		t.Fatal("info should not be nil")
	}
	if info.Algorithm != crypto.AlgMLDSA65 {
		t.Errorf("algorithm mismatch")
	}
	if info.Policy != HybridPolicyPQCPreferred {
		t.Errorf("policy mismatch")
	}
}

func TestParseHybridExtension_NotFound(t *testing.T) {
	extensions := []pkix.Extension{}

	info, err := ParseHybridExtension(extensions)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info != nil {
		t.Error("info should be nil when no extension")
	}
}

// =============================================================================
// Catalyst Extensions Tests (ITU-T X.509 Section 9.8)
// =============================================================================

func TestEncodeAltSubjectPublicKeyInfo(t *testing.T) {
	pubKey := make([]byte, 1952) // ML-DSA-65 public key
	rand.Read(pubKey)

	ext, err := EncodeAltSubjectPublicKeyInfo(crypto.AlgMLDSA65, pubKey)
	if err != nil {
		t.Fatalf("EncodeAltSubjectPublicKeyInfo failed: %v", err)
	}

	if ext.Critical {
		t.Error("extension should not be critical")
	}
	if !OIDEqual(ext.Id, OIDAltSubjectPublicKeyInfo) {
		t.Error("wrong extension OID")
	}
}

func TestEncodeAltSubjectPublicKeyInfo_NoOID(t *testing.T) {
	pubKey := make([]byte, 100)

	_, err := EncodeAltSubjectPublicKeyInfo("invalid-alg", pubKey)
	if err == nil {
		t.Error("expected error for algorithm without OID")
	}
}

func TestDecodeAltSubjectPublicKeyInfo(t *testing.T) {
	originalPubKey := make([]byte, 1952)
	rand.Read(originalPubKey)

	ext, _ := EncodeAltSubjectPublicKeyInfo(crypto.AlgMLDSA65, originalPubKey)

	alg, pubKey, err := DecodeAltSubjectPublicKeyInfo(ext)
	if err != nil {
		t.Fatalf("DecodeAltSubjectPublicKeyInfo failed: %v", err)
	}

	if alg != crypto.AlgMLDSA65 {
		t.Errorf("algorithm mismatch")
	}
	if len(pubKey) != len(originalPubKey) {
		t.Errorf("public key length mismatch")
	}
}

func TestDecodeAltSubjectPublicKeyInfo_WrongOID(t *testing.T) {
	ext := pkix.Extension{
		Id:    OIDExtKeyUsage,
		Value: []byte{0x30, 0x00},
	}

	_, _, err := DecodeAltSubjectPublicKeyInfo(ext)
	if err == nil {
		t.Error("expected error for wrong OID")
	}
}

func TestEncodeAltSignatureAlgorithm(t *testing.T) {
	ext, err := EncodeAltSignatureAlgorithm(crypto.AlgMLDSA65)
	if err != nil {
		t.Fatalf("EncodeAltSignatureAlgorithm failed: %v", err)
	}

	if ext.Critical {
		t.Error("extension should not be critical")
	}
	if !OIDEqual(ext.Id, OIDAltSignatureAlgorithm) {
		t.Error("wrong extension OID")
	}
}

func TestDecodeAltSignatureAlgorithm(t *testing.T) {
	ext, _ := EncodeAltSignatureAlgorithm(crypto.AlgMLDSA87)

	alg, err := DecodeAltSignatureAlgorithm(ext)
	if err != nil {
		t.Fatalf("DecodeAltSignatureAlgorithm failed: %v", err)
	}

	if alg != crypto.AlgMLDSA87 {
		t.Errorf("algorithm mismatch: got %s, want %s", alg, crypto.AlgMLDSA87)
	}
}

func TestDecodeAltSignatureAlgorithm_WrongOID(t *testing.T) {
	ext := pkix.Extension{
		Id:    OIDExtKeyUsage,
		Value: []byte{0x30, 0x00},
	}

	_, err := DecodeAltSignatureAlgorithm(ext)
	if err == nil {
		t.Error("expected error for wrong OID")
	}
}

func TestEncodeAltSignatureValue(t *testing.T) {
	signature := make([]byte, 3293) // ML-DSA-65 signature size
	rand.Read(signature)

	ext, err := EncodeAltSignatureValue(signature)
	if err != nil {
		t.Fatalf("EncodeAltSignatureValue failed: %v", err)
	}

	if ext.Critical {
		t.Error("extension should not be critical")
	}
	if !OIDEqual(ext.Id, OIDAltSignatureValue) {
		t.Error("wrong extension OID")
	}
}

func TestDecodeAltSignatureValue(t *testing.T) {
	originalSig := make([]byte, 3293)
	rand.Read(originalSig)

	ext, _ := EncodeAltSignatureValue(originalSig)

	sig, err := DecodeAltSignatureValue(ext)
	if err != nil {
		t.Fatalf("DecodeAltSignatureValue failed: %v", err)
	}

	if len(sig) != len(originalSig) {
		t.Errorf("signature length mismatch")
	}
}

func TestDecodeAltSignatureValue_WrongOID(t *testing.T) {
	ext := pkix.Extension{
		Id:    OIDExtKeyUsage,
		Value: []byte{0x30, 0x00},
	}

	_, err := DecodeAltSignatureValue(ext)
	if err == nil {
		t.Error("expected error for wrong OID")
	}
}

func TestFindCatalystExtensions(t *testing.T) {
	pubKey := make([]byte, 1952)
	rand.Read(pubKey)
	sig := make([]byte, 3293)
	rand.Read(sig)

	altPubKeyExt, _ := EncodeAltSubjectPublicKeyInfo(crypto.AlgMLDSA65, pubKey)
	altSigAlgExt, _ := EncodeAltSignatureAlgorithm(crypto.AlgMLDSA65)
	altSigValExt, _ := EncodeAltSignatureValue(sig)

	extensions := []pkix.Extension{
		{Id: OIDExtKeyUsage, Value: []byte{0x00}},
		altPubKeyExt,
		altSigAlgExt,
		altSigValExt,
	}

	cat := FindCatalystExtensions(extensions)
	if cat == nil {
		t.Fatal("expected to find Catalyst extensions")
	}

	if cat.AltPublicKey == nil {
		t.Error("AltPublicKey should not be nil")
	}
	if cat.AltSigAlgorithm.Algorithm == nil {
		t.Error("AltSigAlgorithm should not be nil")
	}
	if len(cat.AltSignature) == 0 {
		t.Error("AltSignature should not be empty")
	}
}

func TestFindCatalystExtensions_NotFound(t *testing.T) {
	extensions := []pkix.Extension{
		{Id: OIDExtKeyUsage, Value: []byte{0x00}},
	}

	cat := FindCatalystExtensions(extensions)
	if cat != nil {
		t.Error("should not find Catalyst extensions")
	}
}

func TestFindCatalystExtensions_Partial(t *testing.T) {
	pubKey := make([]byte, 100)
	rand.Read(pubKey)

	altPubKeyExt, _ := EncodeAltSubjectPublicKeyInfo(crypto.AlgMLDSA65, pubKey)

	extensions := []pkix.Extension{
		altPubKeyExt,
		// Missing AltSignatureAlgorithm and AltSignatureValue
	}

	cat := FindCatalystExtensions(extensions)
	if cat == nil {
		t.Fatal("should find partial Catalyst extensions")
	}
	if cat.AltPublicKey == nil {
		t.Error("AltPublicKey should be present")
	}
	if len(cat.AltSignature) != 0 {
		t.Error("AltSignature should be empty")
	}
}

func TestHasCatalystExtensions(t *testing.T) {
	pubKey := make([]byte, 100)
	rand.Read(pubKey)

	altPubKeyExt, _ := EncodeAltSubjectPublicKeyInfo(crypto.AlgMLDSA65, pubKey)

	withCatalyst := []pkix.Extension{altPubKeyExt}
	withoutCatalyst := []pkix.Extension{{Id: OIDExtKeyUsage, Value: []byte{0x00}}}

	if !HasCatalystExtensions(withCatalyst) {
		t.Error("should have Catalyst extensions")
	}
	if HasCatalystExtensions(withoutCatalyst) {
		t.Error("should not have Catalyst extensions")
	}
}

func TestIsCatalystComplete(t *testing.T) {
	pubKey := make([]byte, 100)
	rand.Read(pubKey)
	sig := make([]byte, 100)
	rand.Read(sig)

	altPubKeyExt, _ := EncodeAltSubjectPublicKeyInfo(crypto.AlgMLDSA65, pubKey)
	altSigAlgExt, _ := EncodeAltSignatureAlgorithm(crypto.AlgMLDSA65)
	altSigValExt, _ := EncodeAltSignatureValue(sig)

	complete := []pkix.Extension{altPubKeyExt, altSigAlgExt, altSigValExt}
	partial := []pkix.Extension{altPubKeyExt}

	if !IsCatalystComplete(complete) {
		t.Error("should be complete")
	}
	if IsCatalystComplete(partial) {
		t.Error("should not be complete")
	}
}

func TestParseCatalystExtensions(t *testing.T) {
	pubKey := make([]byte, 1952)
	rand.Read(pubKey)
	sig := make([]byte, 3293)
	rand.Read(sig)

	altPubKeyExt, _ := EncodeAltSubjectPublicKeyInfo(crypto.AlgMLDSA65, pubKey)
	altSigAlgExt, _ := EncodeAltSignatureAlgorithm(crypto.AlgMLDSA65)
	altSigValExt, _ := EncodeAltSignatureValue(sig)

	extensions := []pkix.Extension{altPubKeyExt, altSigAlgExt, altSigValExt}

	info, err := ParseCatalystExtensions(extensions)
	if err != nil {
		t.Fatalf("ParseCatalystExtensions failed: %v", err)
	}

	if info == nil {
		t.Fatal("info should not be nil")
	}
	if info.AltAlgorithm != crypto.AlgMLDSA65 {
		t.Errorf("AltAlgorithm mismatch")
	}
	if info.AltSigAlg != crypto.AlgMLDSA65 {
		t.Errorf("AltSigAlg mismatch")
	}
	if len(info.AltPublicKey) != len(pubKey) {
		t.Errorf("AltPublicKey length mismatch")
	}
	if len(info.AltSignature) != len(sig) {
		t.Errorf("AltSignature length mismatch")
	}
}

func TestParseCatalystExtensions_NotFound(t *testing.T) {
	extensions := []pkix.Extension{}

	info, err := ParseCatalystExtensions(extensions)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info != nil {
		t.Error("info should be nil")
	}
}

// =============================================================================
// RelatedCertificate Extension Tests
// =============================================================================

func TestEncodeRelatedCertificate(t *testing.T) {
	cert := generateTestCert(t)

	ext, err := EncodeRelatedCertificate(cert)
	if err != nil {
		t.Fatalf("EncodeRelatedCertificate failed: %v", err)
	}

	if ext.Critical {
		t.Error("extension should not be critical")
	}
	if !OIDEqual(ext.Id, OIDRelatedCertificate) {
		t.Error("wrong extension OID")
	}
}

func TestEncodeRelatedCertificate_NilCert(t *testing.T) {
	_, err := EncodeRelatedCertificate(nil)
	if err == nil {
		t.Error("expected error for nil certificate")
	}
}

func TestDecodeRelatedCertificate(t *testing.T) {
	cert := generateTestCert(t)

	ext, err := EncodeRelatedCertificate(cert)
	if err != nil {
		t.Fatalf("EncodeRelatedCertificate failed: %v", err)
	}

	relCert, err := DecodeRelatedCertificate(ext)
	if err != nil {
		t.Fatalf("DecodeRelatedCertificate failed: %v", err)
	}

	if relCert == nil {
		t.Fatal("relCert should not be nil")
	}
	if len(relCert.CertHash) != 32 { // SHA-256
		t.Errorf("unexpected hash length: %d", len(relCert.CertHash))
	}
	if len(relCert.IssuerSerial.Issuer.FullBytes) == 0 {
		t.Error("IssuerSerial.Issuer should not be empty")
	}
}

func TestDecodeRelatedCertificate_WrongOID(t *testing.T) {
	ext := pkix.Extension{
		Id:    OIDExtKeyUsage,
		Value: []byte{0x30, 0x00},
	}

	_, err := DecodeRelatedCertificate(ext)
	if err == nil {
		t.Error("expected error for wrong OID")
	}
}

func TestFindRelatedCertificateExtension(t *testing.T) {
	cert := generateTestCert(t)
	relCertExt, _ := EncodeRelatedCertificate(cert)

	extensions := []pkix.Extension{
		{Id: OIDExtKeyUsage, Value: []byte{0x00}},
		relCertExt,
	}

	found := FindRelatedCertificateExtension(extensions)
	if found == nil {
		t.Fatal("expected to find RelatedCertificate extension")
	}
	if !OIDEqual(found.Id, OIDRelatedCertificate) {
		t.Error("found wrong extension")
	}
}

func TestFindRelatedCertificateExtension_NotFound(t *testing.T) {
	extensions := []pkix.Extension{
		{Id: OIDExtKeyUsage, Value: []byte{0x00}},
	}

	found := FindRelatedCertificateExtension(extensions)
	if found != nil {
		t.Error("should not find extension")
	}
}

func TestHasRelatedCertificate(t *testing.T) {
	cert := generateTestCert(t)
	relCertExt, _ := EncodeRelatedCertificate(cert)

	with := []pkix.Extension{relCertExt}
	without := []pkix.Extension{{Id: OIDExtKeyUsage, Value: []byte{0x00}}}

	if !HasRelatedCertificate(with) {
		t.Error("should have RelatedCertificate")
	}
	if HasRelatedCertificate(without) {
		t.Error("should not have RelatedCertificate")
	}
}

func TestVerifyRelatedCertificate(t *testing.T) {
	cert := generateTestCert(t)

	ext, _ := EncodeRelatedCertificate(cert)
	relCert, _ := DecodeRelatedCertificate(ext)

	// Verify against correct certificate
	if !VerifyRelatedCertificate(relCert, cert) {
		t.Error("verification should succeed for correct certificate")
	}

	// Verify against different certificate
	otherCert := generateTestCert(t)
	if VerifyRelatedCertificate(relCert, otherCert) {
		t.Error("verification should fail for different certificate")
	}
}

func TestVerifyRelatedCertificate_NilInputs(t *testing.T) {
	cert := generateTestCert(t)
	ext, _ := EncodeRelatedCertificate(cert)
	relCert, _ := DecodeRelatedCertificate(ext)

	if VerifyRelatedCertificate(nil, cert) {
		t.Error("should fail for nil extension")
	}
	if VerifyRelatedCertificate(relCert, nil) {
		t.Error("should fail for nil candidate")
	}
}

func TestParseRelatedCertificate(t *testing.T) {
	cert := generateTestCert(t)
	relCertExt, _ := EncodeRelatedCertificate(cert)

	extensions := []pkix.Extension{relCertExt}

	info, err := ParseRelatedCertificate(extensions)
	if err != nil {
		t.Fatalf("ParseRelatedCertificate failed: %v", err)
	}

	if info == nil {
		t.Fatal("info should not be nil")
	}
	if info.HashAlgorithm != "SHA-256" {
		t.Errorf("unexpected hash algorithm: %s", info.HashAlgorithm)
	}
	if len(info.CertHash) != 32 {
		t.Errorf("unexpected hash length: %d", len(info.CertHash))
	}
	if !info.HasIssuer {
		t.Error("HasIssuer should be true")
	}
}

func TestParseRelatedCertificate_NotFound(t *testing.T) {
	extensions := []pkix.Extension{}

	info, err := ParseRelatedCertificate(extensions)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info != nil {
		t.Error("info should be nil")
	}
}

// =============================================================================
// OID Tests
// =============================================================================

func TestOIDToString(t *testing.T) {
	oid := OIDAltSubjectPublicKeyInfo
	s := OIDToString(oid)

	if s == "" {
		t.Error("OIDToString should not return empty string")
	}
	// OID 2.5.29.72 should produce "2.5.29.72"
	if s != "2.5.29.72" {
		t.Errorf("unexpected OID string: %s", s)
	}
}

// =============================================================================
// Algorithm OID Mapping Tests
// =============================================================================

func TestOidToAlgorithm(t *testing.T) {
	tests := []struct {
		name     string
		oid      []int
		expected crypto.AlgorithmID
		wantErr  bool
	}{
		{"ML-DSA-44", []int{2, 16, 840, 1, 101, 3, 4, 3, 17}, crypto.AlgMLDSA44, false},
		{"ML-DSA-65", []int{2, 16, 840, 1, 101, 3, 4, 3, 18}, crypto.AlgMLDSA65, false},
		{"ML-DSA-87", []int{2, 16, 840, 1, 101, 3, 4, 3, 19}, crypto.AlgMLDSA87, false},
		{"ML-KEM-512", []int{2, 16, 840, 1, 101, 3, 4, 4, 1}, crypto.AlgMLKEM512, false},
		{"ML-KEM-768", []int{2, 16, 840, 1, 101, 3, 4, 4, 2}, crypto.AlgMLKEM768, false},
		{"ML-KEM-1024", []int{2, 16, 840, 1, 101, 3, 4, 4, 3}, crypto.AlgMLKEM1024, false},
		{"unknown", []int{1, 2, 3, 4, 5}, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alg, err := oidToAlgorithm(tt.oid)
			if (err != nil) != tt.wantErr {
				t.Errorf("oidToAlgorithm() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if alg != tt.expected {
				t.Errorf("oidToAlgorithm() = %s, want %s", alg, tt.expected)
			}
		})
	}
}

// =============================================================================
// Round-trip Tests
// =============================================================================

func TestCatalystExtensions_RoundTrip(t *testing.T) {
	// Generate test data
	pubKey := make([]byte, 1952) // ML-DSA-65
	rand.Read(pubKey)
	sig := make([]byte, 3293)
	rand.Read(sig)

	// Encode all three Catalyst extensions
	altPubKeyExt, err := EncodeAltSubjectPublicKeyInfo(crypto.AlgMLDSA65, pubKey)
	if err != nil {
		t.Fatalf("EncodeAltSubjectPublicKeyInfo failed: %v", err)
	}

	altSigAlgExt, err := EncodeAltSignatureAlgorithm(crypto.AlgMLDSA65)
	if err != nil {
		t.Fatalf("EncodeAltSignatureAlgorithm failed: %v", err)
	}

	altSigValExt, err := EncodeAltSignatureValue(sig)
	if err != nil {
		t.Fatalf("EncodeAltSignatureValue failed: %v", err)
	}

	// Parse them back
	alg1, key1, err := DecodeAltSubjectPublicKeyInfo(altPubKeyExt)
	if err != nil {
		t.Fatalf("DecodeAltSubjectPublicKeyInfo failed: %v", err)
	}

	alg2, err := DecodeAltSignatureAlgorithm(altSigAlgExt)
	if err != nil {
		t.Fatalf("DecodeAltSignatureAlgorithm failed: %v", err)
	}

	sig2, err := DecodeAltSignatureValue(altSigValExt)
	if err != nil {
		t.Fatalf("DecodeAltSignatureValue failed: %v", err)
	}

	// Verify round-trip
	if alg1 != crypto.AlgMLDSA65 {
		t.Error("public key algorithm mismatch")
	}
	if alg2 != crypto.AlgMLDSA65 {
		t.Error("signature algorithm mismatch")
	}
	if len(key1) != len(pubKey) {
		t.Error("public key length mismatch")
	}
	if len(sig2) != len(sig) {
		t.Error("signature length mismatch")
	}
}

func TestRelatedCertificate_RoundTrip(t *testing.T) {
	cert := generateTestCert(t)

	// Encode
	ext, err := EncodeRelatedCertificate(cert)
	if err != nil {
		t.Fatalf("EncodeRelatedCertificate failed: %v", err)
	}

	// Decode
	relCert, err := DecodeRelatedCertificate(ext)
	if err != nil {
		t.Fatalf("DecodeRelatedCertificate failed: %v", err)
	}

	// Verify
	if !VerifyRelatedCertificate(relCert, cert) {
		t.Error("round-trip verification failed")
	}
}

// =============================================================================
// Helper Functions
// =============================================================================

func generateTestCert(t *testing.T) *x509.Certificate {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "Test Certificate",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert
}
