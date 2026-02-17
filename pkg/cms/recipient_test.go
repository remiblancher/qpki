package cms

import (
	"context"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"

	"github.com/remiblancher/post-quantum-pki/pkg/credential"
	pkicrypto "github.com/remiblancher/post-quantum-pki/pkg/crypto"
)

// =============================================================================
// Unit Tests: ExtractRecipientMatchers
// =============================================================================

// TestU_ExtractRecipientMatchers_RSA tests extraction from RSA (KeyTransRecipientInfo).
func TestU_ExtractRecipientMatchers_RSA(t *testing.T) {
	kp := generateRSAKeyPair(t, 2048)
	cert := generateTestCertificate(t, kp)

	plaintext := []byte("test data for RSA encryption")

	// Encrypt with RSA
	ciphertext, err := Encrypt(context.Background(), plaintext, &EncryptOptions{
		Recipients:        []*x509.Certificate{cert},
		ContentEncryption: AES256GCM,
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Extract matchers
	matchers, err := ExtractRecipientMatchers(ciphertext)
	if err != nil {
		t.Fatalf("ExtractRecipientMatchers failed: %v", err)
	}

	if len(matchers) == 0 {
		t.Fatal("Expected at least one matcher")
	}

	// Verify matcher has IssuerAndSerial
	found := false
	for _, m := range matchers {
		if m.IssuerAndSerialNumber != nil {
			if m.IssuerAndSerialNumber.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				found = true
				break
			}
		}
	}
	if !found {
		t.Error("Expected matcher with matching IssuerAndSerialNumber")
	}
}

// TestU_ExtractRecipientMatchers_ECDH tests extraction from ECDH (KeyAgreeRecipientInfo).
func TestU_ExtractRecipientMatchers_ECDH(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	plaintext := []byte("test data for ECDH encryption")

	// Encrypt with ECDH
	ciphertext, err := Encrypt(context.Background(), plaintext, &EncryptOptions{
		Recipients:        []*x509.Certificate{cert},
		ContentEncryption: AES256GCM,
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Extract matchers
	matchers, err := ExtractRecipientMatchers(ciphertext)
	if err != nil {
		t.Fatalf("ExtractRecipientMatchers failed: %v", err)
	}

	if len(matchers) == 0 {
		t.Fatal("Expected at least one matcher")
	}

	// Verify matcher has IssuerAndSerial
	found := false
	for _, m := range matchers {
		if m.IssuerAndSerialNumber != nil {
			if m.IssuerAndSerialNumber.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				found = true
				break
			}
		}
	}
	if !found {
		t.Error("Expected matcher with matching IssuerAndSerialNumber")
	}
}

// TestU_ExtractRecipientMatchers_MLKEM tests extraction from ML-KEM (KEMRecipientInfo).
func TestU_ExtractRecipientMatchers_MLKEM(t *testing.T) {
	kemKP := generateMLKEMKeyPair(t, pkicrypto.AlgMLKEM768)
	cert := generateMLKEMCertificate(t, kemKP)

	plaintext := []byte("test data for ML-KEM encryption")

	// Encrypt with ML-KEM (public key is extracted from certificate)
	ciphertext, err := Encrypt(context.Background(), plaintext, &EncryptOptions{
		Recipients:        []*x509.Certificate{cert},
		ContentEncryption: AES256GCM,
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Extract matchers
	matchers, err := ExtractRecipientMatchers(ciphertext)
	if err != nil {
		t.Fatalf("ExtractRecipientMatchers failed: %v", err)
	}

	if len(matchers) == 0 {
		t.Fatal("Expected at least one matcher")
	}

	// Verify matcher has IssuerAndSerial
	found := false
	for _, m := range matchers {
		if m.IssuerAndSerialNumber != nil {
			if m.IssuerAndSerialNumber.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				found = true
				break
			}
		}
	}
	if !found {
		t.Error("Expected matcher with matching IssuerAndSerialNumber")
	}
}

// TestU_ExtractRecipientMatchers_MultipleRecipients tests extraction with multiple recipients.
func TestU_ExtractRecipientMatchers_MultipleRecipients(t *testing.T) {
	kp1 := generateRSAKeyPair(t, 2048)
	cert1 := generateTestCertificate(t, kp1)

	kp2 := generateRSAKeyPair(t, 2048)
	cert2 := generateTestCertificate(t, kp2)

	plaintext := []byte("test data for multiple recipients")

	// Encrypt with multiple recipients
	ciphertext, err := Encrypt(context.Background(), plaintext, &EncryptOptions{
		Recipients:        []*x509.Certificate{cert1, cert2},
		ContentEncryption: AES256GCM,
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Extract matchers
	matchers, err := ExtractRecipientMatchers(ciphertext)
	if err != nil {
		t.Fatalf("ExtractRecipientMatchers failed: %v", err)
	}

	if len(matchers) < 2 {
		t.Fatalf("Expected at least 2 matchers, got %d", len(matchers))
	}

	// Verify both certificates are represented
	foundCert1 := false
	foundCert2 := false
	for _, m := range matchers {
		if m.IssuerAndSerialNumber != nil {
			if m.IssuerAndSerialNumber.SerialNumber.Cmp(cert1.SerialNumber) == 0 {
				foundCert1 = true
			}
			if m.IssuerAndSerialNumber.SerialNumber.Cmp(cert2.SerialNumber) == 0 {
				foundCert2 = true
			}
		}
	}
	if !foundCert1 {
		t.Error("Expected matcher for cert1")
	}
	if !foundCert2 {
		t.Error("Expected matcher for cert2")
	}
}

// TestU_ExtractRecipientMatchers_AES256CBC tests extraction from EnvelopedData (CBC mode).
func TestU_ExtractRecipientMatchers_AES256CBC(t *testing.T) {
	kp := generateRSAKeyPair(t, 2048)
	cert := generateTestCertificate(t, kp)

	plaintext := []byte("test data for AES-CBC")

	// Encrypt with AES-CBC (uses EnvelopedData, not AuthEnvelopedData)
	ciphertext, err := Encrypt(context.Background(), plaintext, &EncryptOptions{
		Recipients:        []*x509.Certificate{cert},
		ContentEncryption: AES256CBC,
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Verify it's EnvelopedData (not AuthEnvelopedData)
	var ci ContentInfo
	_, err = asn1.Unmarshal(ciphertext, &ci)
	if err != nil {
		t.Fatalf("Failed to parse ContentInfo: %v", err)
	}
	if !ci.ContentType.Equal(OIDEnvelopedData) {
		t.Errorf("Expected EnvelopedData OID, got %v", ci.ContentType)
	}

	// Extract matchers
	matchers, err := ExtractRecipientMatchers(ciphertext)
	if err != nil {
		t.Fatalf("ExtractRecipientMatchers failed: %v", err)
	}

	if len(matchers) == 0 {
		t.Fatal("Expected at least one matcher")
	}
}

// TestU_ExtractRecipientMatchers_InvalidData tests error handling for invalid data.
func TestU_ExtractRecipientMatchers_InvalidData(t *testing.T) {
	testCases := []struct {
		name string
		data []byte
	}{
		{"empty data", []byte{}},
		{"invalid ASN.1", []byte{0x00, 0x01, 0x02}},
		{"random data", []byte("not a CMS message")},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ExtractRecipientMatchers(tc.data)
			if err == nil {
				t.Error("Expected error for invalid data")
			}
		})
	}
}

// TestU_ExtractRecipientMatchers_NotEnvelopedData tests error for non-EnvelopedData content.
func TestU_ExtractRecipientMatchers_NotEnvelopedData(t *testing.T) {
	// Create a SignedData message instead
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	signedData, err := Sign(context.Background(), []byte("test"), &SignerConfig{
		Signer:      kp.PrivateKey,
		Certificate: cert,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Try to extract matchers - should fail
	_, err = ExtractRecipientMatchers(signedData)
	if err == nil {
		t.Error("Expected error for SignedData input")
	}
}

// =============================================================================
// Unit Tests: matchersFromRecipientIdentifier
// =============================================================================

// TestU_matchersFromRecipientIdentifier_IssuerAndSerial tests matcher creation with IssuerAndSerial.
func TestU_matchersFromRecipientIdentifier_IssuerAndSerial(t *testing.T) {
	issuerRDN := pkix.RDNSequence{
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{
				Type:  asn1.ObjectIdentifier{2, 5, 4, 3},
				Value: "Test Issuer",
			},
		},
	}
	issuerBytes, _ := asn1.Marshal(issuerRDN)

	rid := &RecipientIdentifier{
		IssuerAndSerial: &IssuerAndSerialNumber{
			Issuer:       asn1.RawValue{FullBytes: issuerBytes},
			SerialNumber: big.NewInt(12345),
		},
	}

	matchers := matchersFromRecipientIdentifier(rid)

	if len(matchers) != 1 {
		t.Fatalf("Expected 1 matcher, got %d", len(matchers))
	}

	m := matchers[0]
	if m.IssuerAndSerialNumber == nil {
		t.Fatal("Expected IssuerAndSerialNumber in matcher")
	}
	if m.IssuerAndSerialNumber.SerialNumber.Cmp(big.NewInt(12345)) != 0 {
		t.Errorf("SerialNumber mismatch: expected 12345, got %v", m.IssuerAndSerialNumber.SerialNumber)
	}
}

// TestU_matchersFromRecipientIdentifier_SKI tests matcher creation with SubjectKeyIdentifier.
func TestU_matchersFromRecipientIdentifier_SKI(t *testing.T) {
	ski := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	rid := &RecipientIdentifier{
		SKI: ski,
	}

	matchers := matchersFromRecipientIdentifier(rid)

	if len(matchers) != 1 {
		t.Fatalf("Expected 1 matcher, got %d", len(matchers))
	}

	m := matchers[0]
	if m.SubjectKeyIdentifier == nil {
		t.Fatal("Expected SubjectKeyIdentifier in matcher")
	}
	if string(m.SubjectKeyIdentifier) != string(ski) {
		t.Errorf("SKI mismatch")
	}
}

// TestU_matchersFromRecipientIdentifier_Both tests matcher creation with both identifiers.
func TestU_matchersFromRecipientIdentifier_Both(t *testing.T) {
	issuerRDN := pkix.RDNSequence{
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{
				Type:  asn1.ObjectIdentifier{2, 5, 4, 3},
				Value: "Test Issuer",
			},
		},
	}
	issuerBytes, _ := asn1.Marshal(issuerRDN)
	ski := []byte{0x01, 0x02, 0x03, 0x04}

	rid := &RecipientIdentifier{
		IssuerAndSerial: &IssuerAndSerialNumber{
			Issuer:       asn1.RawValue{FullBytes: issuerBytes},
			SerialNumber: big.NewInt(99),
		},
		SKI: ski,
	}

	matchers := matchersFromRecipientIdentifier(rid)

	if len(matchers) != 2 {
		t.Fatalf("Expected 2 matchers, got %d", len(matchers))
	}
}

// TestU_matchersFromRecipientIdentifier_Empty tests empty RecipientIdentifier.
func TestU_matchersFromRecipientIdentifier_Empty(t *testing.T) {
	rid := &RecipientIdentifier{}

	matchers := matchersFromRecipientIdentifier(rid)

	if len(matchers) != 0 {
		t.Fatalf("Expected 0 matchers for empty RID, got %d", len(matchers))
	}
}

// =============================================================================
// Unit Tests: matchersFromKeyAgreeRecipientInfo
// =============================================================================

// TestU_matchersFromKeyAgreeRecipientInfo tests extraction from KARI.
func TestU_matchersFromKeyAgreeRecipientInfo(t *testing.T) {
	issuerRDN := pkix.RDNSequence{
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{
				Type:  asn1.ObjectIdentifier{2, 5, 4, 3},
				Value: "Test Issuer",
			},
		},
	}
	issuerBytes, _ := asn1.Marshal(issuerRDN)

	kari := &KeyAgreeRecipientInfo{
		RecipientEncryptedKeys: []RecipientEncryptedKey{
			{
				RID: KeyAgreeRecipientIdentifier{
					IssuerAndSerial: &IssuerAndSerialNumber{
						Issuer:       asn1.RawValue{FullBytes: issuerBytes},
						SerialNumber: big.NewInt(111),
					},
				},
				EncryptedKey: []byte{0x00},
			},
			{
				RID: KeyAgreeRecipientIdentifier{
					RKeyID: &RecipientKeyIdentifier{
						SubjectKeyIdentifier: []byte{0xAA, 0xBB, 0xCC},
					},
				},
				EncryptedKey: []byte{0x00},
			},
		},
	}

	matchers := matchersFromKeyAgreeRecipientInfo(kari)

	if len(matchers) != 2 {
		t.Fatalf("Expected 2 matchers, got %d", len(matchers))
	}

	// First matcher should have IssuerAndSerial
	if matchers[0].IssuerAndSerialNumber == nil {
		t.Error("First matcher should have IssuerAndSerialNumber")
	}
	if matchers[0].IssuerAndSerialNumber.SerialNumber.Cmp(big.NewInt(111)) != 0 {
		t.Errorf("First matcher serial mismatch")
	}

	// Second matcher should have SKI
	if matchers[1].SubjectKeyIdentifier == nil {
		t.Error("Second matcher should have SubjectKeyIdentifier")
	}
	if string(matchers[1].SubjectKeyIdentifier) != string([]byte{0xAA, 0xBB, 0xCC}) {
		t.Errorf("Second matcher SKI mismatch")
	}
}

// TestU_matchersFromKeyAgreeRecipientInfo_Empty tests KARI with no recipients.
func TestU_matchersFromKeyAgreeRecipientInfo_Empty(t *testing.T) {
	kari := &KeyAgreeRecipientInfo{
		RecipientEncryptedKeys: []RecipientEncryptedKey{},
	}

	matchers := matchersFromKeyAgreeRecipientInfo(kari)

	if len(matchers) != 0 {
		t.Fatalf("Expected 0 matchers for empty KARI, got %d", len(matchers))
	}
}

// =============================================================================
// Unit Tests: convertIssuer
// =============================================================================

// TestU_convertIssuer_Valid tests conversion of valid issuer.
func TestU_convertIssuer_Valid(t *testing.T) {
	issuerRDN := pkix.RDNSequence{
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{
				Type:  asn1.ObjectIdentifier{2, 5, 4, 3}, // CN
				Value: "Test Issuer",
			},
		},
	}
	issuerBytes, _ := asn1.Marshal(issuerRDN)

	rawValue := asn1.RawValue{FullBytes: issuerBytes}
	result := convertIssuer(rawValue)

	if len(result) == 0 {
		t.Fatal("Expected non-empty RDNSequence")
	}
	if len(result[0]) == 0 {
		t.Fatal("Expected non-empty RDN")
	}
}

// TestU_convertIssuer_Invalid tests conversion of invalid issuer data.
func TestU_convertIssuer_Invalid(t *testing.T) {
	rawValue := asn1.RawValue{FullBytes: []byte{0x00, 0x01, 0x02}}
	result := convertIssuer(rawValue)

	// Should return nil/empty for invalid data
	if len(result) > 0 {
		t.Error("Expected nil or empty result for invalid issuer")
	}
}

// =============================================================================
// Unit Tests: IssuerAndSerialFromCertificate
// =============================================================================

// TestU_IssuerAndSerialFromCertificate_Valid tests creation from valid cert data.
func TestU_IssuerAndSerialFromCertificate_Valid(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	result := IssuerAndSerialFromCertificate(cert.RawIssuer, cert.SerialNumber)

	if result == nil {
		t.Fatal("Expected non-nil result")
	}
	if result.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Errorf("SerialNumber mismatch")
	}
	if len(result.Issuer) == 0 {
		t.Error("Expected non-empty Issuer")
	}
}

// TestU_IssuerAndSerialFromCertificate_InvalidIssuer tests with invalid issuer bytes.
func TestU_IssuerAndSerialFromCertificate_InvalidIssuer(t *testing.T) {
	result := IssuerAndSerialFromCertificate([]byte{0x00, 0x01}, big.NewInt(123))

	if result != nil {
		t.Error("Expected nil for invalid issuer bytes")
	}
}

// =============================================================================
// Integration Tests: RecipientMatcher.MatchesCertificate
// =============================================================================

// TestF_RecipientMatcher_MatchesCertificate_IssuerSerial tests matching by IssuerAndSerial.
func TestF_RecipientMatcher_MatchesCertificate_IssuerSerial(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	// Create matcher from certificate
	ias := IssuerAndSerialFromCertificate(cert.RawIssuer, cert.SerialNumber)
	matcher := &credential.RecipientMatcher{
		IssuerAndSerialNumber: &credential.IssuerAndSerial{
			Issuer:       ias.Issuer,
			SerialNumber: ias.SerialNumber,
		},
	}

	// Should match
	if !matcher.MatchesCertificate(cert) {
		t.Error("Matcher should match certificate")
	}

	// Create a different certificate
	kp2 := generateECDSAKeyPair(t, elliptic.P256())
	cert2 := generateTestCertificate(t, kp2)

	// Should not match
	if matcher.MatchesCertificate(cert2) {
		t.Error("Matcher should not match different certificate")
	}
}

// TestF_RecipientMatcher_MatchesCertificate_SKI tests matching by SubjectKeyIdentifier.
func TestF_RecipientMatcher_MatchesCertificate_SKI(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	// Create matcher with SKI
	matcher := &credential.RecipientMatcher{
		SubjectKeyIdentifier: cert.SubjectKeyId,
	}

	// Should match if cert has SKI
	if len(cert.SubjectKeyId) > 0 {
		if !matcher.MatchesCertificate(cert) {
			t.Error("Matcher should match certificate by SKI")
		}
	}

	// Matcher with different SKI should not match
	matcher2 := &credential.RecipientMatcher{
		SubjectKeyIdentifier: []byte{0xFF, 0xFF, 0xFF, 0xFF},
	}
	if matcher2.MatchesCertificate(cert) {
		t.Error("Matcher with different SKI should not match")
	}
}

// =============================================================================
// Integration Tests: End-to-End Encrypt/Extract/Match
// =============================================================================

// TestF_ExtractAndMatch_RSA tests full flow: encrypt, extract matchers, match certificate.
func TestF_ExtractAndMatch_RSA(t *testing.T) {
	kp := generateRSAKeyPair(t, 2048)
	cert := generateTestCertificate(t, kp)

	plaintext := []byte("test data")

	// Encrypt
	ciphertext, err := Encrypt(context.Background(), plaintext, &EncryptOptions{
		Recipients:        []*x509.Certificate{cert},
		ContentEncryption: AES256GCM,
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Extract matchers
	matchers, err := ExtractRecipientMatchers(ciphertext)
	if err != nil {
		t.Fatalf("ExtractRecipientMatchers failed: %v", err)
	}

	// At least one matcher should match our certificate
	matched := false
	for _, m := range matchers {
		if m.MatchesCertificate(cert) {
			matched = true
			break
		}
	}

	if !matched {
		t.Error("No matcher matched the encryption certificate")
	}

	// Different certificate should not match
	kp2 := generateRSAKeyPair(t, 2048)
	cert2 := generateTestCertificate(t, kp2)

	for _, m := range matchers {
		if m.MatchesCertificate(cert2) {
			t.Error("Matcher should not match different certificate")
		}
	}
}

// TestF_ExtractAndMatch_ECDH tests full flow with ECDH.
func TestF_ExtractAndMatch_ECDH(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	plaintext := []byte("test data")

	// Encrypt
	ciphertext, err := Encrypt(context.Background(), plaintext, &EncryptOptions{
		Recipients:        []*x509.Certificate{cert},
		ContentEncryption: AES256GCM,
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Extract matchers
	matchers, err := ExtractRecipientMatchers(ciphertext)
	if err != nil {
		t.Fatalf("ExtractRecipientMatchers failed: %v", err)
	}

	// At least one matcher should match our certificate
	matched := false
	for _, m := range matchers {
		if m.MatchesCertificate(cert) {
			matched = true
			break
		}
	}

	if !matched {
		t.Error("No matcher matched the encryption certificate")
	}
}

// TestF_ExtractAndMatch_MLKEM tests full flow with ML-KEM.
func TestF_ExtractAndMatch_MLKEM(t *testing.T) {
	kemKP := generateMLKEMKeyPair(t, pkicrypto.AlgMLKEM768)
	cert := generateMLKEMCertificate(t, kemKP)

	plaintext := []byte("test data")

	// Encrypt (public key is extracted from certificate)
	ciphertext, err := Encrypt(context.Background(), plaintext, &EncryptOptions{
		Recipients:        []*x509.Certificate{cert},
		ContentEncryption: AES256GCM,
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Extract matchers
	matchers, err := ExtractRecipientMatchers(ciphertext)
	if err != nil {
		t.Fatalf("ExtractRecipientMatchers failed: %v", err)
	}

	// At least one matcher should match our certificate
	matched := false
	for _, m := range matchers {
		if m.MatchesCertificate(cert) {
			matched = true
			break
		}
	}

	if !matched {
		t.Error("No matcher matched the encryption certificate")
	}
}
