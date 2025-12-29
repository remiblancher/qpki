package tsa

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/remiblancher/post-quantum-pki/internal/cms"
)

func TestParseRequest(t *testing.T) {
	// Create a valid TimeStampReq
	hash := sha256.Sum256([]byte("test data"))
	req := TimeStampReq{
		Version: 1,
		MessageImprint: MessageImprint{
			HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: cms.OIDSHA256},
			HashedMessage: hash[:],
		},
		Nonce:   big.NewInt(12345),
		CertReq: true,
	}

	// Encode it
	encoded, err := asn1.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal TimeStampReq: %v", err)
	}

	// Parse it back
	parsed, err := ParseRequest(encoded)
	if err != nil {
		t.Fatalf("Failed to parse TimeStampReq: %v", err)
	}

	// Verify fields
	if parsed.Version != 1 {
		t.Errorf("Expected version 1, got %d", parsed.Version)
	}
	if parsed.Nonce.Cmp(big.NewInt(12345)) != 0 {
		t.Errorf("Nonce mismatch")
	}
	if !parsed.CertReq {
		t.Error("Expected CertReq to be true")
	}
}

func TestParseRequest_InvalidVersion(t *testing.T) {
	hash := sha256.Sum256([]byte("test"))
	req := TimeStampReq{
		Version: 2, // Invalid version
		MessageImprint: MessageImprint{
			HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: cms.OIDSHA256},
			HashedMessage: hash[:],
		},
	}

	encoded, _ := asn1.Marshal(req)
	_, err := ParseRequest(encoded)
	if err == nil {
		t.Error("Expected error for invalid version")
	}
}

func TestParseRequest_UnsupportedHash(t *testing.T) {
	req := TimeStampReq{
		Version: 1,
		MessageImprint: MessageImprint{
			HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3, 4}}, // Invalid OID
			HashedMessage: []byte{1, 2, 3, 4},
		},
	}

	encoded, _ := asn1.Marshal(req)
	_, err := ParseRequest(encoded)
	if err == nil {
		t.Error("Expected error for unsupported hash algorithm")
	}
}

func TestCreateToken(t *testing.T) {
	// Generate a test key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create a test certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test TSA",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Create a timestamp request
	hash := sha256.Sum256([]byte("test data"))
	req := &TimeStampReq{
		Version:        1,
		MessageImprint: NewMessageImprint(crypto.SHA256, hash[:]),
		Nonce:          big.NewInt(12345),
		CertReq:        true,
	}

	// Create the token
	config := &TokenConfig{
		Certificate: cert,
		Signer:      privateKey,
		Policy:      asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 2, 1},
		IncludeTSA:  true,
	}

	token, err := CreateToken(req, config, &RandomSerialGenerator{})
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// Verify the token
	if token.Info == nil {
		t.Fatal("Token info is nil")
	}
	if token.Info.Version != 1 {
		t.Errorf("Expected version 1, got %d", token.Info.Version)
	}
	if token.Info.SerialNumber == nil {
		t.Error("Serial number is nil")
	}
	if token.Info.GenTime.IsZero() {
		t.Error("GenTime is zero")
	}
	if token.Info.Nonce.Cmp(big.NewInt(12345)) != 0 {
		t.Error("Nonce mismatch")
	}
}

func TestResponse(t *testing.T) {
	// Test granted response
	granted := NewGrantedResponse(nil)
	if !granted.IsGranted() {
		t.Error("Expected granted response to be granted")
	}
	if granted.StatusString() != "granted" {
		t.Errorf("Expected 'granted', got '%s'", granted.StatusString())
	}

	// Test rejection response
	rejection := NewRejectionResponse(FailBadAlg, "unsupported algorithm")
	if rejection.IsGranted() {
		t.Error("Expected rejection response to not be granted")
	}
	if rejection.StatusString() != "rejection" {
		t.Errorf("Expected 'rejection', got '%s'", rejection.StatusString())
	}
}

func TestResponseMarshal(t *testing.T) {
	resp := NewRejectionResponse(FailBadRequest, "test error")
	data, err := resp.Marshal()
	if err != nil {
		t.Fatalf("Failed to marshal response: %v", err)
	}
	if len(data) == 0 {
		t.Error("Marshal returned empty data")
	}

	// Parse it back
	parsed, err := ParseResponse(data)
	if err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}
	if parsed.IsGranted() {
		t.Error("Expected rejection response")
	}
}

func TestNewMessageImprint(t *testing.T) {
	hash := sha256.Sum256([]byte("test"))
	imprint := NewMessageImprint(crypto.SHA256, hash[:])

	if !imprint.HashAlgorithm.Algorithm.Equal(cms.OIDSHA256) {
		t.Error("Hash algorithm OID mismatch")
	}
	if len(imprint.HashedMessage) != 32 {
		t.Errorf("Expected 32 bytes, got %d", len(imprint.HashedMessage))
	}
}

func TestRandomSerialGenerator(t *testing.T) {
	gen := &RandomSerialGenerator{}

	// Generate multiple serials
	serials := make(map[string]bool)
	for i := 0; i < 100; i++ {
		serial, err := gen.Next()
		if err != nil {
			t.Fatalf("Failed to generate serial: %v", err)
		}
		if serial == nil {
			t.Fatal("Serial is nil")
		}

		key := serial.String()
		if serials[key] {
			t.Error("Duplicate serial number generated")
		}
		serials[key] = true
	}
}

func TestAccuracyIsZero(t *testing.T) {
	zero := Accuracy{}
	if !zero.IsZero() {
		t.Error("Expected zero accuracy to be zero")
	}

	nonZero := Accuracy{Seconds: 1}
	if nonZero.IsZero() {
		t.Error("Expected non-zero accuracy to not be zero")
	}
}

func TestGetHashLength(t *testing.T) {
	tests := []struct {
		oid      asn1.ObjectIdentifier
		expected int
	}{
		{cms.OIDSHA256, 32},
		{cms.OIDSHA384, 48},
		{cms.OIDSHA512, 64},
		{cms.OIDSHA3_256, 32},
		{cms.OIDSHA3_384, 48},
		{cms.OIDSHA3_512, 64},
		{cms.OIDSHAKE256, 32},
	}

	for _, test := range tests {
		length := getHashLength(test.oid)
		if length != test.expected {
			t.Errorf("OID %v: expected %d, got %d", test.oid, test.expected, length)
		}
	}
}

func TestValidateHashAlgorithm(t *testing.T) {
	// Valid algorithms
	validOIDs := []asn1.ObjectIdentifier{
		cms.OIDSHA256,
		cms.OIDSHA384,
		cms.OIDSHA512,
		cms.OIDSHA3_256,
		cms.OIDSHA3_384,
		cms.OIDSHA3_512,
		cms.OIDSHAKE256,
	}

	for _, oid := range validOIDs {
		if err := validateHashAlgorithm(oid); err != nil {
			t.Errorf("Expected OID %v to be valid, got error: %v", oid, err)
		}
	}

	// Invalid algorithm
	invalidOID := asn1.ObjectIdentifier{1, 2, 3, 4}
	if err := validateHashAlgorithm(invalidOID); err == nil {
		t.Error("Expected error for invalid OID")
	}
}
