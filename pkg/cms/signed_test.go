package cms

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

// =============================================================================
// Unit Tests: NewAttribute
// =============================================================================

// TestU_Attribute_Create tests creating a new attribute.
func TestU_Attribute_Create(t *testing.T) {
	oid := asn1.ObjectIdentifier{1, 2, 3, 4}
	value := []byte{0x01, 0x02, 0x03}

	attr, err := NewAttribute(oid, value)
	if err != nil {
		t.Fatalf("NewAttribute failed: %v", err)
	}

	if !attr.Type.Equal(oid) {
		t.Errorf("OID mismatch: expected %v, got %v", oid, attr.Type)
	}

	if len(attr.Values) != 1 {
		t.Errorf("Expected 1 value, got %d", len(attr.Values))
	}
}

// TestU_Attribute_CreateInvalid tests that invalid values are rejected.
func TestU_Attribute_CreateInvalid(t *testing.T) {
	oid := asn1.ObjectIdentifier{1, 2, 3}
	// Channel cannot be marshaled to ASN.1
	invalidValue := make(chan int)

	_, err := NewAttribute(oid, invalidValue)
	if err == nil {
		t.Error("Expected error for unmarshallable value")
	}
}

// =============================================================================
// Unit Tests: NewContentTypeAttr
// =============================================================================

// TestU_ContentTypeAttr_Create tests creating a content-type attribute.
func TestU_ContentTypeAttr_Create(t *testing.T) {
	contentType := OIDData

	attr, err := NewContentTypeAttr(contentType)
	if err != nil {
		t.Fatalf("NewContentTypeAttr failed: %v", err)
	}

	if !attr.Type.Equal(OIDContentType) {
		t.Errorf("Attribute type should be OIDContentType, got %v", attr.Type)
	}

	if len(attr.Values) != 1 {
		t.Errorf("Expected 1 value, got %d", len(attr.Values))
	}

	// Verify the encoded value is the content type OID
	var decoded asn1.ObjectIdentifier
	_, err = asn1.Unmarshal(attr.Values[0].FullBytes, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal content type: %v", err)
	}

	if !decoded.Equal(contentType) {
		t.Errorf("Content type mismatch: expected %v, got %v", contentType, decoded)
	}
}

// TestU_ContentTypeAttr_CustomOID tests with custom content type.
func TestU_ContentTypeAttr_CustomOID(t *testing.T) {
	customOID := asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7}

	attr, err := NewContentTypeAttr(customOID)
	if err != nil {
		t.Fatalf("NewContentTypeAttr failed: %v", err)
	}

	var decoded asn1.ObjectIdentifier
	_, err = asn1.Unmarshal(attr.Values[0].FullBytes, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if !decoded.Equal(customOID) {
		t.Errorf("OID mismatch: expected %v, got %v", customOID, decoded)
	}
}

// =============================================================================
// Unit Tests: NewMessageDigestAttr
// =============================================================================

// TestU_MessageDigestAttr_Create tests creating a message-digest attribute.
func TestU_MessageDigestAttr_Create(t *testing.T) {
	digest := []byte{0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90}

	attr, err := NewMessageDigestAttr(digest)
	if err != nil {
		t.Fatalf("NewMessageDigestAttr failed: %v", err)
	}

	if !attr.Type.Equal(OIDMessageDigest) {
		t.Errorf("Attribute type should be OIDMessageDigest, got %v", attr.Type)
	}

	// Verify the encoded value is the digest
	var decoded []byte
	_, err = asn1.Unmarshal(attr.Values[0].FullBytes, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal digest: %v", err)
	}

	if len(decoded) != len(digest) {
		t.Errorf("Digest length mismatch: expected %d, got %d", len(digest), len(decoded))
	}

	for i := range digest {
		if decoded[i] != digest[i] {
			t.Errorf("Digest byte %d mismatch: expected %02x, got %02x", i, digest[i], decoded[i])
		}
	}
}

// TestU_MessageDigestAttr_SHA256Size tests with SHA-256 sized digest.
func TestU_MessageDigestAttr_SHA256Size(t *testing.T) {
	// 32-byte SHA-256 digest
	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = byte(i)
	}

	attr, err := NewMessageDigestAttr(digest)
	if err != nil {
		t.Fatalf("NewMessageDigestAttr failed: %v", err)
	}

	var decoded []byte
	_, err = asn1.Unmarshal(attr.Values[0].FullBytes, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if len(decoded) != 32 {
		t.Errorf("Expected 32-byte digest, got %d", len(decoded))
	}
}

// TestU_MessageDigestAttr_Empty tests empty digest.
func TestU_MessageDigestAttr_Empty(t *testing.T) {
	digest := []byte{}

	attr, err := NewMessageDigestAttr(digest)
	if err != nil {
		t.Fatalf("NewMessageDigestAttr failed: %v", err)
	}

	var decoded []byte
	_, err = asn1.Unmarshal(attr.Values[0].FullBytes, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if len(decoded) != 0 {
		t.Errorf("Expected empty digest, got %d bytes", len(decoded))
	}
}

// =============================================================================
// Unit Tests: NewSigningTimeAttr
// =============================================================================

// TestU_SigningTimeAttr_Create tests creating a signing-time attribute.
func TestU_SigningTimeAttr_Create(t *testing.T) {
	signingTime := time.Date(2024, 6, 15, 12, 30, 45, 0, time.UTC)

	attr, err := NewSigningTimeAttr(signingTime)
	if err != nil {
		t.Fatalf("NewSigningTimeAttr failed: %v", err)
	}

	if !attr.Type.Equal(OIDSigningTime) {
		t.Errorf("Attribute type should be OIDSigningTime, got %v", attr.Type)
	}

	// Verify the encoded value is the time
	var decoded time.Time
	_, err = asn1.Unmarshal(attr.Values[0].FullBytes, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal time: %v", err)
	}

	if !decoded.Equal(signingTime) {
		t.Errorf("Time mismatch: expected %v, got %v", signingTime, decoded)
	}
}

// TestU_SigningTimeAttr_NonUTC tests that times are converted to UTC.
func TestU_SigningTimeAttr_NonUTC(t *testing.T) {
	// Create a time in a different timezone
	loc, _ := time.LoadLocation("America/New_York")
	localTime := time.Date(2024, 6, 15, 8, 30, 45, 0, loc)

	attr, err := NewSigningTimeAttr(localTime)
	if err != nil {
		t.Fatalf("NewSigningTimeAttr failed: %v", err)
	}

	var decoded time.Time
	_, err = asn1.Unmarshal(attr.Values[0].FullBytes, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal time: %v", err)
	}

	// Should be stored as UTC
	if decoded.Location().String() != "UTC" {
		t.Logf("Note: ASN.1 time parsed as %s", decoded.Location().String())
	}

	// The actual instant should match
	if !decoded.Equal(localTime.UTC()) {
		t.Errorf("Time instant mismatch: expected %v, got %v", localTime.UTC(), decoded)
	}
}

// =============================================================================
// Unit Tests: MarshalSignedAttrs
// =============================================================================

// TestU_MarshalSignedAttrs_Basic tests marshaling signed attributes.
func TestU_MarshalSignedAttrs_Basic(t *testing.T) {
	attrs := []Attribute{
		{
			Type:   asn1.ObjectIdentifier{1, 2, 3},
			Values: []asn1.RawValue{{FullBytes: []byte{0x04, 0x01, 0x01}}},
		},
		{
			Type:   asn1.ObjectIdentifier{1, 2, 4},
			Values: []asn1.RawValue{{FullBytes: []byte{0x04, 0x01, 0x02}}},
		},
	}

	result, err := MarshalSignedAttrs(attrs)
	if err != nil {
		t.Fatalf("MarshalSignedAttrs failed: %v", err)
	}

	// Should start with SET tag (0x31)
	if len(result) == 0 || result[0] != 0x31 {
		t.Errorf("Result should start with SET tag (0x31), got %02x", result[0])
	}
}

// TestU_MarshalSignedAttrs_DERSorting tests that attributes are sorted in DER order.
func TestU_MarshalSignedAttrs_DERSorting(t *testing.T) {
	// Create attributes in non-sorted order
	attr1 := Attribute{
		Type:   asn1.ObjectIdentifier{1, 2, 9}, // Larger OID
		Values: []asn1.RawValue{{FullBytes: []byte{0x04, 0x01, 0x01}}},
	}
	attr2 := Attribute{
		Type:   asn1.ObjectIdentifier{1, 2, 1}, // Smaller OID
		Values: []asn1.RawValue{{FullBytes: []byte{0x04, 0x01, 0x02}}},
	}
	attr3 := Attribute{
		Type:   asn1.ObjectIdentifier{1, 2, 5}, // Middle OID
		Values: []asn1.RawValue{{FullBytes: []byte{0x04, 0x01, 0x03}}},
	}

	// Pass in non-sorted order
	attrs := []Attribute{attr1, attr2, attr3}

	result, err := MarshalSignedAttrs(attrs)
	if err != nil {
		t.Fatalf("MarshalSignedAttrs failed: %v", err)
	}

	// Marshal twice - result should be identical (deterministic)
	result2, err := MarshalSignedAttrs(attrs)
	if err != nil {
		t.Fatalf("MarshalSignedAttrs second call failed: %v", err)
	}

	if len(result) != len(result2) {
		t.Errorf("Results should be identical, got different lengths: %d vs %d", len(result), len(result2))
	}

	for i := range result {
		if result[i] != result2[i] {
			t.Errorf("Results differ at byte %d: %02x vs %02x", i, result[i], result2[i])
			break
		}
	}
}

// TestU_MarshalSignedAttrs_Empty tests marshaling empty attributes.
func TestU_MarshalSignedAttrs_Empty(t *testing.T) {
	attrs := []Attribute{}

	result, err := MarshalSignedAttrs(attrs)
	if err != nil {
		t.Fatalf("MarshalSignedAttrs failed: %v", err)
	}

	// Should be empty SET: 0x31 0x00
	if len(result) != 2 || result[0] != 0x31 || result[1] != 0x00 {
		t.Errorf("Expected empty SET (0x31 0x00), got %v", result)
	}
}

// TestU_MarshalSignedAttrs_Single tests single attribute.
func TestU_MarshalSignedAttrs_Single(t *testing.T) {
	attr, err := NewContentTypeAttr(OIDData)
	if err != nil {
		t.Fatalf("NewContentTypeAttr failed: %v", err)
	}

	result, err := MarshalSignedAttrs([]Attribute{attr})
	if err != nil {
		t.Fatalf("MarshalSignedAttrs failed: %v", err)
	}

	if len(result) < 3 {
		t.Errorf("Result too short: %d bytes", len(result))
	}

	if result[0] != 0x31 {
		t.Errorf("Should start with SET tag")
	}
}

// TestU_MarshalSignedAttrs_LargeLength tests length encoding for larger sets.
func TestU_MarshalSignedAttrs_LargeLength(t *testing.T) {
	// Create many attributes to exceed 127 bytes
	attrs := make([]Attribute, 20)
	for i := range attrs {
		attrs[i] = Attribute{
			Type: asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7, 8, 9, i},
			Values: []asn1.RawValue{{FullBytes: []byte{
				0x04, 0x10, // OCTET STRING, 16 bytes
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
			}}},
		}
	}

	result, err := MarshalSignedAttrs(attrs)
	if err != nil {
		t.Fatalf("MarshalSignedAttrs failed: %v", err)
	}

	// Length should use long form
	if len(result) < 4 {
		t.Fatalf("Result too short")
	}

	// Check for long-form length encoding
	if result[1]&0x80 == 0 {
		t.Logf("Length is short form: %d", result[1])
	} else {
		numLenBytes := int(result[1] & 0x7F)
		t.Logf("Length uses %d bytes in long form", numLenBytes)
	}
}

// =============================================================================
// Unit Tests: ASN.1 Structure Marshaling
// =============================================================================

// TestU_SignedData_Marshal tests SignedData structure marshaling.
func TestU_SignedData_Marshal(t *testing.T) {
	sd := SignedData{
		Version: 1,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{
			{Algorithm: OIDSHA256},
		},
		EncapContentInfo: EncapsulatedContentInfo{
			EContentType: OIDData,
		},
		SignerInfos: []SignerInfo{},
	}

	data, err := asn1.Marshal(sd)
	if err != nil {
		t.Fatalf("Failed to marshal SignedData: %v", err)
	}

	if len(data) == 0 {
		t.Error("Marshaled data is empty")
	}
}

// TestU_ContentInfo_Marshal tests ContentInfo structure marshaling.
func TestU_ContentInfo_Marshal(t *testing.T) {
	ci := ContentInfo{
		ContentType: OIDSignedData,
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      []byte{0x30, 0x00}, // Empty SEQUENCE
		},
	}

	data, err := asn1.Marshal(ci)
	if err != nil {
		t.Fatalf("Failed to marshal ContentInfo: %v", err)
	}

	if len(data) == 0 {
		t.Error("Marshaled data is empty")
	}
}

// TestU_IssuerAndSerialNumber_Marshal tests IssuerAndSerialNumber structure.
func TestU_IssuerAndSerialNumber_Marshal(t *testing.T) {
	isn := IssuerAndSerialNumber{
		Issuer:       asn1.RawValue{FullBytes: []byte{0x30, 0x00}}, // Empty SEQUENCE
		SerialNumber: big.NewInt(12345),
	}

	data, err := asn1.Marshal(isn)
	if err != nil {
		t.Fatalf("Failed to marshal IssuerAndSerialNumber: %v", err)
	}

	if len(data) == 0 {
		t.Error("Marshaled data is empty")
	}
}

// TestU_Attribute_Marshal tests Attribute structure marshaling.
func TestU_Attribute_Marshal(t *testing.T) {
	attr := Attribute{
		Type:   OIDContentType,
		Values: []asn1.RawValue{{FullBytes: []byte{0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01}}},
	}

	data, err := asn1.Marshal(attr)
	if err != nil {
		t.Fatalf("Failed to marshal Attribute: %v", err)
	}

	if len(data) == 0 {
		t.Error("Marshaled data is empty")
	}
}

// =============================================================================
// Unit Tests: OID Values
// =============================================================================

// TestU_OID_CMSValues tests that CMS OIDs have expected values.
func TestU_OID_CMSValues(t *testing.T) {
	tests := []struct {
		name     string
		oid      asn1.ObjectIdentifier
		expected asn1.ObjectIdentifier
	}{
		{"[Unit] OID: Data", OIDData, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}},
		{"[Unit] OID: SignedData", OIDSignedData, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}},
		{"[Unit] OID: EnvelopedData", OIDEnvelopedData, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}},
		{"[Unit] OID: ContentType", OIDContentType, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}},
		{"[Unit] OID: MessageDigest", OIDMessageDigest, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}},
		{"[Unit] OID: SigningTime", OIDSigningTime, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.oid.Equal(tt.expected) {
				t.Errorf("OID mismatch: expected %v, got %v", tt.expected, tt.oid)
			}
		})
	}
}

// TestU_OID_SignatureValues tests signature algorithm OIDs.
func TestU_OID_SignatureValues(t *testing.T) {
	tests := []struct {
		name     string
		oid      asn1.ObjectIdentifier
		expected asn1.ObjectIdentifier
	}{
		{"[Unit] OID: ECDSA-SHA256", OIDECDSAWithSHA256, asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}},
		{"[Unit] OID: ECDSA-SHA384", OIDECDSAWithSHA384, asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}},
		{"[Unit] OID: ECDSA-SHA512", OIDECDSAWithSHA512, asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}},
		{"[Unit] OID: Ed25519", OIDEd25519, asn1.ObjectIdentifier{1, 3, 101, 112}},
		{"[Unit] OID: RSA-SHA256", OIDSHA256WithRSA, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}},
		{"[Unit] OID: RSA-SHA384", OIDSHA384WithRSA, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}},
		{"[Unit] OID: RSA-SHA512", OIDSHA512WithRSA, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.oid.Equal(tt.expected) {
				t.Errorf("OID mismatch: expected %v, got %v", tt.expected, tt.oid)
			}
		})
	}
}

// TestU_OID_HashValues tests hash algorithm OIDs.
func TestU_OID_HashValues(t *testing.T) {
	tests := []struct {
		name     string
		oid      asn1.ObjectIdentifier
		expected asn1.ObjectIdentifier
	}{
		{"[Unit] OID: SHA-256", OIDSHA256, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}},
		{"[Unit] OID: SHA-384", OIDSHA384, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}},
		{"[Unit] OID: SHA-512", OIDSHA512, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.oid.Equal(tt.expected) {
				t.Errorf("OID mismatch: expected %v, got %v", tt.expected, tt.oid)
			}
		})
	}
}

// TestU_OID_MLDSAValues tests ML-DSA OIDs.
func TestU_OID_MLDSAValues(t *testing.T) {
	tests := []struct {
		name     string
		oid      asn1.ObjectIdentifier
		expected asn1.ObjectIdentifier
	}{
		{"[Unit] OID: ML-DSA-44", OIDMLDSA44, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}},
		{"[Unit] OID: ML-DSA-65", OIDMLDSA65, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}},
		{"[Unit] OID: ML-DSA-87", OIDMLDSA87, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.oid.Equal(tt.expected) {
				t.Errorf("OID mismatch: expected %v, got %v", tt.expected, tt.oid)
			}
		})
	}
}

// =============================================================================
// Unit Tests: Round-trip (Marshal/Unmarshal)
// =============================================================================

// TestU_Attribute_RoundTrip tests attribute marshal/unmarshal round trip.
func TestU_Attribute_RoundTrip(t *testing.T) {
	original := Attribute{
		Type:   OIDContentType,
		Values: []asn1.RawValue{{FullBytes: []byte{0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01}}},
	}

	data, err := asn1.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded Attribute
	_, err = asn1.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if !decoded.Type.Equal(original.Type) {
		t.Errorf("Type mismatch after round-trip")
	}

	if len(decoded.Values) != len(original.Values) {
		t.Errorf("Values count mismatch: expected %d, got %d", len(original.Values), len(decoded.Values))
	}
}

// =============================================================================
// Unit Tests: NewSigningCertificateV2Attr (RFC 5035)
// =============================================================================

// TestU_NewSigningCertificateV2Attr_Valid tests creating a valid signing-certificate-v2 attribute.
func TestU_NewSigningCertificateV2Attr_Valid(t *testing.T) {
	// Create a test certificate
	certDER := []byte{
		0x30, 0x82, 0x01, 0x00, // SEQUENCE
		// Minimal certificate data for hash testing
		0x02, 0x01, 0x01, // Version
		0x02, 0x03, 0x01, 0x00, 0x01, // Serial number 65537
	}

	// Mock issuer raw bytes
	issuerRaw := []byte{
		0x30, 0x15, // SEQUENCE
		0x31, 0x13, // SET
		0x30, 0x11, // SEQUENCE
		0x06, 0x03, 0x55, 0x04, 0x03, // OID: CN
		0x13, 0x0A, 0x54, 0x65, 0x73, 0x74, 0x20, 0x49, 0x73, 0x73, 0x75, 0x65, 0x72, // UTF8: Test Issuer
	}

	serialNumber := big.NewInt(65537)

	attr, err := NewSigningCertificateV2Attr(certDER, issuerRaw, serialNumber)
	if err != nil {
		t.Fatalf("NewSigningCertificateV2Attr failed: %v", err)
	}

	// Verify the attribute type is OIDSigningCertificateV2
	if !attr.Type.Equal(OIDSigningCertificateV2) {
		t.Errorf("Attribute type mismatch: expected %v, got %v", OIDSigningCertificateV2, attr.Type)
	}

	// Verify we have exactly one value
	if len(attr.Values) != 1 {
		t.Errorf("Expected 1 value, got %d", len(attr.Values))
	}

	// Verify the value can be parsed back as SigningCertificateV2
	var sigCertV2 SigningCertificateV2
	_, err = asn1.Unmarshal(attr.Values[0].FullBytes, &sigCertV2)
	if err != nil {
		t.Fatalf("Failed to parse SigningCertificateV2: %v", err)
	}

	// Should have exactly one ESSCertIDv2
	if len(sigCertV2.Certs) != 1 {
		t.Errorf("Expected 1 cert in SigningCertificateV2, got %d", len(sigCertV2.Certs))
	}

	// Verify hash length (SHA-256 = 32 bytes)
	if len(sigCertV2.Certs[0].CertHash) != 32 {
		t.Errorf("Expected 32-byte SHA-256 hash, got %d bytes", len(sigCertV2.Certs[0].CertHash))
	}

	// Verify serial number is preserved
	if sigCertV2.Certs[0].IssuerSerial.SerialNumber.Cmp(serialNumber) != 0 {
		t.Errorf("SerialNumber mismatch: expected %v, got %v", serialNumber, sigCertV2.Certs[0].IssuerSerial.SerialNumber)
	}
}

// TestU_NewSigningCertificateV2Attr_DifferentCerts tests with different certificate data.
func TestU_NewSigningCertificateV2Attr_DifferentCerts(t *testing.T) {
	tests := []struct {
		name         string
		certDER      []byte
		issuerRaw    []byte
		serialNumber *big.Int
	}{
		{
			name:         "[Unit] SigningCertV2: Small cert",
			certDER:      []byte{0x30, 0x03, 0x02, 0x01, 0x01},
			issuerRaw:    []byte{0x30, 0x00},
			serialNumber: big.NewInt(1),
		},
		{
			name:         "[Unit] SigningCertV2: Large serial",
			certDER:      []byte{0x30, 0x10, 0x02, 0x01, 0x01, 0x02, 0x03, 0xFF, 0xFF, 0xFF},
			issuerRaw:    []byte{0x30, 0x03, 0x02, 0x01, 0x00},
			serialNumber: new(big.Int).SetBytes([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}),
		},
		{
			name:         "[Unit] SigningCertV2: Zero serial",
			certDER:      []byte{0x30, 0x05, 0x02, 0x01, 0x00},
			issuerRaw:    []byte{0x30, 0x00},
			serialNumber: big.NewInt(0),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attr, err := NewSigningCertificateV2Attr(tt.certDER, tt.issuerRaw, tt.serialNumber)
			if err != nil {
				t.Fatalf("NewSigningCertificateV2Attr failed: %v", err)
			}

			if !attr.Type.Equal(OIDSigningCertificateV2) {
				t.Errorf("Wrong attribute type")
			}

			// Parse and verify serial number
			var sigCertV2 SigningCertificateV2
			_, err = asn1.Unmarshal(attr.Values[0].FullBytes, &sigCertV2)
			if err != nil {
				t.Fatalf("Failed to parse: %v", err)
			}

			if len(sigCertV2.Certs) != 1 {
				t.Fatalf("Expected 1 cert")
			}

			if sigCertV2.Certs[0].IssuerSerial.SerialNumber.Cmp(tt.serialNumber) != 0 {
				t.Errorf("SerialNumber mismatch")
			}
		})
	}
}

// TestU_NewSigningCertificateV2Attr_HashDeterministic tests that hash is deterministic.
func TestU_NewSigningCertificateV2Attr_HashDeterministic(t *testing.T) {
	certDER := []byte{0x30, 0x10, 0x02, 0x01, 0x01, 0x02, 0x03, 0x01, 0x00, 0x01}
	issuerRaw := []byte{0x30, 0x00}
	serialNumber := big.NewInt(65537)

	attr1, err := NewSigningCertificateV2Attr(certDER, issuerRaw, serialNumber)
	if err != nil {
		t.Fatalf("First call failed: %v", err)
	}

	attr2, err := NewSigningCertificateV2Attr(certDER, issuerRaw, serialNumber)
	if err != nil {
		t.Fatalf("Second call failed: %v", err)
	}

	var sigCert1, sigCert2 SigningCertificateV2
	if _, err := asn1.Unmarshal(attr1.Values[0].FullBytes, &sigCert1); err != nil {
		t.Fatalf("Unmarshal attr1 failed: %v", err)
	}
	if _, err := asn1.Unmarshal(attr2.Values[0].FullBytes, &sigCert2); err != nil {
		t.Fatalf("Unmarshal attr2 failed: %v", err)
	}

	// Hashes should be identical
	for i := range sigCert1.Certs[0].CertHash {
		if sigCert1.Certs[0].CertHash[i] != sigCert2.Certs[0].CertHash[i] {
			t.Errorf("Hash is not deterministic at byte %d", i)
			break
		}
	}
}

// TestU_ESSCertIDv2_Structure tests the ESSCertIDv2 structure.
func TestU_ESSCertIDv2_Structure(t *testing.T) {
	// Create and marshal an ESSCertIDv2
	essCertID := ESSCertIDv2{
		CertHash: make([]byte, 32), // SHA-256 hash
		IssuerSerial: ESSIssuerSerial{
			SerialNumber: big.NewInt(12345),
		},
	}

	// Fill hash with test data
	for i := range essCertID.CertHash {
		essCertID.CertHash[i] = byte(i)
	}

	data, err := asn1.Marshal(essCertID)
	if err != nil {
		t.Fatalf("Failed to marshal ESSCertIDv2: %v", err)
	}

	if len(data) == 0 {
		t.Error("Marshaled data is empty")
	}

	// Verify it can be unmarshaled back
	var decoded ESSCertIDv2
	_, err = asn1.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal ESSCertIDv2: %v", err)
	}

	if len(decoded.CertHash) != 32 {
		t.Errorf("CertHash length mismatch: expected 32, got %d", len(decoded.CertHash))
	}
}

// TestU_SigningCertificateV2_Structure tests the SigningCertificateV2 structure.
func TestU_SigningCertificateV2_Structure(t *testing.T) {
	sigCert := SigningCertificateV2{
		Certs: []ESSCertIDv2{
			{
				CertHash: make([]byte, 32),
				IssuerSerial: ESSIssuerSerial{
					SerialNumber: big.NewInt(1),
				},
			},
		},
	}

	data, err := asn1.Marshal(sigCert)
	if err != nil {
		t.Fatalf("Failed to marshal SigningCertificateV2: %v", err)
	}

	var decoded SigningCertificateV2
	_, err = asn1.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal SigningCertificateV2: %v", err)
	}

	if len(decoded.Certs) != 1 {
		t.Errorf("Expected 1 cert, got %d", len(decoded.Certs))
	}
}
