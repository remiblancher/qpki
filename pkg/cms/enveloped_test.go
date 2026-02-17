package cms

import (
	"crypto/elliptic"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
)

// =============================================================================
// RecipientIdentifierFromCert Tests
// =============================================================================

func TestU_RecipientIdentifierFromCert(t *testing.T) {
	serialNumber := big.NewInt(12345)
	issuerRaw := []byte{0x30, 0x10, 0x31, 0x0e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x05, 0x54, 0x65, 0x73, 0x74}

	rid := RecipientIdentifierFromCert(serialNumber, issuerRaw)

	if rid.IssuerAndSerial == nil {
		t.Fatal("IssuerAndSerial is nil")
	}
	if rid.IssuerAndSerial.SerialNumber.Cmp(serialNumber) != 0 {
		t.Errorf("SerialNumber = %v, want %v", rid.IssuerAndSerial.SerialNumber, serialNumber)
	}
	if string(rid.IssuerAndSerial.Issuer.FullBytes) != string(issuerRaw) {
		t.Errorf("Issuer bytes mismatch")
	}
}

func TestU_RecipientIdentifierFromCert_LargeSerial(t *testing.T) {
	// Test with a large serial number
	serialNumber := new(big.Int)
	serialNumber.SetString("123456789012345678901234567890", 10)
	issuerRaw := []byte{0x30, 0x00}

	rid := RecipientIdentifierFromCert(serialNumber, issuerRaw)

	if rid.IssuerAndSerial.SerialNumber.Cmp(serialNumber) != 0 {
		t.Errorf("SerialNumber = %v, want %v", rid.IssuerAndSerial.SerialNumber, serialNumber)
	}
}

// =============================================================================
// ParseRecipientInfo Tests
// =============================================================================

func TestU_ParseRecipientInfo_KeyTransRecipientInfo(t *testing.T) {
	kp := generateRSAKeyPair(t, 2048)
	cert := generateTestCertificate(t, kp)

	// Create a KeyTransRecipientInfo
	ktri := KeyTransRecipientInfo{
		Version: 0,
		RID: RecipientIdentifier{
			IssuerAndSerial: &IssuerAndSerialNumber{
				Issuer:       asn1.RawValue{FullBytes: cert.RawIssuer},
				SerialNumber: cert.SerialNumber,
			},
		},
		KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: OIDRSAES,
		},
		EncryptedKey: []byte{0x01, 0x02, 0x03},
	}

	// Marshal it
	data, err := MarshalKeyTransRecipientInfo(&ktri)
	if err != nil {
		t.Fatalf("MarshalKeyTransRecipientInfo() error = %v", err)
	}

	// Parse as RawValue
	raw := asn1.RawValue{
		Tag:       asn1.TagSequence,
		FullBytes: data,
	}

	result, err := ParseRecipientInfo(raw)
	if err != nil {
		t.Fatalf("ParseRecipientInfo() error = %v", err)
	}

	parsed, ok := result.(*KeyTransRecipientInfo)
	if !ok {
		t.Fatalf("ParseRecipientInfo() returned %T, want *KeyTransRecipientInfo", result)
	}

	if parsed.Version != ktri.Version {
		t.Errorf("Version = %d, want %d", parsed.Version, ktri.Version)
	}
}

func TestU_ParseRecipientInfo_KeyAgreeRecipientInfo(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	// Create recipient encrypted key
	rek := RecipientEncryptedKey{
		RID: KeyAgreeRecipientIdentifier{
			IssuerAndSerial: &IssuerAndSerialNumber{
				Issuer:       asn1.RawValue{FullBytes: cert.RawIssuer},
				SerialNumber: cert.SerialNumber,
			},
		},
		EncryptedKey: []byte{0x01, 0x02, 0x03},
	}

	// Build originator as OriginatorPublicKey [1]
	originatorPubKey := OriginatorPublicKey{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}, // id-ecPublicKey
			Parameters: asn1.RawValue{
				FullBytes: []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}, // P-256 OID
			},
		},
		PublicKey: asn1.BitString{Bytes: []byte{0x04, 0x01, 0x02, 0x03}},
	}

	// Marshal originator public key and wrap with [1] tag
	originatorBytes, err := asn1.Marshal(originatorPubKey)
	if err != nil {
		t.Fatalf("Failed to marshal originator: %v", err)
	}

	kari := KeyAgreeRecipientInfo{
		Version: 3,
		Originator: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        1,
			IsCompound: true,
			Bytes:      originatorBytes,
		},
		UKM: nil,
		KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: OIDAESWrap256,
		},
		RecipientEncryptedKeys: []RecipientEncryptedKey{rek},
	}

	// Marshal it - returns bytes starting with [1] IMPLICIT tag (0xa1)
	data, err := MarshalKeyAgreeRecipientInfo(&kari)
	if err != nil {
		t.Fatalf("MarshalKeyAgreeRecipientInfo() error = %v", err)
	}

	// Parse the marshaled data to get a RawValue for ParseRecipientInfo
	// MarshalKeyAgreeRecipientInfo returns [1] IMPLICIT SEQUENCE, so we parse it
	var raw asn1.RawValue
	_, err = asn1.Unmarshal(data, &raw)
	if err != nil {
		t.Fatalf("Failed to unmarshal marshaled KARI: %v", err)
	}

	result, err := ParseRecipientInfo(raw)
	if err != nil {
		t.Fatalf("ParseRecipientInfo() error = %v", err)
	}

	parsed, ok := result.(*KeyAgreeRecipientInfo)
	if !ok {
		t.Fatalf("ParseRecipientInfo() returned %T, want *KeyAgreeRecipientInfo", result)
	}

	if parsed.Version != kari.Version {
		t.Errorf("Version = %d, want %d", parsed.Version, kari.Version)
	}
}

func TestU_ParseRecipientInfo_UnsupportedType(t *testing.T) {
	// Use an unsupported tag (e.g., tag 5)
	raw := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        5,
		IsCompound: true,
		Bytes:      []byte{0x01, 0x02, 0x03},
	}

	_, err := ParseRecipientInfo(raw)
	if err == nil {
		t.Error("ParseRecipientInfo() should fail for unsupported type")
	}
}

// =============================================================================
// RecipientIdentifier Marshal Tests
// =============================================================================

func TestU_RecipientIdentifier_Marshal_IssuerAndSerial(t *testing.T) {
	rid := RecipientIdentifier{
		IssuerAndSerial: &IssuerAndSerialNumber{
			Issuer:       asn1.RawValue{FullBytes: []byte{0x30, 0x00}},
			SerialNumber: big.NewInt(12345),
		},
	}

	data, err := rid.Marshal()
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	if len(data) == 0 {
		t.Error("Marshal() returned empty data")
	}
}

func TestU_RecipientIdentifier_Marshal_SubjectKeyIdentifier(t *testing.T) {
	ski := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a}
	rid := RecipientIdentifier{
		SKI: ski,
	}

	data, err := rid.Marshal()
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	if len(data) == 0 {
		t.Error("Marshal() returned empty data")
	}
}

func TestU_RecipientIdentifier_Marshal_NeitherSet(t *testing.T) {
	rid := RecipientIdentifier{}

	_, err := rid.Marshal()
	if err == nil {
		t.Error("Marshal() should fail when neither IssuerAndSerial nor SKI is set")
	}
}

// =============================================================================
// KeyAgreeRecipientIdentifier Marshal Tests
// =============================================================================

func TestU_KeyAgreeRecipientIdentifier_Marshal_IssuerAndSerial(t *testing.T) {
	karid := KeyAgreeRecipientIdentifier{
		IssuerAndSerial: &IssuerAndSerialNumber{
			Issuer:       asn1.RawValue{FullBytes: []byte{0x30, 0x00}},
			SerialNumber: big.NewInt(54321),
		},
	}

	data, err := karid.Marshal()
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	if len(data) == 0 {
		t.Error("Marshal() returned empty data")
	}
}

func TestU_KeyAgreeRecipientIdentifier_Marshal_RecipientKeyId(t *testing.T) {
	karid := KeyAgreeRecipientIdentifier{
		RKeyID: &RecipientKeyIdentifier{
			SubjectKeyIdentifier: []byte{0x01, 0x02, 0x03, 0x04, 0x05},
		},
	}

	data, err := karid.Marshal()
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	if len(data) == 0 {
		t.Error("Marshal() returned empty data")
	}
}

func TestU_KeyAgreeRecipientIdentifier_Marshal_NeitherSet(t *testing.T) {
	karid := KeyAgreeRecipientIdentifier{}

	_, err := karid.Marshal()
	if err == nil {
		t.Error("Marshal() should fail when neither IssuerAndSerial nor RKeyID is set")
	}
}

// =============================================================================
// ParseRecipientIdentifier Tests
// =============================================================================

func TestU_ParseRecipientIdentifier_IssuerAndSerial(t *testing.T) {
	// Create and marshal IssuerAndSerialNumber
	ias := IssuerAndSerialNumber{
		Issuer:       asn1.RawValue{FullBytes: []byte{0x30, 0x00}},
		SerialNumber: big.NewInt(12345),
	}
	data, err := asn1.Marshal(ias)
	if err != nil {
		t.Fatalf("Failed to marshal IssuerAndSerialNumber: %v", err)
	}

	rid, rest, err := ParseRecipientIdentifier(data)
	if err != nil {
		t.Fatalf("ParseRecipientIdentifier() error = %v", err)
	}

	if len(rest) != 0 {
		t.Errorf("ParseRecipientIdentifier() rest = %d bytes, want 0", len(rest))
	}

	if rid.IssuerAndSerial == nil {
		t.Fatal("IssuerAndSerial is nil")
	}
	if rid.IssuerAndSerial.SerialNumber.Cmp(big.NewInt(12345)) != 0 {
		t.Errorf("SerialNumber = %v, want 12345", rid.IssuerAndSerial.SerialNumber)
	}
}

func TestU_ParseRecipientIdentifier_SKI(t *testing.T) {
	// Create a [0] tagged SKI
	ski := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	data, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: false,
		Bytes:      ski,
	})
	if err != nil {
		t.Fatalf("Failed to marshal SKI: %v", err)
	}

	rid, rest, err := ParseRecipientIdentifier(data)
	if err != nil {
		t.Fatalf("ParseRecipientIdentifier() error = %v", err)
	}

	if len(rest) != 0 {
		t.Errorf("ParseRecipientIdentifier() rest = %d bytes, want 0", len(rest))
	}

	if rid.SKI == nil {
		t.Fatal("SKI is nil")
	}
	if string(rid.SKI) != string(ski) {
		t.Errorf("SKI = %x, want %x", rid.SKI, ski)
	}
}

// =============================================================================
// ParseKeyAgreeRecipientIdentifier Tests
// =============================================================================

func TestU_ParseKeyAgreeRecipientIdentifier_IssuerAndSerial(t *testing.T) {
	ias := IssuerAndSerialNumber{
		Issuer:       asn1.RawValue{FullBytes: []byte{0x30, 0x00}},
		SerialNumber: big.NewInt(99999),
	}
	data, err := asn1.Marshal(ias)
	if err != nil {
		t.Fatalf("Failed to marshal IssuerAndSerialNumber: %v", err)
	}

	karid, rest, err := ParseKeyAgreeRecipientIdentifier(data)
	if err != nil {
		t.Fatalf("ParseKeyAgreeRecipientIdentifier() error = %v", err)
	}

	if len(rest) != 0 {
		t.Errorf("ParseKeyAgreeRecipientIdentifier() rest = %d bytes, want 0", len(rest))
	}

	if karid.IssuerAndSerial == nil {
		t.Fatal("IssuerAndSerial is nil")
	}
}

func TestU_ParseKeyAgreeRecipientIdentifier_RKeyID(t *testing.T) {
	// Create a [0] tagged RecipientKeyIdentifier
	rki := RecipientKeyIdentifier{
		SubjectKeyIdentifier: []byte{0x01, 0x02, 0x03},
	}
	rkiBytes, err := asn1.Marshal(rki)
	if err != nil {
		t.Fatalf("Failed to marshal RecipientKeyIdentifier: %v", err)
	}

	data, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      rkiBytes,
	})
	if err != nil {
		t.Fatalf("Failed to wrap RecipientKeyIdentifier: %v", err)
	}

	karid, _, err := ParseKeyAgreeRecipientIdentifier(data)
	if err != nil {
		t.Fatalf("ParseKeyAgreeRecipientIdentifier() error = %v", err)
	}

	if karid.RKeyID == nil {
		t.Fatal("RKeyID is nil")
	}
}

// =============================================================================
// MarshalKeyTransRecipientInfo Tests
// =============================================================================

func TestU_MarshalKeyTransRecipientInfo(t *testing.T) {
	ktri := KeyTransRecipientInfo{
		Version: 0,
		RID: RecipientIdentifier{
			IssuerAndSerial: &IssuerAndSerialNumber{
				Issuer:       asn1.RawValue{FullBytes: []byte{0x30, 0x00}},
				SerialNumber: big.NewInt(12345),
			},
		},
		KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: OIDRSAES,
		},
		EncryptedKey: []byte{0x01, 0x02, 0x03, 0x04},
	}

	data, err := MarshalKeyTransRecipientInfo(&ktri)
	if err != nil {
		t.Fatalf("MarshalKeyTransRecipientInfo() error = %v", err)
	}

	// Verify we can parse it back
	parsed, err := ParseKeyTransRecipientInfo(data)
	if err != nil {
		t.Fatalf("ParseKeyTransRecipientInfo() error = %v", err)
	}

	if parsed.Version != ktri.Version {
		t.Errorf("Version = %d, want %d", parsed.Version, ktri.Version)
	}
	if string(parsed.EncryptedKey) != string(ktri.EncryptedKey) {
		t.Errorf("EncryptedKey mismatch")
	}
}

func TestU_MarshalKeyTransRecipientInfo_WithSKI(t *testing.T) {
	ktri := KeyTransRecipientInfo{
		Version: 2,
		RID: RecipientIdentifier{
			SKI: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a},
		},
		KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: OIDRSAOAEP,
		},
		EncryptedKey: []byte{0xaa, 0xbb, 0xcc, 0xdd},
	}

	data, err := MarshalKeyTransRecipientInfo(&ktri)
	if err != nil {
		t.Fatalf("MarshalKeyTransRecipientInfo() error = %v", err)
	}

	if len(data) == 0 {
		t.Error("MarshalKeyTransRecipientInfo() returned empty data")
	}
}

// =============================================================================
// MarshalRecipientEncryptedKey Tests
// =============================================================================

func TestU_MarshalRecipientEncryptedKey(t *testing.T) {
	rek := RecipientEncryptedKey{
		RID: KeyAgreeRecipientIdentifier{
			IssuerAndSerial: &IssuerAndSerialNumber{
				Issuer:       asn1.RawValue{FullBytes: []byte{0x30, 0x00}},
				SerialNumber: big.NewInt(54321),
			},
		},
		EncryptedKey: []byte{0x01, 0x02, 0x03},
	}

	data, err := MarshalRecipientEncryptedKey(&rek)
	if err != nil {
		t.Fatalf("MarshalRecipientEncryptedKey() error = %v", err)
	}

	// Verify we can parse it back
	parsed, rest, err := ParseRecipientEncryptedKey(data)
	if err != nil {
		t.Fatalf("ParseRecipientEncryptedKey() error = %v", err)
	}

	if len(rest) != 0 {
		t.Errorf("ParseRecipientEncryptedKey() rest = %d bytes, want 0", len(rest))
	}

	if string(parsed.EncryptedKey) != string(rek.EncryptedKey) {
		t.Errorf("EncryptedKey mismatch")
	}
}
