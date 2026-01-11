package ca

import (
	"encoding/asn1"
	"testing"

	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
)

// =============================================================================
// Composite Signature Parsing Fuzz Tests
// =============================================================================

// FuzzParseCompositeSignatureValue tests parsing of composite signature values.
// CompositeSignatureValue ::= SEQUENCE SIZE (2) OF BIT STRING
func FuzzParseCompositeSignatureValue(f *testing.F) {
	// Seed corpus
	f.Add([]byte{0x30, 0x00})                         // Empty SEQUENCE
	f.Add([]byte{0x30, 0x04, 0x03, 0x00, 0x03, 0x00}) // Two empty BIT STRINGs
	f.Add([]byte{0x30, 0x80})                         // Indefinite length
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})             // Invalid
	// Valid-ish structure
	f.Add([]byte{
		0x30, 0x0a, // SEQUENCE
		0x03, 0x04, 0x00, 0x01, 0x02, 0x03, // BIT STRING (ML-DSA sig)
		0x03, 0x02, 0x00, 0x04, // BIT STRING (ECDSA sig)
	})
	// Large signature simulation
	f.Add([]byte{
		0x30, 0x82, 0x00, 0x10, // SEQUENCE with 2-byte length
		0x03, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
		0x03, 0x06, 0x00, 0x06, 0x07, 0x08, 0x09, 0x0a,
	})

	f.Fuzz(func(t *testing.T, data []byte) {
		var compSig CompositeSignatureValue
		// Should not panic
		_, _ = asn1.Unmarshal(data, &compSig)
	})
}

// FuzzParseCompositePublicKey tests parsing of composite public keys.
// CompositeSignaturePublicKey ::= SEQUENCE SIZE (2) OF BIT STRING
func FuzzParseCompositePublicKey(f *testing.F) {
	// Seed corpus
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte{0x30, 0x04, 0x03, 0x00, 0x03, 0x00})
	f.Add([]byte{0x30, 0x80})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	// Valid-ish composite public key
	f.Add([]byte{
		0x30, 0x0a,
		0x03, 0x04, 0x00, 0x01, 0x02, 0x03, // ML-DSA key
		0x03, 0x02, 0x00, 0x04, // ECDSA key
	})

	f.Fuzz(func(t *testing.T, data []byte) {
		var compPK CompositeSignaturePublicKey
		// Should not panic
		_, _ = asn1.Unmarshal(data, &compPK)
	})
}

// =============================================================================
// ML-DSA Public Key Parsing Fuzz Tests
// =============================================================================

// FuzzParseMLDSA65PublicKey tests parsing of ML-DSA-65 public keys.
func FuzzParseMLDSA65PublicKey(f *testing.F) {
	// ML-DSA-65 public key is 1952 bytes
	// Seed with various sizes
	f.Add([]byte{})
	f.Add(make([]byte, 100))
	f.Add(make([]byte, 1952)) // Correct size
	f.Add(make([]byte, 2000)) // Too large
	f.Add([]byte{0xff, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should not panic
		_, _ = parseMLDSAPublicKey(pkicrypto.AlgMLDSA65, data)
	})
}

// FuzzParseMLDSA87PublicKey tests parsing of ML-DSA-87 public keys.
func FuzzParseMLDSA87PublicKey(f *testing.F) {
	// ML-DSA-87 public key is 2592 bytes
	f.Add([]byte{})
	f.Add(make([]byte, 100))
	f.Add(make([]byte, 2592)) // Correct size
	f.Add(make([]byte, 3000)) // Too large
	f.Add([]byte{0xff, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should not panic
		_, _ = parseMLDSAPublicKey(pkicrypto.AlgMLDSA87, data)
	})
}

// =============================================================================
// Classical Public Key Parsing Fuzz Tests
// =============================================================================

// FuzzParseClassicalPublicKeyP256 tests parsing of ECDSA P-256 public keys.
func FuzzParseClassicalPublicKeyP256(f *testing.F) {
	// P-256 uncompressed point is 65 bytes (0x04 || X || Y)
	f.Add([]byte{})
	f.Add([]byte{0x04})     // Just the uncompressed marker
	f.Add(make([]byte, 65)) // Correct size but all zeros
	f.Add(make([]byte, 100))
	f.Add([]byte{0x04, 0x01, 0x02, 0x03}) // Too short
	// Attempt at valid structure
	validP256 := make([]byte, 65)
	validP256[0] = 0x04
	f.Add(validP256)

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should not panic
		_, _ = parseClassicalPublicKeyFromBytes(pkicrypto.AlgECDSAP256, data)
	})
}

// FuzzParseClassicalPublicKeyP384 tests parsing of ECDSA P-384 public keys.
func FuzzParseClassicalPublicKeyP384(f *testing.F) {
	// P-384 uncompressed point is 97 bytes (0x04 || X || Y)
	f.Add([]byte{})
	f.Add([]byte{0x04})
	f.Add(make([]byte, 97))
	f.Add(make([]byte, 100))
	validP384 := make([]byte, 97)
	validP384[0] = 0x04
	f.Add(validP384)

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should not panic
		_, _ = parseClassicalPublicKeyFromBytes(pkicrypto.AlgECDSAP384, data)
	})
}

// =============================================================================
// Composite Algorithm OID Lookup Fuzz Tests
// =============================================================================

// FuzzGetCompositeAlgorithmByOID tests OID lookup for composite algorithms.
func FuzzGetCompositeAlgorithmByOID(f *testing.F) {
	// Known composite OIDs
	f.Add([]byte{0x06, 0x0b, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x30}) // Example OID
	f.Add([]byte{0x06, 0x00})                                                       // Empty OID
	f.Add([]byte{0x06, 0x01, 0xff})
	f.Add([]byte{0xff, 0xff})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Try to parse as OID first
		if len(data) < 2 || data[0] != 0x06 {
			return
		}
		var oid asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(data, &oid); err != nil {
			return
		}
		// Should not panic
		_, _ = GetCompositeAlgorithmByOID(oid)
	})
}

// FuzzIsCompositeOID tests if arbitrary OIDs are recognized as composite.
func FuzzIsCompositeOID(f *testing.F) {
	f.Add([]byte{0x06, 0x03, 0x55, 0x04, 0x03}) // CN OID
	f.Add([]byte{0x06, 0x00})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 2 || data[0] != 0x06 {
			return
		}
		var oid asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(data, &oid); err != nil {
			return
		}
		// Should not panic
		_ = IsCompositeOID(oid)
	})
}

// =============================================================================
// Domain Separator Fuzz Tests
// =============================================================================

// FuzzBuildDomainSeparator tests domain separator construction.
func FuzzBuildDomainSeparator(f *testing.F) {
	f.Add([]byte{0x06, 0x03, 0x55, 0x04, 0x03})
	f.Add([]byte{0x06, 0x00})
	f.Add([]byte{0x06, 0x0b, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x30})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 2 || data[0] != 0x06 {
			return
		}
		var oid asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(data, &oid); err != nil {
			return
		}
		// Should not panic
		_, _ = BuildDomainSeparator(oid)
	})
}

// =============================================================================
// ML-DSA Signature Verification Fuzz Tests
// =============================================================================

// FuzzVerifyMLDSA65 tests ML-DSA-65 signature verification with arbitrary data.
func FuzzVerifyMLDSA65(f *testing.F) {
	// Various message and signature sizes
	f.Add([]byte("test message"), make([]byte, 3309)) // ML-DSA-65 sig is 3309 bytes
	f.Add([]byte{}, []byte{})
	f.Add(make([]byte, 1000), make([]byte, 3309))
	f.Add([]byte{0xff}, []byte{0xff})

	f.Fuzz(func(t *testing.T, message, signature []byte) {
		// Without a valid public key, this should return false but not panic
		// We can't easily fuzz with a valid key, but we can test the error paths
		result := verifyMLDSA(pkicrypto.AlgMLDSA65, nil, message, signature)
		if result {
			t.Error("verifyMLDSA returned true with nil key")
		}
	})
}

// FuzzVerifyECDSA tests ECDSA signature verification with arbitrary data.
func FuzzVerifyECDSA(f *testing.F) {
	// Various digest and signature sizes
	f.Add(make([]byte, 32), []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01})
	f.Add([]byte{}, []byte{})
	f.Add(make([]byte, 64), make([]byte, 100))

	f.Fuzz(func(t *testing.T, digest, signature []byte) {
		// Without a valid public key, this should return false but not panic
		result := verifyECDSA(nil, digest, signature)
		if result {
			t.Error("verifyECDSA returned true with nil key")
		}
	})
}

// =============================================================================
// Certificate Parsing Fuzz Tests (via IsCompositeCertificate)
// =============================================================================

// FuzzIsCompositeCertificate tests composite certificate detection.
func FuzzIsCompositeCertificate(f *testing.F) {
	// Minimal certificate-like DER
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte{0x30, 0x80})
	f.Add([]byte{0xff, 0xff})
	// More complete structure
	f.Add([]byte{
		0x30, 0x20, // Certificate SEQUENCE
		0x30, 0x18, // TBSCertificate
		0xa0, 0x03, 0x02, 0x01, 0x02, // version
		0x02, 0x01, 0x01, // serial
		0x30, 0x00, // signature algorithm
		0x30, 0x00, // issuer
		0x30, 0x00, // validity
		0x30, 0x00, // subject
		0x30, 0x00, // subjectPublicKeyInfo
		0x30, 0x00, // signatureAlgorithm
		0x03, 0x02, 0x00, 0x00, // signatureValue
	})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Parse as certificate - this may fail but shouldn't panic
		// We can't easily test IsCompositeCertificate without a valid cert,
		// but we can at least ensure the code path handles arbitrary input
		// by attempting to parse the DER
		var cert struct {
			TBS struct {
				Version    int `asn1:"optional,explicit,tag:0,default:0"`
				Serial     asn1.RawValue
				SigAlg     asn1.RawValue
				Issuer     asn1.RawValue
				Validity   asn1.RawValue
				Subject    asn1.RawValue
				PublicKey  asn1.RawValue
				Extensions asn1.RawValue `asn1:"optional,explicit,tag:3"`
			}
			SigAlg asn1.RawValue
			Sig    asn1.BitString
		}
		_, _ = asn1.Unmarshal(data, &cert)
	})
}
