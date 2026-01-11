package x509util

import (
	"crypto/x509/pkix"
	"testing"
)

// =============================================================================
// PQC CSR Parsing Fuzz Tests
// =============================================================================

// FuzzParsePQCCSR tests parsing of arbitrary CSR data.
// This is critical for security as CSRs come from untrusted sources.
func FuzzParsePQCCSR(f *testing.F) {
	// Seed corpus with valid ASN.1 structures and edge cases
	f.Add([]byte{0x30, 0x00})                                                       // Empty SEQUENCE
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x00})                                     // SEQUENCE with INTEGER 0
	f.Add([]byte{0x30, 0x80})                                                       // Indefinite length
	f.Add([]byte{0xa0, 0x00})                                                       // Context-specific tag [0]
	f.Add([]byte{0x00, 0x00, 0x00, 0x00})                                           // Null bytes
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})                                           // All 1s
	f.Add([]byte{0x30, 0x82, 0x00, 0x00})                                           // Long form length
	f.Add([]byte{0x30, 0x10, 0x02, 0x01, 0x00, 0x30, 0x00, 0x30, 0x00, 0xa0, 0x00}) // Basic CSR structure
	// Minimal valid-ish CSR structure
	f.Add([]byte{
		0x30, 0x1a, // SEQUENCE
		0x30, 0x12, // CertificationRequestInfo
		0x02, 0x01, 0x00, // version
		0x30, 0x00, // subject (empty)
		0x30, 0x06, // publicKeyInfo
		0x30, 0x00, // algorithm
		0x03, 0x02, 0x00, 0x00, // publicKey
		0xa0, 0x00, // attributes
		0x30, 0x00, // signatureAlgorithm
		0x03, 0x02, 0x00, 0x00, // signature
	})

	f.Fuzz(func(t *testing.T, data []byte) {
		// ParsePQCCSR should not panic regardless of input
		_, _ = ParsePQCCSR(data)
	})
}

// =============================================================================
// Hybrid Extension Fuzz Tests
// =============================================================================

// FuzzDecodeHybridExtension tests decoding of hybrid public key extensions.
func FuzzDecodeHybridExtension(f *testing.F) {
	// Seed with valid-ish extension structures
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte{0x30, 0x06, 0x30, 0x00, 0x03, 0x02, 0x00, 0x00})
	f.Add([]byte{0x30, 0x80}) // Indefinite length
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	// HybridPublicKeyInfo structure attempt
	f.Add([]byte{
		0x30, 0x0c, // SEQUENCE
		0x30, 0x04, // AlgorithmIdentifier
		0x06, 0x02, 0x55, 0x04, // OID
		0x03, 0x04, 0x00, 0x01, 0x02, 0x03, // BIT STRING
	})

	f.Fuzz(func(t *testing.T, data []byte) {
		ext := pkix.Extension{
			Id:    OIDHybridPublicKeyExtension,
			Value: data,
		}
		// Should not panic
		_, _, _, _ = DecodeHybridExtension(ext)
	})
}

// FuzzParseHybridExtension tests parsing hybrid extension from extension list.
func FuzzParseHybridExtension(f *testing.F) {
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte{0x30, 0x06, 0x30, 0x00, 0x03, 0x02, 0x00, 0x00})
	f.Add([]byte{0xff, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		extensions := []pkix.Extension{
			{
				Id:    OIDHybridPublicKeyExtension,
				Value: data,
			},
		}
		// Should not panic
		_, _ = ParseHybridExtension(extensions)
	})
}

// =============================================================================
// Catalyst Extensions Fuzz Tests
// =============================================================================

// FuzzDecodeAltSubjectPublicKeyInfo tests decoding of alternative public key info.
func FuzzDecodeAltSubjectPublicKeyInfo(f *testing.F) {
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte{0x30, 0x06, 0x30, 0x00, 0x03, 0x02, 0x00, 0x00})
	f.Add([]byte{0x30, 0x80})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		ext := pkix.Extension{
			Id:    OIDAltSubjectPublicKeyInfo,
			Value: data,
		}
		_, _, _ = DecodeAltSubjectPublicKeyInfo(ext)
	})
}

// FuzzDecodeAltSignatureAlgorithm tests decoding of alternative signature algorithm.
func FuzzDecodeAltSignatureAlgorithm(f *testing.F) {
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte{0x30, 0x04, 0x06, 0x02, 0x55, 0x04})
	f.Add([]byte{0x30, 0x80})
	f.Add([]byte{0xff, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		ext := pkix.Extension{
			Id:    OIDAltSignatureAlgorithm,
			Value: data,
		}
		_, _ = DecodeAltSignatureAlgorithm(ext)
	})
}

// FuzzDecodeAltSignatureValue tests decoding of alternative signature value.
func FuzzDecodeAltSignatureValue(f *testing.F) {
	f.Add([]byte{0x03, 0x00})
	f.Add([]byte{0x03, 0x04, 0x00, 0x01, 0x02, 0x03})
	f.Add([]byte{0x03, 0x80})
	f.Add([]byte{0xff, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		ext := pkix.Extension{
			Id:    OIDAltSignatureValue,
			Value: data,
		}
		_, _ = DecodeAltSignatureValue(ext)
	})
}

// FuzzParseCatalystExtensions tests parsing all Catalyst extensions together.
func FuzzParseCatalystExtensions(f *testing.F) {
	f.Add([]byte{0x30, 0x00}, []byte{0x30, 0x00}, []byte{0x03, 0x00})
	f.Add([]byte{0xff}, []byte{0xff}, []byte{0xff})
	f.Add([]byte{0x30, 0x06, 0x30, 0x00, 0x03, 0x02, 0x00, 0x00},
		[]byte{0x30, 0x04, 0x06, 0x02, 0x55, 0x04},
		[]byte{0x03, 0x04, 0x00, 0x01, 0x02, 0x03})

	f.Fuzz(func(t *testing.T, altPubKey, altSigAlg, altSigValue []byte) {
		extensions := []pkix.Extension{
			{Id: OIDAltSubjectPublicKeyInfo, Value: altPubKey},
			{Id: OIDAltSignatureAlgorithm, Value: altSigAlg},
			{Id: OIDAltSignatureValue, Value: altSigValue},
		}
		// Should not panic
		_, _ = ParseCatalystExtensions(extensions)
	})
}

// FuzzFindCatalystExtensions tests finding Catalyst extensions.
func FuzzFindCatalystExtensions(f *testing.F) {
	f.Add([]byte{0x30, 0x00}, []byte{0x30, 0x00}, []byte{0x03, 0x00})
	f.Add([]byte{0xff}, []byte{0xff}, []byte{0xff})

	f.Fuzz(func(t *testing.T, altPubKey, altSigAlg, altSigValue []byte) {
		extensions := []pkix.Extension{
			{Id: OIDAltSubjectPublicKeyInfo, Value: altPubKey},
			{Id: OIDAltSignatureAlgorithm, Value: altSigAlg},
			{Id: OIDAltSignatureValue, Value: altSigValue},
		}
		// Should not panic
		_ = FindCatalystExtensions(extensions)
	})
}

// =============================================================================
// RelatedCertificate Extension Fuzz Tests
// =============================================================================

// FuzzDecodeRelatedCertificate tests decoding of RelatedCertificate extension.
func FuzzDecodeRelatedCertificate(f *testing.F) {
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte{0x30, 0x80})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	// RelatedCertificate structure attempt
	f.Add([]byte{
		0x30, 0x18, // SEQUENCE
		0x30, 0x0b, // AlgorithmIdentifier (SHA-256)
		0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
		0x04, 0x04, 0x01, 0x02, 0x03, 0x04, // OCTET STRING (hash)
		0x30, 0x03, 0x30, 0x00, 0x02, 0x01, 0x01, // IssuerAndSerial
	})

	f.Fuzz(func(t *testing.T, data []byte) {
		ext := pkix.Extension{
			Id:    OIDRelatedCertificate,
			Value: data,
		}
		_, _ = DecodeRelatedCertificate(ext)
	})
}

// FuzzParseRelatedCertificate tests parsing RelatedCertificate from extension list.
func FuzzParseRelatedCertificate(f *testing.F) {
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte{0x30, 0x80})
	f.Add([]byte{0xff, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		extensions := []pkix.Extension{
			{Id: OIDRelatedCertificate, Value: data},
		}
		_, _ = ParseRelatedCertificate(extensions)
	})
}

// =============================================================================
// TBS Certificate Reconstruction Fuzz Tests
// =============================================================================

// FuzzReconstructTBSWithoutAltSigValue tests TBS reconstruction.
// This is security-critical for Catalyst signature verification.
func FuzzReconstructTBSWithoutAltSigValue(f *testing.F) {
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte{0x30, 0x80})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	// Minimal TBS structure
	f.Add([]byte{
		0x30, 0x30, // SEQUENCE
		0xa0, 0x03, 0x02, 0x01, 0x02, // version [0] INTEGER 2
		0x02, 0x01, 0x01, // serialNumber
		0x30, 0x00, // signature algorithm
		0x30, 0x00, // issuer
		0x30, 0x00, // validity
		0x30, 0x00, // subject
		0x30, 0x00, // subjectPublicKeyInfo
		0xa3, 0x15, // extensions [3]
		0x30, 0x13, // SEQUENCE OF Extension
		0x30, 0x11, // Extension
		0x06, 0x03, 0x55, 0x1d, 0x0f, // OID
		0x01, 0x01, 0xff, // critical
		0x04, 0x07, 0x03, 0x05, 0x00, 0xa0, 0x00, 0x00, 0x00, // value
	})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should not panic
		_, _ = ReconstructTBSWithoutAltSigValue(data)
	})
}

// =============================================================================
// CSR Attribute Parsing Fuzz Tests
// =============================================================================

// FuzzParseCSRAttributesIndirect tests CSR attribute parsing through ParsePQCCSR.
// Tests various malformed attribute encodings.
func FuzzParseCSRAttributesVariants(f *testing.F) {
	// Context-specific [0] wrapped attributes
	f.Add([]byte{0xa0, 0x00})
	f.Add([]byte{0xa0, 0x05, 0x30, 0x03, 0x06, 0x01, 0x00})
	// Direct attribute encoding
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte{0x30, 0x05, 0x06, 0x01, 0x00, 0x31, 0x00})
	// Malformed
	f.Add([]byte{0xff, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, attrData []byte) {
		// Build a minimal CSR with the fuzzed attributes
		// This indirectly tests parseCSRAttributes
		csr := []byte{
			0x30, byte(23 + len(attrData)), // outer SEQUENCE
			0x30, byte(15 + len(attrData)), // CertificationRequestInfo
			0x02, 0x01, 0x00, // version
			0x30, 0x00, // subject
			0x30, 0x06, // publicKeyInfo
			0x30, 0x02, 0x06, 0x00, // algorithm
			0x03, 0x00, // publicKey
		}
		// Append attributes with context tag [0]
		if len(attrData) > 0 {
			csr = append(csr, 0xa0, byte(len(attrData)))
			csr = append(csr, attrData...)
		}
		// Add signature parts
		csr = append(csr, 0x30, 0x00) // signatureAlgorithm
		csr = append(csr, 0x03, 0x00) // signature

		_, _ = ParsePQCCSR(csr)
	})
}

// =============================================================================
// OID Parsing Fuzz Tests
// =============================================================================

// FuzzOIDToAlgorithm tests OID to algorithm mapping with arbitrary OIDs.
func FuzzOIDToAlgorithm(f *testing.F) {
	// Known OIDs
	f.Add([]byte{0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11}) // ML-DSA-65
	f.Add([]byte{0x06, 0x03, 0x55, 0x04, 0x03})                                     // CN
	// Short/malformed
	f.Add([]byte{0x06, 0x00})
	f.Add([]byte{0x06, 0x01, 0xff})
	f.Add([]byte{0xff, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Try to parse as OID and map to algorithm
		// This shouldn't panic even with garbage input
		if len(data) < 2 {
			return
		}
		// Skip if not an OID tag
		if data[0] != 0x06 {
			return
		}
		// The oidToAlgorithm function takes asn1.ObjectIdentifier
		// We test it indirectly through DecodeHybridExtension
		ext := pkix.Extension{
			Id: OIDHybridPublicKeyExtension,
			Value: append([]byte{0x30, byte(len(data) + 4)}, // SEQUENCE
				append([]byte{0x30, byte(len(data))}, // AlgorithmIdentifier
					append(data, // OID
						[]byte{0x03, 0x02, 0x00, 0x00}...)...)...), // BIT STRING
		}
		_, _, _, _ = DecodeHybridExtension(ext)
	})
}
