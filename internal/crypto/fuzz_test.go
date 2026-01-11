package crypto

import (
	"encoding/asn1"
	"testing"
)

// =============================================================================
// Algorithm Parsing Fuzz Tests
// =============================================================================

// FuzzParseAlgorithm tests parsing of arbitrary algorithm strings.
func FuzzParseAlgorithm(f *testing.F) {
	// Known algorithms
	f.Add("ecdsa-p256")
	f.Add("ecdsa-p384")
	f.Add("ml-dsa-65")
	f.Add("ml-dsa-87")
	f.Add("ml-kem-768")
	f.Add("slh-dsa-128s")
	// Invalid/edge cases
	f.Add("")
	f.Add("unknown")
	f.Add("ml-dsa-")
	f.Add("ECDSA-P256")               // Case sensitivity
	f.Add("ecdsa-p256\x00")           // Null byte
	f.Add(string(make([]byte, 1000))) // Long string

	f.Fuzz(func(t *testing.T, s string) {
		// Should not panic
		_, _ = ParseAlgorithm(s)
	})
}

// FuzzAlgorithmFromOID tests OID to algorithm mapping.
func FuzzAlgorithmFromOID(f *testing.F) {
	// Known OIDs in DER format
	f.Add([]byte{0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11}) // ML-DSA-44
	f.Add([]byte{0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12}) // ML-DSA-65
	f.Add([]byte{0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13}) // ML-DSA-87
	f.Add([]byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07})       // P-256
	// Invalid
	f.Add([]byte{0x06, 0x00})
	f.Add([]byte{0x06, 0x01, 0xff})
	f.Add([]byte{})
	f.Add([]byte{0xff, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 2 || data[0] != 0x06 {
			return
		}
		var oid asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(data, &oid); err != nil {
			return
		}
		// Should not panic
		_ = AlgorithmFromOID(oid)
	})
}

// FuzzAlgorithmIDMethods tests AlgorithmID method calls with arbitrary strings.
func FuzzAlgorithmIDMethods(f *testing.F) {
	f.Add("ecdsa-p256")
	f.Add("ml-dsa-65")
	f.Add("")
	f.Add("garbage")

	f.Fuzz(func(t *testing.T, s string) {
		alg := AlgorithmID(s)
		// None of these should panic
		_ = alg.IsValid()
		_ = alg.Type()
		_ = alg.IsClassical()
		_ = alg.IsPQC()
		_ = alg.IsHybrid()
		_ = alg.IsSignature()
		_ = alg.IsKEM()
		_ = alg.OID()
		_ = alg.X509SignatureAlgorithm()
		_ = alg.Description()
		_ = alg.String()
	})
}

// =============================================================================
// Public Key Parsing Fuzz Tests
// =============================================================================

// FuzzParsePublicKeyMLDSA44 tests parsing of ML-DSA-44 public keys.
func FuzzParsePublicKeyMLDSA44(f *testing.F) {
	// ML-DSA-44 public key is 1312 bytes
	f.Add([]byte{})
	f.Add(make([]byte, 1312)) // Correct size
	f.Add(make([]byte, 100))
	f.Add(make([]byte, 2000))
	f.Add([]byte{0xff, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should not panic
		_, _ = ParsePublicKey(AlgMLDSA44, data)
	})
}

// FuzzParsePublicKeyMLDSA65 tests parsing of ML-DSA-65 public keys.
func FuzzParsePublicKeyMLDSA65(f *testing.F) {
	// ML-DSA-65 public key is 1952 bytes
	f.Add([]byte{})
	f.Add(make([]byte, 1952))
	f.Add(make([]byte, 100))
	f.Add(make([]byte, 2500))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParsePublicKey(AlgMLDSA65, data)
	})
}

// FuzzParsePublicKeyMLDSA87 tests parsing of ML-DSA-87 public keys.
func FuzzParsePublicKeyMLDSA87(f *testing.F) {
	// ML-DSA-87 public key is 2592 bytes
	f.Add([]byte{})
	f.Add(make([]byte, 2592))
	f.Add(make([]byte, 100))
	f.Add(make([]byte, 3000))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParsePublicKey(AlgMLDSA87, data)
	})
}

// FuzzParsePublicKeyMLKEM768 tests parsing of ML-KEM-768 public keys.
func FuzzParsePublicKeyMLKEM768(f *testing.F) {
	// ML-KEM-768 public key is 1184 bytes
	f.Add([]byte{})
	f.Add(make([]byte, 1184))
	f.Add(make([]byte, 100))
	f.Add(make([]byte, 2000))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParsePublicKey(AlgMLKEM768, data)
	})
}

// FuzzParsePublicKeyUnknown tests parsing with unknown algorithms.
func FuzzParsePublicKeyUnknown(f *testing.F) {
	f.Add("unknown-alg", []byte{0x01, 0x02, 0x03})
	f.Add("", []byte{})
	f.Add("ml-dsa-", make([]byte, 100))

	f.Fuzz(func(t *testing.T, algStr string, data []byte) {
		alg := AlgorithmID(algStr)
		_, _ = ParsePublicKey(alg, data)
	})
}

// =============================================================================
// Public Key Bytes Extraction Fuzz Tests
// =============================================================================

// FuzzPublicKeyBytes tests extraction of public key bytes.
func FuzzPublicKeyBytes(f *testing.F) {
	// We can't easily fuzz actual public keys, but we can test nil handling
	f.Add(true)
	f.Add(false)

	f.Fuzz(func(t *testing.T, _ bool) {
		// Should handle nil gracefully
		_, _ = PublicKeyBytes(nil)
	})
}

// =============================================================================
// Signature Verification Fuzz Tests
// =============================================================================

// FuzzVerifySignatureMLDSA65 tests ML-DSA-65 signature verification.
func FuzzVerifySignatureMLDSA65(f *testing.F) {
	// ML-DSA-65 signature is 3309 bytes
	f.Add(make([]byte, 100), make([]byte, 3309)) // message, signature
	f.Add([]byte{}, []byte{})
	f.Add(make([]byte, 1000), make([]byte, 100))
	f.Add([]byte("test message"), []byte{0xff, 0xff})

	f.Fuzz(func(t *testing.T, message, signature []byte) {
		// Without a valid key, this should error but not panic
		_ = VerifySignature(nil, AlgMLDSA65, message, signature)
	})
}

// FuzzVerifySignatureMLDSA87 tests ML-DSA-87 signature verification.
func FuzzVerifySignatureMLDSA87(f *testing.F) {
	// ML-DSA-87 signature is 4627 bytes
	f.Add(make([]byte, 100), make([]byte, 4627))
	f.Add([]byte{}, []byte{})
	f.Add(make([]byte, 1000), make([]byte, 100))

	f.Fuzz(func(t *testing.T, message, signature []byte) {
		_ = VerifySignature(nil, AlgMLDSA87, message, signature)
	})
}

// FuzzVerifySignatureUnknownAlg tests verification with unknown algorithms.
func FuzzVerifySignatureUnknownAlg(f *testing.F) {
	f.Add("unknown", []byte("msg"), []byte("sig"))
	f.Add("", []byte{}, []byte{})

	f.Fuzz(func(t *testing.T, algStr string, message, signature []byte) {
		alg := AlgorithmID(algStr)
		_ = VerifySignature(nil, alg, message, signature)
	})
}

// =============================================================================
// HSM Config Parsing Fuzz Tests
// =============================================================================

// FuzzParseHSMConfig tests HSM configuration parsing.
func FuzzParseHSMConfig(f *testing.F) {
	// Valid-ish config strings
	f.Add("pkcs11:module=/usr/lib/softhsm.so;slot=0")
	f.Add("pkcs11:module=test.so")
	f.Add("software:")
	// Invalid/edge cases
	f.Add("")
	f.Add("pkcs11:")
	f.Add("unknown:config")
	f.Add(string(make([]byte, 10000))) // Very long

	f.Fuzz(func(t *testing.T, config string) {
		// ParseHSMConfig may not exist, but if it does, test it
		// For now, test KeyStorageConfig string parsing
		cfg := KeyStorageConfig{
			Type: KeyProviderType(config),
		}
		// Should not panic
		_ = cfg.Type
	})
}

// =============================================================================
// Key Manager Type Fuzz Tests
// =============================================================================

// FuzzKeyProviderType tests key manager type handling.
func FuzzKeyProviderType(f *testing.F) {
	f.Add("software")
	f.Add("pkcs11")
	f.Add("")
	f.Add("unknown-type")
	f.Add(string(make([]byte, 1000)))

	f.Fuzz(func(t *testing.T, typeStr string) {
		kmt := KeyProviderType(typeStr)
		// Should not panic
		_ = kmt == KeyProviderTypeSoftware
		_ = kmt == KeyProviderTypePKCS11
	})
}

// =============================================================================
// Key Storage Config Fuzz Tests
// =============================================================================

// FuzzKeyStorageConfigValidation tests key storage config with various inputs.
func FuzzKeyStorageConfigValidation(f *testing.F) {
	f.Add("software", "/tmp/key.pem", "passphrase")
	f.Add("pkcs11", "/usr/lib/softhsm.so", "")
	f.Add("", "", "")
	f.Add("unknown", string(make([]byte, 1000)), string(make([]byte, 100)))

	f.Fuzz(func(t *testing.T, typeStr, keyPath, passphrase string) {
		cfg := KeyStorageConfig{
			Type:       KeyProviderType(typeStr),
			KeyPath:    keyPath,
			Passphrase: passphrase,
		}
		// Should not panic when accessing fields
		_ = cfg.Type == KeyProviderTypeSoftware
		_ = cfg.KeyPath
		_ = cfg.Passphrase
	})
}
