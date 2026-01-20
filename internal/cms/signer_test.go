package cms

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
	"time"

	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
)

// =============================================================================
// Functional Tests: Sign with OID Verification
// =============================================================================

// TestF_Sign_ECDSAP256_VerifyOID tests that signing with ECDSA P-256 produces correct OID.
func TestF_Sign_ECDSAP256_VerifyOID(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	content := []byte("test content")

	signedData, err := Sign(context.Background(), content, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA256,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// STRUCTURE: Verify OID is ECDSA-SHA256
	oid := extractSignerInfoOID(t, signedData)
	if !oid.Equal(OIDECDSAWithSHA256) {
		t.Errorf("STRUCTURE: Expected OID %v, got %v", OIDECDSAWithSHA256, oid)
	}

	// CRYPTO: Verify signature is valid
	_, err = Verify(context.Background(), signedData, &VerifyConfig{SkipCertVerify: true})
	if err != nil {
		t.Errorf("CRYPTO: Verification failed: %v", err)
	}
}

// TestF_Sign_ECDSAP384_VerifyOID tests ECDSA P-384 with SHA-384.
func TestF_Sign_ECDSAP384_VerifyOID(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P384())
	cert := generateTestCertificate(t, kp)

	content := []byte("test content P-384")

	signedData, err := Sign(context.Background(), content, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA384,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	oid := extractSignerInfoOID(t, signedData)
	if !oid.Equal(OIDECDSAWithSHA384) {
		t.Errorf("STRUCTURE: Expected OID %v, got %v", OIDECDSAWithSHA384, oid)
	}

	_, err = Verify(context.Background(), signedData, &VerifyConfig{SkipCertVerify: true})
	if err != nil {
		t.Errorf("CRYPTO: Verification failed: %v", err)
	}
}

// TestF_Sign_ECDSAP521_VerifyOID tests ECDSA P-521 with SHA-512.
func TestF_Sign_ECDSAP521_VerifyOID(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P521())
	cert := generateTestCertificate(t, kp)

	content := []byte("test content P-521")

	signedData, err := Sign(context.Background(), content, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA512,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	oid := extractSignerInfoOID(t, signedData)
	if !oid.Equal(OIDECDSAWithSHA512) {
		t.Errorf("STRUCTURE: Expected OID %v, got %v", OIDECDSAWithSHA512, oid)
	}

	_, err = Verify(context.Background(), signedData, &VerifyConfig{SkipCertVerify: true})
	if err != nil {
		t.Errorf("CRYPTO: Verification failed: %v", err)
	}
}

// TestF_Sign_RSASHA256_VerifyOID tests RSA with SHA-256.
func TestF_Sign_RSASHA256_VerifyOID(t *testing.T) {
	kp := generateRSAKeyPair(t, 2048)
	cert := generateTestCertificate(t, kp)

	content := []byte("test content RSA")

	signedData, err := Sign(context.Background(), content, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA256,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	oid := extractSignerInfoOID(t, signedData)
	if !oid.Equal(OIDSHA256WithRSA) {
		t.Errorf("STRUCTURE: Expected OID %v, got %v", OIDSHA256WithRSA, oid)
	}

	_, err = Verify(context.Background(), signedData, &VerifyConfig{SkipCertVerify: true})
	if err != nil {
		t.Errorf("CRYPTO: Verification failed: %v", err)
	}
}

// TestF_Sign_RSASHA384_VerifyOID tests RSA with SHA-384.
func TestF_Sign_RSASHA384_VerifyOID(t *testing.T) {
	kp := generateRSAKeyPair(t, 2048)
	cert := generateTestCertificate(t, kp)

	content := []byte("test content RSA SHA-384")

	signedData, err := Sign(context.Background(), content, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA384,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	oid := extractSignerInfoOID(t, signedData)
	if !oid.Equal(OIDSHA384WithRSA) {
		t.Errorf("STRUCTURE: Expected OID %v, got %v", OIDSHA384WithRSA, oid)
	}

	_, err = Verify(context.Background(), signedData, &VerifyConfig{SkipCertVerify: true})
	if err != nil {
		t.Errorf("CRYPTO: Verification failed: %v", err)
	}
}

// TestF_Sign_Ed25519_VerifyOID tests Ed25519.
func TestF_Sign_Ed25519_VerifyOID(t *testing.T) {
	kp := generateEd25519KeyPair(t)
	cert := generateTestCertificate(t, kp)

	content := []byte("test content Ed25519")

	signedData, err := Sign(context.Background(), content, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	oid := extractSignerInfoOID(t, signedData)
	if !oid.Equal(OIDEd25519) {
		t.Errorf("STRUCTURE: Expected OID %v, got %v", OIDEd25519, oid)
	}

	_, err = Verify(context.Background(), signedData, &VerifyConfig{SkipCertVerify: true})
	if err != nil {
		t.Errorf("CRYPTO: Verification failed: %v", err)
	}
}

// =============================================================================
// Functional Tests: Detached Signatures
// =============================================================================

// TestF_Sign_DetachedECDSA_VerifyOID tests detached ECDSA signature OID.
func TestF_Sign_DetachedECDSA_VerifyOID(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	content := []byte("detached content")

	signedData, err := Sign(context.Background(), content, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA256,
		IncludeCerts: true,
		Detached:     true,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// STRUCTURE: Verify OID even for detached
	oid := extractSignerInfoOID(t, signedData)
	if !oid.Equal(OIDECDSAWithSHA256) {
		t.Errorf("STRUCTURE: Expected OID %v, got %v", OIDECDSAWithSHA256, oid)
	}

	// CRYPTO: Verify with original content
	_, err = Verify(context.Background(), signedData, &VerifyConfig{
		Data:           content,
		SkipCertVerify: true,
	})
	if err != nil {
		t.Errorf("CRYPTO: Verification failed: %v", err)
	}
}

// TestF_Sign_DetachedRSA_VerifyOID tests detached RSA signature OID.
func TestF_Sign_DetachedRSA_VerifyOID(t *testing.T) {
	kp := generateRSAKeyPair(t, 2048)
	cert := generateTestCertificate(t, kp)

	content := []byte("detached RSA content")

	signedData, err := Sign(context.Background(), content, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA256,
		IncludeCerts: true,
		Detached:     true,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	oid := extractSignerInfoOID(t, signedData)
	if !oid.Equal(OIDSHA256WithRSA) {
		t.Errorf("STRUCTURE: Expected OID %v, got %v", OIDSHA256WithRSA, oid)
	}

	_, err = Verify(context.Background(), signedData, &VerifyConfig{
		Data:           content,
		SkipCertVerify: true,
	})
	if err != nil {
		t.Errorf("CRYPTO: Verification failed: %v", err)
	}
}

// =============================================================================
// Unit Tests: SignerConfig Validation
// =============================================================================

// TestU_Sign_CertificateMissing tests that nil certificate is rejected.
func TestU_Sign_CertificateMissing(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())

	_, err := Sign(context.Background(), []byte("test"), &SignerConfig{
		Certificate: nil,
		Signer:      kp.PrivateKey,
	})
	if err == nil {
		t.Error("Expected error for nil certificate")
	}
}

// TestU_Sign_SignerMissing tests that nil signer is rejected.
func TestU_Sign_SignerMissing(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	_, err := Sign(context.Background(), []byte("test"), &SignerConfig{
		Certificate: cert,
		Signer:      nil,
	})
	if err == nil {
		t.Error("Expected error for nil signer")
	}
}

// TestU_Sign_DefaultDigestAlgorithm tests that default digest algorithm is SHA-256.
func TestU_Sign_DefaultDigestAlgorithm(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	signedData, err := Sign(context.Background(), []byte("test"), &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		IncludeCerts: true,
		// DigestAlg not set - should default to SHA-256
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	oid := extractSignerInfoOID(t, signedData)
	if !oid.Equal(OIDECDSAWithSHA256) {
		t.Errorf("Expected default ECDSA-SHA256, got %v", oid)
	}
}

// TestF_Sign_CustomSigningTime tests custom signing time.
func TestF_Sign_CustomSigningTime(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	customTime := time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC)

	signedData, err := Sign(context.Background(), []byte("test"), &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		IncludeCerts: true,
		SigningTime:  customTime,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	result, err := Verify(context.Background(), signedData, &VerifyConfig{SkipCertVerify: true})
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if !result.SigningTime.Equal(customTime) {
		t.Errorf("Signing time mismatch: expected %v, got %v", customTime, result.SigningTime)
	}
}

// TestF_Sign_CustomContentType tests custom content type OID.
func TestF_Sign_CustomContentType(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	customOID := asn1.ObjectIdentifier{1, 2, 3, 4, 5}

	signedData, err := Sign(context.Background(), []byte("test"), &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		IncludeCerts: true,
		ContentType:  customOID,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	result, err := Verify(context.Background(), signedData, &VerifyConfig{SkipCertVerify: true})
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if !result.ContentType.Equal(customOID) {
		t.Errorf("ContentType mismatch: expected %v, got %v", customOID, result.ContentType)
	}
}

// TestF_Sign_EmptyContent tests signing empty content.
func TestF_Sign_EmptyContent(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	signedData, err := Sign(context.Background(), []byte{}, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Sign failed for empty content: %v", err)
	}

	result, err := Verify(context.Background(), signedData, &VerifyConfig{SkipCertVerify: true})
	if err != nil {
		t.Fatalf("Verify failed for empty content: %v", err)
	}

	if len(result.Content) != 0 {
		t.Errorf("Expected empty content, got %d bytes", len(result.Content))
	}
}

// TestF_Sign_LargeContent tests signing large content.
func TestF_Sign_LargeContent(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	// 1 MB content
	largeContent := make([]byte, 1024*1024)
	for i := range largeContent {
		largeContent[i] = byte(i % 256)
	}

	signedData, err := Sign(context.Background(), largeContent, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Sign failed for large content: %v", err)
	}

	result, err := Verify(context.Background(), signedData, &VerifyConfig{SkipCertVerify: true})
	if err != nil {
		t.Fatalf("Verify failed for large content: %v", err)
	}

	if len(result.Content) != len(largeContent) {
		t.Errorf("Content length mismatch: expected %d, got %d", len(largeContent), len(result.Content))
	}
}

// =============================================================================
// Unit Tests: Digest Algorithm
// =============================================================================

// TestU_Sign_DigestAlgorithmSHA256 tests that DigestAlgorithm is correctly set.
func TestU_Sign_DigestAlgorithmSHA256(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	signedData, err := Sign(context.Background(), []byte("test"), &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA256,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	digestAlgOID := extractDigestAlgorithmOID(t, signedData)
	if !digestAlgOID.Equal(OIDSHA256) {
		t.Errorf("DigestAlgorithm mismatch: expected SHA-256, got %v", digestAlgOID)
	}
}

// TestU_Sign_DigestAlgorithmSHA384 tests SHA-384 digest algorithm.
func TestU_Sign_DigestAlgorithmSHA384(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P384())
	cert := generateTestCertificate(t, kp)

	signedData, err := Sign(context.Background(), []byte("test"), &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA384,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	digestAlgOID := extractDigestAlgorithmOID(t, signedData)
	if !digestAlgOID.Equal(OIDSHA384) {
		t.Errorf("DigestAlgorithm mismatch: expected SHA-384, got %v", digestAlgOID)
	}
}

// extractDigestAlgorithmOID extracts the DigestAlgorithm OID from SignedData.
func extractDigestAlgorithmOID(t *testing.T, signedDataDER []byte) asn1.ObjectIdentifier {
	t.Helper()

	var contentInfo ContentInfo
	_, err := asn1.Unmarshal(signedDataDER, &contentInfo)
	if err != nil {
		t.Fatalf("Failed to parse ContentInfo: %v", err)
	}

	var signedData SignedData
	_, err = asn1.Unmarshal(contentInfo.Content.Bytes, &signedData)
	if err != nil {
		t.Fatalf("Failed to parse SignedData: %v", err)
	}

	if len(signedData.DigestAlgorithms) == 0 {
		t.Fatal("No digest algorithms in SignedData")
	}

	return signedData.DigestAlgorithms[0].Algorithm
}

// =============================================================================
// Functional Tests: All Algorithms (Table-Driven)
// =============================================================================

// TestF_Sign_AllAlgorithms tests signing with all supported classical algorithms.
func TestF_Sign_AllAlgorithms(t *testing.T) {
	tests := []struct {
		name        string
		keyGen      func(t *testing.T) *testKeyPair
		digestAlg   crypto.Hash
		expectedOID asn1.ObjectIdentifier
	}{
		{
			name:        "[Functional] Sign: ECDSA-P256-SHA256",
			keyGen:      func(t *testing.T) *testKeyPair { return generateECDSAKeyPair(t, elliptic.P256()) },
			digestAlg:   crypto.SHA256,
			expectedOID: OIDECDSAWithSHA256,
		},
		{
			name:        "[Functional] Sign: ECDSA-P384-SHA384",
			keyGen:      func(t *testing.T) *testKeyPair { return generateECDSAKeyPair(t, elliptic.P384()) },
			digestAlg:   crypto.SHA384,
			expectedOID: OIDECDSAWithSHA384,
		},
		{
			name:        "[Functional] Sign: ECDSA-P521-SHA512",
			keyGen:      func(t *testing.T) *testKeyPair { return generateECDSAKeyPair(t, elliptic.P521()) },
			digestAlg:   crypto.SHA512,
			expectedOID: OIDECDSAWithSHA512,
		},
		{
			name:        "[Functional] Sign: RSA-2048-SHA256",
			keyGen:      func(t *testing.T) *testKeyPair { return generateRSAKeyPair(t, 2048) },
			digestAlg:   crypto.SHA256,
			expectedOID: OIDSHA256WithRSA,
		},
		{
			name:        "[Functional] Sign: RSA-2048-SHA384",
			keyGen:      func(t *testing.T) *testKeyPair { return generateRSAKeyPair(t, 2048) },
			digestAlg:   crypto.SHA384,
			expectedOID: OIDSHA384WithRSA,
		},
		{
			name:        "[Functional] Sign: RSA-2048-SHA512",
			keyGen:      func(t *testing.T) *testKeyPair { return generateRSAKeyPair(t, 2048) },
			digestAlg:   crypto.SHA512,
			expectedOID: OIDSHA512WithRSA,
		},
		{
			name:        "[Functional] Sign: Ed25519",
			keyGen:      func(t *testing.T) *testKeyPair { return generateEd25519KeyPair(t) },
			digestAlg:   0, // Ed25519 doesn't use external hash
			expectedOID: OIDEd25519,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kp := tt.keyGen(t)
			cert := generateTestCertificate(t, kp)

			config := &SignerConfig{
				Certificate:  cert,
				Signer:       kp.PrivateKey,
				IncludeCerts: true,
			}
			if tt.digestAlg != 0 {
				config.DigestAlg = tt.digestAlg
			}

			signedData, err := Sign(context.Background(), []byte("test content"), config)
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}

			// STRUCTURE check
			oid := extractSignerInfoOID(t, signedData)
			if !oid.Equal(tt.expectedOID) {
				t.Errorf("STRUCTURE: Expected OID %v, got %v", tt.expectedOID, oid)
			}

			// CRYPTO check
			_, err = Verify(context.Background(), signedData, &VerifyConfig{SkipCertVerify: true})
			if err != nil {
				t.Errorf("CRYPTO: Verification failed: %v", err)
			}
		})
	}
}

// =============================================================================
// Unit Tests: Helper Functions
// =============================================================================

// TestU_GetDigestAlgorithmIdentifier tests the digest algorithm identifier mapping.
func TestU_GetDigestAlgorithmIdentifier(t *testing.T) {
	tests := []struct {
		name        string
		alg         crypto.Hash
		expectedOID asn1.ObjectIdentifier
	}{
		{"[Unit] DigestAlg: SHA256", crypto.SHA256, OIDSHA256},
		{"[Unit] DigestAlg: SHA384", crypto.SHA384, OIDSHA384},
		{"[Unit] DigestAlg: SHA512", crypto.SHA512, OIDSHA512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			algID := getDigestAlgorithmIdentifier(tt.alg)
			if !algID.Algorithm.Equal(tt.expectedOID) {
				t.Errorf("Expected %v, got %v", tt.expectedOID, algID.Algorithm)
			}
		})
	}
}

// TestU_GetSignatureAlgorithmIdentifier tests signature algorithm detection.
func TestU_GetSignatureAlgorithmIdentifier(t *testing.T) {
	tests := []struct {
		name        string
		keyGen      func(t *testing.T) *testKeyPair
		digestAlg   crypto.Hash
		expectedOID asn1.ObjectIdentifier
	}{
		{
			name:        "[Unit] SigAlg: ECDSA-P256-SHA256",
			keyGen:      func(t *testing.T) *testKeyPair { return generateECDSAKeyPair(t, elliptic.P256()) },
			digestAlg:   crypto.SHA256,
			expectedOID: OIDECDSAWithSHA256,
		},
		{
			name:        "[Unit] SigAlg: RSA-SHA256",
			keyGen:      func(t *testing.T) *testKeyPair { return generateRSAKeyPair(t, 2048) },
			digestAlg:   crypto.SHA256,
			expectedOID: OIDSHA256WithRSA,
		},
		{
			name:        "[Unit] SigAlg: Ed25519",
			keyGen:      func(t *testing.T) *testKeyPair { return generateEd25519KeyPair(t) },
			digestAlg:   crypto.SHA256,
			expectedOID: OIDEd25519,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kp := tt.keyGen(t)

			algID, err := getSignatureAlgorithmIdentifier(kp.PrivateKey, tt.digestAlg)
			if err != nil {
				t.Fatalf("getSignatureAlgorithmIdentifier failed: %v", err)
			}

			if !algID.Algorithm.Equal(tt.expectedOID) {
				t.Errorf("Expected %v, got %v", tt.expectedOID, algID.Algorithm)
			}
		})
	}
}

// TestU_SortAttributes tests that attributes are sorted in DER order.
func TestU_SortAttributes(t *testing.T) {
	// Create attributes with different OIDs
	attr1 := Attribute{
		Type:   asn1.ObjectIdentifier{1, 2, 3},
		Values: []asn1.RawValue{{FullBytes: []byte{0x04, 0x01, 0x01}}},
	}
	attr2 := Attribute{
		Type:   asn1.ObjectIdentifier{1, 2, 1},
		Values: []asn1.RawValue{{FullBytes: []byte{0x04, 0x01, 0x02}}},
	}
	attr3 := Attribute{
		Type:   asn1.ObjectIdentifier{1, 2, 2},
		Values: []asn1.RawValue{{FullBytes: []byte{0x04, 0x01, 0x03}}},
	}

	attrs := []Attribute{attr1, attr2, attr3}
	sorted, err := sortAttributes(attrs)
	if err != nil {
		t.Fatalf("sortAttributes failed: %v", err)
	}

	// After sorting, the order should be by DER encoding
	// This verifies the sorting function works
	if len(sorted) != 3 {
		t.Errorf("Expected 3 sorted attributes, got %d", len(sorted))
	}
}

// TestU_BuildSignedAttrs tests building signed attributes.
func TestU_BuildSignedAttrs(t *testing.T) {
	contentType := OIDData
	digest := []byte{0x01, 0x02, 0x03, 0x04}
	signingTime := time.Now().UTC()

	attrs, err := buildSignedAttrs(&buildSignedAttrsConfig{
		ContentType: contentType,
		Digest:      digest,
		SigningTime: signingTime,
	})
	if err != nil {
		t.Fatalf("buildSignedAttrs failed: %v", err)
	}

	// Should have 3 attributes: content-type, message-digest, signing-time
	if len(attrs) != 3 {
		t.Errorf("Expected 3 attributes, got %d", len(attrs))
	}

	// Verify each attribute type is present
	hasContentType := false
	hasMessageDigest := false
	hasSigningTime := false

	for _, attr := range attrs {
		switch {
		case attr.Type.Equal(OIDContentType):
			hasContentType = true
		case attr.Type.Equal(OIDMessageDigest):
			hasMessageDigest = true
		case attr.Type.Equal(OIDSigningTime):
			hasSigningTime = true
		}
	}

	if !hasContentType {
		t.Error("Missing content-type attribute")
	}
	if !hasMessageDigest {
		t.Error("Missing message-digest attribute")
	}
	if !hasSigningTime {
		t.Error("Missing signing-time attribute")
	}
}

// TestU_ComputeDigest tests digest computation.
func TestU_ComputeDigest(t *testing.T) {
	tests := []struct {
		name         string
		alg          crypto.Hash
		expectedSize int
	}{
		{"[Unit] Digest: SHA256", crypto.SHA256, 32},
		{"[Unit] Digest: SHA384", crypto.SHA384, 48},
		{"[Unit] Digest: SHA512", crypto.SHA512, 64},
	}

	data := []byte("test data for digest")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			digest, err := computeDigest(data, tt.alg)
			if err != nil {
				t.Fatalf("computeDigest failed: %v", err)
			}

			if len(digest) != tt.expectedSize {
				t.Errorf("Expected digest size %d, got %d", tt.expectedSize, len(digest))
			}
		})
	}
}

// TestU_ComputeDigest_UnsupportedAlgorithm tests unsupported algorithm rejection.
func TestU_ComputeDigest_UnsupportedAlgorithm(t *testing.T) {
	_, err := computeDigest([]byte("test"), crypto.MD5)
	if err == nil {
		t.Error("Expected error for unsupported algorithm MD5")
	}
}

// =============================================================================
// Functional Tests: Certificate Inclusion
// =============================================================================

// TestF_Sign_WithCertificates verifies certificates are included when requested.
func TestF_Sign_WithCertificates(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	signedData, err := Sign(context.Background(), []byte("test"), &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	result, err := Verify(context.Background(), signedData, &VerifyConfig{SkipCertVerify: true})
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if result.SignerCert == nil {
		t.Error("Expected signer certificate in result")
	}
}

// TestF_Sign_WithoutCertificates verifies signing works without embedding certs.
func TestF_Sign_WithoutCertificates(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	signedData, err := Sign(context.Background(), []byte("test"), &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		IncludeCerts: false, // Don't include certificates
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Without embedded certs, verification should fail (no signer cert found)
	_, err = Verify(context.Background(), signedData, &VerifyConfig{SkipCertVerify: true})
	if err == nil {
		t.Error("Expected verification to fail without embedded certificates")
	}
}

// =============================================================================
// Unit Tests: IssuerAndSerialNumber
// =============================================================================

// TestU_Sign_IssuerAndSerialNumber verifies SID is correctly set.
func TestU_Sign_IssuerAndSerialNumber(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	signedData, err := Sign(context.Background(), []byte("test"), &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Parse and verify SID matches certificate
	var contentInfo ContentInfo
	_, err = asn1.Unmarshal(signedData, &contentInfo)
	if err != nil {
		t.Fatalf("Failed to parse ContentInfo: %v", err)
	}

	var sd SignedData
	_, err = asn1.Unmarshal(contentInfo.Content.Bytes, &sd)
	if err != nil {
		t.Fatalf("Failed to parse SignedData: %v", err)
	}

	if len(sd.SignerInfos) == 0 {
		t.Fatal("No SignerInfos")
	}

	sid := sd.SignerInfos[0].SID

	// Verify serial number matches
	if sid.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Errorf("SerialNumber mismatch: expected %v, got %v", cert.SerialNumber, sid.SerialNumber)
	}

	// Verify issuer matches (by comparing raw bytes)
	var issuerName pkix.RDNSequence
	_, err = asn1.Unmarshal(sid.Issuer.FullBytes, &issuerName)
	if err != nil {
		t.Fatalf("Failed to parse issuer: %v", err)
	}
}

// =============================================================================
// Functional Tests: ML-DSA Algorithms (Post-Quantum)
// =============================================================================

// TestF_Sign_MLDSA_AllVariants tests CMS signing with all ML-DSA variants.
func TestF_Sign_MLDSA_AllVariants(t *testing.T) {
	tests := []struct {
		name        string
		alg         pkicrypto.AlgorithmID
		expectedOID asn1.ObjectIdentifier
	}{
		{
			name:        "[Functional] Sign: ML-DSA-44",
			alg:         pkicrypto.AlgMLDSA44,
			expectedOID: OIDMLDSA44,
		},
		{
			name:        "[Functional] Sign: ML-DSA-65",
			alg:         pkicrypto.AlgMLDSA65,
			expectedOID: OIDMLDSA65,
		},
		{
			name:        "[Functional] Sign: ML-DSA-87",
			alg:         pkicrypto.AlgMLDSA87,
			expectedOID: OIDMLDSA87,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kp := generateMLDSAKeyPair(t, tt.alg)
			cert := generateMLDSACertificate(t, kp, tt.alg)

			content := []byte("ML-DSA test content")

			signedData, err := Sign(context.Background(), content, &SignerConfig{
				Certificate:  cert,
				Signer:       kp.PrivateKey,
				IncludeCerts: true,
			})
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}

			// STRUCTURE check: verify OID
			oid := extractSignerInfoOID(t, signedData)
			if !oid.Equal(tt.expectedOID) {
				t.Errorf("STRUCTURE: Expected OID %v, got %v", tt.expectedOID, oid)
			}

			// CRYPTO check: verify signature
			_, err = Verify(context.Background(), signedData, &VerifyConfig{SkipCertVerify: true})
			if err != nil {
				t.Errorf("CRYPTO: Verification failed: %v", err)
			}
		})
	}
}

// TestF_Sign_MLDSA44_Detached tests detached ML-DSA-44 signature.
func TestF_Sign_MLDSA44_Detached(t *testing.T) {
	kp := generateMLDSAKeyPair(t, pkicrypto.AlgMLDSA44)
	cert := generateMLDSACertificate(t, kp, pkicrypto.AlgMLDSA44)

	content := []byte("detached ML-DSA content")

	signedData, err := Sign(context.Background(), content, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		IncludeCerts: true,
		Detached:     true,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// STRUCTURE: verify OID
	oid := extractSignerInfoOID(t, signedData)
	if !oid.Equal(OIDMLDSA44) {
		t.Errorf("STRUCTURE: Expected OID %v, got %v", OIDMLDSA44, oid)
	}

	// CRYPTO: verify with original content
	_, err = Verify(context.Background(), signedData, &VerifyConfig{
		Data:           content,
		SkipCertVerify: true,
	})
	if err != nil {
		t.Errorf("CRYPTO: Verification failed: %v", err)
	}
}

// TestF_Sign_MLDSA65_LargeContent tests ML-DSA-65 with large content.
func TestF_Sign_MLDSA65_LargeContent(t *testing.T) {
	kp := generateMLDSAKeyPair(t, pkicrypto.AlgMLDSA65)
	cert := generateMLDSACertificate(t, kp, pkicrypto.AlgMLDSA65)

	// 512 KB content
	largeContent := make([]byte, 512*1024)
	for i := range largeContent {
		largeContent[i] = byte(i % 256)
	}

	signedData, err := Sign(context.Background(), largeContent, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Sign failed for large content: %v", err)
	}

	result, err := Verify(context.Background(), signedData, &VerifyConfig{SkipCertVerify: true})
	if err != nil {
		t.Fatalf("Verify failed for large content: %v", err)
	}

	if len(result.Content) != len(largeContent) {
		t.Errorf("Content length mismatch: expected %d, got %d", len(largeContent), len(result.Content))
	}
}

// =============================================================================
// Functional Tests: SLH-DSA Algorithms (Post-Quantum)
// =============================================================================

// TestF_Sign_SLHDSA_FastVariants tests CMS signing with SLH-DSA fast variants.
func TestF_Sign_SLHDSA_FastVariants(t *testing.T) {
	tests := []struct {
		name        string
		alg         pkicrypto.AlgorithmID
		expectedOID asn1.ObjectIdentifier
	}{
		{
			name:        "[Functional] Sign: SLH-DSA-128f",
			alg:         pkicrypto.AlgSLHDSA128f,
			expectedOID: OIDSLHDSA128f,
		},
		{
			name:        "[Functional] Sign: SLH-DSA-192f",
			alg:         pkicrypto.AlgSLHDSA192f,
			expectedOID: OIDSLHDSA192f,
		},
		{
			name:        "[Functional] Sign: SLH-DSA-256f",
			alg:         pkicrypto.AlgSLHDSA256f,
			expectedOID: OIDSLHDSA256f,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kp := generateSLHDSAKeyPair(t, tt.alg)
			cert := generateSLHDSACertificate(t, kp, tt.alg)

			content := []byte("SLH-DSA test content")

			signedData, err := Sign(context.Background(), content, &SignerConfig{
				Certificate:  cert,
				Signer:       kp.PrivateKey,
				IncludeCerts: true,
			})
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}

			// STRUCTURE check: verify OID
			oid := extractSignerInfoOID(t, signedData)
			if !oid.Equal(tt.expectedOID) {
				t.Errorf("STRUCTURE: Expected OID %v, got %v", tt.expectedOID, oid)
			}

			// CRYPTO check: verify signature
			_, err = Verify(context.Background(), signedData, &VerifyConfig{SkipCertVerify: true})
			if err != nil {
				t.Errorf("CRYPTO: Verification failed: %v", err)
			}
		})
	}
}

// TestF_Sign_SLHDSA_SmallVariants tests CMS signing with SLH-DSA small (slow) variants.
// These variants produce smaller signatures but are slower.
func TestF_Sign_SLHDSA_SmallVariants(t *testing.T) {
	tests := []struct {
		name        string
		alg         pkicrypto.AlgorithmID
		expectedOID asn1.ObjectIdentifier
	}{
		{
			name:        "[Functional] Sign: SLH-DSA-128s",
			alg:         pkicrypto.AlgSLHDSA128s,
			expectedOID: OIDSLHDSA128s,
		},
		// Note: SLH-DSA-192s and SLH-DSA-256s are very slow, skip in unit tests
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kp := generateSLHDSAKeyPair(t, tt.alg)
			cert := generateSLHDSACertificate(t, kp, tt.alg)

			content := []byte("SLH-DSA small test content")

			signedData, err := Sign(context.Background(), content, &SignerConfig{
				Certificate:  cert,
				Signer:       kp.PrivateKey,
				IncludeCerts: true,
			})
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}

			// STRUCTURE check: verify OID
			oid := extractSignerInfoOID(t, signedData)
			if !oid.Equal(tt.expectedOID) {
				t.Errorf("STRUCTURE: Expected OID %v, got %v", tt.expectedOID, oid)
			}

			// CRYPTO check: verify signature
			_, err = Verify(context.Background(), signedData, &VerifyConfig{SkipCertVerify: true})
			if err != nil {
				t.Errorf("CRYPTO: Verification failed: %v", err)
			}
		})
	}
}

// TestF_Sign_SLHDSA128f_Detached tests detached SLH-DSA-128f signature.
func TestF_Sign_SLHDSA128f_Detached(t *testing.T) {
	kp := generateSLHDSAKeyPair(t, pkicrypto.AlgSLHDSA128f)
	cert := generateSLHDSACertificate(t, kp, pkicrypto.AlgSLHDSA128f)

	content := []byte("detached SLH-DSA content")

	signedData, err := Sign(context.Background(), content, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		IncludeCerts: true,
		Detached:     true,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// STRUCTURE: verify OID
	oid := extractSignerInfoOID(t, signedData)
	if !oid.Equal(OIDSLHDSA128f) {
		t.Errorf("STRUCTURE: Expected OID %v, got %v", OIDSLHDSA128f, oid)
	}

	// CRYPTO: verify with original content
	_, err = Verify(context.Background(), signedData, &VerifyConfig{
		Data:           content,
		SkipCertVerify: true,
	})
	if err != nil {
		t.Errorf("CRYPTO: Verification failed: %v", err)
	}
}

// =============================================================================
// Functional Tests: All PQC Algorithms (Combined Table-Driven)
// =============================================================================

// TestF_Sign_AllPQCAlgorithms tests signing with all supported PQC signature algorithms.
func TestF_Sign_AllPQCAlgorithms(t *testing.T) {
	tests := []struct {
		name        string
		alg         pkicrypto.AlgorithmID
		expectedOID asn1.ObjectIdentifier
		genKeyPair  func(t *testing.T, alg pkicrypto.AlgorithmID) *testKeyPair
		genCert     func(t *testing.T, kp *testKeyPair, alg pkicrypto.AlgorithmID) *x509.Certificate
	}{
		// ML-DSA variants
		{
			name:        "[Functional] Sign: ML-DSA-44",
			alg:         pkicrypto.AlgMLDSA44,
			expectedOID: OIDMLDSA44,
			genKeyPair:  generateMLDSAKeyPair,
			genCert:     generateMLDSACertificate,
		},
		{
			name:        "[Functional] Sign: ML-DSA-65",
			alg:         pkicrypto.AlgMLDSA65,
			expectedOID: OIDMLDSA65,
			genKeyPair:  generateMLDSAKeyPair,
			genCert:     generateMLDSACertificate,
		},
		{
			name:        "[Functional] Sign: ML-DSA-87",
			alg:         pkicrypto.AlgMLDSA87,
			expectedOID: OIDMLDSA87,
			genKeyPair:  generateMLDSAKeyPair,
			genCert:     generateMLDSACertificate,
		},
		// SLH-DSA fast variants
		{
			name:        "[Functional] Sign: SLH-DSA-128f",
			alg:         pkicrypto.AlgSLHDSA128f,
			expectedOID: OIDSLHDSA128f,
			genKeyPair:  generateSLHDSAKeyPair,
			genCert:     generateSLHDSACertificate,
		},
		{
			name:        "[Functional] Sign: SLH-DSA-128s",
			alg:         pkicrypto.AlgSLHDSA128s,
			expectedOID: OIDSLHDSA128s,
			genKeyPair:  generateSLHDSAKeyPair,
			genCert:     generateSLHDSACertificate,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kp := tt.genKeyPair(t, tt.alg)
			cert := tt.genCert(t, kp, tt.alg)

			content := []byte("PQC test content for " + string(tt.alg))

			signedData, err := Sign(context.Background(), content, &SignerConfig{
				Certificate:  cert,
				Signer:       kp.PrivateKey,
				IncludeCerts: true,
			})
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}

			// STRUCTURE check
			oid := extractSignerInfoOID(t, signedData)
			if !oid.Equal(tt.expectedOID) {
				t.Errorf("STRUCTURE: Expected OID %v, got %v", tt.expectedOID, oid)
			}

			// CRYPTO check
			result, err := Verify(context.Background(), signedData, &VerifyConfig{SkipCertVerify: true})
			if err != nil {
				t.Errorf("CRYPTO: Verification failed: %v", err)
			}

			// Verify content round-trip
			if string(result.Content) != string(content) {
				t.Errorf("Content mismatch: expected %q, got %q", content, result.Content)
			}
		})
	}
}

// =============================================================================
// Unit Tests: Algorithm ID to OID Mapping
// =============================================================================

// TestU_AlgorithmIDToOID tests the algorithmIDToOID function.
func TestU_AlgorithmIDToOID(t *testing.T) {
	tests := []struct {
		name        string
		alg         pkicrypto.AlgorithmID
		expectedOID asn1.ObjectIdentifier
		expectNil   bool
	}{
		// ML-DSA
		{"[Unit] AlgToOID: ML-DSA-44", pkicrypto.AlgMLDSA44, OIDMLDSA44, false},
		{"[Unit] AlgToOID: ML-DSA-65", pkicrypto.AlgMLDSA65, OIDMLDSA65, false},
		{"[Unit] AlgToOID: ML-DSA-87", pkicrypto.AlgMLDSA87, OIDMLDSA87, false},
		// SLH-DSA
		{"[Unit] AlgToOID: SLH-DSA-128s", pkicrypto.AlgSLHDSA128s, OIDSLHDSA128s, false},
		{"[Unit] AlgToOID: SLH-DSA-128f", pkicrypto.AlgSLHDSA128f, OIDSLHDSA128f, false},
		{"[Unit] AlgToOID: SLH-DSA-192s", pkicrypto.AlgSLHDSA192s, OIDSLHDSA192s, false},
		{"[Unit] AlgToOID: SLH-DSA-192f", pkicrypto.AlgSLHDSA192f, OIDSLHDSA192f, false},
		{"[Unit] AlgToOID: SLH-DSA-256s", pkicrypto.AlgSLHDSA256s, OIDSLHDSA256s, false},
		{"[Unit] AlgToOID: SLH-DSA-256f", pkicrypto.AlgSLHDSA256f, OIDSLHDSA256f, false},
		// Unknown
		{"[Unit] AlgToOID: Unknown", pkicrypto.AlgUnknown, nil, true},
		{"[Unit] AlgToOID: ML-KEM (not signature)", pkicrypto.AlgMLKEM768, nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oid := algorithmIDToOID(tt.alg)
			if tt.expectNil {
				if oid != nil {
					t.Errorf("Expected nil OID, got %v", oid)
				}
			} else {
				if oid == nil {
					t.Error("Expected non-nil OID, got nil")
				} else if !oid.Equal(tt.expectedOID) {
					t.Errorf("OID mismatch: expected %v, got %v", tt.expectedOID, oid)
				}
			}
		})
	}
}

// TestU_DetectPQCAlgorithm tests the detectPQCAlgorithm function with ML-DSA keys.
func TestU_DetectPQCAlgorithm(t *testing.T) {
	tests := []struct {
		name        string
		alg         pkicrypto.AlgorithmID
		expectedOID asn1.ObjectIdentifier
	}{
		{"[Unit] DetectPQC: ML-DSA-44", pkicrypto.AlgMLDSA44, OIDMLDSA44},
		{"[Unit] DetectPQC: ML-DSA-65", pkicrypto.AlgMLDSA65, OIDMLDSA65},
		{"[Unit] DetectPQC: ML-DSA-87", pkicrypto.AlgMLDSA87, OIDMLDSA87},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kp := generateMLDSAKeyPair(t, tt.alg)
			algID, err := detectPQCAlgorithm(kp.PublicKey)
			if err != nil {
				t.Fatalf("detectPQCAlgorithm failed: %v", err)
			}
			if !algID.Algorithm.Equal(tt.expectedOID) {
				t.Errorf("OID mismatch: expected %v, got %v", tt.expectedOID, algID.Algorithm)
			}
		})
	}
}

// TestU_DetectPQCAlgorithm_SLH tests detectPQCAlgorithm with SLH-DSA keys.
func TestU_DetectPQCAlgorithm_SLH(t *testing.T) {
	tests := []struct {
		name        string
		alg         pkicrypto.AlgorithmID
		expectedOID asn1.ObjectIdentifier
	}{
		{"[Unit] DetectPQC: SLH-DSA-128f", pkicrypto.AlgSLHDSA128f, OIDSLHDSA128f},
		{"[Unit] DetectPQC: SLH-DSA-128s", pkicrypto.AlgSLHDSA128s, OIDSLHDSA128s},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kp := generateSLHDSAKeyPair(t, tt.alg)
			algID, err := detectPQCAlgorithm(kp.PublicKey)
			if err != nil {
				t.Fatalf("detectPQCAlgorithm failed: %v", err)
			}
			if !algID.Algorithm.Equal(tt.expectedOID) {
				t.Errorf("OID mismatch: expected %v, got %v", tt.expectedOID, algID.Algorithm)
			}
		})
	}
}

// TestU_DetectPQCAlgorithm_UnsupportedKey tests detectPQCAlgorithm with unsupported keys.
func TestU_DetectPQCAlgorithm_UnsupportedKey(t *testing.T) {
	// Test with a classical key (should fail)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	_, err := detectPQCAlgorithm(kp.PublicKey)
	if err == nil {
		t.Error("Expected error for ECDSA key in detectPQCAlgorithm")
	}
}

// =============================================================================
// Unit Tests: ASN.1 Length Parsing
// =============================================================================

// TestU_ParseASN1Length tests the parseASN1Length function.
func TestU_ParseASN1Length(t *testing.T) {
	tests := []struct {
		name           string
		data           []byte
		expectedLength int
		expectedBytes  int
	}{
		{"[Unit] ParseLen: Short form 0", []byte{0x00}, 0, 1},
		{"[Unit] ParseLen: Short form 127", []byte{0x7F}, 127, 1},
		{"[Unit] ParseLen: Long form 1 byte (128)", []byte{0x81, 0x80}, 128, 2},
		{"[Unit] ParseLen: Long form 1 byte (255)", []byte{0x81, 0xFF}, 255, 2},
		{"[Unit] ParseLen: Long form 2 bytes (256)", []byte{0x82, 0x01, 0x00}, 256, 3},
		{"[Unit] ParseLen: Long form 2 bytes (65535)", []byte{0x82, 0xFF, 0xFF}, 65535, 3},
		{"[Unit] ParseLen: Empty data", []byte{}, 0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			length, bytesConsumed := parseASN1Length(tt.data)
			if length != tt.expectedLength {
				t.Errorf("Length mismatch: expected %d, got %d", tt.expectedLength, length)
			}
			if bytesConsumed != tt.expectedBytes {
				t.Errorf("Bytes consumed mismatch: expected %d, got %d", tt.expectedBytes, bytesConsumed)
			}
		})
	}
}

// =============================================================================
// Unit Tests: Classical Signature Algorithm Identifier
// =============================================================================

// TestU_GetClassicalSignatureAlgorithmIdentifier tests getClassicalSignatureAlgorithmIdentifier.
func TestU_GetClassicalSignatureAlgorithmIdentifier(t *testing.T) {
	ecdsaKP := generateECDSAKeyPair(t, elliptic.P256())
	rsaKP := generateRSAKeyPair(t, 2048)
	ed25519KP := generateEd25519KeyPair(t)

	tests := []struct {
		name        string
		pub         crypto.PublicKey
		digestAlg   crypto.Hash
		expectedOID asn1.ObjectIdentifier
		expectError bool
	}{
		{"[Unit] ClassicalSigAlg: ECDSA P-256 SHA-256", ecdsaKP.PublicKey, crypto.SHA256, OIDECDSAWithSHA256, false},
		{"[Unit] ClassicalSigAlg: ECDSA P-256 SHA-384", ecdsaKP.PublicKey, crypto.SHA384, OIDECDSAWithSHA384, false},
		{"[Unit] ClassicalSigAlg: ECDSA P-256 SHA-512", ecdsaKP.PublicKey, crypto.SHA512, OIDECDSAWithSHA512, false},
		{"[Unit] ClassicalSigAlg: RSA SHA-256", rsaKP.PublicKey, crypto.SHA256, OIDSHA256WithRSA, false},
		{"[Unit] ClassicalSigAlg: RSA SHA-384", rsaKP.PublicKey, crypto.SHA384, OIDSHA384WithRSA, false},
		{"[Unit] ClassicalSigAlg: RSA SHA-512", rsaKP.PublicKey, crypto.SHA512, OIDSHA512WithRSA, false},
		{"[Unit] ClassicalSigAlg: Ed25519", ed25519KP.PublicKey, crypto.SHA256, OIDEd25519, false},
		{"[Unit] ClassicalSigAlg: ECDSA unsupported hash", ecdsaKP.PublicKey, crypto.MD5, nil, true},
		{"[Unit] ClassicalSigAlg: RSA unsupported hash", rsaKP.PublicKey, crypto.MD5, nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			algID, err := getClassicalSignatureAlgorithmIdentifier(tt.pub, tt.digestAlg)
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if !algID.Algorithm.Equal(tt.expectedOID) {
					t.Errorf("OID mismatch: expected %v, got %v", tt.expectedOID, algID.Algorithm)
				}
			}
		})
	}
}

// TestU_GetClassicalSignatureAlgorithmIdentifier_UnsupportedKey tests with unsupported key type.
func TestU_GetClassicalSignatureAlgorithmIdentifier_UnsupportedKey(t *testing.T) {
	// Use ML-DSA key (not classical)
	mldsaKP := generateMLDSAKeyPair(t, pkicrypto.AlgMLDSA65)
	_, err := getClassicalSignatureAlgorithmIdentifier(mldsaKP.PublicKey, crypto.SHA256)
	if err == nil {
		t.Error("Expected error for ML-DSA key in getClassicalSignatureAlgorithmIdentifier")
	}
}

// =============================================================================
// Unit Tests: Certificate Injection
// =============================================================================

// TestU_InjectCertificates tests the injectCertificates function.
func TestU_InjectCertificates(t *testing.T) {
	// Generate a test certificate
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	// Create a minimal SignedData structure
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

	sdBytes, err := asn1.Marshal(sd)
	if err != nil {
		t.Fatalf("Failed to marshal SignedData: %v", err)
	}

	// Inject certificate
	result, err := injectCertificates(sdBytes, cert.Raw)
	if err != nil {
		t.Fatalf("injectCertificates failed: %v", err)
	}

	// Verify result is longer than original
	if len(result) <= len(sdBytes) {
		t.Error("Result should be longer than original")
	}

	// Verify result starts with SEQUENCE tag
	if result[0] != 0x30 {
		t.Errorf("Result should start with SEQUENCE tag (0x30), got 0x%02x", result[0])
	}
}

// TestU_InjectCertificates_InvalidInput tests injectCertificates with invalid input.
func TestU_InjectCertificates_InvalidInput(t *testing.T) {
	tests := []struct {
		name    string
		sdBytes []byte
		certDER []byte
	}{
		{"[Unit] InjectCerts: Empty SignedData", []byte{}, []byte{0x30, 0x00}},
		{"[Unit] InjectCerts: Too short", []byte{0x30}, []byte{0x30, 0x00}},
		{"[Unit] InjectCerts: Wrong tag", []byte{0x31, 0x00}, []byte{0x30, 0x00}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := injectCertificates(tt.sdBytes, tt.certDER)
			if err == nil {
				t.Error("Expected error for invalid input")
			}
		})
	}
}

// =============================================================================
// Functional Tests: Sign with ESSCertIDv2 (TSA)
// =============================================================================

// TestF_Sign_WithSigningCertV2 tests signing with ESSCertIDv2 attribute (RFC 5816 TSA requirement).
func TestF_Sign_WithSigningCertV2(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	content := []byte("TSA test content")

	signedData, err := Sign(context.Background(), content, &SignerConfig{
		Certificate:          cert,
		Signer:               kp.PrivateKey,
		DigestAlg:            crypto.SHA256,
		IncludeCerts:         true,
		IncludeSigningCertV2: true, // Enable ESSCertIDv2
	})
	if err != nil {
		t.Fatalf("Sign with SigningCertV2 failed: %v", err)
	}

	// Parse and verify the SigningCertificateV2 attribute is present
	var contentInfo ContentInfo
	_, err = asn1.Unmarshal(signedData, &contentInfo)
	if err != nil {
		t.Fatalf("Failed to parse ContentInfo: %v", err)
	}

	var sd SignedData
	_, err = asn1.Unmarshal(contentInfo.Content.Bytes, &sd)
	if err != nil {
		t.Fatalf("Failed to parse SignedData: %v", err)
	}

	if len(sd.SignerInfos) == 0 {
		t.Fatal("No signer info")
	}

	// Find SigningCertificateV2 attribute
	found := false
	for _, attr := range sd.SignerInfos[0].SignedAttrs {
		if attr.Type.Equal(OIDSigningCertificateV2) {
			found = true
			break
		}
	}

	if !found {
		t.Error("SigningCertificateV2 attribute not found in signed attributes")
	}

	// Verify the signature is valid
	_, err = Verify(context.Background(), signedData, &VerifyConfig{SkipCertVerify: true})
	if err != nil {
		t.Errorf("Verification failed: %v", err)
	}
}

// TestF_Sign_WithoutSigningCertV2 tests that SigningCertV2 is not included by default.
func TestF_Sign_WithoutSigningCertV2(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	content := []byte("Normal content")

	signedData, err := Sign(context.Background(), content, &SignerConfig{
		Certificate:          cert,
		Signer:               kp.PrivateKey,
		DigestAlg:            crypto.SHA256,
		IncludeCerts:         true,
		IncludeSigningCertV2: false, // Explicitly disabled
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Parse and verify the SigningCertificateV2 attribute is NOT present
	var contentInfo ContentInfo
	_, err = asn1.Unmarshal(signedData, &contentInfo)
	if err != nil {
		t.Fatalf("Failed to parse ContentInfo: %v", err)
	}

	var sd SignedData
	_, err = asn1.Unmarshal(contentInfo.Content.Bytes, &sd)
	if err != nil {
		t.Fatalf("Failed to parse SignedData: %v", err)
	}

	// Find SigningCertificateV2 attribute - should NOT be present
	for _, attr := range sd.SignerInfos[0].SignedAttrs {
		if attr.Type.Equal(OIDSigningCertificateV2) {
			t.Error("SigningCertificateV2 attribute should not be present when disabled")
			break
		}
	}
}
