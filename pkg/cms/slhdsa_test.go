package cms

import (
	"context"
	"crypto"
	"encoding/asn1"
	"testing"

	pkicrypto "github.com/remiblancher/qpki/pkg/crypto"
)

// =============================================================================
// RFC 9814 Compliance Tests: SLH-DSA in CMS
// =============================================================================
//
// These tests verify compliance with RFC 9814 (SLH-DSA in CMS).
// RFC 9814 specifies:
//   - 12 SLH-DSA variants: 6 SHA2 + 6 SHAKE
//   - OIDs for all variants (2.16.840.1.101.3.4.3.20-31)
//   - Digest auto-selection based on security level
//   - Pure mode signing (no pre-hash)
//
// =============================================================================

// =============================================================================
// Functional Tests: SLH-DSA SHA2 Variants Sign/Verify
// =============================================================================

// TestF_RFC9814_SLHDSA_SHA2_AllVariants tests all 6 SHA2 variants.
func TestF_RFC9814_SLHDSA_SHA2_AllVariants(t *testing.T) {
	tests := []struct {
		name              string
		alg               pkicrypto.AlgorithmID
		expectedSigOID    asn1.ObjectIdentifier
		expectedDigestOID asn1.ObjectIdentifier
	}{
		{
			name:              "[RFC9814] SLH-DSA-SHA2-128s",
			alg:               pkicrypto.AlgSLHDSASHA2128s,
			expectedSigOID:    OIDSLHDSASHA2128s,
			expectedDigestOID: OIDSHA256, // NIST Level 1 -> SHA-256
		},
		{
			name:              "[RFC9814] SLH-DSA-SHA2-128f",
			alg:               pkicrypto.AlgSLHDSASHA2128f,
			expectedSigOID:    OIDSLHDSASHA2128f,
			expectedDigestOID: OIDSHA256, // NIST Level 1 -> SHA-256
		},
		{
			name:              "[RFC9814] SLH-DSA-SHA2-192s",
			alg:               pkicrypto.AlgSLHDSASHA2192s,
			expectedSigOID:    OIDSLHDSASHA2192s,
			expectedDigestOID: OIDSHA512, // NIST Level 3 -> SHA-512
		},
		{
			name:              "[RFC9814] SLH-DSA-SHA2-192f",
			alg:               pkicrypto.AlgSLHDSASHA2192f,
			expectedSigOID:    OIDSLHDSASHA2192f,
			expectedDigestOID: OIDSHA512, // NIST Level 3 -> SHA-512
		},
		{
			name:              "[RFC9814] SLH-DSA-SHA2-256s",
			alg:               pkicrypto.AlgSLHDSASHA2256s,
			expectedSigOID:    OIDSLHDSASHA2256s,
			expectedDigestOID: OIDSHA512, // NIST Level 5 -> SHA-512
		},
		{
			name:              "[RFC9814] SLH-DSA-SHA2-256f",
			alg:               pkicrypto.AlgSLHDSASHA2256f,
			expectedSigOID:    OIDSLHDSASHA2256f,
			expectedDigestOID: OIDSHA512, // NIST Level 5 -> SHA-512
		},
	}

	for _, tt := range tests {
		tt := tt // capture for parallel
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			kp := generateSLHDSAKeyPair(t, tt.alg)
			cert := generateSLHDSACertificate(t, kp, tt.alg)

			content := []byte("RFC 9814 SHA2 variant test content")

			signedData, err := Sign(context.Background(), content, &SignerConfig{
				Certificate:  cert,
				Signer:       kp.PrivateKey,
				IncludeCerts: true,
				// DigestAlg NOT set - should auto-select per RFC 9814
			})
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}

			// STRUCTURE: Verify signature algorithm OID
			sigOID := extractSignerInfoOID(t, signedData)
			if !sigOID.Equal(tt.expectedSigOID) {
				t.Errorf("Signature OID mismatch: expected %v, got %v", tt.expectedSigOID, sigOID)
			}

			// STRUCTURE: Verify digest algorithm OID (RFC 9814 auto-selection)
			digestOID := extractDigestAlgorithmOID(t, signedData)
			if !digestOID.Equal(tt.expectedDigestOID) {
				t.Errorf("Digest OID mismatch: expected %v, got %v", tt.expectedDigestOID, digestOID)
			}

			// CRYPTO: Verify signature
			result, err := Verify(context.Background(), signedData, &VerifyConfig{SkipCertVerify: true})
			if err != nil {
				t.Errorf("Verification failed: %v", err)
			}

			// Verify content round-trip
			if string(result.Content) != string(content) {
				t.Error("Content mismatch after verification")
			}
		})
	}
}

// =============================================================================
// Functional Tests: SLH-DSA SHAKE Variants Sign/Verify
// =============================================================================

// TestF_RFC9814_SLHDSA_SHAKE_AllVariants tests all 6 SHAKE variants.
func TestF_RFC9814_SLHDSA_SHAKE_AllVariants(t *testing.T) {
	tests := []struct {
		name              string
		alg               pkicrypto.AlgorithmID
		expectedSigOID    asn1.ObjectIdentifier
		expectedDigestOID asn1.ObjectIdentifier
	}{
		{
			name:              "[RFC9814] SLH-DSA-SHAKE-128s",
			alg:               pkicrypto.AlgSLHDSASHAKE128s,
			expectedSigOID:    OIDSLHDSASHAKE128s,
			expectedDigestOID: OIDSHA256, // NIST Level 1 -> SHA-256
		},
		{
			name:              "[RFC9814] SLH-DSA-SHAKE-128f",
			alg:               pkicrypto.AlgSLHDSASHAKE128f,
			expectedSigOID:    OIDSLHDSASHAKE128f,
			expectedDigestOID: OIDSHA256, // NIST Level 1 -> SHA-256
		},
		{
			name:              "[RFC9814] SLH-DSA-SHAKE-192s",
			alg:               pkicrypto.AlgSLHDSASHAKE192s,
			expectedSigOID:    OIDSLHDSASHAKE192s,
			expectedDigestOID: OIDSHA512, // NIST Level 3 -> SHA-512
		},
		{
			name:              "[RFC9814] SLH-DSA-SHAKE-192f",
			alg:               pkicrypto.AlgSLHDSASHAKE192f,
			expectedSigOID:    OIDSLHDSASHAKE192f,
			expectedDigestOID: OIDSHA512, // NIST Level 3 -> SHA-512
		},
		{
			name:              "[RFC9814] SLH-DSA-SHAKE-256s",
			alg:               pkicrypto.AlgSLHDSASHAKE256s,
			expectedSigOID:    OIDSLHDSASHAKE256s,
			expectedDigestOID: OIDSHA512, // NIST Level 5 -> SHA-512
		},
		{
			name:              "[RFC9814] SLH-DSA-SHAKE-256f",
			alg:               pkicrypto.AlgSLHDSASHAKE256f,
			expectedSigOID:    OIDSLHDSASHAKE256f,
			expectedDigestOID: OIDSHA512, // NIST Level 5 -> SHA-512
		},
	}

	for _, tt := range tests {
		tt := tt // capture for parallel
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			kp := generateSLHDSAKeyPair(t, tt.alg)
			cert := generateSLHDSACertificate(t, kp, tt.alg)

			content := []byte("RFC 9814 SHAKE variant test content")

			signedData, err := Sign(context.Background(), content, &SignerConfig{
				Certificate:  cert,
				Signer:       kp.PrivateKey,
				IncludeCerts: true,
				// DigestAlg NOT set - should auto-select per RFC 9814
			})
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}

			// STRUCTURE: Verify signature algorithm OID
			sigOID := extractSignerInfoOID(t, signedData)
			if !sigOID.Equal(tt.expectedSigOID) {
				t.Errorf("Signature OID mismatch: expected %v, got %v", tt.expectedSigOID, sigOID)
			}

			// STRUCTURE: Verify digest algorithm OID (RFC 9814 auto-selection)
			digestOID := extractDigestAlgorithmOID(t, signedData)
			if !digestOID.Equal(tt.expectedDigestOID) {
				t.Errorf("Digest OID mismatch: expected %v, got %v", tt.expectedDigestOID, digestOID)
			}

			// CRYPTO: Verify signature
			result, err := Verify(context.Background(), signedData, &VerifyConfig{SkipCertVerify: true})
			if err != nil {
				t.Errorf("Verification failed: %v", err)
			}

			// Verify content round-trip
			if string(result.Content) != string(content) {
				t.Error("Content mismatch after verification")
			}
		})
	}
}

// =============================================================================
// Functional Tests: Detached Signatures
// =============================================================================

// TestF_RFC9814_SLHDSA_Detached_SHA2 tests detached signatures with SHA2 variants.
func TestF_RFC9814_SLHDSA_Detached_SHA2(t *testing.T) {
	// Use fast variant for test speed
	alg := pkicrypto.AlgSLHDSASHA2128f
	kp := generateSLHDSAKeyPair(t, alg)
	cert := generateSLHDSACertificate(t, kp, alg)

	content := []byte("Detached SHA2 SLH-DSA content")

	signedData, err := Sign(context.Background(), content, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		IncludeCerts: true,
		Detached:     true,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Verify OID
	oid := extractSignerInfoOID(t, signedData)
	if !oid.Equal(OIDSLHDSASHA2128f) {
		t.Errorf("OID mismatch: expected SHA2-128f, got %v", oid)
	}

	// Verify with detached content
	result, err := Verify(context.Background(), signedData, &VerifyConfig{
		Data:           content,
		SkipCertVerify: true,
	})
	if err != nil {
		t.Fatalf("Verification failed: %v", err)
	}

	// Content should not be embedded (detached)
	if result.Content != nil {
		t.Error("Expected nil content for detached signature")
	}
}

// TestF_RFC9814_SLHDSA_Detached_SHAKE tests detached signatures with SHAKE variants.
func TestF_RFC9814_SLHDSA_Detached_SHAKE(t *testing.T) {
	// Use fast variant for test speed
	alg := pkicrypto.AlgSLHDSASHAKE128f
	kp := generateSLHDSAKeyPair(t, alg)
	cert := generateSLHDSACertificate(t, kp, alg)

	content := []byte("Detached SHAKE SLH-DSA content")

	signedData, err := Sign(context.Background(), content, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		IncludeCerts: true,
		Detached:     true,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Verify OID
	oid := extractSignerInfoOID(t, signedData)
	if !oid.Equal(OIDSLHDSASHAKE128f) {
		t.Errorf("OID mismatch: expected SHAKE-128f, got %v", oid)
	}

	// Verify with detached content
	result, err := Verify(context.Background(), signedData, &VerifyConfig{
		Data:           content,
		SkipCertVerify: true,
	})
	if err != nil {
		t.Fatalf("Verification failed: %v", err)
	}

	if result.Content != nil {
		t.Error("Expected nil content for detached signature")
	}
}

// =============================================================================
// Unit Tests: RFC 9814 Digest Auto-Selection
// =============================================================================

// TestU_RFC9814_DigestAutoSelection_SHA2 tests digest auto-selection for SHA2 variants.
func TestU_RFC9814_DigestAutoSelection_SHA2(t *testing.T) {
	tests := []struct {
		name           string
		alg            pkicrypto.AlgorithmID
		expectedDigest crypto.Hash
	}{
		// NIST Level 1 (128-bit) -> SHA-256
		{"[Unit] RFC9814: SHA2-128s -> SHA-256", pkicrypto.AlgSLHDSASHA2128s, crypto.SHA256},
		{"[Unit] RFC9814: SHA2-128f -> SHA-256", pkicrypto.AlgSLHDSASHA2128f, crypto.SHA256},
		// NIST Level 3 (192-bit) -> SHA-512
		{"[Unit] RFC9814: SHA2-192s -> SHA-512", pkicrypto.AlgSLHDSASHA2192s, crypto.SHA512},
		{"[Unit] RFC9814: SHA2-192f -> SHA-512", pkicrypto.AlgSLHDSASHA2192f, crypto.SHA512},
		// NIST Level 5 (256-bit) -> SHA-512
		{"[Unit] RFC9814: SHA2-256s -> SHA-512", pkicrypto.AlgSLHDSASHA2256s, crypto.SHA512},
		{"[Unit] RFC9814: SHA2-256f -> SHA-512", pkicrypto.AlgSLHDSASHA2256f, crypto.SHA512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kp := generateSLHDSAKeyPair(t, tt.alg)
			cert := generateSLHDSACertificate(t, kp, tt.alg)

			digest := selectDigestForSigner(kp.PrivateKey, cert)
			if digest != tt.expectedDigest {
				t.Errorf("Expected digest %v for %s, got %v", tt.expectedDigest, tt.alg, digest)
			}
		})
	}
}

// TestU_RFC9814_DigestAutoSelection_SHAKE tests digest auto-selection for SHAKE variants.
func TestU_RFC9814_DigestAutoSelection_SHAKE(t *testing.T) {
	tests := []struct {
		name           string
		alg            pkicrypto.AlgorithmID
		expectedDigest crypto.Hash
	}{
		// NIST Level 1 (128-bit) -> SHA-256
		{"[Unit] RFC9814: SHAKE-128s -> SHA-256", pkicrypto.AlgSLHDSASHAKE128s, crypto.SHA256},
		{"[Unit] RFC9814: SHAKE-128f -> SHA-256", pkicrypto.AlgSLHDSASHAKE128f, crypto.SHA256},
		// NIST Level 3 (192-bit) -> SHA-512
		{"[Unit] RFC9814: SHAKE-192s -> SHA-512", pkicrypto.AlgSLHDSASHAKE192s, crypto.SHA512},
		{"[Unit] RFC9814: SHAKE-192f -> SHA-512", pkicrypto.AlgSLHDSASHAKE192f, crypto.SHA512},
		// NIST Level 5 (256-bit) -> SHA-512
		{"[Unit] RFC9814: SHAKE-256s -> SHA-512", pkicrypto.AlgSLHDSASHAKE256s, crypto.SHA512},
		{"[Unit] RFC9814: SHAKE-256f -> SHA-512", pkicrypto.AlgSLHDSASHAKE256f, crypto.SHA512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kp := generateSLHDSAKeyPair(t, tt.alg)
			cert := generateSLHDSACertificate(t, kp, tt.alg)

			digest := selectDigestForSigner(kp.PrivateKey, cert)
			if digest != tt.expectedDigest {
				t.Errorf("Expected digest %v for %s, got %v", tt.expectedDigest, tt.alg, digest)
			}
		})
	}
}

// =============================================================================
// Unit Tests: Algorithm ID to OID Mapping
// =============================================================================

// TestU_RFC9814_AlgorithmIDToOID_SHA2 tests OID mapping for SHA2 variants.
func TestU_RFC9814_AlgorithmIDToOID_SHA2(t *testing.T) {
	tests := []struct {
		name        string
		alg         pkicrypto.AlgorithmID
		expectedOID asn1.ObjectIdentifier
	}{
		{"[Unit] AlgToOID: SHA2-128s", pkicrypto.AlgSLHDSASHA2128s, OIDSLHDSASHA2128s},
		{"[Unit] AlgToOID: SHA2-128f", pkicrypto.AlgSLHDSASHA2128f, OIDSLHDSASHA2128f},
		{"[Unit] AlgToOID: SHA2-192s", pkicrypto.AlgSLHDSASHA2192s, OIDSLHDSASHA2192s},
		{"[Unit] AlgToOID: SHA2-192f", pkicrypto.AlgSLHDSASHA2192f, OIDSLHDSASHA2192f},
		{"[Unit] AlgToOID: SHA2-256s", pkicrypto.AlgSLHDSASHA2256s, OIDSLHDSASHA2256s},
		{"[Unit] AlgToOID: SHA2-256f", pkicrypto.AlgSLHDSASHA2256f, OIDSLHDSASHA2256f},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oid := algorithmIDToOID(tt.alg)
			if oid == nil {
				t.Error("Expected non-nil OID, got nil")
			} else if !oid.Equal(tt.expectedOID) {
				t.Errorf("OID mismatch: expected %v, got %v", tt.expectedOID, oid)
			}
		})
	}
}

// TestU_RFC9814_AlgorithmIDToOID_SHAKE tests OID mapping for SHAKE variants.
func TestU_RFC9814_AlgorithmIDToOID_SHAKE(t *testing.T) {
	tests := []struct {
		name        string
		alg         pkicrypto.AlgorithmID
		expectedOID asn1.ObjectIdentifier
	}{
		{"[Unit] AlgToOID: SHAKE-128s", pkicrypto.AlgSLHDSASHAKE128s, OIDSLHDSASHAKE128s},
		{"[Unit] AlgToOID: SHAKE-128f", pkicrypto.AlgSLHDSASHAKE128f, OIDSLHDSASHAKE128f},
		{"[Unit] AlgToOID: SHAKE-192s", pkicrypto.AlgSLHDSASHAKE192s, OIDSLHDSASHAKE192s},
		{"[Unit] AlgToOID: SHAKE-192f", pkicrypto.AlgSLHDSASHAKE192f, OIDSLHDSASHAKE192f},
		{"[Unit] AlgToOID: SHAKE-256s", pkicrypto.AlgSLHDSASHAKE256s, OIDSLHDSASHAKE256s},
		{"[Unit] AlgToOID: SHAKE-256f", pkicrypto.AlgSLHDSASHAKE256f, OIDSLHDSASHAKE256f},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oid := algorithmIDToOID(tt.alg)
			if oid == nil {
				t.Error("Expected non-nil OID, got nil")
			} else if !oid.Equal(tt.expectedOID) {
				t.Errorf("OID mismatch: expected %v, got %v", tt.expectedOID, oid)
			}
		})
	}
}

// =============================================================================
// Functional Tests: Invalid Signature Detection
// =============================================================================

// TestF_RFC9814_SLHDSA_InvalidSignature tests that corrupted signatures are detected.
func TestF_RFC9814_SLHDSA_InvalidSignature(t *testing.T) {
	alg := pkicrypto.AlgSLHDSASHA2128f
	kp := generateSLHDSAKeyPair(t, alg)
	cert := generateSLHDSACertificate(t, kp, alg)

	content := []byte("Content to sign with SLH-DSA")

	signedData, err := Sign(context.Background(), content, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Modify signature
	modifiedData := modifySignature(t, signedData)

	_, err = Verify(context.Background(), modifiedData, &VerifyConfig{SkipCertVerify: true})
	if err == nil {
		t.Error("Verification should fail with corrupted SLH-DSA signature")
	}
}

// TestF_RFC9814_SLHDSA_ModifiedContent tests that modified content is detected.
func TestF_RFC9814_SLHDSA_ModifiedContent(t *testing.T) {
	alg := pkicrypto.AlgSLHDSASHAKE128f
	kp := generateSLHDSAKeyPair(t, alg)
	cert := generateSLHDSACertificate(t, kp, alg)

	content := []byte("Original SLH-DSA content")

	signedData, err := Sign(context.Background(), content, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Modify message digest
	modifiedData := modifyMessageDigest(t, signedData)

	_, err = Verify(context.Background(), modifiedData, &VerifyConfig{SkipCertVerify: true})
	if err == nil {
		t.Error("Verification should fail with modified content digest")
	}
}

// =============================================================================
// Functional Tests: Algorithm Mismatch Detection
// =============================================================================

// TestF_RFC9814_AlgorithmMismatch_SHA2vsSHAKE tests that SHA2 and SHAKE use different OIDs.
// Note: SLH-DSA keys internally know their algorithm variant, so modifying just the OID
// in CMS doesn't cause verification failure - the key's internal algorithm is used.
// This test verifies that different keys produce different OIDs.
func TestF_RFC9814_AlgorithmMismatch_SHA2vsSHAKE(t *testing.T) {
	content := []byte("Test content for algorithm mismatch")

	// Sign with SHA2 variant
	sha2Alg := pkicrypto.AlgSLHDSASHA2128f
	sha2KP := generateSLHDSAKeyPair(t, sha2Alg)
	sha2Cert := generateSLHDSACertificate(t, sha2KP, sha2Alg)

	sha2Signed, err := Sign(context.Background(), content, &SignerConfig{
		Certificate:  sha2Cert,
		Signer:       sha2KP.PrivateKey,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("SHA2 sign failed: %v", err)
	}

	// Sign with SHAKE variant
	shakeAlg := pkicrypto.AlgSLHDSASHAKE128f
	shakeKP := generateSLHDSAKeyPair(t, shakeAlg)
	shakeCert := generateSLHDSACertificate(t, shakeKP, shakeAlg)

	shakeSigned, err := Sign(context.Background(), content, &SignerConfig{
		Certificate:  shakeCert,
		Signer:       shakeKP.PrivateKey,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("SHAKE sign failed: %v", err)
	}

	// Verify different OIDs are used
	sha2OID := extractSignerInfoOID(t, sha2Signed)
	shakeOID := extractSignerInfoOID(t, shakeSigned)

	if sha2OID.Equal(shakeOID) {
		t.Error("SHA2 and SHAKE variants should use different OIDs")
	}

	// Verify SHA2 OID is in SHA2 range (20-25)
	if sha2OID[len(sha2OID)-1] < 20 || sha2OID[len(sha2OID)-1] > 25 {
		t.Errorf("SHA2 OID should end in 20-25, got %v", sha2OID)
	}

	// Verify SHAKE OID is in SHAKE range (26-31)
	if shakeOID[len(shakeOID)-1] < 26 || shakeOID[len(shakeOID)-1] > 31 {
		t.Errorf("SHAKE OID should end in 26-31, got %v", shakeOID)
	}
}

// =============================================================================
// Functional Tests: Explicit Digest Override
// =============================================================================

// TestF_RFC9814_ExplicitDigestOverride tests that explicit digest can override auto-selection.
func TestF_RFC9814_ExplicitDigestOverride(t *testing.T) {
	tests := []struct {
		name              string
		alg               pkicrypto.AlgorithmID
		explicitDigest    crypto.Hash
		expectedDigestOID asn1.ObjectIdentifier
	}{
		{
			name:              "[Functional] SLH-DSA-SHA2-256f with explicit SHA-256",
			alg:               pkicrypto.AlgSLHDSASHA2256f,
			explicitDigest:    crypto.SHA256,
			expectedDigestOID: OIDSHA256,
		},
		{
			name:              "[Functional] SLH-DSA-SHA2-128f with explicit SHA-512",
			alg:               pkicrypto.AlgSLHDSASHA2128f,
			explicitDigest:    crypto.SHA512,
			expectedDigestOID: OIDSHA512,
		},
		{
			name:              "[Functional] SLH-DSA-SHAKE-256f with explicit SHA-384",
			alg:               pkicrypto.AlgSLHDSASHAKE256f,
			explicitDigest:    crypto.SHA384,
			expectedDigestOID: OIDSHA384,
		},
	}

	for _, tt := range tests {
		tt := tt // capture for parallel
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			kp := generateSLHDSAKeyPair(t, tt.alg)
			cert := generateSLHDSACertificate(t, kp, tt.alg)

			content := []byte("Explicit digest override test")

			signedData, err := Sign(context.Background(), content, &SignerConfig{
				Certificate:  cert,
				Signer:       kp.PrivateKey,
				DigestAlg:    tt.explicitDigest, // Explicit override
				IncludeCerts: true,
			})
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}

			// Verify explicit digest was used
			digestOID := extractDigestAlgorithmOID(t, signedData)
			if !digestOID.Equal(tt.expectedDigestOID) {
				t.Errorf("Digest OID mismatch: expected %v, got %v", tt.expectedDigestOID, digestOID)
			}

			// Verify signature is valid
			_, err = Verify(context.Background(), signedData, &VerifyConfig{SkipCertVerify: true})
			if err != nil {
				t.Errorf("Verification failed: %v", err)
			}
		})
	}
}

// =============================================================================
// Functional Tests: SHA2 vs SHAKE Comparison
// =============================================================================

// TestF_RFC9814_SHA2vsSHAKE_Comparison tests that both SHA2 and SHAKE variants work correctly.
func TestF_RFC9814_SHA2vsSHAKE_Comparison(t *testing.T) {
	tests := []struct {
		name          string
		sha2Alg       pkicrypto.AlgorithmID
		shakeAlg      pkicrypto.AlgorithmID
		sha2OID       asn1.ObjectIdentifier
		shakeOID      asn1.ObjectIdentifier
		securityLevel string
	}{
		{
			name:          "Level 1 (128-bit)",
			sha2Alg:       pkicrypto.AlgSLHDSASHA2128f,
			shakeAlg:      pkicrypto.AlgSLHDSASHAKE128f,
			sha2OID:       OIDSLHDSASHA2128f,
			shakeOID:      OIDSLHDSASHAKE128f,
			securityLevel: "NIST Level 1",
		},
		{
			name:          "Level 3 (192-bit)",
			sha2Alg:       pkicrypto.AlgSLHDSASHA2192f,
			shakeAlg:      pkicrypto.AlgSLHDSASHAKE192f,
			sha2OID:       OIDSLHDSASHA2192f,
			shakeOID:      OIDSLHDSASHAKE192f,
			securityLevel: "NIST Level 3",
		},
		{
			name:          "Level 5 (256-bit)",
			sha2Alg:       pkicrypto.AlgSLHDSASHA2256f,
			shakeAlg:      pkicrypto.AlgSLHDSASHAKE256f,
			sha2OID:       OIDSLHDSASHA2256f,
			shakeOID:      OIDSLHDSASHAKE256f,
			securityLevel: "NIST Level 5",
		},
	}

	for _, tt := range tests {
		tt := tt // capture for parallel
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			content := []byte("SHA2 vs SHAKE comparison test for " + tt.securityLevel)

			// Test SHA2 variant
			sha2KP := generateSLHDSAKeyPair(t, tt.sha2Alg)
			sha2Cert := generateSLHDSACertificate(t, sha2KP, tt.sha2Alg)

			sha2Signed, err := Sign(context.Background(), content, &SignerConfig{
				Certificate:  sha2Cert,
				Signer:       sha2KP.PrivateKey,
				IncludeCerts: true,
			})
			if err != nil {
				t.Fatalf("SHA2 sign failed: %v", err)
			}

			sha2SigOID := extractSignerInfoOID(t, sha2Signed)
			if !sha2SigOID.Equal(tt.sha2OID) {
				t.Errorf("SHA2 OID mismatch: expected %v, got %v", tt.sha2OID, sha2SigOID)
			}

			_, err = Verify(context.Background(), sha2Signed, &VerifyConfig{SkipCertVerify: true})
			if err != nil {
				t.Errorf("SHA2 verification failed: %v", err)
			}

			// Test SHAKE variant
			shakeKP := generateSLHDSAKeyPair(t, tt.shakeAlg)
			shakeCert := generateSLHDSACertificate(t, shakeKP, tt.shakeAlg)

			shakeSigned, err := Sign(context.Background(), content, &SignerConfig{
				Certificate:  shakeCert,
				Signer:       shakeKP.PrivateKey,
				IncludeCerts: true,
			})
			if err != nil {
				t.Fatalf("SHAKE sign failed: %v", err)
			}

			shakeSigOID := extractSignerInfoOID(t, shakeSigned)
			if !shakeSigOID.Equal(tt.shakeOID) {
				t.Errorf("SHAKE OID mismatch: expected %v, got %v", tt.shakeOID, shakeSigOID)
			}

			_, err = Verify(context.Background(), shakeSigned, &VerifyConfig{SkipCertVerify: true})
			if err != nil {
				t.Errorf("SHAKE verification failed: %v", err)
			}
		})
	}
}

// =============================================================================
// Integration Tests: pkicrypto Package Integration
// =============================================================================

// TestI_RFC9814_SignerFromPkiCrypto tests SLH-DSA keys from pkicrypto package.
func TestU_CMS_RFC9814_SignerFromPkiCrypto(t *testing.T) {
	tests := []struct {
		name        string
		alg         pkicrypto.AlgorithmID
		expectedOID asn1.ObjectIdentifier
	}{
		{"[Integration] SHA2-128f via pkicrypto", pkicrypto.AlgSLHDSASHA2128f, OIDSLHDSASHA2128f},
		{"[Integration] SHAKE-128f via pkicrypto", pkicrypto.AlgSLHDSASHAKE128f, OIDSLHDSASHAKE128f},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate key using pkicrypto directly
			signer, err := pkicrypto.GenerateSoftwareSigner(tt.alg)
			if err != nil {
				t.Fatalf("GenerateSoftwareSigner failed: %v", err)
			}

			// Create test key pair wrapper
			kp := &testKeyPair{
				PrivateKey: signer,
				PublicKey:  signer.Public(),
				Algorithm:  string(tt.alg),
			}

			cert := generateSLHDSACertificate(t, kp, tt.alg)

			content := []byte("Integration test content")

			signedData, err := Sign(context.Background(), content, &SignerConfig{
				Certificate:  cert,
				Signer:       signer,
				IncludeCerts: true,
			})
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}

			// Verify OID
			sigOID := extractSignerInfoOID(t, signedData)
			if !sigOID.Equal(tt.expectedOID) {
				t.Errorf("OID mismatch: expected %v, got %v", tt.expectedOID, sigOID)
			}

			_, err = Verify(context.Background(), signedData, &VerifyConfig{SkipCertVerify: true})
			if err != nil {
				t.Fatalf("Verification failed: %v", err)
			}
		})
	}
}

// =============================================================================
// Unit Tests: OID Validation
// =============================================================================

// TestU_RFC9814_OIDValues verifies RFC 9814 OID values are correct.
func TestU_RFC9814_OIDValues(t *testing.T) {
	// RFC 9814 specifies OIDs 2.16.840.1.101.3.4.3.20-31
	baseOID := []int{2, 16, 840, 1, 101, 3, 4, 3}

	tests := []struct {
		name   string
		oid    asn1.ObjectIdentifier
		suffix int
	}{
		// SHA2 variants (20-25)
		{"SHA2-128s", OIDSLHDSASHA2128s, 20},
		{"SHA2-128f", OIDSLHDSASHA2128f, 21},
		{"SHA2-192s", OIDSLHDSASHA2192s, 22},
		{"SHA2-192f", OIDSLHDSASHA2192f, 23},
		{"SHA2-256s", OIDSLHDSASHA2256s, 24},
		{"SHA2-256f", OIDSLHDSASHA2256f, 25},
		// SHAKE variants (26-31)
		{"SHAKE-128s", OIDSLHDSASHAKE128s, 26},
		{"SHAKE-128f", OIDSLHDSASHAKE128f, 27},
		{"SHAKE-192s", OIDSLHDSASHAKE192s, 28},
		{"SHAKE-192f", OIDSLHDSASHAKE192f, 29},
		{"SHAKE-256s", OIDSLHDSASHAKE256s, 30},
		{"SHAKE-256f", OIDSLHDSASHAKE256f, 31},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expectedOID := append(asn1.ObjectIdentifier(nil), baseOID...)
			expectedOID = append(expectedOID, tt.suffix)

			if !tt.oid.Equal(expectedOID) {
				t.Errorf("OID mismatch for %s: expected %v, got %v", tt.name, expectedOID, tt.oid)
			}
		})
	}
}

// TestU_RFC9814_BackwardsCompatibilityAliases tests backwards compatibility aliases.
func TestU_RFC9814_BackwardsCompatibilityAliases(t *testing.T) {
	tests := []struct {
		name     string
		alias    asn1.ObjectIdentifier
		expected asn1.ObjectIdentifier
	}{
		{"OIDSLHDSA128s -> SHA2", OIDSLHDSA128s, OIDSLHDSASHA2128s},
		{"OIDSLHDSA128f -> SHA2", OIDSLHDSA128f, OIDSLHDSASHA2128f},
		{"OIDSLHDSA192s -> SHA2", OIDSLHDSA192s, OIDSLHDSASHA2192s},
		{"OIDSLHDSA192f -> SHA2", OIDSLHDSA192f, OIDSLHDSASHA2192f},
		{"OIDSLHDSA256s -> SHA2", OIDSLHDSA256s, OIDSLHDSASHA2256s},
		{"OIDSLHDSA256f -> SHA2", OIDSLHDSA256f, OIDSLHDSASHA2256f},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.alias.Equal(tt.expected) {
				t.Errorf("Backwards compatibility alias broken: %v != %v", tt.alias, tt.expected)
			}
		})
	}
}

// =============================================================================
// Functional Tests: Large Content
// =============================================================================

// TestF_RFC9814_LargeContent tests SLH-DSA signing with large content.
func TestF_RFC9814_LargeContent(t *testing.T) {
	alg := pkicrypto.AlgSLHDSASHA2128f
	kp := generateSLHDSAKeyPair(t, alg)
	cert := generateSLHDSACertificate(t, kp, alg)

	// 256 KB content
	largeContent := make([]byte, 256*1024)
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
		t.Fatalf("Verification failed for large content: %v", err)
	}

	if len(result.Content) != len(largeContent) {
		t.Errorf("Content length mismatch: expected %d, got %d", len(largeContent), len(result.Content))
	}
}

// =============================================================================
// Functional Tests: Empty Content
// =============================================================================

// TestF_RFC9814_EmptyContent tests SLH-DSA signing with empty content.
func TestF_RFC9814_EmptyContent(t *testing.T) {
	alg := pkicrypto.AlgSLHDSASHAKE128f
	kp := generateSLHDSAKeyPair(t, alg)
	cert := generateSLHDSACertificate(t, kp, alg)

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
		t.Fatalf("Verification failed for empty content: %v", err)
	}

	if len(result.Content) != 0 {
		t.Errorf("Expected empty content, got %d bytes", len(result.Content))
	}
}
