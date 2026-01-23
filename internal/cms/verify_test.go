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

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/remiblancher/post-quantum-pki/internal/ca"
	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
)

// =============================================================================
// Security Tests: Algorithm Confusion (TDD - must FAIL before fix)
// =============================================================================

// TestF_Verify_AlgorithmConfusion_OIDNotKeyType tests that verification is driven by the declared
// OID in SignerInfo.SignatureAlgorithm, NOT by the Go key type.
//
// SECURITY: This is the "golden rule" test. The algorithm used for verification
// MUST be determined by the OID (and its parameters), NEVER by the Go key type.
//
// This test creates a valid ECDSA signature, then modifies the OID to RSA.
// If the implementation switches on key type instead of OID, it would verify
// successfully (wrong!). The correct behavior is to REJECT because OID says RSA
// but the key is ECDSA.
func TestF_Verify_AlgorithmConfusion_OIDNotKeyType(t *testing.T) {
	// Setup: Create ECDSA key and certificate
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	content := []byte("test content for algorithm confusion")

	// Sign with ECDSA (legitimate)
	signConfig := &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA256,
		IncludeCerts: true,
	}

	signedData, err := Sign(context.Background(), content, signConfig)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Verify the OID is ECDSA
	oid := extractSignerInfoOID(t, signedData)
	if !oid.Equal(OIDECDSAWithSHA256) {
		t.Fatalf("Expected ECDSA OID, got %v", oid)
	}

	// ATTACK: Modify the OID to RSA (SHA256WithRSA)
	// The signature is still a valid ECDSA signature, but OID claims RSA
	tamperedData := modifySignedDataOID(t, signedData, OIDSHA256WithRSA)

	// Verify should FAIL because OID says RSA but key is ECDSA
	// If this passes, we have an algorithm confusion vulnerability!
	_, err = Verify(context.Background(), tamperedData, &VerifyConfig{SkipCertVerify: true})
	if err == nil {
		t.Fatal("SECURITY VULNERABILITY: Verification succeeded despite OID/key type mismatch. " +
			"The implementation switches on Go key type instead of validating OID. " +
			"This allows algorithm confusion attacks (CVE-2024-49958, CVE-2022-21449)")
	}

	// The error should indicate algorithm mismatch
	t.Logf("Correctly rejected with error: %v", err)
}

// TestF_Verify_AlgorithmMismatch_RSADeclaredECDSAKey tests that RSA OID with ECDSA key is rejected.
func TestF_Verify_AlgorithmMismatch_RSADeclaredECDSAKey(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	content := []byte("test content")

	// Sign with ECDSA
	signedData, err := Sign(context.Background(), content, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA256,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Tamper: Change OID to RSA
	tamperedData := modifySignedDataOID(t, signedData, OIDSHA256WithRSA)

	// Must fail - OID says RSA, key is ECDSA
	_, err = Verify(context.Background(), tamperedData, &VerifyConfig{SkipCertVerify: true})
	if err == nil {
		t.Fatal("SECURITY: Should reject RSA OID with ECDSA key")
	}
	t.Logf("Correctly rejected RSA/ECDSA mismatch: %v", err)
}

// TestF_Verify_AlgorithmMismatch_ECDSADeclaredRSAKey tests that ECDSA OID with RSA key is rejected.
func TestF_Verify_AlgorithmMismatch_ECDSADeclaredRSAKey(t *testing.T) {
	kp := generateRSAKeyPair(t, 2048)
	cert := generateTestCertificate(t, kp)

	content := []byte("test content")

	// Sign with RSA
	signedData, err := Sign(context.Background(), content, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA256,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Tamper: Change OID to ECDSA
	tamperedData := modifySignedDataOID(t, signedData, OIDECDSAWithSHA256)

	// Must fail - OID says ECDSA, key is RSA
	_, err = Verify(context.Background(), tamperedData, &VerifyConfig{SkipCertVerify: true})
	if err == nil {
		t.Fatal("SECURITY: Should reject ECDSA OID with RSA key")
	}
	t.Logf("Correctly rejected ECDSA/RSA mismatch: %v", err)
}

// TestF_Verify_AlgorithmMismatch_Ed25519DeclaredECDSAKey tests Ed25519 OID with ECDSA key.
func TestF_Verify_AlgorithmMismatch_Ed25519DeclaredECDSAKey(t *testing.T) {
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
		t.Fatalf("Failed to sign: %v", err)
	}

	// Tamper: Change OID to Ed25519
	tamperedData := modifySignedDataOID(t, signedData, OIDEd25519)

	_, err = Verify(context.Background(), tamperedData, &VerifyConfig{SkipCertVerify: true})
	if err == nil {
		t.Fatal("SECURITY: Should reject Ed25519 OID with ECDSA key")
	}
	t.Logf("Correctly rejected Ed25519/ECDSA mismatch: %v", err)
}

// TestF_Verify_AlgorithmMismatch_CurveP256vsP384 tests curve mismatch detection.
func TestF_Verify_AlgorithmMismatch_CurveP256vsP384(t *testing.T) {
	// Sign with P-256
	kpP256 := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kpP256)

	content := []byte("test content")

	signedData, err := Sign(context.Background(), content, &SignerConfig{
		Certificate:  cert,
		Signer:       kpP256.PrivateKey,
		DigestAlg:    crypto.SHA256,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Tamper: Change OID to ECDSA-SHA384 (implies P-384)
	tamperedData := modifySignedDataOID(t, signedData, OIDECDSAWithSHA384)

	// Should fail - hash algorithm mismatch (SHA256 was used, but OID says SHA384)
	_, err = Verify(context.Background(), tamperedData, &VerifyConfig{SkipCertVerify: true})
	if err == nil {
		t.Fatal("SECURITY: Should reject hash algorithm mismatch")
	}
	t.Logf("Correctly rejected curve/hash mismatch: %v", err)
}

// TestF_Verify_AlgorithmMismatch_MLDSADeclaredECDSAKey tests ML-DSA OID with ECDSA key.
func TestF_Verify_AlgorithmMismatch_MLDSADeclaredECDSAKey(t *testing.T) {
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
		t.Fatalf("Failed to sign: %v", err)
	}

	// Tamper: Change OID to ML-DSA-65
	tamperedData := modifySignedDataOID(t, signedData, OIDMLDSA65)

	_, err = Verify(context.Background(), tamperedData, &VerifyConfig{SkipCertVerify: true})
	if err == nil {
		t.Fatal("SECURITY: Should reject ML-DSA OID with ECDSA key")
	}
	t.Logf("Correctly rejected ML-DSA/ECDSA mismatch: %v", err)
}

// =============================================================================
// Functional Tests: Basic Sign/Verify Round-trip
// =============================================================================

// TestF_SignVerify_ECDSAP256 tests ECDSA P-256 sign and verify round trip.
func TestF_SignVerify_ECDSAP256(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	content := []byte("Hello, CMS!")

	signConfig := &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA256,
		IncludeCerts: true,
	}

	// Sign
	signedData, err := Sign(context.Background(), content, signConfig)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Verify OID matches expected algorithm
	oid := extractSignerInfoOID(t, signedData)
	if !oid.Equal(OIDECDSAWithSHA256) {
		t.Errorf("OID mismatch: expected ECDSA-SHA256, got %v", oid)
	}

	// Verify
	result, err := Verify(context.Background(), signedData, &VerifyConfig{SkipCertVerify: true})
	if err != nil {
		t.Fatalf("Failed to verify: %v", err)
	}

	if result.SignerCert == nil {
		t.Error("SignerCert is nil")
	}

	// Verify content matches
	if string(result.Content) != string(content) {
		t.Errorf("Content mismatch: expected %q, got %q", content, result.Content)
	}
}

// TestF_SignVerify_ECDSAP384 tests ECDSA P-384 sign and verify round trip.
func TestF_SignVerify_ECDSAP384(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P384())
	cert := generateTestCertificate(t, kp)

	content := []byte("Hello, CMS with P-384!")

	signConfig := &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA384,
		IncludeCerts: true,
	}

	signedData, err := Sign(context.Background(), content, signConfig)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	oid := extractSignerInfoOID(t, signedData)
	if !oid.Equal(OIDECDSAWithSHA384) {
		t.Errorf("OID mismatch: expected ECDSA-SHA384, got %v", oid)
	}

	result, err := Verify(context.Background(), signedData, &VerifyConfig{SkipCertVerify: true})
	if err != nil {
		t.Fatalf("Failed to verify: %v", err)
	}

	if string(result.Content) != string(content) {
		t.Errorf("Content mismatch")
	}
}

// TestF_SignVerify_RSA tests RSA sign and verify round trip.
func TestF_SignVerify_RSA(t *testing.T) {
	kp := generateRSAKeyPair(t, 2048)
	cert := generateTestCertificate(t, kp)

	content := []byte("Hello, CMS with RSA!")

	signConfig := &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA256,
		IncludeCerts: true,
	}

	signedData, err := Sign(context.Background(), content, signConfig)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	oid := extractSignerInfoOID(t, signedData)
	if !oid.Equal(OIDSHA256WithRSA) {
		t.Errorf("OID mismatch: expected RSA-SHA256, got %v", oid)
	}

	result, err := Verify(context.Background(), signedData, &VerifyConfig{SkipCertVerify: true})
	if err != nil {
		t.Fatalf("Failed to verify: %v", err)
	}

	if string(result.Content) != string(content) {
		t.Errorf("Content mismatch")
	}
}

// TestF_SignVerify_Ed25519 tests Ed25519 sign and verify round trip.
func TestF_SignVerify_Ed25519(t *testing.T) {
	kp := generateEd25519KeyPair(t)
	cert := generateTestCertificate(t, kp)

	content := []byte("Hello, CMS with Ed25519!")

	signConfig := &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		IncludeCerts: true,
	}

	signedData, err := Sign(context.Background(), content, signConfig)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	oid := extractSignerInfoOID(t, signedData)
	if !oid.Equal(OIDEd25519) {
		t.Errorf("OID mismatch: expected Ed25519, got %v", oid)
	}

	result, err := Verify(context.Background(), signedData, &VerifyConfig{SkipCertVerify: true})
	if err != nil {
		t.Fatalf("Failed to verify: %v", err)
	}

	if string(result.Content) != string(content) {
		t.Errorf("Content mismatch")
	}
}

// =============================================================================
// Functional Tests: Detached Signatures
// =============================================================================

// TestF_SignVerify_DetachedECDSA tests detached ECDSA signature.
func TestF_SignVerify_DetachedECDSA(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	content := []byte("Detached content for ECDSA")

	signConfig := &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA256,
		IncludeCerts: true,
		Detached:     true,
	}

	signedData, err := Sign(context.Background(), content, signConfig)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Verify OID
	oid := extractSignerInfoOID(t, signedData)
	if !oid.Equal(OIDECDSAWithSHA256) {
		t.Errorf("OID mismatch: expected ECDSA-SHA256, got %v", oid)
	}

	// Verify with detached content
	result, err := Verify(context.Background(), signedData, &VerifyConfig{
		Data:           content,
		SkipCertVerify: true,
	})
	if err != nil {
		t.Fatalf("Failed to verify: %v", err)
	}

	// Content should not be in the result (detached)
	if result.Content != nil {
		t.Error("Expected nil content for detached signature")
	}
}

// TestF_SignVerify_DetachedRSA tests detached RSA signature.
func TestF_SignVerify_DetachedRSA(t *testing.T) {
	kp := generateRSAKeyPair(t, 2048)
	cert := generateTestCertificate(t, kp)

	content := []byte("Detached content for RSA")

	signConfig := &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA256,
		IncludeCerts: true,
		Detached:     true,
	}

	signedData, err := Sign(context.Background(), content, signConfig)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	oid := extractSignerInfoOID(t, signedData)
	if !oid.Equal(OIDSHA256WithRSA) {
		t.Errorf("OID mismatch: expected RSA-SHA256, got %v", oid)
	}

	_, err = Verify(context.Background(), signedData, &VerifyConfig{
		Data:           content,
		SkipCertVerify: true,
	})
	if err != nil {
		t.Fatalf("Failed to verify: %v", err)
	}
}

// =============================================================================
// Unit Tests: Invalid Signatures (Negative Tests)
// =============================================================================

// TestU_Verify_SignatureInvalid tests that tampered signatures are rejected.
func TestU_Verify_SignatureInvalid(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	content := []byte("Content to tamper")

	signedData, err := Sign(context.Background(), content, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA256,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Tamper with signature
	tamperedData := modifySignature(t, signedData)

	_, err = Verify(context.Background(), tamperedData, &VerifyConfig{SkipCertVerify: true})
	if err == nil {
		t.Fatal("Verification should fail for tampered signature")
	}
	t.Logf("Correctly rejected tampered signature: %v", err)
}

// TestU_Verify_MessageDigestInvalid tests that tampered message digest is rejected.
func TestU_Verify_MessageDigestInvalid(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	content := []byte("Content with digest to tamper")

	signedData, err := Sign(context.Background(), content, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA256,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Tamper with message digest
	tamperedData := modifyMessageDigest(t, signedData)

	_, err = Verify(context.Background(), tamperedData, &VerifyConfig{SkipCertVerify: true})
	if err == nil {
		t.Fatal("Verification should fail for tampered message digest")
	}
	t.Logf("Correctly rejected tampered message digest: %v", err)
}

// TestU_Verify_WrongDetachedContent tests wrong content for detached signature.
func TestU_Verify_WrongDetachedContent(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	originalContent := []byte("Original content")
	wrongContent := []byte("Wrong content")

	signedData, err := Sign(context.Background(), originalContent, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA256,
		IncludeCerts: true,
		Detached:     true,
	})
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Verify with wrong content
	_, err = Verify(context.Background(), signedData, &VerifyConfig{
		Data:           wrongContent,
		SkipCertVerify: true,
	})
	if err == nil {
		t.Fatal("Verification should fail for wrong detached content")
	}
	t.Logf("Correctly rejected wrong content: %v", err)
}

// =============================================================================
// Functional Tests: Certificate Chain Verification
// =============================================================================

// TestF_Verify_CertificateChain tests certificate chain verification.
func TestF_Verify_CertificateChain(t *testing.T) {
	// Create CA
	caCert, caKey := generateTestCA(t)

	// Create end entity key and certificate
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, caCert, caKey, kp)

	content := []byte("Content with chain verification")

	signedData, err := Sign(context.Background(), content, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA256,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Create root pool
	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	// Verify with chain
	result, err := Verify(context.Background(), signedData, &VerifyConfig{
		Roots: roots,
	})
	if err != nil {
		t.Fatalf("Failed to verify with chain: %v", err)
	}

	if result.SignerCert == nil {
		t.Error("SignerCert is nil")
	}
}

// TestU_Verify_CertificateUntrusted tests that untrusted certificates are rejected.
func TestU_Verify_CertificateUntrusted(t *testing.T) {
	// Create two different CAs
	trustedCACert, _ := generateTestCA(t)
	untrustedCACert, untrustedCAKey := generateTestCA(t)

	// Create end entity key and certificate signed by untrusted CA
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, untrustedCACert, untrustedCAKey, kp)

	content := []byte("Content from untrusted source")

	signedData, err := Sign(context.Background(), content, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA256,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Create root pool with only trusted CA
	roots := x509.NewCertPool()
	roots.AddCert(trustedCACert)

	// Verify should fail - certificate is not from trusted CA
	_, err = Verify(context.Background(), signedData, &VerifyConfig{
		Roots: roots,
	})
	if err == nil {
		t.Fatal("Verification should fail for untrusted certificate")
	}
	t.Logf("Correctly rejected untrusted certificate: %v", err)
}

// =============================================================================
// Unit Tests: Algorithm Validation Helpers
// =============================================================================

// TestU_ValidatePQCKeyMatch tests the validatePQCKeyMatch function.
func TestU_ValidatePQCKeyMatch(t *testing.T) {
	// Generate ML-DSA key for testing
	mldsaKP := generateMLDSAKeyPair(t, pkicrypto.AlgMLDSA65)

	tests := []struct {
		name        string
		sigAlgOID   asn1.ObjectIdentifier
		pub         crypto.PublicKey
		expectError bool
	}{
		{
			name:        "[Unit] PQCKeyMatch: ML-DSA-65 OID with ML-DSA-65 key",
			sigAlgOID:   OIDMLDSA65,
			pub:         mldsaKP.PublicKey,
			expectError: false,
		},
		{
			name:        "[Unit] PQCKeyMatch: SLH-DSA-128f OID (valid SLH-DSA)",
			sigAlgOID:   OIDSLHDSA128f,
			pub:         nil, // SLH-DSA validation doesn't check key
			expectError: false,
		},
		{
			name:        "[Unit] PQCKeyMatch: SLH-DSA-128s OID (valid SLH-DSA)",
			sigAlgOID:   OIDSLHDSA128s,
			pub:         nil,
			expectError: false,
		},
		{
			name:        "[Unit] PQCKeyMatch: Unknown OID",
			sigAlgOID:   asn1.ObjectIdentifier{1, 2, 3, 4, 5},
			pub:         mldsaKP.PublicKey,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePQCKeyMatch(tt.sigAlgOID, tt.pub)
			if tt.expectError && err == nil {
				t.Error("Expected error but got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

// TestU_ValidateMLDSAKeyMatch tests the validateMLDSAKeyMatch function.
func TestU_ValidateMLDSAKeyMatch(t *testing.T) {
	// Generate ML-DSA keys for testing
	mldsa44KP := generateMLDSAKeyPair(t, pkicrypto.AlgMLDSA44)
	mldsa65KP := generateMLDSAKeyPair(t, pkicrypto.AlgMLDSA65)
	mldsa87KP := generateMLDSAKeyPair(t, pkicrypto.AlgMLDSA87)

	tests := []struct {
		name        string
		sigAlgOID   asn1.ObjectIdentifier
		pub         crypto.PublicKey
		expectError bool
	}{
		{
			name:        "[Unit] MLDSAKeyMatch: ML-DSA-44 OID with ML-DSA-44 key",
			sigAlgOID:   OIDMLDSA44,
			pub:         mldsa44KP.PublicKey,
			expectError: false,
		},
		{
			name:        "[Unit] MLDSAKeyMatch: ML-DSA-65 OID with ML-DSA-65 key",
			sigAlgOID:   OIDMLDSA65,
			pub:         mldsa65KP.PublicKey,
			expectError: false,
		},
		{
			name:        "[Unit] MLDSAKeyMatch: ML-DSA-87 OID with ML-DSA-87 key",
			sigAlgOID:   OIDMLDSA87,
			pub:         mldsa87KP.PublicKey,
			expectError: false,
		},
		{
			name:        "[Unit] MLDSAKeyMatch: ML-DSA-44 OID with ML-DSA-65 key (mismatch)",
			sigAlgOID:   OIDMLDSA44,
			pub:         mldsa65KP.PublicKey,
			expectError: true,
		},
		{
			name:        "[Unit] MLDSAKeyMatch: ML-DSA-65 OID with ML-DSA-87 key (mismatch)",
			sigAlgOID:   OIDMLDSA65,
			pub:         mldsa87KP.PublicKey,
			expectError: true,
		},
		{
			name:        "[Unit] MLDSAKeyMatch: Non-ML-DSA OID",
			sigAlgOID:   OIDECDSAWithSHA256,
			pub:         mldsa65KP.PublicKey,
			expectError: true,
		},
		{
			name:        "[Unit] MLDSAKeyMatch: Nil key (should pass if OID is valid)",
			sigAlgOID:   OIDMLDSA65,
			pub:         nil,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateMLDSAKeyMatch(tt.sigAlgOID, tt.pub)
			if tt.expectError && err == nil {
				t.Error("Expected error but got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

// TestU_IsSLHDSAOID tests the isSLHDSAOID function.
func TestU_IsSLHDSAOID(t *testing.T) {
	tests := []struct {
		name     string
		oid      asn1.ObjectIdentifier
		expected bool
	}{
		{"[Unit] isSLHDSAOID: SLH-DSA-128s", OIDSLHDSA128s, true},
		{"[Unit] isSLHDSAOID: SLH-DSA-128f", OIDSLHDSA128f, true},
		{"[Unit] isSLHDSAOID: SLH-DSA-192s", OIDSLHDSA192s, true},
		{"[Unit] isSLHDSAOID: SLH-DSA-192f", OIDSLHDSA192f, true},
		{"[Unit] isSLHDSAOID: SLH-DSA-256s", OIDSLHDSA256s, true},
		{"[Unit] isSLHDSAOID: SLH-DSA-256f", OIDSLHDSA256f, true},
		{"[Unit] isSLHDSAOID: ML-DSA-65 (not SLH-DSA)", OIDMLDSA65, false},
		{"[Unit] isSLHDSAOID: ECDSA-SHA256 (not SLH-DSA)", OIDECDSAWithSHA256, false},
		{"[Unit] isSLHDSAOID: Unknown OID", asn1.ObjectIdentifier{1, 2, 3, 4}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isSLHDSAOID(tt.oid)
			if result != tt.expected {
				t.Errorf("isSLHDSAOID(%v) = %v, expected %v", tt.oid, result, tt.expected)
			}
		})
	}
}

// TestU_OidToHash tests the oidToHash function.
func TestU_OidToHash(t *testing.T) {
	tests := []struct {
		name         string
		oid          asn1.ObjectIdentifier
		expectedHash crypto.Hash
		expectError  bool
	}{
		{"[Unit] oidToHash: SHA-256", OIDSHA256, crypto.SHA256, false},
		{"[Unit] oidToHash: SHA-384", OIDSHA384, crypto.SHA384, false},
		{"[Unit] oidToHash: SHA-512", OIDSHA512, crypto.SHA512, false},
		{"[Unit] oidToHash: SHA3-256", OIDSHA3_256, crypto.SHA3_256, false},
		{"[Unit] oidToHash: SHA3-384", OIDSHA3_384, crypto.SHA3_384, false},
		{"[Unit] oidToHash: SHA3-512", OIDSHA3_512, crypto.SHA3_512, false},
		{"[Unit] oidToHash: Unknown OID", asn1.ObjectIdentifier{1, 2, 3}, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := oidToHash(tt.oid)
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if hash != tt.expectedHash {
					t.Errorf("Hash mismatch: expected %v, got %v", tt.expectedHash, hash)
				}
			}
		})
	}
}

// TestU_ExtractSigningTime tests the extractSigningTime function.
func TestU_ExtractSigningTime(t *testing.T) {
	// Create a signing time attribute
	testTime := time.Date(2024, 6, 15, 12, 30, 45, 0, time.UTC)
	stAttr, err := NewSigningTimeAttr(testTime)
	if err != nil {
		t.Fatalf("Failed to create signing time attr: %v", err)
	}

	tests := []struct {
		name         string
		attrs        []Attribute
		expectedTime time.Time
	}{
		{
			name:         "[Unit] ExtractSigningTime: With signing time",
			attrs:        []Attribute{stAttr},
			expectedTime: testTime,
		},
		{
			name:         "[Unit] ExtractSigningTime: Empty attrs",
			attrs:        []Attribute{},
			expectedTime: time.Time{},
		},
		{
			name: "[Unit] ExtractSigningTime: No signing time attr",
			attrs: []Attribute{
				{Type: OIDContentType, Values: []asn1.RawValue{{FullBytes: []byte{0x06, 0x01, 0x01}}}},
			},
			expectedTime: time.Time{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractSigningTime(tt.attrs)
			if !result.Equal(tt.expectedTime) {
				t.Errorf("Time mismatch: expected %v, got %v", tt.expectedTime, result)
			}
		})
	}
}

// TestU_ValidateECDSAKeyMatch tests ECDSA OID validation.
func TestU_ValidateECDSAKeyMatch(t *testing.T) {
	tests := []struct {
		name        string
		sigAlgOID   asn1.ObjectIdentifier
		hashAlg     crypto.Hash
		expectError bool
	}{
		{"[Unit] ECDSAKeyMatch: SHA256 OID with SHA256", OIDECDSAWithSHA256, crypto.SHA256, false},
		{"[Unit] ECDSAKeyMatch: SHA384 OID with SHA384", OIDECDSAWithSHA384, crypto.SHA384, false},
		{"[Unit] ECDSAKeyMatch: SHA512 OID with SHA512", OIDECDSAWithSHA512, crypto.SHA512, false},
		{"[Unit] ECDSAKeyMatch: SHA256 OID with SHA384 (mismatch)", OIDECDSAWithSHA256, crypto.SHA384, true},
		{"[Unit] ECDSAKeyMatch: Non-ECDSA OID", OIDSHA256WithRSA, crypto.SHA256, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateECDSAKeyMatch(tt.sigAlgOID, tt.hashAlg)
			if tt.expectError && err == nil {
				t.Error("Expected error but got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

// TestU_ValidateRSAKeyMatch tests RSA OID validation.
func TestU_ValidateRSAKeyMatch(t *testing.T) {
	tests := []struct {
		name        string
		sigAlgOID   asn1.ObjectIdentifier
		hashAlg     crypto.Hash
		expectError bool
	}{
		{"[Unit] RSAKeyMatch: SHA256 OID with SHA256", OIDSHA256WithRSA, crypto.SHA256, false},
		{"[Unit] RSAKeyMatch: SHA384 OID with SHA384", OIDSHA384WithRSA, crypto.SHA384, false},
		{"[Unit] RSAKeyMatch: SHA512 OID with SHA512", OIDSHA512WithRSA, crypto.SHA512, false},
		{"[Unit] RSAKeyMatch: SHA256 OID with SHA384 (mismatch)", OIDSHA256WithRSA, crypto.SHA384, true},
		{"[Unit] RSAKeyMatch: Non-RSA OID", OIDECDSAWithSHA256, crypto.SHA256, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRSAKeyMatch(tt.sigAlgOID, tt.hashAlg)
			if tt.expectError && err == nil {
				t.Error("Expected error but got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

// TestU_ValidateEd25519KeyMatch tests Ed25519 OID validation.
func TestU_ValidateEd25519KeyMatch(t *testing.T) {
	tests := []struct {
		name        string
		sigAlgOID   asn1.ObjectIdentifier
		expectError bool
	}{
		{"[Unit] Ed25519KeyMatch: Ed25519 OID", OIDEd25519, false},
		{"[Unit] Ed25519KeyMatch: Non-Ed25519 OID (ECDSA)", OIDECDSAWithSHA256, true},
		{"[Unit] Ed25519KeyMatch: Non-Ed25519 OID (RSA)", OIDSHA256WithRSA, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateEd25519KeyMatch(tt.sigAlgOID)
			if tt.expectError && err == nil {
				t.Error("Expected error but got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

// TestU_GetContent tests the getContent function for detached/attached signatures.
func TestU_GetContent(t *testing.T) {
	attachedContent := []byte("attached content")
	detachedContent := []byte("detached content")

	// Create SignedData with attached content
	sdAttached := &SignedData{
		EncapContentInfo: EncapsulatedContentInfo{
			EContentType: OIDData,
			EContent: asn1.RawValue{
				Tag:   asn1.TagOctetString,
				Bytes: attachedContent,
			},
		},
	}

	// Create SignedData without content (for detached)
	sdDetached := &SignedData{
		EncapContentInfo: EncapsulatedContentInfo{
			EContentType: OIDData,
		},
	}

	tests := []struct {
		name            string
		signedData      *SignedData
		config          *VerifyConfig
		expectedContent []byte
	}{
		{
			name:            "[Unit] GetContent: Attached content",
			signedData:      sdAttached,
			config:          &VerifyConfig{},
			expectedContent: attachedContent,
		},
		{
			name:       "[Unit] GetContent: Detached content from config",
			signedData: sdDetached,
			config: &VerifyConfig{
				Data: detachedContent,
			},
			expectedContent: detachedContent,
		},
		{
			name:       "[Unit] GetContent: Detached overrides attached",
			signedData: sdAttached,
			config: &VerifyConfig{
				Data: detachedContent,
			},
			expectedContent: detachedContent,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getContent(tt.signedData, tt.config)
			if string(result) != string(tt.expectedContent) {
				t.Errorf("Content mismatch: expected %q, got %q", tt.expectedContent, result)
			}
		})
	}
}

// TestU_ParseCertificates tests the parseCertificates function.
func TestU_ParseCertificates(t *testing.T) {
	// Generate a test certificate
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	tests := []struct {
		name        string
		raw         []byte
		expectError bool
		expectCount int
	}{
		{
			name:        "[Unit] ParseCertificates: Valid single cert",
			raw:         cert.Raw,
			expectError: false,
			expectCount: 1,
		},
		{
			name:        "[Unit] ParseCertificates: Empty data",
			raw:         []byte{},
			expectError: true,
			expectCount: 0,
		},
		{
			name:        "[Unit] ParseCertificates: Invalid data",
			raw:         []byte{0xFF, 0xFF, 0xFF},
			expectError: true,
			expectCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certs, err := parseCertificates(tt.raw)
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if len(certs) != tt.expectCount {
					t.Errorf("Certificate count mismatch: expected %d, got %d", tt.expectCount, len(certs))
				}
			}
		})
	}
}

// =============================================================================
// Unit Tests: RFC 9882 Digest Security Level Warnings
// =============================================================================

// TestU_CheckDigestSecurityLevel_RFC9882 tests the checkDigestSecurityLevel function.
func TestU_CheckDigestSecurityLevel_RFC9882(t *testing.T) {
	tests := []struct {
		name          string
		sigAlgOID     asn1.ObjectIdentifier
		digestAlg     crypto.Hash
		expectWarning bool
	}{
		// ML-DSA-87 (Level 5) - requires SHA-512
		{
			name:          "[Unit] RFC9882: ML-DSA-87 + SHA-512 = OK",
			sigAlgOID:     OIDMLDSA87,
			digestAlg:     crypto.SHA512,
			expectWarning: false,
		},
		{
			name:          "[Unit] RFC9882: ML-DSA-87 + SHA-384 = Warning",
			sigAlgOID:     OIDMLDSA87,
			digestAlg:     crypto.SHA384,
			expectWarning: true,
		},
		{
			name:          "[Unit] RFC9882: ML-DSA-87 + SHA-256 = Warning",
			sigAlgOID:     OIDMLDSA87,
			digestAlg:     crypto.SHA256,
			expectWarning: true,
		},
		// ML-DSA-65 (Level 3) - requires SHA-384 or SHA-512
		{
			name:          "[Unit] RFC9882: ML-DSA-65 + SHA-512 = OK",
			sigAlgOID:     OIDMLDSA65,
			digestAlg:     crypto.SHA512,
			expectWarning: false,
		},
		{
			name:          "[Unit] RFC9882: ML-DSA-65 + SHA-384 = OK",
			sigAlgOID:     OIDMLDSA65,
			digestAlg:     crypto.SHA384,
			expectWarning: false,
		},
		{
			name:          "[Unit] RFC9882: ML-DSA-65 + SHA-256 = Warning",
			sigAlgOID:     OIDMLDSA65,
			digestAlg:     crypto.SHA256,
			expectWarning: true,
		},
		// ML-DSA-44 (Level 1) - SHA-256 is fine
		{
			name:          "[Unit] RFC9882: ML-DSA-44 + SHA-256 = OK",
			sigAlgOID:     OIDMLDSA44,
			digestAlg:     crypto.SHA256,
			expectWarning: false,
		},
		// Classical algorithms - no warning
		{
			name:          "[Unit] RFC9882: ECDSA + SHA-256 = OK (no warning)",
			sigAlgOID:     OIDECDSAWithSHA256,
			digestAlg:     crypto.SHA256,
			expectWarning: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warning := checkDigestSecurityLevel(tt.sigAlgOID, tt.digestAlg)
			hasWarning := warning != ""
			if hasWarning != tt.expectWarning {
				if tt.expectWarning {
					t.Error("Expected warning but got none")
				} else {
					t.Errorf("Unexpected warning: %s", warning)
				}
			}
		})
	}
}

// TestF_Verify_RFC9882_Warning tests that verification produces warnings for
// suboptimal digest/ML-DSA combinations.
func TestF_Verify_RFC9882_Warning(t *testing.T) {
	// Create ML-DSA-87 key and cert
	kp := generateMLDSAKeyPair(t, pkicrypto.AlgMLDSA87)
	cert := generateMLDSACertificate(t, kp, pkicrypto.AlgMLDSA87)

	content := []byte("RFC 9882 warning test")

	// Sign with ML-DSA-87 but force SHA-256 (suboptimal per RFC 9882)
	signedData, err := Sign(context.Background(), content, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA256, // Force SHA-256 (should trigger warning)
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Verify - should succeed but produce a warning
	result, err := Verify(context.Background(), signedData, &VerifyConfig{SkipCertVerify: true})
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	// Check that a warning was produced
	if len(result.Warnings) == 0 {
		t.Error("Expected RFC 9882 warning for ML-DSA-87 + SHA-256, but got none")
	} else {
		t.Logf("Got expected warning: %s", result.Warnings[0])
	}
}

// TestF_Verify_RFC9882_NoWarning tests that verification produces no warnings
// for correct digest/ML-DSA combinations.
func TestF_Verify_RFC9882_NoWarning(t *testing.T) {
	// Create ML-DSA-87 key and cert
	kp := generateMLDSAKeyPair(t, pkicrypto.AlgMLDSA87)
	cert := generateMLDSACertificate(t, kp, pkicrypto.AlgMLDSA87)

	content := []byte("RFC 9882 no warning test")

	// Sign with ML-DSA-87 and SHA-512 (correct per RFC 9882)
	signedData, err := Sign(context.Background(), content, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA512, // Correct digest
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Verify - should succeed without warning
	result, err := Verify(context.Background(), signedData, &VerifyConfig{SkipCertVerify: true})
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	// Check that no warning was produced
	if len(result.Warnings) > 0 {
		t.Errorf("Unexpected warning for ML-DSA-87 + SHA-512: %s", result.Warnings[0])
	}
}

// =============================================================================
// Unit Tests: RFC 9882 Warning Edge Cases
// =============================================================================

// TestU_CheckDigestSecurityLevel_MLDSA44_AllDigests tests ML-DSA-44 with all digests.
func TestU_CheckDigestSecurityLevel_MLDSA44_AllDigests(t *testing.T) {
	tests := []struct {
		name          string
		digestAlg     crypto.Hash
		expectWarning bool
	}{
		{"ML-DSA-44 + SHA-256 = OK", crypto.SHA256, false},
		{"ML-DSA-44 + SHA-384 = OK", crypto.SHA384, false},
		{"ML-DSA-44 + SHA-512 = OK", crypto.SHA512, false},
		{"ML-DSA-44 + SHA3-256 = OK", crypto.SHA3_256, false},
		{"ML-DSA-44 + SHA3-384 = OK", crypto.SHA3_384, false},
		{"ML-DSA-44 + SHA3-512 = OK", crypto.SHA3_512, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warning := checkDigestSecurityLevel(OIDMLDSA44, tt.digestAlg)
			hasWarning := warning != ""
			if hasWarning != tt.expectWarning {
				if tt.expectWarning {
					t.Error("Expected warning but got none")
				} else {
					t.Errorf("Unexpected warning: %s", warning)
				}
			}
		})
	}
}

// TestU_CheckDigestSecurityLevel_SLHDSA tests SLH-DSA OIDs (no warnings expected).
func TestU_CheckDigestSecurityLevel_SLHDSA(t *testing.T) {
	slhdsaOIDs := []asn1.ObjectIdentifier{
		OIDSLHDSA128s, OIDSLHDSA128f,
		OIDSLHDSA192s, OIDSLHDSA192f,
		OIDSLHDSA256s, OIDSLHDSA256f,
	}

	digests := []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512}

	for _, oid := range slhdsaOIDs {
		for _, digest := range digests {
			t.Run(oid.String()+"_"+digest.String(), func(t *testing.T) {
				warning := checkDigestSecurityLevel(oid, digest)
				if warning != "" {
					t.Errorf("Unexpected warning for SLH-DSA: %s", warning)
				}
			})
		}
	}
}

// TestU_CheckDigestSecurityLevel_Classical tests classical algorithms (no warnings).
func TestU_CheckDigestSecurityLevel_Classical(t *testing.T) {
	classicalOIDs := []asn1.ObjectIdentifier{
		OIDECDSAWithSHA256, OIDECDSAWithSHA384, OIDECDSAWithSHA512,
		OIDSHA256WithRSA, OIDSHA384WithRSA, OIDSHA512WithRSA,
		OIDEd25519,
	}

	digests := []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512}

	for _, oid := range classicalOIDs {
		for _, digest := range digests {
			t.Run(oid.String()+"_"+digest.String(), func(t *testing.T) {
				warning := checkDigestSecurityLevel(oid, digest)
				if warning != "" {
					t.Errorf("Unexpected warning for classical algorithm: %s", warning)
				}
			})
		}
	}
}

// TestU_CheckDigestSecurityLevel_WarningMessage tests the warning message content.
func TestU_CheckDigestSecurityLevel_WarningMessage(t *testing.T) {
	tests := []struct {
		name            string
		sigAlgOID       asn1.ObjectIdentifier
		digestAlg       crypto.Hash
		expectedContain string
	}{
		{
			name:            "ML-DSA-87 warning mentions SHA-512",
			sigAlgOID:       OIDMLDSA87,
			digestAlg:       crypto.SHA256,
			expectedContain: "SHA-512",
		},
		{
			name:            "ML-DSA-87 warning mentions Level 5",
			sigAlgOID:       OIDMLDSA87,
			digestAlg:       crypto.SHA256,
			expectedContain: "Level 5",
		},
		{
			name:            "ML-DSA-65 warning mentions SHA-384",
			sigAlgOID:       OIDMLDSA65,
			digestAlg:       crypto.SHA256,
			expectedContain: "SHA-384",
		},
		{
			name:            "ML-DSA-65 warning mentions Level 3",
			sigAlgOID:       OIDMLDSA65,
			digestAlg:       crypto.SHA256,
			expectedContain: "Level 3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warning := checkDigestSecurityLevel(tt.sigAlgOID, tt.digestAlg)
			if warning == "" {
				t.Fatal("Expected warning but got none")
			}
			if !containsString(warning, tt.expectedContain) {
				t.Errorf("Warning should contain %q, got: %s", tt.expectedContain, warning)
			}
		})
	}
}

// containsString checks if str contains substr (case-insensitive would need strings.Contains).
func containsString(str, substr string) bool {
	return len(str) >= len(substr) && (str == substr || len(str) > len(substr) && findSubstring(str, substr))
}

func findSubstring(str, substr string) bool {
	for i := 0; i <= len(str)-len(substr); i++ {
		if str[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// =============================================================================
// Functional Tests: RFC 9882 Warning Integration
// =============================================================================

// TestF_Verify_RFC9882_MLDSA65_Warning tests ML-DSA-65 with SHA-256 produces warning.
func TestF_Verify_RFC9882_MLDSA65_Warning(t *testing.T) {
	kp := generateMLDSAKeyPair(t, pkicrypto.AlgMLDSA65)
	cert := generateMLDSACertificate(t, kp, pkicrypto.AlgMLDSA65)

	content := []byte("ML-DSA-65 warning test")

	// Sign with SHA-256 (suboptimal for Level 3)
	signedData, err := Sign(context.Background(), content, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA256,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	result, err := Verify(context.Background(), signedData, &VerifyConfig{SkipCertVerify: true})
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if len(result.Warnings) == 0 {
		t.Error("Expected RFC 9882 warning for ML-DSA-65 + SHA-256")
	}
}

// TestF_Verify_RFC9882_MLDSA65_NoWarning_SHA384 tests ML-DSA-65 with SHA-384 produces no warning.
func TestF_Verify_RFC9882_MLDSA65_NoWarning_SHA384(t *testing.T) {
	kp := generateMLDSAKeyPair(t, pkicrypto.AlgMLDSA65)
	cert := generateMLDSACertificate(t, kp, pkicrypto.AlgMLDSA65)

	content := []byte("ML-DSA-65 no warning test")

	// Sign with SHA-384 (correct for Level 3)
	signedData, err := Sign(context.Background(), content, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA384,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	result, err := Verify(context.Background(), signedData, &VerifyConfig{SkipCertVerify: true})
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if len(result.Warnings) > 0 {
		t.Errorf("Unexpected warning for ML-DSA-65 + SHA-384: %s", result.Warnings[0])
	}
}

// TestF_Verify_RFC9882_MLDSA44_NoWarning tests ML-DSA-44 with SHA-256 produces no warning.
func TestF_Verify_RFC9882_MLDSA44_NoWarning(t *testing.T) {
	kp := generateMLDSAKeyPair(t, pkicrypto.AlgMLDSA44)
	cert := generateMLDSACertificate(t, kp, pkicrypto.AlgMLDSA44)

	content := []byte("ML-DSA-44 test")

	signedData, err := Sign(context.Background(), content, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA256,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	result, err := Verify(context.Background(), signedData, &VerifyConfig{SkipCertVerify: true})
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if len(result.Warnings) > 0 {
		t.Errorf("Unexpected warning for ML-DSA-44 + SHA-256: %s", result.Warnings[0])
	}
}

// TestF_Verify_RFC9882_SLHDSA_NoWarning tests SLH-DSA produces no warnings.
func TestF_Verify_RFC9882_SLHDSA_NoWarning(t *testing.T) {
	kp := generateSLHDSAKeyPair(t, pkicrypto.AlgSLHDSA128f)
	cert := generateSLHDSACertificate(t, kp, pkicrypto.AlgSLHDSA128f)

	content := []byte("SLH-DSA test")

	signedData, err := Sign(context.Background(), content, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA256,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	result, err := Verify(context.Background(), signedData, &VerifyConfig{SkipCertVerify: true})
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if len(result.Warnings) > 0 {
		t.Errorf("Unexpected warning for SLH-DSA: %s", result.Warnings[0])
	}
}

// TestF_Verify_Classical_NoWarning tests classical algorithms produce no warnings.
func TestF_Verify_Classical_NoWarning(t *testing.T) {
	tests := []struct {
		name      string
		keyGen    func(t *testing.T) *testKeyPair
		digestAlg crypto.Hash
	}{
		{"ECDSA P-256 + SHA-256", func(t *testing.T) *testKeyPair { return generateECDSAKeyPair(t, elliptic.P256()) }, crypto.SHA256},
		{"ECDSA P-384 + SHA-384", func(t *testing.T) *testKeyPair { return generateECDSAKeyPair(t, elliptic.P384()) }, crypto.SHA384},
		{"RSA + SHA-256", func(t *testing.T) *testKeyPair { return generateRSAKeyPair(t, 2048) }, crypto.SHA256},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kp := tt.keyGen(t)
			cert := generateTestCertificate(t, kp)

			content := []byte("classical test")

			signedData, err := Sign(context.Background(), content, &SignerConfig{
				Certificate:  cert,
				Signer:       kp.PrivateKey,
				DigestAlg:    tt.digestAlg,
				IncludeCerts: true,
			})
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}

			result, err := Verify(context.Background(), signedData, &VerifyConfig{SkipCertVerify: true})
			if err != nil {
				t.Fatalf("Verify failed: %v", err)
			}

			if len(result.Warnings) > 0 {
				t.Errorf("Unexpected warning for classical algorithm: %s", result.Warnings[0])
			}
		})
	}
}

// =============================================================================
// Unit Tests: OID to Hash Mapping (Additional Coverage)
// =============================================================================

// TestU_OidToHash_SHA3 tests SHA3 OID to hash mapping.
func TestU_OidToHash_SHA3(t *testing.T) {
	tests := []struct {
		name         string
		oid          asn1.ObjectIdentifier
		expectedHash crypto.Hash
	}{
		{"SHA3-256", OIDSHA3_256, crypto.SHA3_256},
		{"SHA3-384", OIDSHA3_384, crypto.SHA3_384},
		{"SHA3-512", OIDSHA3_512, crypto.SHA3_512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := oidToHash(tt.oid)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if hash != tt.expectedHash {
				t.Errorf("Hash mismatch: expected %v, got %v", tt.expectedHash, hash)
			}
		})
	}
}

// =============================================================================
// Unit Tests: verifyCertChain
// =============================================================================

// TestU_verifyCertChain_ValidChain tests verifyCertChain with a valid ECDSA chain.
func TestU_verifyCertChain_ValidChain(t *testing.T) {
	// Create CA and issue EE certificate
	caCert, caKey := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	eeCert := issueTestCertificate(t, caCert, caKey, kp)

	// Verify the chain
	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	config := &VerifyConfig{
		Roots: roots,
	}

	err := verifyCertChain(eeCert, config)
	if err != nil {
		t.Errorf("verifyCertChain() error = %v", err)
	}
}

// TestU_verifyCertChain_ExpiredCert tests verifyCertChain with expired certificate.
func TestU_verifyCertChain_ExpiredCert(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	eeCert := issueTestCertificate(t, caCert, caKey, kp)

	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	// Set verification time to the future (after cert expires)
	config := &VerifyConfig{
		Roots:       roots,
		CurrentTime: time.Now().Add(365 * 24 * time.Hour), // 1 year in future
	}

	err := verifyCertChain(eeCert, config)
	if err == nil {
		t.Error("verifyCertChain() should fail for expired certificate")
	}
}

// TestU_verifyCertChain_UnknownAuthority tests verifyCertChain with missing root.
func TestU_verifyCertChain_UnknownAuthority(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	eeCert := issueTestCertificate(t, caCert, caKey, kp)

	// Empty roots pool - certificate won't chain
	roots := x509.NewCertPool()

	config := &VerifyConfig{
		Roots: roots,
	}

	err := verifyCertChain(eeCert, config)
	if err == nil {
		t.Error("verifyCertChain() should fail with unknown authority")
	}
}

// TestU_verifyCertChain_SelfSigned tests verifyCertChain with self-signed CA certificate.
func TestU_verifyCertChain_SelfSigned(t *testing.T) {
	// Use generateTestCA which creates a proper CA certificate
	caCert, _ := generateTestCA(t)

	// Add self-signed CA cert as root
	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	config := &VerifyConfig{
		Roots: roots,
	}

	err := verifyCertChain(caCert, config)
	if err != nil {
		t.Errorf("verifyCertChain() error = %v", err)
	}
}

// TestU_verifyCertChain_WithIntermediates tests verifyCertChain with intermediate CA.
func TestU_verifyCertChain_WithIntermediates(t *testing.T) {
	// Create Root CA using existing helper (creates proper CA)
	rootCert, rootKey := generateTestCA(t)

	// Create Intermediate CA (issued by root with CA flags)
	intKp := generateECDSAKeyPair(t, elliptic.P256())
	intCert := issueIntermediateCA(t, rootCert, rootKey, intKp)

	// Create EE certificate (issued by intermediate)
	eeKp := generateECDSAKeyPair(t, elliptic.P256())
	eeCert := issueTestCertificate(t, intCert, intKp.PrivateKey, eeKp)

	roots := x509.NewCertPool()
	roots.AddCert(rootCert)

	intermediates := x509.NewCertPool()
	intermediates.AddCert(intCert)

	config := &VerifyConfig{
		Roots:         roots,
		Intermediates: intermediates,
	}

	err := verifyCertChain(eeCert, config)
	if err != nil {
		t.Errorf("verifyCertChain() error = %v", err)
	}
}

// TestU_verifyCertChain_WrongCA tests verifyCertChain with certificate from different CA.
func TestU_verifyCertChain_WrongCA(t *testing.T) {
	// Create CA 1
	ca1Cert, ca1Key := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	eeCert := issueTestCertificate(t, ca1Cert, ca1Key, kp)

	// Create CA 2 (different)
	ca2Cert, _ := generateTestCA(t)

	// Try to verify with wrong CA
	roots := x509.NewCertPool()
	roots.AddCert(ca2Cert)

	config := &VerifyConfig{
		Roots: roots,
	}

	err := verifyCertChain(eeCert, config)
	if err == nil {
		t.Error("verifyCertChain() should fail with wrong CA")
	}
}

// TestU_verifyCertChain_CurrentTime tests verifyCertChain respects custom CurrentTime.
func TestU_verifyCertChain_CurrentTime(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	eeCert := issueTestCertificate(t, caCert, caKey, kp)

	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	// Verify at current time (should work)
	config := &VerifyConfig{
		Roots:       roots,
		CurrentTime: time.Now(),
	}

	err := verifyCertChain(eeCert, config)
	if err != nil {
		t.Errorf("verifyCertChain() at current time error = %v", err)
	}
}

// TestU_verifyCertChain_NilConfig tests verifyCertChain with missing config fields.
func TestU_verifyCertChain_NilConfig(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	// Empty config - should fail as no roots are provided
	config := &VerifyConfig{}

	err := verifyCertChain(cert, config)
	if err == nil {
		t.Error("verifyCertChain() should fail with empty config")
	}
}

// =============================================================================
// Unit Tests: verifyCertChain PQC/Composite Fallback
// =============================================================================

// TestU_verifyCertChain_PQCFallback tests the PQC fallback path when Go's x509
// fails with "unknown authority" for PQC certificates.
func TestU_verifyCertChain_PQCFallback(t *testing.T) {
	// Create PQC CA (ML-DSA-65)
	tmpDir := t.TempDir()
	store := ca.NewFileStore(tmpDir)

	cfg := ca.PQCCAConfig{
		CommonName:    "Test PQC CA",
		Organization:  "Test Org",
		Algorithm:     pkicrypto.AlgMLDSA65,
		ValidityYears: 1,
		PathLen:       0,
	}

	pqcCA, err := ca.InitializePQCCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializePQCCA() error = %v", err)
	}

	// Generate subject key and issue certificate
	subjectKey, err := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgMLDSA65)
	if err != nil {
		t.Fatalf("GenerateSoftwareSigner() error = %v", err)
	}

	eeCert, err := pqcCA.IssuePQC(context.Background(), ca.IssueRequest{
		Template: &x509.Certificate{
			Subject: pkix.Name{
				CommonName:   "Test End Entity",
				Organization: []string{"Test Org"},
			},
		},
		PublicKey: subjectKey.Public(),
		Validity:  24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("IssuePQC() error = %v", err)
	}

	// Configure verifyCertChain:
	// - Empty Roots (Go will fail with "unknown authority")
	// - RootCertRaw set to trigger PQC fallback
	config := &VerifyConfig{
		Roots:       x509.NewCertPool(), // Empty - Go fails
		RootCertRaw: pqcCA.Certificate().Raw,
	}

	// This should succeed via the PQC fallback path
	err = verifyCertChain(eeCert, config)
	if err != nil {
		t.Errorf("verifyCertChain() with PQC fallback error = %v", err)
	}
}

// TestU_verifyCertChain_CompositeFallback tests the Composite fallback path.
func TestU_verifyCertChain_CompositeFallback(t *testing.T) {
	// Create Composite CA (P256 + ML-DSA-65)
	tmpDir := t.TempDir()
	store := ca.NewFileStore(tmpDir)

	cfg := ca.CompositeCAConfig{
		CommonName:         "Test Composite CA",
		Organization:       "Test Org",
		ClassicalAlgorithm: pkicrypto.AlgECDSAP256,
		PQCAlgorithm:       pkicrypto.AlgMLDSA65,
		ValidityYears:      1,
		PathLen:            0,
	}

	compositeCA, err := ca.InitializeCompositeCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeCompositeCA() error = %v", err)
	}

	// Generate subject keys
	classicalSigner, err := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgECDSAP256)
	if err != nil {
		t.Fatalf("GenerateSoftwareSigner(classical) error = %v", err)
	}
	pqcSigner, err := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgMLDSA65)
	if err != nil {
		t.Fatalf("GenerateSoftwareSigner(pqc) error = %v", err)
	}

	// Issue Composite certificate
	eeCert, err := compositeCA.IssueComposite(ca.CompositeRequest{
		Template: &x509.Certificate{
			Subject: pkix.Name{
				CommonName:   "Test End Entity",
				Organization: []string{"Test Org"},
			},
		},
		ClassicalPublicKey: classicalSigner.Public(),
		PQCPublicKey:       pqcSigner.Public(),
		ClassicalAlg:       pkicrypto.AlgECDSAP256,
		PQCAlg:             pkicrypto.AlgMLDSA65,
		Validity:           24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("IssueComposite() error = %v", err)
	}

	// Configure verifyCertChain:
	// - Empty Roots (Go will fail with "unknown authority")
	// - RootCertRaw set to trigger Composite fallback
	config := &VerifyConfig{
		Roots:       x509.NewCertPool(), // Empty - Go fails
		RootCertRaw: compositeCA.Certificate().Raw,
	}

	// This should succeed via the Composite fallback path
	err = verifyCertChain(eeCert, config)
	if err != nil {
		t.Errorf("verifyCertChain() with Composite fallback error = %v", err)
	}
}

// =============================================================================
// Unit Tests: verifyPQCSignature
// =============================================================================

// TestU_verifyPQCSignature_MLDSA tests verifyPQCSignature with ML-DSA.
func TestU_verifyPQCSignature_MLDSA(t *testing.T) {
	// Create ML-DSA key and certificate
	kp := generateMLDSAKeyPair(t, pkicrypto.AlgMLDSA65)
	cert := generateMLDSACertificate(t, kp, pkicrypto.AlgMLDSA65)

	// Sign test data
	testData := []byte("test data for PQC signature verification")
	signature, err := kp.PrivateKey.Sign(nil, testData, crypto.Hash(0))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Verify the signature
	err = verifyPQCSignature(testData, signature, cert, OIDMLDSA65)
	if err != nil {
		t.Errorf("verifyPQCSignature() error = %v", err)
	}
}

// TestU_verifyPQCSignature_InvalidSignature tests verifyPQCSignature rejects invalid signatures.
func TestU_verifyPQCSignature_InvalidSignature(t *testing.T) {
	kp := generateMLDSAKeyPair(t, pkicrypto.AlgMLDSA65)
	cert := generateMLDSACertificate(t, kp, pkicrypto.AlgMLDSA65)

	testData := []byte("test data")
	signature := []byte("invalid signature bytes that are too short")

	err := verifyPQCSignature(testData, signature, cert, OIDMLDSA65)
	if err == nil {
		t.Error("verifyPQCSignature() should fail for invalid signature")
	}
}

// TestU_verifyPQCSignature_Composite tests verifyPQCSignature with Composite signature.
func TestU_verifyPQCSignature_Composite(t *testing.T) {
	// Create Composite CA and certificate
	tmpDir := t.TempDir()
	store := ca.NewFileStore(tmpDir)

	cfg := ca.CompositeCAConfig{
		CommonName:         "Test Composite CA",
		Organization:       "Test Org",
		ClassicalAlgorithm: pkicrypto.AlgECDSAP256,
		PQCAlgorithm:       pkicrypto.AlgMLDSA65,
		ValidityYears:      1,
		PathLen:            0,
	}

	compositeCA, err := ca.InitializeCompositeCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeCompositeCA() error = %v", err)
	}

	// Generate subject keys
	classicalSigner, err := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgECDSAP256)
	if err != nil {
		t.Fatalf("GenerateSoftwareSigner(classical) error = %v", err)
	}
	pqcSigner, err := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgMLDSA65)
	if err != nil {
		t.Fatalf("GenerateSoftwareSigner(pqc) error = %v", err)
	}

	hybridSigner, err := pkicrypto.NewHybridSigner(classicalSigner, pqcSigner)
	if err != nil {
		t.Fatalf("NewHybridSigner() error = %v", err)
	}

	// Issue Composite certificate
	eeCert, err := compositeCA.IssueComposite(ca.CompositeRequest{
		Template: &x509.Certificate{
			Subject: pkix.Name{
				CommonName:   "Test End Entity",
				Organization: []string{"Test Org"},
			},
		},
		ClassicalPublicKey: classicalSigner.Public(),
		PQCPublicKey:       pqcSigner.Public(),
		ClassicalAlg:       pkicrypto.AlgECDSAP256,
		PQCAlg:             pkicrypto.AlgMLDSA65,
		Validity:           24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("IssueComposite() error = %v", err)
	}

	// Sign test data with Composite signature
	testData := []byte("test data for composite signature")
	signature, err := signComposite(testData, hybridSigner)
	if err != nil {
		t.Fatalf("signComposite() error = %v", err)
	}

	// OID for MLDSA65-ECDSA-P256-SHA512
	compositeOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 45}

	// Verify the Composite signature
	err = verifyPQCSignature(testData, signature, eeCert, compositeOID)
	if err != nil {
		t.Errorf("verifyPQCSignature(Composite) error = %v", err)
	}
}

// TestU_verifyPQCSignature_SLHDSA tests verifyPQCSignature with SLH-DSA.
func TestU_verifyPQCSignature_SLHDSA(t *testing.T) {
	kp := generateSLHDSAKeyPair(t, pkicrypto.AlgSLHDSA128f)
	cert := generateSLHDSACertificate(t, kp, pkicrypto.AlgSLHDSA128f)

	testData := []byte("test data for SLH-DSA signature")
	signature, err := kp.PrivateKey.Sign(nil, testData, crypto.Hash(0))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	err = verifyPQCSignature(testData, signature, cert, OIDSLHDSA128f)
	if err != nil {
		t.Errorf("verifyPQCSignature(SLH-DSA) error = %v", err)
	}
}

// TestU_verifyCertChain_PQCFallback_InvalidSignature tests that PQC fallback
// correctly rejects certificates with invalid signatures.
func TestU_verifyCertChain_PQCFallback_InvalidSignature(t *testing.T) {
	// Create two different PQC CAs
	tmpDir1 := t.TempDir()
	store1 := ca.NewFileStore(tmpDir1)
	cfg1 := ca.PQCCAConfig{
		CommonName:    "Test PQC CA 1",
		Organization:  "Test Org",
		Algorithm:     pkicrypto.AlgMLDSA65,
		ValidityYears: 1,
		PathLen:       0,
	}
	ca1, err := ca.InitializePQCCA(store1, cfg1)
	if err != nil {
		t.Fatalf("InitializePQCCA(CA1) error = %v", err)
	}

	tmpDir2 := t.TempDir()
	store2 := ca.NewFileStore(tmpDir2)
	cfg2 := ca.PQCCAConfig{
		CommonName:    "Test PQC CA 2",
		Organization:  "Test Org",
		Algorithm:     pkicrypto.AlgMLDSA65,
		ValidityYears: 1,
		PathLen:       0,
	}
	ca2, err := ca.InitializePQCCA(store2, cfg2)
	if err != nil {
		t.Fatalf("InitializePQCCA(CA2) error = %v", err)
	}

	// Issue certificate from CA1
	subjectKey, err := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgMLDSA65)
	if err != nil {
		t.Fatalf("GenerateSoftwareSigner() error = %v", err)
	}

	eeCert, err := ca1.IssuePQC(context.Background(), ca.IssueRequest{
		Template: &x509.Certificate{
			Subject: pkix.Name{
				CommonName:   "Test End Entity",
				Organization: []string{"Test Org"},
			},
		},
		PublicKey: subjectKey.Public(),
		Validity:  24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("IssuePQC() error = %v", err)
	}

	// Try to verify with CA2's certificate (wrong CA)
	config := &VerifyConfig{
		Roots:       x509.NewCertPool(),
		RootCertRaw: ca2.Certificate().Raw, // Wrong CA!
	}

	// This should fail because the signature was made by CA1, not CA2
	err = verifyCertChain(eeCert, config)
	if err == nil {
		t.Error("verifyCertChain() should fail with wrong CA certificate")
	}
}

// TestU_verifyPQCSignature_ExtractFallback tests the extractPQCPublicKey fallback path.
// This tests the code path when cert.PublicKey is nil or doesn't implement Verify.
func TestU_verifyPQCSignature_ExtractFallback(t *testing.T) {
	// Create ML-DSA key and certificate
	kp := generateMLDSAKeyPair(t, pkicrypto.AlgMLDSA65)
	cert := generateMLDSACertificate(t, kp, pkicrypto.AlgMLDSA65)

	// Sign test data
	testData := []byte("test data for fallback verification")
	signature, err := kp.PrivateKey.Sign(nil, testData, crypto.Hash(0))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Create a copy of the certificate with nil PublicKey to force fallback
	certCopy := *cert
	certCopy.PublicKey = nil

	// Verify using the certificate with nil PublicKey
	// This forces the extractPQCPublicKey fallback path
	err = verifyPQCSignature(testData, signature, &certCopy, OIDMLDSA65)
	if err != nil {
		t.Errorf("verifyPQCSignature() with nil PublicKey error = %v", err)
	}
}

// TestU_extractPQCPublicKey_InvalidSPKI tests extractPQCPublicKey with invalid data.
func TestU_extractPQCPublicKey_InvalidSPKI(t *testing.T) {
	// Create a certificate with invalid RawSubjectPublicKeyInfo
	cert := &x509.Certificate{
		RawSubjectPublicKeyInfo: []byte{0x00, 0x01, 0x02}, // Invalid ASN.1
	}

	_, _, err := extractPQCPublicKey(cert)
	if err == nil {
		t.Error("extractPQCPublicKey() should fail with invalid SPKI")
	}
}

// TestU_extractPQCPublicKey_UnknownOID tests extractPQCPublicKey with unknown OID.
func TestU_extractPQCPublicKey_UnknownOID(t *testing.T) {
	// Create a valid SPKI structure with an unknown OID
	unknownOID := asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7, 8, 9}
	spki := struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: unknownOID},
		PublicKey: asn1.BitString{Bytes: []byte{0x00}},
	}
	spkiBytes, err := asn1.Marshal(spki)
	if err != nil {
		t.Fatalf("asn1.Marshal() error = %v", err)
	}

	cert := &x509.Certificate{
		RawSubjectPublicKeyInfo: spkiBytes,
	}

	_, _, err = extractPQCPublicKey(cert)
	if err == nil {
		t.Error("extractPQCPublicKey() should fail with unknown OID")
	}
}

// =============================================================================
// Unit Tests: parseCertificates
// =============================================================================

// TestU_parseCertificates_Empty tests parseCertificates with empty data.
func TestU_parseCertificates_Empty(t *testing.T) {
	_, err := parseCertificates([]byte{})
	if err == nil {
		t.Error("parseCertificates([]) should fail")
	}
}

// TestU_parseCertificates_InvalidData tests parseCertificates with invalid data.
func TestU_parseCertificates_InvalidData(t *testing.T) {
	_, err := parseCertificates([]byte{0x00, 0x01, 0x02})
	if err == nil {
		t.Error("parseCertificates(invalid) should fail")
	}
}

// TestU_parseCertificates_ValidCert tests parseCertificates with a valid certificate.
func TestU_parseCertificates_ValidCert(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	certs, err := parseCertificates(cert.Raw)
	if err != nil {
		t.Fatalf("parseCertificates() error = %v", err)
	}
	if len(certs) != 1 {
		t.Errorf("parseCertificates() returned %d certs, want 1", len(certs))
	}
}

// =============================================================================
// Unit Tests: verifyClassicalSignature
// =============================================================================

// TestU_verifyClassicalSignature_UnsupportedKeyType tests with unsupported key type.
func TestU_verifyClassicalSignature_UnsupportedKeyType(t *testing.T) {
	// Create a certificate with an unsupported public key type (custom type)
	cert := &x509.Certificate{
		PublicKey: struct{}{}, // Empty struct is not a supported key type
	}

	err := verifyClassicalSignature([]byte("data"), []byte("sig"), cert, crypto.SHA256, OIDECDSAWithSHA256)
	if err == nil {
		t.Error("verifyClassicalSignature() should fail with unsupported key type")
	}
}

// TestU_verifyClassicalSignature_ECDSA_InvalidSignature tests ECDSA with invalid signature.
func TestU_verifyClassicalSignature_ECDSA_InvalidSignature(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	err := verifyClassicalSignature([]byte("data"), []byte("invalid"), cert, crypto.SHA256, OIDECDSAWithSHA256)
	if err == nil {
		t.Error("verifyClassicalSignature() should fail with invalid signature")
	}
}

// =============================================================================
// Unit Tests: verifySignature
// =============================================================================

// TestU_verifySignature_UnknownDigestOID tests verifySignature with unknown digest OID.
func TestU_verifySignature_UnknownDigestOID(t *testing.T) {
	unknownOID := asn1.ObjectIdentifier{1, 2, 3, 4, 5}
	signerInfo := &SignerInfo{
		DigestAlgorithm: pkix.AlgorithmIdentifier{Algorithm: unknownOID},
	}

	err := verifySignature(nil, signerInfo, nil, nil)
	if err == nil {
		t.Error("verifySignature() should fail with unknown digest OID")
	}
}

// TestU_verifySignature_NoMessageDigestAttribute tests verifySignature when message digest attribute is missing.
func TestU_verifySignature_NoMessageDigestAttribute(t *testing.T) {
	// Create SignerInfo with signed attributes but NO message digest
	contentTypeAttr, _ := NewContentTypeAttr(OIDData)
	signingTimeAttr, _ := NewSigningTimeAttr(time.Now())

	signerInfo := &SignerInfo{
		DigestAlgorithm: pkix.AlgorithmIdentifier{Algorithm: OIDSHA256},
		SignedAttrs:     []Attribute{contentTypeAttr, signingTimeAttr}, // No MessageDigest!
	}

	err := verifySignature(nil, signerInfo, nil, []byte("content"))
	if err == nil {
		t.Error("verifySignature() should fail when message digest attribute is missing")
	}
}

// TestU_verifySignature_MessageDigestMismatch tests verifySignature with wrong message digest.
func TestU_verifySignature_MessageDigestMismatch(t *testing.T) {
	// Create SignerInfo with wrong message digest
	contentTypeAttr, _ := NewContentTypeAttr(OIDData)
	mdAttr, _ := NewMessageDigestAttr([]byte("wrong digest value"))
	signingTimeAttr, _ := NewSigningTimeAttr(time.Now())

	signerInfo := &SignerInfo{
		DigestAlgorithm: pkix.AlgorithmIdentifier{Algorithm: OIDSHA256},
		SignedAttrs:     []Attribute{contentTypeAttr, mdAttr, signingTimeAttr},
	}

	err := verifySignature(nil, signerInfo, nil, []byte("actual content"))
	if err == nil {
		t.Error("verifySignature() should fail with message digest mismatch")
	}
}

// TestU_verifySignature_NoSignedAttrs tests verifySignature without signed attributes.
func TestU_verifySignature_NoSignedAttrs(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	// Sign content directly (no signed attrs)
	content := []byte("test content")
	digest, _ := computeDigest(content, crypto.SHA256)
	signature, _ := kp.PrivateKey.Sign(nil, digest, crypto.SHA256)

	signerInfo := &SignerInfo{
		DigestAlgorithm:    pkix.AlgorithmIdentifier{Algorithm: OIDSHA256},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: OIDECDSAWithSHA256},
		Signature:          signature,
		SignedAttrs:        nil, // No signed attrs
	}

	// This should verify successfully (direct content verification)
	err := verifySignature(nil, signerInfo, cert, content)
	if err != nil {
		t.Errorf("verifySignature() without signed attrs error = %v", err)
	}
}

// =============================================================================
// Unit Tests: validateAlgorithmKeyMatch
// =============================================================================

// TestU_validateAlgorithmKeyMatch_Ed448 tests validateAlgorithmKeyMatch with Ed448 key.
func TestU_validateAlgorithmKeyMatch_Ed448(t *testing.T) {
	_, privKey, _ := ed448.GenerateKey(nil)
	pubKey := privKey.Public().(ed448.PublicKey)

	// Valid Ed448 OID
	err := validateAlgorithmKeyMatch(OIDEd448, pubKey, crypto.Hash(0))
	if err != nil {
		t.Errorf("validateAlgorithmKeyMatch(Ed448) error = %v", err)
	}

	// Invalid OID for Ed448 key
	err = validateAlgorithmKeyMatch(OIDEd25519, pubKey, crypto.Hash(0))
	if err == nil {
		t.Error("validateAlgorithmKeyMatch() should fail with wrong OID for Ed448")
	}
}

// TestU_validateAlgorithmKeyMatch_PQC tests validateAlgorithmKeyMatch with PQC key.
func TestU_validateAlgorithmKeyMatch_PQC(t *testing.T) {
	kp := generateMLDSAKeyPair(t, pkicrypto.AlgMLDSA65)

	// Valid ML-DSA OID
	err := validateAlgorithmKeyMatch(OIDMLDSA65, kp.PublicKey, crypto.Hash(0))
	if err != nil {
		t.Errorf("validateAlgorithmKeyMatch(ML-DSA) error = %v", err)
	}

	// Invalid OID for ML-DSA key
	err = validateAlgorithmKeyMatch(OIDECDSAWithSHA256, kp.PublicKey, crypto.SHA256)
	if err == nil {
		t.Error("validateAlgorithmKeyMatch() should fail with wrong OID for ML-DSA")
	}
}

// TestU_validateEd448KeyMatch tests validateEd448KeyMatch directly.
func TestU_validateEd448KeyMatch(t *testing.T) {
	tests := []struct {
		name      string
		oid       asn1.ObjectIdentifier
		wantError bool
	}{
		{"Valid Ed448 OID", OIDEd448, false},
		{"Invalid OID (Ed25519)", OIDEd25519, true},
		{"Invalid OID (ECDSA)", OIDECDSAWithSHA256, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateEd448KeyMatch(tt.oid)
			if (err != nil) != tt.wantError {
				t.Errorf("validateEd448KeyMatch() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

// TestU_validatePQCKeyMatch_SLHDSA tests validatePQCKeyMatch with SLH-DSA.
func TestU_validatePQCKeyMatch_SLHDSA(t *testing.T) {
	kp := generateSLHDSAKeyPair(t, pkicrypto.AlgSLHDSA128s)

	// SLH-DSA OID should pass
	err := validatePQCKeyMatch(OIDSLHDSA128s, kp.PublicKey)
	if err != nil {
		t.Errorf("validatePQCKeyMatch(SLH-DSA) error = %v", err)
	}
}

// =============================================================================
// Unit Tests: verifyClassicalSignature Ed448
// =============================================================================

// TestU_verifyClassicalSignature_Ed448_WithNilPublicKey tests Ed448 verification when cert.PublicKey is nil.
func TestU_verifyClassicalSignature_Ed448_WithNilPublicKey(t *testing.T) {
	// Generate Ed448 key pair
	pubKey, privKey, err := ed448.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed448.GenerateKey() error = %v", err)
	}

	// Create SPKI bytes for Ed448
	spki := struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: OIDEd448},
		PublicKey: asn1.BitString{Bytes: pubKey, BitLength: len(pubKey) * 8},
	}
	spkiBytes, err := asn1.Marshal(spki)
	if err != nil {
		t.Fatalf("asn1.Marshal() error = %v", err)
	}

	// Create certificate with nil PublicKey but valid RawSubjectPublicKeyInfo
	cert := &x509.Certificate{
		PublicKey:               nil, // Go couldn't parse Ed448
		RawSubjectPublicKeyInfo: spkiBytes,
	}

	// Sign test data
	testData := []byte("test data for Ed448 verification")
	signature := ed448.Sign(privKey, testData, "")

	// Verify using the special Ed448 path (pub is nil, sigAlgOID is Ed448)
	err = verifyClassicalSignature(testData, signature, cert, crypto.Hash(0), OIDEd448)
	if err != nil {
		t.Errorf("verifyClassicalSignature(Ed448 with nil PublicKey) error = %v", err)
	}
}

// TestU_verifyClassicalSignature_Ed448_InvalidSignature tests Ed448 with invalid signature.
func TestU_verifyClassicalSignature_Ed448_InvalidSignature(t *testing.T) {
	// Generate Ed448 key pair
	pubKey, _, err := ed448.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed448.GenerateKey() error = %v", err)
	}

	// Create SPKI bytes for Ed448
	spki := struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: OIDEd448},
		PublicKey: asn1.BitString{Bytes: pubKey, BitLength: len(pubKey) * 8},
	}
	spkiBytes, err := asn1.Marshal(spki)
	if err != nil {
		t.Fatalf("asn1.Marshal() error = %v", err)
	}

	// Create certificate with nil PublicKey but valid RawSubjectPublicKeyInfo
	cert := &x509.Certificate{
		PublicKey:               nil,
		RawSubjectPublicKeyInfo: spkiBytes,
	}

	// Invalid signature
	invalidSig := make([]byte, 114) // Ed448 signature size

	err = verifyClassicalSignature([]byte("test data"), invalidSig, cert, crypto.Hash(0), OIDEd448)
	if err == nil {
		t.Error("verifyClassicalSignature(Ed448 with invalid signature) should fail")
	}
}

// TestU_extractEd448PublicKey_ValidKey tests extractEd448PublicKey with valid Ed448 key.
func TestU_extractEd448PublicKey_ValidKey(t *testing.T) {
	pubKey, _, err := ed448.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed448.GenerateKey() error = %v", err)
	}

	// Create SPKI bytes for Ed448
	spki := struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: OIDEd448},
		PublicKey: asn1.BitString{Bytes: pubKey, BitLength: len(pubKey) * 8},
	}
	spkiBytes, err := asn1.Marshal(spki)
	if err != nil {
		t.Fatalf("asn1.Marshal() error = %v", err)
	}

	cert := &x509.Certificate{
		RawSubjectPublicKeyInfo: spkiBytes,
	}

	extractedKey, err := extractEd448PublicKey(cert)
	if err != nil {
		t.Errorf("extractEd448PublicKey() error = %v", err)
	}
	if len(extractedKey) != ed448.PublicKeySize {
		t.Errorf("extractEd448PublicKey() key size = %d, want %d", len(extractedKey), ed448.PublicKeySize)
	}
}

// TestU_extractEd448PublicKey_WrongOID tests extractEd448PublicKey with wrong OID.
func TestU_extractEd448PublicKey_WrongOID(t *testing.T) {
	// Create SPKI bytes with Ed25519 OID instead of Ed448
	spki := struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: OIDEd25519},
		PublicKey: asn1.BitString{Bytes: make([]byte, 57), BitLength: 57 * 8},
	}
	spkiBytes, err := asn1.Marshal(spki)
	if err != nil {
		t.Fatalf("asn1.Marshal() error = %v", err)
	}

	cert := &x509.Certificate{
		RawSubjectPublicKeyInfo: spkiBytes,
	}

	_, err = extractEd448PublicKey(cert)
	if err == nil {
		t.Error("extractEd448PublicKey() should fail with wrong OID")
	}
}

// TestU_extractEd448PublicKey_WrongKeySize tests extractEd448PublicKey with wrong key size.
func TestU_extractEd448PublicKey_WrongKeySize(t *testing.T) {
	// Create SPKI bytes with wrong key size
	spki := struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: OIDEd448},
		PublicKey: asn1.BitString{Bytes: make([]byte, 32), BitLength: 32 * 8}, // Wrong size
	}
	spkiBytes, err := asn1.Marshal(spki)
	if err != nil {
		t.Fatalf("asn1.Marshal() error = %v", err)
	}

	cert := &x509.Certificate{
		RawSubjectPublicKeyInfo: spkiBytes,
	}

	_, err = extractEd448PublicKey(cert)
	if err == nil {
		t.Error("extractEd448PublicKey() should fail with wrong key size")
	}
}

// TestU_verifyPQCSignature_VerifyFails tests verifyPQCSignature when Verify interface returns false.
func TestU_verifyPQCSignature_VerifyFails(t *testing.T) {
	// Create ML-DSA key and certificate
	kp := generateMLDSAKeyPair(t, pkicrypto.AlgMLDSA65)
	cert := generateMLDSACertificate(t, kp, pkicrypto.AlgMLDSA65)

	// Sign test data
	testData := []byte("test data for PQC verification")
	signature, err := kp.PrivateKey.Sign(nil, testData, crypto.Hash(0))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Tamper with the signature to make verification fail
	tamperedSig := make([]byte, len(signature))
	copy(tamperedSig, signature)
	tamperedSig[0] ^= 0xFF // Flip first byte

	// This should fail because the signature is tampered
	err = verifyPQCSignature(testData, tamperedSig, cert, OIDMLDSA65)
	if err == nil {
		t.Error("verifyPQCSignature() should fail with tampered signature")
	}
}

// TestU_verifyPQCSignature_ExtractFallback_VerifyFails tests fallback path with invalid signature.
func TestU_verifyPQCSignature_ExtractFallback_VerifyFails(t *testing.T) {
	// Create ML-DSA key and certificate
	kp := generateMLDSAKeyPair(t, pkicrypto.AlgMLDSA65)
	cert := generateMLDSACertificate(t, kp, pkicrypto.AlgMLDSA65)

	// Create a copy of the certificate with nil PublicKey to force fallback
	certCopy := *cert
	certCopy.PublicKey = nil

	// Create an invalid signature
	invalidSig := make([]byte, 100) // Wrong size for ML-DSA-65

	// This should fail in the pkicrypto.VerifySignature path
	err := verifyPQCSignature([]byte("test data"), invalidSig, &certCopy, OIDMLDSA65)
	if err == nil {
		t.Error("verifyPQCSignature() should fail with invalid signature in fallback path")
	}
}

// TestU_verifyClassicalSignature_Ed25519_InvalidSignature tests Ed25519 with invalid signature.
func TestU_verifyClassicalSignature_Ed25519_InvalidSignature(t *testing.T) {
	kp := generateEd25519KeyPair(t)
	cert := generateTestCertificate(t, kp)

	err := verifyClassicalSignature([]byte("data"), []byte("invalid"), cert, crypto.Hash(0), OIDEd25519)
	if err == nil {
		t.Error("verifyClassicalSignature(Ed25519) should fail with invalid signature")
	}
}

// TestU_verifyClassicalSignature_RSA_InvalidSignature tests RSA with invalid signature.
func TestU_verifyClassicalSignature_RSA_InvalidSignature(t *testing.T) {
	kp := generateRSAKeyPair(t, 2048)
	cert := generateTestCertificate(t, kp)

	err := verifyClassicalSignature([]byte("data"), []byte("invalid"), cert, crypto.SHA256, OIDSHA256WithRSA)
	if err == nil {
		t.Error("verifyClassicalSignature(RSA) should fail with invalid signature")
	}
}
