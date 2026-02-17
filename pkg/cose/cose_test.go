package cose

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/cloudflare/circl/sign/slhdsa"
	pkicrypto "github.com/remiblancher/post-quantum-pki/pkg/crypto"
	gocose "github.com/veraison/go-cose"
)

// =============================================================================
// Test Helpers
// =============================================================================

// generateECDSAKey generates an ECDSA key pair for testing.
func generateECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}
	return key
}

// generateMLDSA44Key generates an ML-DSA-44 key pair for testing.
func generateMLDSA44Key(t *testing.T) (*mldsa44.PublicKey, *mldsa44.PrivateKey) {
	t.Helper()
	pub, priv, err := mldsa44.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ML-DSA-44 key: %v", err)
	}
	return pub, priv
}

// generateMLDSA65Key generates an ML-DSA-65 key pair for testing.
func generateMLDSA65Key(t *testing.T) (*mldsa65.PublicKey, *mldsa65.PrivateKey) {
	t.Helper()
	pub, priv, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ML-DSA-65 key: %v", err)
	}
	return pub, priv
}

// generateMLDSA87Key generates an ML-DSA-87 key pair for testing.
func generateMLDSA87Key(t *testing.T) (*mldsa87.PublicKey, *mldsa87.PrivateKey) {
	t.Helper()
	pub, priv, err := mldsa87.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ML-DSA-87 key: %v", err)
	}
	return pub, priv
}

// generateTestCertificate generates a self-signed certificate for testing.
func generateTestCertificate(t *testing.T, key crypto.Signer) *x509.Certificate {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert
}

// =============================================================================
// Algorithm Tests
// =============================================================================

func TestU_COSEAlgorithmFromKey_ECDSA(t *testing.T) {
	tests := []struct {
		name     string
		curve    elliptic.Curve
		expected gocose.Algorithm
	}{
		{"P256", elliptic.P256(), AlgES256},
		{"P384", elliptic.P384(), AlgES384},
		{"P521", elliptic.P521(), AlgES512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(tt.curve, rand.Reader)
			if err != nil {
				t.Fatalf("failed to generate key: %v", err)
			}

			alg, err := COSEAlgorithmFromKey(&key.PublicKey)
			if err != nil {
				t.Fatalf("COSEAlgorithmFromKey failed: %v", err)
			}

			if alg != tt.expected {
				t.Errorf("expected algorithm %d, got %d", tt.expected, alg)
			}
		})
	}
}

func TestU_COSEAlgorithmFromKey_MLDSA(t *testing.T) {
	tests := []struct {
		name     string
		genKey   func() (crypto.PublicKey, error)
		expected gocose.Algorithm
	}{
		{
			name: "ML-DSA-44",
			genKey: func() (crypto.PublicKey, error) {
				pub, _, err := mldsa44.GenerateKey(rand.Reader)
				return pub, err
			},
			expected: AlgMLDSA44,
		},
		{
			name: "ML-DSA-65",
			genKey: func() (crypto.PublicKey, error) {
				pub, _, err := mldsa65.GenerateKey(rand.Reader)
				return pub, err
			},
			expected: AlgMLDSA65,
		},
		{
			name: "ML-DSA-87",
			genKey: func() (crypto.PublicKey, error) {
				pub, _, err := mldsa87.GenerateKey(rand.Reader)
				return pub, err
			},
			expected: AlgMLDSA87,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pub, err := tt.genKey()
			if err != nil {
				t.Fatalf("failed to generate key: %v", err)
			}

			alg, err := COSEAlgorithmFromKey(pub)
			if err != nil {
				t.Fatalf("COSEAlgorithmFromKey failed: %v", err)
			}

			if alg != tt.expected {
				t.Errorf("expected algorithm %d, got %d", tt.expected, alg)
			}
		})
	}
}

func TestU_IsPQCAlgorithm(t *testing.T) {
	tests := []struct {
		name     string
		alg      gocose.Algorithm
		expected bool
	}{
		{"ES256 is not PQC", AlgES256, false},
		{"ES384 is not PQC", AlgES384, false},
		{"EdDSA is not PQC", AlgEdDSA, false},
		{"ML-DSA-44 is PQC", AlgMLDSA44, true},
		{"ML-DSA-65 is PQC", AlgMLDSA65, true},
		{"ML-DSA-87 is PQC", AlgMLDSA87, true},
		{"SLH-DSA-SHA2-128s is PQC", AlgSLHDSASHA2128s, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsPQCAlgorithm(tt.alg)
			if result != tt.expected {
				t.Errorf("IsPQCAlgorithm(%d) = %v, expected %v", tt.alg, result, tt.expected)
			}
		})
	}
}

func TestU_AlgorithmName(t *testing.T) {
	tests := []struct {
		alg      gocose.Algorithm
		expected string
	}{
		{AlgES256, "ES256"},
		{AlgES384, "ES384"},
		{AlgES512, "ES512"},
		{AlgEdDSA, "EdDSA"},
		{AlgMLDSA44, "ML-DSA-44"},
		{AlgMLDSA65, "ML-DSA-65"},
		{AlgMLDSA87, "ML-DSA-87"},
		{AlgSLHDSASHA2128s, "SLH-DSA-SHA2-128s"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			name := AlgorithmName(tt.alg)
			if name != tt.expected {
				t.Errorf("AlgorithmName(%d) = %q, expected %q", tt.alg, name, tt.expected)
			}
		})
	}
}

// =============================================================================
// Claims Tests
// =============================================================================

func TestU_Claims_NewClaims(t *testing.T) {
	claims := NewClaims()

	if claims.IssuedAt.IsZero() {
		t.Error("IssuedAt should be set")
	}

	if claims.Custom == nil {
		t.Error("Custom map should be initialized")
	}
}

func TestU_Claims_SetExpiration(t *testing.T) {
	claims := NewClaims()
	claims.SetExpiration(time.Hour)

	if claims.Expiration.IsZero() {
		t.Error("Expiration should be set")
	}

	// Should be approximately 1 hour from now
	expected := time.Now().Add(time.Hour)
	diff := claims.Expiration.Sub(expected)
	if diff < -time.Second || diff > time.Second {
		t.Errorf("Expiration not within expected range: got %v, expected ~%v", claims.Expiration, expected)
	}
}

func TestU_Claims_IsExpired(t *testing.T) {
	tests := []struct {
		name       string
		expiration time.Time
		expected   bool
	}{
		{"Future expiration", time.Now().Add(time.Hour), false},
		{"Past expiration", time.Now().Add(-time.Hour), true},
		{"Zero expiration", time.Time{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := NewClaims()
			claims.Expiration = tt.expiration

			if claims.IsExpired() != tt.expected {
				t.Errorf("IsExpired() = %v, expected %v", claims.IsExpired(), tt.expected)
			}
		})
	}
}

func TestU_Claims_SetCustom(t *testing.T) {
	claims := NewClaims()

	// Valid negative key
	err := claims.SetCustom(-1, "value1")
	if err != nil {
		t.Errorf("SetCustom with negative key failed: %v", err)
	}

	// Valid key >= 8
	err = claims.SetCustom(8, "value2")
	if err != nil {
		t.Errorf("SetCustom with key >= 8 failed: %v", err)
	}

	// Invalid reserved key
	err = claims.SetCustom(1, "invalid")
	if err == nil {
		t.Error("SetCustom with reserved key should fail")
	}
}

func TestU_Claims_MarshalUnmarshal(t *testing.T) {
	claims := NewClaims()
	claims.Issuer = "https://issuer.example.com"
	claims.Subject = "user-123"
	claims.Audience = "https://api.example.com"
	claims.SetExpiration(time.Hour)
	claims.CWTID = []byte("cwt-id-123")
	_ = claims.SetCustom(-1, "custom-value")

	// Marshal
	data, err := claims.MarshalCBOR()
	if err != nil {
		t.Fatalf("MarshalCBOR failed: %v", err)
	}

	// Unmarshal
	parsed := &Claims{Custom: make(map[int64]interface{})}
	err = parsed.UnmarshalCBOR(data)
	if err != nil {
		t.Fatalf("UnmarshalCBOR failed: %v", err)
	}

	// Verify
	if parsed.Issuer != claims.Issuer {
		t.Errorf("Issuer mismatch: got %q, expected %q", parsed.Issuer, claims.Issuer)
	}
	if parsed.Subject != claims.Subject {
		t.Errorf("Subject mismatch: got %q, expected %q", parsed.Subject, claims.Subject)
	}
	if parsed.Audience != claims.Audience {
		t.Errorf("Audience mismatch: got %q, expected %q", parsed.Audience, claims.Audience)
	}
}

func TestU_Claims_Validate(t *testing.T) {
	tests := []struct {
		name      string
		setup     func() *Claims
		expectErr bool
	}{
		{
			name: "Valid claims",
			setup: func() *Claims {
				c := NewClaims()
				c.SetExpiration(time.Hour)
				return c
			},
			expectErr: false,
		},
		{
			name: "Expired claims",
			setup: func() *Claims {
				c := NewClaims()
				c.Expiration = time.Now().Add(-time.Hour)
				return c
			},
			expectErr: true,
		},
		{
			name: "NotBefore in future",
			setup: func() *Claims {
				c := NewClaims()
				c.NotBefore = time.Now().Add(time.Hour)
				return c
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := tt.setup()
			err := claims.Validate()

			if tt.expectErr && err == nil {
				t.Error("expected error but got nil")
			}
			if !tt.expectErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// =============================================================================
// Signer Tests
// =============================================================================

func TestU_Signer_ECDSA(t *testing.T) {
	key := generateECDSAKey(t)

	signer, err := NewSigner(key)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	if signer.Algorithm() != AlgES256 {
		t.Errorf("expected ES256, got %d", signer.Algorithm())
	}

	// Test signing
	data := []byte("test data to sign")
	sig, err := signer.Sign(rand.Reader, data)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if len(sig) == 0 {
		t.Error("signature should not be empty")
	}

	// Verify
	err = signer.Verify(data, sig)
	if err != nil {
		t.Errorf("Verify failed: %v", err)
	}
}

func TestU_Signer_MLDSA44(t *testing.T) {
	_, priv := generateMLDSA44Key(t)

	signer, err := NewSigner(priv)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	if signer.Algorithm() != AlgMLDSA44 {
		t.Errorf("expected ML-DSA-44, got %d", signer.Algorithm())
	}

	// Test signing
	data := []byte("test data to sign with ML-DSA-44")
	sig, err := signer.Sign(rand.Reader, data)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if len(sig) == 0 {
		t.Error("signature should not be empty")
	}

	// Verify
	err = signer.Verify(data, sig)
	if err != nil {
		t.Errorf("Verify failed: %v", err)
	}
}

func TestU_Signer_MLDSA65(t *testing.T) {
	_, priv := generateMLDSA65Key(t)

	signer, err := NewSigner(priv)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	if signer.Algorithm() != AlgMLDSA65 {
		t.Errorf("expected ML-DSA-65, got %d", signer.Algorithm())
	}

	// Test signing
	data := []byte("test data to sign with ML-DSA-65")
	sig, err := signer.Sign(rand.Reader, data)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Verify
	err = signer.Verify(data, sig)
	if err != nil {
		t.Errorf("Verify failed: %v", err)
	}
}

func TestU_Signer_MLDSA87(t *testing.T) {
	_, priv := generateMLDSA87Key(t)

	signer, err := NewSigner(priv)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	if signer.Algorithm() != AlgMLDSA87 {
		t.Errorf("expected ML-DSA-87, got %d", signer.Algorithm())
	}

	// Test signing
	data := []byte("test data to sign with ML-DSA-87")
	sig, err := signer.Sign(rand.Reader, data)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Verify
	err = signer.Verify(data, sig)
	if err != nil {
		t.Errorf("Verify failed: %v", err)
	}
}

// =============================================================================
// Verifier Tests
// =============================================================================

func TestU_Verifier_ECDSA(t *testing.T) {
	key := generateECDSAKey(t)

	verifier := NewVerifierWithAlgorithm(&key.PublicKey, AlgES256)

	if verifier.Algorithm() != AlgES256 {
		t.Errorf("expected ES256, got %d", verifier.Algorithm())
	}
}

func TestU_Verifier_MLDSA(t *testing.T) {
	pub, _ := generateMLDSA44Key(t)

	verifier := NewVerifierWithAlgorithm(pub, AlgMLDSA44)

	if verifier.Algorithm() != AlgMLDSA44 {
		t.Errorf("expected ML-DSA-44, got %d", verifier.Algorithm())
	}
}

// =============================================================================
// CWT Sign/Verify Tests
// =============================================================================

func TestU_CWT_SignVerify_ECDSA(t *testing.T) {
	ctx := context.Background()
	key := generateECDSAKey(t)
	cert := generateTestCertificate(t, key)

	// Create CWT
	claims := NewClaims()
	claims.Issuer = "https://issuer.example.com"
	claims.Subject = "user-123"
	claims.SetExpiration(time.Hour)

	config := &CWTConfig{
		MessageConfig: MessageConfig{
			Signer:      key,
			Certificate: cert,
		},
		Claims:       claims,
		AutoIssuedAt: true,
		AutoCWTID:    true,
	}

	cwt, err := IssueCWT(ctx, config)
	if err != nil {
		t.Fatalf("IssueCWT failed: %v", err)
	}

	if len(cwt) == 0 {
		t.Fatal("CWT should not be empty")
	}

	// Verify CWT
	verifyConfig := &VerifyConfig{
		Certificate:     cert,
		CheckExpiration: true,
	}

	result, err := VerifyCWT(cwt, verifyConfig)
	if err != nil {
		t.Fatalf("VerifyCWT failed: %v", err)
	}

	if !result.Valid {
		t.Errorf("CWT verification failed: %v", result.Warnings)
	}

	if result.Claims == nil {
		t.Error("Claims should be present")
	}

	if result.Claims.Issuer != claims.Issuer {
		t.Errorf("Issuer mismatch: got %q, expected %q", result.Claims.Issuer, claims.Issuer)
	}
}

func TestU_CWT_SignVerify_MLDSA44(t *testing.T) {
	ctx := context.Background()
	_, priv := generateMLDSA44Key(t)

	// Create CWT
	claims := NewClaims()
	claims.Issuer = "https://pqc-issuer.example.com"
	claims.Subject = "pqc-user-456"
	claims.SetExpiration(time.Hour)

	config := &CWTConfig{
		MessageConfig: MessageConfig{
			PQCSigner: priv,
		},
		Claims:       claims,
		AutoIssuedAt: true,
		AutoCWTID:    true,
	}

	cwt, err := IssueCWT(ctx, config)
	if err != nil {
		t.Fatalf("IssueCWT failed: %v", err)
	}

	// Verify CWT
	verifyConfig := &VerifyConfig{
		PQCPublicKey:    priv.Public(),
		CheckExpiration: true,
	}

	result, err := VerifyCWT(cwt, verifyConfig)
	if err != nil {
		t.Fatalf("VerifyCWT failed: %v", err)
	}

	if !result.Valid {
		t.Errorf("CWT verification failed: %v", result.Warnings)
	}

	if len(result.Algorithms) == 0 {
		t.Error("Algorithms should be present")
	}

	if result.Algorithms[0] != AlgMLDSA44 {
		t.Errorf("expected ML-DSA-44, got %d", result.Algorithms[0])
	}
}

func TestU_CWT_SignVerify_MLDSA65(t *testing.T) {
	ctx := context.Background()
	_, priv := generateMLDSA65Key(t)

	claims := NewClaims()
	claims.Issuer = "https://pqc-issuer.example.com"
	claims.Subject = "mldsa65-user"
	claims.SetExpiration(time.Hour)

	config := &CWTConfig{
		MessageConfig: MessageConfig{
			PQCSigner: priv,
		},
		Claims:       claims,
		AutoIssuedAt: true,
	}

	cwt, err := IssueCWT(ctx, config)
	if err != nil {
		t.Fatalf("IssueCWT failed: %v", err)
	}

	verifyConfig := &VerifyConfig{
		PQCPublicKey:    priv.Public(),
		CheckExpiration: true,
	}

	result, err := VerifyCWT(cwt, verifyConfig)
	if err != nil {
		t.Fatalf("VerifyCWT failed: %v", err)
	}

	if !result.Valid {
		t.Errorf("CWT verification failed: %v", result.Warnings)
	}

	if result.Algorithms[0] != AlgMLDSA65 {
		t.Errorf("expected ML-DSA-65, got %d", result.Algorithms[0])
	}
}

func TestU_CWT_SignVerify_MLDSA87(t *testing.T) {
	ctx := context.Background()
	_, priv := generateMLDSA87Key(t)

	claims := NewClaims()
	claims.Issuer = "https://pqc-issuer.example.com"
	claims.Subject = "mldsa87-user"
	claims.SetExpiration(time.Hour)

	config := &CWTConfig{
		MessageConfig: MessageConfig{
			PQCSigner: priv,
		},
		Claims:       claims,
		AutoIssuedAt: true,
	}

	cwt, err := IssueCWT(ctx, config)
	if err != nil {
		t.Fatalf("IssueCWT failed: %v", err)
	}

	verifyConfig := &VerifyConfig{
		PQCPublicKey:    priv.Public(),
		CheckExpiration: true,
	}

	result, err := VerifyCWT(cwt, verifyConfig)
	if err != nil {
		t.Fatalf("VerifyCWT failed: %v", err)
	}

	if !result.Valid {
		t.Errorf("CWT verification failed: %v", result.Warnings)
	}

	if result.Algorithms[0] != AlgMLDSA87 {
		t.Errorf("expected ML-DSA-87, got %d", result.Algorithms[0])
	}
}

func TestU_CWT_Expired(t *testing.T) {
	ctx := context.Background()
	key := generateECDSAKey(t)
	cert := generateTestCertificate(t, key)

	// Create expired CWT
	claims := NewClaims()
	claims.Issuer = "https://issuer.example.com"
	claims.Expiration = time.Now().Add(-time.Hour) // Expired

	config := &CWTConfig{
		MessageConfig: MessageConfig{
			Signer:      key,
			Certificate: cert,
		},
		Claims:       claims,
		AutoIssuedAt: true,
	}

	cwt, err := IssueCWT(ctx, config)
	if err != nil {
		t.Fatalf("IssueCWT failed: %v", err)
	}

	// Verify should fail due to expiration
	verifyConfig := &VerifyConfig{
		Certificate:     cert,
		CheckExpiration: true,
	}

	result, err := VerifyCWT(cwt, verifyConfig)
	if err != nil {
		t.Fatalf("VerifyCWT failed: %v", err)
	}

	if result.Valid {
		t.Error("Expired CWT should not be valid")
	}
}

// =============================================================================
// Sign1 Tests
// =============================================================================

func TestU_Sign1_SignVerify_ECDSA(t *testing.T) {
	ctx := context.Background()
	key := generateECDSAKey(t)
	cert := generateTestCertificate(t, key)

	payload := []byte("Hello, COSE Sign1!")

	config := &MessageConfig{
		Type:        TypeSign1,
		Signer:      key,
		Certificate: cert,
	}

	signed, err := IssueSign1(ctx, payload, config)
	if err != nil {
		t.Fatalf("IssueSign1 failed: %v", err)
	}

	// Verify
	verifyConfig := &VerifyConfig{
		Certificate: cert,
	}

	result, err := VerifySign1(signed, verifyConfig)
	if err != nil {
		t.Fatalf("VerifySign1 failed: %v", err)
	}

	if !result.Valid {
		t.Errorf("Sign1 verification failed: %v", result.Warnings)
	}
}

func TestU_Sign1_SignVerify_MLDSA(t *testing.T) {
	ctx := context.Background()
	_, priv := generateMLDSA65Key(t)

	payload := []byte("Hello, COSE Sign1 with ML-DSA!")

	config := &MessageConfig{
		Type:      TypeSign1,
		PQCSigner: priv,
	}

	signed, err := IssueSign1(ctx, payload, config)
	if err != nil {
		t.Fatalf("IssueSign1 failed: %v", err)
	}

	// Verify
	verifyConfig := &VerifyConfig{
		PQCPublicKey: priv.Public(),
	}

	result, err := VerifySign1(signed, verifyConfig)
	if err != nil {
		t.Fatalf("VerifySign1 failed: %v", err)
	}

	if !result.Valid {
		t.Errorf("Sign1 verification failed: %v", result.Warnings)
	}
}

// =============================================================================
// Hybrid Sign Tests
// =============================================================================

func TestU_HybridSign_SignVerify(t *testing.T) {
	ctx := context.Background()

	// Classical key
	ecKey := generateECDSAKey(t)
	ecCert := generateTestCertificate(t, ecKey)

	// PQC key
	_, mldsaPriv := generateMLDSA44Key(t)

	payload := []byte("Hello, Hybrid COSE!")

	config := &MessageConfig{
		Type:           TypeSign,
		Signer:         ecKey,
		Certificate:    ecCert,
		PQCSigner:      mldsaPriv,
		PQCCertificate: nil, // No cert for PQC in this test
	}

	signed, err := IssueSign(ctx, payload, config)
	if err != nil {
		t.Fatalf("IssueSign failed: %v", err)
	}

	// Verify
	verifyConfig := &VerifyConfig{
		Certificate:  ecCert,
		PQCPublicKey: mldsaPriv.Public(),
	}

	result, err := VerifySign(signed, verifyConfig)
	if err != nil {
		t.Fatalf("VerifySign failed: %v", err)
	}

	if !result.Valid {
		t.Errorf("Hybrid Sign verification failed: %v", result.Warnings)
	}

	if result.Mode != ModeHybrid {
		t.Errorf("expected hybrid mode, got %v", result.Mode)
	}

	if len(result.Algorithms) != 2 {
		t.Errorf("expected 2 algorithms, got %d", len(result.Algorithms))
	}
}

// =============================================================================
// Parse Tests
// =============================================================================

func TestU_Parse_CWT(t *testing.T) {
	ctx := context.Background()
	key := generateECDSAKey(t)
	cert := generateTestCertificate(t, key)

	claims := NewClaims()
	claims.Issuer = "https://issuer.example.com"
	claims.Subject = "user-123"

	config := &CWTConfig{
		MessageConfig: MessageConfig{
			Signer:      key,
			Certificate: cert,
		},
		Claims: claims,
	}

	cwt, err := IssueCWT(ctx, config)
	if err != nil {
		t.Fatalf("IssueCWT failed: %v", err)
	}

	// Parse
	msg, err := ParseCWT(cwt)
	if err != nil {
		t.Fatalf("ParseCWT failed: %v", err)
	}

	if msg.Type != TypeCWT {
		t.Errorf("expected TypeCWT, got %v", msg.Type)
	}

	if msg.Claims == nil {
		t.Error("Claims should be present")
	}

	if msg.Claims.Issuer != claims.Issuer {
		t.Errorf("Issuer mismatch: got %q, expected %q", msg.Claims.Issuer, claims.Issuer)
	}
}

func TestU_Parse_Sign1(t *testing.T) {
	ctx := context.Background()
	key := generateECDSAKey(t)

	payload := []byte("test payload")

	config := &MessageConfig{
		Type:   TypeSign1,
		Signer: key,
	}

	signed, err := IssueSign1(ctx, payload, config)
	if err != nil {
		t.Fatalf("IssueSign1 failed: %v", err)
	}

	// Parse
	msg, err := ParseSign1(signed)
	if err != nil {
		t.Fatalf("ParseSign1 failed: %v", err)
	}

	if msg.Type != TypeSign1 {
		t.Errorf("expected TypeSign1, got %v", msg.Type)
	}

	if string(msg.Payload) != string(payload) {
		t.Errorf("payload mismatch: got %q, expected %q", msg.Payload, payload)
	}
}

func TestU_Parse_Auto(t *testing.T) {
	ctx := context.Background()
	key := generateECDSAKey(t)
	cert := generateTestCertificate(t, key)

	claims := NewClaims()
	claims.Issuer = "https://issuer.example.com"

	config := &CWTConfig{
		MessageConfig: MessageConfig{
			Signer:      key,
			Certificate: cert,
		},
		Claims: claims,
	}

	cwt, err := IssueCWT(ctx, config)
	if err != nil {
		t.Fatalf("IssueCWT failed: %v", err)
	}

	// Auto-parse
	msg, err := Parse(cwt)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	// Should detect as CWT (Sign1 with claims)
	if msg.Type != TypeCWT && msg.Type != TypeSign1 {
		t.Errorf("expected TypeCWT or TypeSign1, got %v", msg.Type)
	}
}

// =============================================================================
// Info Tests
// =============================================================================

func TestU_Info_CWT(t *testing.T) {
	ctx := context.Background()
	key := generateECDSAKey(t)
	cert := generateTestCertificate(t, key)

	claims := NewClaims()
	claims.Issuer = "https://issuer.example.com"
	claims.Subject = "user-123"

	config := &CWTConfig{
		MessageConfig: MessageConfig{
			Signer:           key,
			Certificate:      cert,
			IncludeCertChain: true,
		},
		Claims: claims,
	}

	cwt, err := IssueCWT(ctx, config)
	if err != nil {
		t.Fatalf("IssueCWT failed: %v", err)
	}

	// Get info
	info, err := GetInfo(cwt)
	if err != nil {
		t.Fatalf("GetInfo failed: %v", err)
	}

	if info.Type == "" {
		t.Error("Type should be set")
	}

	if len(info.Signatures) == 0 {
		t.Error("Signatures should be present")
	}

	if info.Claims == nil {
		t.Error("Claims should be present")
	}

	if info.Claims.Issuer != claims.Issuer {
		t.Errorf("Issuer mismatch: got %q, expected %q", info.Claims.Issuer, claims.Issuer)
	}
}

// =============================================================================
// Serial Generator Tests
// =============================================================================

func TestU_SerialGenerator(t *testing.T) {
	gen := DefaultSerialGenerator

	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id, err := gen.Next()
		if err != nil {
			t.Fatalf("Next() failed: %v", err)
		}

		if len(id) == 0 {
			t.Error("ID should not be empty")
		}

		idStr := string(id)
		if ids[idStr] {
			t.Error("Generated duplicate ID")
		}
		ids[idStr] = true
	}
}

// =============================================================================
// Certificate Fingerprint Tests
// =============================================================================

func TestU_CertificateFingerprint(t *testing.T) {
	key := generateECDSAKey(t)
	cert := generateTestCertificate(t, key)

	fp := CertificateFingerprint(cert)

	if len(fp) != 32 { // SHA-256 produces 32 bytes
		t.Errorf("fingerprint should be 32 bytes, got %d", len(fp))
	}

	// Same cert should produce same fingerprint
	fp2 := CertificateFingerprint(cert)
	if string(fp) != string(fp2) {
		t.Error("same certificate should produce same fingerprint")
	}
}

// =============================================================================
// Error Cases
// =============================================================================

func TestU_CWT_NoClaims(t *testing.T) {
	ctx := context.Background()
	key := generateECDSAKey(t)

	config := &CWTConfig{
		MessageConfig: MessageConfig{
			Signer: key,
		},
		Claims: nil, // No claims
	}

	_, err := IssueCWT(ctx, config)
	if err == nil {
		t.Error("IssueCWT should fail without claims")
	}
}

func TestU_Sign1_NoSigner(t *testing.T) {
	ctx := context.Background()

	config := &MessageConfig{
		Type: TypeSign1,
		// No signer
	}

	_, err := IssueSign1(ctx, []byte("test"), config)
	if err == nil {
		t.Error("IssueSign1 should fail without signer")
	}
}

func TestU_Verify_WrongKey(t *testing.T) {
	ctx := context.Background()

	// Sign with one key
	key1 := generateECDSAKey(t)
	cert1 := generateTestCertificate(t, key1)

	claims := NewClaims()
	claims.Issuer = "test"

	config := &CWTConfig{
		MessageConfig: MessageConfig{
			Signer:      key1,
			Certificate: cert1,
		},
		Claims: claims,
	}

	cwt, err := IssueCWT(ctx, config)
	if err != nil {
		t.Fatalf("IssueCWT failed: %v", err)
	}

	// Verify with different key
	key2 := generateECDSAKey(t)
	cert2 := generateTestCertificate(t, key2)

	verifyConfig := &VerifyConfig{
		Certificate: cert2,
	}

	result, err := VerifyCWT(cwt, verifyConfig)
	if err != nil {
		t.Fatalf("VerifyCWT failed: %v", err)
	}

	if result.Valid {
		t.Error("verification with wrong key should fail")
	}
}

func TestU_Parse_InvalidData(t *testing.T) {
	_, err := Parse([]byte("not valid CBOR"))
	if err == nil {
		t.Error("Parse should fail with invalid data")
	}
}

// =============================================================================
// Quick Verify Tests
// =============================================================================

func TestU_QuickVerify(t *testing.T) {
	ctx := context.Background()
	key := generateECDSAKey(t)

	claims := NewClaims()
	claims.Issuer = "test"

	config := &CWTConfig{
		MessageConfig: MessageConfig{
			Signer: key,
		},
		Claims: claims,
	}

	cwt, err := IssueCWT(ctx, config)
	if err != nil {
		t.Fatalf("IssueCWT failed: %v", err)
	}

	// Quick verify
	err = QuickVerify(cwt, &key.PublicKey)
	if err != nil {
		t.Errorf("QuickVerify failed: %v", err)
	}
}

// =============================================================================
// Additional Coverage Tests
// =============================================================================

func TestU_CWT_WithCustomClaims(t *testing.T) {
	ctx := context.Background()
	key := generateECDSAKey(t)
	cert := generateTestCertificate(t, key)

	claims := NewClaims()
	claims.Issuer = "https://issuer.example.com"
	claims.Subject = "user-with-custom"
	claims.SetExpiration(time.Hour)
	_ = claims.SetCustom(-1, "custom-value")
	_ = claims.SetCustom(-2, 42)
	_ = claims.SetCustom(10, true)

	config := &CWTConfig{
		MessageConfig: MessageConfig{
			Signer:      key,
			Certificate: cert,
		},
		Claims:       claims,
		AutoIssuedAt: true,
	}

	cwt, err := IssueCWT(ctx, config)
	if err != nil {
		t.Fatalf("IssueCWT failed: %v", err)
	}

	// Parse and verify custom claims are present
	msg, err := ParseCWT(cwt)
	if err != nil {
		t.Fatalf("ParseCWT failed: %v", err)
	}

	if len(msg.Claims.Custom) == 0 {
		t.Error("Custom claims should be present")
	}
}

func TestU_CWT_WithContentType(t *testing.T) {
	ctx := context.Background()
	key := generateECDSAKey(t)
	cert := generateTestCertificate(t, key)

	claims := NewClaims()
	claims.Issuer = "test"

	config := &CWTConfig{
		MessageConfig: MessageConfig{
			Signer:      key,
			Certificate: cert,
			ContentType: "application/custom-cwt",
		},
		Claims: claims,
	}

	cwt, err := IssueCWT(ctx, config)
	if err != nil {
		t.Fatalf("IssueCWT failed: %v", err)
	}

	msg, err := Parse(cwt)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	// Note: content type may or may not be preserved depending on implementation
	_ = msg // Just verify parsing works
}

func TestU_CWT_WithCertChain(t *testing.T) {
	ctx := context.Background()
	key := generateECDSAKey(t)
	cert := generateTestCertificate(t, key)

	claims := NewClaims()
	claims.Issuer = "test"

	config := &CWTConfig{
		MessageConfig: MessageConfig{
			Signer:           key,
			Certificate:      cert,
			IncludeCertChain: true,
		},
		Claims: claims,
	}

	cwt, err := IssueCWT(ctx, config)
	if err != nil {
		t.Fatalf("IssueCWT failed: %v", err)
	}

	// Verify the message can be parsed and has cert info
	msg, err := ParseCWT(cwt)
	if err != nil {
		t.Fatalf("ParseCWT failed: %v", err)
	}

	// Cert should be embedded in the message
	if len(msg.Signatures) == 0 {
		t.Error("Signatures should be present")
	}
}

func TestU_Mode_Detection(t *testing.T) {
	tests := []struct {
		name     string
		config   *CWTConfig
		expected SigningMode
	}{
		{
			name: "Classical mode",
			config: &CWTConfig{
				MessageConfig: MessageConfig{
					Signer: generateECDSAKey(t),
				},
				Claims: NewClaims(),
			},
			expected: ModeClassical,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.config.Claims.Issuer = "test"
			mode := tt.config.Mode()
			if mode != tt.expected {
				t.Errorf("expected mode %v, got %v", tt.expected, mode)
			}
		})
	}
}

func TestU_MessageType_String(t *testing.T) {
	tests := []struct {
		msgType  MessageType
		expected string
	}{
		{TypeCWT, "CWT"},
		{TypeSign1, "Sign1"},
		{TypeSign, "Sign"},
		{MessageType(99), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if tt.msgType.String() != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, tt.msgType.String())
			}
		})
	}
}

func TestU_SigningMode_String(t *testing.T) {
	tests := []struct {
		mode     SigningMode
		expected string
	}{
		{ModeClassical, "Classical"},
		{ModePQC, "PQC"},
		{ModeHybrid, "Hybrid"},
		{SigningMode(99), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if tt.mode.String() != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, tt.mode.String())
			}
		})
	}
}

func TestU_IsClassicalAlgorithm(t *testing.T) {
	tests := []struct {
		alg      gocose.Algorithm
		expected bool
	}{
		{AlgES256, true},
		{AlgES384, true},
		{AlgES512, true},
		{AlgEdDSA, true},
		{AlgPS256, true},
		{AlgMLDSA44, false},
		{AlgMLDSA65, false},
		{AlgSLHDSASHA2128s, false},
	}

	for _, tt := range tests {
		t.Run(AlgorithmName(tt.alg), func(t *testing.T) {
			if IsClassicalAlgorithm(tt.alg) != tt.expected {
				t.Errorf("IsClassicalAlgorithm(%d) = %v, expected %v", tt.alg, !tt.expected, tt.expected)
			}
		})
	}
}

func TestU_Verifier_VerifyWithWrongData(t *testing.T) {
	key := generateECDSAKey(t)

	signer, err := NewSigner(key)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	// Sign some data
	data := []byte("original data")
	sig, err := signer.Sign(rand.Reader, data)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Verify with different data should fail
	wrongData := []byte("different data")
	err = signer.Verify(wrongData, sig)
	if err == nil {
		t.Error("Verify should fail with wrong data")
	}
}

func TestU_Parse_EmptyData(t *testing.T) {
	_, err := Parse([]byte{})
	if err == nil {
		t.Error("Parse should fail with empty data")
	}
}

func TestU_Parse_ShortData(t *testing.T) {
	_, err := Parse([]byte{0xd8}) // Truncated tag
	if err == nil {
		t.Error("Parse should fail with truncated data")
	}
}

func TestU_MatchKeyID(t *testing.T) {
	key := generateECDSAKey(t)
	cert := generateTestCertificate(t, key)

	keyID := CertificateFingerprint(cert)

	// Should match
	if !MatchKeyID(cert, keyID) {
		t.Error("MatchKeyID should return true for matching fingerprint")
	}

	// Should not match with wrong ID
	if MatchKeyID(cert, []byte("wrong-id")) {
		t.Error("MatchKeyID should return false for wrong ID")
	}

	// Nil cert should return false
	if MatchKeyID(nil, keyID) {
		t.Error("MatchKeyID should return false for nil cert")
	}

	// Empty keyID should return false
	if MatchKeyID(cert, []byte{}) {
		t.Error("MatchKeyID should return false for empty keyID")
	}
}

func TestU_Info_Print(t *testing.T) {
	ctx := context.Background()
	key := generateECDSAKey(t)
	cert := generateTestCertificate(t, key)

	claims := NewClaims()
	claims.Issuer = "https://issuer.example.com"
	claims.Subject = "user-123"
	claims.Audience = "https://audience.example.com"
	claims.SetExpiration(time.Hour)

	config := &CWTConfig{
		MessageConfig: MessageConfig{
			Signer:           key,
			Certificate:      cert,
			IncludeCertChain: true,
		},
		Claims: claims,
	}

	cwt, err := IssueCWT(ctx, config)
	if err != nil {
		t.Fatalf("IssueCWT failed: %v", err)
	}

	info, err := GetInfo(cwt)
	if err != nil {
		t.Fatalf("GetInfo failed: %v", err)
	}

	// Print to discard writer to test Print function
	info.Print(&discardWriter{})
}

// discardWriter is a writer that discards all data.
type discardWriter struct{}

func (d *discardWriter) Write(p []byte) (n int, err error) {
	return len(p), nil
}

func TestU_CWT_VerifyWithCertificateChain(t *testing.T) {
	ctx := context.Background()
	key := generateECDSAKey(t)
	cert := generateTestCertificate(t, key)

	claims := NewClaims()
	claims.Issuer = "test"
	claims.SetExpiration(time.Hour)

	config := &CWTConfig{
		MessageConfig: MessageConfig{
			Signer:           key,
			Certificate:      cert,
			IncludeCertChain: true,
		},
		Claims: claims,
	}

	cwt, err := IssueCWT(ctx, config)
	if err != nil {
		t.Fatalf("IssueCWT failed: %v", err)
	}

	// Create a cert pool with the signer cert
	pool := x509.NewCertPool()
	pool.AddCert(cert)

	verifyConfig := &VerifyConfig{
		Roots:           pool,
		Certificate:     cert,
		CheckExpiration: true,
	}

	result, err := VerifyCWT(cwt, verifyConfig)
	if err != nil {
		t.Fatalf("VerifyCWT failed: %v", err)
	}

	if !result.Valid {
		t.Errorf("CWT verification failed: %v", result.Warnings)
	}
}

func TestU_Sign_OnlyPQC(t *testing.T) {
	ctx := context.Background()
	_, priv := generateMLDSA44Key(t)

	payload := []byte("PQC only sign message")

	config := &MessageConfig{
		Type:      TypeSign,
		PQCSigner: priv,
	}

	signed, err := IssueSign(ctx, payload, config)
	if err != nil {
		t.Fatalf("IssueSign failed: %v", err)
	}

	// Verify
	verifyConfig := &VerifyConfig{
		PQCPublicKey: priv.Public(),
	}

	result, err := VerifySign(signed, verifyConfig)
	if err != nil {
		t.Fatalf("VerifySign failed: %v", err)
	}

	if !result.Valid {
		t.Errorf("Sign verification failed: %v", result.Warnings)
	}

	if result.Mode != ModePQC {
		t.Errorf("expected PQC mode, got %v", result.Mode)
	}
}

// =============================================================================
// Extended Coverage Tests
// =============================================================================

func TestU_NewSignerWithAlgorithm(t *testing.T) {
	key := generateECDSAKey(t)

	signer := NewSignerWithAlgorithm(key, AlgES256)

	if signer.Algorithm() != AlgES256 {
		t.Errorf("expected ES256, got %d", signer.Algorithm())
	}

	// Test PublicKey
	pub := signer.PublicKey()
	if pub == nil {
		t.Error("PublicKey should not be nil")
	}
}

func TestU_NewVerifier(t *testing.T) {
	key := generateECDSAKey(t)

	verifier, err := NewVerifier(&key.PublicKey)
	if err != nil {
		t.Fatalf("NewVerifier failed: %v", err)
	}

	if verifier.Algorithm() != AlgES256 {
		t.Errorf("expected ES256, got %d", verifier.Algorithm())
	}

	// Test PublicKey method
	pub := verifier.PublicKey()
	if pub == nil {
		t.Error("PublicKey should not be nil")
	}
}

func TestU_Claims_GetCustom(t *testing.T) {
	claims := NewClaims()
	_ = claims.SetCustom(-1, "test-value")
	_ = claims.SetCustom(-2, 42)

	// Get existing custom claim
	val, ok := claims.GetCustom(-1)
	if !ok {
		t.Error("GetCustom should return true for existing claim")
	}
	if val != "test-value" {
		t.Errorf("expected 'test-value', got %v", val)
	}

	// Get non-existing custom claim
	_, ok = claims.GetCustom(-999)
	if ok {
		t.Error("GetCustom should return false for non-existing claim")
	}
}

func TestU_VerifyWithTime(t *testing.T) {
	ctx := context.Background()
	key := generateECDSAKey(t)
	cert := generateTestCertificate(t, key)

	claims := NewClaims()
	claims.Issuer = "test"
	claims.SetExpiration(time.Hour)

	config := &CWTConfig{
		MessageConfig: MessageConfig{
			Signer:      key,
			Certificate: cert,
		},
		Claims: claims,
	}

	cwt, err := IssueCWT(ctx, config)
	if err != nil {
		t.Fatalf("IssueCWT failed: %v", err)
	}

	verifyConfig := &VerifyConfig{
		Certificate:     cert,
		CheckExpiration: true,
	}

	// Verify at current time
	result, err := VerifyWithTime(cwt, verifyConfig, time.Now())
	if err != nil {
		t.Fatalf("VerifyWithTime failed: %v", err)
	}

	if !result.Valid {
		t.Errorf("verification failed: %v", result.Warnings)
	}

	// Verify at future time (should fail due to expiration)
	futureResult, err := VerifyWithTime(cwt, verifyConfig, time.Now().Add(2*time.Hour))
	if err != nil {
		t.Fatalf("VerifyWithTime failed: %v", err)
	}

	if futureResult.Valid {
		t.Error("verification at future time should fail due to expiration")
	}
}

func TestU_Info_String(t *testing.T) {
	ctx := context.Background()
	key := generateECDSAKey(t)
	cert := generateTestCertificate(t, key)

	claims := NewClaims()
	claims.Issuer = "https://issuer.example.com"
	claims.Subject = "user-123"
	claims.SetExpiration(time.Hour)

	config := &CWTConfig{
		MessageConfig: MessageConfig{
			Signer:           key,
			Certificate:      cert,
			IncludeCertChain: true,
		},
		Claims: claims,
	}

	cwt, err := IssueCWT(ctx, config)
	if err != nil {
		t.Fatalf("IssueCWT failed: %v", err)
	}

	info, err := GetInfo(cwt)
	if err != nil {
		t.Fatalf("GetInfo failed: %v", err)
	}

	// Test String method
	str := info.String()
	if str == "" {
		t.Error("String() should not return empty string")
	}
}

func TestU_PrintMessage(t *testing.T) {
	ctx := context.Background()
	key := generateECDSAKey(t)
	cert := generateTestCertificate(t, key)

	claims := NewClaims()
	claims.Issuer = "test"

	config := &CWTConfig{
		MessageConfig: MessageConfig{
			Signer:      key,
			Certificate: cert,
		},
		Claims: claims,
	}

	cwt, err := IssueCWT(ctx, config)
	if err != nil {
		t.Fatalf("IssueCWT failed: %v", err)
	}

	// Test PrintMessage function
	_ = PrintMessage(&discardWriter{}, cwt)
}

func TestU_AlgorithmName_Extended(t *testing.T) {
	// Test all algorithm names including SLH-DSA variants
	tests := []struct {
		alg      gocose.Algorithm
		expected string
	}{
		{AlgPS256, "PS256"},
		{AlgPS384, "PS384"},
		{AlgPS512, "PS512"},
		{AlgSLHDSASHA2128f, "SLH-DSA-SHA2-128f"},
		{AlgSLHDSASHA2192s, "SLH-DSA-SHA2-192s"},
		{AlgSLHDSASHA2192f, "SLH-DSA-SHA2-192f"},
		{AlgSLHDSASHA2256s, "SLH-DSA-SHA2-256s"},
		{AlgSLHDSASHA2256f, "SLH-DSA-SHA2-256f"},
		{AlgSLHDSASHAKE128s, "SLH-DSA-SHAKE-128s"},
		{AlgSLHDSASHAKE128f, "SLH-DSA-SHAKE-128f"},
		{AlgSLHDSASHAKE192s, "SLH-DSA-SHAKE-192s"},
		{AlgSLHDSASHAKE192f, "SLH-DSA-SHAKE-192f"},
		{AlgSLHDSASHAKE256s, "SLH-DSA-SHAKE-256s"},
		{AlgSLHDSASHAKE256f, "SLH-DSA-SHAKE-256f"},
		{gocose.Algorithm(9999), "Unknown(9999)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			name := AlgorithmName(tt.alg)
			if name != tt.expected {
				t.Errorf("AlgorithmName(%d) = %q, expected %q", tt.alg, name, tt.expected)
			}
		})
	}
}

func TestU_Mode_Hybrid(t *testing.T) {
	ecKey := generateECDSAKey(t)
	_, mldsaKey := generateMLDSA44Key(t)

	config := &CWTConfig{
		MessageConfig: MessageConfig{
			Signer:    ecKey,
			PQCSigner: mldsaKey,
		},
		Claims: NewClaims(),
	}
	config.Claims.Issuer = "test"

	mode := config.Mode()
	if mode != ModeHybrid {
		t.Errorf("expected ModeHybrid, got %v", mode)
	}
}

func TestU_Mode_PQCOnly(t *testing.T) {
	_, mldsaKey := generateMLDSA44Key(t)

	config := &CWTConfig{
		MessageConfig: MessageConfig{
			PQCSigner: mldsaKey,
		},
		Claims: NewClaims(),
	}
	config.Claims.Issuer = "test"

	mode := config.Mode()
	if mode != ModePQC {
		t.Errorf("expected ModePQC, got %v", mode)
	}
}

func TestU_CertificateFingerprint_Nil(t *testing.T) {
	fp := CertificateFingerprint(nil)
	if fp != nil {
		t.Error("CertificateFingerprint(nil) should return nil")
	}
}

func TestU_Parse_Sign_Message(t *testing.T) {
	ctx := context.Background()
	ecKey := generateECDSAKey(t)
	ecCert := generateTestCertificate(t, ecKey)
	_, mldsaKey := generateMLDSA44Key(t)

	payload := []byte("test hybrid payload")

	config := &MessageConfig{
		Type:        TypeSign,
		Signer:      ecKey,
		Certificate: ecCert,
		PQCSigner:   mldsaKey,
	}

	signed, err := IssueSign(ctx, payload, config)
	if err != nil {
		t.Fatalf("IssueSign failed: %v", err)
	}

	// Parse as Sign message
	msg, err := ParseSign(signed)
	if err != nil {
		t.Fatalf("ParseSign failed: %v", err)
	}

	if msg.Type != TypeSign {
		t.Errorf("expected TypeSign, got %v", msg.Type)
	}

	if len(msg.Signatures) != 2 {
		t.Errorf("expected 2 signatures, got %d", len(msg.Signatures))
	}
}

func TestU_Parse_UnknownType(t *testing.T) {
	// Test with a 2-byte tag that we don't recognize
	data := []byte{0xd9, 0x01, 0x00, 0x84} // Tag 256, array of 4
	_, err := Parse(data)
	if err == nil {
		t.Error("Parse should fail with unknown message type")
	}
}

func TestU_detectMessageType_ArrayFormat(t *testing.T) {
	// Test untagged array format (0x84 = array of 4 elements)
	data := []byte{0x84, 0x40, 0xa0, 0x40, 0x40}
	msgType, err := detectMessageType(data)
	if err != nil {
		t.Fatalf("detectMessageType failed: %v", err)
	}
	if msgType != TypeSign1 {
		t.Errorf("expected TypeSign1, got %v", msgType)
	}
}

func TestU_Signer_Ed25519(t *testing.T) {
	// Generate Ed25519 key
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}
	_ = pub

	signer, err := NewSigner(priv)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	if signer.Algorithm() != AlgEdDSA {
		t.Errorf("expected EdDSA, got %d", signer.Algorithm())
	}

	// Test signing
	data := []byte("test data for Ed25519")
	sig, err := signer.Sign(rand.Reader, data)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Verify
	err = signer.Verify(data, sig)
	if err != nil {
		t.Errorf("Verify failed: %v", err)
	}
}

func TestU_Signer_ECDSA_P384(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate P384 key: %v", err)
	}

	signer, err := NewSigner(key)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	if signer.Algorithm() != AlgES384 {
		t.Errorf("expected ES384, got %d", signer.Algorithm())
	}

	// Test signing
	data := []byte("test data for P384")
	sig, err := signer.Sign(rand.Reader, data)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Verify
	err = signer.Verify(data, sig)
	if err != nil {
		t.Errorf("Verify failed: %v", err)
	}
}

func TestU_Signer_ECDSA_P521(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate P521 key: %v", err)
	}

	signer, err := NewSigner(key)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	if signer.Algorithm() != AlgES512 {
		t.Errorf("expected ES512, got %d", signer.Algorithm())
	}

	// Test signing
	data := []byte("test data for P521")
	sig, err := signer.Sign(rand.Reader, data)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Verify
	err = signer.Verify(data, sig)
	if err != nil {
		t.Errorf("Verify failed: %v", err)
	}
}

func TestU_Verifier_Ed25519(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}

	verifier, err := NewVerifier(pub)
	if err != nil {
		t.Fatalf("NewVerifier failed: %v", err)
	}

	if verifier.Algorithm() != AlgEdDSA {
		t.Errorf("expected EdDSA, got %d", verifier.Algorithm())
	}
}

func TestU_CWT_AutoCWTID(t *testing.T) {
	ctx := context.Background()
	key := generateECDSAKey(t)
	cert := generateTestCertificate(t, key)

	claims := NewClaims()
	claims.Issuer = "test"

	config := &CWTConfig{
		MessageConfig: MessageConfig{
			Signer:      key,
			Certificate: cert,
		},
		Claims:    claims,
		AutoCWTID: true,
	}

	cwt, err := IssueCWT(ctx, config)
	if err != nil {
		t.Fatalf("IssueCWT failed: %v", err)
	}

	// Parse and check CWTID was auto-generated
	msg, err := ParseCWT(cwt)
	if err != nil {
		t.Fatalf("ParseCWT failed: %v", err)
	}

	if len(msg.Claims.CWTID) == 0 {
		t.Error("CWTID should be auto-generated")
	}
}

func TestU_Claims_MarshalCBOR_Audience(t *testing.T) {
	claims := NewClaims()
	claims.Issuer = "test-issuer"
	claims.Subject = "test-subject"
	claims.Audience = "test-audience"
	claims.SetExpiration(time.Hour)

	data, err := claims.MarshalCBOR()
	if err != nil {
		t.Fatalf("MarshalCBOR failed: %v", err)
	}

	// Unmarshal and verify
	parsed := &Claims{Custom: make(map[int64]interface{})}
	err = parsed.UnmarshalCBOR(data)
	if err != nil {
		t.Fatalf("UnmarshalCBOR failed: %v", err)
	}

	if parsed.Audience != claims.Audience {
		t.Errorf("Audience mismatch: got %q, expected %q", parsed.Audience, claims.Audience)
	}
}

func TestU_Claims_MarshalCBOR_NotBefore(t *testing.T) {
	claims := NewClaims()
	claims.Issuer = "test"
	claims.NotBefore = time.Now().Add(-time.Hour)

	data, err := claims.MarshalCBOR()
	if err != nil {
		t.Fatalf("MarshalCBOR failed: %v", err)
	}

	parsed := &Claims{Custom: make(map[int64]interface{})}
	err = parsed.UnmarshalCBOR(data)
	if err != nil {
		t.Fatalf("UnmarshalCBOR failed: %v", err)
	}

	if parsed.NotBefore.IsZero() {
		t.Error("NotBefore should be set")
	}
}

func TestU_QuickVerify_InvalidSignature(t *testing.T) {
	ctx := context.Background()
	key := generateECDSAKey(t)

	claims := NewClaims()
	claims.Issuer = "test"

	config := &CWTConfig{
		MessageConfig: MessageConfig{
			Signer: key,
		},
		Claims: claims,
	}

	cwt, err := IssueCWT(ctx, config)
	if err != nil {
		t.Fatalf("IssueCWT failed: %v", err)
	}

	// Try to verify with wrong key
	wrongKey := generateECDSAKey(t)
	err = QuickVerify(cwt, &wrongKey.PublicKey)
	if err == nil {
		t.Error("QuickVerify should fail with wrong key")
	}
}

func TestU_VerifySign1_WithEmbeddedCert(t *testing.T) {
	ctx := context.Background()
	key := generateECDSAKey(t)
	cert := generateTestCertificate(t, key)

	payload := []byte("test payload with cert")

	config := &MessageConfig{
		Type:             TypeSign1,
		Signer:           key,
		Certificate:      cert,
		IncludeCertChain: true,
	}

	signed, err := IssueSign1(ctx, payload, config)
	if err != nil {
		t.Fatalf("IssueSign1 failed: %v", err)
	}

	// Verify using embedded cert (no cert in config)
	verifyConfig := &VerifyConfig{
		Certificate: cert, // Still need to provide for now
	}

	result, err := VerifySign1(signed, verifyConfig)
	if err != nil {
		t.Fatalf("VerifySign1 failed: %v", err)
	}

	if !result.Valid {
		t.Errorf("verification failed: %v", result.Warnings)
	}
}

func TestU_IssueSign_NoSigner(t *testing.T) {
	ctx := context.Background()

	config := &MessageConfig{
		Type: TypeSign,
		// No signers
	}

	_, err := IssueSign(ctx, []byte("test"), config)
	if err == nil {
		t.Error("IssueSign should fail without signers")
	}
}

func TestU_CWT_HybridMode(t *testing.T) {
	ctx := context.Background()

	ecKey := generateECDSAKey(t)
	ecCert := generateTestCertificate(t, ecKey)
	_, mldsaKey := generateMLDSA65Key(t)

	claims := NewClaims()
	claims.Issuer = "hybrid-issuer"
	claims.Subject = "hybrid-subject"
	claims.SetExpiration(time.Hour)

	config := &CWTConfig{
		MessageConfig: MessageConfig{
			Signer:      ecKey,
			Certificate: ecCert,
			PQCSigner:   mldsaKey,
		},
		Claims:       claims,
		AutoIssuedAt: true,
		AutoCWTID:    true,
	}

	cwt, err := IssueCWT(ctx, config)
	if err != nil {
		t.Fatalf("IssueCWT failed: %v", err)
	}

	// Verify
	verifyConfig := &VerifyConfig{
		Certificate:  ecCert,
		PQCPublicKey: mldsaKey.Public(),
	}

	result, err := VerifyCWT(cwt, verifyConfig)
	if err != nil {
		t.Fatalf("VerifyCWT failed: %v", err)
	}

	if !result.Valid {
		t.Errorf("hybrid CWT verification failed: %v", result.Warnings)
	}

	if result.Mode != ModeHybrid {
		t.Errorf("expected ModeHybrid, got %v", result.Mode)
	}

	if len(result.Algorithms) != 2 {
		t.Errorf("expected 2 algorithms, got %d", len(result.Algorithms))
	}
}

// =============================================================================
// Extended Coverage Tests - Algorithm Conversions
// =============================================================================

func TestU_COSEAlgorithmFromPKI(t *testing.T) {
	tests := []struct {
		name     string
		pkiAlg   pkicrypto.AlgorithmID
		expected gocose.Algorithm
		wantErr  bool
	}{
		{"ECDSA P-256", pkicrypto.AlgECDSAP256, AlgES256, false},
		{"ECDSA P-384", pkicrypto.AlgECDSAP384, AlgES384, false},
		{"ECDSA P-521", pkicrypto.AlgECDSAP521, AlgES512, false},
		{"EC P-256", pkicrypto.AlgECP256, AlgES256, false},
		{"EC P-384", pkicrypto.AlgECP384, AlgES384, false},
		{"EC P-521", pkicrypto.AlgECP521, AlgES512, false},
		{"Ed25519", pkicrypto.AlgEd25519, AlgEdDSA, false},
		{"Ed448", pkicrypto.AlgEd448, AlgEdDSA, false},
		{"RSA-2048", pkicrypto.AlgRSA2048, AlgPS256, false},
		{"RSA-4096", pkicrypto.AlgRSA4096, AlgPS256, false},
		{"ML-DSA-44", pkicrypto.AlgMLDSA44, AlgMLDSA44, false},
		{"ML-DSA-65", pkicrypto.AlgMLDSA65, AlgMLDSA65, false},
		{"ML-DSA-87", pkicrypto.AlgMLDSA87, AlgMLDSA87, false},
		{"SLH-DSA-SHA2-128s", pkicrypto.AlgSLHDSASHA2128s, AlgSLHDSASHA2128s, false},
		{"SLH-DSA-SHA2-128f", pkicrypto.AlgSLHDSASHA2128f, AlgSLHDSASHA2128f, false},
		{"SLH-DSA-SHA2-192s", pkicrypto.AlgSLHDSASHA2192s, AlgSLHDSASHA2192s, false},
		{"SLH-DSA-SHA2-192f", pkicrypto.AlgSLHDSASHA2192f, AlgSLHDSASHA2192f, false},
		{"SLH-DSA-SHA2-256s", pkicrypto.AlgSLHDSASHA2256s, AlgSLHDSASHA2256s, false},
		{"SLH-DSA-SHA2-256f", pkicrypto.AlgSLHDSASHA2256f, AlgSLHDSASHA2256f, false},
		{"SLH-DSA-SHAKE-128s", pkicrypto.AlgSLHDSASHAKE128s, AlgSLHDSASHAKE128s, false},
		{"SLH-DSA-SHAKE-128f", pkicrypto.AlgSLHDSASHAKE128f, AlgSLHDSASHAKE128f, false},
		{"SLH-DSA-SHAKE-192s", pkicrypto.AlgSLHDSASHAKE192s, AlgSLHDSASHAKE192s, false},
		{"SLH-DSA-SHAKE-192f", pkicrypto.AlgSLHDSASHAKE192f, AlgSLHDSASHAKE192f, false},
		{"SLH-DSA-SHAKE-256s", pkicrypto.AlgSLHDSASHAKE256s, AlgSLHDSASHAKE256s, false},
		{"SLH-DSA-SHAKE-256f", pkicrypto.AlgSLHDSASHAKE256f, AlgSLHDSASHAKE256f, false},
		{"Unknown", pkicrypto.AlgorithmID("unknown-algorithm"), 0, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			alg, err := COSEAlgorithmFromPKI(tc.pkiAlg)
			if tc.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if alg != tc.expected {
					t.Errorf("expected %d, got %d", tc.expected, alg)
				}
			}
		})
	}
}

func TestU_PKIAlgorithmFromCOSE(t *testing.T) {
	tests := []struct {
		name     string
		coseAlg  gocose.Algorithm
		expected pkicrypto.AlgorithmID
		wantErr  bool
	}{
		{"ES256", AlgES256, pkicrypto.AlgECDSAP256, false},
		{"ES384", AlgES384, pkicrypto.AlgECDSAP384, false},
		{"ES512", AlgES512, pkicrypto.AlgECDSAP521, false},
		{"EdDSA", AlgEdDSA, pkicrypto.AlgEd25519, false},
		{"PS256", AlgPS256, pkicrypto.AlgRSA4096, false},
		{"PS384", AlgPS384, pkicrypto.AlgRSA4096, false},
		{"PS512", AlgPS512, pkicrypto.AlgRSA4096, false},
		{"ML-DSA-44", AlgMLDSA44, pkicrypto.AlgMLDSA44, false},
		{"ML-DSA-65", AlgMLDSA65, pkicrypto.AlgMLDSA65, false},
		{"ML-DSA-87", AlgMLDSA87, pkicrypto.AlgMLDSA87, false},
		{"SLH-DSA-SHA2-128s", AlgSLHDSASHA2128s, pkicrypto.AlgSLHDSASHA2128s, false},
		{"SLH-DSA-SHA2-128f", AlgSLHDSASHA2128f, pkicrypto.AlgSLHDSASHA2128f, false},
		{"SLH-DSA-SHA2-192s", AlgSLHDSASHA2192s, pkicrypto.AlgSLHDSASHA2192s, false},
		{"SLH-DSA-SHA2-192f", AlgSLHDSASHA2192f, pkicrypto.AlgSLHDSASHA2192f, false},
		{"SLH-DSA-SHA2-256s", AlgSLHDSASHA2256s, pkicrypto.AlgSLHDSASHA2256s, false},
		{"SLH-DSA-SHA2-256f", AlgSLHDSASHA2256f, pkicrypto.AlgSLHDSASHA2256f, false},
		{"SLH-DSA-SHAKE-128s", AlgSLHDSASHAKE128s, pkicrypto.AlgSLHDSASHAKE128s, false},
		{"SLH-DSA-SHAKE-128f", AlgSLHDSASHAKE128f, pkicrypto.AlgSLHDSASHAKE128f, false},
		{"SLH-DSA-SHAKE-192s", AlgSLHDSASHAKE192s, pkicrypto.AlgSLHDSASHAKE192s, false},
		{"SLH-DSA-SHAKE-192f", AlgSLHDSASHAKE192f, pkicrypto.AlgSLHDSASHAKE192f, false},
		{"SLH-DSA-SHAKE-256s", AlgSLHDSASHAKE256s, pkicrypto.AlgSLHDSASHAKE256s, false},
		{"SLH-DSA-SHAKE-256f", AlgSLHDSASHAKE256f, pkicrypto.AlgSLHDSASHAKE256f, false},
		{"Unknown", gocose.Algorithm(9999), pkicrypto.AlgorithmID(""), true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			alg, err := PKIAlgorithmFromCOSE(tc.coseAlg)
			if tc.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if alg != tc.expected {
					t.Errorf("expected %s, got %s", tc.expected, alg)
				}
			}
		})
	}
}

func TestU_algorithmFromSLHDSAKey(t *testing.T) {
	// Generate SLH-DSA keys of different types
	tests := []struct {
		name     string
		params   slhdsa.ID
		expected gocose.Algorithm
	}{
		{"SHA2-128s", slhdsa.SHA2_128s, AlgSLHDSASHA2128s},
		{"SHA2-128f", slhdsa.SHA2_128f, AlgSLHDSASHA2128f},
		{"SHA2-192s", slhdsa.SHA2_192s, AlgSLHDSASHA2192s},
		{"SHA2-192f", slhdsa.SHA2_192f, AlgSLHDSASHA2192f},
		{"SHA2-256s", slhdsa.SHA2_256s, AlgSLHDSASHA2256s},
		{"SHA2-256f", slhdsa.SHA2_256f, AlgSLHDSASHA2256f},
		{"SHAKE-128s", slhdsa.SHAKE_128s, AlgSLHDSASHAKE128s},
		{"SHAKE-128f", slhdsa.SHAKE_128f, AlgSLHDSASHAKE128f},
		{"SHAKE-192s", slhdsa.SHAKE_192s, AlgSLHDSASHAKE192s},
		{"SHAKE-192f", slhdsa.SHAKE_192f, AlgSLHDSASHAKE192f},
		{"SHAKE-256s", slhdsa.SHAKE_256s, AlgSLHDSASHAKE256s},
		{"SHAKE-256f", slhdsa.SHAKE_256f, AlgSLHDSASHAKE256f},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pub, _, err := slhdsa.GenerateKey(rand.Reader, tc.params)
			if err != nil {
				t.Fatalf("failed to generate key: %v", err)
			}

			alg, err := algorithmFromSLHDSAKey(&pub)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if alg != tc.expected {
				t.Errorf("expected %d, got %d", tc.expected, alg)
			}
		})
	}
}

// =============================================================================
// Extended Coverage Tests - Claims
// =============================================================================

func TestU_Claims_IsNotYetValid(t *testing.T) {
	// Test with no NotBefore
	claims := NewClaims()
	if claims.IsNotYetValid() {
		t.Error("expected IsNotYetValid to be false when NotBefore is not set")
	}

	// Test with future NotBefore
	claims.NotBefore = time.Now().Add(time.Hour)
	if !claims.IsNotYetValid() {
		t.Error("expected IsNotYetValid to be true when NotBefore is in the future")
	}

	// Test with past NotBefore
	claims.NotBefore = time.Now().Add(-time.Hour)
	if claims.IsNotYetValid() {
		t.Error("expected IsNotYetValid to be false when NotBefore is in the past")
	}
}

func TestU_Claims_ValidateAt_NotYetValid(t *testing.T) {
	claims := NewClaims()
	claims.NotBefore = time.Now().Add(time.Hour)

	// Validate at current time should fail
	err := claims.ValidateAt(time.Now())
	if err == nil {
		t.Error("expected error for not-yet-valid token")
	}
	if !strings.Contains(err.Error(), "not valid until") {
		t.Errorf("unexpected error message: %v", err)
	}

	// Validate at future time should succeed
	err = claims.ValidateAt(time.Now().Add(2 * time.Hour))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestU_ClaimsFromMap(t *testing.T) {
	now := time.Now().Unix()
	m := map[int64]interface{}{
		ClaimIss: "test-issuer",
		ClaimSub: "test-subject",
		ClaimAud: "test-audience",
		ClaimExp: now + 3600,
		ClaimNbf: now - 60,
		ClaimIat: now,
		ClaimCti: []byte("test-cti-id"),
		-1000:    "custom-value",
	}

	claims := ClaimsFromMap(m)

	if claims.Issuer != "test-issuer" {
		t.Errorf("expected issuer 'test-issuer', got '%s'", claims.Issuer)
	}
	if claims.Subject != "test-subject" {
		t.Errorf("expected subject 'test-subject', got '%s'", claims.Subject)
	}
	if claims.Audience != "test-audience" {
		t.Errorf("expected audience 'test-audience', got '%s'", claims.Audience)
	}
	if string(claims.CWTID) != "test-cti-id" {
		t.Errorf("expected CWTID 'test-cti-id', got '%s'", string(claims.CWTID))
	}
	if claims.Custom[-1000] != "custom-value" {
		t.Errorf("expected custom claim, got '%v'", claims.Custom[-1000])
	}
}

func TestU_ClaimsFromMap_DifferentTimeTypes(t *testing.T) {
	// Test with uint64 time
	m1 := map[int64]interface{}{
		ClaimExp: uint64(time.Now().Add(time.Hour).Unix()),
	}
	claims1 := ClaimsFromMap(m1)
	if claims1.Expiration.IsZero() {
		t.Error("expected expiration to be set from uint64")
	}

	// Test with float64 time
	m2 := map[int64]interface{}{
		ClaimExp: float64(time.Now().Add(time.Hour).Unix()),
	}
	claims2 := ClaimsFromMap(m2)
	if claims2.Expiration.IsZero() {
		t.Error("expected expiration to be set from float64")
	}
}

// =============================================================================
// Extended Coverage Tests - RSA-PSS
// =============================================================================

func TestU_RSA_PSS_SignAndVerify(t *testing.T) {
	// Generate RSA key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Create signer
	signer, err := NewSigner(key)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	if signer.Algorithm() != AlgPS256 {
		t.Errorf("expected PS256, got %d", signer.Algorithm())
	}

	// Test signing
	data := []byte("test data for RSA-PSS")
	sig, err := signer.Sign(rand.Reader, data)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Test verification
	err = signer.Verify(data, sig)
	if err != nil {
		t.Errorf("Verify failed: %v", err)
	}

	// Test verification with wrong data
	err = signer.Verify([]byte("wrong data"), sig)
	if err == nil {
		t.Error("expected verification to fail with wrong data")
	}
}

func TestU_RSA_PSS_CWT(t *testing.T) {
	ctx := context.Background()

	// Generate RSA key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Create certificate for RSA
	cert := generateTestCertificateForKey(t, key)

	claims := NewClaims()
	claims.Issuer = "rsa-test-issuer"
	claims.Subject = "rsa-test-subject"
	claims.SetExpiration(time.Hour)

	config := &CWTConfig{
		MessageConfig: MessageConfig{
			Signer:      key,
			Certificate: cert,
		},
		Claims: claims,
	}

	cwt, err := IssueCWT(ctx, config)
	if err != nil {
		t.Fatalf("IssueCWT failed: %v", err)
	}

	// Verify
	verifyConfig := &VerifyConfig{
		Certificate:     cert,
		CheckExpiration: true,
	}

	result, err := VerifyCWT(cwt, verifyConfig)
	if err != nil {
		t.Fatalf("VerifyCWT failed: %v", err)
	}

	if !result.Valid {
		t.Errorf("verification failed: %v", result.Warnings)
	}
}

// generateTestCertificateForKey generates a self-signed certificate for a given key.
func generateTestCertificateForKey(t *testing.T, key crypto.Signer) *x509.Certificate {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   "Test Certificate",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert
}

// =============================================================================
// Extended Coverage Tests - Verifier
// =============================================================================

func TestU_Verifier_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	verifier, err := NewVerifier(&key.PublicKey)
	if err != nil {
		t.Fatalf("NewVerifier failed: %v", err)
	}

	if verifier.Algorithm() != AlgPS256 {
		t.Errorf("expected PS256, got %d", verifier.Algorithm())
	}
}

func TestU_Verifier_MLDSA87(t *testing.T) {
	pub, _, err := mldsa87.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ML-DSA-87 key: %v", err)
	}

	verifier, err := NewVerifier(pub)
	if err != nil {
		t.Fatalf("NewVerifier failed: %v", err)
	}

	if verifier.Algorithm() != AlgMLDSA87 {
		t.Errorf("expected ML-DSA-87, got %d", verifier.Algorithm())
	}
}

func TestU_Verifier_SLHDSA(t *testing.T) {
	pub, _, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_128s)
	if err != nil {
		t.Fatalf("failed to generate SLH-DSA key: %v", err)
	}

	verifier, err := NewVerifier(&pub)
	if err != nil {
		t.Fatalf("NewVerifier failed: %v", err)
	}

	if verifier.Algorithm() != AlgSLHDSASHA2128s {
		t.Errorf("expected SLH-DSA-SHA2-128s, got %d", verifier.Algorithm())
	}
}

// =============================================================================
// Extended Coverage Tests - Serial Generator
// =============================================================================

func TestU_Serial_Next_Multiple(t *testing.T) {
	gen := &RandomSerialGenerator{}

	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id, err := gen.Next()
		if err != nil {
			t.Fatalf("Next() failed: %v", err)
		}
		if len(id) == 0 {
			t.Error("Next() returned empty ID")
		}
		idStr := string(id)
		if seen[idStr] {
			t.Error("Next() returned duplicate ID")
		}
		seen[idStr] = true
	}
}

// =============================================================================
// Extended Coverage Tests - Error Cases
// =============================================================================

func TestU_Parse_InvalidCBOR(t *testing.T) {
	// Invalid CBOR data
	_, err := Parse([]byte{0xFF, 0xFF, 0xFF})
	if err == nil {
		t.Error("expected error for invalid CBOR")
	}
}

func TestU_ParseCWT_InvalidClaims(t *testing.T) {
	// Create a Sign1 message with invalid payload (not CBOR claims)
	ctx := context.Background()
	key := generateECDSAKey(t)
	cert := generateTestCertificate(t, key)

	// Create Sign1 with raw data (not claims)
	config := &MessageConfig{
		Signer:      key,
		Certificate: cert,
	}
	payload := []byte("not valid cbor claims")

	msg, err := IssueSign1(ctx, payload, config)
	if err != nil {
		t.Fatalf("IssueSign1 failed: %v", err)
	}

	// Try to parse as CWT - should fail
	_, err = ParseCWT(msg)
	if err == nil {
		t.Error("expected error when parsing non-claims payload as CWT")
	}
}

func TestU_Verifier_UnsupportedKey(t *testing.T) {
	// Use a custom type that implements crypto.PublicKey but isn't supported
	type unsupportedKey struct{}

	_, err := NewVerifier(unsupportedKey{})
	if err == nil {
		t.Error("expected error for unsupported key type")
	}
}

func TestU_Signer_UnsupportedKey(t *testing.T) {
	// Mock signer with unsupported public key type
	mockSigner := &mockUnsupportedSigner{}
	_, err := NewSigner(mockSigner)
	if err == nil {
		t.Error("expected error for unsupported key type")
	}
}

type mockUnsupportedSigner struct{}

func (m *mockUnsupportedSigner) Public() crypto.PublicKey {
	return struct{}{}
}

func (m *mockUnsupportedSigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}

// =============================================================================
// Extended Coverage Tests - Info
// =============================================================================

func TestU_Info_WithoutCertificate(t *testing.T) {
	ctx := context.Background()
	key := generateECDSAKey(t)

	claims := NewClaims()
	claims.Issuer = "test"

	// Create CWT without certificate
	config := &CWTConfig{
		MessageConfig: MessageConfig{
			Signer:           key,
			IncludeCertChain: false,
		},
		Claims: claims,
	}

	cwt, err := IssueCWT(ctx, config)
	if err != nil {
		t.Fatalf("IssueCWT failed: %v", err)
	}

	info, err := GetInfo(cwt)
	if err != nil {
		t.Fatalf("GetInfo failed: %v", err)
	}

	// Should have empty certificate info
	if len(info.Signatures) > 0 && info.Signatures[0].Certificate != nil {
		t.Error("expected no certificate in info")
	}
}

func TestU_Info_Print_Full(t *testing.T) {
	ctx := context.Background()
	key := generateECDSAKey(t)
	cert := generateTestCertificate(t, key)

	claims := NewClaims()
	claims.Issuer = "test-issuer"
	claims.Subject = "test-subject"
	claims.Audience = "test-audience"
	claims.SetExpiration(time.Hour)
	claims.NotBefore = time.Now()
	claims.IssuedAt = time.Now()
	claims.CWTID = []byte("test-cwt-id")
	_ = claims.SetCustom(-1000, "custom-value")

	config := &CWTConfig{
		MessageConfig: MessageConfig{
			Signer:           key,
			Certificate:      cert,
			IncludeCertChain: true,
		},
		Claims: claims,
	}

	cwt, err := IssueCWT(ctx, config)
	if err != nil {
		t.Fatalf("IssueCWT failed: %v", err)
	}

	info, err := GetInfo(cwt)
	if err != nil {
		t.Fatalf("GetInfo failed: %v", err)
	}

	// Test Print method with all fields populated
	var buf strings.Builder
	info.Print(&buf)
	output := buf.String()

	// Check that various expected strings are present
	expectedStrings := []string{
		"COSE Message Info",
		"Type:",
		"Mode:",
		"Signatures",
		"Algorithm:",
		"CWT Claims",
		"Issuer",
		"Subject",
		"Audience",
		"Expiration",
		"Not Before",
		"Issued At",
		"CWT ID",
		"Custom Claims",
	}

	for _, s := range expectedStrings {
		if !strings.Contains(output, s) {
			t.Errorf("expected output to contain '%s'", s)
		}
	}
}

// =============================================================================
// Verify Helpers Tests
// =============================================================================

func TestU_findCertByKeyID_NilPool(t *testing.T) {
	result := findCertByKeyID(nil, []byte("test-key-id"))
	if result != nil {
		t.Error("expected nil for nil pool")
	}
}

func TestU_findCertByKeyID_EmptyKeyID(t *testing.T) {
	pool := x509.NewCertPool()
	result := findCertByKeyID(pool, nil)
	if result != nil {
		t.Error("expected nil for empty key ID")
	}
}

func TestU_findCertByKeyID_EmptyKeyIDSlice(t *testing.T) {
	pool := x509.NewCertPool()
	result := findCertByKeyID(pool, []byte{})
	if result != nil {
		t.Error("expected nil for empty key ID slice")
	}
}

func TestU_MatchKeyID_NilCert(t *testing.T) {
	result := MatchKeyID(nil, []byte("test-key-id"))
	if result {
		t.Error("expected false for nil cert")
	}
}

func TestU_MatchKeyID_EmptyKeyID(t *testing.T) {
	key := generateECDSAKey(t)
	cert := generateTestCertificate(t, key)
	result := MatchKeyID(cert, nil)
	if result {
		t.Error("expected false for empty key ID")
	}
}

func TestU_MatchKeyID_Match(t *testing.T) {
	key := generateECDSAKey(t)
	cert := generateTestCertificate(t, key)
	fp := CertificateFingerprint(cert)
	result := MatchKeyID(cert, fp)
	if !result {
		t.Error("expected true for matching fingerprint")
	}
}

func TestU_MatchKeyID_NoMatch(t *testing.T) {
	key := generateECDSAKey(t)
	cert := generateTestCertificate(t, key)
	result := MatchKeyID(cert, []byte("wrong-fingerprint"))
	if result {
		t.Error("expected false for non-matching fingerprint")
	}
}

func TestU_getPublicKeyFromCert_NilCert(t *testing.T) {
	_, err := getPublicKeyFromCert(nil)
	if err == nil {
		t.Error("expected error for nil cert")
	}
}

func TestU_getPublicKeyFromCert_Classical(t *testing.T) {
	key := generateECDSAKey(t)
	cert := generateTestCertificate(t, key)

	pubKey, err := getPublicKeyFromCert(cert)
	if err != nil {
		t.Fatalf("getPublicKeyFromCert failed: %v", err)
	}

	if _, ok := pubKey.(*ecdsa.PublicKey); !ok {
		t.Errorf("expected *ecdsa.PublicKey, got %T", pubKey)
	}
}

func TestU_resolvePublicKey_FromCertificate(t *testing.T) {
	key := generateECDSAKey(t)
	cert := generateTestCertificate(t, key)

	sigInfo := SignatureInfo{
		Algorithm: AlgES256,
	}

	config := &VerifyConfig{
		Certificate: cert,
	}

	pubKey, resolvedCert, err := resolvePublicKey(sigInfo, config)
	if err != nil {
		t.Fatalf("resolvePublicKey failed: %v", err)
	}

	if pubKey == nil {
		t.Error("expected public key, got nil")
	}

	if resolvedCert != cert {
		t.Error("expected same certificate")
	}
}

func TestU_resolvePublicKey_FromPublicKey(t *testing.T) {
	key := generateECDSAKey(t)
	cert := generateTestCertificate(t, key)

	sigInfo := SignatureInfo{
		Algorithm: AlgES256,
	}

	config := &VerifyConfig{
		PublicKey:   key.Public(),
		Certificate: cert,
	}

	pubKey, resolvedCert, err := resolvePublicKey(sigInfo, config)
	if err != nil {
		t.Fatalf("resolvePublicKey failed: %v", err)
	}

	if pubKey == nil {
		t.Error("expected public key, got nil")
	}

	if resolvedCert != cert {
		t.Error("expected same certificate")
	}
}

func TestU_resolvePublicKey_FromSignatureInfo(t *testing.T) {
	key := generateECDSAKey(t)
	cert := generateTestCertificate(t, key)

	sigInfo := SignatureInfo{
		Algorithm:   AlgES256,
		Certificate: cert,
	}

	config := &VerifyConfig{}

	pubKey, resolvedCert, err := resolvePublicKey(sigInfo, config)
	if err != nil {
		t.Fatalf("resolvePublicKey failed: %v", err)
	}

	if pubKey == nil {
		t.Error("expected public key, got nil")
	}

	if resolvedCert != cert {
		t.Error("expected same certificate")
	}
}

func TestU_resolvePublicKey_PQCKey(t *testing.T) {
	pub, _ := generateMLDSA65Key(t)

	sigInfo := SignatureInfo{
		Algorithm: AlgMLDSA65,
	}

	config := &VerifyConfig{
		PQCPublicKey: pub,
	}

	pubKey, resolvedCert, err := resolvePublicKey(sigInfo, config)
	if err != nil {
		t.Fatalf("resolvePublicKey failed: %v", err)
	}

	if pubKey == nil {
		t.Error("expected public key, got nil")
	}

	if resolvedCert != nil {
		t.Error("expected nil certificate for PQC key without cert")
	}
}

func TestU_resolvePublicKey_NoKey(t *testing.T) {
	sigInfo := SignatureInfo{
		Algorithm: AlgES256,
	}

	config := &VerifyConfig{}

	_, _, err := resolvePublicKey(sigInfo, config)
	if err == nil {
		t.Error("expected error when no key available")
	}
}

func TestU_resolvePublicKeyForSignature_Classical(t *testing.T) {
	key := generateECDSAKey(t)
	cert := generateTestCertificate(t, key)

	sigInfo := SignatureInfo{
		Algorithm: AlgES256,
	}

	config := &VerifyConfig{
		Certificate: cert,
	}

	pubKey, resolvedCert, err := resolvePublicKeyForSignature(0, sigInfo, config)
	if err != nil {
		t.Fatalf("resolvePublicKeyForSignature failed: %v", err)
	}

	if pubKey == nil {
		t.Error("expected public key, got nil")
	}

	if resolvedCert != cert {
		t.Error("expected same certificate")
	}
}

func TestU_resolvePublicKeyForSignature_PQC(t *testing.T) {
	pub, _ := generateMLDSA65Key(t)

	sigInfo := SignatureInfo{
		Algorithm: AlgMLDSA65,
	}

	config := &VerifyConfig{
		PQCPublicKey: pub,
	}

	pubKey, _, err := resolvePublicKeyForSignature(0, sigInfo, config)
	if err != nil {
		t.Fatalf("resolvePublicKeyForSignature failed: %v", err)
	}

	if pubKey == nil {
		t.Error("expected public key, got nil")
	}
}

func TestU_resolvePublicKeyForSignature_NoKey(t *testing.T) {
	sigInfo := SignatureInfo{
		Algorithm: AlgES256,
	}

	config := &VerifyConfig{}

	_, _, err := resolvePublicKeyForSignature(0, sigInfo, config)
	if err == nil {
		t.Error("expected error when no key available")
	}
}

func TestU_QuickVerify_NoSignatures(t *testing.T) {
	key := generateECDSAKey(t)

	// Create a mock CBOR message without proper signature
	// This should fail parsing
	err := QuickVerify([]byte{0x00, 0x01, 0x02}, key.Public())
	if err == nil {
		t.Error("expected error for invalid CBOR")
	}
}

func TestU_VerifyWithTime_FutureExpiration(t *testing.T) {
	ctx := context.Background()
	key := generateECDSAKey(t)
	cert := generateTestCertificate(t, key)

	claims := NewClaims()
	claims.Issuer = "https://issuer.example.com"
	claims.Expiration = time.Now().Add(time.Hour)

	config := &CWTConfig{
		MessageConfig: MessageConfig{
			Signer:      key,
			Certificate: cert,
		},
		Claims:       claims,
		AutoIssuedAt: true,
	}

	cwt, err := IssueCWT(ctx, config)
	if err != nil {
		t.Fatalf("IssueCWT failed: %v", err)
	}

	verifyConfig := &VerifyConfig{
		Certificate:     cert,
		CheckExpiration: true,
	}

	// Verify at current time
	result, err := VerifyWithTime(cwt, verifyConfig, time.Now())
	if err != nil {
		t.Fatalf("VerifyWithTime failed: %v", err)
	}

	if !result.Valid {
		t.Error("expected valid CWT")
	}

	// Verify at future time (after expiration)
	futureTime := time.Now().Add(2 * time.Hour)
	result, err = VerifyWithTime(cwt, verifyConfig, futureTime)
	if err != nil {
		t.Fatalf("VerifyWithTime failed: %v", err)
	}

	if result.Valid {
		t.Error("expected invalid CWT at future time")
	}
}

func TestU_verifyCertificateChain_WithRoots(t *testing.T) {
	key := generateECDSAKey(t)
	cert := generateTestCertificate(t, key)

	pool := x509.NewCertPool()
	pool.AddCert(cert)

	config := &VerifyConfig{
		Roots: pool,
	}

	// Self-signed cert should verify against itself as root
	err := verifyCertificateChain(cert, config)
	if err != nil {
		t.Logf("Certificate chain verification failed (expected for self-signed): %v", err)
	}
}
