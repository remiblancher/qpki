package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestU_Crypto_NewSigningContext_ECDSA(t *testing.T) {
	signer, err := GenerateSoftwareSigner(AlgECDSAP256)
	if err != nil {
		t.Fatalf("Failed to generate signer: %v", err)
	}

	ctx := NewSigningContext(signer)
	if ctx == nil {
		t.Fatal("Expected non-nil context")
	}

	if ctx.Algorithm() != AlgECDSAP256 {
		t.Errorf("Expected algorithm %s, got %s", AlgECDSAP256, ctx.Algorithm())
	}

	if !ctx.SupportsOperation(OpSign) {
		t.Error("ECDSA context should support signing")
	}

	if !ctx.SupportsOperation(OpVerify) {
		t.Error("ECDSA context should support verification")
	}

	if ctx.SupportsOperation(OpEncapsulate) {
		t.Error("ECDSA context should not support encapsulation")
	}
}

func TestU_Crypto_NewSigningContext_Ed25519(t *testing.T) {
	signer, err := GenerateSoftwareSigner(AlgEd25519)
	if err != nil {
		t.Fatalf("Failed to generate signer: %v", err)
	}

	ctx := NewSigningContext(signer)
	if ctx == nil {
		t.Fatal("Expected non-nil context")
	}

	if ctx.Algorithm() != AlgEd25519 {
		t.Errorf("Expected algorithm %s, got %s", AlgEd25519, ctx.Algorithm())
	}
}

func TestU_Crypto_NewSigningContext_MLDSA(t *testing.T) {
	signer, err := GenerateSoftwareSigner(AlgMLDSA44)
	if err != nil {
		t.Fatalf("Failed to generate signer: %v", err)
	}

	ctx := NewSigningContext(signer)
	if ctx == nil {
		t.Fatal("Expected non-nil context")
	}

	if ctx.Algorithm() != AlgMLDSA44 {
		t.Errorf("Expected algorithm %s, got %s", AlgMLDSA44, ctx.Algorithm())
	}

	if !ctx.SupportsOperation(OpSign) {
		t.Error("ML-DSA context should support signing")
	}
}

func TestU_Crypto_NewSigningContext_Nil(t *testing.T) {
	ctx := NewSigningContext(nil)
	if ctx != nil {
		t.Error("Expected nil context for nil signer")
	}
}

func TestU_Crypto_SigningContext_SignAndVerify_ECDSA(t *testing.T) {
	signer, err := GenerateSoftwareSigner(AlgECDSAP256)
	if err != nil {
		t.Fatalf("Failed to generate signer: %v", err)
	}

	ctx := NewSigningContext(signer)
	message := []byte("test message")

	// ECDSA expects pre-hashed data
	hash := sha256.Sum256(message)
	sig, err := ctx.Sign(rand.Reader, hash[:])
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if len(sig) == 0 {
		t.Error("Expected non-empty signature")
	}

	// Verify
	if err := ctx.Verify(hash[:], sig); err != nil {
		t.Errorf("Verify failed: %v", err)
	}
}

func TestU_Crypto_SigningContext_SignAndVerify_MLDSA(t *testing.T) {
	signer, err := GenerateSoftwareSigner(AlgMLDSA44)
	if err != nil {
		t.Fatalf("Failed to generate signer: %v", err)
	}

	ctx := NewSigningContext(signer)
	message := []byte("test message for ML-DSA")

	// ML-DSA signs the full message (pure mode)
	sig, err := ctx.Sign(rand.Reader, message)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if len(sig) == 0 {
		t.Error("Expected non-empty signature")
	}

	// Verify
	if err := ctx.Verify(message, sig); err != nil {
		t.Errorf("Verify failed: %v", err)
	}
}

func TestU_Crypto_SigningContext_InvalidSignature(t *testing.T) {
	signer, err := GenerateSoftwareSigner(AlgECDSAP256)
	if err != nil {
		t.Fatalf("Failed to generate signer: %v", err)
	}

	ctx := NewSigningContext(signer)
	message := []byte("test message")
	hash := sha256.Sum256(message)

	// Invalid signature
	invalidSig := []byte("invalid signature")
	if err := ctx.Verify(hash[:], invalidSig); err == nil {
		t.Error("Expected error for invalid signature")
	}
}

func TestU_Crypto_NewVerificationContext(t *testing.T) {
	// Generate a key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	ctx := NewVerificationContext(AlgECDSAP256, &privateKey.PublicKey)
	if ctx == nil {
		t.Fatal("Expected non-nil context")
	}

	if ctx.Algorithm() != AlgECDSAP256 {
		t.Errorf("Expected algorithm %s, got %s", AlgECDSAP256, ctx.Algorithm())
	}

	// Verification context should not support signing
	if ctx.SupportsOperation(OpSign) {
		t.Error("Verification context should not support signing")
	}

	if !ctx.SupportsOperation(OpVerify) {
		t.Error("Verification context should support verification")
	}

	// Sign should fail
	_, err = ctx.Sign(rand.Reader, []byte("test"))
	if err == nil {
		t.Error("Expected error when signing with verification context")
	}
}

func TestU_Crypto_VerificationContext_Verify(t *testing.T) {
	// Generate a signer
	signer, err := GenerateSoftwareSigner(AlgECDSAP256)
	if err != nil {
		t.Fatalf("Failed to generate signer: %v", err)
	}

	// Create signature
	message := []byte("test message")
	hash := sha256.Sum256(message)
	sig, err := signer.Sign(rand.Reader, hash[:], nil)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Create verification context from public key
	ctx := NewVerificationContext(AlgECDSAP256, signer.Public())

	// Verify
	if err := ctx.Verify(hash[:], sig); err != nil {
		t.Errorf("Verify failed: %v", err)
	}
}

func TestAlgorithmFromPublicKey_ECDSA(t *testing.T) {
	tests := []struct {
		curve elliptic.Curve
		want  AlgorithmID
	}{
		{elliptic.P256(), AlgECDSAP256},
		{elliptic.P384(), AlgECDSAP384},
		{elliptic.P521(), AlgECDSAP521},
	}

	for _, tt := range tests {
		privateKey, err := ecdsa.GenerateKey(tt.curve, rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}

		got := AlgorithmFromPublicKey(&privateKey.PublicKey)
		if got != tt.want {
			t.Errorf("AlgorithmFromPublicKey(%s) = %s, want %s", tt.curve.Params().Name, got, tt.want)
		}
	}
}

func TestAlgorithmFromPublicKey_Ed25519(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	got := AlgorithmFromPublicKey(pub)
	if got != AlgEd25519 {
		t.Errorf("AlgorithmFromPublicKey(Ed25519) = %s, want %s", got, AlgEd25519)
	}
}

func TestAlgorithmFromPublicKey_RSA(t *testing.T) {
	tests := []struct {
		bits int
		want AlgorithmID
	}{
		{2048, AlgRSA2048},
		{4096, AlgRSA4096},
	}

	for _, tt := range tests {
		privateKey, err := rsa.GenerateKey(rand.Reader, tt.bits)
		if err != nil {
			t.Fatalf("Failed to generate %d-bit key: %v", tt.bits, err)
		}

		got := AlgorithmFromPublicKey(&privateKey.PublicKey)
		if got != tt.want {
			t.Errorf("AlgorithmFromPublicKey(RSA-%d) = %s, want %s", tt.bits, got, tt.want)
		}
	}
}

func TestAlgorithmFromPublicKey_MLDSA(t *testing.T) {
	tests := []AlgorithmID{
		AlgMLDSA44,
		AlgMLDSA65,
		AlgMLDSA87,
	}

	for _, alg := range tests {
		signer, err := GenerateSoftwareSigner(alg)
		if err != nil {
			t.Fatalf("Failed to generate %s signer: %v", alg, err)
		}

		got := AlgorithmFromPublicKey(signer.Public())
		if got != alg {
			t.Errorf("AlgorithmFromPublicKey(%s) = %s, want %s", alg, got, alg)
		}
	}
}

func TestAlgorithmFromPublicKey_Unknown(t *testing.T) {
	got := AlgorithmFromPublicKey("not a key")
	if got != AlgUnknown {
		t.Errorf("AlgorithmFromPublicKey(string) = %s, want %s", got, AlgUnknown)
	}
}

func TestU_Crypto_HybridSigningContext(t *testing.T) {
	// Generate hybrid signer
	classical, err := GenerateSoftwareSigner(AlgECDSAP256)
	if err != nil {
		t.Fatalf("Failed to generate classical signer: %v", err)
	}

	pqc, err := GenerateSoftwareSigner(AlgMLDSA44)
	if err != nil {
		t.Fatalf("Failed to generate PQC signer: %v", err)
	}

	hybrid, err := NewHybridSigner(classical, pqc)
	if err != nil {
		t.Fatalf("Failed to create hybrid signer: %v", err)
	}

	ctx := NewSigningContext(hybrid)
	if ctx == nil {
		t.Fatal("Expected non-nil context")
	}

	// Check it's a HybridContext
	hctx, ok := ctx.(HybridContext)
	if !ok {
		t.Fatal("Expected HybridContext for hybrid signer")
	}

	if hctx.ClassicalContext() == nil {
		t.Error("Classical context should not be nil")
	}

	if hctx.PQCContext() == nil {
		t.Error("PQC context should not be nil")
	}

	// Test SignBoth - SignHybrid receives the same data for both signers
	// For ECDSA, this should be the hash; for ML-DSA, the full message
	// In practice, SignHybrid passes the same input to both, so we pass the hash
	// since that's what ECDSA expects
	message := []byte("test message for hybrid")

	classicalSig, pqcSig, err := hctx.SignBoth(rand.Reader, message)
	if err != nil {
		t.Fatalf("SignBoth failed: %v", err)
	}

	if len(classicalSig) == 0 {
		t.Error("Expected non-empty classical signature")
	}

	if len(pqcSig) == 0 {
		t.Error("Expected non-empty PQC signature")
	}

	// Test VerifyBoth - must use same data as SignBoth
	if err := hctx.VerifyBoth(message, classicalSig, pqcSig); err != nil {
		t.Errorf("VerifyBoth failed: %v", err)
	}
}

func TestU_Crypto_HybridSigningContext_DefaultSign(t *testing.T) {
	classical, _ := GenerateSoftwareSigner(AlgECDSAP256)
	pqc, _ := GenerateSoftwareSigner(AlgMLDSA44)
	hybrid, _ := NewHybridSigner(classical, pqc)

	ctx := NewSigningContext(hybrid)

	// Default Sign should use classical (Catalyst mode)
	message := []byte("test message")
	hash := sha256.Sum256(message)

	sig, err := ctx.Sign(rand.Reader, hash[:])
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Verify with classical context
	hctx := ctx.(HybridContext)
	if err := hctx.ClassicalContext().Verify(hash[:], sig); err != nil {
		t.Errorf("Classical verification failed: %v", err)
	}
}

func TestU_Crypto_PublicKey(t *testing.T) {
	signer, _ := GenerateSoftwareSigner(AlgECDSAP256)
	ctx := NewSigningContext(signer)

	pub := ctx.PublicKey()
	if pub == nil {
		t.Error("Expected non-nil public key")
	}

	if _, ok := pub.(*ecdsa.PublicKey); !ok {
		t.Error("Expected ECDSA public key")
	}
}

// =============================================================================
// KEM Context Tests
// =============================================================================

func TestU_Crypto_NewKEMContext(t *testing.T) {
	tests := []AlgorithmID{
		AlgMLKEM512,
		AlgMLKEM768,
		AlgMLKEM1024,
	}

	for _, alg := range tests {
		t.Run(alg.String(), func(t *testing.T) {
			kp, err := GenerateKEMKeyPair(alg)
			if err != nil {
				t.Fatalf("Failed to generate KEM key pair: %v", err)
			}

			ctx, err := NewKEMContext(kp)
			if err != nil {
				t.Fatalf("NewKEMContext failed: %v", err)
			}

			if ctx.Algorithm() != alg {
				t.Errorf("Algorithm mismatch: got %s, want %s", ctx.Algorithm(), alg)
			}

			if !ctx.SupportsOperation(OpEncapsulate) {
				t.Error("KEM context should support encapsulation")
			}

			if !ctx.SupportsOperation(OpDecapsulate) {
				t.Error("KEM context should support decapsulation")
			}

			if ctx.SupportsOperation(OpSign) {
				t.Error("KEM context should not support signing")
			}
		})
	}
}

func TestU_Crypto_NewKEMContext_Nil(t *testing.T) {
	ctx, err := NewKEMContext(nil)
	if err == nil {
		t.Error("Expected error for nil key pair")
	}
	if ctx != nil {
		t.Error("Expected nil context for nil key pair")
	}
}

func TestU_Crypto_NewKEMContext_NonKEMAlgorithm(t *testing.T) {
	// Create a key pair with a non-KEM algorithm
	kp := &KEMKeyPair{
		Algorithm: AlgECDSAP256, // Not a KEM algorithm
	}

	ctx, err := NewKEMContext(kp)
	if err == nil {
		t.Error("Expected error for non-KEM algorithm")
	}
	if ctx != nil {
		t.Error("Expected nil context for non-KEM algorithm")
	}
}

func TestU_Crypto_KEMContext_EncapsulateDecapsulate(t *testing.T) {
	tests := []AlgorithmID{
		AlgMLKEM512,
		AlgMLKEM768,
		AlgMLKEM1024,
	}

	for _, alg := range tests {
		t.Run(alg.String(), func(t *testing.T) {
			kp, err := GenerateKEMKeyPair(alg)
			if err != nil {
				t.Fatalf("Failed to generate KEM key pair: %v", err)
			}

			ctx, err := NewKEMContext(kp)
			if err != nil {
				t.Fatalf("NewKEMContext failed: %v", err)
			}

			// Encapsulate
			ct, ss1, err := ctx.Encapsulate()
			if err != nil {
				t.Fatalf("Encapsulate failed: %v", err)
			}

			if len(ct) == 0 {
				t.Error("Expected non-empty ciphertext")
			}

			if len(ss1) == 0 {
				t.Error("Expected non-empty shared secret")
			}

			// Decapsulate
			ss2, err := ctx.Decapsulate(ct)
			if err != nil {
				t.Fatalf("Decapsulate failed: %v", err)
			}

			// Shared secrets must match
			if len(ss1) != len(ss2) {
				t.Errorf("Shared secret length mismatch: %d vs %d", len(ss1), len(ss2))
			}

			for i := range ss1 {
				if ss1[i] != ss2[i] {
					t.Error("Shared secrets do not match")
					break
				}
			}
		})
	}
}

func TestU_Crypto_NewKEMContextForEncapsulation(t *testing.T) {
	kp, err := GenerateKEMKeyPair(AlgMLKEM768)
	if err != nil {
		t.Fatalf("Failed to generate KEM key pair: %v", err)
	}

	// Create encapsulation-only context
	ctx, err := NewKEMContextForEncapsulation(AlgMLKEM768, kp.PublicKey)
	if err != nil {
		t.Fatalf("NewKEMContextForEncapsulation failed: %v", err)
	}

	if !ctx.SupportsOperation(OpEncapsulate) {
		t.Error("Should support encapsulation")
	}

	if ctx.SupportsOperation(OpDecapsulate) {
		t.Error("Should not support decapsulation without private key")
	}

	// Encapsulation should work
	ct, ss, err := ctx.Encapsulate()
	if err != nil {
		t.Fatalf("Encapsulate failed: %v", err)
	}

	if len(ct) == 0 || len(ss) == 0 {
		t.Error("Expected non-empty ciphertext and shared secret")
	}

	// Decapsulation should fail
	_, err = ctx.Decapsulate(ct)
	if err == nil {
		t.Error("Expected error when decapsulating without private key")
	}
}

func TestU_Crypto_KEMContext_SignAndVerifyFail(t *testing.T) {
	kp, err := GenerateKEMKeyPair(AlgMLKEM512)
	if err != nil {
		t.Fatalf("Failed to generate KEM key pair: %v", err)
	}

	ctx, err := NewKEMContext(kp)
	if err != nil {
		t.Fatalf("NewKEMContext failed: %v", err)
	}

	// Sign should fail
	_, err = ctx.Sign(rand.Reader, []byte("test"))
	if err == nil {
		t.Error("Expected error when signing with KEM context")
	}

	// Verify should fail
	err = ctx.Verify([]byte("test"), []byte("sig"))
	if err == nil {
		t.Error("Expected error when verifying with KEM context")
	}
}

func TestU_Crypto_KEMContext_PublicKey(t *testing.T) {
	tests := []AlgorithmID{AlgMLKEM512, AlgMLKEM768, AlgMLKEM1024}

	for _, alg := range tests {
		t.Run(alg.String(), func(t *testing.T) {
			kp, err := GenerateKEMKeyPair(alg)
			if err != nil {
				t.Fatalf("Failed to generate KEM key pair: %v", err)
			}

			ctx, err := NewKEMContext(kp)
			if err != nil {
				t.Fatalf("NewKEMContext failed: %v", err)
			}

			pub := ctx.PublicKey()
			if pub == nil {
				t.Error("PublicKey() returned nil")
			}

			// Verify the returned public key matches the original
			if pub != kp.PublicKey {
				t.Error("PublicKey() did not return the expected public key")
			}
		})
	}
}

// =============================================================================
// NewContextFromCertificate Tests
// =============================================================================

func TestU_Crypto_NewContextFromCertificate_ECDSA(t *testing.T) {
	// Generate ECDSA key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create a test certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test ECDSA Cert",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Create context from certificate
	ctx, err := NewContextFromCertificate(cert)
	if err != nil {
		t.Fatalf("NewContextFromCertificate failed: %v", err)
	}

	if ctx.Algorithm() != AlgECDSAP256 {
		t.Errorf("Expected algorithm %s, got %s", AlgECDSAP256, ctx.Algorithm())
	}

	// Verify supports verification
	if !ctx.SupportsOperation(OpVerify) {
		t.Error("Context should support verification")
	}
}

func TestU_Crypto_NewContextFromCertificate_Ed25519(t *testing.T) {
	// Generate Ed25519 key
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Ed25519 Cert",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	ctx, err := NewContextFromCertificate(cert)
	if err != nil {
		t.Fatalf("NewContextFromCertificate failed: %v", err)
	}

	if ctx.Algorithm() != AlgEd25519 {
		t.Errorf("Expected algorithm %s, got %s", AlgEd25519, ctx.Algorithm())
	}
}

func TestU_Crypto_NewContextFromCertificate_RSA(t *testing.T) {
	// Generate RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test RSA Cert",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	ctx, err := NewContextFromCertificate(cert)
	if err != nil {
		t.Fatalf("NewContextFromCertificate failed: %v", err)
	}

	if ctx.Algorithm() != AlgRSA2048 {
		t.Errorf("Expected algorithm %s, got %s", AlgRSA2048, ctx.Algorithm())
	}
}

func TestU_Crypto_NewContextFromCertificate_Nil(t *testing.T) {
	ctx, err := NewContextFromCertificate(nil)
	if err == nil {
		t.Error("Expected error for nil certificate")
	}
	if ctx != nil {
		t.Error("Expected nil context for nil certificate")
	}
}

// =============================================================================
// SLH-DSA Algorithm Detection Tests
// =============================================================================

func TestAlgorithmFromPublicKey_SLHDSA(t *testing.T) {
	// Test only fast variants to keep tests quick
	tests := []AlgorithmID{
		AlgSLHDSA128f,
		AlgSLHDSA192f,
		AlgSLHDSA256f,
	}

	for _, alg := range tests {
		t.Run(alg.String(), func(t *testing.T) {
			signer, err := GenerateSoftwareSigner(alg)
			if err != nil {
				t.Fatalf("Failed to generate %s signer: %v", alg, err)
			}

			got := AlgorithmFromPublicKey(signer.Public())
			if got != alg {
				t.Errorf("AlgorithmFromPublicKey(%s) = %s, want %s", alg, got, alg)
			}
		})
	}
}

func TestAlgorithmFromPublicKey_MLKEM(t *testing.T) {
	tests := []AlgorithmID{
		AlgMLKEM512,
		AlgMLKEM768,
		AlgMLKEM1024,
	}

	for _, alg := range tests {
		t.Run(alg.String(), func(t *testing.T) {
			kp, err := GenerateKEMKeyPair(alg)
			if err != nil {
				t.Fatalf("Failed to generate %s key pair: %v", alg, err)
			}

			got := AlgorithmFromPublicKey(kp.PublicKey)
			if got != alg {
				t.Errorf("AlgorithmFromPublicKey(%s) = %s, want %s", alg, got, alg)
			}
		})
	}
}

// =============================================================================
// Hybrid Context Methods Tests
// =============================================================================

func TestU_Crypto_HybridSigningContext_Algorithm(t *testing.T) {
	classical, _ := GenerateSoftwareSigner(AlgECDSAP256)
	pqc, _ := GenerateSoftwareSigner(AlgMLDSA44)
	hybrid, _ := NewHybridSigner(classical, pqc)

	ctx := NewSigningContext(hybrid)
	hctx := ctx.(HybridContext)

	// Algorithm should return the hybrid algorithm ID
	alg := hctx.Algorithm()
	if alg != hybrid.Algorithm() {
		t.Errorf("Algorithm mismatch: got %s, want %s", alg, hybrid.Algorithm())
	}
}

func TestU_Crypto_HybridSigningContext_SupportsOperation(t *testing.T) {
	classical, _ := GenerateSoftwareSigner(AlgECDSAP256)
	pqc, _ := GenerateSoftwareSigner(AlgMLDSA44)
	hybrid, _ := NewHybridSigner(classical, pqc)

	ctx := NewSigningContext(hybrid)

	if !ctx.SupportsOperation(OpSign) {
		t.Error("Hybrid context should support signing")
	}

	if !ctx.SupportsOperation(OpVerify) {
		t.Error("Hybrid context should support verification")
	}

	if ctx.SupportsOperation(OpEncapsulate) {
		t.Error("Hybrid context should not support encapsulation")
	}

	if ctx.SupportsOperation(OpDecapsulate) {
		t.Error("Hybrid context should not support decapsulation")
	}
}

func TestU_Crypto_HybridSigningContext_Verify(t *testing.T) {
	classical, _ := GenerateSoftwareSigner(AlgECDSAP256)
	pqc, _ := GenerateSoftwareSigner(AlgMLDSA44)
	hybrid, _ := NewHybridSigner(classical, pqc)

	ctx := NewSigningContext(hybrid)

	// Sign a message (uses classical by default in Catalyst mode)
	message := []byte("test message")
	hash := sha256.Sum256(message)

	sig, err := ctx.Sign(rand.Reader, hash[:])
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Verify the signature
	if err := ctx.Verify(hash[:], sig); err != nil {
		t.Errorf("Verify failed: %v", err)
	}

	// Verify with invalid signature should fail
	if err := ctx.Verify(hash[:], []byte("invalid")); err == nil {
		t.Error("Expected error for invalid signature")
	}
}

func TestU_Crypto_HybridSigningContext_PublicKey(t *testing.T) {
	classical, _ := GenerateSoftwareSigner(AlgECDSAP256)
	pqc, _ := GenerateSoftwareSigner(AlgMLDSA44)
	hybrid, _ := NewHybridSigner(classical, pqc)

	ctx := NewSigningContext(hybrid)

	pub := ctx.PublicKey()
	if pub == nil {
		t.Error("Expected non-nil public key")
	}

	// The public key should be the hybrid public key
	if pub != hybrid.Public() {
		t.Error("Public key mismatch")
	}
}

func TestU_Crypto_HybridSigningContext_VerifyBoth_InvalidClassical(t *testing.T) {
	classical, _ := GenerateSoftwareSigner(AlgECDSAP256)
	pqc, _ := GenerateSoftwareSigner(AlgMLDSA44)
	hybrid, _ := NewHybridSigner(classical, pqc)

	ctx := NewSigningContext(hybrid)
	hctx := ctx.(HybridContext)

	// Sign both
	message := []byte("test message")
	classicalSig, pqcSig, err := hctx.SignBoth(rand.Reader, message)
	if err != nil {
		t.Fatalf("SignBoth failed: %v", err)
	}

	// VerifyBoth with invalid classical signature
	err = hctx.VerifyBoth(message, []byte("invalid"), pqcSig)
	if err == nil {
		t.Error("Expected error for invalid classical signature")
	}

	// VerifyBoth with invalid PQC signature
	err = hctx.VerifyBoth(message, classicalSig, []byte("invalid"))
	if err == nil {
		t.Error("Expected error for invalid PQC signature")
	}
}

// =============================================================================
// KEMSigner Tests
// =============================================================================

func TestU_Crypto_NewKEMSigner(t *testing.T) {
	tests := []AlgorithmID{
		AlgMLKEM512,
		AlgMLKEM768,
		AlgMLKEM1024,
	}

	for _, alg := range tests {
		t.Run(alg.String(), func(t *testing.T) {
			kp, err := GenerateKEMKeyPair(alg)
			if err != nil {
				t.Fatalf("Failed to generate KEM key pair: %v", err)
			}

			signer, err := NewKEMSigner(kp)
			if err != nil {
				t.Fatalf("NewKEMSigner failed: %v", err)
			}

			if signer.Algorithm() != alg {
				t.Errorf("Algorithm mismatch: got %s, want %s", signer.Algorithm(), alg)
			}

			if signer.Public() == nil {
				t.Error("Expected non-nil public key")
			}

			if signer.PrivateKey() == nil {
				t.Error("Expected non-nil private key")
			}
		})
	}
}

func TestU_Crypto_NewKEMSigner_Nil(t *testing.T) {
	signer, err := NewKEMSigner(nil)
	if err == nil {
		t.Error("Expected error for nil key pair")
	}
	if signer != nil {
		t.Error("Expected nil signer for nil key pair")
	}
}

func TestU_Crypto_GenerateKEMSigner(t *testing.T) {
	tests := []AlgorithmID{
		AlgMLKEM512,
		AlgMLKEM768,
		AlgMLKEM1024,
	}

	for _, alg := range tests {
		t.Run(alg.String(), func(t *testing.T) {
			signer, err := GenerateKEMSigner(alg)
			if err != nil {
				t.Fatalf("GenerateKEMSigner failed: %v", err)
			}

			if signer.Algorithm() != alg {
				t.Errorf("Algorithm mismatch: got %s, want %s", signer.Algorithm(), alg)
			}
		})
	}
}

func TestU_Crypto_KEMSigner_SignFails(t *testing.T) {
	signer, err := GenerateKEMSigner(AlgMLKEM768)
	if err != nil {
		t.Fatalf("GenerateKEMSigner failed: %v", err)
	}

	// Sign should return an error because KEM keys cannot sign
	_, err = signer.Sign(rand.Reader, []byte("test message"), nil)
	if err == nil {
		t.Error("Expected error when signing with KEM signer")
	}
}

func TestU_Crypto_VerificationContext_PublicKey(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	ctx := NewVerificationContext(AlgECDSAP256, &privateKey.PublicKey)

	pub := ctx.PublicKey()
	if pub == nil {
		t.Error("Expected non-nil public key")
	}

	if pub != &privateKey.PublicKey {
		t.Error("Public key mismatch")
	}
}

// =============================================================================
// NewKEMContextForEncapsulation Error Tests
// =============================================================================

func TestU_Crypto_NewKEMContextForEncapsulation_NilPublicKey(t *testing.T) {
	// Context is created with nil public key
	ctx, err := NewKEMContextForEncapsulation(AlgMLKEM768, nil)
	if err != nil {
		t.Fatalf("NewKEMContextForEncapsulation() error = %v", err)
	}

	// Context should not support encapsulation with nil public key
	if ctx.SupportsOperation(OpEncapsulate) {
		t.Error("Should not support encapsulation with nil public key")
	}

	// Encapsulate should fail
	_, _, err = ctx.Encapsulate()
	if err == nil {
		t.Error("Expected error for encapsulation with nil public key")
	}
}

func TestU_Crypto_NewKEMContextForEncapsulation_NonKEMAlgorithm(t *testing.T) {
	// Generate ECDSA key
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Non-KEM algorithm should fail
	ctx, err := NewKEMContextForEncapsulation(AlgECDSAP256, &privateKey.PublicKey)
	if err == nil {
		t.Error("Expected error for non-KEM algorithm")
	}
	if ctx != nil {
		t.Error("Expected nil context for non-KEM algorithm")
	}
}

// =============================================================================
// slhdsaAlgorithmFromID Tests (via AlgorithmFromPublicKey)
// =============================================================================

func TestAlgorithmFromPublicKey_SLHDSA_AllVariants(t *testing.T) {
	// Test all SLH-DSA variants (skip slow ones unless -short is not set)
	tests := []struct {
		alg    AlgorithmID
		isSlow bool
	}{
		{AlgSLHDSA128f, false},
		{AlgSLHDSA192f, false},
		{AlgSLHDSA256f, false},
		{AlgSLHDSA128s, true},
		{AlgSLHDSA192s, true},
		{AlgSLHDSA256s, true},
	}

	for _, tt := range tests {
		t.Run(tt.alg.String(), func(t *testing.T) {
			if tt.isSlow && testing.Short() {
				t.Skip("Skipping slow SLH-DSA variant in short mode")
			}

			if !tt.isSlow {
				t.Parallel()
			}

			signer, err := GenerateSoftwareSigner(tt.alg)
			if err != nil {
				t.Fatalf("Failed to generate %s signer: %v", tt.alg, err)
			}

			got := AlgorithmFromPublicKey(signer.Public())
			if got != tt.alg {
				t.Errorf("AlgorithmFromPublicKey(%s) = %s, want %s", tt.alg, got, tt.alg)
			}
		})
	}
}

func TestAlgorithmFromPublicKey_SLHDSA_SHAKEVariants(t *testing.T) {
	// Test all SHAKE SLH-DSA variants
	tests := []struct {
		alg    AlgorithmID
		isSlow bool
	}{
		{AlgSLHDSASHAKE128f, false},
		{AlgSLHDSASHAKE192f, false},
		{AlgSLHDSASHAKE256f, false},
		{AlgSLHDSASHAKE128s, true},
		{AlgSLHDSASHAKE192s, true},
		{AlgSLHDSASHAKE256s, true},
	}

	for _, tt := range tests {
		t.Run(tt.alg.String(), func(t *testing.T) {
			if tt.isSlow && testing.Short() {
				t.Skip("Skipping slow SLH-DSA SHAKE variant in short mode")
			}

			if !tt.isSlow {
				t.Parallel()
			}

			signer, err := GenerateSoftwareSigner(tt.alg)
			if err != nil {
				t.Fatalf("Failed to generate %s signer: %v", tt.alg, err)
			}

			got := AlgorithmFromPublicKey(signer.Public())
			if got != tt.alg {
				t.Errorf("AlgorithmFromPublicKey(%s) = %s, want %s", tt.alg, got, tt.alg)
			}
		})
	}
}

// =============================================================================
// Verification Context Verify Error Tests
// =============================================================================

func TestU_Crypto_VerificationContext_Verify_InvalidSignature(t *testing.T) {
	// Generate signer
	signer, _ := GenerateSoftwareSigner(AlgECDSAP256)

	// Create verification context
	ctx := NewVerificationContext(AlgECDSAP256, signer.Public())

	// Verify with invalid signature
	err := ctx.Verify([]byte("message"), []byte("invalid signature"))
	if err == nil {
		t.Error("Expected error for invalid signature")
	}
}

func TestU_Crypto_SigningContext_Verify_InvalidSignature(t *testing.T) {
	signer, _ := GenerateSoftwareSigner(AlgMLDSA65)
	ctx := NewSigningContext(signer)

	// Try to verify with invalid signature
	err := ctx.Verify([]byte("message"), []byte("invalid"))
	if err == nil {
		t.Error("Expected error for invalid signature")
	}
}
