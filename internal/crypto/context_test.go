package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"
)

func TestNewSigningContext_ECDSA(t *testing.T) {
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

func TestNewSigningContext_Ed25519(t *testing.T) {
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

func TestNewSigningContext_MLDSA(t *testing.T) {
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

func TestNewSigningContext_Nil(t *testing.T) {
	ctx := NewSigningContext(nil)
	if ctx != nil {
		t.Error("Expected nil context for nil signer")
	}
}

func TestSigningContext_SignAndVerify_ECDSA(t *testing.T) {
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

func TestSigningContext_SignAndVerify_MLDSA(t *testing.T) {
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

func TestSigningContext_InvalidSignature(t *testing.T) {
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

func TestNewVerificationContext(t *testing.T) {
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

func TestVerificationContext_Verify(t *testing.T) {
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

func TestHybridSigningContext(t *testing.T) {
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

func TestHybridSigningContext_DefaultSign(t *testing.T) {
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

func TestPublicKey(t *testing.T) {
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

func TestNewKEMContext(t *testing.T) {
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

func TestNewKEMContext_Nil(t *testing.T) {
	ctx, err := NewKEMContext(nil)
	if err == nil {
		t.Error("Expected error for nil key pair")
	}
	if ctx != nil {
		t.Error("Expected nil context for nil key pair")
	}
}

func TestNewKEMContext_NonKEMAlgorithm(t *testing.T) {
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

func TestKEMContext_EncapsulateDecapsulate(t *testing.T) {
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

func TestNewKEMContextForEncapsulation(t *testing.T) {
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

func TestKEMContext_SignAndVerifyFail(t *testing.T) {
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
