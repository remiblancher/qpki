package crypto

import (
	"crypto"
	"crypto/rand"
	"path/filepath"
	"testing"

	"github.com/cloudflare/circl/sign/ed448"
)

// =============================================================================
// [Unit] Ed448 Key Generation Tests
// =============================================================================

func TestU_Ed448_KeyGeneration(t *testing.T) {
	kp, err := GenerateKeyPair(AlgEd448)
	if err != nil {
		t.Fatalf("GenerateKeyPair(Ed448) error = %v", err)
	}

	if kp.PrivateKey == nil {
		t.Error("GenerateKeyPair(Ed448) private key is nil")
	}
	if kp.PublicKey == nil {
		t.Error("GenerateKeyPair(Ed448) public key is nil")
	}

	// Verify key types
	_, ok := kp.PrivateKey.(ed448.PrivateKey)
	if !ok {
		t.Errorf("Expected ed448.PrivateKey, got %T", kp.PrivateKey)
	}

	_, ok = kp.PublicKey.(ed448.PublicKey)
	if !ok {
		t.Errorf("Expected ed448.PublicKey, got %T", kp.PublicKey)
	}
}

func TestU_Ed448_KeyGeneration_MultipleKeys(t *testing.T) {
	// Generate multiple keys and verify they are different
	kp1, err := GenerateKeyPair(AlgEd448)
	if err != nil {
		t.Fatalf("GenerateKeyPair(Ed448) first call error = %v", err)
	}

	kp2, err := GenerateKeyPair(AlgEd448)
	if err != nil {
		t.Fatalf("GenerateKeyPair(Ed448) second call error = %v", err)
	}

	pub1, _ := kp1.PublicKeyBytes()
	pub2, _ := kp2.PublicKeyBytes()

	if string(pub1) == string(pub2) {
		t.Error("Generated keys should be different")
	}
}

// =============================================================================
// [Unit] Ed448 Sign/Verify Tests
// =============================================================================

func TestU_VerifySignature_Ed448(t *testing.T) {
	signer, err := GenerateSoftwareSigner(AlgEd448)
	if err != nil {
		t.Fatalf("GenerateSoftwareSigner(Ed448) error = %v", err)
	}

	message := []byte("test message for Ed448")

	// Sign - Ed448 uses pure mode, pass message directly
	sig, err := signer.Sign(rand.Reader, message, nil)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Ed448 signature should be 114 bytes (2 * 57)
	if len(sig) != 114 {
		t.Errorf("Signature length = %d, want 114", len(sig))
	}

	// Verify
	err = VerifySignature(signer.Public(), AlgEd448, message, sig)
	if err != nil {
		t.Errorf("VerifySignature() should pass for valid signature: %v", err)
	}
}

func TestU_VerifySignature_Ed448_InvalidSignature(t *testing.T) {
	signer, err := GenerateSoftwareSigner(AlgEd448)
	if err != nil {
		t.Fatalf("GenerateSoftwareSigner(Ed448) error = %v", err)
	}

	message := []byte("test message for Ed448")

	// Sign
	sig, err := signer.Sign(rand.Reader, message, nil)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Modify signature
	sig[0] ^= 0xFF

	// Verify should fail
	err = VerifySignature(signer.Public(), AlgEd448, message, sig)
	if err == nil {
		t.Error("VerifySignature() should fail for invalid signature")
	}
}

func TestU_VerifySignature_Ed448_WrongMessage(t *testing.T) {
	signer, err := GenerateSoftwareSigner(AlgEd448)
	if err != nil {
		t.Fatalf("GenerateSoftwareSigner(Ed448) error = %v", err)
	}

	message := []byte("test message for Ed448")

	// Sign
	sig, err := signer.Sign(rand.Reader, message, nil)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Verify with wrong message
	wrongMessage := []byte("wrong message")
	err = VerifySignature(signer.Public(), AlgEd448, wrongMessage, sig)
	if err == nil {
		t.Error("VerifySignature() should fail for wrong message")
	}
}

func TestU_VerifySignature_Ed448_WrongKey(t *testing.T) {
	signer1, err := GenerateSoftwareSigner(AlgEd448)
	if err != nil {
		t.Fatalf("GenerateSoftwareSigner(Ed448) first call error = %v", err)
	}

	signer2, err := GenerateSoftwareSigner(AlgEd448)
	if err != nil {
		t.Fatalf("GenerateSoftwareSigner(Ed448) second call error = %v", err)
	}

	message := []byte("test message for Ed448")

	// Sign with first key
	sig, err := signer1.Sign(rand.Reader, message, nil)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Verify with second key should fail
	err = VerifySignature(signer2.Public(), AlgEd448, message, sig)
	if err == nil {
		t.Error("VerifySignature() should fail for wrong key")
	}
}

// =============================================================================
// [Unit] Ed448 PublicKeyBytes Tests
// =============================================================================

func TestU_PublicKeyBytes_Ed448(t *testing.T) {
	kp, err := GenerateKeyPair(AlgEd448)
	if err != nil {
		t.Fatalf("GenerateKeyPair(Ed448) error = %v", err)
	}

	pubBytes, err := PublicKeyBytes(kp.PublicKey)
	if err != nil {
		t.Fatalf("PublicKeyBytes() error = %v", err)
	}

	// Ed448 public key should be 57 bytes
	if len(pubBytes) != 57 {
		t.Errorf("PublicKeyBytes() length = %d, want 57", len(pubBytes))
	}
}

func TestU_KeyPair_PublicKeyBytes_Ed448(t *testing.T) {
	kp, err := GenerateKeyPair(AlgEd448)
	if err != nil {
		t.Fatalf("GenerateKeyPair(Ed448) error = %v", err)
	}

	pubBytes, err := kp.PublicKeyBytes()
	if err != nil {
		t.Fatalf("PublicKeyBytes() error = %v", err)
	}

	// Ed448 public key should be 57 bytes
	if len(pubBytes) != 57 {
		t.Errorf("PublicKeyBytes() length = %d, want 57", len(pubBytes))
	}
}

// =============================================================================
// [Unit] Ed448 ParsePublicKey Tests
// =============================================================================

func TestU_ParsePublicKey_Ed448(t *testing.T) {
	kp, err := GenerateKeyPair(AlgEd448)
	if err != nil {
		t.Fatalf("GenerateKeyPair(Ed448) error = %v", err)
	}

	pubBytes, err := kp.PublicKeyBytes()
	if err != nil {
		t.Fatalf("PublicKeyBytes() error = %v", err)
	}

	parsed, err := ParsePublicKey(AlgEd448, pubBytes)
	if err != nil {
		t.Fatalf("ParsePublicKey() error = %v", err)
	}

	if parsed == nil {
		t.Error("ParsePublicKey() returned nil")
	}

	// Verify it's the right type
	_, ok := parsed.(ed448.PublicKey)
	if !ok {
		t.Errorf("ParsePublicKey() returned %T, want ed448.PublicKey", parsed)
	}
}

func TestU_ParsePublicKey_Ed448_InvalidSize(t *testing.T) {
	_, err := ParsePublicKey(AlgEd448, []byte{1, 2, 3})
	if err == nil {
		t.Error("ParsePublicKey(Ed448) should fail for invalid size")
	}
}

func TestU_ParsePublicKey_Ed448_RoundTrip(t *testing.T) {
	// Generate key pair
	kp, err := GenerateKeyPair(AlgEd448)
	if err != nil {
		t.Fatalf("GenerateKeyPair(Ed448) error = %v", err)
	}

	// Get public key bytes
	pubBytes, err := kp.PublicKeyBytes()
	if err != nil {
		t.Fatalf("PublicKeyBytes() error = %v", err)
	}

	// Parse public key
	parsedPub, err := ParsePublicKey(AlgEd448, pubBytes)
	if err != nil {
		t.Fatalf("ParsePublicKey() error = %v", err)
	}

	// Sign with original key
	signer := kp.PrivateKey.(ed448.PrivateKey)
	message := []byte("test message for round-trip")
	sig := ed448.Sign(signer, message, "")

	// Verify with parsed key
	parsedPubKey := parsedPub.(ed448.PublicKey)
	if !ed448.Verify(parsedPubKey, message, sig, "") {
		t.Error("Signature verification failed with parsed public key")
	}
}

// =============================================================================
// [Unit] Ed448 Save/Load Key Tests
// =============================================================================

func TestU_SaveLoadKey_Ed448(t *testing.T) {
	// NOTE: Go's standard library x509.MarshalPKCS8PrivateKey doesn't support
	// Ed448 keys yet. This test documents the current limitation.
	// Ed448 key persistence would require custom PKCS#8 marshaling.
	t.Skip("Ed448 PKCS#8 marshaling not supported by Go's x509 library")

	tempDir := t.TempDir()

	// Generate key
	signer, err := GenerateSoftwareSigner(AlgEd448)
	if err != nil {
		t.Fatalf("GenerateSoftwareSigner(Ed448) error = %v", err)
	}

	keyPath := filepath.Join(tempDir, "ed448.key.pem")

	// Save key without encryption
	if err := signer.SavePrivateKey(keyPath, nil); err != nil {
		t.Fatalf("SavePrivateKey() error = %v", err)
	}

	// Load key
	loaded, err := LoadPrivateKey(keyPath, nil)
	if err != nil {
		t.Fatalf("LoadPrivateKey() error = %v", err)
	}

	if loaded.Algorithm() != AlgEd448 {
		t.Errorf("Algorithm() = %v, want %v", loaded.Algorithm(), AlgEd448)
	}

	// Verify signing still works
	message := []byte("test message after load")
	sig, err := loaded.Sign(rand.Reader, message, nil)
	if err != nil {
		t.Fatalf("Sign() after load error = %v", err)
	}

	err = VerifySignature(loaded.Public(), AlgEd448, message, sig)
	if err != nil {
		t.Errorf("VerifySignature() after load should pass: %v", err)
	}
}

func TestU_SaveLoadKey_Ed448_Encrypted(t *testing.T) {
	// NOTE: Go's standard library x509.MarshalPKCS8PrivateKey doesn't support
	// Ed448 keys yet. This test documents the current limitation.
	t.Skip("Ed448 PKCS#8 marshaling not supported by Go's x509 library")

	tempDir := t.TempDir()

	// Generate key
	signer, err := GenerateSoftwareSigner(AlgEd448)
	if err != nil {
		t.Fatalf("GenerateSoftwareSigner(Ed448) error = %v", err)
	}

	keyPath := filepath.Join(tempDir, "ed448-encrypted.key.pem")
	passphrase := []byte("test-passphrase")

	// Save key with encryption
	if err := signer.SavePrivateKey(keyPath, passphrase); err != nil {
		t.Fatalf("SavePrivateKey() error = %v", err)
	}

	// Load key with correct passphrase
	loaded, err := LoadPrivateKey(keyPath, passphrase)
	if err != nil {
		t.Fatalf("LoadPrivateKey() error = %v", err)
	}

	if loaded.Algorithm() != AlgEd448 {
		t.Errorf("Algorithm() = %v, want %v", loaded.Algorithm(), AlgEd448)
	}

	// Load key with wrong passphrase should fail
	_, err = LoadPrivateKey(keyPath, []byte("wrong-passphrase"))
	if err == nil {
		t.Error("LoadPrivateKey() should fail with wrong passphrase")
	}
}

// =============================================================================
// [Unit] Ed448 Algorithm Properties Tests
// =============================================================================

func TestU_Algorithm_Properties_Ed448(t *testing.T) {
	alg := AlgEd448

	if !alg.IsValid() {
		t.Error("Ed448 should be valid")
	}

	if !alg.IsClassical() {
		t.Error("Ed448 should be classical")
	}

	if alg.IsPQC() {
		t.Error("Ed448 should not be PQC")
	}

	if alg.IsHybrid() {
		t.Error("Ed448 should not be hybrid")
	}

	if !alg.IsSignature() {
		t.Error("Ed448 should be a signature algorithm")
	}

	if alg.IsKEM() {
		t.Error("Ed448 should not be a KEM")
	}
}

func TestU_Algorithm_OID_Ed448(t *testing.T) {
	oid := AlgEd448.OID()
	if oid == nil {
		t.Error("Ed448 OID should not be nil")
	}

	// Ed448 OID should be 1.3.101.113
	expected := []int{1, 3, 101, 113}
	if len(oid) != len(expected) {
		t.Errorf("Ed448 OID length = %d, want %d", len(oid), len(expected))
	}
	for i, v := range expected {
		if oid[i] != v {
			t.Errorf("Ed448 OID[%d] = %d, want %d", i, oid[i], v)
		}
	}
}

func TestU_Algorithm_Family_Ed448(t *testing.T) {
	family := AlgEd448.Family()
	if family != "ed" {
		t.Errorf("Ed448 Family() = %q, want %q", family, "ed")
	}

	// Ed25519 and Ed448 should have the same family
	if AlgEd25519.Family() != AlgEd448.Family() {
		t.Error("Ed25519 and Ed448 should have the same family")
	}
}

func TestU_Algorithm_KeySizeBits_Ed448(t *testing.T) {
	info := algorithms[AlgEd448]
	if info.KeySizeBits != 448 {
		t.Errorf("Ed448 KeySizeBits = %d, want 448", info.KeySizeBits)
	}
}

// =============================================================================
// [Unit] Ed448 AlgorithmFromPublicKey Tests
// =============================================================================

func TestU_AlgorithmFromPublicKey_Ed448(t *testing.T) {
	kp, err := GenerateKeyPair(AlgEd448)
	if err != nil {
		t.Fatalf("GenerateKeyPair(Ed448) error = %v", err)
	}

	detected := AlgorithmFromPublicKey(kp.PublicKey)
	if detected != AlgEd448 {
		t.Errorf("AlgorithmFromPublicKey() = %v, want %v", detected, AlgEd448)
	}
}

// =============================================================================
// [Unit] Ed448 SoftwareSigner Tests
// =============================================================================

func TestU_SoftwareSigner_Ed448_Algorithm(t *testing.T) {
	signer, err := GenerateSoftwareSigner(AlgEd448)
	if err != nil {
		t.Fatalf("GenerateSoftwareSigner(Ed448) error = %v", err)
	}

	if signer.Algorithm() != AlgEd448 {
		t.Errorf("Algorithm() = %v, want %v", signer.Algorithm(), AlgEd448)
	}
}

func TestU_SoftwareSigner_Ed448_Public(t *testing.T) {
	signer, err := GenerateSoftwareSigner(AlgEd448)
	if err != nil {
		t.Fatalf("GenerateSoftwareSigner(Ed448) error = %v", err)
	}

	pub := signer.Public()
	if pub == nil {
		t.Error("Public() should not be nil")
	}

	_, ok := pub.(ed448.PublicKey)
	if !ok {
		t.Errorf("Public() returned %T, want ed448.PublicKey", pub)
	}
}

func TestU_SoftwareSigner_Ed448_SignerInterface(t *testing.T) {
	signer, err := GenerateSoftwareSigner(AlgEd448)
	if err != nil {
		t.Fatalf("GenerateSoftwareSigner(Ed448) error = %v", err)
	}

	// Verify that SoftwareSigner implements crypto.Signer
	var _ crypto.Signer = signer
}

// =============================================================================
// [Unit] Ed448 Algorithm Extended Tests
// =============================================================================

func TestU_Algorithm_Type_Ed448(t *testing.T) {
	algType := AlgEd448.Type()
	if algType != TypeClassicalSignature {
		t.Errorf("Ed448 Type() = %v, want %v", algType, TypeClassicalSignature)
	}
}

func TestU_Algorithm_Description_Ed448(t *testing.T) {
	desc := AlgEd448.Description()
	if desc == "" {
		t.Error("Ed448 Description() should not be empty")
	}
	if desc != "Ed448 (EdDSA with Curve448)" {
		t.Errorf("Ed448 Description() = %q, want %q", desc, "Ed448 (EdDSA with Curve448)")
	}
}

func TestU_Algorithm_String_Ed448(t *testing.T) {
	str := AlgEd448.String()
	if str != "ed448" {
		t.Errorf("Ed448 String() = %q, want %q", str, "ed448")
	}
}

// =============================================================================
// [Unit] Ed448 NewSoftwareSigner Tests
// =============================================================================

func TestU_NewSoftwareSigner_Ed448(t *testing.T) {
	// Generate a key pair
	kp, err := GenerateKeyPair(AlgEd448)
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	// Create signer from KeyPair
	signer, err := NewSoftwareSigner(kp)
	if err != nil {
		t.Fatalf("NewSoftwareSigner() error = %v", err)
	}

	if signer.Algorithm() != AlgEd448 {
		t.Errorf("Algorithm() = %v, want %v", signer.Algorithm(), AlgEd448)
	}

	// Test signing with the created signer
	message := []byte("test message")
	sig, err := signer.Sign(rand.Reader, message, nil)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Verify the signature
	pub := kp.PublicKey.(ed448.PublicKey)
	if !ed448.Verify(pub, message, sig, "") {
		t.Error("Signature verification failed")
	}
}

func TestU_NewSoftwareSigner_Ed448_NilKeyPair(t *testing.T) {
	// Try to create signer with nil KeyPair
	_, err := NewSoftwareSigner(nil)
	if err == nil {
		t.Error("NewSoftwareSigner() should fail with nil KeyPair")
	}
}

// =============================================================================
// [Unit] Ed448 PrivateKey() Method Tests
// =============================================================================

func TestU_SoftwareSigner_Ed448_PrivateKey(t *testing.T) {
	signer, err := GenerateSoftwareSigner(AlgEd448)
	if err != nil {
		t.Fatalf("GenerateSoftwareSigner(Ed448) error = %v", err)
	}

	priv := signer.PrivateKey()
	if priv == nil {
		t.Error("PrivateKey() should not be nil")
	}

	_, ok := priv.(ed448.PrivateKey)
	if !ok {
		t.Errorf("PrivateKey() returned %T, want ed448.PrivateKey", priv)
	}
}

// =============================================================================
// [Unit] Ed448 VerifySignature Tests
// =============================================================================

func TestU_VerifySignature_Ed448_ValidSignature(t *testing.T) {
	signer, err := GenerateSoftwareSigner(AlgEd448)
	if err != nil {
		t.Fatalf("GenerateSoftwareSigner(Ed448) error = %v", err)
	}

	message := []byte("test message for verification")

	// Sign
	sig, err := signer.Sign(rand.Reader, message, nil)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Use VerifySignature function
	err = VerifySignature(signer.Public(), AlgEd448, message, sig)
	if err != nil {
		t.Errorf("VerifySignature() should pass for valid signature: %v", err)
	}

	// Test with invalid signature
	invalidSig := make([]byte, len(sig))
	copy(invalidSig, sig)
	invalidSig[0] ^= 0xFF
	err = VerifySignature(signer.Public(), AlgEd448, message, invalidSig)
	if err == nil {
		t.Error("VerifySignature() should fail for invalid signature")
	}
}

// =============================================================================
// [Unit] Ed448 Context Detection Tests
// =============================================================================

func TestU_NewSigningContext_Ed448(t *testing.T) {
	signer, err := GenerateSoftwareSigner(AlgEd448)
	if err != nil {
		t.Fatalf("GenerateSoftwareSigner(Ed448) error = %v", err)
	}

	ctx := NewSigningContext(signer)
	if ctx.Algorithm() != AlgEd448 {
		t.Errorf("Algorithm() = %v, want %v", ctx.Algorithm(), AlgEd448)
	}
}

func TestU_NewVerificationContext_Ed448(t *testing.T) {
	kp, err := GenerateKeyPair(AlgEd448)
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	ctx := NewVerificationContext(AlgEd448, kp.PublicKey)
	if ctx.Algorithm() != AlgEd448 {
		t.Errorf("Algorithm() = %v, want %v", ctx.Algorithm(), AlgEd448)
	}
}

// =============================================================================
// [Unit] Ed448 KeyPair Tests
// =============================================================================

func TestU_KeyPair_Ed448_Algorithm(t *testing.T) {
	kp, err := GenerateKeyPair(AlgEd448)
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	// Access the KeyPair fields directly
	if kp.Algorithm != AlgEd448 {
		t.Errorf("KeyPair.Algorithm = %v, want %v", kp.Algorithm, AlgEd448)
	}

	if kp.PrivateKey == nil {
		t.Error("KeyPair.PrivateKey should not be nil")
	}

	if kp.PublicKey == nil {
		t.Error("KeyPair.PublicKey should not be nil")
	}
}

// =============================================================================
// [Unit] Ed448 Multiple Signatures Test
// =============================================================================

func TestU_Ed448_MultipleSignatures(t *testing.T) {
	signer, err := GenerateSoftwareSigner(AlgEd448)
	if err != nil {
		t.Fatalf("GenerateSoftwareSigner(Ed448) error = %v", err)
	}

	messages := [][]byte{
		[]byte("message 1"),
		[]byte("message 2"),
		[]byte("message 3"),
		[]byte("a longer message that tests the signing capability"),
		{}, // empty message
	}

	for i, msg := range messages {
		sig, err := signer.Sign(rand.Reader, msg, nil)
		if err != nil {
			t.Fatalf("Sign() error for message %d: %v", i, err)
		}

		err = VerifySignature(signer.Public(), AlgEd448, msg, sig)
		if err != nil {
			t.Errorf("VerifySignature() failed for message %d: %v", i, err)
		}
	}
}

// =============================================================================
// [Unit] Ed448 Large Message Test
// =============================================================================

func TestU_Ed448_LargeMessage(t *testing.T) {
	signer, err := GenerateSoftwareSigner(AlgEd448)
	if err != nil {
		t.Fatalf("GenerateSoftwareSigner(Ed448) error = %v", err)
	}

	// Create a 1MB message
	largeMessage := make([]byte, 1024*1024)
	_, err = rand.Read(largeMessage)
	if err != nil {
		t.Fatalf("Failed to generate random message: %v", err)
	}

	sig, err := signer.Sign(rand.Reader, largeMessage, nil)
	if err != nil {
		t.Fatalf("Sign() error for large message: %v", err)
	}

	err = VerifySignature(signer.Public(), AlgEd448, largeMessage, sig)
	if err != nil {
		t.Errorf("VerifySignature() failed for large message: %v", err)
	}
}
