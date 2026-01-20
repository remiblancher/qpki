package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// =============================================================================
// HybridSigner Tests
// =============================================================================

func TestNewHybridSigner_Valid(t *testing.T) {
	classical, err := GenerateSoftwareSigner(AlgECDSAP256)
	if err != nil {
		t.Fatalf("failed to generate classical signer: %v", err)
	}

	pqc, err := GenerateSoftwareSigner(AlgMLDSA65)
	if err != nil {
		t.Fatalf("failed to generate PQC signer: %v", err)
	}

	hybrid, err := NewHybridSigner(classical, pqc)
	if err != nil {
		t.Fatalf("NewHybridSigner failed: %v", err)
	}

	if hybrid == nil {
		t.Fatal("hybrid signer is nil")
	}

	// Verify accessors
	if hybrid.ClassicalSigner() != classical {
		t.Error("ClassicalSigner() mismatch")
	}
	if hybrid.PQCSigner() != pqc {
		t.Error("PQCSigner() mismatch")
	}
}

func TestNewHybridSigner_NilClassical(t *testing.T) {
	pqc, _ := GenerateSoftwareSigner(AlgMLDSA65)

	_, err := NewHybridSigner(nil, pqc)
	if err == nil {
		t.Error("expected error for nil classical signer")
	}
}

func TestNewHybridSigner_NilPQC(t *testing.T) {
	classical, _ := GenerateSoftwareSigner(AlgECDSAP256)

	_, err := NewHybridSigner(classical, nil)
	if err == nil {
		t.Error("expected error for nil PQC signer")
	}
}

func TestNewHybridSigner_ClassicalIsPQC(t *testing.T) {
	// Both signers are PQC - should fail
	classical, _ := GenerateSoftwareSigner(AlgMLDSA44)
	pqc, _ := GenerateSoftwareSigner(AlgMLDSA65)

	_, err := NewHybridSigner(classical, pqc)
	if err == nil {
		t.Error("expected error when classical signer uses PQC algorithm")
	}
}

func TestNewHybridSigner_PQCIsClassical(t *testing.T) {
	// Both signers are classical - should fail
	classical, _ := GenerateSoftwareSigner(AlgECDSAP256)
	pqc, _ := GenerateSoftwareSigner(AlgECDSAP384)

	_, err := NewHybridSigner(classical, pqc)
	if err == nil {
		t.Error("expected error when PQC signer uses classical algorithm")
	}
}

func TestGenerateHybridSigner(t *testing.T) {
	tests := []struct {
		name        string
		classicalAg AlgorithmID
		pqcAlg      AlgorithmID
	}{
		{"P256+MLDSA44", AlgECDSAP256, AlgMLDSA44},
		{"P384+MLDSA65", AlgECDSAP384, AlgMLDSA65},
		{"P521+MLDSA87", AlgECDSAP521, AlgMLDSA87},
		{"Ed25519+MLDSA65", AlgEd25519, AlgMLDSA65},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hybrid, err := GenerateHybridSigner(tt.classicalAg, tt.pqcAlg)
			if err != nil {
				t.Fatalf("GenerateHybridSigner failed: %v", err)
			}

			if hybrid.ClassicalAlgorithm() != tt.classicalAg {
				t.Errorf("ClassicalAlgorithm() = %s, want %s", hybrid.ClassicalAlgorithm(), tt.classicalAg)
			}
			if hybrid.PQCAlgorithm() != tt.pqcAlg {
				t.Errorf("PQCAlgorithm() = %s, want %s", hybrid.PQCAlgorithm(), tt.pqcAlg)
			}
		})
	}
}

func TestGenerateHybridSigner_InvalidClassical(t *testing.T) {
	_, err := GenerateHybridSigner("invalid-algo", AlgMLDSA65)
	if err == nil {
		t.Error("expected error for invalid classical algorithm")
	}
}

func TestGenerateHybridSigner_InvalidPQC(t *testing.T) {
	_, err := GenerateHybridSigner(AlgECDSAP256, "invalid-algo")
	if err == nil {
		t.Error("expected error for invalid PQC algorithm")
	}
}

func TestHybridSigner_Algorithm(t *testing.T) {
	hybrid, err := GenerateHybridSigner(AlgECDSAP256, AlgMLDSA65)
	if err != nil {
		t.Fatalf("GenerateHybridSigner failed: %v", err)
	}

	alg := hybrid.Algorithm()
	if alg == "" {
		t.Error("Algorithm() returned empty string")
	}

	// Algorithm should be a combined identifier
	expected := AlgorithmID("hybrid-ecdsa-p256-ml-dsa-65")
	if alg != expected {
		t.Errorf("Algorithm() = %s, want %s", alg, expected)
	}
}

func TestHybridSigner_Public(t *testing.T) {
	classical, _ := GenerateSoftwareSigner(AlgECDSAP256)
	pqc, _ := GenerateSoftwareSigner(AlgMLDSA65)

	hybrid, err := NewHybridSigner(classical, pqc)
	if err != nil {
		t.Fatalf("NewHybridSigner failed: %v", err)
	}

	// Public() should return the classical public key
	pub := hybrid.Public()
	if pub != classical.Public() {
		t.Error("Public() should return classical public key")
	}
}

func TestHybridSigner_Sign(t *testing.T) {
	hybrid, err := GenerateHybridSigner(AlgECDSAP256, AlgMLDSA65)
	if err != nil {
		t.Fatalf("GenerateHybridSigner failed: %v", err)
	}

	message := []byte("test message for signing")

	// Sign() should use the classical signer
	sig, err := hybrid.Sign(rand.Reader, message, nil)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}

	if len(sig) == 0 {
		t.Error("signature is empty")
	}

	// Verify with classical algorithm
	valid := Verify(hybrid.ClassicalAlgorithm(), hybrid.ClassicalPublicKey(), message, sig)
	if !valid {
		t.Error("classical signature verification failed")
	}
}

func TestHybridSigner_SignHybrid(t *testing.T) {
	hybrid, err := GenerateHybridSigner(AlgECDSAP256, AlgMLDSA65)
	if err != nil {
		t.Fatalf("GenerateHybridSigner failed: %v", err)
	}

	message := []byte("test message for dual signing")

	classicalSig, pqcSig, err := hybrid.SignHybrid(rand.Reader, message)
	if err != nil {
		t.Fatalf("SignHybrid() failed: %v", err)
	}

	if len(classicalSig) == 0 {
		t.Error("classical signature is empty")
	}
	if len(pqcSig) == 0 {
		t.Error("PQC signature is empty")
	}

	// Verify classical signature
	classicalValid := Verify(hybrid.ClassicalAlgorithm(), hybrid.ClassicalPublicKey(), message, classicalSig)
	if !classicalValid {
		t.Error("classical signature verification failed")
	}

	// Verify PQC signature
	pqcValid := Verify(hybrid.PQCAlgorithm(), hybrid.PQCPublicKey(), message, pqcSig)
	if !pqcValid {
		t.Error("PQC signature verification failed")
	}
}

func TestHybridSigner_VerifyHybrid(t *testing.T) {
	hybrid, err := GenerateHybridSigner(AlgECDSAP384, AlgMLDSA65)
	if err != nil {
		t.Fatalf("GenerateHybridSigner failed: %v", err)
	}

	message := []byte("test message for verification")

	classicalSig, pqcSig, err := hybrid.SignHybrid(rand.Reader, message)
	if err != nil {
		t.Fatalf("SignHybrid() failed: %v", err)
	}

	// Verify both signatures
	valid := hybrid.VerifyHybrid(message, classicalSig, pqcSig)
	if !valid {
		t.Error("VerifyHybrid() returned false, expected true")
	}

	// Verify with wrong message should fail
	wrongMessage := []byte("wrong message")
	if hybrid.VerifyHybrid(wrongMessage, classicalSig, pqcSig) {
		t.Error("VerifyHybrid() with wrong message should return false")
	}

	// Verify with wrong classical signature should fail
	wrongClassicalSig := make([]byte, len(classicalSig))
	copy(wrongClassicalSig, classicalSig)
	wrongClassicalSig[0] ^= 0xFF
	if hybrid.VerifyHybrid(message, wrongClassicalSig, pqcSig) {
		t.Error("VerifyHybrid() with wrong classical signature should return false")
	}

	// Verify with wrong PQC signature should fail
	wrongPQCSig := make([]byte, len(pqcSig))
	copy(wrongPQCSig, pqcSig)
	wrongPQCSig[0] ^= 0xFF
	if hybrid.VerifyHybrid(message, classicalSig, wrongPQCSig) {
		t.Error("VerifyHybrid() with wrong PQC signature should return false")
	}
}

func TestHybridSigner_ClassicalAlgorithm(t *testing.T) {
	hybrid, _ := GenerateHybridSigner(AlgECDSAP384, AlgMLDSA65)

	if hybrid.ClassicalAlgorithm() != AlgECDSAP384 {
		t.Errorf("ClassicalAlgorithm() = %s, want %s", hybrid.ClassicalAlgorithm(), AlgECDSAP384)
	}
}

func TestHybridSigner_PQCAlgorithm(t *testing.T) {
	hybrid, _ := GenerateHybridSigner(AlgECDSAP256, AlgMLDSA87)

	if hybrid.PQCAlgorithm() != AlgMLDSA87 {
		t.Errorf("PQCAlgorithm() = %s, want %s", hybrid.PQCAlgorithm(), AlgMLDSA87)
	}
}

func TestHybridSigner_ClassicalPublicKey(t *testing.T) {
	classical, _ := GenerateSoftwareSigner(AlgECDSAP256)
	pqc, _ := GenerateSoftwareSigner(AlgMLDSA65)

	hybrid, _ := NewHybridSigner(classical, pqc)

	if hybrid.ClassicalPublicKey() != classical.Public() {
		t.Error("ClassicalPublicKey() mismatch")
	}
}

func TestHybridSigner_PQCPublicKey(t *testing.T) {
	classical, _ := GenerateSoftwareSigner(AlgECDSAP256)
	pqc, _ := GenerateSoftwareSigner(AlgMLDSA65)

	hybrid, _ := NewHybridSigner(classical, pqc)

	if hybrid.PQCPublicKey() != pqc.Public() {
		t.Error("PQCPublicKey() mismatch")
	}
}

func TestHybridSigner_PQCPublicKeyBytes(t *testing.T) {
	hybrid, err := GenerateHybridSigner(AlgECDSAP256, AlgMLDSA65)
	if err != nil {
		t.Fatalf("GenerateHybridSigner failed: %v", err)
	}

	bytes, err := hybrid.PQCPublicKeyBytes()
	if err != nil {
		t.Fatalf("PQCPublicKeyBytes() failed: %v", err)
	}

	if len(bytes) == 0 {
		t.Error("PQCPublicKeyBytes() returned empty bytes")
	}
}

// =============================================================================
// Key Persistence Tests
// =============================================================================

func TestHybridSigner_SaveLoadKeys(t *testing.T) {
	tmpDir := t.TempDir()

	hybrid, err := GenerateHybridSigner(AlgECDSAP256, AlgMLDSA65)
	if err != nil {
		t.Fatalf("GenerateHybridSigner failed: %v", err)
	}

	classicalPath := filepath.Join(tmpDir, "classical.key.pem")
	pqcPath := filepath.Join(tmpDir, "pqc.key.pem")

	// Save keys
	if err := hybrid.SaveHybridKeys(classicalPath, pqcPath, nil); err != nil {
		t.Fatalf("SaveHybridKeys() failed: %v", err)
	}

	// Verify files exist
	if _, err := os.Stat(classicalPath); err != nil {
		t.Errorf("classical key file not created: %v", err)
	}
	if _, err := os.Stat(pqcPath); err != nil {
		t.Errorf("PQC key file not created: %v", err)
	}

	// Load keys
	loaded, err := LoadHybridSigner(classicalPath, pqcPath, nil)
	if err != nil {
		t.Fatalf("LoadHybridSigner() failed: %v", err)
	}

	// Verify loaded signer works
	message := []byte("test message")
	origClassical, origPQC, _ := hybrid.SignHybrid(rand.Reader, message)
	loadedValid := loaded.VerifyHybrid(message, origClassical, origPQC)
	if !loadedValid {
		t.Error("loaded signer cannot verify signatures from original")
	}
}

func TestHybridSigner_SaveLoadKeysEncrypted(t *testing.T) {
	tmpDir := t.TempDir()

	hybrid, _ := GenerateHybridSigner(AlgECDSAP256, AlgMLDSA65)
	classicalPath := filepath.Join(tmpDir, "classical.key.pem")
	pqcPath := filepath.Join(tmpDir, "pqc.key.pem")
	passphrase := []byte("testpassword")

	// Save encrypted
	if err := hybrid.SaveHybridKeys(classicalPath, pqcPath, passphrase); err != nil {
		t.Fatalf("SaveHybridKeys() failed: %v", err)
	}

	// Load with correct passphrase
	loaded, err := LoadHybridSigner(classicalPath, pqcPath, passphrase)
	if err != nil {
		t.Fatalf("LoadHybridSigner() failed: %v", err)
	}

	if loaded.ClassicalAlgorithm() != AlgECDSAP256 {
		t.Error("loaded classical algorithm mismatch")
	}

	// Load without passphrase should fail
	_, err = LoadHybridSigner(classicalPath, pqcPath, nil)
	if err == nil {
		t.Error("LoadHybridSigner() should fail without passphrase for encrypted keys")
	}
}

func TestHybridSigner_SaveLoadBundle(t *testing.T) {
	tmpDir := t.TempDir()

	hybrid, err := GenerateHybridSigner(AlgECDSAP384, AlgMLDSA65)
	if err != nil {
		t.Fatalf("GenerateHybridSigner failed: %v", err)
	}

	bundlePath := filepath.Join(tmpDir, "hybrid.key.pem")

	// Save bundle
	if err := hybrid.SaveHybridKeyBundle(bundlePath, nil); err != nil {
		t.Fatalf("SaveHybridKeyBundle() failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(bundlePath); err != nil {
		t.Errorf("bundle file not created: %v", err)
	}

	// Load bundle
	loaded, err := LoadHybridSignerBundle(bundlePath, nil)
	if err != nil {
		t.Fatalf("LoadHybridSignerBundle() failed: %v", err)
	}

	// Verify loaded signer
	if loaded.ClassicalAlgorithm() != AlgECDSAP384 {
		t.Errorf("loaded classical algorithm = %s, want %s", loaded.ClassicalAlgorithm(), AlgECDSAP384)
	}
	if loaded.PQCAlgorithm() != AlgMLDSA65 {
		t.Errorf("loaded PQC algorithm = %s, want %s", loaded.PQCAlgorithm(), AlgMLDSA65)
	}

	// Verify can sign and verify
	message := []byte("test message")
	classicalSig, pqcSig, err := loaded.SignHybrid(rand.Reader, message)
	if err != nil {
		t.Fatalf("SignHybrid() failed: %v", err)
	}

	if !hybrid.VerifyHybrid(message, classicalSig, pqcSig) {
		t.Error("original signer cannot verify signatures from loaded")
	}
}

func TestHybridSigner_SaveLoadBundleEncrypted(t *testing.T) {
	tmpDir := t.TempDir()

	hybrid, _ := GenerateHybridSigner(AlgECDSAP256, AlgMLDSA44)
	bundlePath := filepath.Join(tmpDir, "hybrid-enc.key.pem")
	passphrase := []byte("bundlepassword")

	// Save encrypted bundle
	if err := hybrid.SaveHybridKeyBundle(bundlePath, passphrase); err != nil {
		t.Fatalf("SaveHybridKeyBundle() failed: %v", err)
	}

	// Load with correct passphrase
	loaded, err := LoadHybridSignerBundle(bundlePath, passphrase)
	if err != nil {
		t.Fatalf("LoadHybridSignerBundle() failed: %v", err)
	}

	if loaded.ClassicalAlgorithm() != AlgECDSAP256 {
		t.Error("loaded classical algorithm mismatch")
	}

	// Load without passphrase should fail
	_, err = LoadHybridSignerBundle(bundlePath, nil)
	if err == nil {
		t.Error("LoadHybridSignerBundle() should fail without passphrase")
	}
}

func TestLoadHybridSignerBundle_InvalidFile(t *testing.T) {
	tmpDir := t.TempDir()
	bundlePath := filepath.Join(tmpDir, "invalid.pem")

	// Write invalid content
	if err := os.WriteFile(bundlePath, []byte("not a pem file"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadHybridSignerBundle(bundlePath, nil)
	if err == nil {
		t.Error("expected error for invalid bundle file")
	}
}

func TestLoadHybridSignerBundle_OnlyOneKey(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a file with only one key
	signer, _ := GenerateSoftwareSigner(AlgECDSAP256)
	keyPath := filepath.Join(tmpDir, "single.key.pem")
	_ = signer.SavePrivateKey(keyPath, nil)

	_, err := LoadHybridSignerBundle(keyPath, nil)
	if err == nil {
		t.Error("expected error when bundle contains only one key")
	}
}

// =============================================================================
// HybridKeyPair Tests
// =============================================================================

func TestHybridKeyPair_ToHybridSigner(t *testing.T) {
	hkp, err := GenerateHybridKeyPair(AlgHybridP256MLDSA44)
	if err != nil {
		t.Fatalf("GenerateHybridKeyPair failed: %v", err)
	}

	hybrid, err := hkp.ToHybridSigner()
	if err != nil {
		t.Fatalf("ToHybridSigner() failed: %v", err)
	}

	if hybrid.ClassicalAlgorithm() != hkp.Classical.Algorithm {
		t.Errorf("classical algorithm mismatch")
	}
	if hybrid.PQCAlgorithm() != hkp.PQC.Algorithm {
		t.Errorf("PQC algorithm mismatch")
	}

	// Verify can sign
	message := []byte("test")
	_, _, err = hybrid.SignHybrid(rand.Reader, message)
	if err != nil {
		t.Fatalf("SignHybrid() failed: %v", err)
	}
}

// =============================================================================
// Interface Compliance Tests
// =============================================================================

func TestHybridSigner_ImplementsSigner(t *testing.T) {
	hybrid, _ := GenerateHybridSigner(AlgECDSAP256, AlgMLDSA65)

	// Verify it implements Signer interface
	var _ Signer = hybrid
}

func TestHybridSigner_ImplementsHybridSigner(t *testing.T) {
	hybrid, _ := GenerateHybridSigner(AlgECDSAP256, AlgMLDSA65)

	// Verify it implements HybridSigner interface
	var _ HybridSigner = hybrid
}

// =============================================================================
// Edge Cases
// =============================================================================

func TestHybridSigner_EmptyMessage(t *testing.T) {
	hybrid, _ := GenerateHybridSigner(AlgECDSAP256, AlgMLDSA65)

	emptyMessage := []byte{}
	classicalSig, pqcSig, err := hybrid.SignHybrid(rand.Reader, emptyMessage)
	if err != nil {
		t.Fatalf("SignHybrid() with empty message failed: %v", err)
	}

	if !hybrid.VerifyHybrid(emptyMessage, classicalSig, pqcSig) {
		t.Error("verification of empty message signature failed")
	}
}

func TestHybridSigner_LargeMessage(t *testing.T) {
	hybrid, _ := GenerateHybridSigner(AlgECDSAP256, AlgMLDSA65)

	// 1MB message
	largeMessage := make([]byte, 1024*1024)
	_, _ = rand.Read(largeMessage)

	classicalSig, pqcSig, err := hybrid.SignHybrid(rand.Reader, largeMessage)
	if err != nil {
		t.Fatalf("SignHybrid() with large message failed: %v", err)
	}

	if !hybrid.VerifyHybrid(largeMessage, classicalSig, pqcSig) {
		t.Error("verification of large message signature failed")
	}
}

// =============================================================================
// Benchmarks
// =============================================================================

func BenchmarkHybridSigner_SignHybrid(b *testing.B) {
	hybrid, _ := GenerateHybridSigner(AlgECDSAP256, AlgMLDSA65)
	message := []byte("benchmark message for hybrid signing")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = hybrid.SignHybrid(rand.Reader, message)
	}
}

func BenchmarkHybridSigner_VerifyHybrid(b *testing.B) {
	hybrid, _ := GenerateHybridSigner(AlgECDSAP256, AlgMLDSA65)
	message := []byte("benchmark message for hybrid verification")
	classicalSig, pqcSig, _ := hybrid.SignHybrid(rand.Reader, message)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hybrid.VerifyHybrid(message, classicalSig, pqcSig)
	}
}

func BenchmarkGenerateHybridSigner(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = GenerateHybridSigner(AlgECDSAP256, AlgMLDSA65)
	}
}

// =============================================================================
// Additional Coverage Tests
// =============================================================================

func TestHybridSigner_SaveLoadBundle_RSA(t *testing.T) {
	tmpDir := t.TempDir()

	hybrid, err := GenerateHybridSigner(AlgRSA2048, AlgMLDSA65)
	if err != nil {
		t.Fatalf("GenerateHybridSigner failed: %v", err)
	}

	bundlePath := filepath.Join(tmpDir, "rsa-hybrid.key.pem")

	// Save bundle with RSA classical key
	if err := hybrid.SaveHybridKeyBundle(bundlePath, nil); err != nil {
		t.Fatalf("SaveHybridKeyBundle() failed: %v", err)
	}

	// Load bundle
	loaded, err := LoadHybridSignerBundle(bundlePath, nil)
	if err != nil {
		t.Fatalf("LoadHybridSignerBundle() failed: %v", err)
	}

	if loaded.ClassicalAlgorithm() != AlgRSA2048 {
		t.Errorf("loaded classical algorithm = %s, want %s", loaded.ClassicalAlgorithm(), AlgRSA2048)
	}
}

func TestHybridSigner_SaveLoadBundle_Ed25519(t *testing.T) {
	tmpDir := t.TempDir()

	hybrid, err := GenerateHybridSigner(AlgEd25519, AlgMLDSA65)
	if err != nil {
		t.Fatalf("GenerateHybridSigner failed: %v", err)
	}

	bundlePath := filepath.Join(tmpDir, "ed25519-hybrid.key.pem")

	if err := hybrid.SaveHybridKeyBundle(bundlePath, nil); err != nil {
		t.Fatalf("SaveHybridKeyBundle() failed: %v", err)
	}

	loaded, err := LoadHybridSignerBundle(bundlePath, nil)
	if err != nil {
		t.Fatalf("LoadHybridSignerBundle() failed: %v", err)
	}

	if loaded.ClassicalAlgorithm() != AlgEd25519 {
		t.Errorf("loaded classical algorithm = %s, want %s", loaded.ClassicalAlgorithm(), AlgEd25519)
	}
}

func TestHybridSigner_SaveLoadBundle_MLDSA44(t *testing.T) {
	tmpDir := t.TempDir()

	hybrid, err := GenerateHybridSigner(AlgECDSAP256, AlgMLDSA44)
	if err != nil {
		t.Fatalf("GenerateHybridSigner failed: %v", err)
	}

	bundlePath := filepath.Join(tmpDir, "mldsa44-hybrid.key.pem")

	if err := hybrid.SaveHybridKeyBundle(bundlePath, nil); err != nil {
		t.Fatalf("SaveHybridKeyBundle() failed: %v", err)
	}

	loaded, err := LoadHybridSignerBundle(bundlePath, nil)
	if err != nil {
		t.Fatalf("LoadHybridSignerBundle() failed: %v", err)
	}

	if loaded.PQCAlgorithm() != AlgMLDSA44 {
		t.Errorf("loaded PQC algorithm = %s, want %s", loaded.PQCAlgorithm(), AlgMLDSA44)
	}
}

func TestHybridSigner_SaveLoadBundle_MLDSA87(t *testing.T) {
	tmpDir := t.TempDir()

	hybrid, err := GenerateHybridSigner(AlgECDSAP521, AlgMLDSA87)
	if err != nil {
		t.Fatalf("GenerateHybridSigner failed: %v", err)
	}

	bundlePath := filepath.Join(tmpDir, "mldsa87-hybrid.key.pem")

	if err := hybrid.SaveHybridKeyBundle(bundlePath, nil); err != nil {
		t.Fatalf("SaveHybridKeyBundle() failed: %v", err)
	}

	loaded, err := LoadHybridSignerBundle(bundlePath, nil)
	if err != nil {
		t.Fatalf("LoadHybridSignerBundle() failed: %v", err)
	}

	if loaded.PQCAlgorithm() != AlgMLDSA87 {
		t.Errorf("loaded PQC algorithm = %s, want %s", loaded.PQCAlgorithm(), AlgMLDSA87)
	}
}

func TestLoadHybridSigner_FileNotFound(t *testing.T) {
	_, err := LoadHybridSigner("/nonexistent/classical.pem", "/nonexistent/pqc.pem", nil)
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestLoadHybridSignerBundle_FileNotFound(t *testing.T) {
	_, err := LoadHybridSignerBundle("/nonexistent/bundle.pem", nil)
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestSaveHybridKeys_InvalidPath(t *testing.T) {
	hybrid, _ := GenerateHybridSigner(AlgECDSAP256, AlgMLDSA65)

	err := hybrid.SaveHybridKeys("/nonexistent/dir/classical.pem", "/nonexistent/dir/pqc.pem", nil)
	if err == nil {
		t.Error("expected error for invalid path")
	}
}

func TestSaveHybridKeyBundle_InvalidPath(t *testing.T) {
	hybrid, _ := GenerateHybridSigner(AlgECDSAP256, AlgMLDSA65)

	err := hybrid.SaveHybridKeyBundle("/nonexistent/dir/bundle.pem", nil)
	if err == nil {
		t.Error("expected error for invalid path")
	}
}

// =============================================================================
// Additional Coverage Tests for Error Paths
// =============================================================================

// mockFailingSigner is a signer that always fails on Sign()
type mockFailingSigner struct {
	alg AlgorithmID
	pub crypto.PublicKey
}

func (m *mockFailingSigner) Algorithm() AlgorithmID { return m.alg }
func (m *mockFailingSigner) Public() crypto.PublicKey { return m.pub }
func (m *mockFailingSigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, fmt.Errorf("mock sign failure")
}

func TestSignHybrid_ClassicalSignFails(t *testing.T) {
	// Create a hybrid signer with failing classical signer
	pqc, _ := GenerateSoftwareSigner(AlgMLDSA65)
	classical, _ := GenerateSoftwareSigner(AlgECDSAP256)

	hybrid, err := NewHybridSigner(classical, pqc)
	if err != nil {
		t.Fatalf("NewHybridSigner failed: %v", err)
	}

	// Replace classical signer with a failing one
	hybrid.classical = &mockFailingSigner{alg: AlgECDSAP256, pub: classical.Public()}

	_, _, err = hybrid.SignHybrid(rand.Reader, []byte("test"))
	if err == nil {
		t.Error("expected error when classical signing fails")
	}
	if !contains(err.Error(), "classical signing failed") {
		t.Errorf("error message should mention classical signing: %v", err)
	}
}

func TestSignHybrid_PQCSignFails(t *testing.T) {
	// Create a hybrid signer with failing PQC signer
	classical, _ := GenerateSoftwareSigner(AlgECDSAP256)
	pqc, _ := GenerateSoftwareSigner(AlgMLDSA65)

	hybrid, err := NewHybridSigner(classical, pqc)
	if err != nil {
		t.Fatalf("NewHybridSigner failed: %v", err)
	}

	// Replace PQC signer with a failing one
	hybrid.pqc = &mockFailingSigner{alg: AlgMLDSA65, pub: pqc.Public()}

	_, _, err = hybrid.SignHybrid(rand.Reader, []byte("test"))
	if err == nil {
		t.Error("expected error when PQC signing fails")
	}
	if !contains(err.Error(), "PQC signing failed") {
		t.Errorf("error message should mention PQC signing: %v", err)
	}
}

// mockNonSoftwareSigner is a non-SoftwareSigner that cannot be saved
type mockNonSoftwareSigner struct {
	alg AlgorithmID
	pub crypto.PublicKey
}

func (m *mockNonSoftwareSigner) Algorithm() AlgorithmID { return m.alg }
func (m *mockNonSoftwareSigner) Public() crypto.PublicKey { return m.pub }
func (m *mockNonSoftwareSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	return digest, nil
}

func TestSaveHybridKeys_NonSoftwareSignerClassical(t *testing.T) {
	tmpDir := t.TempDir()
	pqc, _ := GenerateSoftwareSigner(AlgMLDSA65)
	classical, _ := GenerateSoftwareSigner(AlgECDSAP256)

	hybrid, _ := NewHybridSigner(classical, pqc)
	// Replace classical with non-SoftwareSigner
	hybrid.classical = &mockNonSoftwareSigner{alg: AlgECDSAP256, pub: classical.Public()}

	err := hybrid.SaveHybridKeys(
		filepath.Join(tmpDir, "classical.pem"),
		filepath.Join(tmpDir, "pqc.pem"),
		nil,
	)
	if err == nil {
		t.Error("expected error for non-SoftwareSigner classical")
	}
	if !contains(err.Error(), "classical signer is not a SoftwareSigner") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSaveHybridKeys_NonSoftwareSignerPQC(t *testing.T) {
	tmpDir := t.TempDir()
	classical, _ := GenerateSoftwareSigner(AlgECDSAP256)
	pqc, _ := GenerateSoftwareSigner(AlgMLDSA65)

	hybrid, _ := NewHybridSigner(classical, pqc)
	// Replace PQC with non-SoftwareSigner
	hybrid.pqc = &mockNonSoftwareSigner{alg: AlgMLDSA65, pub: pqc.Public()}

	err := hybrid.SaveHybridKeys(
		filepath.Join(tmpDir, "classical.pem"),
		filepath.Join(tmpDir, "pqc.pem"),
		nil,
	)
	if err == nil {
		t.Error("expected error for non-SoftwareSigner PQC")
	}
	if !contains(err.Error(), "PQC signer is not a SoftwareSigner") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSaveHybridKeyBundle_NonSoftwareSignerClassical(t *testing.T) {
	tmpDir := t.TempDir()
	pqc, _ := GenerateSoftwareSigner(AlgMLDSA65)
	classical, _ := GenerateSoftwareSigner(AlgECDSAP256)

	hybrid, _ := NewHybridSigner(classical, pqc)
	// Replace classical with non-SoftwareSigner
	hybrid.classical = &mockNonSoftwareSigner{alg: AlgECDSAP256, pub: classical.Public()}

	err := hybrid.SaveHybridKeyBundle(filepath.Join(tmpDir, "bundle.pem"), nil)
	if err == nil {
		t.Error("expected error for non-SoftwareSigner classical")
	}
	if !contains(err.Error(), "classical signer is not a SoftwareSigner") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSaveHybridKeyBundle_NonSoftwareSignerPQC(t *testing.T) {
	tmpDir := t.TempDir()
	classical, _ := GenerateSoftwareSigner(AlgECDSAP256)
	pqc, _ := GenerateSoftwareSigner(AlgMLDSA65)

	hybrid, _ := NewHybridSigner(classical, pqc)
	// Replace PQC with non-SoftwareSigner
	hybrid.pqc = &mockNonSoftwareSigner{alg: AlgMLDSA65, pub: pqc.Public()}

	err := hybrid.SaveHybridKeyBundle(filepath.Join(tmpDir, "bundle.pem"), nil)
	if err == nil {
		t.Error("expected error for non-SoftwareSigner PQC")
	}
	if !contains(err.Error(), "PQC signer is not a SoftwareSigner") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestParsePEMBlockToSigner_ECPrivateKey(t *testing.T) {
	// Generate an EC key and save it as EC PRIVATE KEY format
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "ec.key.pem")

	signer, err := GenerateSoftwareSigner(AlgECDSAP256)
	if err != nil {
		t.Fatalf("failed to generate signer: %v", err)
	}

	// Get the private key and encode as EC PRIVATE KEY
	ecKey := signer.PrivateKey().(*ecdsa.PrivateKey)
	ecBytes, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatalf("failed to marshal EC key: %v", err)
	}

	pemBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: ecBytes,
	}
	pemData := pem.EncodeToMemory(pemBlock)
	if err := os.WriteFile(keyPath, pemData, 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	// Load as bundle first block
	data, _ := os.ReadFile(keyPath)
	block, _ := pem.Decode(data)

	parsed, err := parsePEMBlockToSigner(block, nil)
	if err != nil {
		t.Fatalf("parsePEMBlockToSigner failed: %v", err)
	}

	if parsed.Algorithm() != AlgECDSAP256 {
		t.Errorf("algorithm = %s, want %s", parsed.Algorithm(), AlgECDSAP256)
	}
}

func TestParsePEMBlockToSigner_RSAPrivateKey(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "rsa.key.pem")

	signer, err := GenerateSoftwareSigner(AlgRSA2048)
	if err != nil {
		t.Fatalf("failed to generate signer: %v", err)
	}

	// Get the private key and encode as RSA PRIVATE KEY
	rsaKey := signer.PrivateKey().(*rsa.PrivateKey)
	rsaBytes := x509.MarshalPKCS1PrivateKey(rsaKey)

	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: rsaBytes,
	}
	pemData := pem.EncodeToMemory(pemBlock)
	if err := os.WriteFile(keyPath, pemData, 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	data, _ := os.ReadFile(keyPath)
	block, _ := pem.Decode(data)

	parsed, err := parsePEMBlockToSigner(block, nil)
	if err != nil {
		t.Fatalf("parsePEMBlockToSigner failed: %v", err)
	}

	if parsed.Algorithm() != AlgRSA2048 {
		t.Errorf("algorithm = %s, want %s", parsed.Algorithm(), AlgRSA2048)
	}
}

func TestParsePEMBlockToSigner_UnknownType(t *testing.T) {
	block := &pem.Block{
		Type:  "UNKNOWN KEY TYPE",
		Bytes: []byte("some data"),
	}

	_, err := parsePEMBlockToSigner(block, nil)
	if err == nil {
		t.Error("expected error for unknown PEM type")
	}
	if !contains(err.Error(), "unknown PEM type") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestParsePEMBlockToSigner_InvalidPKCS8(t *testing.T) {
	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: []byte("invalid pkcs8 data"),
	}

	_, err := parsePEMBlockToSigner(block, nil)
	if err == nil {
		t.Error("expected error for invalid PKCS8 data")
	}
}

func TestParsePEMBlockToSigner_InvalidECKey(t *testing.T) {
	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: []byte("invalid ec data"),
	}

	_, err := parsePEMBlockToSigner(block, nil)
	if err == nil {
		t.Error("expected error for invalid EC data")
	}
}

func TestParsePEMBlockToSigner_InvalidRSAKey(t *testing.T) {
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: []byte("invalid rsa data"),
	}

	_, err := parsePEMBlockToSigner(block, nil)
	if err == nil {
		t.Error("expected error for invalid RSA data")
	}
}

func TestParsePEMBlockToSigner_InvalidMLDSA44(t *testing.T) {
	block := &pem.Block{
		Type:  "ML-DSA-44 PRIVATE KEY",
		Bytes: []byte("invalid mldsa44 data"),
	}

	_, err := parsePEMBlockToSigner(block, nil)
	if err == nil {
		t.Error("expected error for invalid ML-DSA-44 data")
	}
}

func TestParsePEMBlockToSigner_InvalidMLDSA65(t *testing.T) {
	block := &pem.Block{
		Type:  "ML-DSA-65 PRIVATE KEY",
		Bytes: []byte("invalid mldsa65 data"),
	}

	_, err := parsePEMBlockToSigner(block, nil)
	if err == nil {
		t.Error("expected error for invalid ML-DSA-65 data")
	}
}

func TestParsePEMBlockToSigner_InvalidMLDSA87(t *testing.T) {
	block := &pem.Block{
		Type:  "ML-DSA-87 PRIVATE KEY",
		Bytes: []byte("invalid mldsa87 data"),
	}

	_, err := parsePEMBlockToSigner(block, nil)
	if err == nil {
		t.Error("expected error for invalid ML-DSA-87 data")
	}
}

func TestPrivateKeyToPEMBlock_UnsupportedType(t *testing.T) {
	// Use a type that's not supported
	type unsupportedKey struct{}

	_, err := privateKeyToPEMBlock(&unsupportedKey{}, "test", nil)
	if err == nil {
		t.Error("expected error for unsupported key type")
	}
	if !contains(err.Error(), "unsupported private key type") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestHybridSigner_SaveLoadBundle_SLHDSA(t *testing.T) {
	tmpDir := t.TempDir()

	// Test with SLH-DSA-SHA2-128f (fast variant for testing)
	hybrid, err := GenerateHybridSigner(AlgECDSAP256, AlgSLHDSA128f)
	if err != nil {
		t.Fatalf("GenerateHybridSigner failed: %v", err)
	}

	bundlePath := filepath.Join(tmpDir, "slhdsa-hybrid.key.pem")

	if err := hybrid.SaveHybridKeyBundle(bundlePath, nil); err != nil {
		t.Fatalf("SaveHybridKeyBundle() failed: %v", err)
	}

	loaded, err := LoadHybridSignerBundle(bundlePath, nil)
	if err != nil {
		t.Fatalf("LoadHybridSignerBundle() failed: %v", err)
	}

	if loaded.PQCAlgorithm() != AlgSLHDSA128f {
		t.Errorf("loaded PQC algorithm = %s, want %s", loaded.PQCAlgorithm(), AlgSLHDSA128f)
	}

	// Verify signing works with loaded signer
	message := []byte("test message")
	classicalSig, pqcSig, err := loaded.SignHybrid(rand.Reader, message)
	if err != nil {
		t.Fatalf("SignHybrid() failed: %v", err)
	}

	if !loaded.VerifyHybrid(message, classicalSig, pqcSig) {
		t.Error("VerifyHybrid() failed")
	}
}

func TestToHybridSigner_NilClassicalKeyPair(t *testing.T) {
	// Create a HybridKeyPair with nil classical KeyPair
	pqc, _ := GenerateSoftwareSigner(AlgMLDSA65)

	hkp := &HybridKeyPair{
		Classical: nil, // Invalid - nil KeyPair
		PQC: &KeyPair{
			Algorithm:  AlgMLDSA65,
			PrivateKey: pqc.PrivateKey(),
			PublicKey:  pqc.Public(),
		},
	}

	_, err := hkp.ToHybridSigner()
	if err == nil {
		t.Error("expected error for nil classical KeyPair")
	}
}

func TestToHybridSigner_NilPQCKeyPair(t *testing.T) {
	// Create a HybridKeyPair with nil PQC KeyPair
	classical, _ := GenerateSoftwareSigner(AlgECDSAP256)

	hkp := &HybridKeyPair{
		Classical: &KeyPair{
			Algorithm:  AlgECDSAP256,
			PrivateKey: classical.PrivateKey(),
			PublicKey:  classical.Public(),
		},
		PQC: nil, // Invalid - nil KeyPair
	}

	_, err := hkp.ToHybridSigner()
	if err == nil {
		t.Error("expected error for nil PQC KeyPair")
	}
}

func TestLoadHybridSigner_PQCFileNotFound(t *testing.T) {
	tmpDir := t.TempDir()

	// Create only classical key
	classical, _ := GenerateSoftwareSigner(AlgECDSAP256)
	classicalPath := filepath.Join(tmpDir, "classical.pem")
	_ = classical.SavePrivateKey(classicalPath, nil)

	_, err := LoadHybridSigner(classicalPath, "/nonexistent/pqc.pem", nil)
	if err == nil {
		t.Error("expected error for non-existent PQC file")
	}
	if !contains(err.Error(), "failed to load PQC key") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestParsePEMBlockToSigner_EncryptedWithoutPassphrase(t *testing.T) {
	tmpDir := t.TempDir()

	// Save an encrypted key
	signer, _ := GenerateSoftwareSigner(AlgECDSAP256)
	keyPath := filepath.Join(tmpDir, "encrypted.pem")
	if err := signer.SavePrivateKey(keyPath, []byte("password")); err != nil {
		t.Fatalf("failed to save encrypted key: %v", err)
	}

	data, _ := os.ReadFile(keyPath)
	block, _ := pem.Decode(data)

	// Try to parse without passphrase
	_, err := parsePEMBlockToSigner(block, nil)
	if err == nil {
		t.Error("expected error for encrypted key without passphrase")
	}
	if !contains(err.Error(), "no passphrase provided") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestParsePEMBlockToSigner_EncryptedWrongPassphrase(t *testing.T) {
	tmpDir := t.TempDir()

	// Save an encrypted key
	signer, _ := GenerateSoftwareSigner(AlgECDSAP256)
	keyPath := filepath.Join(tmpDir, "encrypted.pem")
	if err := signer.SavePrivateKey(keyPath, []byte("correctpassword")); err != nil {
		t.Fatalf("failed to save encrypted key: %v", err)
	}

	data, _ := os.ReadFile(keyPath)
	block, _ := pem.Decode(data)

	// Try to parse with wrong passphrase
	_, err := parsePEMBlockToSigner(block, []byte("wrongpassword"))
	if err == nil {
		t.Error("expected error for wrong passphrase")
	}
}

// helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
