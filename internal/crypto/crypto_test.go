package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"os"
	"path/filepath"
	"testing"
)

// =============================================================================
// [Unit] Algorithm Property Tests
// =============================================================================

func TestU_Algorithm_Properties(t *testing.T) {
	tests := []struct {
		name        string
		alg         AlgorithmID
		wantValid   bool
		wantClassic bool
		wantPQC     bool
		wantHybrid  bool
		wantSig     bool
		wantKEM     bool
	}{
		{"[Unit] Properties: EC P-256", AlgECDSAP256, true, true, false, false, true, false},
		{"[Unit] Properties: EC P-384", AlgECDSAP384, true, true, false, false, true, false},
		{"[Unit] Properties: EC P-521", AlgECDSAP521, true, true, false, false, true, false},
		{"[Unit] Properties: Ed25519", AlgEd25519, true, true, false, false, true, false},
		{"[Unit] Properties: RSA-2048", AlgRSA2048, true, true, false, false, true, false},
		{"[Unit] Properties: RSA-4096", AlgRSA4096, true, true, false, false, true, false},
		{"[Unit] Properties: ML-DSA-44", AlgMLDSA44, true, false, true, false, true, false},
		{"[Unit] Properties: ML-DSA-65", AlgMLDSA65, true, false, true, false, true, false},
		{"[Unit] Properties: ML-DSA-87", AlgMLDSA87, true, false, true, false, true, false},
		{"[Unit] Properties: ML-KEM-512", AlgMLKEM512, true, false, true, false, false, true},
		{"[Unit] Properties: ML-KEM-768", AlgMLKEM768, true, false, true, false, false, true},
		{"[Unit] Properties: ML-KEM-1024", AlgMLKEM1024, true, false, true, false, false, true},
		{"[Unit] Properties: SLH-DSA-128s", AlgSLHDSA128s, true, false, true, false, true, false},
		{"[Unit] Properties: SLH-DSA-128f", AlgSLHDSA128f, true, false, true, false, true, false},
		{"[Unit] Properties: SLH-DSA-192s", AlgSLHDSA192s, true, false, true, false, true, false},
		{"[Unit] Properties: SLH-DSA-192f", AlgSLHDSA192f, true, false, true, false, true, false},
		{"[Unit] Properties: SLH-DSA-256s", AlgSLHDSA256s, true, false, true, false, true, false},
		{"[Unit] Properties: SLH-DSA-256f", AlgSLHDSA256f, true, false, true, false, true, false},
		{"[Unit] Properties: Hybrid P-256 + ML-DSA-44", AlgHybridP256MLDSA44, true, false, false, true, false, false},
		{"[Unit] Properties: Hybrid P-384 + ML-DSA-65", AlgHybridP384MLDSA65, true, false, false, true, false, false},
		{"[Unit] Properties: Invalid Algorithm", "invalid", false, false, false, false, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.alg.IsValid(); got != tt.wantValid {
				t.Errorf("IsValid() = %v, want %v", got, tt.wantValid)
			}
			if got := tt.alg.IsClassical(); got != tt.wantClassic {
				t.Errorf("IsClassical() = %v, want %v", got, tt.wantClassic)
			}
			if got := tt.alg.IsPQC(); got != tt.wantPQC {
				t.Errorf("IsPQC() = %v, want %v", got, tt.wantPQC)
			}
			if got := tt.alg.IsHybrid(); got != tt.wantHybrid {
				t.Errorf("IsHybrid() = %v, want %v", got, tt.wantHybrid)
			}
			if got := tt.alg.IsSignature(); got != tt.wantSig {
				t.Errorf("IsSignature() = %v, want %v", got, tt.wantSig)
			}
			if got := tt.alg.IsKEM(); got != tt.wantKEM {
				t.Errorf("IsKEM() = %v, want %v", got, tt.wantKEM)
			}
		})
	}
}

func TestU_Algorithm_OID(t *testing.T) {
	tests := []struct {
		name    string
		alg     AlgorithmID
		wantOID bool
	}{
		{"[Unit] OID: EC P-256", AlgECDSAP256, true},
		{"[Unit] OID: Ed25519", AlgEd25519, true},
		{"[Unit] OID: ML-DSA-65", AlgMLDSA65, true},
		{"[Unit] OID: Invalid", "invalid", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oid := tt.alg.OID()
			if tt.wantOID && oid == nil {
				t.Error("expected OID, got nil")
			}
			if !tt.wantOID && oid != nil {
				t.Errorf("expected nil OID, got %v", oid)
			}
		})
	}
}

func TestU_ParseAlgorithm(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    AlgorithmID
		wantErr bool
	}{
		{"[Unit] Parse: ECDSA P-256", "ecdsa-p256", AlgECDSAP256, false},
		{"[Unit] Parse: ML-DSA-65", "ml-dsa-65", AlgMLDSA65, false},
		{"[Unit] Parse: Invalid", "invalid", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseAlgorithm(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseAlgorithm() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ParseAlgorithm() = %v, want %v", got, tt.want)
			}
		})
	}
}

// =============================================================================
// [Unit] Key Generation Tests
// =============================================================================

// TestU_KeyGen_SignatureAlgorithms tests key generation for all signature algorithms.
func TestU_KeyGen_SignatureAlgorithms(t *testing.T) {
	signatureAlgs := []AlgorithmID{
		AlgECDSAP256,
		AlgECDSAP384,
		AlgECDSAP521,
		AlgEd25519,
		AlgRSA2048,
		// AlgRSA4096, // Skip in tests - too slow
		AlgMLDSA44,
		AlgMLDSA65,
		AlgMLDSA87,
		AlgSLHDSA128f, // Test one SLH-DSA variant (fast signing)
	}

	for _, alg := range signatureAlgs {
		t.Run(string(alg), func(t *testing.T) {
			kp, err := GenerateKeyPair(alg)
			if err != nil {
				t.Fatalf("GenerateKeyPair(%s) error = %v", alg, err)
			}

			if kp.Algorithm != alg {
				t.Errorf("Algorithm = %v, want %v", kp.Algorithm, alg)
			}
			if kp.PrivateKey == nil {
				t.Error("PrivateKey is nil")
			}
			if kp.PublicKey == nil {
				t.Error("PublicKey is nil")
			}
		})
	}
}

// TestU_KeyGen_AlgorithmInvalid tests that invalid algorithms are rejected.
func TestU_KeyGen_AlgorithmInvalid(t *testing.T) {
	_, err := GenerateKeyPair("invalid")
	if err == nil {
		t.Error("expected error for invalid algorithm")
	}
}

// TestU_KeyGen_HybridRequiresSpecialFunction tests that hybrid algorithms require special function.
func TestU_KeyGen_HybridRequiresSpecialFunction(t *testing.T) {
	_, err := GenerateKeyPair(AlgHybridP256MLDSA44)
	if err == nil {
		t.Error("expected error for hybrid algorithm")
	}
}

// TestU_KeyGen_HybridAlgorithms tests hybrid key generation.
func TestU_KeyGen_HybridAlgorithms(t *testing.T) {
	hybridAlgs := []struct {
		alg          AlgorithmID
		classicalAlg AlgorithmID
		pqcAlg       AlgorithmID
	}{
		{AlgHybridP256MLDSA44, AlgECDSAP256, AlgMLDSA44},
		{AlgHybridP384MLDSA65, AlgECDSAP384, AlgMLDSA65},
	}

	for _, tt := range hybridAlgs {
		t.Run(string(tt.alg), func(t *testing.T) {
			hkp, err := GenerateHybridKeyPair(tt.alg)
			if err != nil {
				t.Fatalf("GenerateHybridKeyPair(%s) error = %v", tt.alg, err)
			}

			if hkp.Algorithm != tt.alg {
				t.Errorf("Algorithm = %v, want %v", hkp.Algorithm, tt.alg)
			}
			if hkp.Classical.Algorithm != tt.classicalAlg {
				t.Errorf("Classical.Algorithm = %v, want %v", hkp.Classical.Algorithm, tt.classicalAlg)
			}
			if hkp.PQC.Algorithm != tt.pqcAlg {
				t.Errorf("PQC.Algorithm = %v, want %v", hkp.PQC.Algorithm, tt.pqcAlg)
			}
		})
	}
}

// TestSoftwareSigner_SignVerify tests signing and verification for all algorithms.
func TestSoftwareSigner_SignVerify(t *testing.T) {
	signatureAlgs := []AlgorithmID{
		AlgECDSAP256,
		AlgECDSAP384,
		AlgECDSAP521,
		AlgEd25519,
		AlgRSA2048,
		AlgMLDSA44,
		AlgMLDSA65,
		AlgMLDSA87,
		AlgSLHDSA128f, // Test one SLH-DSA variant (fast signing)
	}

	message := []byte("test message for signing")

	for _, alg := range signatureAlgs {
		t.Run(string(alg), func(t *testing.T) {
			signer, err := GenerateSoftwareSigner(alg)
			if err != nil {
				t.Fatalf("GenerateSoftwareSigner(%s) error = %v", alg, err)
			}

			// For classical algorithms, we sign the hash
			// For PQC algorithms, we sign the message directly
			var digest []byte
			var opts crypto.SignerOpts

			if alg.IsClassical() && !isEdDSA(alg) {
				h := sha256.Sum256(message)
				digest = h[:]
				opts = crypto.SHA256
			} else {
				// Ed25519 and PQC sign the message directly
				digest = message
			}

			sig, err := signer.Sign(rand.Reader, digest, opts)
			if err != nil {
				t.Fatalf("Sign() error = %v", err)
			}

			if len(sig) == 0 {
				t.Error("signature is empty")
			}

			// Verify
			valid := Verify(alg, signer.Public(), digest, sig)
			if !valid {
				t.Error("Verify() returned false, expected true")
			}

			// Verify with wrong message should fail
			wrongDigest := make([]byte, len(digest))
			copy(wrongDigest, digest)
			wrongDigest[0] ^= 0xFF // Flip bits in first byte
			if Verify(alg, signer.Public(), wrongDigest, sig) {
				t.Error("Verify() with wrong message should return false")
			}
		})
	}
}

func isEdDSA(alg AlgorithmID) bool {
	return alg == AlgEd25519
}

// TestSoftwareSigner_SaveLoad tests key serialization.
func TestSoftwareSigner_SaveLoad(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		alg        AlgorithmID
		passphrase []byte
	}{
		{AlgECDSAP256, nil},
		{AlgECDSAP256, []byte("testpassword")},
		{AlgEd25519, nil},
		{AlgMLDSA65, nil},
		{AlgSLHDSA128f, nil}, // Test SLH-DSA save/load
	}

	for _, tt := range tests {
		name := string(tt.alg)
		if tt.passphrase != nil {
			name += "-encrypted"
		}

		t.Run(name, func(t *testing.T) {
			// Generate key
			signer, err := GenerateSoftwareSigner(tt.alg)
			if err != nil {
				t.Fatalf("GenerateSoftwareSigner() error = %v", err)
			}

			// Save key
			keyPath := filepath.Join(tempDir, name+".key.pem")
			if err := signer.SavePrivateKey(keyPath, tt.passphrase); err != nil {
				t.Fatalf("SavePrivateKey() error = %v", err)
			}

			// Check file exists with correct permissions
			info, err := os.Stat(keyPath)
			if err != nil {
				t.Fatalf("Stat() error = %v", err)
			}
			if info.Mode().Perm() != 0600 {
				t.Errorf("key file permissions = %v, want 0600", info.Mode().Perm())
			}

			// Load key
			loaded, err := LoadPrivateKey(keyPath, tt.passphrase)
			if err != nil {
				t.Fatalf("LoadPrivateKey() error = %v", err)
			}

			if loaded.Algorithm() != tt.alg {
				t.Errorf("loaded Algorithm() = %v, want %v", loaded.Algorithm(), tt.alg)
			}

			// Sign with loaded key and verify with original
			message := []byte("test message")
			var digest []byte
			var opts crypto.SignerOpts

			// Classical algorithms (except Ed25519) sign the hash
			// Ed25519, PQC (ML-DSA, SLH-DSA) sign the message directly
			if tt.alg.IsClassical() && !isEdDSA(tt.alg) {
				h := sha256.Sum256(message)
				digest = h[:]
				opts = crypto.SHA256
			} else {
				digest = message
			}

			sig, err := loaded.Sign(rand.Reader, digest, opts)
			if err != nil {
				t.Fatalf("Sign() error = %v", err)
			}

			if !Verify(tt.alg, signer.Public(), digest, sig) {
				t.Error("signature from loaded key doesn't verify with original public key")
			}
		})
	}
}

// TestLoadPrivateKey_EncryptedWithoutPassphrase tests that loading encrypted key without passphrase fails.
func TestLoadPrivateKey_EncryptedWithoutPassphrase(t *testing.T) {
	tempDir := t.TempDir()

	signer, err := GenerateSoftwareSigner(AlgECDSAP256)
	if err != nil {
		t.Fatalf("GenerateSoftwareSigner() error = %v", err)
	}

	keyPath := filepath.Join(tempDir, "encrypted.key.pem")
	if err := signer.SavePrivateKey(keyPath, []byte("password")); err != nil {
		t.Fatalf("SavePrivateKey() error = %v", err)
	}

	_, err = LoadPrivateKey(keyPath, nil)
	if err == nil {
		t.Error("LoadPrivateKey() should fail without passphrase for encrypted key")
	}
}

// TestVerifierFromPublicKey tests the Verifier interface.
func TestVerifierFromPublicKey(t *testing.T) {
	signer, err := GenerateSoftwareSigner(AlgECDSAP256)
	if err != nil {
		t.Fatalf("GenerateSoftwareSigner() error = %v", err)
	}

	verifier, err := VerifierFromPublicKey(AlgECDSAP256, signer.Public())
	if err != nil {
		t.Fatalf("VerifierFromPublicKey() error = %v", err)
	}

	if verifier.Algorithm() != AlgECDSAP256 {
		t.Errorf("Algorithm() = %v, want %v", verifier.Algorithm(), AlgECDSAP256)
	}

	message := []byte("test message")
	h := sha256.Sum256(message)
	digest := h[:]

	sig, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	if !verifier.Verify(digest, sig) {
		t.Error("Verify() returned false, expected true")
	}
}

// TestAllAlgorithms tests that algorithm listing functions work.
func TestAllAlgorithms(t *testing.T) {
	all := AllAlgorithms()
	if len(all) == 0 {
		t.Error("AllAlgorithms() returned empty list")
	}

	sig := SignatureAlgorithms()
	if len(sig) == 0 {
		t.Error("SignatureAlgorithms() returned empty list")
	}

	classical := ClassicalAlgorithms()
	if len(classical) == 0 {
		t.Error("ClassicalAlgorithms() returned empty list")
	}

	pqc := PQCAlgorithms()
	if len(pqc) == 0 {
		t.Error("PQCAlgorithms() returned empty list")
	}
}

// =============================================================================
// SLH-DSA (SPHINCS+) All Variants Tests
// =============================================================================

// TestSLHDSA_AllVariants_Integration tests all 6 SLH-DSA variants.
// Note: The 's' (small) variants are significantly slower than 'f' (fast) variants.
func TestSLHDSA_AllVariants_Integration(t *testing.T) {
	variants := []struct {
		alg     AlgorithmID
		name    string
		isSlow  bool
	}{
		{AlgSLHDSA128s, "SLH-DSA-128s", true},
		{AlgSLHDSA128f, "SLH-DSA-128f", false},
		{AlgSLHDSA192s, "SLH-DSA-192s", true},
		{AlgSLHDSA192f, "SLH-DSA-192f", false},
		{AlgSLHDSA256s, "SLH-DSA-256s", true},
		{AlgSLHDSA256f, "SLH-DSA-256f", false},
	}

	message := []byte("SLH-DSA test message for signature verification")

	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			// Don't run slow variants in parallel (they can take 1-2 seconds each)
			if !v.isSlow {
				t.Parallel()
			}

			// Test key generation
			kp, err := GenerateKeyPair(v.alg)
			if err != nil {
				t.Fatalf("GenerateKeyPair(%s) error = %v", v.alg, err)
			}

			if kp.Algorithm != v.alg {
				t.Errorf("Algorithm = %v, want %v", kp.Algorithm, v.alg)
			}
			if kp.PrivateKey == nil {
				t.Error("PrivateKey is nil")
			}
			if kp.PublicKey == nil {
				t.Error("PublicKey is nil")
			}

			// Test signing
			signer, err := NewSoftwareSigner(kp)
			if err != nil {
				t.Fatalf("NewSoftwareSigner() error = %v", err)
			}

			sig, err := signer.Sign(rand.Reader, message, nil)
			if err != nil {
				t.Fatalf("Sign() error = %v", err)
			}

			if len(sig) == 0 {
				t.Error("Signature is empty")
			}

			// Test verification
			if !Verify(v.alg, kp.PublicKey, message, sig) {
				t.Error("Verify() returned false, expected true")
			}

			// Test verification with wrong message fails
			wrongMessage := []byte("wrong message")
			if Verify(v.alg, kp.PublicKey, wrongMessage, sig) {
				t.Error("Verify() should return false with wrong message")
			}
		})
	}
}

// TestSLHDSA_PublicKeyBytes tests public key serialization for all SLH-DSA variants.
func TestSLHDSA_PublicKeyBytes(t *testing.T) {
	// Test fast variants only for speed
	variants := []AlgorithmID{
		AlgSLHDSA128f,
		AlgSLHDSA192f,
		AlgSLHDSA256f,
	}

	for _, alg := range variants {
		t.Run(string(alg), func(t *testing.T) {
			t.Parallel()

			kp, err := GenerateKeyPair(alg)
			if err != nil {
				t.Fatalf("GenerateKeyPair() error = %v", err)
			}

			pubBytes, err := kp.PublicKeyBytes()
			if err != nil {
				t.Fatalf("PublicKeyBytes() error = %v", err)
			}

			if len(pubBytes) == 0 {
				t.Error("PublicKeyBytes() returned empty")
			}
		})
	}
}

// Benchmark key generation
func BenchmarkGenerateKeyPair_ECDSA_P256(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = GenerateKeyPair(AlgECDSAP256)
	}
}

func BenchmarkGenerateKeyPair_Ed25519(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = GenerateKeyPair(AlgEd25519)
	}
}

func BenchmarkGenerateKeyPair_MLDSA65(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = GenerateKeyPair(AlgMLDSA65)
	}
}

// Benchmark signing
func BenchmarkSign_ECDSA_P256(b *testing.B) {
	signer, _ := GenerateSoftwareSigner(AlgECDSAP256)
	message := []byte("benchmark message")
	h := sha256.Sum256(message)
	digest := h[:]

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = signer.Sign(rand.Reader, digest, crypto.SHA256)
	}
}

func BenchmarkSign_Ed25519(b *testing.B) {
	signer, _ := GenerateSoftwareSigner(AlgEd25519)
	message := []byte("benchmark message")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = signer.Sign(rand.Reader, message, nil)
	}
}

func BenchmarkSign_MLDSA65(b *testing.B) {
	signer, _ := GenerateSoftwareSigner(AlgMLDSA65)
	message := []byte("benchmark message")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = signer.Sign(rand.Reader, message, nil)
	}
}

func BenchmarkGenerateKeyPair_SLHDSA128f(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = GenerateKeyPair(AlgSLHDSA128f)
	}
}

func BenchmarkSign_SLHDSA128f(b *testing.B) {
	signer, _ := GenerateSoftwareSigner(AlgSLHDSA128f)
	message := []byte("benchmark message")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = signer.Sign(rand.Reader, message, nil)
	}
}

// Benchmark verification
func BenchmarkVerify_ECDSA_P256(b *testing.B) {
	signer, _ := GenerateSoftwareSigner(AlgECDSAP256)
	message := []byte("benchmark message")
	h := sha256.Sum256(message)
	digest := h[:]
	sig, _ := signer.Sign(rand.Reader, digest, crypto.SHA256)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Verify(AlgECDSAP256, signer.Public(), digest, sig)
	}
}

func BenchmarkVerify_Ed25519(b *testing.B) {
	signer, _ := GenerateSoftwareSigner(AlgEd25519)
	message := []byte("benchmark message")
	sig, _ := signer.Sign(rand.Reader, message, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Verify(AlgEd25519, signer.Public(), message, sig)
	}
}

func BenchmarkVerify_MLDSA65(b *testing.B) {
	signer, _ := GenerateSoftwareSigner(AlgMLDSA65)
	message := []byte("benchmark message")
	sig, _ := signer.Sign(rand.Reader, message, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Verify(AlgMLDSA65, signer.Public(), message, sig)
	}
}

func BenchmarkVerify_SLHDSA128f(b *testing.B) {
	signer, _ := GenerateSoftwareSigner(AlgSLHDSA128f)
	message := []byte("benchmark message")
	sig, _ := signer.Sign(rand.Reader, message, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Verify(AlgSLHDSA128f, signer.Public(), message, sig)
	}
}

// =============================================================================
// SignerOpts Tests
// =============================================================================

func TestSignerOptsConfig_HashFunc(t *testing.T) {
	tests := []struct {
		name     string
		config   *SignerOptsConfig
		wantHash crypto.Hash
	}{
		{"SHA256", &SignerOptsConfig{Hash: crypto.SHA256}, crypto.SHA256},
		{"SHA384", &SignerOptsConfig{Hash: crypto.SHA384}, crypto.SHA384},
		{"SHA512", &SignerOptsConfig{Hash: crypto.SHA512}, crypto.SHA512},
		{"NoHash", &SignerOptsConfig{Hash: 0}, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.config.HashFunc(); got != tt.wantHash {
				t.Errorf("HashFunc() = %v, want %v", got, tt.wantHash)
			}
		})
	}
}

func TestDefaultSignerOpts(t *testing.T) {
	tests := []struct {
		alg      AlgorithmID
		wantHash crypto.Hash
		wantPSS  bool
	}{
		{AlgECDSAP256, crypto.SHA256, false},
		{AlgECP256, crypto.SHA256, false},
		{AlgECDSAP384, crypto.SHA384, false},
		{AlgECP384, crypto.SHA384, false},
		{AlgECDSAP521, crypto.SHA512, false},
		{AlgECP521, crypto.SHA512, false},
		{AlgRSA2048, crypto.SHA256, true},
		{AlgRSA4096, crypto.SHA256, true},
		{AlgEd25519, 0, false},
		{AlgMLDSA65, 0, false},
		{AlgSLHDSA128f, 0, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.alg), func(t *testing.T) {
			opts := DefaultSignerOpts(tt.alg)
			if opts == nil {
				t.Fatal("expected non-nil opts")
			}
			if opts.Hash != tt.wantHash {
				t.Errorf("Hash = %v, want %v", opts.Hash, tt.wantHash)
			}
			if opts.UsePSS != tt.wantPSS {
				t.Errorf("UsePSS = %v, want %v", opts.UsePSS, tt.wantPSS)
			}
		})
	}
}

func TestRSAPKCSSignerOpts(t *testing.T) {
	tests := []struct {
		hash crypto.Hash
	}{
		{crypto.SHA256},
		{crypto.SHA384},
		{crypto.SHA512},
	}

	for _, tt := range tests {
		t.Run(tt.hash.String(), func(t *testing.T) {
			opts := RSAPKCSSignerOpts(tt.hash)
			if opts.Hash != tt.hash {
				t.Errorf("Hash = %v, want %v", opts.Hash, tt.hash)
			}
			if opts.UsePSS {
				t.Error("UsePSS should be false for PKCS#1 v1.5")
			}
			if opts.PSSOptions != nil {
				t.Error("PSSOptions should be nil for PKCS#1 v1.5")
			}
		})
	}
}

func TestRSAPSSSignerOpts(t *testing.T) {
	tests := []struct {
		hash       crypto.Hash
		saltLength int
	}{
		{crypto.SHA256, 32},
		{crypto.SHA384, 48},
		{crypto.SHA512, 64},
	}

	for _, tt := range tests {
		t.Run(tt.hash.String(), func(t *testing.T) {
			opts := RSAPSSSignerOpts(tt.hash, tt.saltLength)
			if opts.Hash != tt.hash {
				t.Errorf("Hash = %v, want %v", opts.Hash, tt.hash)
			}
			if !opts.UsePSS {
				t.Error("UsePSS should be true for PSS")
			}
			if opts.PSSOptions == nil {
				t.Fatal("PSSOptions should not be nil")
			}
			if opts.PSSOptions.SaltLength != tt.saltLength {
				t.Errorf("SaltLength = %v, want %v", opts.PSSOptions.SaltLength, tt.saltLength)
			}
			if opts.PSSOptions.Hash != tt.hash {
				t.Errorf("PSSOptions.Hash = %v, want %v", opts.PSSOptions.Hash, tt.hash)
			}
		})
	}
}

func TestRSAPSSSignerOptsWithMGF(t *testing.T) {
	hash := crypto.SHA256
	mgfHash := crypto.SHA512
	saltLength := 32

	opts := RSAPSSSignerOptsWithMGF(hash, saltLength, mgfHash)

	if opts.Hash != hash {
		t.Errorf("Hash = %v, want %v", opts.Hash, hash)
	}
	if !opts.UsePSS {
		t.Error("UsePSS should be true")
	}
	if opts.PSSOptions == nil {
		t.Fatal("PSSOptions should not be nil")
	}
	if opts.PSSOptions.SaltLength != saltLength {
		t.Errorf("SaltLength = %v, want %v", opts.PSSOptions.SaltLength, saltLength)
	}
	// Note: Go's RSA implementation doesn't support different MGF hash
	if opts.PSSOptions.Hash != hash {
		t.Errorf("PSSOptions.Hash = %v, want %v", opts.PSSOptions.Hash, hash)
	}
}

// =============================================================================
// Algorithm X509SignatureAlgorithm Tests
// =============================================================================

func TestAlgorithmID_X509SignatureAlgorithm(t *testing.T) {
	tests := []struct {
		alg    AlgorithmID
		wantID bool
	}{
		{AlgECDSAP256, true},
		{AlgECDSAP384, true},
		{AlgECDSAP521, true},
		{AlgRSA2048, true},
		{AlgEd25519, true},
		{AlgMLDSA65, false}, // PQC uses UnknownSignatureAlgorithm
		{"invalid", false},
	}

	for _, tt := range tests {
		t.Run(string(tt.alg), func(t *testing.T) {
			sigAlg := tt.alg.X509SignatureAlgorithm()
			// For classical algorithms, sigAlg should not be UnknownSignatureAlgorithm
			if tt.wantID && sigAlg == 0 {
				t.Error("expected valid signature algorithm")
			}
		})
	}
}

// =============================================================================
// Algorithm Description Tests
// =============================================================================

func TestAlgorithmID_Description(t *testing.T) {
	tests := []struct {
		alg             AlgorithmID
		wantKnown       bool
	}{
		{AlgECDSAP256, true},
		{AlgMLDSA65, true},
		{AlgRSA2048, true},
		{AlgEd25519, true},
		{"invalid", false},
	}

	for _, tt := range tests {
		t.Run(string(tt.alg), func(t *testing.T) {
			desc := tt.alg.Description()
			if tt.wantKnown && desc == "Unknown algorithm" {
				t.Error("expected known algorithm description")
			}
			if !tt.wantKnown && desc != "Unknown algorithm" {
				t.Errorf("expected 'Unknown algorithm', got %q", desc)
			}
		})
	}
}

// =============================================================================
// AlgorithmFromOID Tests
// =============================================================================

func TestAlgorithmFromOID(t *testing.T) {
	// Test with valid OIDs - verify round-trip works
	validAlgs := []AlgorithmID{AlgEd25519, AlgMLDSA65, AlgMLDSA44, AlgMLDSA87}

	for _, alg := range validAlgs {
		oid := alg.OID()
		if oid == nil {
			continue
		}
		t.Run(string(alg), func(t *testing.T) {
			found := AlgorithmFromOID(oid)
			if found == "" {
				t.Error("expected to find algorithm from OID")
			}
			// Some algorithms may share OIDs (ecdsa-p256 vs ec-p256)
			// So we just verify we get a valid result
			if !found.IsValid() {
				t.Errorf("AlgorithmFromOID() returned invalid algorithm: %v", found)
			}
		})
	}

	// Test with unknown OID
	t.Run("unknown OID", func(t *testing.T) {
		unknownOID := asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7, 8, 9}
		found := AlgorithmFromOID(unknownOID)
		if found != "" {
			t.Errorf("expected empty result for unknown OID, got %v", found)
		}
	})
}
