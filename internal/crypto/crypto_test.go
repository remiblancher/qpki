package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
)

func TestAlgorithmID_Properties(t *testing.T) {
	tests := []struct {
		alg         AlgorithmID
		wantValid   bool
		wantClassic bool
		wantPQC     bool
		wantHybrid  bool
		wantSig     bool
		wantKEM     bool
	}{
		{AlgECDSAP256, true, true, false, false, true, false},
		{AlgECDSAP384, true, true, false, false, true, false},
		{AlgECDSAP521, true, true, false, false, true, false},
		{AlgEd25519, true, true, false, false, true, false},
		{AlgRSA2048, true, true, false, false, true, false},
		{AlgRSA4096, true, true, false, false, true, false},
		{AlgMLDSA44, true, false, true, false, true, false},
		{AlgMLDSA65, true, false, true, false, true, false},
		{AlgMLDSA87, true, false, true, false, true, false},
		{AlgMLKEM512, true, false, true, false, false, true},
		{AlgMLKEM768, true, false, true, false, false, true},
		{AlgMLKEM1024, true, false, true, false, false, true},
		{AlgSLHDSA128s, true, false, true, false, true, false},
		{AlgSLHDSA128f, true, false, true, false, true, false},
		{AlgSLHDSA192s, true, false, true, false, true, false},
		{AlgSLHDSA192f, true, false, true, false, true, false},
		{AlgSLHDSA256s, true, false, true, false, true, false},
		{AlgSLHDSA256f, true, false, true, false, true, false},
		{AlgHybridP256MLDSA44, true, false, false, true, false, false},
		{AlgHybridP384MLDSA65, true, false, false, true, false, false},
		{"invalid", false, false, false, false, false, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.alg), func(t *testing.T) {
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

func TestAlgorithmID_OID(t *testing.T) {
	tests := []struct {
		alg     AlgorithmID
		wantOID bool
	}{
		{AlgECDSAP256, true},
		{AlgEd25519, true},
		{AlgMLDSA65, true},
		{"invalid", false},
	}

	for _, tt := range tests {
		t.Run(string(tt.alg), func(t *testing.T) {
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

func TestParseAlgorithm(t *testing.T) {
	tests := []struct {
		input   string
		want    AlgorithmID
		wantErr bool
	}{
		{"ecdsa-p256", AlgECDSAP256, false},
		{"ml-dsa-65", AlgMLDSA65, false},
		{"invalid", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
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

// TestGenerateKeyPair tests key generation for all signature algorithms.
func TestGenerateKeyPair(t *testing.T) {
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

// TestGenerateKeyPair_Invalid tests that invalid algorithms are rejected.
func TestGenerateKeyPair_Invalid(t *testing.T) {
	_, err := GenerateKeyPair("invalid")
	if err == nil {
		t.Error("expected error for invalid algorithm")
	}
}

// TestGenerateKeyPair_Hybrid tests that hybrid algorithms require special function.
func TestGenerateKeyPair_Hybrid(t *testing.T) {
	_, err := GenerateKeyPair(AlgHybridP256MLDSA44)
	if err == nil {
		t.Error("expected error for hybrid algorithm")
	}
}

// TestGenerateHybridKeyPair tests hybrid key generation.
func TestGenerateHybridKeyPair(t *testing.T) {
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

// TestSoftwareSignerProvider tests the SignerProvider interface.
func TestSoftwareSignerProvider(t *testing.T) {
	tempDir := t.TempDir()
	provider := &SoftwareSignerProvider{}

	keyPath := filepath.Join(tempDir, "test.key.pem")
	cfg := SignerConfig{
		Type:    SignerTypeSoftware,
		KeyPath: keyPath,
	}

	// Generate and save
	signer, err := provider.GenerateAndSave(AlgECDSAP256, cfg)
	if err != nil {
		t.Fatalf("GenerateAndSave() error = %v", err)
	}

	if signer.Algorithm() != AlgECDSAP256 {
		t.Errorf("Algorithm() = %v, want %v", signer.Algorithm(), AlgECDSAP256)
	}

	// Load
	loaded, err := provider.LoadSigner(cfg)
	if err != nil {
		t.Fatalf("LoadSigner() error = %v", err)
	}

	if loaded.Algorithm() != AlgECDSAP256 {
		t.Errorf("loaded Algorithm() = %v, want %v", loaded.Algorithm(), AlgECDSAP256)
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
