package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestSoftwareKeyProviderGenerate(t *testing.T) {
	tests := []struct {
		name       string
		algorithm  AlgorithmID
		passphrase string
	}{
		{"ECDSA P-256", AlgECDSAP256, ""},
		{"ECDSA P-384", AlgECDSAP384, "test-passphrase"},
		{"ECDSA P-521", AlgECDSAP521, ""},
		{"Ed25519", AlgEd25519, ""},
		{"RSA 2048", AlgRSA2048, ""},
		{"ML-DSA-44", AlgMLDSA44, "pqc-test"},
		{"ML-DSA-65", AlgMLDSA65, ""},
		{"ML-DSA-87", AlgMLDSA87, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			keyPath := filepath.Join(tmpDir, "test.key")

			cfg := KeyStorageConfig{
				Type:       KeyProviderTypeSoftware,
				KeyPath:    keyPath,
				Passphrase: tt.passphrase,
			}

			km := NewSoftwareKeyProvider()
			signer, err := km.Generate(tt.algorithm, cfg)
			if err != nil {
				t.Fatalf("Generate() failed: %v", err)
			}

			if signer == nil {
				t.Fatal("Generate() returned nil signer")
			}

			// Verify the key file was created
			if _, err := os.Stat(keyPath); os.IsNotExist(err) {
				t.Errorf("key file was not created at %s", keyPath)
			}

			// Verify we can load the key back
			loadedSigner, err := km.Load(cfg)
			if err != nil {
				t.Fatalf("Load() failed: %v", err)
			}

			if loadedSigner == nil {
				t.Fatal("Load() returned nil signer")
			}

			// Verify the algorithm matches
			if sw, ok := loadedSigner.(*SoftwareSigner); ok {
				if sw.Algorithm() != tt.algorithm {
					t.Errorf("loaded key algorithm = %s, want %s", sw.Algorithm(), tt.algorithm)
				}
			}
		})
	}
}

func TestSoftwareKeyProviderLoad(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test.key")
	passphrase := "test-passphrase"

	// First generate a key
	cfg := KeyStorageConfig{
		Type:       KeyProviderTypeSoftware,
		KeyPath:    keyPath,
		Passphrase: passphrase,
	}

	km := NewSoftwareKeyProvider()
	_, err := km.Generate(AlgECDSAP384, cfg)
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}

	// Test loading with correct passphrase
	t.Run("correct passphrase", func(t *testing.T) {
		signer, err := km.Load(cfg)
		if err != nil {
			t.Fatalf("Load() failed: %v", err)
		}
		if signer == nil {
			t.Fatal("Load() returned nil signer")
		}
	})

	// Test loading with wrong passphrase
	t.Run("wrong passphrase", func(t *testing.T) {
		wrongCfg := KeyStorageConfig{
			Type:       KeyProviderTypeSoftware,
			KeyPath:    keyPath,
			Passphrase: "wrong-passphrase",
		}
		_, err := km.Load(wrongCfg)
		if err == nil {
			t.Error("Load() should fail with wrong passphrase")
		}
	})

	// Test loading non-existent key
	t.Run("non-existent key", func(t *testing.T) {
		nonExistentCfg := KeyStorageConfig{
			Type:       KeyProviderTypeSoftware,
			KeyPath:    filepath.Join(tmpDir, "non-existent.key"),
			Passphrase: passphrase,
		}
		_, err := km.Load(nonExistentCfg)
		if err == nil {
			t.Error("Load() should fail for non-existent key")
		}
	})
}

func TestNewKeyProvider(t *testing.T) {
	tests := []struct {
		name     string
		cfg      KeyStorageConfig
		wantType string
	}{
		{
			name: "software type",
			cfg: KeyStorageConfig{
				Type: KeyProviderTypeSoftware,
			},
			wantType: "*crypto.SoftwareKeyProvider",
		},
		{
			name: "pkcs11 type",
			cfg: KeyStorageConfig{
				Type: KeyProviderTypePKCS11,
			},
			wantType: "*crypto.PKCS11KeyProvider",
		},
		{
			name: "empty type defaults to software",
			cfg: KeyStorageConfig{
				Type: "",
			},
			wantType: "*crypto.SoftwareKeyProvider",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			km := NewKeyProvider(tt.cfg)
			if km == nil {
				t.Fatal("NewKeyProvider() returned nil")
			}

			// Check the type (we can't easily check the concrete type, but we can verify it's not nil)
			switch tt.cfg.Type {
			case KeyProviderTypePKCS11:
				if _, ok := km.(*PKCS11KeyProvider); !ok {
					t.Errorf("expected PKCS11KeyProvider, got %T", km)
				}
			default:
				if _, ok := km.(*SoftwareKeyProvider); !ok {
					t.Errorf("expected SoftwareKeyProvider, got %T", km)
				}
			}
		})
	}
}

func TestKeyStorageConfigValidation(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name    string
		cfg     KeyStorageConfig
		wantErr bool
	}{
		{
			name: "valid software config",
			cfg: KeyStorageConfig{
				Type:    KeyProviderTypeSoftware,
				KeyPath: filepath.Join(tmpDir, "valid.key"),
			},
			wantErr: false,
		},
		{
			name: "software config without path",
			cfg: KeyStorageConfig{
				Type:    KeyProviderTypeSoftware,
				KeyPath: "",
			},
			wantErr: true,
		},
	}

	km := NewSoftwareKeyProvider()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := km.Generate(AlgECDSAP256, tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("Generate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSoftwareKeyProviderSignVerify(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "sign-test.key")

	cfg := KeyStorageConfig{
		Type:    KeyProviderTypeSoftware,
		KeyPath: keyPath,
	}

	km := NewSoftwareKeyProvider()
	signer, err := km.Generate(AlgECDSAP384, cfg)
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}

	// Test signing
	data := []byte("test data to sign")
	signature, err := signer.Sign(rand.Reader, data, nil)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}

	if len(signature) == 0 {
		t.Error("Sign() returned empty signature")
	}

	// Verify the signature
	pubKey := signer.Public()
	if pubKey == nil {
		t.Fatal("Public() returned nil")
	}
}

func TestSoftwareKeyProviderPQCAlgorithms(t *testing.T) {
	pqcAlgorithms := []AlgorithmID{
		AlgMLDSA44,
		AlgMLDSA65,
		AlgMLDSA87,
		AlgSLHDSA128s,
		AlgSLHDSA128f,
	}

	for _, alg := range pqcAlgorithms {
		t.Run(string(alg), func(t *testing.T) {
			tmpDir := t.TempDir()
			keyPath := filepath.Join(tmpDir, "pqc.key")

			cfg := KeyStorageConfig{
				Type:    KeyProviderTypeSoftware,
				KeyPath: keyPath,
			}

			km := NewSoftwareKeyProvider()
			signer, err := km.Generate(alg, cfg)
			if err != nil {
				t.Fatalf("Generate(%s) failed: %v", alg, err)
			}

			// Test signing with PQC key
			data := []byte("test data for PQC signing")
			signature, err := signer.Sign(rand.Reader, data, nil)
			if err != nil {
				t.Fatalf("Sign() failed: %v", err)
			}

			if len(signature) == 0 {
				t.Error("Sign() returned empty signature")
			}

			// Reload and verify
			loadedSigner, err := km.Load(cfg)
			if err != nil {
				t.Fatalf("Load() failed: %v", err)
			}

			signature2, err := loadedSigner.Sign(rand.Reader, data, nil)
			if err != nil {
				t.Fatalf("Sign() after reload failed: %v", err)
			}

			if len(signature2) == 0 {
				t.Error("Sign() after reload returned empty signature")
			}
		})
	}
}

// =============================================================================
// [Unit] ResolvePassphrase Tests
// =============================================================================

func TestU_ResolvePassphrase_Empty(t *testing.T) {
	result := ResolvePassphrase("")
	if result != nil {
		t.Errorf("expected nil for empty passphrase, got %v", result)
	}
}

func TestU_ResolvePassphrase_Literal(t *testing.T) {
	result := ResolvePassphrase("mysecretpassword")
	if string(result) != "mysecretpassword" {
		t.Errorf("expected 'mysecretpassword', got '%s'", string(result))
	}
}

func TestU_ResolvePassphrase_EnvVar(t *testing.T) {
	_ = os.Setenv("TEST_PASSPHRASE_VAR", "envpassword123")
	defer func() { _ = os.Unsetenv("TEST_PASSPHRASE_VAR") }()

	result := ResolvePassphrase("env:TEST_PASSPHRASE_VAR")
	if string(result) != "envpassword123" {
		t.Errorf("expected 'envpassword123', got '%s'", string(result))
	}
}

func TestU_ResolvePassphrase_EnvVar_NotSet(t *testing.T) {
	_ = os.Unsetenv("NONEXISTENT_PASSPHRASE_VAR")

	result := ResolvePassphrase("env:NONEXISTENT_PASSPHRASE_VAR")
	if string(result) != "" {
		t.Errorf("expected empty string for unset env var, got '%s'", string(result))
	}
}

func TestU_ResolvePassphrase_ShortEnvPrefix(t *testing.T) {
	// "env" without colon should be treated as literal
	result := ResolvePassphrase("env")
	if string(result) != "env" {
		t.Errorf("expected 'env', got '%s'", string(result))
	}
}

// =============================================================================
// [Unit] StorageRef.ToKeyStorageConfig Tests
// =============================================================================

func TestU_StorageRef_ToKeyStorageConfig_Software(t *testing.T) {
	ref := &StorageRef{
		Type: "software",
		Path: "keys/private.pem",
	}

	cfg, err := ref.ToKeyStorageConfig("/ca/path", "mypassword")
	if err != nil {
		t.Fatalf("ToKeyStorageConfig() error = %v", err)
	}

	if cfg.Type != KeyProviderTypeSoftware {
		t.Errorf("Type = %v, want software", cfg.Type)
	}
	if cfg.KeyPath != "/ca/path/keys/private.pem" {
		t.Errorf("KeyPath = %v, want /ca/path/keys/private.pem", cfg.KeyPath)
	}
	if cfg.Passphrase != "mypassword" {
		t.Errorf("Passphrase = %v, want mypassword", cfg.Passphrase)
	}
}

func TestU_StorageRef_ToKeyStorageConfig_Software_AbsPath(t *testing.T) {
	ref := &StorageRef{
		Type: "software",
		Path: "/absolute/keys/private.pem",
	}

	cfg, err := ref.ToKeyStorageConfig("/ca/path", "")
	if err != nil {
		t.Fatalf("ToKeyStorageConfig() error = %v", err)
	}

	// Absolute path should not be modified
	if cfg.KeyPath != "/absolute/keys/private.pem" {
		t.Errorf("KeyPath = %v, want /absolute/keys/private.pem", cfg.KeyPath)
	}
}

func TestU_StorageRef_ToKeyStorageConfig_EmptyType(t *testing.T) {
	// Empty type should default to software
	ref := &StorageRef{
		Type: "",
		Path: "key.pem",
	}

	cfg, err := ref.ToKeyStorageConfig("", "")
	if err != nil {
		t.Fatalf("ToKeyStorageConfig() error = %v", err)
	}

	if cfg.Type != KeyProviderTypeSoftware {
		t.Errorf("Type = %v, want software", cfg.Type)
	}
}

func TestU_StorageRef_ToKeyStorageConfig_UnsupportedType(t *testing.T) {
	ref := &StorageRef{
		Type: "unsupported",
	}

	_, err := ref.ToKeyStorageConfig("", "")
	if err == nil {
		t.Error("expected error for unsupported storage type")
	}
}

// =============================================================================
// [Unit] SoftwareSigner.KeyPath Tests
// =============================================================================

func TestU_SoftwareSigner_KeyPath(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test-keypath.key")

	cfg := KeyStorageConfig{
		Type:    KeyProviderTypeSoftware,
		KeyPath: keyPath,
	}

	km := NewSoftwareKeyProvider()
	signer, err := km.Generate(AlgECDSAP256, cfg)
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}

	sw, ok := signer.(*SoftwareSigner)
	if !ok {
		t.Fatal("expected *SoftwareSigner")
	}

	if sw.KeyPath() != keyPath {
		t.Errorf("KeyPath() = %v, want %v", sw.KeyPath(), keyPath)
	}
}

// =============================================================================
// [Unit] SoftwareSigner.Decrypt Tests (RSA only)
// =============================================================================

func TestU_SoftwareSigner_Decrypt_RSA_OAEP(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "rsa-decrypt.key")

	cfg := KeyStorageConfig{
		Type:    KeyProviderTypeSoftware,
		KeyPath: keyPath,
	}

	km := NewSoftwareKeyProvider()
	signer, err := km.Generate(AlgRSA2048, cfg)
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}

	sw, ok := signer.(*SoftwareSigner)
	if !ok {
		t.Fatal("expected *SoftwareSigner")
	}

	// Get public key for encryption
	pubKey := sw.Public().(*rsa.PublicKey)

	// Encrypt a message
	plaintext := []byte("secret message for RSA decryption test")
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, plaintext, nil)
	if err != nil {
		t.Fatalf("EncryptOAEP failed: %v", err)
	}

	// Decrypt with default options (should use OAEP with SHA-256)
	decrypted, err := sw.Decrypt(rand.Reader, ciphertext, nil)
	if err != nil {
		t.Fatalf("Decrypt() failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("decrypted = %q, want %q", string(decrypted), string(plaintext))
	}
}

func TestU_SoftwareSigner_Decrypt_RSA_PKCS1v15(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "rsa-pkcs1.key")

	cfg := KeyStorageConfig{
		Type:    KeyProviderTypeSoftware,
		KeyPath: keyPath,
	}

	km := NewSoftwareKeyProvider()
	signer, err := km.Generate(AlgRSA2048, cfg)
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}

	sw := signer.(*SoftwareSigner)
	pubKey := sw.Public().(*rsa.PublicKey)

	// Encrypt with PKCS#1 v1.5
	plaintext := []byte("pkcs1 test message")
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, plaintext)
	if err != nil {
		t.Fatalf("EncryptPKCS1v15 failed: %v", err)
	}

	// Decrypt with PKCS#1 v1.5 options
	opts := &rsa.PKCS1v15DecryptOptions{}
	decrypted, err := sw.Decrypt(rand.Reader, ciphertext, opts)
	if err != nil {
		t.Fatalf("Decrypt() with PKCS1v15 failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("decrypted = %q, want %q", string(decrypted), string(plaintext))
	}
}

func TestU_SoftwareSigner_Decrypt_RSA_OAEP_WithOptions(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "rsa-oaep-opts.key")

	cfg := KeyStorageConfig{
		Type:    KeyProviderTypeSoftware,
		KeyPath: keyPath,
	}

	km := NewSoftwareKeyProvider()
	signer, err := km.Generate(AlgRSA2048, cfg)
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}

	sw := signer.(*SoftwareSigner)
	pubKey := sw.Public().(*rsa.PublicKey)

	// Encrypt with OAEP and custom label
	plaintext := []byte("oaep with label")
	label := []byte("test-label")
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, plaintext, label)
	if err != nil {
		t.Fatalf("EncryptOAEP failed: %v", err)
	}

	// Decrypt with explicit OAEP options
	opts := &rsa.OAEPOptions{
		Hash:  crypto.SHA256,
		Label: label,
	}
	decrypted, err := sw.Decrypt(rand.Reader, ciphertext, opts)
	if err != nil {
		t.Fatalf("Decrypt() with OAEP options failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("decrypted = %q, want %q", string(decrypted), string(plaintext))
	}
}

func TestU_SoftwareSigner_Decrypt_NonRSA_Fails(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "ecdsa-decrypt.key")

	cfg := KeyStorageConfig{
		Type:    KeyProviderTypeSoftware,
		KeyPath: keyPath,
	}

	km := NewSoftwareKeyProvider()
	signer, err := km.Generate(AlgECDSAP256, cfg)
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}

	sw := signer.(*SoftwareSigner)

	// Decrypt should fail for non-RSA keys
	_, err = sw.Decrypt(rand.Reader, []byte("fake ciphertext"), nil)
	if err == nil {
		t.Error("Decrypt() should fail for non-RSA keys")
	}
}

// =============================================================================
// [Unit] parsePrivateKeyByType Tests
// =============================================================================

func TestU_ParsePrivateKeyByType_ECPrivateKey(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "ec.key")

	// Generate an EC key
	cfg := KeyStorageConfig{
		Type:    KeyProviderTypeSoftware,
		KeyPath: keyPath,
	}
	km := NewSoftwareKeyProvider()
	_, err := km.Generate(AlgECDSAP384, cfg)
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}

	// Load and verify
	signer, err := km.Load(cfg)
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	sw := signer.(*SoftwareSigner)
	if sw.Algorithm() != AlgECDSAP384 {
		t.Errorf("Algorithm() = %v, want %v", sw.Algorithm(), AlgECDSAP384)
	}
}

func TestU_ParsePrivateKeyByType_RSAPrivateKey(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "rsa.key")

	// Generate an RSA key
	cfg := KeyStorageConfig{
		Type:    KeyProviderTypeSoftware,
		KeyPath: keyPath,
	}
	km := NewSoftwareKeyProvider()
	_, err := km.Generate(AlgRSA2048, cfg)
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}

	// Load and verify
	signer, err := km.Load(cfg)
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	sw := signer.(*SoftwareSigner)
	if sw.Algorithm() != AlgRSA2048 {
		t.Errorf("Algorithm() = %v, want %v", sw.Algorithm(), AlgRSA2048)
	}
}

func TestU_ParsePrivateKeyByType_MLDSA44(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "mldsa44.key")

	cfg := KeyStorageConfig{
		Type:    KeyProviderTypeSoftware,
		KeyPath: keyPath,
	}
	km := NewSoftwareKeyProvider()
	_, err := km.Generate(AlgMLDSA44, cfg)
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}

	// Load and verify
	signer, err := km.Load(cfg)
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	sw := signer.(*SoftwareSigner)
	if sw.Algorithm() != AlgMLDSA44 {
		t.Errorf("Algorithm() = %v, want %v", sw.Algorithm(), AlgMLDSA44)
	}
}

func TestU_ParsePrivateKeyByType_MLDSA87(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "mldsa87.key")

	cfg := KeyStorageConfig{
		Type:    KeyProviderTypeSoftware,
		KeyPath: keyPath,
	}
	km := NewSoftwareKeyProvider()
	_, err := km.Generate(AlgMLDSA87, cfg)
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}

	// Load and verify
	signer, err := km.Load(cfg)
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	sw := signer.(*SoftwareSigner)
	if sw.Algorithm() != AlgMLDSA87 {
		t.Errorf("Algorithm() = %v, want %v", sw.Algorithm(), AlgMLDSA87)
	}
}

// =============================================================================
// [Unit] LoadPrivateKeysAsHybrid Tests
// =============================================================================

func TestU_LoadPrivateKeysAsHybrid_SingleKey(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "single.key")

	cfg := KeyStorageConfig{
		Type:    KeyProviderTypeSoftware,
		KeyPath: keyPath,
	}
	km := NewSoftwareKeyProvider()
	_, err := km.Generate(AlgECDSAP256, cfg)
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}

	// Load as hybrid (should return single signer)
	signer, err := LoadPrivateKeysAsHybrid(keyPath, nil)
	if err != nil {
		t.Fatalf("LoadPrivateKeysAsHybrid() failed: %v", err)
	}

	// Should be a SoftwareSigner, not HybridSigner
	if _, ok := signer.(*SoftwareSigner); !ok {
		t.Errorf("expected *SoftwareSigner for single key, got %T", signer)
	}
}

func TestU_LoadPrivateKeysAsHybrid_FileNotFound(t *testing.T) {
	_, err := LoadPrivateKeysAsHybrid("/nonexistent/key.pem", nil)
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestU_LoadPrivateKeysAsHybrid_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "empty.pem")

	// Create empty file
	if err := os.WriteFile(keyPath, []byte(""), 0600); err != nil {
		t.Fatalf("failed to create empty file: %v", err)
	}

	_, err := LoadPrivateKeysAsHybrid(keyPath, nil)
	if err == nil {
		t.Error("expected error for empty file")
	}
}

func TestU_LoadPrivateKeysAsHybrid_InvalidPEM(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "invalid.pem")

	// Create file with invalid content
	if err := os.WriteFile(keyPath, []byte("not a pem file"), 0600); err != nil {
		t.Fatalf("failed to create invalid file: %v", err)
	}

	_, err := LoadPrivateKeysAsHybrid(keyPath, nil)
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

// =============================================================================
// [Unit] PrivateKey accessor Tests
// =============================================================================

func TestU_SoftwareSigner_PrivateKey(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "privkey.key")

	cfg := KeyStorageConfig{
		Type:    KeyProviderTypeSoftware,
		KeyPath: keyPath,
	}
	km := NewSoftwareKeyProvider()
	signer, err := km.Generate(AlgECDSAP256, cfg)
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}

	sw := signer.(*SoftwareSigner)
	privKey := sw.PrivateKey()
	if privKey == nil {
		t.Error("PrivateKey() returned nil")
	}
}

// =============================================================================
// [Unit] Verify Signature Tests
// =============================================================================

func TestU_VerifySignature(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "verify.key")

	cfg := KeyStorageConfig{
		Type:    KeyProviderTypeSoftware,
		KeyPath: keyPath,
	}
	km := NewSoftwareKeyProvider()
	signer, err := km.Generate(AlgECDSAP256, cfg)
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}

	sw := signer.(*SoftwareSigner)

	// Sign data
	data := []byte("test data for verification")
	signature, err := sw.Sign(rand.Reader, data, nil)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}

	// Verify signature using package-level function
	valid := Verify(AlgECDSAP256, sw.Public(), data, signature)
	if !valid {
		t.Error("Verify() returned false for valid signature")
	}

	// Verify with wrong data
	valid = Verify(AlgECDSAP256, sw.Public(), []byte("wrong data"), signature)
	if valid {
		t.Error("Verify() returned true for wrong data")
	}
}

func TestU_VerifySignature_Error(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "verify-err.key")

	cfg := KeyStorageConfig{
		Type:    KeyProviderTypeSoftware,
		KeyPath: keyPath,
	}
	km := NewSoftwareKeyProvider()
	signer, err := km.Generate(AlgECDSAP256, cfg)
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}

	sw := signer.(*SoftwareSigner)

	// Sign data
	data := []byte("test data")
	signature, err := sw.Sign(rand.Reader, data, nil)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}

	// Verify signature using VerifySignature (returns error)
	err = VerifySignature(sw.Public(), AlgECDSAP256, data, signature)
	if err != nil {
		t.Errorf("VerifySignature() error = %v for valid signature", err)
	}

	// Verify with wrong data should return error
	err = VerifySignature(sw.Public(), AlgECDSAP256, []byte("wrong"), signature)
	if err == nil {
		t.Error("VerifySignature() should return error for wrong data")
	}
}

// =============================================================================
// [Unit] Legacy PEM Format Tests (EC PRIVATE KEY, RSA PRIVATE KEY)
// =============================================================================

func TestU_LoadPrivateKey_LegacyECFormat(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "legacy-ec.pem")

	// Generate EC key using standard library
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate EC key: %v", err)
	}

	// Marshal to legacy EC format
	ecBytes, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatalf("failed to marshal EC key: %v", err)
	}

	// Write in legacy "EC PRIVATE KEY" format
	pemBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: ecBytes,
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(pemBlock), 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	// Load using our LoadPrivateKey
	signer, err := LoadPrivateKey(keyPath, nil)
	if err != nil {
		t.Fatalf("LoadPrivateKey() failed: %v", err)
	}

	if signer == nil {
		t.Fatal("LoadPrivateKey() returned nil signer")
	}

	if signer.Algorithm() != AlgECDSAP256 {
		t.Errorf("Algorithm() = %v, want %v", signer.Algorithm(), AlgECDSAP256)
	}
}

func TestU_LoadPrivateKey_LegacyRSAFormat(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "legacy-rsa.pem")

	// Generate RSA key using standard library
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Marshal to legacy PKCS#1 format
	rsaBytes := x509.MarshalPKCS1PrivateKey(rsaKey)

	// Write in legacy "RSA PRIVATE KEY" format
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: rsaBytes,
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(pemBlock), 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	// Load using our LoadPrivateKey
	signer, err := LoadPrivateKey(keyPath, nil)
	if err != nil {
		t.Fatalf("LoadPrivateKey() failed: %v", err)
	}

	if signer == nil {
		t.Fatal("LoadPrivateKey() returned nil signer")
	}

	if signer.Algorithm() != AlgRSA2048 {
		t.Errorf("Algorithm() = %v, want %v", signer.Algorithm(), AlgRSA2048)
	}
}
