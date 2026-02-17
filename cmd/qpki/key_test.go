package main

import (
	"os"
	"testing"

	"github.com/remiblancher/post-quantum-pki/pkg/crypto"
)

// resetKeyFlags resets all key command flags to their default values.
func resetKeyFlags() {
	keyGenAlgorithm = "ecdsa-p256"
	keyGenOutput = ""
	keyGenPassphrase = ""
	keyGenHSMConfig = ""
	keyGenKeyLabel = ""
	keyGenKeyID = ""

	keyListHSMConfig = ""
	keyListDir = ""

	keyPubKey = ""
	keyPubOut = ""
	keyPubPassphrase = ""

	keyInfoPassphrase = ""

	keyConvertOut = ""
	keyConvertFormat = "pem"
	keyConvertPassphrase = ""
	keyConvertNewPass = ""
}

// =============================================================================
// Key Gen Tests (Table-Driven)
// =============================================================================

func TestF_Key_Gen(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
		wantErr   bool
	}{
		{"[Functional] Key Gen: ECDSA P-256 default", "", false},
		{"[Functional] Key Gen: ECDSA P-256 explicit", "ecdsa-p256", false},
		{"[Functional] Key Gen: ECDSA P-384", "ecdsa-p384", false},
		{"[Functional] Key Gen: Ed25519", "ed25519", false},
		{"[Functional] Key Gen: RSA 2048", "rsa-2048", false},
		{"[Functional] Key Gen: ML-DSA-44", "ml-dsa-44", false},
		{"[Functional] Key Gen: ML-DSA-65", "ml-dsa-65", false},
		{"[Functional] Key Gen: ML-KEM-512", "ml-kem-512", false},
		{"[Functional] Key Gen: ML-KEM-768", "ml-kem-768", false},
		{"[Functional] Key Gen: ML-KEM-1024", "ml-kem-1024", false},
		{"[Functional] Key Gen: Invalid algorithm", "invalid-algo", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := newTestContext(t)
			resetKeyFlags()

			outputPath := tc.path("key.pem")

			args := []string{"key", "gen", "--out", outputPath}
			if tt.algorithm != "" {
				args = append(args, "--algorithm", tt.algorithm)
			}

			_, err := executeCommand(rootCmd, args...)

			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				assertFileExists(t, outputPath)
				assertFileNotEmpty(t, outputPath)
			}
		})
	}
}

func TestF_Key_Gen_WithPassphrase(t *testing.T) {
	tc := newTestContext(t)
	resetKeyFlags()

	outputPath := tc.path("encrypted.pem")

	_, err := executeCommand(rootCmd, "key", "gen",
		"--algorithm", "ecdsa-p256",
		"--out", outputPath,
		"--passphrase", "secret123",
	)

	assertNoError(t, err)
	assertFileExists(t, outputPath)

	// Verify the file contains encrypted PEM
	data, _ := os.ReadFile(outputPath)
	if len(data) == 0 {
		t.Error("key file is empty")
	}
}

func TestF_Key_Gen_MissingOutput(t *testing.T) {
	resetKeyFlags()

	_, err := executeCommand(rootCmd, "key", "gen", "--algorithm", "ecdsa-p256")

	// Should fail because --out is required
	assertError(t, err)
}

// =============================================================================
// Key Info Tests (Table-Driven)
// =============================================================================

func TestF_Key_Info(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
	}{
		{"[Functional] Key Info: ECDSA P-256", "ecdsa-p256"},
		{"[Functional] Key Info: Ed25519", "ed25519"},
		{"[Functional] Key Info: RSA 2048", "rsa-2048"},
		{"[Functional] Key Info: ML-DSA-65", "ml-dsa-65"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := newTestContext(t)
			resetKeyFlags()

			// First generate a key
			keyPath := tc.path("key.pem")
			_, err := executeCommand(rootCmd, "key", "gen",
				"--algorithm", tt.algorithm,
				"--out", keyPath,
			)
			assertNoError(t, err)

			resetKeyFlags()

			// Then get info (note: output goes to stdout, not captured)
			_, err = executeCommand(rootCmd, "key", "info", keyPath)

			assertNoError(t, err)
		})
	}
}

func TestF_Key_Info_EncryptedKey(t *testing.T) {
	tc := newTestContext(t)
	resetKeyFlags()

	keyPath := tc.path("encrypted.pem")
	passphrase := "secret123"

	// Generate encrypted key
	_, err := executeCommand(rootCmd, "key", "gen",
		"--algorithm", "ecdsa-p256",
		"--out", keyPath,
		"--passphrase", passphrase,
	)
	assertNoError(t, err)

	resetKeyFlags()

	// Info without passphrase should work (shows limited info)
	_, err = executeCommand(rootCmd, "key", "info", keyPath)
	assertNoError(t, err)

	resetKeyFlags()

	// Info with passphrase should work (shows full info)
	_, err = executeCommand(rootCmd, "key", "info", keyPath,
		"--passphrase", passphrase,
	)
	assertNoError(t, err)
}

func TestF_Key_Info_FileNotFound(t *testing.T) {
	tc := newTestContext(t)
	resetKeyFlags()

	_, err := executeCommand(rootCmd, "key", "info", tc.path("nonexistent.pem"))

	assertError(t, err)
}

// =============================================================================
// Key Convert Tests (Table-Driven)
// =============================================================================

func TestF_Key_Convert(t *testing.T) {
	tests := []struct {
		name          string
		addPassphrase bool
	}{
		{"[Functional] Key Convert: plain to plain", false},
		{"[Functional] Key Convert: plain to encrypted", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := newTestContext(t)
			resetKeyFlags()

			// Generate source key
			srcPath := tc.path("source.pem")
			_, err := executeCommand(rootCmd, "key", "gen",
				"--algorithm", "ecdsa-p256",
				"--out", srcPath,
			)
			assertNoError(t, err)

			resetKeyFlags()

			// Convert
			dstPath := tc.path("converted.pem")
			args := []string{"key", "convert", srcPath, "--out", dstPath}
			if tt.addPassphrase {
				args = append(args, "--new-passphrase", "newpass")
			}

			_, err = executeCommand(rootCmd, args...)

			assertNoError(t, err)
			assertFileExists(t, dstPath)
			assertFileNotEmpty(t, dstPath)
		})
	}
}

func TestF_Key_Convert_RemovePassphrase(t *testing.T) {
	tc := newTestContext(t)
	resetKeyFlags()

	passphrase := "secret123"

	// Generate encrypted key
	srcPath := tc.path("encrypted.pem")
	_, err := executeCommand(rootCmd, "key", "gen",
		"--algorithm", "ecdsa-p256",
		"--out", srcPath,
		"--passphrase", passphrase,
	)
	assertNoError(t, err)

	resetKeyFlags()

	// Convert to plain
	dstPath := tc.path("plain.pem")
	_, err = executeCommand(rootCmd, "key", "convert", srcPath,
		"--passphrase", passphrase,
		"--out", dstPath,
	)

	assertNoError(t, err)
	assertFileExists(t, dstPath)
}

func TestF_Key_Convert_ToDER(t *testing.T) {
	tc := newTestContext(t)
	resetKeyFlags()

	// Generate source key
	srcPath := tc.path("source.pem")
	_, err := executeCommand(rootCmd, "key", "gen",
		"--algorithm", "ecdsa-p256",
		"--out", srcPath,
	)
	assertNoError(t, err)

	resetKeyFlags()

	// Convert to DER
	dstPath := tc.path("key.der")
	_, err = executeCommand(rootCmd, "key", "convert", srcPath,
		"--format", "der",
		"--out", dstPath,
	)

	assertNoError(t, err)
	assertFileExists(t, dstPath)
	assertFileNotEmpty(t, dstPath)
}

func TestF_Key_Convert_MissingOutput(t *testing.T) {
	tc := newTestContext(t)
	resetKeyFlags()

	// Generate source key
	srcPath := tc.path("source.pem")
	_, _ = executeCommand(rootCmd, "key", "gen",
		"--algorithm", "ecdsa-p256",
		"--out", srcPath,
	)

	resetKeyFlags()

	// Convert without --out should fail
	_, err := executeCommand(rootCmd, "key", "convert", srcPath)

	assertError(t, err)
}

// =============================================================================
// Key Pub Tests (Table-Driven)
// =============================================================================

func TestF_Key_Pub_Classical(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
	}{
		{"[Functional] Key Pub: ECDSA P-256", "ecdsa-p256"},
		{"[Functional] Key Pub: ECDSA P-384", "ecdsa-p384"},
		{"[Functional] Key Pub: ECDSA P-521", "ecdsa-p521"},
		{"[Functional] Key Pub: Ed25519", "ed25519"},
		{"[Functional] Key Pub: RSA 2048", "rsa-2048"},
		{"[Functional] Key Pub: RSA 4096", "rsa-4096"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := newTestContext(t)
			resetKeyFlags()

			// Generate private key
			keyPath := tc.path("private.pem")
			_, err := executeCommand(rootCmd, "key", "gen",
				"--algorithm", tt.algorithm,
				"--out", keyPath,
			)
			assertNoError(t, err)

			resetKeyFlags()

			// Extract public key
			pubPath := tc.path("public.pem")
			_, err = executeCommand(rootCmd, "key", "pub",
				"--key", keyPath,
				"--out", pubPath,
			)

			assertNoError(t, err)
			assertFileExists(t, pubPath)
			assertFileNotEmpty(t, pubPath)

			// Verify PEM format
			data, _ := os.ReadFile(pubPath)
			if len(data) == 0 {
				t.Error("public key file is empty")
			}
			// Classical keys should have standard PUBLIC KEY header
			if !contains(string(data), "-----BEGIN PUBLIC KEY-----") {
				t.Errorf("expected PUBLIC KEY PEM block, got: %s", string(data)[:50])
			}
		})
	}
}

func TestF_Key_Pub_PQC(t *testing.T) {
	tests := []struct {
		name            string
		algorithm       string
		expectedPEMType string
	}{
		{"[Functional] Key Pub: ML-DSA-44", "ml-dsa-44", "ML-DSA-44 PUBLIC KEY"},
		{"[Functional] Key Pub: ML-DSA-65", "ml-dsa-65", "ML-DSA-65 PUBLIC KEY"},
		{"[Functional] Key Pub: ML-DSA-87", "ml-dsa-87", "ML-DSA-87 PUBLIC KEY"},
		{"[Functional] Key Pub: SLH-DSA-128s", "slh-dsa-sha2-128s", "SLH-DSA-SHA2-128s PUBLIC KEY"},
		{"[Functional] Key Pub: SLH-DSA-128f", "slh-dsa-sha2-128f", "SLH-DSA-SHA2-128f PUBLIC KEY"},
		{"[Functional] Key Pub: SLH-DSA-192s", "slh-dsa-sha2-192s", "SLH-DSA-SHA2-192s PUBLIC KEY"},
		{"[Functional] Key Pub: SLH-DSA-256f", "slh-dsa-sha2-256f", "SLH-DSA-SHA2-256f PUBLIC KEY"},
		// ML-KEM (encryption)
		{"[Functional] Key Pub: ML-KEM-512", "ml-kem-512", "ML-KEM-512 PUBLIC KEY"},
		{"[Functional] Key Pub: ML-KEM-768", "ml-kem-768", "ML-KEM-768 PUBLIC KEY"},
		{"[Functional] Key Pub: ML-KEM-1024", "ml-kem-1024", "ML-KEM-1024 PUBLIC KEY"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := newTestContext(t)
			resetKeyFlags()

			// Generate private key
			keyPath := tc.path("private.pem")
			_, err := executeCommand(rootCmd, "key", "gen",
				"--algorithm", tt.algorithm,
				"--out", keyPath,
			)
			assertNoError(t, err)

			resetKeyFlags()

			// Extract public key
			pubPath := tc.path("public.pem")
			_, err = executeCommand(rootCmd, "key", "pub",
				"--key", keyPath,
				"--out", pubPath,
			)

			assertNoError(t, err)
			assertFileExists(t, pubPath)
			assertFileNotEmpty(t, pubPath)

			// Verify PEM format has correct type
			data, _ := os.ReadFile(pubPath)
			expectedHeader := "-----BEGIN " + tt.expectedPEMType + "-----"
			if !contains(string(data), expectedHeader) {
				t.Errorf("expected %s PEM block, got: %s", tt.expectedPEMType, string(data)[:80])
			}
		})
	}
}

func TestF_Key_Pub_EncryptedKey(t *testing.T) {
	tc := newTestContext(t)
	resetKeyFlags()

	passphrase := "secret123"

	// Generate encrypted private key
	keyPath := tc.path("encrypted.pem")
	_, err := executeCommand(rootCmd, "key", "gen",
		"--algorithm", "ecdsa-p256",
		"--out", keyPath,
		"--passphrase", passphrase,
	)
	assertNoError(t, err)

	resetKeyFlags()

	// Extract public key with passphrase
	pubPath := tc.path("public.pem")
	_, err = executeCommand(rootCmd, "key", "pub",
		"--key", keyPath,
		"--out", pubPath,
		"--passphrase", passphrase,
	)

	assertNoError(t, err)
	assertFileExists(t, pubPath)
	assertFileNotEmpty(t, pubPath)
}

func TestF_Key_Pub_EncryptedKeyWrongPassphrase(t *testing.T) {
	tc := newTestContext(t)
	resetKeyFlags()

	// Generate encrypted private key
	keyPath := tc.path("encrypted.pem")
	_, err := executeCommand(rootCmd, "key", "gen",
		"--algorithm", "ecdsa-p256",
		"--out", keyPath,
		"--passphrase", "correct-password",
	)
	assertNoError(t, err)

	resetKeyFlags()

	// Try to extract with wrong passphrase
	pubPath := tc.path("public.pem")
	_, err = executeCommand(rootCmd, "key", "pub",
		"--key", keyPath,
		"--out", pubPath,
		"--passphrase", "wrong-password",
	)

	assertError(t, err)
}

func TestF_Key_Pub_EncryptedKeyNoPassphrase(t *testing.T) {
	tc := newTestContext(t)
	resetKeyFlags()

	// Generate encrypted private key
	keyPath := tc.path("encrypted.pem")
	_, err := executeCommand(rootCmd, "key", "gen",
		"--algorithm", "ecdsa-p256",
		"--out", keyPath,
		"--passphrase", "secret123",
	)
	assertNoError(t, err)

	resetKeyFlags()

	// Try to extract without passphrase
	pubPath := tc.path("public.pem")
	_, err = executeCommand(rootCmd, "key", "pub",
		"--key", keyPath,
		"--out", pubPath,
	)

	assertError(t, err)
}

func TestF_Key_Pub_FileNotFound(t *testing.T) {
	tc := newTestContext(t)
	resetKeyFlags()

	_, err := executeCommand(rootCmd, "key", "pub",
		"--key", tc.path("nonexistent.pem"),
		"--out", tc.path("public.pem"),
	)

	assertError(t, err)
}

func TestF_Key_Pub_MissingKeyFlag(t *testing.T) {
	tc := newTestContext(t)
	resetKeyFlags()

	_, err := executeCommand(rootCmd, "key", "pub",
		"--out", tc.path("public.pem"),
	)

	assertError(t, err)
}

func TestF_Key_Pub_MissingOutFlag(t *testing.T) {
	tc := newTestContext(t)
	resetKeyFlags()

	// Generate a key first
	keyPath := tc.path("private.pem")
	_, _ = executeCommand(rootCmd, "key", "gen",
		"--algorithm", "ecdsa-p256",
		"--out", keyPath,
	)

	resetKeyFlags()

	_, err := executeCommand(rootCmd, "key", "pub",
		"--key", keyPath,
	)

	assertError(t, err)
}

func TestF_Key_Pub_InvalidKeyFile(t *testing.T) {
	tc := newTestContext(t)
	resetKeyFlags()

	// Create an invalid key file
	invalidPath := tc.path("invalid.pem")
	_ = os.WriteFile(invalidPath, []byte("not a valid PEM file"), 0600)

	_, err := executeCommand(rootCmd, "key", "pub",
		"--key", invalidPath,
		"--out", tc.path("public.pem"),
	)

	assertError(t, err)
}

// contains checks if s contains substr.
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

// =============================================================================
// Key List Directory Tests
// =============================================================================

func TestF_Key_List_Dir(t *testing.T) {
	tc := newTestContext(t)
	resetKeyFlags()

	// Create a directory with some keys
	keyDir := tc.path("keys")
	_ = os.MkdirAll(keyDir, 0755)

	// Generate a few keys
	_, _ = executeCommand(rootCmd, "key", "gen",
		"--algorithm", "ecdsa-p256",
		"--out", keyDir+"/key1.pem",
	)
	resetKeyFlags()

	_, _ = executeCommand(rootCmd, "key", "gen",
		"--algorithm", "ed25519",
		"--out", keyDir+"/key2.key",
	)
	resetKeyFlags()

	// List keys in directory
	_, err := executeCommand(rootCmd, "key", "list", "--dir", keyDir)
	assertNoError(t, err)
}

func TestF_Key_List_EmptyDir(t *testing.T) {
	tc := newTestContext(t)
	resetKeyFlags()

	// Create an empty directory
	emptyDir := tc.path("empty")
	_ = os.MkdirAll(emptyDir, 0755)

	// List keys in empty directory - should not error
	_, err := executeCommand(rootCmd, "key", "list", "--dir", emptyDir)
	assertNoError(t, err)
}

func TestF_Key_List_DirNotFound(t *testing.T) {
	tc := newTestContext(t)
	resetKeyFlags()

	_, err := executeCommand(rootCmd, "key", "list", "--dir", tc.path("nonexistent"))
	assertError(t, err)
}

// =============================================================================
// Key Helper Function Unit Tests
// =============================================================================

func TestU_HasKeyExtension(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		want     bool
	}{
		{"PEM extension", "private.pem", true},
		{"KEY extension", "private.key", true},
		{"CRT extension", "cert.crt", false},
		{"No extension", "private", false},
		{"Hidden file with pem", ".private.pem", true},
		{"Just .pem", ".pem", false},
		{"Just .key", ".key", false},
		{"Multiple dots", "my.key.pem", true},
		{"Uppercase PEM", "private.PEM", false}, // case sensitive
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasKeyExtension(tt.filename)
			if got != tt.want {
				t.Errorf("hasKeyExtension(%q) = %v, want %v", tt.filename, got, tt.want)
			}
		})
	}
}

func TestU_IsPrivateKeyPEM(t *testing.T) {
	tests := []struct {
		pemType string
		want    bool
	}{
		{"PRIVATE KEY", true},
		{"EC PRIVATE KEY", true},
		{"RSA PRIVATE KEY", true},
		{"ML-DSA-44 PRIVATE KEY", true},
		{"ML-DSA-65 PRIVATE KEY", true},
		{"ML-DSA-87 PRIVATE KEY", true},
		{"SLH-DSA-SHAKE-128S PRIVATE KEY", true},
		{"SLH-DSA-SHAKE-128F PRIVATE KEY", true},
		{"ENCRYPTED PRIVATE KEY", true},
		{"CERTIFICATE", false},
		{"CERTIFICATE REQUEST", false},
		{"PUBLIC KEY", false},
		{"RSA PUBLIC KEY", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.pemType, func(t *testing.T) {
			got := isPrivateKeyPEM(tt.pemType)
			if got != tt.want {
				t.Errorf("isPrivateKeyPEM(%q) = %v, want %v", tt.pemType, got, tt.want)
			}
		})
	}
}

func TestU_AlgorithmFromPEMType(t *testing.T) {
	tests := []struct {
		pemType string
		want    string
	}{
		{"EC PRIVATE KEY", "ECDSA"},
		{"RSA PRIVATE KEY", "RSA"},
		{"ML-DSA-44 PRIVATE KEY", "ML-DSA-44"},
		{"ML-DSA-65 PRIVATE KEY", "ML-DSA-65"},
		{"ML-DSA-87 PRIVATE KEY", "ML-DSA-87"},
		{"SLH-DSA-SHAKE-128S PRIVATE KEY", "SLH-DSA-SHAKE-128s"},
		{"SLH-DSA-SHAKE-256F PRIVATE KEY", "SLH-DSA-SHAKE-256f"},
		{"PRIVATE KEY", "PKCS#8 (EC/RSA/Ed25519)"},
		{"ENCRYPTED PRIVATE KEY", "PKCS#8 (encrypted)"},
		{"CERTIFICATE", ""},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.pemType, func(t *testing.T) {
			got := algorithmFromPEMType(tt.pemType)
			if got != tt.want {
				t.Errorf("algorithmFromPEMType(%q) = %q, want %q", tt.pemType, got, tt.want)
			}
		})
	}
}

func TestF_Key_Convert_InvalidFormat(t *testing.T) {
	tc := newTestContext(t)
	resetKeyFlags()

	// Generate a key first
	keyPath := tc.path("private.pem")
	_, _ = executeCommand(rootCmd, "key", "gen",
		"--algorithm", "ecdsa-p256",
		"--out", keyPath,
	)

	resetKeyFlags()

	// Try to convert to invalid format
	_, err := executeCommand(rootCmd, "key", "convert",
		keyPath,
		"--format", "invalid",
		"--out", tc.path("out.key"),
	)
	assertError(t, err)
}

func TestF_Key_Convert_DERWithPassphrase(t *testing.T) {
	tc := newTestContext(t)
	resetKeyFlags()

	// Generate a key first
	keyPath := tc.path("private.pem")
	_, _ = executeCommand(rootCmd, "key", "gen",
		"--algorithm", "ecdsa-p256",
		"--out", keyPath,
	)

	resetKeyFlags()

	// Try to convert to DER with passphrase (should fail)
	_, err := executeCommand(rootCmd, "key", "convert",
		keyPath,
		"--format", "der",
		"--new-passphrase", "test",
		"--out", tc.path("out.der"),
	)
	assertError(t, err)
}

// =============================================================================
// Key Gen Mutual Exclusivity Tests
// =============================================================================

func TestF_Key_Gen_MutualExclusivity(t *testing.T) {
	tc := newTestContext(t)
	resetKeyFlags()

	// Create a fake HSM config
	hsmConfig := tc.writeFile("hsm.yaml", "pkcs11:\n  lib: /fake/lib.so\n  token: test\n")

	// Test --out and --hsm-config are mutually exclusive
	_, err := executeCommand(rootCmd, "key", "gen",
		"--algorithm", "ecdsa-p256",
		"--out", tc.path("key.pem"),
		"--hsm-config", hsmConfig,
		"--key-label", "test-key",
	)
	assertError(t, err)
}

func TestF_Key_Gen_HSMWithoutLabel(t *testing.T) {
	tc := newTestContext(t)
	resetKeyFlags()

	// Create a fake HSM config
	hsmConfig := tc.writeFile("hsm.yaml", "pkcs11:\n  lib: /fake/lib.so\n  token: test\n")

	// Test --hsm-config without --key-label should fail
	_, err := executeCommand(rootCmd, "key", "gen",
		"--algorithm", "ecdsa-p256",
		"--hsm-config", hsmConfig,
	)
	assertError(t, err)
}

func TestF_Key_Gen_HSMWithPassphrase(t *testing.T) {
	tc := newTestContext(t)
	resetKeyFlags()

	// Create a fake HSM config
	hsmConfig := tc.writeFile("hsm.yaml", "pkcs11:\n  lib: /fake/lib.so\n  token: test\n")

	// Test --hsm-config with --passphrase should fail
	_, err := executeCommand(rootCmd, "key", "gen",
		"--algorithm", "ecdsa-p256",
		"--hsm-config", hsmConfig,
		"--key-label", "test-key",
		"--passphrase", "secret",
	)
	assertError(t, err)
}

// =============================================================================
// Key List Mutual Exclusivity Tests
// =============================================================================

func TestF_Key_List_MutualExclusivity(t *testing.T) {
	tc := newTestContext(t)
	resetKeyFlags()

	// Create a fake HSM config
	hsmConfig := tc.writeFile("hsm.yaml", "pkcs11:\n  lib: /fake/lib.so\n  token: test\n")

	// Create a directory
	keyDir := tc.path("keys")
	_ = os.MkdirAll(keyDir, 0755)

	// Test --hsm-config and --dir are mutually exclusive
	_, err := executeCommand(rootCmd, "key", "list",
		"--hsm-config", hsmConfig,
		"--dir", keyDir,
	)
	assertError(t, err)
}

func TestF_Key_List_NeitherProvided(t *testing.T) {
	resetKeyFlags()

	// Test neither --hsm-config nor --dir provided
	_, err := executeCommand(rootCmd, "key", "list")
	assertError(t, err)
}

// =============================================================================
// PQC Public Key PEM Type Tests
// =============================================================================

func TestU_PQCPublicKeyPEMType(t *testing.T) {
	tests := []struct {
		alg      string
		expected string
	}{
		{"ml-dsa-44", "ML-DSA-44 PUBLIC KEY"},
		{"ml-dsa-65", "ML-DSA-65 PUBLIC KEY"},
		{"ml-dsa-87", "ML-DSA-87 PUBLIC KEY"},
		{"slh-dsa-sha2-128s", "SLH-DSA-SHA2-128s PUBLIC KEY"},
		{"slh-dsa-sha2-128f", "SLH-DSA-SHA2-128f PUBLIC KEY"},
		{"slh-dsa-sha2-192s", "SLH-DSA-SHA2-192s PUBLIC KEY"},
		{"slh-dsa-sha2-192f", "SLH-DSA-SHA2-192f PUBLIC KEY"},
		{"slh-dsa-sha2-256s", "SLH-DSA-SHA2-256s PUBLIC KEY"},
		{"slh-dsa-sha2-256f", "SLH-DSA-SHA2-256f PUBLIC KEY"},
		{"ml-kem-512", "ML-KEM-512 PUBLIC KEY"},
		{"ml-kem-768", "ML-KEM-768 PUBLIC KEY"},
		{"ml-kem-1024", "ML-KEM-1024 PUBLIC KEY"},
		{"unknown", "PUBLIC KEY"},
	}

	for _, tt := range tests {
		t.Run(tt.alg, func(t *testing.T) {
			result := pqcPublicKeyPEMType(crypto.AlgorithmID(tt.alg))
			if result != tt.expected {
				t.Errorf("pqcPublicKeyPEMType(%s) = %q, want %q", tt.alg, result, tt.expected)
			}
		})
	}
}

// =============================================================================
// Key Gen KEM with Passphrase Tests
// =============================================================================

func TestF_Key_Gen_KEMWithPassphrase(t *testing.T) {
	tc := newTestContext(t)
	resetKeyFlags()

	outputPath := tc.path("kem-encrypted.pem")

	_, err := executeCommand(rootCmd, "key", "gen",
		"--algorithm", "ml-kem-768",
		"--out", outputPath,
		"--passphrase", "secret123",
	)

	assertNoError(t, err)
	assertFileExists(t, outputPath)
	assertFileNotEmpty(t, outputPath)
}

// =============================================================================
// Get Key Size Tests
// =============================================================================

func TestF_Key_Info_PQCKeySize(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
	}{
		{"ML-DSA-44", "ml-dsa-44"},
		{"ML-DSA-65", "ml-dsa-65"},
		{"ML-DSA-87", "ml-dsa-87"},
		{"SLH-DSA-128s", "slh-dsa-sha2-128s"},
		{"SLH-DSA-256f", "slh-dsa-sha2-256f"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := newTestContext(t)
			resetKeyFlags()

			// Generate PQC key
			keyPath := tc.path("pqc.pem")
			_, err := executeCommand(rootCmd, "key", "gen",
				"--algorithm", tt.algorithm,
				"--out", keyPath,
			)
			assertNoError(t, err)

			resetKeyFlags()

			// Get info - should show NIST level
			_, err = executeCommand(rootCmd, "key", "info", keyPath)
			assertNoError(t, err)
		})
	}
}

// =============================================================================
// Convert PQC to DER Tests
// =============================================================================

func TestF_Key_Convert_PQCToDER(t *testing.T) {
	tc := newTestContext(t)
	resetKeyFlags()

	// Generate PQC key
	keyPath := tc.path("pqc.pem")
	_, err := executeCommand(rootCmd, "key", "gen",
		"--algorithm", "ml-dsa-65",
		"--out", keyPath,
	)
	assertNoError(t, err)

	resetKeyFlags()

	// Try to convert PQC key to DER - should fail (not supported)
	_, err = executeCommand(rootCmd, "key", "convert",
		keyPath,
		"--format", "der",
		"--out", tc.path("pqc.der"),
	)
	assertError(t, err)
}

// =============================================================================
// Print Key Info Tests (edge cases)
// =============================================================================

func TestF_Key_List_WithNonPEMFiles(t *testing.T) {
	tc := newTestContext(t)
	resetKeyFlags()

	// Create a directory with mixed files
	keyDir := tc.path("mixed")
	_ = os.MkdirAll(keyDir, 0755)

	// Create a valid key
	_, _ = executeCommand(rootCmd, "key", "gen",
		"--algorithm", "ecdsa-p256",
		"--out", keyDir+"/valid.pem",
	)
	resetKeyFlags()

	// Create a non-PEM file with .pem extension
	_ = os.WriteFile(keyDir+"/not-pem.pem", []byte("not a PEM file"), 0644)

	// Create a certificate (not a private key)
	certPEM := `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHBfpG2qz/wMAoGCCqGSM49BAMCMBQxEjAQBgNVBAMMCXRlc3Qt
Y2VydDAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMBQxEjAQBgNVBAMM
CXRlc3QtY2VydDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHkzCRb/5LQ8bUvL
-----END CERTIFICATE-----`
	_ = os.WriteFile(keyDir+"/cert.pem", []byte(certPEM), 0644)

	// List should work and skip non-key files
	_, err := executeCommand(rootCmd, "key", "list", "--dir", keyDir)
	assertNoError(t, err)
}

// =============================================================================
// Algorithm From PEM Type Additional Tests
// =============================================================================

func TestU_AlgorithmFromPEMType_AllTypes(t *testing.T) {
	tests := []struct {
		pemType string
		want    string
	}{
		{"EC PRIVATE KEY", "ECDSA"},
		{"RSA PRIVATE KEY", "RSA"},
		{"ML-DSA-44 PRIVATE KEY", "ML-DSA-44"},
		{"ML-DSA-65 PRIVATE KEY", "ML-DSA-65"},
		{"ML-DSA-87 PRIVATE KEY", "ML-DSA-87"},
		{"SLH-DSA-SHAKE-128S PRIVATE KEY", "SLH-DSA-SHAKE-128s"},
		{"SLH-DSA-SHAKE-128F PRIVATE KEY", "SLH-DSA-SHAKE-128f"},
		{"SLH-DSA-SHAKE-192S PRIVATE KEY", "SLH-DSA-SHAKE-192s"},
		{"SLH-DSA-SHAKE-192F PRIVATE KEY", "SLH-DSA-SHAKE-192f"},
		{"SLH-DSA-SHAKE-256S PRIVATE KEY", "SLH-DSA-SHAKE-256s"},
		{"SLH-DSA-SHAKE-256F PRIVATE KEY", "SLH-DSA-SHAKE-256f"},
		{"PRIVATE KEY", "PKCS#8 (EC/RSA/Ed25519)"},
		{"ENCRYPTED PRIVATE KEY", "PKCS#8 (encrypted)"},
		{"UNKNOWN TYPE", ""},
	}

	for _, tt := range tests {
		t.Run(tt.pemType, func(t *testing.T) {
			got := algorithmFromPEMType(tt.pemType)
			if got != tt.want {
				t.Errorf("algorithmFromPEMType(%q) = %q, want %q", tt.pemType, got, tt.want)
			}
		})
	}
}

// =============================================================================
// Key Info Edge Cases
// =============================================================================

func TestF_Key_Info_InvalidPEM(t *testing.T) {
	tc := newTestContext(t)
	resetKeyFlags()

	// Create a file without PEM block
	invalidPath := tc.writeFile("invalid.pem", "not a PEM file at all")

	_, err := executeCommand(rootCmd, "key", "info", invalidPath)
	assertError(t, err)
}
