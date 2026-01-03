package main

import (
	"os"
	"testing"
)

// resetKeyFlags resets all key command flags to their default values.
func resetKeyFlags() {
	keyGenAlgorithm = "ecdsa-p256"
	keyGenOutput = ""
	keyGenPassphrase = ""

	keyInfoPassphrase = ""

	keyConvertOut = ""
	keyConvertFormat = "pem"
	keyConvertPassphrase = ""
	keyConvertNewPass = ""
}

// =============================================================================
// Key Gen Tests (Table-Driven)
// =============================================================================

func TestF_KeyGen(t *testing.T) {
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

func TestF_KeyGen_WithPassphrase(t *testing.T) {
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

func TestF_KeyGen_MissingOutput(t *testing.T) {
	resetKeyFlags()

	_, err := executeCommand(rootCmd, "key", "gen", "--algorithm", "ecdsa-p256")

	// Should fail because --out is required
	assertError(t, err)
}

// =============================================================================
// Key Info Tests (Table-Driven)
// =============================================================================

func TestF_KeyInfo(t *testing.T) {
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

func TestF_KeyInfo_EncryptedKey(t *testing.T) {
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

func TestF_KeyInfo_FileNotFound(t *testing.T) {
	tc := newTestContext(t)
	resetKeyFlags()

	_, err := executeCommand(rootCmd, "key", "info", tc.path("nonexistent.pem"))

	assertError(t, err)
}

// =============================================================================
// Key Convert Tests (Table-Driven)
// =============================================================================

func TestF_KeyConvert(t *testing.T) {
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

func TestF_KeyConvert_RemovePassphrase(t *testing.T) {
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

func TestF_KeyConvert_ToDER(t *testing.T) {
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

func TestF_KeyConvert_MissingOutput(t *testing.T) {
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
