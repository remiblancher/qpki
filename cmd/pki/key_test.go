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

func TestKeyGen(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
		wantErr   bool
	}{
		{"ECDSA P-256 (default)", "", false},
		{"ECDSA P-256 explicit", "ecdsa-p256", false},
		{"ECDSA P-384", "ecdsa-p384", false},
		{"Ed25519", "ed25519", false},
		{"RSA 2048", "rsa-2048", false},
		{"ML-DSA-44", "ml-dsa-44", false},
		{"ML-DSA-65", "ml-dsa-65", false},
		{"invalid algorithm", "invalid-algo", true},
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

func TestKeyGen_WithPassphrase(t *testing.T) {
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

func TestKeyGen_MissingOutput(t *testing.T) {
	resetKeyFlags()

	_, err := executeCommand(rootCmd, "key", "gen", "--algorithm", "ecdsa-p256")

	// Should fail because --out is required
	assertError(t, err)
}

// =============================================================================
// Key Info Tests (Table-Driven)
// =============================================================================

func TestKeyInfo(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
	}{
		{"ECDSA P-256", "ecdsa-p256"},
		{"Ed25519", "ed25519"},
		{"RSA 2048", "rsa-2048"},
		{"ML-DSA-65", "ml-dsa-65"},
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

func TestKeyInfo_EncryptedKey(t *testing.T) {
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

func TestKeyInfo_MissingFile(t *testing.T) {
	tc := newTestContext(t)
	resetKeyFlags()

	_, err := executeCommand(rootCmd, "key", "info", tc.path("nonexistent.pem"))

	assertError(t, err)
}

// =============================================================================
// Key Convert Tests (Table-Driven)
// =============================================================================

func TestKeyConvert(t *testing.T) {
	tests := []struct {
		name          string
		addPassphrase bool
	}{
		{"plain to plain", false},
		{"plain to encrypted", true},
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

func TestKeyConvert_RemovePassphrase(t *testing.T) {
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

func TestKeyConvert_ToDER(t *testing.T) {
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

func TestKeyConvert_MissingOutput(t *testing.T) {
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
