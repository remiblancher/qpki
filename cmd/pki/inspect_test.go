package main

import (
	"path/filepath"
	"testing"
)

// =============================================================================
// Inspect Certificate Tests
// =============================================================================

func TestInspect_Certificate(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create a CA to get a certificate
	caDir := tc.path("ca")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--name", "Test CA",
		"--profile", "ec/root-ca",
		"--dir", caDir,
	)
	assertNoError(t, err)

	// Inspect the CA certificate
	certPath := filepath.Join(caDir, "ca.crt")
	_, err = executeCommand(rootCmd, "inspect", certPath)

	assertNoError(t, err)
}

// =============================================================================
// Inspect Private Key Tests
// =============================================================================

func TestInspect_PrivateKey(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
	}{
		{"ECDSA key", "ecdsa-p256"},
		{"Ed25519 key", "ed25519"},
		{"RSA key", "rsa-2048"},
		{"ML-DSA key", "ml-dsa-65"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := newTestContext(t)
			resetKeyFlags()

			keyPath := tc.path("key.pem")
			_, err := executeCommand(rootCmd, "key", "gen",
				"--algorithm", tt.algorithm,
				"--out", keyPath,
			)
			assertNoError(t, err)

			// Inspect the key
			_, err = executeCommand(rootCmd, "inspect", keyPath)
			assertNoError(t, err)
		})
	}
}

func TestInspect_EncryptedKey(t *testing.T) {
	tc := newTestContext(t)
	resetKeyFlags()

	keyPath := tc.path("encrypted.pem")
	_, err := executeCommand(rootCmd, "key", "gen",
		"--algorithm", "ecdsa-p256",
		"--out", keyPath,
		"--passphrase", "secret123",
	)
	assertNoError(t, err)

	// Inspect should work even for encrypted keys
	_, err = executeCommand(rootCmd, "inspect", keyPath)
	assertNoError(t, err)
}

// =============================================================================
// Inspect CRL Tests
// =============================================================================

func TestInspect_CRL(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create CA
	caDir := tc.path("ca")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--name", "Test CA",
		"--profile", "ec/root-ca",
		"--dir", caDir,
	)
	assertNoError(t, err)

	resetCAFlags()

	// Generate CRL
	_, err = executeCommand(rootCmd, "ca", "crl", "gen", "--ca-dir", caDir)
	assertNoError(t, err)

	// Inspect the CRL
	crlPath := filepath.Join(caDir, "crl", "ca.crl")
	_, err = executeCommand(rootCmd, "inspect", crlPath)
	assertNoError(t, err)
}

// =============================================================================
// Inspect Error Cases
// =============================================================================

func TestInspect_FileNotFound(t *testing.T) {
	tc := newTestContext(t)

	_, err := executeCommand(rootCmd, "inspect", tc.path("nonexistent.pem"))
	assertError(t, err)
}

func TestInspect_InvalidFile(t *testing.T) {
	tc := newTestContext(t)

	// Create a file with invalid content
	invalidPath := tc.writeFile("invalid.pem", "this is not a valid PEM file")

	_, err := executeCommand(rootCmd, "inspect", invalidPath)
	assertError(t, err)
}

func TestInspect_MissingArgument(t *testing.T) {
	_, err := executeCommand(rootCmd, "inspect")
	assertError(t, err)
}
