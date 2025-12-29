package main

import (
	"testing"
)

// resetTSAFlags resets all TSA command flags to their default values.
func resetTSAFlags() {
	tsaSignData = ""
	tsaSignCert = ""
	tsaSignKey = ""
	tsaSignPassphrase = ""
	tsaSignHash = "sha256"
	tsaSignPolicy = "1.3.6.1.4.1.99999.2.1"
	tsaSignOutput = ""
	tsaSignIncludeTSA = true

	tsaVerifyToken = ""
	tsaVerifyData = ""
	tsaVerifyCA = ""

	tsaServePort = 8318
	tsaServeCert = ""
	tsaServeKey = ""
	tsaServePassphrase = ""
	tsaServePolicy = "1.3.6.1.4.1.99999.2.1"
	tsaServeAccuracy = 1
	tsaServeTLSCert = ""
	tsaServeTLSKey = ""
}

// =============================================================================
// TSA Sign Tests
// =============================================================================

func TestTSASign_MissingData(t *testing.T) {
	tc := newTestContext(t)
	resetTSAFlags()

	certPath, keyPath := tc.setupSigningPair()

	_, err := executeCommand(rootCmd, "tsa", "sign",
		"--cert", certPath,
		"--key", keyPath,
		"--out", tc.path("token.tsr"),
	)
	assertError(t, err)
}

func TestTSASign_MissingCert(t *testing.T) {
	tc := newTestContext(t)
	resetTSAFlags()

	_, keyPath := tc.setupSigningPair()
	dataPath := tc.writeFile("data.txt", "test data")

	_, err := executeCommand(rootCmd, "tsa", "sign",
		"--data", dataPath,
		"--key", keyPath,
		"--out", tc.path("token.tsr"),
	)
	assertError(t, err)
}

func TestTSASign_MissingKey(t *testing.T) {
	tc := newTestContext(t)
	resetTSAFlags()

	certPath, _ := tc.setupSigningPair()
	dataPath := tc.writeFile("data.txt", "test data")

	_, err := executeCommand(rootCmd, "tsa", "sign",
		"--data", dataPath,
		"--cert", certPath,
		"--out", tc.path("token.tsr"),
	)
	assertError(t, err)
}

func TestTSASign_MissingOutput(t *testing.T) {
	tc := newTestContext(t)
	resetTSAFlags()

	certPath, keyPath := tc.setupSigningPair()
	dataPath := tc.writeFile("data.txt", "test data")

	_, err := executeCommand(rootCmd, "tsa", "sign",
		"--data", dataPath,
		"--cert", certPath,
		"--key", keyPath,
	)
	assertError(t, err)
}

func TestTSASign_DataFileNotFound(t *testing.T) {
	tc := newTestContext(t)
	resetTSAFlags()

	certPath, keyPath := tc.setupSigningPair()

	_, err := executeCommand(rootCmd, "tsa", "sign",
		"--data", tc.path("nonexistent.txt"),
		"--cert", certPath,
		"--key", keyPath,
		"--out", tc.path("token.tsr"),
	)
	assertError(t, err)
}

func TestTSASign_InvalidHashAlgorithm(t *testing.T) {
	tc := newTestContext(t)
	resetTSAFlags()

	certPath, keyPath := tc.setupSigningPair()
	dataPath := tc.writeFile("data.txt", "test data")

	_, err := executeCommand(rootCmd, "tsa", "sign",
		"--data", dataPath,
		"--cert", certPath,
		"--key", keyPath,
		"--hash", "invalid-hash",
		"--out", tc.path("token.tsr"),
	)
	assertError(t, err)
}

// =============================================================================
// TSA Verify Tests
// =============================================================================

func TestTSAVerify_MissingToken(t *testing.T) {
	resetTSAFlags()

	_, err := executeCommand(rootCmd, "tsa", "verify")
	assertError(t, err)
}

func TestTSAVerify_TokenNotFound(t *testing.T) {
	tc := newTestContext(t)
	resetTSAFlags()

	_, err := executeCommand(rootCmd, "tsa", "verify",
		"--token", tc.path("nonexistent.tsr"),
	)
	assertError(t, err)
}

func TestTSAVerify_InvalidToken(t *testing.T) {
	tc := newTestContext(t)
	resetTSAFlags()

	// Create invalid token file
	tokenPath := tc.writeFile("invalid.tsr", "not a valid token")

	_, err := executeCommand(rootCmd, "tsa", "verify",
		"--token", tokenPath,
	)
	assertError(t, err)
}
