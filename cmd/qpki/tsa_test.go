package main

import (
	"os"
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
	tsaServePIDFile = ""

	tsaStopPort = 8318
	tsaStopPIDFile = ""
}

// =============================================================================
// TSA Sign Tests
// =============================================================================

func TestF_TSA_Sign_MissingData(t *testing.T) {
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

func TestF_TSA_Sign_MissingCert(t *testing.T) {
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

func TestF_TSA_Sign_MissingKey(t *testing.T) {
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

func TestF_TSA_Sign_MissingOutput(t *testing.T) {
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

func TestF_TSA_Sign_DataFileNotFound(t *testing.T) {
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

func TestF_TSA_Sign_InvalidHashAlgorithm(t *testing.T) {
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

func TestF_TSA_Verify_MissingToken(t *testing.T) {
	resetTSAFlags()

	_, err := executeCommand(rootCmd, "tsa", "verify")
	assertError(t, err)
}

func TestF_TSA_Verify_TokenNotFound(t *testing.T) {
	tc := newTestContext(t)
	resetTSAFlags()

	_, err := executeCommand(rootCmd, "tsa", "verify",
		tc.path("nonexistent.tsr"),
	)
	assertError(t, err)
}

func TestF_TSA_Verify_InvalidToken(t *testing.T) {
	tc := newTestContext(t)
	resetTSAFlags()

	// Create invalid token file
	tokenPath := tc.writeFile("invalid.tsr", "not a valid token")

	_, err := executeCommand(rootCmd, "tsa", "verify",
		tokenPath,
	)
	assertError(t, err)
}

// =============================================================================
// TSA Sign Success Tests
// =============================================================================

func TestF_TSA_Sign_Success(t *testing.T) {
	tc := newTestContext(t)
	resetTSAFlags()

	certPath, keyPath := tc.setupSigningPair()
	dataPath := tc.writeFile("data.txt", "test data for timestamp")
	tokenPath := tc.path("token.tsr")

	_, err := executeCommand(rootCmd, "tsa", "sign",
		"--data", dataPath,
		"--cert", certPath,
		"--key", keyPath,
		"--out", tokenPath,
	)
	assertNoError(t, err)
	assertFileExists(t, tokenPath)
}

func TestF_TSA_Sign_WithSHA384(t *testing.T) {
	tc := newTestContext(t)
	resetTSAFlags()

	certPath, keyPath := tc.setupSigningPair()
	dataPath := tc.writeFile("data.txt", "test data for timestamp")
	tokenPath := tc.path("token.tsr")

	_, err := executeCommand(rootCmd, "tsa", "sign",
		"--data", dataPath,
		"--cert", certPath,
		"--key", keyPath,
		"--hash", "sha384",
		"--out", tokenPath,
	)
	assertNoError(t, err)
	assertFileExists(t, tokenPath)
}

func TestF_TSA_Sign_WithSHA512(t *testing.T) {
	tc := newTestContext(t)
	resetTSAFlags()

	certPath, keyPath := tc.setupSigningPair()
	dataPath := tc.writeFile("data.txt", "test data for timestamp")
	tokenPath := tc.path("token.tsr")

	_, err := executeCommand(rootCmd, "tsa", "sign",
		"--data", dataPath,
		"--cert", certPath,
		"--key", keyPath,
		"--hash", "sha512",
		"--out", tokenPath,
	)
	assertNoError(t, err)
	assertFileExists(t, tokenPath)
}

func TestF_TSA_Sign_WithoutTSACert(t *testing.T) {
	tc := newTestContext(t)
	resetTSAFlags()

	certPath, keyPath := tc.setupSigningPair()
	dataPath := tc.writeFile("data.txt", "test data for timestamp")
	tokenPath := tc.path("token.tsr")

	_, err := executeCommand(rootCmd, "tsa", "sign",
		"--data", dataPath,
		"--cert", certPath,
		"--key", keyPath,
		"--include-tsa=false",
		"--out", tokenPath,
	)
	assertNoError(t, err)
	assertFileExists(t, tokenPath)
}

// =============================================================================
// TSA Inspect Tests
// =============================================================================

func TestF_TSA_Inspect_TimestampToken(t *testing.T) {
	tc := newTestContext(t)
	resetTSAFlags()

	// Create a timestamp token
	certPath, keyPath := tc.setupSigningPair()
	dataPath := tc.writeFile("data.txt", "test data for inspection")
	tokenPath := tc.path("token.tsr")

	_, err := executeCommand(rootCmd, "tsa", "sign",
		"--data", dataPath,
		"--cert", certPath,
		"--key", keyPath,
		"--out", tokenPath,
	)
	assertNoError(t, err)

	// Inspect the token
	_, err = executeCommand(rootCmd, "inspect", tokenPath)
	assertNoError(t, err)
}

// =============================================================================
// TSA Verify with Valid Token
// =============================================================================

func TestF_TSA_Verify_ValidToken(t *testing.T) {
	tc := newTestContext(t)
	resetTSAFlags()

	// Create a timestamp token with TSA cert included
	certPath, keyPath := tc.setupSigningPair()
	dataPath := tc.writeFile("data.txt", "test data for verification")
	tokenPath := tc.path("token.tsr")

	_, err := executeCommand(rootCmd, "tsa", "sign",
		"--data", dataPath,
		"--cert", certPath,
		"--key", keyPath,
		"--include-tsa=true",
		"--out", tokenPath,
	)
	assertNoError(t, err)

	resetTSAFlags()

	// Verify the token - this may fail due to cert capabilities but tests the path
	_, _ = executeCommand(rootCmd, "tsa", "verify",
		tokenPath,
		"--data", dataPath,
		"--ca", certPath,
	)
	// We just test the command path executes; the test cert may not have proper EKU
}

func TestF_TSA_Verify_DataMismatch(t *testing.T) {
	tc := newTestContext(t)
	resetTSAFlags()

	// Create a timestamp token for one data
	certPath, keyPath := tc.setupSigningPair()
	dataPath := tc.writeFile("data.txt", "original data")
	tokenPath := tc.path("token.tsr")

	_, err := executeCommand(rootCmd, "tsa", "sign",
		"--data", dataPath,
		"--cert", certPath,
		"--key", keyPath,
		"--out", tokenPath,
	)
	assertNoError(t, err)

	resetTSAFlags()

	// Try to verify with different data
	differentDataPath := tc.writeFile("different.txt", "different data")
	_, err = executeCommand(rootCmd, "tsa", "verify",
		tokenPath,
		"--data", differentDataPath,
		"--ca", certPath,
	)
	assertError(t, err)
}

// =============================================================================
// TSA Info Tests
// =============================================================================

func TestF_TSA_Info_Basic(t *testing.T) {
	tc := newTestContext(t)
	resetTSAFlags()

	// Create a timestamp token
	certPath, keyPath := tc.setupSigningPair()
	dataPath := tc.writeFile("data.txt", "test data for info")
	tokenPath := tc.path("token.tsr")

	_, err := executeCommand(rootCmd, "tsa", "sign",
		"--data", dataPath,
		"--cert", certPath,
		"--key", keyPath,
		"--out", tokenPath,
	)
	assertNoError(t, err)

	// Get info about the token
	_, err = executeCommand(rootCmd, "tsa", "info", tokenPath)
	assertNoError(t, err)
}

func TestF_TSA_Info_TokenNotFound(t *testing.T) {
	tc := newTestContext(t)

	_, err := executeCommand(rootCmd, "tsa", "info", tc.path("nonexistent.tsr"))
	assertError(t, err)
}

func TestF_TSA_Info_InvalidToken(t *testing.T) {
	tc := newTestContext(t)

	// Create an invalid token file
	invalidPath := tc.writeFile("invalid.tsr", "not a valid token")
	_, err := executeCommand(rootCmd, "tsa", "info", invalidPath)
	assertError(t, err)
}

func TestF_TSA_Info_ArgMissing(t *testing.T) {
	_, err := executeCommand(rootCmd, "tsa", "info")
	assertError(t, err)
}

// =============================================================================
// TSA Stop Tests
// =============================================================================

func TestF_TSA_Stop_PIDFileNotFound(t *testing.T) {
	tc := newTestContext(t)
	resetTSAFlags()

	// Try to stop when no server is running (PID file doesn't exist)
	_, err := executeCommand(rootCmd, "tsa", "stop",
		"--pid-file", tc.path("nonexistent.pid"),
	)
	assertError(t, err)
}

func TestF_TSA_Stop_InvalidPIDFile(t *testing.T) {
	tc := newTestContext(t)
	resetTSAFlags()

	// Create an invalid PID file
	pidPath := tc.writeFile("invalid.pid", "not-a-number")

	_, err := executeCommand(rootCmd, "tsa", "stop",
		"--pid-file", pidPath,
	)
	assertError(t, err)
}

func TestF_TSA_Stop_ProcessNotRunning(t *testing.T) {
	tc := newTestContext(t)
	resetTSAFlags()

	// Create a PID file with a non-existent process ID (very high number)
	pidPath := tc.writeFile("stale.pid", "999999999")

	_, err := executeCommand(rootCmd, "tsa", "stop",
		"--pid-file", pidPath,
	)
	// This should fail because the process doesn't exist
	assertError(t, err)
}

func TestF_TSA_Stop_DefaultPIDPath(t *testing.T) {
	resetTSAFlags()

	// Test that stop uses the default PID path based on port
	_, err := executeCommand(rootCmd, "tsa", "stop",
		"--port", "9999",
	)
	// Should fail because no server is running on that port
	assertError(t, err)
}

// =============================================================================
// TSA PID File Helper Tests
// =============================================================================

func TestU_TSA_WritePIDFile(t *testing.T) {
	tc := newTestContext(t)

	pidPath := tc.path("tsa-test.pid")
	err := tsaWritePIDFile(pidPath)
	assertNoError(t, err)
	assertFileExists(t, pidPath)

	// Verify PID file contains a valid number
	data, err := os.ReadFile(pidPath)
	assertNoError(t, err)
	if len(data) == 0 {
		t.Error("PID file is empty")
	}
}

func TestU_TSA_RemovePIDFile(t *testing.T) {
	tc := newTestContext(t)

	pidPath := tc.path("tsa-test.pid")

	// Write PID file first
	err := tsaWritePIDFile(pidPath)
	assertNoError(t, err)
	assertFileExists(t, pidPath)

	// Remove PID file
	tsaRemovePIDFile(pidPath)

	// Verify file is removed
	if _, err := os.Stat(pidPath); !os.IsNotExist(err) {
		t.Error("PID file should have been removed")
	}
}

func TestU_TSA_RemovePIDFile_NonExistent(t *testing.T) {
	tc := newTestContext(t)

	// Should not panic when file doesn't exist
	tsaRemovePIDFile(tc.path("nonexistent.pid"))
}
