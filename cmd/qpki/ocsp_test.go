package main

import (
	"os"
	"testing"
)

// resetOCSPFlags resets all OCSP command flags to their default values.
func resetOCSPFlags() {
	ocspSignSerial = ""
	ocspSignStatus = "good"
	ocspSignRevocationTime = ""
	ocspSignRevocationReason = ""
	ocspSignCA = ""
	ocspSignCert = ""
	ocspSignKey = ""
	ocspSignPassphrase = ""
	ocspSignOutput = ""
	ocspSignValidity = "1h"

	ocspVerifyResponse = ""
	ocspVerifyCA = ""
	ocspVerifyCert = ""

	ocspServePort = 8080
	ocspServeCADir = ""
	ocspServeCert = ""
	ocspServeKey = ""
	ocspServePassphrase = ""
	ocspServeValidity = "1h"
	ocspServeCopyNonce = true
	ocspServePIDFile = ""

	ocspStopPort = 8080
	ocspStopPIDFile = ""

	ocspRequestIssuer = ""
	ocspRequestCert = ""
	ocspRequestNonce = false
	ocspRequestOutput = ""
}

// =============================================================================
// OCSP Sign Tests
// =============================================================================

func TestF_OCSP_Sign_MissingSerial(t *testing.T) {
	tc := newTestContext(t)
	resetOCSPFlags()

	certPath, keyPath := tc.setupSigningPair()

	_, err := executeCommand(rootCmd, "ocsp", "sign",
		"--ca", certPath,
		"--key", keyPath,
		"--out", tc.path("response.ocsp"),
	)
	assertError(t, err)
}

func TestF_OCSP_Sign_MissingCA(t *testing.T) {
	tc := newTestContext(t)
	resetOCSPFlags()

	_, keyPath := tc.setupSigningPair()

	_, err := executeCommand(rootCmd, "ocsp", "sign",
		"--serial", "01",
		"--key", keyPath,
		"--out", tc.path("response.ocsp"),
	)
	assertError(t, err)
}

func TestF_OCSP_Sign_MissingKey(t *testing.T) {
	tc := newTestContext(t)
	resetOCSPFlags()

	certPath, _ := tc.setupSigningPair()

	_, err := executeCommand(rootCmd, "ocsp", "sign",
		"--serial", "01",
		"--ca", certPath,
		"--out", tc.path("response.ocsp"),
	)
	assertError(t, err)
}

func TestF_OCSP_Sign_MissingOutput(t *testing.T) {
	tc := newTestContext(t)
	resetOCSPFlags()

	certPath, keyPath := tc.setupSigningPair()

	_, err := executeCommand(rootCmd, "ocsp", "sign",
		"--serial", "01",
		"--ca", certPath,
		"--key", keyPath,
	)
	assertError(t, err)
}

func TestF_OCSP_Sign_InvalidSerial(t *testing.T) {
	tc := newTestContext(t)
	resetOCSPFlags()

	certPath, keyPath := tc.setupSigningPair()

	_, err := executeCommand(rootCmd, "ocsp", "sign",
		"--serial", "not-hex",
		"--ca", certPath,
		"--key", keyPath,
		"--out", tc.path("response.ocsp"),
	)
	assertError(t, err)
}

func TestF_OCSP_Sign_InvalidStatus(t *testing.T) {
	tc := newTestContext(t)
	resetOCSPFlags()

	certPath, keyPath := tc.setupSigningPair()

	_, err := executeCommand(rootCmd, "ocsp", "sign",
		"--serial", "01",
		"--status", "invalid-status",
		"--ca", certPath,
		"--key", keyPath,
		"--out", tc.path("response.ocsp"),
	)
	assertError(t, err)
}

func TestF_OCSP_Sign_Good(t *testing.T) {
	tc := newTestContext(t)
	resetOCSPFlags()

	certPath, keyPath := tc.setupSigningPair()
	responsePath := tc.path("response.ocsp")

	_, err := executeCommand(rootCmd, "ocsp", "sign",
		"--serial", "01",
		"--status", "good",
		"--ca", certPath,
		"--key", keyPath,
		"--out", responsePath,
	)
	assertNoError(t, err)
	assertFileExists(t, responsePath)
}

func TestF_OCSP_Sign_Revoked(t *testing.T) {
	tc := newTestContext(t)
	resetOCSPFlags()

	certPath, keyPath := tc.setupSigningPair()
	responsePath := tc.path("response.ocsp")

	_, err := executeCommand(rootCmd, "ocsp", "sign",
		"--serial", "02",
		"--status", "revoked",
		"--revocation-time", "2024-01-01T00:00:00Z",
		"--revocation-reason", "keyCompromise",
		"--ca", certPath,
		"--key", keyPath,
		"--out", responsePath,
	)
	assertNoError(t, err)
	assertFileExists(t, responsePath)
}

func TestF_OCSP_Sign_Unknown(t *testing.T) {
	tc := newTestContext(t)
	resetOCSPFlags()

	certPath, keyPath := tc.setupSigningPair()
	responsePath := tc.path("response.ocsp")

	_, err := executeCommand(rootCmd, "ocsp", "sign",
		"--serial", "03",
		"--status", "unknown",
		"--ca", certPath,
		"--key", keyPath,
		"--out", responsePath,
	)
	assertNoError(t, err)
	assertFileExists(t, responsePath)
}

func TestF_OCSP_Sign_AllRevocationReasons(t *testing.T) {
	reasons := []string{
		"keyCompromise",
		"caCompromise",
		"affiliationChanged",
		"superseded",
		"cessationOfOperation",
		"certificateHold",
		"privilegeWithdrawn",
		"aaCompromise",
	}

	for _, reason := range reasons {
		t.Run("[Functional] OCSPSign: "+reason, func(t *testing.T) {
			tc := newTestContext(t)
			resetOCSPFlags()

			certPath, keyPath := tc.setupSigningPair()
			responsePath := tc.path("response.ocsp")

			_, err := executeCommand(rootCmd, "ocsp", "sign",
				"--serial", "02",
				"--status", "revoked",
				"--revocation-time", "2024-01-01T00:00:00Z",
				"--revocation-reason", reason,
				"--ca", certPath,
				"--key", keyPath,
				"--out", responsePath,
			)
			assertNoError(t, err)
		})
	}
}

// =============================================================================
// OCSP Verify Tests
// =============================================================================

func TestF_OCSP_Verify_MissingResponse(t *testing.T) {
	resetOCSPFlags()

	_, err := executeCommand(rootCmd, "ocsp", "verify")
	assertError(t, err)
}

func TestF_OCSP_Verify_GoodResponse(t *testing.T) {
	tc := newTestContext(t)
	resetOCSPFlags()

	// Create OCSP response
	certPath, keyPath := tc.setupSigningPair()
	responsePath := tc.path("response.ocsp")

	_, err := executeCommand(rootCmd, "ocsp", "sign",
		"--serial", "01",
		"--status", "good",
		"--ca", certPath,
		"--key", keyPath,
		"--out", responsePath,
	)
	assertNoError(t, err)

	resetOCSPFlags()

	// Verify the response
	_, err = executeCommand(rootCmd, "ocsp", "verify",
		responsePath,
		"--ca", certPath,
	)
	assertNoError(t, err)
}

func TestF_OCSP_Verify_RevokedResponse(t *testing.T) {
	tc := newTestContext(t)
	resetOCSPFlags()

	// Create OCSP response
	certPath, keyPath := tc.setupSigningPair()
	responsePath := tc.path("response.ocsp")

	_, err := executeCommand(rootCmd, "ocsp", "sign",
		"--serial", "02",
		"--status", "revoked",
		"--revocation-time", "2024-01-01T00:00:00Z",
		"--ca", certPath,
		"--key", keyPath,
		"--out", responsePath,
	)
	assertNoError(t, err)

	resetOCSPFlags()

	// Verify the response (should still succeed - verify just checks the signature)
	_, err = executeCommand(rootCmd, "ocsp", "verify",
		responsePath,
		"--ca", certPath,
	)
	assertNoError(t, err)
}

func TestF_OCSP_Verify_ResponseNotFound(t *testing.T) {
	tc := newTestContext(t)
	resetOCSPFlags()

	_, err := executeCommand(rootCmd, "ocsp", "verify",
		tc.path("nonexistent.ocsp"),
	)
	assertError(t, err)
}

func TestF_OCSP_Verify_InvalidResponse(t *testing.T) {
	tc := newTestContext(t)
	resetOCSPFlags()

	// Create invalid response file
	responsePath := tc.writeFile("invalid.ocsp", "not a valid response")

	_, err := executeCommand(rootCmd, "ocsp", "verify",
		responsePath,
	)
	assertError(t, err)
}

// =============================================================================
// OCSP Info Tests
// =============================================================================

func TestF_OCSP_Info_ResponseNotFound(t *testing.T) {
	tc := newTestContext(t)
	resetOCSPFlags()

	_, err := executeCommand(rootCmd, "ocsp", "info", tc.path("nonexistent.ocsp"))
	assertError(t, err)
}

func TestF_OCSP_Info_InvalidResponse(t *testing.T) {
	tc := newTestContext(t)
	resetOCSPFlags()

	// Create invalid response file
	responsePath := tc.writeFile("invalid.ocsp", "not a valid response")

	_, err := executeCommand(rootCmd, "ocsp", "info", responsePath)
	assertError(t, err)
}

// =============================================================================
// OCSP Request Tests
// =============================================================================

func TestF_OCSP_Request_MissingIssuer(t *testing.T) {
	tc := newTestContext(t)
	resetOCSPFlags()

	certPath, _ := tc.setupSigningPair()

	_, err := executeCommand(rootCmd, "ocsp", "request",
		"--cert", certPath,
		"--out", tc.path("request.ocsp"),
	)
	assertError(t, err)
}

func TestF_OCSP_Request_MissingCert(t *testing.T) {
	tc := newTestContext(t)
	resetOCSPFlags()

	certPath, _ := tc.setupSigningPair()

	_, err := executeCommand(rootCmd, "ocsp", "request",
		"--issuer", certPath,
		"--out", tc.path("request.ocsp"),
	)
	assertError(t, err)
}

func TestF_OCSP_Request_MissingOutput(t *testing.T) {
	tc := newTestContext(t)
	resetOCSPFlags()

	certPath, _ := tc.setupSigningPair()

	_, err := executeCommand(rootCmd, "ocsp", "request",
		"--issuer", certPath,
		"--cert", certPath,
	)
	assertError(t, err)
}

func TestF_OCSP_Request_IssuerNotFound(t *testing.T) {
	tc := newTestContext(t)
	resetOCSPFlags()

	certPath, _ := tc.setupSigningPair()

	_, err := executeCommand(rootCmd, "ocsp", "request",
		"--issuer", tc.path("nonexistent.crt"),
		"--cert", certPath,
		"--out", tc.path("request.ocsp"),
	)
	assertError(t, err)
}

// =============================================================================
// OCSP Serve Tests (just flag validation, not actual serving)
// =============================================================================

func TestF_OCSP_Serve_MissingCADir(t *testing.T) {
	resetOCSPFlags()

	// This should fail because --ca-dir is required
	_, err := executeCommand(rootCmd, "ocsp", "serve")
	assertError(t, err)
}

// =============================================================================
// OCSP Info Tests
// =============================================================================

func TestF_OCSP_Info_GoodResponse(t *testing.T) {
	tc := newTestContext(t)
	resetOCSPFlags()

	certPath, keyPath := tc.setupSigningPair()
	responsePath := tc.path("response.ocsp")

	// Create a signed OCSP response
	_, err := executeCommand(rootCmd, "ocsp", "sign",
		"--serial", "123456",
		"--status", "good",
		"--ca", certPath,
		"--key", keyPath,
		"--out", responsePath,
	)
	assertNoError(t, err)

	// Get info about the response
	_, err = executeCommand(rootCmd, "ocsp", "info", responsePath)
	assertNoError(t, err)
}

func TestF_OCSP_Info_RevokedResponse(t *testing.T) {
	tc := newTestContext(t)
	resetOCSPFlags()

	certPath, keyPath := tc.setupSigningPair()
	responsePath := tc.path("response.ocsp")

	// Create a signed OCSP response for revoked status
	_, err := executeCommand(rootCmd, "ocsp", "sign",
		"--serial", "ABCDEF",
		"--status", "revoked",
		"--revocation-reason", "keyCompromise",
		"--ca", certPath,
		"--key", keyPath,
		"--out", responsePath,
	)
	assertNoError(t, err)

	// Get info about the response
	_, err = executeCommand(rootCmd, "ocsp", "info", responsePath)
	assertNoError(t, err)
}

func TestF_OCSP_Info_ArgMissing(t *testing.T) {
	_, err := executeCommand(rootCmd, "ocsp", "info")
	assertError(t, err)
}

// =============================================================================
// OCSP Stop Tests
// =============================================================================

func TestF_OCSP_Stop_PIDFileNotFound(t *testing.T) {
	tc := newTestContext(t)
	resetOCSPFlags()

	// Try to stop when no server is running (PID file doesn't exist)
	_, err := executeCommand(rootCmd, "ocsp", "stop",
		"--pid-file", tc.path("nonexistent.pid"),
	)
	assertError(t, err)
}

func TestF_OCSP_Stop_InvalidPIDFile(t *testing.T) {
	tc := newTestContext(t)
	resetOCSPFlags()

	// Create an invalid PID file
	pidPath := tc.writeFile("invalid.pid", "not-a-number")

	_, err := executeCommand(rootCmd, "ocsp", "stop",
		"--pid-file", pidPath,
	)
	assertError(t, err)
}

func TestF_OCSP_Stop_ProcessNotRunning(t *testing.T) {
	tc := newTestContext(t)
	resetOCSPFlags()

	// Create a PID file with a non-existent process ID (very high number)
	pidPath := tc.writeFile("stale.pid", "999999999")

	_, err := executeCommand(rootCmd, "ocsp", "stop",
		"--pid-file", pidPath,
	)
	// This should fail because the process doesn't exist
	assertError(t, err)
}

func TestF_OCSP_Stop_DefaultPIDPath(t *testing.T) {
	resetOCSPFlags()

	// Test that stop uses the default PID path based on port
	_, err := executeCommand(rootCmd, "ocsp", "stop",
		"--port", "9999",
	)
	// Should fail because no server is running on that port
	assertError(t, err)
}

// =============================================================================
// PID File Helper Tests
// =============================================================================

func TestU_WritePIDFile(t *testing.T) {
	tc := newTestContext(t)

	pidPath := tc.path("test.pid")
	err := writePIDFile(pidPath)
	assertNoError(t, err)
	assertFileExists(t, pidPath)

	// Verify PID file contains a valid number
	data, err := os.ReadFile(pidPath)
	assertNoError(t, err)
	if len(data) == 0 {
		t.Error("PID file is empty")
	}
}

func TestU_RemovePIDFile(t *testing.T) {
	tc := newTestContext(t)

	pidPath := tc.path("test.pid")

	// Write PID file first
	err := writePIDFile(pidPath)
	assertNoError(t, err)
	assertFileExists(t, pidPath)

	// Remove PID file
	removePIDFile(pidPath)

	// Verify file is removed
	if _, err := os.Stat(pidPath); !os.IsNotExist(err) {
		t.Error("PID file should have been removed")
	}
}

func TestU_RemovePIDFile_NonExistent(t *testing.T) {
	tc := newTestContext(t)

	// Should not panic when file doesn't exist
	removePIDFile(tc.path("nonexistent.pid"))
}
