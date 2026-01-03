package main

import (
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
