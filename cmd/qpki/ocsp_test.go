package main

import (
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/remiblancher/post-quantum-pki/pkg/ocsp"
)

// testTime returns the current time for tests.
func testTime() time.Time {
	return time.Now()
}

// testDuration returns a standard test duration.
func testDuration() time.Duration {
	return time.Hour
}

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
	ocspSignHSMConfig = ""
	ocspSignKeyLabel = ""
	ocspSignKeyID = ""

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
	ocspServeHSMConfig = ""
	ocspServeKeyLabel = ""
	ocspServeKeyID = ""

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

// =============================================================================
// Helper Function Unit Tests
// =============================================================================

func TestU_RevocationReasonString(t *testing.T) {
	tests := []struct {
		reason   ocsp.RevocationReason
		expected string
	}{
		{ocsp.ReasonUnspecified, "unspecified"},
		{ocsp.ReasonKeyCompromise, "keyCompromise"},
		{ocsp.ReasonCACompromise, "caCompromise"},
		{ocsp.ReasonAffiliationChanged, "affiliationChanged"},
		{ocsp.ReasonSuperseded, "superseded"},
		{ocsp.ReasonCessationOfOperation, "cessationOfOperation"},
		{ocsp.ReasonCertificateHold, "certificateHold"},
		{ocsp.ReasonRemoveFromCRL, "removeFromCRL"},
		{ocsp.ReasonPrivilegeWithdrawn, "privilegeWithdrawn"},
		{ocsp.ReasonAACompromise, "aaCompromise"},
		{ocsp.RevocationReason(999), "unspecified"}, // Unknown defaults to unspecified
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := revocationReasonString(tt.reason)
			if result != tt.expected {
				t.Errorf("revocationReasonString(%d) = %q, want %q", tt.reason, result, tt.expected)
			}
		})
	}
}

func TestU_ParseOCSPRevocationReason(t *testing.T) {
	tests := []struct {
		input    string
		expected ocsp.RevocationReason
	}{
		{"unspecified", ocsp.ReasonUnspecified},
		{"keycompromise", ocsp.ReasonKeyCompromise},
		{"cacompromise", ocsp.ReasonCACompromise},
		{"affiliationchanged", ocsp.ReasonAffiliationChanged},
		{"superseded", ocsp.ReasonSuperseded},
		{"cessationofoperation", ocsp.ReasonCessationOfOperation},
		{"certificatehold", ocsp.ReasonCertificateHold},
		{"removefromcrl", ocsp.ReasonRemoveFromCRL},
		{"privilegewithdrawn", ocsp.ReasonPrivilegeWithdrawn},
		{"aacompromise", ocsp.ReasonAACompromise},
		{"unknown", ocsp.ReasonUnspecified}, // Unknown defaults to unspecified
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := parseOCSPRevocationReason(tt.input)
			if result != tt.expected {
				t.Errorf("parseOCSPRevocationReason(%q) = %d, want %d", tt.input, result, tt.expected)
			}
		})
	}
}

// =============================================================================
// ocsp_helpers.go Unit Tests
// =============================================================================

func TestU_ParseOCSPSerial(t *testing.T) {
	tests := []struct {
		name      string
		serialHex string
		wantErr   bool
	}{
		{"valid single byte", "01", false},
		{"valid multi byte", "ABCDEF", false},
		{"valid lowercase", "abcdef", false},
		{"valid with leading zeros", "00123456", false},
		{"invalid hex", "not-hex", true},
		{"invalid odd length", "ABC", true}, // hex.DecodeString returns error for odd length
		{"empty string", "", false},         // empty hex decodes to empty bytes = 0
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serial, err := parseOCSPSerial(tt.serialHex)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseOCSPSerial(%q) error = %v, wantErr %v", tt.serialHex, err, tt.wantErr)
				return
			}
			if !tt.wantErr && serial == nil {
				t.Error("parseOCSPSerial() returned nil serial")
			}
		})
	}
}

func TestU_ParseOCSPCertStatus(t *testing.T) {
	tests := []struct {
		status   string
		expected ocsp.CertStatus
		wantErr  bool
	}{
		{"good", ocsp.CertStatusGood, false},
		{"GOOD", ocsp.CertStatusGood, false},
		{"Good", ocsp.CertStatusGood, false},
		{"revoked", ocsp.CertStatusRevoked, false},
		{"REVOKED", ocsp.CertStatusRevoked, false},
		{"unknown", ocsp.CertStatusUnknown, false},
		{"UNKNOWN", ocsp.CertStatusUnknown, false},
		{"invalid", 0, true},
		{"", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			status, err := parseOCSPCertStatus(tt.status)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseOCSPCertStatus(%q) error = %v, wantErr %v", tt.status, err, tt.wantErr)
				return
			}
			if !tt.wantErr && status != tt.expected {
				t.Errorf("parseOCSPCertStatus(%q) = %v, want %v", tt.status, status, tt.expected)
			}
		})
	}
}

func TestU_ParseOCSPRevocationTime(t *testing.T) {
	tests := []struct {
		name    string
		timeStr string
		wantErr bool
	}{
		{"empty string returns now", "", false},
		{"valid RFC3339", "2024-01-15T12:30:00Z", false},
		{"valid with timezone", "2024-01-15T12:30:00+05:00", false},
		{"invalid format", "not-a-time", true},
		{"partial date", "2024-01-15", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			revTime, err := parseOCSPRevocationTime(tt.timeStr)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseOCSPRevocationTime(%q) error = %v, wantErr %v", tt.timeStr, err, tt.wantErr)
				return
			}
			if !tt.wantErr && revTime.IsZero() {
				t.Error("parseOCSPRevocationTime() returned zero time")
			}
		})
	}
}

func TestU_PrintOCSPSignResult(t *testing.T) {
	// Test that printOCSPSignResult doesn't panic with various inputs
	now := testTime()

	// Good status
	printOCSPSignResult("output.ocsp", "01", ocsp.CertStatusGood, now, "", testDuration())

	// Revoked status
	printOCSPSignResult("output.ocsp", "02", ocsp.CertStatusRevoked, now, "keyCompromise", testDuration())

	// Revoked status without reason
	printOCSPSignResult("output.ocsp", "03", ocsp.CertStatusRevoked, now, "", testDuration())

	// Unknown status
	printOCSPSignResult("output.ocsp", "04", ocsp.CertStatusUnknown, now, "", testDuration())
}

func TestU_LoadOCSPSigner_SoftwareMode(t *testing.T) {
	tc := newTestContext(t)

	_, keyPath := tc.setupSigningPair()

	// Software mode with valid key
	signer, err := loadOCSPSigner("", keyPath, "", "", "", nil)
	if err != nil {
		t.Errorf("loadOCSPSigner() error = %v", err)
	}
	if signer == nil {
		t.Error("loadOCSPSigner() returned nil signer")
	}
}

func TestU_LoadOCSPSigner_MissingKey(t *testing.T) {
	// Software mode without key path
	_, err := loadOCSPSigner("", "", "", "", "", nil)
	if err == nil {
		t.Error("loadOCSPSigner() expected error for missing key path")
	}
}

func TestU_LoadOCSPSigner_HSMMode_InvalidConfig(t *testing.T) {
	tc := newTestContext(t)

	// HSM mode with non-existent config file
	_, err := loadOCSPSigner(tc.path("nonexistent.yaml"), "", "", "label", "", nil)
	if err == nil {
		t.Error("loadOCSPSigner() expected error for non-existent HSM config")
	}
}

func TestU_LoadOCSPSigner_HSMMode_MissingKeyLabelAndID(t *testing.T) {
	tc := newTestContext(t)

	// Create a valid HSM config file with pin_env (but we won't have actual HSM)
	hsmConfig := `type: pkcs11
pkcs11:
  lib: /usr/lib/softhsm/libsofthsm2.so
  token: test-token
  pin_env: TEST_HSM_PIN
`
	hsmConfigPath := tc.writeFile("hsm.yaml", hsmConfig)

	// Set the environment variable for the PIN
	t.Setenv("TEST_HSM_PIN", "1234")

	// HSM mode without key-label or key-id should fail
	_, err := loadOCSPSigner(hsmConfigPath, "", "", "", "", nil)
	if err == nil {
		t.Error("loadOCSPSigner() expected error for HSM mode without key-label or key-id")
	}
	if err != nil && !strings.Contains(err.Error(), "--key-label or --key-id required") {
		t.Errorf("expected error about missing key-label/key-id, got: %v", err)
	}
}

func TestU_LoadOCSPSigner_SoftwareMode_KeyNotFound(t *testing.T) {
	tc := newTestContext(t)

	// Software mode with non-existent key file
	_, err := loadOCSPSigner("", tc.path("nonexistent.key"), "", "", "", nil)
	if err == nil {
		t.Error("loadOCSPSigner() expected error for non-existent key file")
	}
}

// =============================================================================
// OCSP Request Tests - Successful cases
// =============================================================================

func TestF_OCSP_Request_Success(t *testing.T) {
	tc := newTestContext(t)
	resetOCSPFlags()

	certPath, _ := tc.setupSigningPair()
	requestPath := tc.path("request.ocsp")

	// Create a request using the same cert as issuer and cert (self-signed)
	_, err := executeCommand(rootCmd, "ocsp", "request",
		"--issuer", certPath,
		"--cert", certPath,
		"--out", requestPath,
	)
	assertNoError(t, err)
	assertFileExists(t, requestPath)
}

func TestF_OCSP_Request_WithNonce(t *testing.T) {
	tc := newTestContext(t)
	resetOCSPFlags()

	certPath, _ := tc.setupSigningPair()
	requestPath := tc.path("request-nonce.ocsp")

	// Create a request with nonce
	_, err := executeCommand(rootCmd, "ocsp", "request",
		"--issuer", certPath,
		"--cert", certPath,
		"--nonce",
		"--out", requestPath,
	)
	assertNoError(t, err)
	assertFileExists(t, requestPath)
}

func TestF_OCSP_Request_CertNotFound(t *testing.T) {
	tc := newTestContext(t)
	resetOCSPFlags()

	certPath, _ := tc.setupSigningPair()

	_, err := executeCommand(rootCmd, "ocsp", "request",
		"--issuer", certPath,
		"--cert", tc.path("nonexistent.crt"),
		"--out", tc.path("request.ocsp"),
	)
	assertError(t, err)
}

// =============================================================================
// OCSP Sign Tests - Additional cases
// =============================================================================

func TestF_OCSP_Sign_WithResponderCert(t *testing.T) {
	tc := newTestContext(t)
	resetOCSPFlags()

	// Setup CA and responder (using same key for simplicity)
	caCertPath, caKeyPath := tc.setupSigningPair()
	responderCertPath := caCertPath // Use same cert as responder in test
	responsePath := tc.path("response.ocsp")

	_, err := executeCommand(rootCmd, "ocsp", "sign",
		"--serial", "ABCD",
		"--status", "good",
		"--ca", caCertPath,
		"--cert", responderCertPath,
		"--key", caKeyPath,
		"--out", responsePath,
	)
	assertNoError(t, err)
	assertFileExists(t, responsePath)
}

func TestF_OCSP_Sign_InvalidValidity(t *testing.T) {
	tc := newTestContext(t)
	resetOCSPFlags()

	certPath, keyPath := tc.setupSigningPair()

	_, err := executeCommand(rootCmd, "ocsp", "sign",
		"--serial", "01",
		"--status", "good",
		"--ca", certPath,
		"--key", keyPath,
		"--validity", "not-a-duration",
		"--out", tc.path("response.ocsp"),
	)
	assertError(t, err)
}

func TestF_OCSP_Sign_InvalidCAFile(t *testing.T) {
	tc := newTestContext(t)
	resetOCSPFlags()

	_, keyPath := tc.setupSigningPair()
	invalidCA := tc.writeFile("invalid-ca.crt", "not a certificate")

	_, err := executeCommand(rootCmd, "ocsp", "sign",
		"--serial", "01",
		"--status", "good",
		"--ca", invalidCA,
		"--key", keyPath,
		"--out", tc.path("response.ocsp"),
	)
	assertError(t, err)
}

func TestF_OCSP_Sign_InvalidResponderCertFile(t *testing.T) {
	tc := newTestContext(t)
	resetOCSPFlags()

	certPath, keyPath := tc.setupSigningPair()
	invalidCert := tc.writeFile("invalid-responder.crt", "not a certificate")

	_, err := executeCommand(rootCmd, "ocsp", "sign",
		"--serial", "01",
		"--status", "good",
		"--ca", certPath,
		"--cert", invalidCert,
		"--key", keyPath,
		"--out", tc.path("response.ocsp"),
	)
	assertError(t, err)
}

func TestF_OCSP_Sign_RevokedWithoutTime(t *testing.T) {
	tc := newTestContext(t)
	resetOCSPFlags()

	certPath, keyPath := tc.setupSigningPair()
	responsePath := tc.path("response.ocsp")

	// Revoked status without explicit revocation time should use current time
	_, err := executeCommand(rootCmd, "ocsp", "sign",
		"--serial", "02",
		"--status", "revoked",
		"--ca", certPath,
		"--key", keyPath,
		"--out", responsePath,
	)
	assertNoError(t, err)
	assertFileExists(t, responsePath)
}

func TestF_OCSP_Sign_RevokedInvalidTime(t *testing.T) {
	tc := newTestContext(t)
	resetOCSPFlags()

	certPath, keyPath := tc.setupSigningPair()

	_, err := executeCommand(rootCmd, "ocsp", "sign",
		"--serial", "02",
		"--status", "revoked",
		"--revocation-time", "not-a-time",
		"--ca", certPath,
		"--key", keyPath,
		"--out", tc.path("response.ocsp"),
	)
	assertError(t, err)
}

// =============================================================================
// OCSP Verify Tests - Additional cases
// =============================================================================

func TestF_OCSP_Verify_WithoutCA(t *testing.T) {
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

	// Verify without CA (should skip signature verification)
	_, err = executeCommand(rootCmd, "ocsp", "verify", responsePath)
	assertNoError(t, err)
}

func TestF_OCSP_Verify_WithCertMismatch(t *testing.T) {
	tc := newTestContext(t)
	resetOCSPFlags()

	// Create OCSP response with specific serial
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

	// Verify with cert specified - should fail because serials don't match
	// The cert has a different serial than "01" used in the OCSP response
	_, err = executeCommand(rootCmd, "ocsp", "verify",
		responsePath,
		"--ca", certPath,
		"--cert", certPath, // This cert has a different serial
	)
	assertError(t, err) // Should fail because CertID doesn't match
}

func TestF_OCSP_Verify_InvalidCertFile(t *testing.T) {
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

	// Verify with invalid cert file
	invalidCert := tc.writeFile("invalid.crt", "not a certificate")
	_, err = executeCommand(rootCmd, "ocsp", "verify",
		responsePath,
		"--ca", certPath,
		"--cert", invalidCert,
	)
	assertError(t, err)
}

func TestF_OCSP_Verify_InvalidCAFile(t *testing.T) {
	tc := newTestContext(t)
	resetOCSPFlags()

	// Create OCSP response first
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

	// Verify with invalid CA file
	invalidCA := tc.writeFile("invalid-ca.crt", "not a certificate")
	_, err = executeCommand(rootCmd, "ocsp", "verify",
		responsePath,
		"--ca", invalidCA,
	)
	assertError(t, err)
}

// =============================================================================
// OCSP Info Tests - Additional cases
// =============================================================================

func TestF_OCSP_Info_UnknownResponse(t *testing.T) {
	tc := newTestContext(t)
	resetOCSPFlags()

	certPath, keyPath := tc.setupSigningPair()
	responsePath := tc.path("response.ocsp")

	// Create response with unknown status
	_, err := executeCommand(rootCmd, "ocsp", "sign",
		"--serial", "DEADBEEF",
		"--status", "unknown",
		"--ca", certPath,
		"--key", keyPath,
		"--out", responsePath,
	)
	assertNoError(t, err)

	resetOCSPFlags()

	// Get info about the response
	_, err = executeCommand(rootCmd, "ocsp", "info", responsePath)
	assertNoError(t, err)
}

// =============================================================================
// buildOCSPSignResponse Unit Tests
// =============================================================================

func TestU_BuildOCSPSignResponse_AllStatuses(t *testing.T) {
	tc := newTestContext(t)

	certPath, keyPath := tc.setupSigningPair()
	caCert, err := loadCertificate(certPath)
	assertNoError(t, err)

	signer, err := loadOCSPSigner("", keyPath, "", "", "", nil)
	assertNoError(t, err)

	statuses := []ocsp.CertStatus{
		ocsp.CertStatusGood,
		ocsp.CertStatusRevoked,
		ocsp.CertStatusUnknown,
	}

	for _, status := range statuses {
		t.Run(status.String(), func(t *testing.T) {
			params := &ocspSignParams{
				Serial:         big.NewInt(123),
				CertStatus:     status,
				RevocationTime: time.Now(),
				CACert:         caCert,
				ResponderCert:  caCert,
				Signer:         signer,
				Validity:       time.Hour,
			}

			responseData, err := buildOCSPSignResponse(params)
			if err != nil {
				t.Errorf("buildOCSPSignResponse() error = %v for status %v", err, status)
			}
			if len(responseData) == 0 {
				t.Error("buildOCSPSignResponse() returned empty response")
			}
		})
	}
}
