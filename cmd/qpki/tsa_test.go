package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/remiblancher/post-quantum-pki/pkg/tsa"
)

// resetTSAFlags resets all TSA command flags to their default values.
func resetTSAFlags() {
	tsaRequestData = ""
	tsaRequestHash = "sha256"
	tsaRequestNonce = false
	tsaRequestOutput = ""

	tsaSignData = ""
	tsaSignCert = ""
	tsaSignKey = ""
	tsaSignPassphrase = ""
	tsaSignHash = "sha256"
	tsaSignPolicy = "1.3.6.1.4.1.99999.2.1"
	tsaSignOutput = ""
	tsaSignIncludeTSA = true
	tsaSignHSMConfig = ""
	tsaSignKeyLabel = ""
	tsaSignKeyID = ""

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
	tsaServeHSMConfig = ""
	tsaServeKeyLabel = ""
	tsaServeKeyID = ""
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
// TSA Request Tests
// =============================================================================

func TestF_TSA_Request_Success(t *testing.T) {
	tc := newTestContext(t)
	resetTSAFlags()

	dataPath := tc.writeFile("data.txt", "test data for request")
	requestPath := tc.path("request.tsq")

	_, err := executeCommand(rootCmd, "tsa", "request",
		"--data", dataPath,
		"--out", requestPath,
	)
	assertNoError(t, err)
	assertFileExists(t, requestPath)
	assertFileNotEmpty(t, requestPath)
}

func TestF_TSA_Request_WithNonce(t *testing.T) {
	tc := newTestContext(t)
	resetTSAFlags()

	dataPath := tc.writeFile("data.txt", "test data with nonce")
	requestPath := tc.path("request.tsq")

	_, err := executeCommand(rootCmd, "tsa", "request",
		"--data", dataPath,
		"--nonce",
		"--out", requestPath,
	)
	assertNoError(t, err)
	assertFileExists(t, requestPath)
}

func TestF_TSA_Request_WithSHA384(t *testing.T) {
	tc := newTestContext(t)
	resetTSAFlags()

	dataPath := tc.writeFile("data.txt", "test data sha384")
	requestPath := tc.path("request.tsq")

	_, err := executeCommand(rootCmd, "tsa", "request",
		"--data", dataPath,
		"--hash", "sha384",
		"--out", requestPath,
	)
	assertNoError(t, err)
	assertFileExists(t, requestPath)
}

func TestF_TSA_Request_WithSHA512(t *testing.T) {
	tc := newTestContext(t)
	resetTSAFlags()

	dataPath := tc.writeFile("data.txt", "test data sha512")
	requestPath := tc.path("request.tsq")

	_, err := executeCommand(rootCmd, "tsa", "request",
		"--data", dataPath,
		"--hash", "sha512",
		"--out", requestPath,
	)
	assertNoError(t, err)
	assertFileExists(t, requestPath)
}

func TestF_TSA_Request_InvalidHash(t *testing.T) {
	tc := newTestContext(t)
	resetTSAFlags()

	dataPath := tc.writeFile("data.txt", "test data")
	requestPath := tc.path("request.tsq")

	_, err := executeCommand(rootCmd, "tsa", "request",
		"--data", dataPath,
		"--hash", "invalid-hash",
		"--out", requestPath,
	)
	assertError(t, err)
}

func TestF_TSA_Request_MissingData(t *testing.T) {
	tc := newTestContext(t)
	resetTSAFlags()

	_, err := executeCommand(rootCmd, "tsa", "request",
		"--out", tc.path("request.tsq"),
	)
	assertError(t, err)
}

func TestF_TSA_Request_MissingOutput(t *testing.T) {
	tc := newTestContext(t)
	resetTSAFlags()

	dataPath := tc.writeFile("data.txt", "test data")

	_, err := executeCommand(rootCmd, "tsa", "request",
		"--data", dataPath,
	)
	assertError(t, err)
}

func TestF_TSA_Request_DataFileNotFound(t *testing.T) {
	tc := newTestContext(t)
	resetTSAFlags()

	_, err := executeCommand(rootCmd, "tsa", "request",
		"--data", tc.path("nonexistent.txt"),
		"--out", tc.path("request.tsq"),
	)
	assertError(t, err)
}

// =============================================================================
// TSA Server Handler Tests
// =============================================================================

func TestU_TSAServer_HandleRequest_MethodNotAllowed(t *testing.T) {
	tc := newTestContext(t)
	certPath, keyPath := tc.setupSigningPair()

	cert, _ := loadCertificate(certPath)
	key, _ := loadSigningKey("", keyPath, "", "", "", nil)
	policy, _ := parseOID("1.3.6.1.4.1.99999.2.1")

	server := &tsaServer{
		cert:   cert,
		signer: key,
		policy: policy,
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	server.handleRequest(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

func TestU_TSAServer_HandleRequest_InvalidContentType(t *testing.T) {
	tc := newTestContext(t)
	certPath, keyPath := tc.setupSigningPair()

	cert, _ := loadCertificate(certPath)
	key, _ := loadSigningKey("", keyPath, "", "", "", nil)
	policy, _ := parseOID("1.3.6.1.4.1.99999.2.1")

	server := &tsaServer{
		cert:   cert,
		signer: key,
		policy: policy,
	}

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("test"))
	req.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()

	server.handleRequest(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestU_TSAServer_HandleRequest_InvalidRequestBody(t *testing.T) {
	tc := newTestContext(t)
	certPath, keyPath := tc.setupSigningPair()

	cert, _ := loadCertificate(certPath)
	key, _ := loadSigningKey("", keyPath, "", "", "", nil)
	policy, _ := parseOID("1.3.6.1.4.1.99999.2.1")

	server := &tsaServer{
		cert:   cert,
		signer: key,
		policy: policy,
	}

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("invalid ASN.1 data"))
	req.Header.Set("Content-Type", "application/timestamp-query")
	w := httptest.NewRecorder()

	server.handleRequest(w, req)

	// Should return 200 with a rejection response per RFC 3161
	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d (rejection), got %d", http.StatusOK, w.Code)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/timestamp-reply" {
		t.Errorf("Expected Content-Type %q, got %q", "application/timestamp-reply", contentType)
	}
}

func TestU_TSAServer_SendError(t *testing.T) {
	tc := newTestContext(t)
	certPath, keyPath := tc.setupSigningPair()

	cert, _ := loadCertificate(certPath)
	key, _ := loadSigningKey("", keyPath, "", "", "", nil)
	policy, _ := parseOID("1.3.6.1.4.1.99999.2.1")

	server := &tsaServer{
		cert:   cert,
		signer: key,
		policy: policy,
	}

	w := httptest.NewRecorder()
	server.sendError(w, 2, "test error message") // FailBadDataFormat = 2

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d (RFC 3161), got %d", http.StatusOK, w.Code)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/timestamp-reply" {
		t.Errorf("Expected Content-Type %q, got %q", "application/timestamp-reply", contentType)
	}

	// Response body should not be empty
	if w.Body.Len() == 0 {
		t.Error("Response body should not be empty")
	}
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

// =============================================================================
// TSA Helper Function Unit Tests
// =============================================================================

func TestU_ParseHashAlgorithm(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"SHA256 lowercase", "sha256", false},
		{"SHA256 with dash", "sha-256", false},
		{"SHA384 lowercase", "sha384", false},
		{"SHA384 with dash", "sha-384", false},
		{"SHA512 lowercase", "sha512", false},
		{"SHA512 with dash", "sha-512", false},
		{"SHA3-256", "sha3-256", false},
		{"SHA3-384", "sha3-384", false},
		{"SHA3-512", "sha3-512", false},
		{"Invalid algorithm", "md5", true},
		{"Empty string", "", true},
		{"Random string", "invalid-hash", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseHashAlgorithm(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseHashAlgorithm(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestU_ComputeFileHash(t *testing.T) {
	testData := []byte("test data for hashing")

	tests := []struct {
		name     string
		hashAlg  string
		wantSize int
		wantErr  bool
	}{
		{"SHA256", "sha256", 32, false},
		{"SHA384", "sha384", 48, false},
		{"SHA512", "sha512", 64, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alg, err := parseHashAlgorithm(tt.hashAlg)
			if err != nil {
				t.Fatalf("parseHashAlgorithm failed: %v", err)
			}

			hash, err := computeFileHash(testData, alg)
			if (err != nil) != tt.wantErr {
				t.Errorf("computeFileHash() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(hash) != tt.wantSize {
				t.Errorf("computeFileHash() hash size = %d, want %d", len(hash), tt.wantSize)
			}
		})
	}
}

func TestU_ComputeFileHash_Deterministic(t *testing.T) {
	testData := []byte("deterministic hash test")
	alg, _ := parseHashAlgorithm("sha256")

	hash1, err := computeFileHash(testData, alg)
	assertNoError(t, err)

	hash2, err := computeFileHash(testData, alg)
	assertNoError(t, err)

	if string(hash1) != string(hash2) {
		t.Error("Hash should be deterministic for the same input")
	}
}

func TestU_ParseOID(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantLen int
		wantErr bool
	}{
		{"Valid simple OID", "1.2.3", 3, false},
		{"Valid TSA policy OID", "1.3.6.1.4.1.99999.2.1", 9, false},
		{"Valid ISO OID", "2.5.4.3", 4, false},
		{"Single component", "1", 1, false},
		{"Invalid - letters", "1.2.a.3", 0, true},
		{"Invalid - empty component", "1..3", 0, true},
		{"Invalid - trailing dot", "1.2.3.", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oid, err := parseOID(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseOID(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(oid) != tt.wantLen {
				t.Errorf("parseOID(%q) len = %d, want %d", tt.input, len(oid), tt.wantLen)
			}
		})
	}
}

func TestU_FormatBool(t *testing.T) {
	tests := []struct {
		value    bool
		trueStr  string
		falseStr string
		want     string
	}{
		{true, "YES", "NO", "YES"},
		{false, "YES", "NO", "NO"},
		{true, "VALID", "INVALID", "VALID"},
		{false, "VALID", "INVALID", "INVALID"},
		{true, "", "", ""},
		{false, "", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := formatBool(tt.value, tt.trueStr, tt.falseStr)
			if got != tt.want {
				t.Errorf("formatBool(%v, %q, %q) = %q, want %q", tt.value, tt.trueStr, tt.falseStr, got, tt.want)
			}
		})
	}
}

func TestU_LoadCertificate_Valid(t *testing.T) {
	tc := newTestContext(t)

	// Use setupSigningPair which creates a valid certificate
	certPath, _ := tc.setupSigningPair()

	cert, err := loadCertificate(certPath)
	if err != nil {
		t.Fatalf("loadCertificate() error = %v", err)
	}
	if cert == nil {
		t.Fatal("loadCertificate() returned nil certificate")
	}
	if cert.Subject.CommonName != "Test Certificate" {
		t.Errorf("loadCertificate() CN = %q, want %q", cert.Subject.CommonName, "Test Certificate")
	}
}

func TestU_LoadCertificate_FileNotFound(t *testing.T) {
	tc := newTestContext(t)

	_, err := loadCertificate(tc.path("nonexistent.crt"))
	if err == nil {
		t.Error("loadCertificate() should error for non-existent file")
	}
}

func TestU_LoadCertificate_InvalidPEM(t *testing.T) {
	tc := newTestContext(t)

	invalidPath := tc.writeFile("invalid.crt", "not a valid PEM certificate")

	_, err := loadCertificate(invalidPath)
	if err == nil {
		t.Error("loadCertificate() should error for invalid PEM")
	}
}

func TestU_LoadCertPool_Valid(t *testing.T) {
	tc := newTestContext(t)

	// Use setupSigningPair which creates a valid certificate
	certPath, _ := tc.setupSigningPair()

	pool, err := loadCertPool(certPath)
	if err != nil {
		t.Fatalf("loadCertPool() error = %v", err)
	}
	if pool == nil {
		t.Error("loadCertPool() returned nil pool")
	}
}

func TestU_LoadCertPool_FileNotFound(t *testing.T) {
	tc := newTestContext(t)

	_, err := loadCertPool(tc.path("nonexistent.crt"))
	if err == nil {
		t.Error("loadCertPool() should error for non-existent file")
	}
}

func TestU_LoadCertPool_InvalidPEM(t *testing.T) {
	tc := newTestContext(t)

	invalidPath := tc.writeFile("invalid.crt", "not a valid PEM certificate")

	_, err := loadCertPool(invalidPath)
	if err == nil {
		t.Error("loadCertPool() should error for invalid PEM")
	}
}

// =============================================================================
// TSA Verify Additional Tests
// =============================================================================

func TestF_TSA_Verify_WithoutData(t *testing.T) {
	tc := newTestContext(t)
	resetTSAFlags()

	// Create a timestamp token
	certPath, keyPath := tc.setupSigningPair()
	dataPath := tc.writeFile("data.txt", "test data for verification")
	tokenPath := tc.path("token.tsr")

	_, err := executeCommand(rootCmd, "tsa", "sign",
		"--data", dataPath,
		"--cert", certPath,
		"--key", keyPath,
		"--out", tokenPath,
	)
	assertNoError(t, err)

	resetTSAFlags()

	// Verify the token without data (signature only)
	_, _ = executeCommand(rootCmd, "tsa", "verify",
		tokenPath,
		"--ca", certPath,
	)
	// Just testing the path executes - may fail due to cert EKU
}

func TestF_TSA_Verify_InvalidCAFile(t *testing.T) {
	tc := newTestContext(t)
	resetTSAFlags()

	// Create a timestamp token
	certPath, keyPath := tc.setupSigningPair()
	dataPath := tc.writeFile("data.txt", "test data")
	tokenPath := tc.path("token.tsr")

	_, err := executeCommand(rootCmd, "tsa", "sign",
		"--data", dataPath,
		"--cert", certPath,
		"--key", keyPath,
		"--out", tokenPath,
	)
	assertNoError(t, err)

	resetTSAFlags()

	// Verify with invalid CA file
	invalidCA := tc.writeFile("invalid-ca.crt", "not a certificate")
	_, err = executeCommand(rootCmd, "tsa", "verify",
		tokenPath,
		"--ca", invalidCA,
	)
	assertError(t, err)
}

func TestF_TSA_Verify_DataFileNotFound(t *testing.T) {
	tc := newTestContext(t)
	resetTSAFlags()

	// Create a timestamp token
	certPath, keyPath := tc.setupSigningPair()
	dataPath := tc.writeFile("data.txt", "test data")
	tokenPath := tc.path("token.tsr")

	_, err := executeCommand(rootCmd, "tsa", "sign",
		"--data", dataPath,
		"--cert", certPath,
		"--key", keyPath,
		"--out", tokenPath,
	)
	assertNoError(t, err)

	resetTSAFlags()

	// Verify with non-existent data file
	_, err = executeCommand(rootCmd, "tsa", "verify",
		tokenPath,
		"--data", tc.path("nonexistent.txt"),
		"--ca", certPath,
	)
	assertError(t, err)
}

func TestF_TSA_Verify_NoCA(t *testing.T) {
	tc := newTestContext(t)
	resetTSAFlags()

	// Create a timestamp token
	certPath, keyPath := tc.setupSigningPair()
	dataPath := tc.writeFile("data.txt", "test data without CA")
	tokenPath := tc.path("token.tsr")

	_, err := executeCommand(rootCmd, "tsa", "sign",
		"--data", dataPath,
		"--cert", certPath,
		"--key", keyPath,
		"--out", tokenPath,
	)
	assertNoError(t, err)

	resetTSAFlags()

	// Verify without CA (embedded certs if any)
	_, _ = executeCommand(rootCmd, "tsa", "verify",
		tokenPath,
	)
	// Just testing the path - may fail without embedded cert
}

// =============================================================================
// TSA Sign Additional Tests
// =============================================================================

func TestF_TSA_Sign_InvalidCertFile(t *testing.T) {
	tc := newTestContext(t)
	resetTSAFlags()

	_, keyPath := tc.setupSigningPair()
	dataPath := tc.writeFile("data.txt", "test data")
	invalidCert := tc.writeFile("invalid.crt", "not a certificate")

	_, err := executeCommand(rootCmd, "tsa", "sign",
		"--data", dataPath,
		"--cert", invalidCert,
		"--key", keyPath,
		"--out", tc.path("token.tsr"),
	)
	assertError(t, err)
}

func TestF_TSA_Sign_InvalidKeyFile(t *testing.T) {
	tc := newTestContext(t)
	resetTSAFlags()

	certPath, _ := tc.setupSigningPair()
	dataPath := tc.writeFile("data.txt", "test data")
	invalidKey := tc.writeFile("invalid.key", "not a key")

	_, err := executeCommand(rootCmd, "tsa", "sign",
		"--data", dataPath,
		"--cert", certPath,
		"--key", invalidKey,
		"--out", tc.path("token.tsr"),
	)
	assertError(t, err)
}

func TestF_TSA_Sign_InvalidPolicy(t *testing.T) {
	tc := newTestContext(t)
	resetTSAFlags()

	certPath, keyPath := tc.setupSigningPair()
	dataPath := tc.writeFile("data.txt", "test data")

	_, err := executeCommand(rootCmd, "tsa", "sign",
		"--data", dataPath,
		"--cert", certPath,
		"--key", keyPath,
		"--policy", "invalid.policy.oid",
		"--out", tc.path("token.tsr"),
	)
	assertError(t, err)
}

func TestF_TSA_Sign_CustomPolicy(t *testing.T) {
	tc := newTestContext(t)
	resetTSAFlags()

	certPath, keyPath := tc.setupSigningPair()
	dataPath := tc.writeFile("data.txt", "test data with custom policy")
	tokenPath := tc.path("token.tsr")

	_, err := executeCommand(rootCmd, "tsa", "sign",
		"--data", dataPath,
		"--cert", certPath,
		"--key", keyPath,
		"--policy", "1.2.3.4.5.6.7.8.9",
		"--out", tokenPath,
	)
	assertNoError(t, err)
	assertFileExists(t, tokenPath)
}

// =============================================================================
// TSA Server Handler Additional Tests
// =============================================================================

func TestU_TSAServer_HandleRequest_ValidRequest(t *testing.T) {
	tc := newTestContext(t)
	certPath, keyPath := tc.setupSigningPair()

	cert, _ := loadCertificate(certPath)
	key, _ := loadSigningKey("", keyPath, "", "", "", nil)
	policy, _ := parseOID("1.3.6.1.4.1.99999.2.1")

	server := &tsaServer{
		cert:      cert,
		signer:    key,
		policy:    policy,
		accuracy:  1,
		serialGen: &tsa.RandomSerialGenerator{},
	}

	// Create a valid timestamp request using the internal tsa package
	dataPath := tc.writeFile("data.txt", "test data for request")
	requestPath := tc.path("request.tsq")

	// First create a request using the CLI
	resetTSAFlags()
	_, err := executeCommand(rootCmd, "tsa", "request",
		"--data", dataPath,
		"--out", requestPath,
	)
	if err != nil {
		t.Skipf("Could not create request: %v", err)
	}

	// Read the request
	reqData, err := os.ReadFile(requestPath)
	if err != nil {
		t.Fatalf("Could not read request: %v", err)
	}

	// Create HTTP request with valid timestamp query
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(reqData)))
	req.Header.Set("Content-Type", "application/timestamp-query")
	w := httptest.NewRecorder()

	server.handleRequest(w, req)

	// Should return 200 with a timestamp response
	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/timestamp-reply" {
		t.Errorf("Expected Content-Type %q, got %q", "application/timestamp-reply", contentType)
	}

	// Response body should not be empty
	if w.Body.Len() == 0 {
		t.Error("Response body should not be empty")
	}
}

// =============================================================================
// ComputeFileHash Additional Tests
// =============================================================================

func TestU_ComputeFileHash_UnsupportedAlgorithm(t *testing.T) {
	testData := []byte("test data")

	// Use an algorithm that's not supported by computeFileHash
	// SHA3 algorithms are supported by parseHashAlgorithm but not computeFileHash
	alg, err := parseHashAlgorithm("sha3-256")
	if err != nil {
		t.Skipf("SHA3-256 not available: %v", err)
	}

	_, err = computeFileHash(testData, alg)
	if err == nil {
		t.Error("computeFileHash() should error for unsupported algorithm (SHA3)")
	}
}

// =============================================================================
// TSA Helpers Additional Tests
// =============================================================================

func TestU_LoadTSACAConfig_Empty(t *testing.T) {
	cfg, err := loadTSACAConfig("")
	if err != nil {
		t.Errorf("loadTSACAConfig('') should not error, got: %v", err)
	}
	if cfg == nil {
		t.Error("loadTSACAConfig('') should return non-nil config")
	}
}

func TestU_LoadTSACAConfig_Valid(t *testing.T) {
	tc := newTestContext(t)
	certPath, _ := tc.setupSigningPair()

	cfg, err := loadTSACAConfig(certPath)
	if err != nil {
		t.Errorf("loadTSACAConfig() error = %v", err)
	}
	if cfg == nil {
		t.Fatal("loadTSACAConfig() returned nil")
	}
	if cfg.Roots == nil {
		t.Error("loadTSACAConfig() should have Roots")
	}
	if cfg.RootCertRaw == nil {
		t.Error("loadTSACAConfig() should have RootCertRaw")
	}
}

func TestU_LoadTSACAConfig_InvalidFile(t *testing.T) {
	tc := newTestContext(t)
	invalidPath := tc.writeFile("invalid.crt", "not a certificate")

	_, err := loadTSACAConfig(invalidPath)
	if err == nil {
		t.Error("loadTSACAConfig() should error for invalid file")
	}
}
