//go:build acceptance

package acceptance

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// =============================================================================
// OCSP Sign and Verify Tests (TestA_OCSP_*)
// =============================================================================

func TestA_OCSP_Sign_EC(t *testing.T) {
	caDir := setupCA(t, "ec/root-ca", "OCSP EC CA")

	// Issue OCSP responder credential
	ocspCred := enrollCredentialWithInfo(t, caDir, "ec/ocsp-responder", "cn=EC OCSP Responder")

	// Issue end-entity credential
	eeCredDir := enrollCredential(t, caDir, "ec/tls-server", "cn=ee.test.local", "dns_names=ee.test.local")

	// Get serial number from index.txt
	serial := getLastSerial(t, caDir)

	// Sign OCSP response
	dir := t.TempDir()
	respPath := filepath.Join(dir, "ocsp-resp.der")

	args := []string{
		"ocsp", "sign",
		"--serial", serial,
		"--status", "good",
		"--ca", getCACert(t, caDir),
		"--cert", getCredentialCert(t, ocspCred.Dir),
		"--out", respPath,
	}
	args = append(args, ocspCred.KeyConfig.buildSignKeyArgs(getCredentialKey(t, ocspCred.Dir))...)
	runQPKI(t, args...)
	assertFileExists(t, respPath)

	// Verify OCSP response
	runQPKI(t, "ocsp", "verify", respPath, "--ca", getCACert(t, caDir))

	// Get OCSP info
	output := runQPKI(t, "ocsp", "info", respPath)
	assertOutputContains(t, output, "Status")

	_ = eeCredDir // used to generate the end-entity cert
}

func TestA_OCSP_Sign_MLDSA(t *testing.T) {
	skipIfAlgorithmNotSupported(t, "ml-dsa-65")
	caDir := setupCA(t, "ml/root-ca", "OCSP ML-DSA CA")

	ocspCred := enrollCredentialWithInfo(t, caDir, "ml/ocsp-responder", "cn=ML-DSA OCSP Responder")
	enrollCredential(t, caDir, "ml/tls-server-sign", "cn=mldsa.test.local", "dns_names=mldsa.test.local")

	serial := getLastSerial(t, caDir)

	dir := t.TempDir()
	respPath := filepath.Join(dir, "ocsp-resp.der")

	args := []string{
		"ocsp", "sign",
		"--serial", serial,
		"--status", "good",
		"--ca", getCACert(t, caDir),
		"--cert", getCredentialCert(t, ocspCred.Dir),
		"--out", respPath,
	}
	args = append(args, ocspCred.KeyConfig.buildSignKeyArgs(getCredentialKey(t, ocspCred.Dir))...)
	runQPKI(t, args...)

	runQPKI(t, "ocsp", "verify", respPath, "--ca", getCACert(t, caDir))
}

func TestA_OCSP_Sign_SLHDSA(t *testing.T) {
	skipIfAlgorithmNotSupported(t, "slh-dsa-sha2-128f")
	caDir := setupCA(t, "slh/root-ca", "OCSP SLH-DSA CA")

	ocspCred := enrollCredentialWithInfo(t, caDir, "slh/ocsp-responder", "cn=SLH-DSA OCSP Responder")
	enrollCredential(t, caDir, "slh/tls-server", "cn=slhdsa.test.local", "dns_names=slhdsa.test.local")

	serial := getLastSerial(t, caDir)

	dir := t.TempDir()
	respPath := filepath.Join(dir, "ocsp-resp.der")

	args := []string{
		"ocsp", "sign",
		"--serial", serial,
		"--status", "good",
		"--ca", getCACert(t, caDir),
		"--cert", getCredentialCert(t, ocspCred.Dir),
		"--out", respPath,
	}
	args = append(args, ocspCred.KeyConfig.buildSignKeyArgs(getCredentialKey(t, ocspCred.Dir))...)
	runQPKI(t, args...)

	runQPKI(t, "ocsp", "verify", respPath, "--ca", getCACert(t, caDir))
}

func TestA_OCSP_Sign_Catalyst(t *testing.T) {
	skipIfAlgorithmNotSupported(t, "ml-dsa-65")
	skipIfHybridNotSupported(t)
	caDir := setupCA(t, "hybrid/catalyst/root-ca", "OCSP Catalyst CA")

	ocspCred := enrollCredentialWithInfo(t, caDir, "hybrid/catalyst/ocsp-responder", "cn=Catalyst OCSP Responder")
	enrollCredential(t, caDir, "hybrid/catalyst/tls-server", "cn=catalyst.test.local", "dns_names=catalyst.test.local")

	serial := getLastSerial(t, caDir)

	dir := t.TempDir()
	respPath := filepath.Join(dir, "ocsp-resp.der")

	args := []string{
		"ocsp", "sign",
		"--serial", serial,
		"--status", "good",
		"--ca", getCACert(t, caDir),
		"--cert", getCredentialCert(t, ocspCred.Dir),
		"--out", respPath,
	}
	args = append(args, ocspCred.KeyConfig.buildSignKeyArgs(getCredentialKey(t, ocspCred.Dir))...)
	runQPKI(t, args...)

	runQPKI(t, "ocsp", "verify", respPath, "--ca", getCACert(t, caDir))
}

func TestA_OCSP_Sign_Composite(t *testing.T) {
	skipIfAlgorithmNotSupported(t, "ml-dsa-65")
	skipIfHybridNotSupported(t)
	caDir := setupCA(t, "hybrid/composite/root-ca", "OCSP Composite CA")

	ocspCred := enrollCredentialWithInfo(t, caDir, "hybrid/composite/ocsp-responder", "cn=Composite OCSP Responder")
	enrollCredential(t, caDir, "hybrid/composite/tls-server", "cn=composite.test.local", "dns_names=composite.test.local")

	serial := getLastSerial(t, caDir)

	dir := t.TempDir()
	respPath := filepath.Join(dir, "ocsp-resp.der")

	args := []string{
		"ocsp", "sign",
		"--serial", serial,
		"--status", "good",
		"--ca", getCACert(t, caDir),
		"--cert", getCredentialCert(t, ocspCred.Dir),
		"--out", respPath,
	}
	args = append(args, ocspCred.KeyConfig.buildSignKeyArgs(getCredentialKey(t, ocspCred.Dir))...)
	runQPKI(t, args...)

	runQPKI(t, "ocsp", "verify", respPath, "--ca", getCACert(t, caDir))
}

func TestA_OCSP_Status_Revoked(t *testing.T) {
	caDir := setupCA(t, "ec/root-ca", "OCSP EC CA")

	ocspCred := enrollCredentialWithInfo(t, caDir, "ec/ocsp-responder", "cn=EC OCSP Responder")
	enrollCredential(t, caDir, "ec/tls-server", "cn=ee.test.local", "dns_names=ee.test.local")

	serial := getLastSerial(t, caDir)

	dir := t.TempDir()
	respPath := filepath.Join(dir, "ocsp-resp.der")

	// Sign with revoked status
	args := []string{
		"ocsp", "sign",
		"--serial", serial,
		"--status", "revoked",
		"--ca", getCACert(t, caDir),
		"--cert", getCredentialCert(t, ocspCred.Dir),
		"--out", respPath,
	}
	args = append(args, ocspCred.KeyConfig.buildSignKeyArgs(getCredentialKey(t, ocspCred.Dir))...)
	runQPKI(t, args...)

	runQPKI(t, "ocsp", "verify", respPath, "--ca", getCACert(t, caDir))
	output := runQPKI(t, "ocsp", "info", respPath)
	assertOutputContains(t, output, "revoked")
}

// TestA_OCSP_Server tests the OCSP server functionality.
// This test starts an OCSP server, makes a request, and verifies the response.
func TestA_OCSP_Server(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping OCSP server test in short mode")
	}

	caDir := setupCA(t, "ec/root-ca", "OCSP EC CA")

	ocspCred := enrollCredentialWithInfo(t, caDir, "ec/ocsp-responder", "cn=EC OCSP Responder")
	eeCredDir := enrollCredential(t, caDir, "ec/tls-server", "cn=ee.test.local", "dns_names=ee.test.local")

	dir := t.TempDir()
	reqPath := filepath.Join(dir, "ocsp-req.der")
	respPath := filepath.Join(dir, "ocsp-resp.der")

	// Generate OCSP request
	runQPKI(t, "ocsp", "request",
		"--issuer", getCACert(t, caDir),
		"--cert", getCredentialCert(t, eeCredDir),
		"--out", reqPath,
	)

	// Start OCSP server in background
	port := "18888" // use high port to avoid conflicts
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		// Run server - ignore error as it will be killed
		args := []string{
			"ocsp", "serve",
			"--port", port,
			"--ca-dir", caDir,
			"--cert", getCredentialCert(t, ocspCred.Dir),
		}
		args = append(args, ocspCred.KeyConfig.buildSignKeyArgs(getCredentialKey(t, ocspCred.Dir))...)
		_ = runQPKIBackground(ctx, args...)
	}()

	// Wait for server to start
	time.Sleep(2 * time.Second)

	// Make OCSP request via HTTP
	reqData, err := os.ReadFile(reqPath)
	if err != nil {
		t.Fatalf("failed to read OCSP request: %v", err)
	}

	resp, err := http.Post(
		fmt.Sprintf("http://localhost:%s", port),
		"application/ocsp-request",
		strings.NewReader(string(reqData)),
	)
	if err != nil {
		t.Fatalf("OCSP request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("OCSP server returned status %d", resp.StatusCode)
	}

	// Save response
	respData := make([]byte, 4096)
	n, _ := resp.Body.Read(respData)
	if err := os.WriteFile(respPath, respData[:n], 0644); err != nil {
		t.Fatalf("failed to write OCSP response: %v", err)
	}

	// Verify response
	runQPKI(t, "ocsp", "verify", respPath, "--ca", getCACert(t, caDir))
}

// =============================================================================
// Helper Functions
// =============================================================================

// getLastSerial reads the last serial number from the CA's index.txt file.
func getLastSerial(t *testing.T, caDir string) string {
	t.Helper()
	indexPath := filepath.Join(caDir, "index.txt")
	data, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatalf("failed to read index.txt: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 0 {
		t.Fatal("index.txt is empty")
	}

	// Get last line and extract serial (4th tab-separated field)
	lastLine := lines[len(lines)-1]
	fields := strings.Split(lastLine, "\t")
	if len(fields) < 4 {
		t.Fatalf("invalid index.txt format: %s", lastLine)
	}

	return fields[3]
}

// runQPKIBackground runs qpki in the background until context is cancelled.
func runQPKIBackground(ctx context.Context, args ...string) error {
	cmd := execCommandContext(ctx, qpkiBinary, args...)
	return cmd.Run()
}
