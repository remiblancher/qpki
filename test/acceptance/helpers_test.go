//go:build acceptance

// Package acceptance contains black-box CLI acceptance tests (TestA_*).
// Run with: go test -tags=acceptance ./test/acceptance/...
package acceptance

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// qpkiBinary is the path to the qpki binary.
// Set via QPKI_BINARY env var or default to ./qpki in the repo root.
var qpkiBinary string

func init() {
	if bin := os.Getenv("QPKI_BINARY"); bin != "" {
		qpkiBinary = bin
	} else {
		// Default: look for binary in repo root
		qpkiBinary = "../../bin/qpki"
	}
}

// =============================================================================
// Test Mode Detection (Software vs HSM)
// =============================================================================

// isHSMMode returns true if tests should run in HSM mode.
// Set TEST_HSM_MODE=1 to enable HSM mode.
func isHSMMode() bool {
	return os.Getenv("TEST_HSM_MODE") != ""
}

// isPQCHSMMode returns true if HSM supports PQC (e.g., Utimaco).
// Set HSM_PQC_ENABLED=1 to enable PQC algorithms on HSM.
func isPQCHSMMode() bool {
	return os.Getenv("HSM_PQC_ENABLED") != ""
}

// skipIfAlgorithmNotSupported skips test if algorithm not supported in current mode.
// Algorithm support matrix:
//   - Software: all algorithms (EC, RSA, ML-DSA, ML-KEM, SLH-DSA)
//   - SoftHSM: EC, RSA only
//   - Utimaco: EC, RSA, ML-DSA, ML-KEM (no SLH-DSA)
func skipIfAlgorithmNotSupported(t *testing.T, alg string) {
	t.Helper()
	if !isHSMMode() {
		return // Software mode supports all algorithms
	}

	// SLH-DSA: no HSM supports it
	if strings.HasPrefix(alg, "slh-dsa") {
		t.Skip("SLH-DSA not supported in HSM mode")
	}

	// ML-DSA/ML-KEM: only Utimaco (PQC HSM)
	if strings.HasPrefix(alg, "ml-") && !isPQCHSMMode() {
		t.Skip("ML-DSA/ML-KEM requires PQC-capable HSM (set HSM_PQC_ENABLED=1)")
	}
}

// skipIfNoHSM skips the test if HSM is not configured.
func skipIfNoHSM(t *testing.T) {
	t.Helper()
	if os.Getenv("HSM_CONFIG") == "" {
		t.Skip("HSM_CONFIG not set, skipping HSM tests")
	}
	if os.Getenv("HSM_PIN") == "" {
		t.Skip("HSM_PIN not set, skipping HSM tests")
	}
}

// skipIfHybridNotSupported skips hybrid/composite tests in HSM mode.
// Hybrid profiles require combined keys (EC + PQC) which HSMs don't support.
func skipIfHybridNotSupported(t *testing.T) {
	t.Helper()
	if isHSMMode() {
		t.Skip("Hybrid/Composite profiles not supported in HSM mode")
	}
}

// getHSMConfigPath returns the HSM config path from environment.
func getHSMConfigPath(t *testing.T) string {
	t.Helper()
	configPath := os.Getenv("HSM_CONFIG")
	if configPath == "" {
		t.Skip("HSM_CONFIG not set, skipping HSM tests")
	}
	return configPath
}

// randomSuffix generates a simple random suffix for unique key labels.
func randomSuffix() string {
	return fmt.Sprintf("%08x", time.Now().UnixNano()&0xFFFFFFFF)
}

// =============================================================================
// KeyConfig - Mode-aware key storage configuration
// =============================================================================

// KeyConfig represents key storage configuration for tests.
// In software mode, keys are stored in files.
// In HSM mode, keys are stored in the HSM with labels.
type KeyConfig struct {
	UseHSM    bool
	HSMConfig string
	KeyLabel  string
	KeyPath   string // for software mode
}

// newKeyConfig creates a KeyConfig for the current test mode.
func newKeyConfig(t *testing.T, baseName string) KeyConfig {
	t.Helper()
	if isHSMMode() {
		skipIfNoHSM(t)
		return KeyConfig{
			UseHSM:    true,
			HSMConfig: getHSMConfigPath(t),
			KeyLabel:  baseName + "-" + randomSuffix(),
		}
	}
	return KeyConfig{
		UseHSM:  false,
		KeyPath: filepath.Join(t.TempDir(), baseName+".pem"),
	}
}

// buildKeyGenArgs returns CLI args for 'key gen' command.
func (kc KeyConfig) buildKeyGenArgs(algorithm string) []string {
	if kc.UseHSM {
		return []string{
			"--algorithm", algorithm,
			"--hsm-config", kc.HSMConfig,
			"--key-label", kc.KeyLabel,
		}
	}
	return []string{
		"--algorithm", algorithm,
		"--out", kc.KeyPath,
	}
}

// buildCAInitArgs returns CLI args for 'ca init' command.
func (kc KeyConfig) buildCAInitArgs() []string {
	if kc.UseHSM {
		return []string{
			"--hsm-config", kc.HSMConfig,
			"--key-label", kc.KeyLabel,
		}
	}
	return []string{} // software mode: implicit key generation
}

// buildCredentialEnrollArgs returns CLI args for 'credential enroll'.
func (kc KeyConfig) buildCredentialEnrollArgs() []string {
	if kc.UseHSM {
		return []string{
			"--hsm-config", kc.HSMConfig,
			"--key-label", kc.KeyLabel,
		}
	}
	return []string{} // software mode: implicit key generation
}

// buildSignKeyArgs returns CLI args for signing commands (tsa sign, etc).
// In software mode: ["--key", path]
// In HSM mode: ["--hsm-config", config, "--key-label", label]
func (kc KeyConfig) buildSignKeyArgs(keyFilePath string) []string {
	if kc.UseHSM {
		return []string{
			"--hsm-config", kc.HSMConfig,
			"--key-label", kc.KeyLabel,
		}
	}
	return []string{"--key", keyFilePath}
}

// buildAttestKeyArgs returns CLI args for attestation key in csr gen.
// In software mode: ["--attest-key", path]
// In HSM mode: ["--hsm-config", config, "--attest-key-label", label]
func (kc KeyConfig) buildAttestKeyArgs(keyFilePath string) []string {
	if kc.UseHSM {
		return []string{
			"--hsm-config", kc.HSMConfig,
			"--attest-key-label", kc.KeyLabel,
		}
	}
	return []string{"--attest-key", keyFilePath}
}

// CredentialInfo holds credential directory and key configuration.
// Used to track both the credential location and how to access its key.
type CredentialInfo struct {
	Dir       string    // credential directory path
	KeyConfig KeyConfig // key storage configuration
}

// =============================================================================
// CLI Helpers
// =============================================================================

// runQPKI executes the qpki CLI with the given arguments and returns stdout.
// Fails the test if the command returns a non-zero exit code.
func runQPKI(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.Command(qpkiBinary, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		t.Fatalf("qpki %s failed: %v\nstderr: %s\nstdout: %s",
			strings.Join(args, " "), err, stderr.String(), stdout.String())
	}
	return stdout.String()
}

// runQPKIExpectError executes qpki and expects it to fail.
// Returns the combined output (stdout + stderr).
func runQPKIExpectError(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.Command(qpkiBinary, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err == nil {
		t.Fatalf("qpki %s expected to fail but succeeded\nstdout: %s",
			strings.Join(args, " "), stdout.String())
	}
	return stdout.String() + stderr.String()
}

// setupCA initializes a CA with the given profile and returns the CA directory.
// The CA is automatically cleaned up after the test.
// In HSM mode (TEST_HSM_MODE=1), keys are stored in the HSM.
func setupCA(t *testing.T, profile, cn string) string {
	t.Helper()
	dir := t.TempDir()
	caDir := filepath.Join(dir, "ca")
	keyConfig := newKeyConfig(t, "ca-key")

	args := []string{
		"ca", "init",
		"--var", "cn=" + cn,
		"--profile", profile,
		"--ca-dir", caDir,
	}
	args = append(args, keyConfig.buildCAInitArgs()...)

	runQPKI(t, args...)

	// Export CA cert
	caCert := filepath.Join(caDir, "ca.crt")
	runQPKI(t, "ca", "export", "--ca-dir", caDir, "--out", caCert)

	return caDir
}

// setupSubordinateCA initializes a subordinate CA with the given profile.
// In HSM mode (TEST_HSM_MODE=1), keys are stored in the HSM.
func setupSubordinateCA(t *testing.T, profile, cn, parentDir string) string {
	t.Helper()
	dir := t.TempDir()
	caDir := filepath.Join(dir, "sub-ca")
	keyConfig := newKeyConfig(t, "sub-ca-key")

	args := []string{
		"ca", "init",
		"--var", "cn=" + cn,
		"--profile", profile,
		"--ca-dir", caDir,
		"--parent", parentDir,
	}
	args = append(args, keyConfig.buildCAInitArgs()...)

	runQPKI(t, args...)

	// Export CA cert
	caCert := filepath.Join(caDir, "ca.crt")
	runQPKI(t, "ca", "export", "--ca-dir", caDir, "--out", caCert)

	return caDir
}

// enrollCredential creates a credential using credential enroll.
// Returns the credential directory.
// In HSM mode (TEST_HSM_MODE=1), keys are stored in the HSM.
func enrollCredential(t *testing.T, caDir, profile string, vars ...string) string {
	t.Helper()
	info := enrollCredentialWithInfo(t, caDir, profile, vars...)
	return info.Dir
}

// enrollCredentialWithInfo creates a credential and returns full info including key config.
// Use this when you need to access the key later (e.g., for TSA signing in HSM mode).
func enrollCredentialWithInfo(t *testing.T, caDir, profile string, vars ...string) CredentialInfo {
	t.Helper()
	credDir := filepath.Join(caDir, "credentials")
	keyConfig := newKeyConfig(t, "cred-key")

	args := []string{
		"credential", "enroll",
		"--ca-dir", caDir,
		"--cred-dir", credDir,
		"--profile", profile,
	}
	for _, v := range vars {
		args = append(args, "--var", v)
	}
	args = append(args, keyConfig.buildCredentialEnrollArgs()...)

	runQPKI(t, args...)

	// Find the created credential directory (it's a hash-named subdirectory)
	entries, err := os.ReadDir(credDir)
	if err != nil {
		t.Fatalf("failed to read credential directory: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("no credential directory created")
	}

	// For HSM mode, the actual key label has "-0" appended (keyIndex=0 for simple credentials)
	// See keygen.go line 32: hsmCfg.PKCS11KeyLabel = fmt.Sprintf("%s-%d", labelPrefix, keyIndex)
	if keyConfig.UseHSM {
		keyConfig.KeyLabel = keyConfig.KeyLabel + "-0"
	}

	// Return the most recently created one with key config
	return CredentialInfo{
		Dir:       filepath.Join(credDir, entries[len(entries)-1].Name()),
		KeyConfig: keyConfig,
	}
}

// getCredentialCert returns the path to the certificate file in a credential directory.
func getCredentialCert(t *testing.T, credDir string) string {
	t.Helper()
	return filepath.Join(credDir, "certificates.pem")
}

// getCredentialKey returns the path to the private key file in a credential directory.
func getCredentialKey(t *testing.T, credDir string) string {
	t.Helper()
	return filepath.Join(credDir, "private-keys.pem")
}

// getCACert returns the path to the CA certificate.
func getCACert(t *testing.T, caDir string) string {
	t.Helper()
	return filepath.Join(caDir, "ca.crt")
}

// assertFileExists fails the test if the file does not exist.
func assertFileExists(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatalf("expected file to exist: %s", path)
	}
}

// assertOutputContains fails if the output does not contain the expected substring.
func assertOutputContains(t *testing.T, output, expected string) {
	t.Helper()
	if !strings.Contains(output, expected) {
		t.Errorf("expected output to contain %q, got: %s", expected, output)
	}
}

// writeTestFile creates a temporary file with the given content.
func writeTestFile(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}
	return path
}

// execCommandContext wraps exec.CommandContext for background processes.
func execCommandContext(ctx context.Context, name string, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, name, args...)
}
