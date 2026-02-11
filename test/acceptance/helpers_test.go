//go:build acceptance

// Package acceptance contains black-box CLI acceptance tests (TestA_*).
// Run with: go test -tags=acceptance ./test/acceptance/...
package acceptance

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
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
func setupCA(t *testing.T, profile, cn string) string {
	t.Helper()
	dir := t.TempDir()
	caDir := filepath.Join(dir, "ca")

	runQPKI(t, "ca", "init",
		"--var", "cn="+cn,
		"--profile", profile,
		"--ca-dir", caDir,
	)

	// Export CA cert
	caCert := filepath.Join(caDir, "ca.crt")
	runQPKI(t, "ca", "export", "--ca-dir", caDir, "--out", caCert)

	return caDir
}

// setupSubordinateCA initializes a subordinate CA with the given profile.
func setupSubordinateCA(t *testing.T, profile, cn, parentDir string) string {
	t.Helper()
	dir := t.TempDir()
	caDir := filepath.Join(dir, "sub-ca")

	runQPKI(t, "ca", "init",
		"--var", "cn="+cn,
		"--profile", profile,
		"--ca-dir", caDir,
		"--parent", parentDir,
	)

	// Export CA cert
	caCert := filepath.Join(caDir, "ca.crt")
	runQPKI(t, "ca", "export", "--ca-dir", caDir, "--out", caCert)

	return caDir
}

// enrollCredential creates a credential using credential enroll.
// Returns the credential directory.
func enrollCredential(t *testing.T, caDir, profile string, vars ...string) string {
	t.Helper()
	credDir := filepath.Join(caDir, "credentials")

	args := []string{
		"credential", "enroll",
		"--ca-dir", caDir,
		"--cred-dir", credDir,
		"--profile", profile,
	}
	for _, v := range vars {
		args = append(args, "--var", v)
	}

	runQPKI(t, args...)

	// Find the created credential directory (it's a hash-named subdirectory)
	entries, err := os.ReadDir(credDir)
	if err != nil {
		t.Fatalf("failed to read credential directory: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("no credential directory created")
	}

	// Return the most recently created one
	return filepath.Join(credDir, entries[len(entries)-1].Name())
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
