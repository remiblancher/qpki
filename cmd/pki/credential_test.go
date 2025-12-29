package main

import (
	"path/filepath"
	"testing"
)

// resetCredentialFlags resets all credential command flags to their default values.
func resetCredentialFlags() {
	credCADir = "./ca"
	credPassphrase = ""
	credRevokeReason = "unspecified"
	credExportOut = ""
	credExportKeys = false

	credEnrollProfiles = nil
	credEnrollID = ""
	credEnrollVars = nil
	credEnrollVarFile = ""

	credRotateProfiles = nil
	credRotateAddProfiles = nil
	credRotateRemoveProfiles = nil
	credRotateKeepKeys = false

	credImportCert = ""
	credImportKey = ""
	credImportID = ""
}

// =============================================================================
// Credential Enroll Tests
// =============================================================================

func TestCredentialEnroll(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create CA first
	caDir := tc.path("ca")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--name", "Test CA",
		"--profile", "ec/root-ca",
		"--dir", caDir,
	)
	assertNoError(t, err)

	resetCredentialFlags()

	// Enroll a credential
	_, err = executeCommand(rootCmd, "credential", "enroll",
		"--ca-dir", caDir,
		"--profile", "ec/tls-server",
		"--var", "cn=test.local",
		"--var", "dns_names=test.local",
	)
	assertNoError(t, err)

	// Verify bundle directory was created
	bundlesDir := filepath.Join(caDir, "bundles")
	assertFileExists(t, bundlesDir)
}

func TestCredentialEnroll_MissingProfile(t *testing.T) {
	tc := newTestContext(t)
	resetCredentialFlags()

	_, err := executeCommand(rootCmd, "credential", "enroll",
		"--ca-dir", tc.path("ca"),
		"--var", "cn=test.local",
	)
	assertError(t, err)
}

func TestCredentialEnroll_CANotFound(t *testing.T) {
	tc := newTestContext(t)
	resetCredentialFlags()

	_, err := executeCommand(rootCmd, "credential", "enroll",
		"--ca-dir", tc.path("nonexistent"),
		"--profile", "ec/tls-server",
		"--var", "cn=test.local",
	)
	assertError(t, err)
}

// =============================================================================
// Credential List Tests
// =============================================================================

func TestCredentialList(t *testing.T) {
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

	resetCredentialFlags()

	// List credentials (empty)
	_, err = executeCommand(rootCmd, "credential", "list", "--ca-dir", caDir)
	assertNoError(t, err)
}

func TestCredentialList_WithCredentials(t *testing.T) {
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

	resetCredentialFlags()

	// Enroll a credential
	_, err = executeCommand(rootCmd, "credential", "enroll",
		"--ca-dir", caDir,
		"--profile", "ec/tls-server",
		"--var", "cn=test.local",
		"--var", "dns_names=test.local",
	)
	assertNoError(t, err)

	resetCredentialFlags()

	// List credentials
	_, err = executeCommand(rootCmd, "credential", "list", "--ca-dir", caDir)
	assertNoError(t, err)
}

func TestCredentialList_EmptyDir(t *testing.T) {
	tc := newTestContext(t)
	resetCredentialFlags()

	// List on empty dir should not error, just return "No credentials found"
	_, err := executeCommand(rootCmd, "credential", "list", "--ca-dir", tc.tempDir)
	assertNoError(t, err)
}

// =============================================================================
// Credential Info Tests
// =============================================================================

func TestCredentialInfo_NotFound(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create CA
	caDir := tc.path("ca")
	_, _ = executeCommand(rootCmd, "ca", "init",
		"--name", "Test CA",
		"--profile", "ec/root-ca",
		"--dir", caDir,
	)

	resetCredentialFlags()

	_, err := executeCommand(rootCmd, "credential", "info",
		"--ca-dir", caDir,
		"nonexistent-credential-id",
	)
	assertError(t, err)
}

func TestCredentialInfo_MissingArg(t *testing.T) {
	tc := newTestContext(t)
	resetCredentialFlags()

	_, err := executeCommand(rootCmd, "credential", "info", "--ca-dir", tc.path("ca"))
	assertError(t, err)
}
