package main

import (
	"testing"
)

// resetListFlags resets all list command flags to their default values.
func resetListFlags() {
	listCADir = "./ca"
	listStatus = ""
	listVerbose = false
}

// =============================================================================
// Cert List Tests (pki cert list)
// =============================================================================

func TestCertList_Empty(t *testing.T) {
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

	resetListFlags()

	// List (empty, just the CA cert)
	_, err = executeCommand(rootCmd, "cert", "list", "--ca-dir", caDir)
	assertNoError(t, err)
}

func TestCertList_WithCertificates(t *testing.T) {
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

	resetListFlags()

	// List certificates
	_, err = executeCommand(rootCmd, "cert", "list", "--ca-dir", caDir)
	assertNoError(t, err)
}

func TestCertList_FilterValid(t *testing.T) {
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
	_, _ = executeCommand(rootCmd, "credential", "enroll",
		"--ca-dir", caDir,
		"--profile", "ec/tls-server",
		"--var", "cn=test.local",
		"--var", "dns_names=test.local",
	)

	resetListFlags()

	// List valid certificates
	_, err = executeCommand(rootCmd, "cert", "list", "--ca-dir", caDir, "--status", "valid")
	assertNoError(t, err)
}

func TestCertList_FilterRevoked(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create CA
	caDir := tc.path("ca")
	_, _ = executeCommand(rootCmd, "ca", "init",
		"--name", "Test CA",
		"--profile", "ec/root-ca",
		"--dir", caDir,
	)

	resetListFlags()

	// List revoked (should be empty but not error)
	_, err := executeCommand(rootCmd, "cert", "list", "--ca-dir", caDir, "--status", "revoked")
	assertNoError(t, err)
}

func TestCertList_FilterExpired(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create CA
	caDir := tc.path("ca")
	_, _ = executeCommand(rootCmd, "ca", "init",
		"--name", "Test CA",
		"--profile", "ec/root-ca",
		"--dir", caDir,
	)

	resetListFlags()

	// List expired (should be empty but not error)
	_, err := executeCommand(rootCmd, "cert", "list", "--ca-dir", caDir, "--status", "expired")
	assertNoError(t, err)
}

func TestCertList_InvalidFilter(t *testing.T) {
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

	// Enroll a credential so there are certificates to filter
	_, _ = executeCommand(rootCmd, "credential", "enroll",
		"--ca-dir", caDir,
		"--profile", "ec/tls-server",
		"--var", "cn=test.local",
		"--var", "dns_names=test.local",
	)

	resetListFlags()

	_, err := executeCommand(rootCmd, "cert", "list", "--ca-dir", caDir, "--status", "invalid")
	assertError(t, err)
}

func TestCertList_Verbose(t *testing.T) {
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

	resetListFlags()

	// List with verbose flag
	_, err = executeCommand(rootCmd, "cert", "list", "--ca-dir", caDir, "--verbose")
	assertNoError(t, err)
}

func TestCertList_CANotFound(t *testing.T) {
	tc := newTestContext(t)
	resetListFlags()

	_, err := executeCommand(rootCmd, "cert", "list", "--ca-dir", tc.path("nonexistent"))
	assertError(t, err)
}
