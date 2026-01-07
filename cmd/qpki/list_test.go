package main

import (
	"path/filepath"
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

func TestF_Cert_List_Empty(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create CA
	caDir := tc.path("ca")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
		"--var", "cn=Test CA",
	)
	assertNoError(t, err)

	resetListFlags()

	// List (empty, just the CA cert)
	_, err = executeCommand(rootCmd, "cert", "list", "--ca-dir", caDir)
	assertNoError(t, err)
}

func TestF_Cert_List_WithCertificates(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create CA
	caDir := tc.path("ca")
	credentialsDir := tc.path("credentials")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
		"--var", "cn=Test CA",
	)
	assertNoError(t, err)

	resetCredentialFlags()

	// Enroll a credential
	_, err = executeCommand(rootCmd, "credential", "enroll",
		"--ca-dir", caDir,
		"--cred-dir", credentialsDir,
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

func TestF_Cert_List_FilterValid(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create CA
	caDir := tc.path("ca")
	credentialsDir := tc.path("credentials")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
		"--var", "cn=Test CA",
	)
	assertNoError(t, err)

	resetCredentialFlags()

	// Enroll a credential
	_, _ = executeCommand(rootCmd, "credential", "enroll",
		"--ca-dir", caDir,
		"--cred-dir", credentialsDir,
		"--profile", "ec/tls-server",
		"--var", "cn=test.local",
		"--var", "dns_names=test.local",
	)

	resetListFlags()

	// List valid certificates
	_, err = executeCommand(rootCmd, "cert", "list", "--ca-dir", caDir, "--status", "valid")
	assertNoError(t, err)
}

func TestF_Cert_List_FilterRevoked(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create CA
	caDir := tc.path("ca")
	_, _ = executeCommand(rootCmd, "ca", "init",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
		"--var", "cn=Test CA",
	)

	resetListFlags()

	// List revoked (should be empty but not error)
	_, err := executeCommand(rootCmd, "cert", "list", "--ca-dir", caDir, "--status", "revoked")
	assertNoError(t, err)
}

func TestF_Cert_List_FilterExpired(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create CA
	caDir := tc.path("ca")
	_, _ = executeCommand(rootCmd, "ca", "init",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
		"--var", "cn=Test CA",
	)

	resetListFlags()

	// List expired (should be empty but not error)
	_, err := executeCommand(rootCmd, "cert", "list", "--ca-dir", caDir, "--status", "expired")
	assertNoError(t, err)
}

func TestF_Cert_List_InvalidFilter(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create CA
	caDir := tc.path("ca")
	credentialsDir := tc.path("credentials")
	_, _ = executeCommand(rootCmd, "ca", "init",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
		"--var", "cn=Test CA",
	)

	resetCredentialFlags()

	// Enroll a credential so there are certificates to filter
	_, _ = executeCommand(rootCmd, "credential", "enroll",
		"--ca-dir", caDir,
		"--cred-dir", credentialsDir,
		"--profile", "ec/tls-server",
		"--var", "cn=test.local",
		"--var", "dns_names=test.local",
	)

	resetListFlags()

	_, err := executeCommand(rootCmd, "cert", "list", "--ca-dir", caDir, "--status", "invalid")
	assertError(t, err)
}

func TestF_Cert_List_Verbose(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create CA
	caDir := tc.path("ca")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
		"--var", "cn=Test CA",
	)
	assertNoError(t, err)

	resetListFlags()

	// List with verbose flag
	_, err = executeCommand(rootCmd, "cert", "list", "--ca-dir", caDir, "--verbose")
	assertNoError(t, err)
}

func TestF_Cert_List_CANotFound(t *testing.T) {
	tc := newTestContext(t)
	resetListFlags()

	_, err := executeCommand(rootCmd, "cert", "list", "--ca-dir", tc.path("nonexistent"))
	assertError(t, err)
}

// =============================================================================
// Cert List with Revoked Certificate
// =============================================================================

func TestF_Cert_List_WithRevokedCert(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create CA
	caDir := tc.path("ca")
	credentialsDir := tc.path("credentials")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
		"--var", "cn=Test CA",
	)
	assertNoError(t, err)

	// Enroll a credential
	resetCredentialFlags()
	_, err = executeCommand(rootCmd, "credential", "enroll",
		"--ca-dir", caDir,
		"--cred-dir", credentialsDir,
		"--profile", "ec/tls-client",
		"--var", "cn=revoked@test.local",
		"--var", "email=revoked@test.local",
	)
	assertNoError(t, err)

	// Find the credential ID
	entries, _ := filepath.Glob(credentialsDir + "/*")
	if len(entries) == 0 {
		t.Fatal("no credential found")
	}
	credID := filepath.Base(entries[0])

	// Revoke the credential
	resetCredentialFlags()
	_, err = executeCommand(rootCmd, "credential", "revoke",
		"--ca-dir", caDir,
		"--cred-dir", credentialsDir,
		credID,
	)
	assertNoError(t, err)

	resetListFlags()

	// List all certificates (should show revoked status [R])
	_, err = executeCommand(rootCmd, "cert", "list", "--ca-dir", caDir)
	assertNoError(t, err)
}

func TestF_Cert_List_WithRevokedFilteredByValid(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create CA
	caDir := tc.path("ca")
	credentialsDir := tc.path("credentials")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
		"--var", "cn=Test CA",
	)
	assertNoError(t, err)

	// Enroll two credentials
	resetCredentialFlags()
	_, _ = executeCommand(rootCmd, "credential", "enroll",
		"--ca-dir", caDir,
		"--cred-dir", credentialsDir,
		"--profile", "ec/tls-client",
		"--var", "cn=valid@test.local",
		"--var", "email=valid@test.local",
	)

	resetCredentialFlags()
	_, _ = executeCommand(rootCmd, "credential", "enroll",
		"--ca-dir", caDir,
		"--cred-dir", credentialsDir,
		"--profile", "ec/tls-client",
		"--var", "cn=torevoke@test.local",
		"--var", "email=torevoke@test.local",
	)

	// Find and revoke the second credential
	entries, _ := filepath.Glob(credentialsDir + "/*")
	if len(entries) >= 2 {
		credID := filepath.Base(entries[1])
		resetCredentialFlags()
		_, _ = executeCommand(rootCmd, "credential", "revoke",
			"--ca-dir", caDir,
			"--cred-dir", credentialsDir,
			credID,
		)
	}

	resetListFlags()

	// Filter by valid should exclude revoked
	_, err = executeCommand(rootCmd, "cert", "list",
		"--ca-dir", caDir,
		"--status", "valid",
	)
	assertNoError(t, err)

	resetListFlags()

	// Filter by revoked should only show revoked
	_, err = executeCommand(rootCmd, "cert", "list",
		"--ca-dir", caDir,
		"--status", "revoked",
	)
	assertNoError(t, err)
}

func TestF_Cert_List_VerboseWithRevoked(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create CA
	caDir := tc.path("ca")
	credentialsDir := tc.path("credentials")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
		"--var", "cn=Test CA",
	)
	assertNoError(t, err)

	// Enroll and revoke a credential
	resetCredentialFlags()
	_, err = executeCommand(rootCmd, "credential", "enroll",
		"--ca-dir", caDir,
		"--cred-dir", credentialsDir,
		"--profile", "ec/tls-client",
		"--var", "cn=revoked@test.local",
		"--var", "email=revoked@test.local",
	)
	assertNoError(t, err)

	entries, _ := filepath.Glob(credentialsDir + "/*")
	if len(entries) > 0 {
		credID := filepath.Base(entries[0])
		resetCredentialFlags()
		_, _ = executeCommand(rootCmd, "credential", "revoke",
			"--ca-dir", caDir,
			"--cred-dir", credentialsDir,
			credID,
		)
	}

	resetListFlags()

	// List with verbose to show revocation details
	_, err = executeCommand(rootCmd, "cert", "list",
		"--ca-dir", caDir,
		"--verbose",
	)
	assertNoError(t, err)
}
