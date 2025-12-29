package main

import (
	"testing"
)

// resetRevokeFlags resets all revoke command flags to their default values.
func resetRevokeFlags() {
	revokeCADir = "./ca"
	revokeReason = "unspecified"
	revokeCAPassphrase = ""
	revokeGenCRL = false
	revokeCRLDays = 7
}

// =============================================================================
// Revoke Tests
// =============================================================================

func TestRevoke_Certificate(t *testing.T) {
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

	// Enroll a credential to have a certificate to revoke
	_, err = executeCommand(rootCmd, "credential", "enroll",
		"--ca-dir", caDir,
		"--profile", "ec/tls-server",
		"--var", "cn=test.local",
		"--var", "dns_names=test.local",
	)
	assertNoError(t, err)

	resetRevokeFlags()

	// Certificate serial is always "02" (CA is 01, first issued cert is 02)
	_, err = executeCommand(rootCmd, "cert", "revoke",
		"--ca-dir", caDir,
		"02",
	)
	assertNoError(t, err)
}

func TestRevoke_WithReason(t *testing.T) {
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

	resetRevokeFlags()

	// Revoke with specific reason (serial 02 is the first issued cert)
	_, err = executeCommand(rootCmd, "cert", "revoke",
		"--ca-dir", caDir,
		"--reason", "superseded",
		"02",
	)
	assertNoError(t, err)
}

func TestRevoke_WithCRLGeneration(t *testing.T) {
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

	resetRevokeFlags()

	// Revoke with CRL generation (serial 02 is the first issued cert)
	_, err = executeCommand(rootCmd, "cert", "revoke",
		"--ca-dir", caDir,
		"--gen-crl",
		"02",
	)
	assertNoError(t, err)
}

// =============================================================================
// Revoke Error Cases
// =============================================================================

func TestRevoke_MissingSerial(t *testing.T) {
	tc := newTestContext(t)
	resetRevokeFlags()

	_, err := executeCommand(rootCmd, "cert", "revoke", "--ca-dir", tc.path("ca"))
	assertError(t, err)
}

func TestRevoke_InvalidSerial(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create CA
	caDir := tc.path("ca")
	_, _ = executeCommand(rootCmd, "ca", "init",
		"--name", "Test CA",
		"--profile", "ec/root-ca",
		"--dir", caDir,
	)

	resetRevokeFlags()

	// Invalid hex serial
	_, err := executeCommand(rootCmd, "cert", "revoke",
		"--ca-dir", caDir,
		"not-hex",
	)
	assertError(t, err)
}

func TestRevoke_InvalidReason(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create CA
	caDir := tc.path("ca")
	_, _ = executeCommand(rootCmd, "ca", "init",
		"--name", "Test CA",
		"--profile", "ec/root-ca",
		"--dir", caDir,
	)

	resetRevokeFlags()

	_, err := executeCommand(rootCmd, "cert", "revoke",
		"--ca-dir", caDir,
		"--reason", "invalid-reason",
		"01",
	)
	assertError(t, err)
}

func TestRevoke_CANotFound(t *testing.T) {
	tc := newTestContext(t)
	resetRevokeFlags()

	_, err := executeCommand(rootCmd, "cert", "revoke",
		"--ca-dir", tc.path("nonexistent"),
		"01",
	)
	assertError(t, err)
}

func TestRevoke_CertificateNotFound(t *testing.T) {
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

	resetRevokeFlags()

	// Try to revoke non-existent certificate
	_, err = executeCommand(rootCmd, "cert", "revoke",
		"--ca-dir", caDir,
		"ff",
	)
	assertError(t, err)
}

