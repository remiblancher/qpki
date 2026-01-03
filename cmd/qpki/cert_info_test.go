package main

import (
	"testing"
)

// resetCertInfoFlags resets all cert info command flags to their default values.
func resetCertInfoFlags() {
	certInfoCADir = "./ca"
}

// =============================================================================
// Cert Info Tests
// =============================================================================

func TestF_Cert_Info_Basic(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()
	resetCSRFlags()
	resetIssueFlags()
	resetCertInfoFlags()

	caDir := tc.path("ca")

	// Create CA
	_, err := executeCommand(rootCmd, "ca", "init",
		"--name", "Test CA",
		"--profile", "ec/root-ca",
		"--dir", caDir,
	)
	assertNoError(t, err)

	resetCSRFlags()

	// Generate CSR
	keyOut := tc.path("server.key")
	csrOut := tc.path("server.csr")
	_, err = executeCommand(rootCmd, "csr", "gen",
		"--algorithm", "ecdsa-p256",
		"--keyout", keyOut,
		"--cn", "server.example.com",
		"--dns", "server.example.com",
		"--out", csrOut,
	)
	assertNoError(t, err)

	resetIssueFlags()

	// Issue certificate from CSR
	certOut := tc.path("server.crt")
	_, err = executeCommand(rootCmd, "cert", "issue",
		"--ca-dir", caDir,
		"--profile", "ec/tls-server",
		"--csr", csrOut,
		"--var", "cn=server.example.com",
		"--var", "dns_names=server.example.com",
		"--out", certOut,
	)
	assertNoError(t, err)

	resetCertInfoFlags()

	// Get cert info (serial 02 = first issued cert, CA is 01)
	_, err = executeCommand(rootCmd, "cert", "info",
		"--ca-dir", caDir,
		"02",
	)

	assertNoError(t, err)
}

func TestF_Cert_Info_MissingSerial(t *testing.T) {
	resetCertInfoFlags()

	// Missing serial argument
	_, err := executeCommand(rootCmd, "cert", "info", "--ca-dir", "./ca")

	assertError(t, err)
}

func TestF_Cert_Info_InvalidSerial(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()
	resetCertInfoFlags()

	caDir := tc.path("ca")

	// Create CA
	_, _ = executeCommand(rootCmd, "ca", "init",
		"--name", "Test CA",
		"--profile", "ec/root-ca",
		"--dir", caDir,
	)

	resetCertInfoFlags()

	// Invalid serial (not hex)
	_, err := executeCommand(rootCmd, "cert", "info",
		"--ca-dir", caDir,
		"not-hex",
	)

	assertError(t, err)
}

func TestF_Cert_Info_CANotFound(t *testing.T) {
	tc := newTestContext(t)
	resetCertInfoFlags()

	_, err := executeCommand(rootCmd, "cert", "info",
		"--ca-dir", tc.path("nonexistent"),
		"01",
	)

	assertError(t, err)
}

func TestF_Cert_Info_CertNotFound(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()
	resetCertInfoFlags()

	caDir := tc.path("ca")

	// Create CA
	_, _ = executeCommand(rootCmd, "ca", "init",
		"--name", "Test CA",
		"--profile", "ec/root-ca",
		"--dir", caDir,
	)

	resetCertInfoFlags()

	// Serial that doesn't exist
	_, err := executeCommand(rootCmd, "cert", "info",
		"--ca-dir", caDir,
		"FF",
	)

	assertError(t, err)
}
