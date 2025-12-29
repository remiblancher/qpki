package main

import (
	"testing"
)

// resetIssueFlags resets all issue command flags to their default values.
func resetIssueFlags() {
	issueCADir = "./ca"
	issueProfile = ""
	issueCommonName = ""
	issueDNSNames = nil
	issueIPAddrs = nil
	issueCSRFile = ""
	issuePubKeyFile = ""
	issueKeyFile = ""
	issueCertOut = ""
	issueValidityDays = 0
	issueCAPassphrase = ""
	issueHybridAlg = ""
	issueAttestCert = ""
	issueVars = nil
	issueVarFile = ""
}

// =============================================================================
// Issue from CSR Tests
// =============================================================================

func TestIssue_FromCSR(t *testing.T) {
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

	resetCSRFlags()

	// Generate CSR
	keyOut := tc.path("server.key")
	csrOut := tc.path("server.csr")
	_, err = executeCommand(rootCmd, "cert", "csr",
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
	assertFileExists(t, certOut)
}

func TestIssue_WithCommonNameOverride(t *testing.T) {
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

	resetCSRFlags()

	// Generate CSR
	keyOut := tc.path("server.key")
	csrOut := tc.path("server.csr")
	_, err = executeCommand(rootCmd, "cert", "csr",
		"--algorithm", "ecdsa-p256",
		"--keyout", keyOut,
		"--cn", "original.example.com",
		"--out", csrOut,
	)
	assertNoError(t, err)

	resetIssueFlags()

	// Issue with CN override
	certOut := tc.path("server.crt")
	_, err = executeCommand(rootCmd, "cert", "issue",
		"--ca-dir", caDir,
		"--profile", "ec/tls-server",
		"--csr", csrOut,
		"--cn", "override.example.com",
		"--var", "dns_names=override.example.com",
		"--out", certOut,
	)
	assertNoError(t, err)
	assertFileExists(t, certOut)
}

// =============================================================================
// Issue Error Cases
// =============================================================================

func TestIssue_MissingProfile(t *testing.T) {
	tc := newTestContext(t)
	resetIssueFlags()

	_, err := executeCommand(rootCmd, "cert", "issue",
		"--ca-dir", tc.path("ca"),
		"--csr", tc.path("server.csr"),
	)
	assertError(t, err)
}

func TestIssue_MissingCSR(t *testing.T) {
	tc := newTestContext(t)
	resetIssueFlags()

	_, err := executeCommand(rootCmd, "cert", "issue",
		"--ca-dir", tc.path("ca"),
		"--profile", "ec/tls-server",
	)
	assertError(t, err)
}

func TestIssue_CANotFound(t *testing.T) {
	tc := newTestContext(t)
	resetIssueFlags()

	// Create a dummy CSR file
	csrPath := tc.writeFile("dummy.csr", "-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----\n")

	_, err := executeCommand(rootCmd, "cert", "issue",
		"--ca-dir", tc.path("nonexistent"),
		"--profile", "ec/tls-server",
		"--csr", csrPath,
	)
	assertError(t, err)
}

func TestIssue_InvalidCSRFile(t *testing.T) {
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

	resetIssueFlags()

	// Create invalid CSR
	invalidCSR := tc.writeFile("invalid.csr", "not a valid CSR")

	_, err = executeCommand(rootCmd, "cert", "issue",
		"--ca-dir", caDir,
		"--profile", "ec/tls-server",
		"--csr", invalidCSR,
	)
	assertError(t, err)
}

func TestIssue_CSRFileNotFound(t *testing.T) {
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

	resetIssueFlags()

	_, err = executeCommand(rootCmd, "cert", "issue",
		"--ca-dir", caDir,
		"--profile", "ec/tls-server",
		"--csr", tc.path("nonexistent.csr"),
	)
	assertError(t, err)
}

func TestIssue_InvalidProfile(t *testing.T) {
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

	resetCSRFlags()

	// Generate CSR
	keyOut := tc.path("server.key")
	csrOut := tc.path("server.csr")
	_, _ = executeCommand(rootCmd, "cert", "csr",
		"--algorithm", "ecdsa-p256",
		"--keyout", keyOut,
		"--cn", "server.example.com",
		"--out", csrOut,
	)

	resetIssueFlags()

	_, err = executeCommand(rootCmd, "cert", "issue",
		"--ca-dir", caDir,
		"--profile", "nonexistent/profile",
		"--csr", csrOut,
	)
	assertError(t, err)
}
