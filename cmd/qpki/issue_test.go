package main

import (
	"testing"
)

// resetIssueFlags resets all issue command flags to their default values.
func resetIssueFlags() {
	issueCADir = "./ca"
	issueProfile = ""
	issueCSRFile = ""
	issuePubKeyFile = ""
	issueKeyFile = ""
	issueCertOut = ""
	issueCAPassphrase = ""
	issueHybridAlg = ""
	issueAttestCert = ""
	issueVars = nil
	issueVarFile = ""
}

// =============================================================================
// Issue from CSR Tests
// =============================================================================

func TestF_Cert_Issue_FromCSR(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create CA
	caDir := tc.path("ca")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Test CA",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
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
	assertFileExists(t, certOut)
}

func TestF_Cert_Issue_WithCommonNameOverride(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create CA
	caDir := tc.path("ca")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Test CA",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
	)
	assertNoError(t, err)

	resetCSRFlags()

	// Generate CSR
	keyOut := tc.path("server.key")
	csrOut := tc.path("server.csr")
	_, err = executeCommand(rootCmd, "csr", "gen",
		"--algorithm", "ecdsa-p256",
		"--keyout", keyOut,
		"--cn", "original.example.com",
		"--out", csrOut,
	)
	assertNoError(t, err)

	resetIssueFlags()

	// Issue with CN override via --var
	certOut := tc.path("server.crt")
	_, err = executeCommand(rootCmd, "cert", "issue",
		"--ca-dir", caDir,
		"--profile", "ec/tls-server",
		"--csr", csrOut,
		"--var", "cn=override.example.com",
		"--var", "dns_names=override.example.com",
		"--out", certOut,
	)
	assertNoError(t, err)
	assertFileExists(t, certOut)
}

// =============================================================================
// Issue Error Cases
// =============================================================================

func TestF_Cert_Issue_MissingProfile(t *testing.T) {
	tc := newTestContext(t)
	resetIssueFlags()

	_, err := executeCommand(rootCmd, "cert", "issue",
		"--ca-dir", tc.path("ca"),
		"--csr", tc.path("server.csr"),
	)
	assertError(t, err)
}

func TestF_Cert_Issue_MissingCSR(t *testing.T) {
	tc := newTestContext(t)
	resetIssueFlags()

	_, err := executeCommand(rootCmd, "cert", "issue",
		"--ca-dir", tc.path("ca"),
		"--profile", "ec/tls-server",
	)
	assertError(t, err)
}

func TestF_Cert_Issue_CANotFound(t *testing.T) {
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

func TestF_Cert_Issue_InvalidCSRFile(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create CA
	caDir := tc.path("ca")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Test CA",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
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

func TestF_Cert_Issue_CSRFileNotFound(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create CA
	caDir := tc.path("ca")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Test CA",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
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

func TestF_Cert_Issue_InvalidProfile(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create CA
	caDir := tc.path("ca")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Test CA",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
	)
	assertNoError(t, err)

	resetCSRFlags()

	// Generate CSR
	keyOut := tc.path("server.key")
	csrOut := tc.path("server.csr")
	_, _ = executeCommand(rootCmd, "csr", "gen",
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

// =============================================================================
// Issue with IP Addresses
// =============================================================================

func TestF_Cert_Issue_WithIPAddresses(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create CA
	caDir := tc.path("ca")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Test CA",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
	)
	assertNoError(t, err)

	resetCSRFlags()

	// Generate CSR with IP addresses
	keyOut := tc.path("server.key")
	csrOut := tc.path("server.csr")
	_, err = executeCommand(rootCmd, "csr", "gen",
		"--algorithm", "ecdsa-p256",
		"--keyout", keyOut,
		"--cn", "server.example.com",
		"--ip", "192.168.1.1",
		"--ip", "10.0.0.1",
		"--out", csrOut,
	)
	assertNoError(t, err)

	resetIssueFlags()

	// Issue certificate
	certOut := tc.path("server.crt")
	_, err = executeCommand(rootCmd, "cert", "issue",
		"--ca-dir", caDir,
		"--profile", "ec/tls-server",
		"--csr", csrOut,
		"--var", "cn=server.example.com",
		"--var", "dns_names=server.example.com",
		"--var", "ip_addresses=192.168.1.1,10.0.0.1",
		"--out", certOut,
	)
	assertNoError(t, err)
	assertFileExists(t, certOut)
}

func TestF_Cert_Issue_WithIPv6Addresses(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create CA
	caDir := tc.path("ca")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Test CA",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
	)
	assertNoError(t, err)

	resetCSRFlags()

	// Generate CSR with IPv6 addresses
	keyOut := tc.path("server.key")
	csrOut := tc.path("server.csr")
	_, err = executeCommand(rootCmd, "csr", "gen",
		"--algorithm", "ecdsa-p256",
		"--keyout", keyOut,
		"--cn", "server.example.com",
		"--ip", "::1",
		"--ip", "2001:db8::1",
		"--out", csrOut,
	)
	assertNoError(t, err)

	resetIssueFlags()

	// Issue certificate
	certOut := tc.path("server.crt")
	_, err = executeCommand(rootCmd, "cert", "issue",
		"--ca-dir", caDir,
		"--profile", "ec/tls-server",
		"--csr", csrOut,
		"--var", "cn=server.example.com",
		"--var", "dns_names=server.example.com",
		"--var", "ip_addresses=::1,2001:db8::1",
		"--out", certOut,
	)
	assertNoError(t, err)
	assertFileExists(t, certOut)
}

func TestF_Cert_Issue_InvalidIPAddress(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create CA
	caDir := tc.path("ca")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Test CA",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
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
		"--out", csrOut,
	)
	assertNoError(t, err)

	resetIssueFlags()

	// Try to issue with invalid IP
	_, err = executeCommand(rootCmd, "cert", "issue",
		"--ca-dir", caDir,
		"--profile", "ec/tls-server",
		"--csr", csrOut,
		"--var", "cn=server.example.com",
		"--var", "dns_names=server.example.com",
		"--var", "ip_addresses=not-an-ip",
		"--out", tc.path("server.crt"),
	)
	assertError(t, err)
}
