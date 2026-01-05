package main

import (
	"path/filepath"
	"testing"
)

// resetVerifyFlags resets all verify command flags to their default values.
func resetVerifyFlags() {
	verifyCertFile = ""
	verifyCAFile = ""
	verifyCRLFile = ""
	verifyOCSPURL = ""
}

// =============================================================================
// Verify Tests
// =============================================================================

func TestF_Verify_ValidCertificate(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create CA
	caDir := tc.path("ca")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--profile", "ec/root-ca",
		"--dir", caDir,
		"--var", "cn=Test CA",
	)
	assertNoError(t, err)

	// CA cert is self-signed, should verify against itself
	caCert := filepath.Join(caDir, "ca.crt")

	resetVerifyFlags()

	_, err = executeCommand(rootCmd, "cert", "verify",
		caCert,
		"--ca", caCert,
	)
	assertNoError(t, err)
}

func TestF_Verify_SubordinateCA(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create root CA
	rootDir := tc.path("root-ca")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--profile", "ec/root-ca",
		"--dir", rootDir,
		"--var", "cn=Root CA",
	)
	assertNoError(t, err)

	resetCAFlags()

	// Create subordinate CA
	subDir := tc.path("sub-ca")
	_, err = executeCommand(rootCmd, "ca", "init",
		"--profile", "ec/issuing-ca",
		"--dir", subDir,
		"--parent", rootDir,
		"--var", "cn=Issuing CA",
	)
	assertNoError(t, err)

	resetVerifyFlags()

	// Verify subordinate CA cert against root
	_, err = executeCommand(rootCmd, "cert", "verify",
		filepath.Join(subDir, "ca.crt"),
		"--ca", filepath.Join(rootDir, "ca.crt"),
	)
	assertNoError(t, err)
}

func TestF_Verify_WithCRL(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create CA
	caDir := tc.path("ca")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--profile", "ec/root-ca",
		"--dir", caDir,
		"--var", "cn=Test CA",
	)
	assertNoError(t, err)

	resetCAFlags()

	// Generate CRL
	_, err = executeCommand(rootCmd, "crl", "gen", "--ca-dir", caDir)
	assertNoError(t, err)

	resetVerifyFlags()

	// Verify with CRL check
	caCert := filepath.Join(caDir, "ca.crt")
	crlFile := filepath.Join(caDir, "crl", "ca.crl")

	_, err = executeCommand(rootCmd, "cert", "verify",
		caCert,
		"--ca", caCert,
		"--crl", crlFile,
	)
	assertNoError(t, err)
}

// =============================================================================
// Verify Error Cases
// =============================================================================

func TestF_Verify_MissingCert(t *testing.T) {
	resetVerifyFlags()

	// Positional argument is now required - cobra will fail
	_, err := executeCommand(rootCmd, "cert", "verify",
		"--ca", "/tmp/ca.crt",
	)
	assertError(t, err)
}

func TestF_Verify_MissingCA(t *testing.T) {
	tc := newTestContext(t)
	resetVerifyFlags()

	_, err := executeCommand(rootCmd, "cert", "verify",
		tc.path("cert.crt"),
	)
	assertError(t, err)
}

func TestF_Verify_CertNotFound(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create CA
	caDir := tc.path("ca")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--profile", "ec/root-ca",
		"--dir", caDir,
		"--var", "cn=Test CA",
	)
	assertNoError(t, err)

	resetVerifyFlags()

	_, err = executeCommand(rootCmd, "cert", "verify",
		tc.path("nonexistent.crt"),
		"--ca", filepath.Join(caDir, "ca.crt"),
	)
	assertError(t, err)
}

func TestF_Verify_CANotFound(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create CA
	caDir := tc.path("ca")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--profile", "ec/root-ca",
		"--dir", caDir,
		"--var", "cn=Test CA",
	)
	assertNoError(t, err)

	resetVerifyFlags()

	_, err = executeCommand(rootCmd, "cert", "verify",
		filepath.Join(caDir, "ca.crt"),
		"--ca", tc.path("nonexistent.crt"),
	)
	assertError(t, err)
}

func TestF_Verify_InvalidCRLPath(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create CA
	caDir := tc.path("ca")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--profile", "ec/root-ca",
		"--dir", caDir,
		"--var", "cn=Test CA",
	)
	assertNoError(t, err)

	resetVerifyFlags()

	caCert := filepath.Join(caDir, "ca.crt")

	_, err = executeCommand(rootCmd, "cert", "verify",
		caCert,
		"--ca", caCert,
		"--crl", tc.path("nonexistent.crl"),
	)
	assertError(t, err)
}
