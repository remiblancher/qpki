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
		"--name", "Test CA",
		"--profile", "ec/root-ca",
		"--dir", caDir,
	)
	assertNoError(t, err)

	// CA cert is self-signed, should verify against itself
	caCert := filepath.Join(caDir, "ca.crt")

	resetVerifyFlags()

	_, err = executeCommand(rootCmd, "cert", "verify",
		"--cert", caCert,
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
		"--name", "Root CA",
		"--profile", "ec/root-ca",
		"--dir", rootDir,
	)
	assertNoError(t, err)

	resetCAFlags()

	// Create subordinate CA
	subDir := tc.path("sub-ca")
	_, err = executeCommand(rootCmd, "ca", "init",
		"--name", "Issuing CA",
		"--profile", "ec/issuing-ca",
		"--dir", subDir,
		"--parent", rootDir,
	)
	assertNoError(t, err)

	resetVerifyFlags()

	// Verify subordinate CA cert against root
	_, err = executeCommand(rootCmd, "cert", "verify",
		"--cert", filepath.Join(subDir, "ca.crt"),
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
		"--name", "Test CA",
		"--profile", "ec/root-ca",
		"--dir", caDir,
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
		"--cert", caCert,
		"--ca", caCert,
		"--crl", crlFile,
	)
	assertNoError(t, err)
}

// =============================================================================
// Verify Error Cases
// =============================================================================

func TestF_Verify_MissingCert(t *testing.T) {
	tc := newTestContext(t)
	resetVerifyFlags()

	_, err := executeCommand(rootCmd, "cert", "verify",
		"--ca", tc.path("ca.crt"),
	)
	assertError(t, err)
}

func TestF_Verify_MissingCA(t *testing.T) {
	tc := newTestContext(t)
	resetVerifyFlags()

	_, err := executeCommand(rootCmd, "cert", "verify",
		"--cert", tc.path("cert.crt"),
	)
	assertError(t, err)
}

func TestF_Verify_CertNotFound(t *testing.T) {
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

	resetVerifyFlags()

	_, err = executeCommand(rootCmd, "cert", "verify",
		"--cert", tc.path("nonexistent.crt"),
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
		"--name", "Test CA",
		"--profile", "ec/root-ca",
		"--dir", caDir,
	)
	assertNoError(t, err)

	resetVerifyFlags()

	_, err = executeCommand(rootCmd, "cert", "verify",
		"--cert", filepath.Join(caDir, "ca.crt"),
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
		"--name", "Test CA",
		"--profile", "ec/root-ca",
		"--dir", caDir,
	)
	assertNoError(t, err)

	resetVerifyFlags()

	caCert := filepath.Join(caDir, "ca.crt")

	_, err = executeCommand(rootCmd, "cert", "verify",
		"--cert", caCert,
		"--ca", caCert,
		"--crl", tc.path("nonexistent.crl"),
	)
	assertError(t, err)
}
