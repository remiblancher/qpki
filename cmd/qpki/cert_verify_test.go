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

func TestF_Verify_RevokedCertificate(t *testing.T) {
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

	resetCredentialFlags()

	// Issue a credential
	_, err = executeCommand(rootCmd, "credential", "enroll",
		"--profile", "ec/tls-server",
		"--var", "cn=test.example.com",
		"--ca-dir", caDir,
		"--id", "test-cert",
	)
	assertNoError(t, err)

	// Revoke the credential
	resetCredentialFlags()
	_, err = executeCommand(rootCmd, "credential", "revoke",
		"test-cert",
		"--ca-dir", caDir,
		"--reason", "keyCompromise",
	)
	assertNoError(t, err)

	// Generate CRL
	resetCAFlags()
	_, err = executeCommand(rootCmd, "crl", "gen", "--ca-dir", caDir)
	assertNoError(t, err)

	// Find the issued certificate
	certPath := filepath.Join(caDir, "credentials", "test-cert", "certificates.pem")
	caCert := filepath.Join(caDir, "ca.crt")
	crlFile := filepath.Join(caDir, "crl", "ca.crl")

	resetVerifyFlags()

	// Verify should fail because cert is revoked
	_, err = executeCommand(rootCmd, "cert", "verify",
		certPath,
		"--ca", caCert,
		"--crl", crlFile,
	)
	assertError(t, err)
}

func TestF_Verify_WrongIssuer(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create first CA
	ca1Dir := tc.path("ca1")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--profile", "ec/root-ca",
		"--dir", ca1Dir,
		"--var", "cn=CA One",
	)
	assertNoError(t, err)

	resetCAFlags()

	// Create second CA
	ca2Dir := tc.path("ca2")
	_, err = executeCommand(rootCmd, "ca", "init",
		"--profile", "ec/root-ca",
		"--dir", ca2Dir,
		"--var", "cn=CA Two",
	)
	assertNoError(t, err)

	resetVerifyFlags()

	// Try to verify CA1's cert with CA2 as the issuer - should fail
	_, err = executeCommand(rootCmd, "cert", "verify",
		filepath.Join(ca1Dir, "ca.crt"),
		"--ca", filepath.Join(ca2Dir, "ca.crt"),
	)
	assertError(t, err)
}

func TestF_Verify_IssuedCertificate(t *testing.T) {
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

	resetCredentialFlags()

	// Issue a credential
	_, err = executeCommand(rootCmd, "credential", "enroll",
		"--profile", "ec/tls-server",
		"--var", "cn=server.example.com",
		"--ca-dir", caDir,
		"--id", "server",
	)
	assertNoError(t, err)

	resetVerifyFlags()

	// Verify the issued certificate
	certPath := filepath.Join(caDir, "credentials", "server", "certificates.pem")
	caCert := filepath.Join(caDir, "ca.crt")

	_, err = executeCommand(rootCmd, "cert", "verify",
		certPath,
		"--ca", caCert,
	)
	assertNoError(t, err)
}

// =============================================================================
// Unit Tests for Helper Functions
// =============================================================================

func TestU_GetRevocationReasonString(t *testing.T) {
	tests := []struct {
		code     int
		expected string
	}{
		{0, "unspecified"},
		{1, "keyCompromise"},
		{2, "cACompromise"},
		{3, "affiliationChanged"},
		{4, "superseded"},
		{5, "cessationOfOperation"},
		{6, "certificateHold"},
		{8, "removeFromCRL"},
		{9, "privilegeWithdrawn"},
		{10, "aACompromise"},
		{99, "unknown (99)"},
		{-1, "unknown (-1)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := getRevocationReasonString(tt.code)
			if result != tt.expected {
				t.Errorf("getRevocationReasonString(%d) = %q, want %q", tt.code, result, tt.expected)
			}
		})
	}
}
