package main

import (
	"path/filepath"
	"testing"
)

// =============================================================================
// Inspect Certificate Tests
// =============================================================================

func TestInspect_Certificate(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create a CA to get a certificate
	caDir := tc.path("ca")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--name", "Test CA",
		"--profile", "ec/root-ca",
		"--dir", caDir,
	)
	assertNoError(t, err)

	// Inspect the CA certificate
	certPath := filepath.Join(caDir, "ca.crt")
	_, err = executeCommand(rootCmd, "inspect", certPath)

	assertNoError(t, err)
}

// =============================================================================
// Inspect Private Key Tests
// =============================================================================

func TestInspect_PrivateKey(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
	}{
		{"ECDSA key", "ecdsa-p256"},
		{"Ed25519 key", "ed25519"},
		{"RSA key", "rsa-2048"},
		{"ML-DSA key", "ml-dsa-65"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := newTestContext(t)
			resetKeyFlags()

			keyPath := tc.path("key.pem")
			_, err := executeCommand(rootCmd, "key", "gen",
				"--algorithm", tt.algorithm,
				"--out", keyPath,
			)
			assertNoError(t, err)

			// Inspect the key
			_, err = executeCommand(rootCmd, "inspect", keyPath)
			assertNoError(t, err)
		})
	}
}

func TestInspect_EncryptedKey(t *testing.T) {
	tc := newTestContext(t)
	resetKeyFlags()

	keyPath := tc.path("encrypted.pem")
	_, err := executeCommand(rootCmd, "key", "gen",
		"--algorithm", "ecdsa-p256",
		"--out", keyPath,
		"--passphrase", "secret123",
	)
	assertNoError(t, err)

	// Inspect should work even for encrypted keys
	_, err = executeCommand(rootCmd, "inspect", keyPath)
	assertNoError(t, err)
}

// =============================================================================
// Inspect CRL Tests
// =============================================================================

func TestInspect_CRL(t *testing.T) {
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
	_, err = executeCommand(rootCmd, "ca", "crl", "gen", "--ca-dir", caDir)
	assertNoError(t, err)

	// Inspect the CRL
	crlPath := filepath.Join(caDir, "crl", "ca.crl")
	_, err = executeCommand(rootCmd, "inspect", crlPath)
	assertNoError(t, err)
}

// =============================================================================
// Inspect Error Cases
// =============================================================================

func TestInspect_FileNotFound(t *testing.T) {
	tc := newTestContext(t)

	_, err := executeCommand(rootCmd, "inspect", tc.path("nonexistent.pem"))
	assertError(t, err)
}

func TestInspect_InvalidFile(t *testing.T) {
	tc := newTestContext(t)

	// Create a file with invalid content
	invalidPath := tc.writeFile("invalid.pem", "this is not a valid PEM file")

	_, err := executeCommand(rootCmd, "inspect", invalidPath)
	assertError(t, err)
}

func TestInspect_MissingArgument(t *testing.T) {
	_, err := executeCommand(rootCmd, "inspect")
	assertError(t, err)
}

// =============================================================================
// Inspect CSR Tests
// =============================================================================

func TestInspect_CSR(t *testing.T) {
	tc := newTestContext(t)
	resetCSRFlags()

	keyOut := tc.path("server.key")
	csrOut := tc.path("server.csr")

	_, err := executeCommand(rootCmd, "cert", "csr",
		"--algorithm", "ecdsa-p256",
		"--keyout", keyOut,
		"--cn", "server.example.com",
		"--dns", "server.example.com",
		"--dns", "www.example.com",
		"--out", csrOut,
	)
	assertNoError(t, err)

	// Inspect the CSR
	_, err = executeCommand(rootCmd, "inspect", csrOut)
	assertNoError(t, err)
}

func TestInspect_CSR_WithIPAddresses(t *testing.T) {
	tc := newTestContext(t)
	resetCSRFlags()

	keyOut := tc.path("server.key")
	csrOut := tc.path("server.csr")

	_, err := executeCommand(rootCmd, "cert", "csr",
		"--algorithm", "ecdsa-p256",
		"--keyout", keyOut,
		"--cn", "server.example.com",
		"--ip", "192.168.1.1",
		"--ip", "10.0.0.1",
		"--out", csrOut,
	)
	assertNoError(t, err)

	// Inspect the CSR
	_, err = executeCommand(rootCmd, "inspect", csrOut)
	assertNoError(t, err)
}

func TestInspect_CSR_MLDSA(t *testing.T) {
	tc := newTestContext(t)
	resetCSRFlags()

	keyOut := tc.path("mldsa.key")
	csrOut := tc.path("mldsa.csr")

	_, err := executeCommand(rootCmd, "cert", "csr",
		"--algorithm", "ml-dsa-65",
		"--keyout", keyOut,
		"--cn", "pqc.example.com",
		"--out", csrOut,
	)
	assertNoError(t, err)

	// Inspect the PQC CSR
	_, err = executeCommand(rootCmd, "inspect", csrOut)
	assertNoError(t, err)
}

// =============================================================================
// Inspect Certificate with Extended Key Usage
// =============================================================================

func TestInspect_CertificateWithExtKeyUsage(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()
	resetCredentialFlags()

	// Create CA
	caDir := tc.path("ca")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--name", "Test CA",
		"--profile", "ec/root-ca",
		"--dir", caDir,
	)
	assertNoError(t, err)

	// Enroll a TLS server credential (has serverAuth EKU)
	resetCredentialFlags()
	_, err = executeCommand(rootCmd, "credential", "enroll",
		"--ca-dir", caDir,
		"--profile", "ec/tls-server",
		"--var", "cn=server.example.com",
		"--var", "dns_names=server.example.com",
	)
	assertNoError(t, err)

	// Find and inspect the credential certificate
	bundlesDir := filepath.Join(caDir, "bundles")
	entries, _ := filepath.Glob(filepath.Join(bundlesDir, "*", "certificates.pem"))
	if len(entries) > 0 {
		_, err = executeCommand(rootCmd, "inspect", entries[0])
		assertNoError(t, err)
	}
}

func TestInspect_CertificateWithClientAuth(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()
	resetCredentialFlags()

	// Create CA
	caDir := tc.path("ca")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--name", "Test CA",
		"--profile", "ec/root-ca",
		"--dir", caDir,
	)
	assertNoError(t, err)

	// Enroll a TLS client credential (has clientAuth EKU)
	resetCredentialFlags()
	_, err = executeCommand(rootCmd, "credential", "enroll",
		"--ca-dir", caDir,
		"--profile", "ec/tls-client",
		"--var", "cn=client@example.com",
		"--var", "email=client@example.com",
	)
	assertNoError(t, err)

	// Find and inspect the credential certificate
	bundlesDir := filepath.Join(caDir, "bundles")
	entries, _ := filepath.Glob(filepath.Join(bundlesDir, "*", "certificates.pem"))
	if len(entries) > 0 {
		_, err = executeCommand(rootCmd, "inspect", entries[0])
		assertNoError(t, err)
	}
}

// =============================================================================
// Inspect CMS Signed Data Tests
// =============================================================================

func TestInspect_CMSSignedData(t *testing.T) {
	tc := newTestContext(t)
	resetCMSFlags()

	// Setup signing pair
	certPath, keyPath := tc.setupSigningPair()

	// Create data to sign
	dataPath := tc.writeFile("data.txt", "Content to sign for inspection")
	sigPath := tc.path("signature.p7s")

	// Create CMS signature
	_, err := executeCommand(rootCmd, "cms", "sign",
		"--data", dataPath,
		"--key", keyPath,
		"--cert", certPath,
		"--out", sigPath,
	)
	assertNoError(t, err)

	// Inspect the CMS signed data
	_, err = executeCommand(rootCmd, "inspect", sigPath)
	assertNoError(t, err)
}

func TestInspect_CMSSignedData_Detached(t *testing.T) {
	tc := newTestContext(t)
	resetCMSFlags()

	certPath, keyPath := tc.setupSigningPair()
	dataPath := tc.writeFile("data.txt", "Detached signature content")
	sigPath := tc.path("signature.p7s")

	// Create detached signature
	_, err := executeCommand(rootCmd, "cms", "sign",
		"--data", dataPath,
		"--key", keyPath,
		"--cert", certPath,
		"--detached",
		"--out", sigPath,
	)
	assertNoError(t, err)

	// Inspect the detached CMS signed data
	_, err = executeCommand(rootCmd, "inspect", sigPath)
	assertNoError(t, err)
}

// =============================================================================
// Inspect CRL with Revoked Certificates
// =============================================================================

func TestInspect_CRL_WithRevokedCerts(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()
	resetCredentialFlags()

	// Create CA
	caDir := tc.path("ca")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--name", "Test CA",
		"--profile", "ec/root-ca",
		"--dir", caDir,
	)
	assertNoError(t, err)

	// Enroll a credential
	resetCredentialFlags()
	_, err = executeCommand(rootCmd, "credential", "enroll",
		"--ca-dir", caDir,
		"--profile", "ec/tls-client",
		"--var", "cn=revoked@example.com",
		"--var", "email=revoked@example.com",
	)
	assertNoError(t, err)

	// Find credential ID
	bundlesDir := filepath.Join(caDir, "bundles")
	entries, _ := filepath.Glob(filepath.Join(bundlesDir, "*"))
	if len(entries) == 0 {
		t.Fatal("no credential found")
	}
	credID := filepath.Base(entries[0])

	// Revoke the credential
	resetCredentialFlags()
	_, err = executeCommand(rootCmd, "credential", "revoke",
		"--ca-dir", caDir,
		"--reason", "keyCompromise",
		credID,
	)
	assertNoError(t, err)

	// Generate CRL
	resetCAFlags()
	_, err = executeCommand(rootCmd, "ca", "crl", "gen", "--ca-dir", caDir)
	assertNoError(t, err)

	// Inspect the CRL with revoked certificate
	crlPath := filepath.Join(caDir, "crl", "ca.crl")
	_, err = executeCommand(rootCmd, "inspect", crlPath)
	assertNoError(t, err)
}
