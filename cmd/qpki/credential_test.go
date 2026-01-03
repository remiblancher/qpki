package main

import (
	"os"
	"path/filepath"
	"testing"
)

// resetCredentialFlags resets all credential command flags to their default values.
func resetCredentialFlags() {
	credCADir = "./ca"
	credPassphrase = ""
	credRevokeReason = "unspecified"
	credExportOut = ""
	credExportKeys = false

	credEnrollProfiles = nil
	credEnrollID = ""
	credEnrollVars = nil
	credEnrollVarFile = ""

	credRotateProfiles = nil
	credRotateAddProfiles = nil
	credRotateRemoveProfiles = nil
	credRotateKeepKeys = false

	credImportCert = ""
	credImportKey = ""
	credImportID = ""
}

// =============================================================================
// Credential Enroll Tests
// =============================================================================

func TestF_CredentialEnroll(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create CA first
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

	// Verify credentials directory was created
	credentialsDir := filepath.Join(caDir, "credentials")
	assertFileExists(t, credentialsDir)
}

func TestF_CredentialEnroll_ProfileMissing(t *testing.T) {
	tc := newTestContext(t)
	resetCredentialFlags()

	_, err := executeCommand(rootCmd, "credential", "enroll",
		"--ca-dir", tc.path("ca"),
		"--var", "cn=test.local",
	)
	assertError(t, err)
}

func TestF_CredentialEnroll_CANotFound(t *testing.T) {
	tc := newTestContext(t)
	resetCredentialFlags()

	_, err := executeCommand(rootCmd, "credential", "enroll",
		"--ca-dir", tc.path("nonexistent"),
		"--profile", "ec/tls-server",
		"--var", "cn=test.local",
	)
	assertError(t, err)
}

// =============================================================================
// Credential List Tests
// =============================================================================

func TestF_CredentialList(t *testing.T) {
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

	// List credentials (empty)
	_, err = executeCommand(rootCmd, "credential", "list", "--ca-dir", caDir)
	assertNoError(t, err)
}

func TestF_CredentialList_WithCredentials(t *testing.T) {
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

	resetCredentialFlags()

	// List credentials
	_, err = executeCommand(rootCmd, "credential", "list", "--ca-dir", caDir)
	assertNoError(t, err)
}

func TestF_CredentialList_EmptyDir(t *testing.T) {
	tc := newTestContext(t)
	resetCredentialFlags()

	// List on empty dir should not error, just return "No credentials found"
	_, err := executeCommand(rootCmd, "credential", "list", "--ca-dir", tc.tempDir)
	assertNoError(t, err)
}

// =============================================================================
// Credential Info Tests
// =============================================================================

func TestF_CredentialInfo_NotFound(t *testing.T) {
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

	_, err := executeCommand(rootCmd, "credential", "info",
		"--ca-dir", caDir,
		"nonexistent-credential-id",
	)
	assertError(t, err)
}

func TestF_CredentialInfo_ArgMissing(t *testing.T) {
	tc := newTestContext(t)
	resetCredentialFlags()

	_, err := executeCommand(rootCmd, "credential", "info", "--ca-dir", tc.path("ca"))
	assertError(t, err)
}

// =============================================================================
// Helper: Setup CA with enrolled credential
// =============================================================================

// setupCAWithCredential creates a CA and enrolls a credential.
// Returns: caDir, credentialID
func setupCAWithCredential(tc *testContext) (string, string) {
	tc.t.Helper()

	resetCAFlags()
	caDir := tc.path("ca")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--name", "Test CA",
		"--profile", "ec/root-ca",
		"--dir", caDir,
	)
	if err != nil {
		tc.t.Fatalf("failed to init CA: %v", err)
	}

	resetCredentialFlags()
	_, err = executeCommand(rootCmd, "credential", "enroll",
		"--ca-dir", caDir,
		"--profile", "ec/tls-server",
		"--var", "cn=test.local",
		"--var", "dns_names=test.local",
	)
	if err != nil {
		tc.t.Fatalf("failed to enroll credential: %v", err)
	}

	// Find the credential ID from credentials directory
	credentialsDir := filepath.Join(caDir, "credentials")
	entries, err := os.ReadDir(credentialsDir)
	if err != nil || len(entries) == 0 {
		tc.t.Fatal("no credentials found")
	}

	return caDir, entries[0].Name()
}

// =============================================================================
// Credential Info Tests (happy path)
// =============================================================================

func TestF_CredentialInfo_Basic(t *testing.T) {
	tc := newTestContext(t)
	caDir, credID := setupCAWithCredential(tc)

	resetCredentialFlags()
	_, err := executeCommand(rootCmd, "credential", "info",
		"--ca-dir", caDir,
		credID,
	)
	assertNoError(t, err)
}

// =============================================================================
// Credential Rotate Tests
// =============================================================================

// setupCAWithSimpleCredential creates a CA with a credential using a profile
// that works well for rotation tests (ec/tls-client with email).
func setupCAWithSimpleCredential(tc *testContext) (string, string) {
	tc.t.Helper()

	resetCAFlags()
	caDir := tc.path("ca")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--name", "Test CA",
		"--profile", "ec/root-ca",
		"--dir", caDir,
	)
	if err != nil {
		tc.t.Fatalf("failed to init CA: %v", err)
	}

	// Use ec/tls-client profile with email
	resetCredentialFlags()
	_, err = executeCommand(rootCmd, "credential", "enroll",
		"--ca-dir", caDir,
		"--profile", "ec/tls-client",
		"--var", "cn=test@test.local",
		"--var", "email=test@test.local",
	)
	if err != nil {
		tc.t.Fatalf("failed to enroll credential: %v", err)
	}

	// Find the credential ID from credentials directory
	credentialsDir := filepath.Join(caDir, "credentials")
	entries, err := os.ReadDir(credentialsDir)
	if err != nil || len(entries) == 0 {
		tc.t.Fatal("no credentials found")
	}

	return caDir, entries[0].Name()
}

func TestF_CredentialRotate_Basic(t *testing.T) {
	tc := newTestContext(t)
	caDir, credID := setupCAWithSimpleCredential(tc)

	resetCredentialFlags()
	_, err := executeCommand(rootCmd, "credential", "rotate",
		"--ca-dir", caDir,
		credID,
	)
	assertNoError(t, err)
}

func TestF_CredentialRotate_KeepKeys(t *testing.T) {
	tc := newTestContext(t)
	caDir, credID := setupCAWithSimpleCredential(tc)

	resetCredentialFlags()
	_, err := executeCommand(rootCmd, "credential", "rotate",
		"--ca-dir", caDir,
		"--keep-keys",
		credID,
	)
	assertNoError(t, err)
}

func TestF_CredentialRotate_CredentialNotFound(t *testing.T) {
	tc := newTestContext(t)
	caDir, _ := setupCAWithCredential(tc)

	resetCredentialFlags()
	_, err := executeCommand(rootCmd, "credential", "rotate",
		"--ca-dir", caDir,
		"nonexistent-credential-id",
	)
	assertError(t, err)
}

func TestF_CredentialRotate_CANotFound(t *testing.T) {
	tc := newTestContext(t)
	resetCredentialFlags()

	_, err := executeCommand(rootCmd, "credential", "rotate",
		"--ca-dir", tc.path("nonexistent"),
		"some-credential-id",
	)
	assertError(t, err)
}

func TestF_CredentialRotate_ArgMissing(t *testing.T) {
	tc := newTestContext(t)
	resetCredentialFlags()

	_, err := executeCommand(rootCmd, "credential", "rotate",
		"--ca-dir", tc.path("ca"),
	)
	assertError(t, err)
}

// =============================================================================
// Credential Revoke Tests
// =============================================================================

func TestF_CredentialRevoke_Basic(t *testing.T) {
	tc := newTestContext(t)
	caDir, credID := setupCAWithCredential(tc)

	resetCredentialFlags()
	_, err := executeCommand(rootCmd, "credential", "revoke",
		"--ca-dir", caDir,
		credID,
	)
	assertNoError(t, err)
}

func TestF_CredentialRevoke_WithReason(t *testing.T) {
	tc := newTestContext(t)
	caDir, credID := setupCAWithCredential(tc)

	resetCredentialFlags()
	_, err := executeCommand(rootCmd, "credential", "revoke",
		"--ca-dir", caDir,
		"--reason", "keyCompromise",
		credID,
	)
	assertNoError(t, err)
}

func TestF_CredentialRevoke_AllReasons(t *testing.T) {
	reasons := []string{
		"caCompromise",
		"affiliationChanged",
		"superseded",
		"cessationOfOperation",
		"privilegeWithdrawn",
	}

	for _, reason := range reasons {
		t.Run(reason, func(t *testing.T) {
			tc := newTestContext(t)
			caDir, credID := setupCAWithCredential(tc)

			resetCredentialFlags()
			_, err := executeCommand(rootCmd, "credential", "revoke",
				"--ca-dir", caDir,
				"--reason", reason,
				credID,
			)
			assertNoError(t, err)
		})
	}
}

func TestF_CredentialRevoke_CredentialNotFound(t *testing.T) {
	tc := newTestContext(t)
	caDir, _ := setupCAWithCredential(tc)

	resetCredentialFlags()
	_, err := executeCommand(rootCmd, "credential", "revoke",
		"--ca-dir", caDir,
		"nonexistent-credential-id",
	)
	assertError(t, err)
}

func TestF_CredentialRevoke_CANotFound(t *testing.T) {
	tc := newTestContext(t)
	resetCredentialFlags()

	_, err := executeCommand(rootCmd, "credential", "revoke",
		"--ca-dir", tc.path("nonexistent"),
		"some-credential-id",
	)
	assertError(t, err)
}

func TestF_CredentialRevoke_ArgMissing(t *testing.T) {
	tc := newTestContext(t)
	resetCredentialFlags()

	_, err := executeCommand(rootCmd, "credential", "revoke",
		"--ca-dir", tc.path("ca"),
	)
	assertError(t, err)
}

// =============================================================================
// Credential Export Tests
// =============================================================================

func TestF_CredentialExport_ToStdout(t *testing.T) {
	tc := newTestContext(t)
	caDir, credID := setupCAWithCredential(tc)

	resetCredentialFlags()
	// Note: Export writes to stdout via fmt.Print, not to Cobra's output buffer.
	// So we just verify the command succeeds without error.
	_, err := executeCommand(rootCmd, "credential", "export",
		"--ca-dir", caDir,
		credID,
	)
	assertNoError(t, err)
}

func TestF_CredentialExport_ToFile(t *testing.T) {
	tc := newTestContext(t)
	caDir, credID := setupCAWithCredential(tc)
	outputPath := tc.path("exported.pem")

	resetCredentialFlags()
	_, err := executeCommand(rootCmd, "credential", "export",
		"--ca-dir", caDir,
		"--out", outputPath,
		credID,
	)
	assertNoError(t, err)
	assertFileExists(t, outputPath)
	assertFileNotEmpty(t, outputPath)
}

func TestF_CredentialExport_CredentialNotFound(t *testing.T) {
	tc := newTestContext(t)
	caDir, _ := setupCAWithCredential(tc)

	resetCredentialFlags()
	output, err := executeCommand(rootCmd, "credential", "export",
		"--ca-dir", caDir,
		"nonexistent-credential-id",
	)
	// Export returns empty output for nonexistent credentials (not an error)
	assertNoError(t, err)
	if output != "" {
		t.Error("expected empty output for nonexistent credential")
	}
}

func TestF_CredentialExport_ArgMissing(t *testing.T) {
	tc := newTestContext(t)
	resetCredentialFlags()

	_, err := executeCommand(rootCmd, "credential", "export",
		"--ca-dir", tc.path("ca"),
	)
	assertError(t, err)
}

// =============================================================================
// Credential Import Tests
// =============================================================================

func TestF_CredentialImport_Basic(t *testing.T) {
	tc := newTestContext(t)

	// Create CA first
	resetCAFlags()
	caDir := tc.path("ca")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--name", "Test CA",
		"--profile", "ec/root-ca",
		"--dir", caDir,
	)
	assertNoError(t, err)

	// Create a self-signed certificate for import
	priv, pub := generateECDSAKeyPair(tc.t)
	cert := generateSelfSignedCert(tc.t, priv, pub)
	certPath := tc.writeCertPEM("import.crt", cert)
	keyPath := tc.writeKeyPEM("import.key", priv)

	resetCredentialFlags()
	_, err = executeCommand(rootCmd, "credential", "import",
		"--ca-dir", caDir,
		"--cert", certPath,
		"--key", keyPath,
	)
	assertNoError(t, err)
}

func TestF_CredentialImport_WithCustomID(t *testing.T) {
	tc := newTestContext(t)

	// Create CA first
	resetCAFlags()
	caDir := tc.path("ca")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--name", "Test CA",
		"--profile", "ec/root-ca",
		"--dir", caDir,
	)
	assertNoError(t, err)

	// Create a self-signed certificate for import
	priv, pub := generateECDSAKeyPair(tc.t)
	cert := generateSelfSignedCert(tc.t, priv, pub)
	certPath := tc.writeCertPEM("import.crt", cert)
	keyPath := tc.writeKeyPEM("import.key", priv)

	resetCredentialFlags()
	_, err = executeCommand(rootCmd, "credential", "import",
		"--ca-dir", caDir,
		"--cert", certPath,
		"--key", keyPath,
		"--id", "my-imported-credential",
	)
	assertNoError(t, err)
}

func TestF_CredentialImport_CertMissing(t *testing.T) {
	tc := newTestContext(t)
	resetCredentialFlags()

	priv, _ := generateECDSAKeyPair(tc.t)
	keyPath := tc.writeKeyPEM("import.key", priv)

	_, err := executeCommand(rootCmd, "credential", "import",
		"--ca-dir", tc.path("ca"),
		"--key", keyPath,
	)
	assertError(t, err)
}

func TestF_CredentialImport_KeyMissing(t *testing.T) {
	tc := newTestContext(t)
	resetCredentialFlags()

	priv, pub := generateECDSAKeyPair(tc.t)
	cert := generateSelfSignedCert(tc.t, priv, pub)
	certPath := tc.writeCertPEM("import.crt", cert)

	_, err := executeCommand(rootCmd, "credential", "import",
		"--ca-dir", tc.path("ca"),
		"--cert", certPath,
	)
	assertError(t, err)
}

func TestF_CredentialImport_CertNotFound(t *testing.T) {
	tc := newTestContext(t)
	resetCredentialFlags()

	priv, _ := generateECDSAKeyPair(tc.t)
	keyPath := tc.writeKeyPEM("import.key", priv)

	_, err := executeCommand(rootCmd, "credential", "import",
		"--ca-dir", tc.path("ca"),
		"--cert", tc.path("nonexistent.crt"),
		"--key", keyPath,
	)
	assertError(t, err)
}

func TestF_CredentialImport_KeyNotFound(t *testing.T) {
	tc := newTestContext(t)
	resetCredentialFlags()

	priv, pub := generateECDSAKeyPair(tc.t)
	cert := generateSelfSignedCert(tc.t, priv, pub)
	certPath := tc.writeCertPEM("import.crt", cert)

	_, err := executeCommand(rootCmd, "credential", "import",
		"--ca-dir", tc.path("ca"),
		"--cert", certPath,
		"--key", tc.path("nonexistent.key"),
	)
	assertError(t, err)
}

func TestF_CredentialImport_KeyMismatch(t *testing.T) {
	tc := newTestContext(t)

	// Create CA first
	resetCAFlags()
	caDir := tc.path("ca")
	_, _ = executeCommand(rootCmd, "ca", "init",
		"--name", "Test CA",
		"--profile", "ec/root-ca",
		"--dir", caDir,
	)

	// Create certificate with one key
	priv1, pub1 := generateECDSAKeyPair(tc.t)
	cert := generateSelfSignedCert(tc.t, priv1, pub1)
	certPath := tc.writeCertPEM("import.crt", cert)

	// Create different key for import
	priv2, _ := generateECDSAKeyPair(tc.t)
	keyPath := tc.writeKeyPEM("import.key", priv2)

	resetCredentialFlags()
	_, err := executeCommand(rootCmd, "credential", "import",
		"--ca-dir", caDir,
		"--cert", certPath,
		"--key", keyPath,
	)
	assertError(t, err)
}
