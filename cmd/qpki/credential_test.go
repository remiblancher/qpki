package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// resetCredentialFlags resets all credential command flags to their default values.
func resetCredentialFlags() {
	credCADir = "./ca"
	credDir = "./credentials"
	credPassphrase = ""
	credRevokeReason = "unspecified"

	// Export flags
	credExportOut = ""
	credExportFormat = "pem"
	credExportBundle = "cert"
	credExportVersion = ""
	credExportAll = false

	// Enroll flags
	credEnrollProfiles = nil
	credEnrollID = ""
	credEnrollVars = nil
	credEnrollVarFile = ""

	// Rotate flags
	credRotateProfiles = nil
	credRotateAddProfiles = nil
	credRotateRemoveProfiles = nil
	credRotateKeepKeys = false
}

// =============================================================================
// Credential Enroll Tests
// =============================================================================

func TestF_Credential_Enroll(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create CA first
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

	// Verify credentials directory was created
	assertFileExists(t, credentialsDir)
}

func TestF_Credential_Enroll_ProfileMissing(t *testing.T) {
	tc := newTestContext(t)
	resetCredentialFlags()

	_, err := executeCommand(rootCmd, "credential", "enroll",
		"--ca-dir", tc.path("ca"),
		"--var", "cn=test.local",
	)
	assertError(t, err)
}

func TestF_Credential_Enroll_CANotFound(t *testing.T) {
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

func TestF_Credential_List(t *testing.T) {
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

	// List credentials (empty)
	_, err = executeCommand(rootCmd, "credential", "list", "--cred-dir", credentialsDir)
	assertNoError(t, err)
}

func TestF_Credential_List_WithCredentials(t *testing.T) {
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

	resetCredentialFlags()

	// List credentials
	_, err = executeCommand(rootCmd, "credential", "list", "--cred-dir", credentialsDir)
	assertNoError(t, err)
}

func TestF_Credential_List_EmptyDir(t *testing.T) {
	tc := newTestContext(t)
	resetCredentialFlags()

	// List on empty dir should not error, just return "No credentials found"
	_, err := executeCommand(rootCmd, "credential", "list", "--cred-dir", tc.tempDir)
	assertNoError(t, err)
}

// =============================================================================
// Credential Info Tests
// =============================================================================

func TestF_Credential_Info_NotFound(t *testing.T) {
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

	_, err := executeCommand(rootCmd, "credential", "info",
		"--ca-dir", caDir,
		"--cred-dir", credentialsDir,
		"nonexistent-credential-id",
	)
	assertError(t, err)
}

func TestF_Credential_Info_ArgMissing(t *testing.T) {
	tc := newTestContext(t)
	resetCredentialFlags()

	_, err := executeCommand(rootCmd, "credential", "info",
		"--ca-dir", tc.path("ca"),
		"--cred-dir", tc.path("credentials"),
	)
	assertError(t, err)
}

// =============================================================================
// Helper: Setup CA with enrolled credential
// =============================================================================

// setupCAWithCredential creates a CA and enrolls a credential.
// Returns: caDir, credentialsDir, credentialID
func setupCAWithCredential(tc *testContext) (string, string, string) {
	tc.t.Helper()

	resetCAFlags()
	caDir := tc.path("ca")
	credentialsDir := tc.path("credentials")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
		"--var", "cn=Test CA",
	)
	if err != nil {
		tc.t.Fatalf("failed to init CA: %v", err)
	}

	resetCredentialFlags()
	_, err = executeCommand(rootCmd, "credential", "enroll",
		"--ca-dir", caDir,
		"--cred-dir", credentialsDir,
		"--profile", "ec/tls-server",
		"--var", "cn=test.local",
		"--var", "dns_names=test.local",
	)
	if err != nil {
		tc.t.Fatalf("failed to enroll credential: %v", err)
	}

	// Find the credential ID from credentials directory
	entries, err := os.ReadDir(credentialsDir)
	if err != nil || len(entries) == 0 {
		tc.t.Fatal("no credentials found")
	}

	return caDir, credentialsDir, entries[0].Name()
}

// =============================================================================
// Credential Info Tests (happy path)
// =============================================================================

func TestF_Credential_Info_Basic(t *testing.T) {
	tc := newTestContext(t)
	caDir, credentialsDir, credID := setupCAWithCredential(tc)

	resetCredentialFlags()
	_, err := executeCommand(rootCmd, "credential", "info",
		"--ca-dir", caDir,
		"--cred-dir", credentialsDir,
		credID,
	)
	assertNoError(t, err)
}

// =============================================================================
// Credential Rotate Tests
// =============================================================================

// setupCAWithSimpleCredential creates a CA with a credential using a profile
// that works well for rotation tests (ec/tls-client with email).
// Returns: caDir, credentialsDir, credentialID
func setupCAWithSimpleCredential(tc *testContext) (string, string, string) {
	tc.t.Helper()

	resetCAFlags()
	caDir := tc.path("ca")
	credentialsDir := tc.path("credentials")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
		"--var", "cn=Test CA",
	)
	if err != nil {
		tc.t.Fatalf("failed to init CA: %v", err)
	}

	// Use ec/tls-client profile with email
	resetCredentialFlags()
	_, err = executeCommand(rootCmd, "credential", "enroll",
		"--ca-dir", caDir,
		"--cred-dir", credentialsDir,
		"--profile", "ec/tls-client",
		"--var", "cn=test@test.local",
		"--var", "email=test@test.local",
	)
	if err != nil {
		tc.t.Fatalf("failed to enroll credential: %v", err)
	}

	// Find the credential ID from credentials directory
	entries, err := os.ReadDir(credentialsDir)
	if err != nil || len(entries) == 0 {
		tc.t.Fatal("no credentials found")
	}

	return caDir, credentialsDir, entries[0].Name()
}

func TestF_Credential_Rotate_Basic(t *testing.T) {
	tc := newTestContext(t)
	caDir, credentialsDir, credID := setupCAWithSimpleCredential(tc)

	resetCredentialFlags()
	_, err := executeCommand(rootCmd, "credential", "rotate",
		"--ca-dir", caDir,
		"--cred-dir", credentialsDir,
		credID,
	)
	assertNoError(t, err)
}

func TestF_Credential_Rotate_KeepKeys(t *testing.T) {
	tc := newTestContext(t)
	caDir, credentialsDir, credID := setupCAWithSimpleCredential(tc)

	resetCredentialFlags()
	_, err := executeCommand(rootCmd, "credential", "rotate",
		"--ca-dir", caDir,
		"--cred-dir", credentialsDir,
		"--keep-keys",
		credID,
	)
	assertNoError(t, err)
}

func TestF_Credential_Rotate_CredentialNotFound(t *testing.T) {
	tc := newTestContext(t)
	caDir, credentialsDir, _ := setupCAWithCredential(tc)

	resetCredentialFlags()
	_, err := executeCommand(rootCmd, "credential", "rotate",
		"--ca-dir", caDir,
		"--cred-dir", credentialsDir,
		"nonexistent-credential-id",
	)
	assertError(t, err)
}

func TestF_Credential_Rotate_CANotFound(t *testing.T) {
	tc := newTestContext(t)
	resetCredentialFlags()

	_, err := executeCommand(rootCmd, "credential", "rotate",
		"--ca-dir", tc.path("nonexistent"),
		"--cred-dir", tc.path("credentials"),
		"some-credential-id",
	)
	assertError(t, err)
}

func TestF_Credential_Rotate_ArgMissing(t *testing.T) {
	tc := newTestContext(t)
	resetCredentialFlags()

	_, err := executeCommand(rootCmd, "credential", "rotate",
		"--ca-dir", tc.path("ca"),
		"--cred-dir", tc.path("credentials"),
	)
	assertError(t, err)
}

func TestF_Credential_Rotate_CreatesPendingVersion(t *testing.T) {
	tc := newTestContext(t)
	caDir, credentialsDir, credID := setupCAWithSimpleCredential(tc)

	resetCredentialFlags()
	_, err := executeCommand(rootCmd, "credential", "rotate",
		"--ca-dir", caDir,
		"--cred-dir", credentialsDir,
		credID,
	)
	assertNoError(t, err)

	// Verify a versions directory was created (versioned rotation)
	versionsDir := filepath.Join(credentialsDir, credID, "versions")
	assertFileExists(t, versionsDir)

	// Verify credential still exists with same ID (info command works)
	resetCredentialFlags()
	_, err = executeCommand(rootCmd, "credential", "info",
		"--ca-dir", caDir,
		"--cred-dir", credentialsDir,
		credID,
	)
	assertNoError(t, err)
}

func TestF_Credential_Rotate_ThenActivate(t *testing.T) {
	tc := newTestContext(t)
	caDir, credentialsDir, credID := setupCAWithSimpleCredential(tc)

	// First rotate
	resetCredentialFlags()
	_, err := executeCommand(rootCmd, "credential", "rotate",
		"--ca-dir", caDir,
		"--cred-dir", credentialsDir,
		credID,
	)
	assertNoError(t, err)

	// Check versions command works
	resetCredentialActivateFlags()
	_, err = executeCommand(rootCmd, "credential", "versions",
		"--cred-dir", credentialsDir,
		credID,
	)
	assertNoError(t, err)

	// Activate using v2 shorthand (first versioned version)
	resetCredentialActivateFlags()
	_, err = executeCommand(rootCmd, "credential", "activate",
		"--cred-dir", credentialsDir,
		"--version", "v2",
		credID,
	)
	assertNoError(t, err)

	// Verify credential is still accessible after activation
	resetCredentialFlags()
	_, err = executeCommand(rootCmd, "credential", "info",
		"--ca-dir", caDir,
		"--cred-dir", credentialsDir,
		credID,
	)
	assertNoError(t, err)
}

func TestF_Credential_Rotate_KeepsSameID(t *testing.T) {
	tc := newTestContext(t)
	caDir, credentialsDir, credID := setupCAWithSimpleCredential(tc)

	resetCredentialFlags()
	_, err := executeCommand(rootCmd, "credential", "rotate",
		"--ca-dir", caDir,
		"--cred-dir", credentialsDir,
		credID,
	)
	assertNoError(t, err)

	// Verify the credential still exists with the same ID
	resetCredentialFlags()
	_, err = executeCommand(rootCmd, "credential", "info",
		"--ca-dir", caDir,
		"--cred-dir", credentialsDir,
		credID,
	)
	assertNoError(t, err)

	// Verify the credential directory still exists
	credentialDir := filepath.Join(credentialsDir, credID)
	assertFileExists(t, credentialDir)
}

// =============================================================================
// Credential Revoke Tests
// =============================================================================

func TestF_Credential_Revoke_Basic(t *testing.T) {
	tc := newTestContext(t)
	caDir, credentialsDir, credID := setupCAWithCredential(tc)

	resetCredentialFlags()
	_, err := executeCommand(rootCmd, "credential", "revoke",
		"--ca-dir", caDir,
		"--cred-dir", credentialsDir,
		credID,
	)
	assertNoError(t, err)
}

func TestF_Credential_Revoke_WithReason(t *testing.T) {
	tc := newTestContext(t)
	caDir, credentialsDir, credID := setupCAWithCredential(tc)

	resetCredentialFlags()
	_, err := executeCommand(rootCmd, "credential", "revoke",
		"--ca-dir", caDir,
		"--cred-dir", credentialsDir,
		"--reason", "keyCompromise",
		credID,
	)
	assertNoError(t, err)
}

func TestF_Credential_Revoke_AllReasons(t *testing.T) {
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
			caDir, credentialsDir, credID := setupCAWithCredential(tc)

			resetCredentialFlags()
			_, err := executeCommand(rootCmd, "credential", "revoke",
				"--ca-dir", caDir,
				"--cred-dir", credentialsDir,
				"--reason", reason,
				credID,
			)
			assertNoError(t, err)
		})
	}
}

func TestF_Credential_Revoke_CredentialNotFound(t *testing.T) {
	tc := newTestContext(t)
	caDir, credentialsDir, _ := setupCAWithCredential(tc)

	resetCredentialFlags()
	_, err := executeCommand(rootCmd, "credential", "revoke",
		"--ca-dir", caDir,
		"--cred-dir", credentialsDir,
		"nonexistent-credential-id",
	)
	assertError(t, err)
}

func TestF_Credential_Revoke_CANotFound(t *testing.T) {
	tc := newTestContext(t)
	resetCredentialFlags()

	_, err := executeCommand(rootCmd, "credential", "revoke",
		"--ca-dir", tc.path("nonexistent"),
		"--cred-dir", tc.path("credentials"),
		"some-credential-id",
	)
	assertError(t, err)
}

func TestF_Credential_Revoke_ArgMissing(t *testing.T) {
	tc := newTestContext(t)
	resetCredentialFlags()

	_, err := executeCommand(rootCmd, "credential", "revoke",
		"--ca-dir", tc.path("ca"),
		"--cred-dir", tc.path("credentials"),
	)
	assertError(t, err)
}

// =============================================================================
// Credential Export Tests
// =============================================================================

func TestF_Credential_Export_ToStdout(t *testing.T) {
	tc := newTestContext(t)
	caDir, credentialsDir, credID := setupCAWithCredential(tc)

	resetCredentialFlags()
	// Note: Export writes to stdout via fmt.Print, not to Cobra's output buffer.
	// So we just verify the command succeeds without error.
	_, err := executeCommand(rootCmd, "credential", "export",
		"--ca-dir", caDir,
		"--cred-dir", credentialsDir,
		credID,
	)
	assertNoError(t, err)
}

func TestF_Credential_Export_ToFile(t *testing.T) {
	tc := newTestContext(t)
	caDir, credentialsDir, credID := setupCAWithCredential(tc)
	outputPath := tc.path("exported.pem")

	resetCredentialFlags()
	_, err := executeCommand(rootCmd, "credential", "export",
		"--ca-dir", caDir,
		"--cred-dir", credentialsDir,
		"--out", outputPath,
		credID,
	)
	assertNoError(t, err)
	assertFileExists(t, outputPath)
	assertFileNotEmpty(t, outputPath)
}

func TestF_Credential_Export_CredentialNotFound(t *testing.T) {
	tc := newTestContext(t)
	caDir, credentialsDir, _ := setupCAWithCredential(tc)

	resetCredentialFlags()
	output, err := executeCommand(rootCmd, "credential", "export",
		"--ca-dir", caDir,
		"--cred-dir", credentialsDir,
		"nonexistent-credential-id",
	)
	// Export returns empty output for nonexistent credentials (not an error)
	assertNoError(t, err)
	if output != "" {
		t.Error("expected empty output for nonexistent credential")
	}
}

func TestF_Credential_Export_ArgMissing(t *testing.T) {
	tc := newTestContext(t)
	resetCredentialFlags()

	_, err := executeCommand(rootCmd, "credential", "export",
		"--ca-dir", tc.path("ca"),
		"--cred-dir", tc.path("credentials"),
	)
	assertError(t, err)
}

// =============================================================================
// Credential Versions Tests
// =============================================================================

func TestF_Credential_Versions_NotVersioned(t *testing.T) {
	tc := newTestContext(t)
	_, credentialsDir, credID := setupCAWithCredential(tc)

	resetCredentialActivateFlags()
	// Should not error, just indicate no versioning
	_, err := executeCommand(rootCmd, "credential", "versions",
		"--cred-dir", credentialsDir,
		credID,
	)
	assertNoError(t, err)
}

// Note: TestF_Credential_Versions_AfterRotate is skipped because current CLI
// credential rotate creates a new credential instead of versioning.

func TestF_Credential_Versions_CredentialNotFound(t *testing.T) {
	tc := newTestContext(t)
	_, credentialsDir, _ := setupCAWithCredential(tc)

	resetCredentialActivateFlags()
	_, err := executeCommand(rootCmd, "credential", "versions",
		"--cred-dir", credentialsDir,
		"nonexistent-credential-id",
	)
	// Should not error, just indicate not versioned
	assertNoError(t, err)
}

func TestF_Credential_Versions_ArgMissing(t *testing.T) {
	tc := newTestContext(t)
	resetCredentialActivateFlags()

	_, err := executeCommand(rootCmd, "credential", "versions",
		"--cred-dir", tc.path("credentials"),
	)
	assertError(t, err)
}

// =============================================================================
// Credential Activate Tests
// =============================================================================

func TestF_Credential_Activate_NotVersioned(t *testing.T) {
	tc := newTestContext(t)
	_, credentialsDir, credID := setupCAWithCredential(tc)

	resetCredentialActivateFlags()
	_, err := executeCommand(rootCmd, "credential", "activate",
		"--cred-dir", credentialsDir,
		"--version", "v1",
		credID,
	)
	assertError(t, err) // Should error: not versioned
}

// Note: TestF_Credential_Activate_VersionNotFound is skipped because current CLI
// credential rotate creates a new credential instead of versioning.

// Note: TestF_Credential_Activate_Success is skipped because current CLI
// credential rotate creates a new credential instead of versioning.
// Versioning tests require the internal API to be used directly.

// Note: TestF_Credential_Activate_V1_Fails is skipped because current CLI
// credential rotate creates a new credential instead of versioning.

func TestF_Credential_Activate_ArgMissing(t *testing.T) {
	tc := newTestContext(t)
	resetCredentialActivateFlags()

	_, err := executeCommand(rootCmd, "credential", "activate",
		"--cred-dir", tc.path("credentials"),
		"--version", "v2",
	)
	assertError(t, err)
}

func TestF_Credential_Activate_VersionFlagMissing(t *testing.T) {
	tc := newTestContext(t)
	resetCredentialActivateFlags()

	_, err := executeCommand(rootCmd, "credential", "activate",
		"--cred-dir", tc.path("credentials"),
		"some-credential-id",
	)
	assertError(t, err) // --version is required
}

func TestF_Credential_Activate_CredentialNotFound(t *testing.T) {
	tc := newTestContext(t)

	// Create empty credentials directory
	credentialsDir := tc.path("credentials")

	resetCredentialActivateFlags()
	_, err := executeCommand(rootCmd, "credential", "activate",
		"--cred-dir", credentialsDir,
		"--version", "v2",
		"nonexistent-credential",
	)
	assertError(t, err) // Credential not found
}

// =============================================================================
// Credential Export Tests (additional)
// =============================================================================

func TestF_Credential_Export_FormatDER(t *testing.T) {
	tc := newTestContext(t)
	caDir, credentialsDir, credID := setupCAWithCredential(tc)

	outPath := tc.path("export.der")
	resetCredentialFlags()
	_, err := executeCommand(rootCmd, "credential", "export",
		"--ca-dir", caDir,
		"--cred-dir", credentialsDir,
		"--format", "der",
		"--out", outPath,
		credID,
	)
	assertNoError(t, err)
	assertFileExists(t, outPath)
}

func TestF_Credential_Export_InvalidFormat(t *testing.T) {
	tc := newTestContext(t)
	caDir, credentialsDir, credID := setupCAWithCredential(tc)

	resetCredentialFlags()
	_, err := executeCommand(rootCmd, "credential", "export",
		"--ca-dir", caDir,
		"--cred-dir", credentialsDir,
		"--format", "invalid",
		credID,
	)
	assertError(t, err)
}

func TestF_Credential_Export_InvalidBundle(t *testing.T) {
	tc := newTestContext(t)
	caDir, credentialsDir, credID := setupCAWithCredential(tc)

	resetCredentialFlags()
	_, err := executeCommand(rootCmd, "credential", "export",
		"--ca-dir", caDir,
		"--cred-dir", credentialsDir,
		"--bundle", "invalid",
		credID,
	)
	assertError(t, err)
}

func TestF_Credential_Export_BundleChain(t *testing.T) {
	tc := newTestContext(t)
	caDir, credentialsDir, credID := setupCAWithCredential(tc)

	outPath := tc.path("chain.pem")
	resetCredentialFlags()
	_, err := executeCommand(rootCmd, "credential", "export",
		"--ca-dir", caDir,
		"--cred-dir", credentialsDir,
		"--bundle", "chain",
		"--out", outPath,
		credID,
	)
	assertNoError(t, err)
	assertFileExists(t, outPath)
}

func TestF_Credential_Export_DER_RequiresOut(t *testing.T) {
	tc := newTestContext(t)
	caDir, credentialsDir, credID := setupCAWithCredential(tc)

	resetCredentialFlags()
	_, err := executeCommand(rootCmd, "credential", "export",
		"--ca-dir", caDir,
		"--cred-dir", credentialsDir,
		"--format", "der",
		credID,
	)
	assertError(t, err) // DER requires --out
}

// =============================================================================
// Crypto-Agility Integration Tests
// =============================================================================

func TestA_Credential_Export_Chain_HybridCA(t *testing.T) {
	tc := newTestContext(t)
	caDir := tc.path("ca")
	credentialsDir := tc.path("credentials")

	// Initialize hybrid CA with ECDSA + ML-DSA (crypto-agility)
	resetCAFlags()
	_, err := executeCommand(rootCmd, "ca", "init",
		"--ca-dir", caDir,
		"--profile", "ec/root-ca",
		"--profile", "ml/root-ca",
		"--var", "cn=Hybrid Test CA",
	)
	if err != nil {
		t.Fatalf("failed to init hybrid CA: %v", err)
	}

	// Note: v1 is already active after InitializeMultiProfile (CreateInitialVersion sets Active="v1")

	// Enroll credential
	resetCredentialFlags()
	_, err = executeCommand(rootCmd, "credential", "enroll",
		"--ca-dir", caDir,
		"--cred-dir", credentialsDir,
		"--profile", "ec/tls-server",
		"--var", "cn=test.local",
		"--var", "dns_names=test.local",
	)
	if err != nil {
		t.Fatalf("failed to enroll credential: %v", err)
	}

	// Find credential ID from credentials directory (more reliable than parsing output)
	entries, err := os.ReadDir(credentialsDir)
	if err != nil || len(entries) == 0 {
		t.Fatal("no credentials found in directory")
	}
	credID := entries[0].Name()

	// Export with bundle=chain
	outPath := tc.path("chain.pem")
	resetCredentialFlags()
	_, err = executeCommand(rootCmd, "credential", "export",
		"--ca-dir", caDir,
		"--cred-dir", credentialsDir,
		"--bundle", "chain",
		"--out", outPath,
		credID,
	)
	assertNoError(t, err)
	assertFileExists(t, outPath)

	// Verify the output contains multiple certificates (credential cert + CA certs)
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	certCount := strings.Count(string(data), "-----BEGIN CERTIFICATE-----")
	// Should have at least: 1 credential cert + 2 CA certs (ECDSA + ML-DSA) = 3
	if certCount < 3 {
		t.Errorf("Expected at least 3 certificates in chain, got %d", certCount)
	}
}
