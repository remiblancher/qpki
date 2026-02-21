package main

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/remiblancher/qpki/pkg/ca"
	"github.com/remiblancher/qpki/pkg/profile"
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

// =============================================================================
// Unit Tests for credential_helpers.go
// =============================================================================

func TestU_FormatRotateKeyInfo(t *testing.T) {
	tests := []struct {
		name       string
		keepKeys   bool
		hsmEnabled bool
		expected   string
	}{
		{
			name:       "keep existing keys",
			keepKeys:   true,
			hsmEnabled: false,
			expected:   "existing keys",
		},
		{
			name:       "keep existing keys with HSM",
			keepKeys:   true,
			hsmEnabled: true,
			expected:   "existing keys", // keepKeys takes precedence
		},
		{
			name:       "new keys without HSM",
			keepKeys:   false,
			hsmEnabled: false,
			expected:   "new keys",
		},
		{
			name:       "new keys with HSM",
			keepKeys:   false,
			hsmEnabled: true,
			expected:   "new keys (HSM)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatRotateKeyInfo(tt.keepKeys, tt.hsmEnabled)
			if result != tt.expected {
				t.Errorf("formatRotateKeyInfo(%v, %v) = %q, want %q",
					tt.keepKeys, tt.hsmEnabled, result, tt.expected)
			}
		})
	}
}

func TestU_LoadEnrollProfiles_ByName(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create CA with profiles
	caDir := tc.path("ca")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
		"--var", "cn=Test CA",
	)
	assertNoError(t, err)

	// Load profile by name
	profiles, err := loadEnrollProfiles(caDir, []string{"ec/tls-server"})
	if err != nil {
		t.Fatalf("loadEnrollProfiles failed: %v", err)
	}

	if len(profiles) != 1 {
		t.Fatalf("expected 1 profile, got %d", len(profiles))
	}

	if profiles[0].Name != "ec/tls-server" {
		t.Errorf("expected profile name 'ec/tls-server', got %q", profiles[0].Name)
	}
}

func TestU_LoadEnrollProfiles_NotFound(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create CA with profiles
	caDir := tc.path("ca")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
		"--var", "cn=Test CA",
	)
	assertNoError(t, err)

	// Try to load non-existent profile
	_, err = loadEnrollProfiles(caDir, []string{"nonexistent-profile"})
	if err == nil {
		t.Error("expected error for non-existent profile")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should contain 'not found', got: %v", err)
	}
}

func TestU_LoadEnrollProfiles_InvalidCADir(t *testing.T) {
	tc := newTestContext(t)

	// Try to load profile from non-existent CA directory
	// Built-in profiles like "ec/tls-server" are always available,
	// so we test with a truly non-existent profile name
	_, err := loadEnrollProfiles(tc.path("nonexistent"), []string{"totally-fake-profile-xyz"})
	if err == nil {
		t.Fatal("expected error when profile not found")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' error, got: %v", err)
	}
}

func TestU_LoadEnrollProfiles_Multiple(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create CA with profiles
	caDir := tc.path("ca")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
		"--var", "cn=Test CA",
	)
	assertNoError(t, err)

	// Load multiple profiles
	profiles, err := loadEnrollProfiles(caDir, []string{"ec/tls-server", "ec/tls-client"})
	if err != nil {
		t.Fatalf("loadEnrollProfiles failed: %v", err)
	}

	if len(profiles) != 2 {
		t.Fatalf("expected 2 profiles, got %d", len(profiles))
	}
}

func TestU_ConfigureHSMKeyProvider_EmptyPath(t *testing.T) {
	// Empty HSM config path should be a no-op
	err := configureHSMKeyProvider(nil, "", "")
	if err != nil {
		t.Errorf("configureHSMKeyProvider with empty path should return nil, got: %v", err)
	}
}

func TestU_ConfigureHSMKeyProvider_InvalidPath(t *testing.T) {
	tc := newTestContext(t)

	// Non-existent HSM config should error
	err := configureHSMKeyProvider(nil, tc.path("nonexistent.yaml"), "key-label")
	if err == nil {
		t.Error("expected error for non-existent HSM config")
	}
	if !strings.Contains(err.Error(), "failed to load HSM config") {
		t.Errorf("error should mention HSM config loading, got: %v", err)
	}
}

func TestU_ResolveProfilesToObjects_Found(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create CA with profiles
	caDir := tc.path("ca")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
		"--var", "cn=Test CA",
	)
	assertNoError(t, err)

	// Load the profile store
	profileStore := profile.NewProfileStore(caDir)
	if err := profileStore.Load(); err != nil {
		t.Fatalf("failed to load profile store: %v", err)
	}

	// Resolve profiles
	profiles, err := resolveProfilesToObjects(profileStore, []string{"ec/tls-server"})
	if err != nil {
		t.Fatalf("resolveProfilesToObjects failed: %v", err)
	}

	if len(profiles) != 1 {
		t.Errorf("expected 1 profile, got %d", len(profiles))
	}
}

func TestU_ResolveProfilesToObjects_NotFound(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create CA with profiles
	caDir := tc.path("ca")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
		"--var", "cn=Test CA",
	)
	assertNoError(t, err)

	// Load the profile store
	profileStore := profile.NewProfileStore(caDir)
	if err := profileStore.Load(); err != nil {
		t.Fatalf("failed to load profile store: %v", err)
	}

	// Try to resolve non-existent profile
	_, err = resolveProfilesToObjects(profileStore, []string{"nonexistent-profile"})
	if err == nil {
		t.Error("expected error for non-existent profile")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should contain 'not found', got: %v", err)
	}
}

func TestU_ValidateEnrollVariables_EmptyProfiles(t *testing.T) {
	varValues := profile.VariableValues{"cn": "test"}

	// Empty profiles should return varValues unchanged
	result, err := validateEnrollVariables([]*profile.Profile{}, varValues)
	if err != nil {
		t.Fatalf("validateEnrollVariables failed: %v", err)
	}

	if result["cn"] != "test" {
		t.Errorf("expected cn=test, got %v", result["cn"])
	}
}

func TestU_ValidateEnrollVariables_NilProfiles(t *testing.T) {
	varValues := profile.VariableValues{"cn": "test"}

	// Nil profiles should return varValues unchanged
	result, err := validateEnrollVariables(nil, varValues)
	if err != nil {
		t.Fatalf("validateEnrollVariables failed: %v", err)
	}

	if result["cn"] != "test" {
		t.Errorf("expected cn=test, got %v", result["cn"])
	}
}

func TestU_ValidateEnrollVariables_WithProfile(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create CA to get real profiles
	caDir := tc.path("ca")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
		"--var", "cn=Test CA",
	)
	assertNoError(t, err)

	// Load profiles
	profiles, err := loadEnrollProfiles(caDir, []string{"ec/tls-server"})
	if err != nil {
		t.Fatalf("loadEnrollProfiles failed: %v", err)
	}

	varValues := profile.VariableValues{
		"cn":        "test.local",
		"dns_names": []string{"test.local"},
	}

	// Validate variables
	result, err := validateEnrollVariables(profiles, varValues)
	if err != nil {
		t.Fatalf("validateEnrollVariables failed: %v", err)
	}

	// Result should contain the resolved values
	if result == nil {
		t.Error("expected non-nil result")
	}
}

func TestU_ResolveProfilesTemplates_NoTemplates(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create CA to get real profiles
	caDir := tc.path("ca")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
		"--var", "cn=Test CA",
	)
	assertNoError(t, err)

	// Load profiles
	profiles, err := loadEnrollProfiles(caDir, []string{"ec/tls-server"})
	if err != nil {
		t.Fatalf("loadEnrollProfiles failed: %v", err)
	}

	varValues := profile.VariableValues{
		"cn":        "test.local",
		"dns_names": []string{"test.local"},
	}

	// Resolve templates
	result, err := resolveProfilesTemplates(profiles, varValues)
	if err != nil {
		t.Fatalf("resolveProfilesTemplates failed: %v", err)
	}

	if len(result) != len(profiles) {
		t.Errorf("expected %d profiles, got %d", len(profiles), len(result))
	}
}

func TestU_ResolveProfilesTemplates_EmptyProfiles(t *testing.T) {
	varValues := profile.VariableValues{"cn": "test"}

	// Empty profiles should return empty slice
	result, err := resolveProfilesTemplates([]*profile.Profile{}, varValues)
	if err != nil {
		t.Fatalf("resolveProfilesTemplates failed: %v", err)
	}

	if len(result) != 0 {
		t.Errorf("expected 0 profiles, got %d", len(result))
	}
}

func TestU_LoadEnrollProfiles_ByFilePath(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create CA to get embedded profiles copied to disk
	caDir := tc.path("ca")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
		"--var", "cn=Test CA",
	)
	assertNoError(t, err)

	// Create a custom profile file with proper format
	customProfile := `name: custom-test-profile
description: "Test profile"
algorithm: ecdsa-p256
validity: 365d
variables:
  cn:
    type: string
    required: true
subject:
  cn: "{{ cn }}"
extensions:
  basicConstraints:
    critical: true
    ca: false
  keyUsage:
    critical: true
    values:
      - digitalSignature
`
	profilePath := tc.path("custom.yaml")
	if err := os.WriteFile(profilePath, []byte(customProfile), 0644); err != nil {
		t.Fatalf("failed to write profile file: %v", err)
	}

	// Load profile by file path
	profiles, err := loadEnrollProfiles(caDir, []string{profilePath})
	if err != nil {
		t.Fatalf("loadEnrollProfiles by path failed: %v", err)
	}

	if len(profiles) != 1 {
		t.Fatalf("expected 1 profile, got %d", len(profiles))
	}

	if profiles[0].Name != "custom-test-profile" {
		t.Errorf("expected profile name 'custom-test-profile', got %q", profiles[0].Name)
	}
}

func TestU_LoadEnrollProfiles_InvalidFilePath(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create CA
	caDir := tc.path("ca")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
		"--var", "cn=Test CA",
	)
	assertNoError(t, err)

	// Try to load from non-existent file path
	_, err = loadEnrollProfiles(caDir, []string{"/nonexistent/path.yaml"})
	if err == nil {
		t.Fatal("expected error for non-existent file path")
	}
	if !strings.Contains(err.Error(), "failed to load profile") {
		t.Errorf("expected 'failed to load profile' error, got: %v", err)
	}
}

func TestU_PrepareEnrollVariablesAndProfiles(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create CA
	caDir := tc.path("ca")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
		"--var", "cn=Test CA",
	)
	assertNoError(t, err)

	// Prepare enrollment with basic variables
	profiles, subject, err := prepareEnrollVariablesAndProfiles(
		caDir,
		[]string{"ec/tls-server"},
		"", // no var file
		[]string{"cn=test.example.com", "dns_names=test.example.com"},
	)

	if err != nil {
		t.Fatalf("prepareEnrollVariablesAndProfiles failed: %v", err)
	}

	if len(profiles) != 1 {
		t.Errorf("expected 1 profile, got %d", len(profiles))
	}

	if subject.CommonName != "test.example.com" {
		t.Errorf("expected subject CN 'test.example.com', got %q", subject.CommonName)
	}
}

func TestU_PrepareEnrollVariablesAndProfiles_InvalidProfile(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create CA
	caDir := tc.path("ca")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
		"--var", "cn=Test CA",
	)
	assertNoError(t, err)

	// Try to prepare with non-existent profile
	_, _, err = prepareEnrollVariablesAndProfiles(
		caDir,
		[]string{"nonexistent-profile"},
		"",
		[]string{"cn=test"},
	)

	if err == nil {
		t.Fatal("expected error for non-existent profile")
	}
}

func TestU_PrepareEnrollVariablesAndProfiles_InvalidSubject(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create CA
	caDir := tc.path("ca")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
		"--var", "cn=Test CA",
	)
	assertNoError(t, err)

	// Try to prepare without required CN variable (should fail)
	_, _, err = prepareEnrollVariablesAndProfiles(
		caDir,
		[]string{"ec/tls-server"},
		"",
		[]string{}, // no variables
	)

	if err == nil {
		t.Fatal("expected error for missing CN")
	}
}

// =============================================================================
// computeProfileSet Tests
// =============================================================================

func TestU_ComputeProfileSet_NoChanges(t *testing.T) {
	current := []string{"ec/tls-server", "ml/tls-server"}
	result := computeProfileSet(current, nil, nil)

	if len(result) != 2 {
		t.Errorf("expected 2 profiles, got %d", len(result))
	}
	if result[0] != "ec/tls-server" || result[1] != "ml/tls-server" {
		t.Errorf("unexpected profiles: %v", result)
	}
}

func TestU_ComputeProfileSet_AddOnly(t *testing.T) {
	current := []string{"ec/tls-server"}
	add := []string{"ml/tls-server"}
	result := computeProfileSet(current, add, nil)

	if len(result) != 2 {
		t.Errorf("expected 2 profiles, got %d", len(result))
	}
	if result[0] != "ec/tls-server" || result[1] != "ml/tls-server" {
		t.Errorf("unexpected profiles: %v", result)
	}
}

func TestU_ComputeProfileSet_RemoveOnly(t *testing.T) {
	current := []string{"ec/tls-server", "ml/tls-server"}
	remove := []string{"ec/tls-server"}
	result := computeProfileSet(current, nil, remove)

	if len(result) != 1 {
		t.Errorf("expected 1 profile, got %d", len(result))
	}
	if result[0] != "ml/tls-server" {
		t.Errorf("expected 'ml/tls-server', got %q", result[0])
	}
}

func TestU_ComputeProfileSet_AddAndRemove(t *testing.T) {
	current := []string{"ec/tls-server", "rsa/tls-server"}
	add := []string{"ml/tls-server"}
	remove := []string{"rsa/tls-server"}
	result := computeProfileSet(current, add, remove)

	if len(result) != 2 {
		t.Errorf("expected 2 profiles, got %d", len(result))
	}
	if result[0] != "ec/tls-server" || result[1] != "ml/tls-server" {
		t.Errorf("unexpected profiles: %v", result)
	}
}

func TestU_ComputeProfileSet_RemoveAll(t *testing.T) {
	current := []string{"ec/tls-server"}
	remove := []string{"ec/tls-server"}
	result := computeProfileSet(current, nil, remove)

	if len(result) != 0 {
		t.Errorf("expected 0 profiles, got %d", len(result))
	}
}

func TestU_ComputeProfileSet_AddDuplicate(t *testing.T) {
	current := []string{"ec/tls-server"}
	add := []string{"ec/tls-server", "ml/tls-server"}
	result := computeProfileSet(current, add, nil)

	// Should not have duplicates
	if len(result) != 2 {
		t.Errorf("expected 2 profiles (no duplicates), got %d", len(result))
	}
}

// =============================================================================
// parseRevocationReason Tests
// =============================================================================

func TestU_ParseRevocationReason(t *testing.T) {
	tests := []struct {
		input    string
		expected ca.RevocationReason
	}{
		{"keyCompromise", ca.ReasonKeyCompromise},
		{"caCompromise", ca.ReasonCACompromise},
		{"affiliationChanged", ca.ReasonAffiliationChanged},
		{"superseded", ca.ReasonSuperseded},
		{"cessationOfOperation", ca.ReasonCessationOfOperation},
		{"certificateHold", ca.ReasonCertificateHold},
		{"removeFromCRL", ca.ReasonRemoveFromCRL},
		{"privilegeWithdrawn", ca.ReasonPrivilegeWithdrawn},
		{"aaCompromise", ca.ReasonAACompromise},
		{"unspecified", ca.ReasonUnspecified},
		{"unknown", ca.ReasonUnspecified},
		{"", ca.ReasonUnspecified},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := parseRevocationReason(tt.input)
			if result != tt.expected {
				t.Errorf("parseRevocationReason(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

// =============================================================================
// credential_export_helpers.go Unit Tests
// =============================================================================

func TestU_ValidateExportFlags(t *testing.T) {
	tests := []struct {
		name    string
		format  string
		bundle  string
		wantErr bool
	}{
		{"valid pem cert", "pem", "cert", false},
		{"valid pem chain", "pem", "chain", false},
		{"valid pem all", "pem", "all", false},
		{"valid der cert", "der", "cert", false},
		{"valid der chain", "der", "chain", false},
		{"invalid format", "invalid", "cert", true},
		{"invalid bundle", "pem", "invalid", true},
		{"both invalid", "invalid", "invalid", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateExportFlags(tt.format, tt.bundle)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateExportFlags(%q, %q) error = %v, wantErr %v",
					tt.format, tt.bundle, err, tt.wantErr)
			}
		})
	}
}

func TestU_EncodeExportCerts_PEM(t *testing.T) {
	tc := newTestContext(t)
	priv, pub := generateECDSAKeyPair(t)
	cert := generateSelfSignedCert(t, priv, pub)
	_ = tc // for cleanup

	// Single cert PEM
	data, err := encodeExportCerts([]*x509.Certificate{cert}, "pem")
	if err != nil {
		t.Fatalf("encodeExportCerts (PEM single) failed: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty PEM data")
	}
	if !strings.Contains(string(data), "BEGIN CERTIFICATE") {
		t.Error("PEM output should contain 'BEGIN CERTIFICATE'")
	}

	// Multiple certs PEM
	data, err = encodeExportCerts([]*x509.Certificate{cert, cert}, "pem")
	if err != nil {
		t.Fatalf("encodeExportCerts (PEM multiple) failed: %v", err)
	}
	certCount := strings.Count(string(data), "BEGIN CERTIFICATE")
	if certCount != 2 {
		t.Errorf("expected 2 certificates in PEM, got %d", certCount)
	}
}

func TestU_EncodeExportCerts_DER_Single(t *testing.T) {
	tc := newTestContext(t)
	priv, pub := generateECDSAKeyPair(t)
	cert := generateSelfSignedCert(t, priv, pub)
	_ = tc // for cleanup

	data, err := encodeExportCerts([]*x509.Certificate{cert}, "der")
	if err != nil {
		t.Fatalf("encodeExportCerts (DER single) failed: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty DER data")
	}
	// DER should equal raw certificate bytes
	if string(data) != string(cert.Raw) {
		t.Error("DER output should equal cert.Raw")
	}
}

func TestU_EncodeExportCerts_DER_Multiple(t *testing.T) {
	tc := newTestContext(t)
	priv, pub := generateECDSAKeyPair(t)
	cert := generateSelfSignedCert(t, priv, pub)
	_ = tc // for cleanup

	// Multiple certs DER should fail
	_, err := encodeExportCerts([]*x509.Certificate{cert, cert}, "der")
	if err == nil {
		t.Error("expected error for multiple certs in DER format")
	}
	if !strings.Contains(err.Error(), "only supports single certificate") {
		t.Errorf("expected 'only supports single certificate' error, got: %v", err)
	}
}

func TestU_EncodeExportCerts_Empty(t *testing.T) {
	// Empty certs list
	data, err := encodeExportCerts([]*x509.Certificate{}, "pem")
	if err != nil {
		t.Fatalf("encodeExportCerts (empty PEM) failed: %v", err)
	}
	if len(data) != 0 {
		t.Errorf("expected empty data for empty certs, got %d bytes", len(data))
	}
}

func TestU_WriteCredExportOutput_Stdout(t *testing.T) {
	// Writing to stdout (empty path) with PEM should succeed
	data := []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n")
	err := writeCredExportOutput(data, "", "pem")
	if err != nil {
		t.Errorf("writeCredExportOutput to stdout failed: %v", err)
	}
}

func TestU_WriteCredExportOutput_StdoutDER_Fails(t *testing.T) {
	// Writing DER to stdout should fail
	data := []byte{0x30, 0x82, 0x01, 0x00} // Some DER bytes
	err := writeCredExportOutput(data, "", "der")
	if err == nil {
		t.Error("expected error for DER output to stdout")
	}
	if !strings.Contains(err.Error(), "DER format requires --out") {
		t.Errorf("expected 'DER format requires --out' error, got: %v", err)
	}
}

func TestU_WriteCredExportOutput_ToFile(t *testing.T) {
	tc := newTestContext(t)

	outPath := tc.path("export.pem")
	data := []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n")

	err := writeCredExportOutput(data, outPath, "pem")
	if err != nil {
		t.Fatalf("writeCredExportOutput to file failed: %v", err)
	}

	assertFileExists(t, outPath)
	content, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}
	if string(content) != string(data) {
		t.Error("written content doesn't match expected")
	}
}

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
