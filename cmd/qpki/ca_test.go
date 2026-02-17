package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/remiblancher/post-quantum-pki/pkg/ca"
)

// resetCAFlags resets all CA command flags to their default values.
func resetCAFlags() {
	caInitDir = "./ca"
	caInitVars = nil
	caInitVarFile = ""
	caInitValidityYears = 10
	caInitPathLen = 1
	caInitPassphrase = ""
	caInitParentDir = ""
	caInitParentPassphrase = ""
	caInitProfiles = nil

	caInfoDir = "./ca"

	crlGenCADir = "./ca"
	crlGenDays = 7
	crlGenPassphrase = ""

	caExportDir = "./ca"
	caExportBundle = "ca"
	caExportOut = ""
	caExportFormat = "pem"
	caExportVersion = ""
	caExportAll = false

	caListDir = "."

	// Rotate flags
	caRotateDir = "./ca"
	caRotateProfiles = nil
	caRotatePassphrase = ""
	caRotateCrossSign = false
	caRotateDryRun = false

	// Activate flags
	caActivateDir = "./ca"
	caActivateVersion = ""

	// Versions flags
	caVersionsDir = "./ca"
}

// =============================================================================
// CA Init Tests (Table-Driven)
// =============================================================================

func TestF_CA_Init(t *testing.T) {
	tests := []struct {
		name    string
		profile string
		algoID  string // Full algorithm ID for versioned paths (ecdsa-p384, ml-dsa-87, etc.)
		wantErr bool
	}{
		{"[Functional] CA Init: EC Root CA", "ec/root-ca", "ecdsa-p384", false},
		{"[Functional] CA Init: EC Issuing CA Profile", "ec/issuing-ca", "ecdsa-p256", false},
		{"[Functional] CA Init: ML-DSA Root CA", "ml/root-ca", "ml-dsa-87", false},
		{"[Functional] CA Init: ProfileInvalid", "nonexistent/profile", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := newTestContext(t)
			resetCAFlags()

			caDir := tc.path("ca")

			args := []string{"ca", "init",
				"--var", "cn=Test CA",
				"--profile", tt.profile,
				"--ca-dir", caDir,
			}

			_, err := executeCommand(rootCmd, args...)

			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Check new versioned structure
				assertFileExists(t, filepath.Join(caDir, "ca.meta.json"))
				assertFileExists(t, filepath.Join(caDir, "versions", "v1", "certs", "ca."+tt.algoID+".pem"))
				assertFileExists(t, filepath.Join(caDir, "versions", "v1", "keys", "ca."+tt.algoID+".key"))
			}
		})
	}
}

func TestF_CA_Init_WithPassphrase(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	caDir := tc.path("ca")

	_, err := executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Encrypted CA",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
		"--passphrase", "secret123",
	)

	assertNoError(t, err)
	// Check new versioned structure (ec/root-ca uses ecdsa-p384)
	assertFileExists(t, filepath.Join(caDir, "ca.meta.json"))
	assertFileExists(t, filepath.Join(caDir, "versions", "v1", "certs", "ca.ecdsa-p384.pem"))
	assertFileExists(t, filepath.Join(caDir, "versions", "v1", "keys", "ca.ecdsa-p384.key"))
}

func TestF_CA_Init_ProfileMissing(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	_, err := executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Test CA",
		"--ca-dir", tc.path("ca"),
	)

	assertError(t, err)
}

func TestF_CA_Init_AlreadyExists(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	caDir := tc.path("ca")

	// Create first CA
	_, err := executeCommand(rootCmd, "ca", "init",
		"--var", "cn=First CA",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
	)
	assertNoError(t, err)

	resetCAFlags()

	// Try to create second CA in same location
	_, err = executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Second CA",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
	)

	assertError(t, err)
}

// =============================================================================
// CA Init Subordinate Tests
// =============================================================================

func TestF_CA_Init_Subordinate(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	rootDir := tc.path("root-ca")
	subDir := tc.path("sub-ca")

	// Create root CA
	_, err := executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Root CA",
		"--profile", "ec/root-ca",
		"--ca-dir", rootDir,
	)
	assertNoError(t, err)

	resetCAFlags()

	// Create subordinate CA
	_, err = executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Issuing CA",
		"--profile", "ec/issuing-ca",
		"--ca-dir", subDir,
		"--parent", rootDir,
	)

	assertNoError(t, err)
	// Check new versioned structure (ec/issuing-ca uses ecdsa-p256)
	assertFileExists(t, filepath.Join(subDir, "ca.meta.json"))
	assertFileExists(t, filepath.Join(subDir, "versions", "v1", "certs", "ca.ecdsa-p256.pem"))
	assertFileExists(t, filepath.Join(subDir, "versions", "v1", "keys", "ca.ecdsa-p256.key"))
	assertFileExists(t, filepath.Join(subDir, "chain.crt"))
}

func TestF_CA_Init_Subordinate_ParentNotFound(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	_, err := executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Issuing CA",
		"--profile", "ec/issuing-ca",
		"--ca-dir", tc.path("sub-ca"),
		"--parent", tc.path("nonexistent"),
	)

	assertError(t, err)
}

// =============================================================================
// CA Info Tests
// =============================================================================

func TestF_CA_Info(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	caDir := tc.path("ca")

	// Create CA first
	_, err := executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Test CA",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
	)
	assertNoError(t, err)

	resetCAFlags()

	// Get info
	_, err = executeCommand(rootCmd, "ca", "info", "--ca-dir", caDir)

	assertNoError(t, err)
}

func TestF_CA_Info_NotFound(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	_, err := executeCommand(rootCmd, "ca", "info", "--ca-dir", tc.path("nonexistent"))

	assertError(t, err)
}

// =============================================================================
// CRL Gen Tests
// =============================================================================

func TestF_CRL_Gen(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	caDir := tc.path("ca")

	// Create CA
	_, err := executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Test CA",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
	)
	assertNoError(t, err)

	resetCAFlags()

	// Generate CRL
	_, err = executeCommand(rootCmd, "crl", "gen", "--ca-dir", caDir)

	assertNoError(t, err)
	assertFileExists(t, filepath.Join(caDir, "crl", "ca.crl"))
}

func TestF_CRL_Gen_CustomDays(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	caDir := tc.path("ca")

	// Create CA
	_, err := executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Test CA",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
	)
	assertNoError(t, err)

	resetCAFlags()

	// Generate CRL with custom validity
	_, err = executeCommand(rootCmd, "crl", "gen",
		"--ca-dir", caDir,
		"--days", "30",
	)

	assertNoError(t, err)
}

func TestF_CRL_Gen_CANotFound(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	_, err := executeCommand(rootCmd, "crl", "gen", "--ca-dir", tc.path("nonexistent"))

	assertError(t, err)
}

// =============================================================================
// CA Export Tests
// =============================================================================

func TestF_CA_Export(t *testing.T) {
	tests := []struct {
		name   string
		bundle string
	}{
		{"[Functional] CA Export: CA Cert", "ca"},
		{"[Functional] CA Export: Chain", "chain"},
		{"[Functional] CA Export: Root", "root"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := newTestContext(t)
			resetCAFlags()

			caDir := tc.path("ca")

			// Create CA
			_, err := executeCommand(rootCmd, "ca", "init",
				"--var", "cn=Test CA",
				"--profile", "ec/root-ca",
				"--ca-dir", caDir,
			)
			assertNoError(t, err)

			resetCAFlags()

			// Export
			outPath := tc.path("exported.pem")
			_, err = executeCommand(rootCmd, "ca", "export",
				"--ca-dir", caDir,
				"--bundle", tt.bundle,
				"--out", outPath,
			)

			assertNoError(t, err)
			assertFileExists(t, outPath)
			assertFileNotEmpty(t, outPath)
		})
	}
}

func TestF_CA_Export_DER(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	caDir := tc.path("ca")

	// Create CA
	_, err := executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Test CA",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
	)
	assertNoError(t, err)

	resetCAFlags()

	// Export as DER
	outPath := tc.path("ca.der")
	_, err = executeCommand(rootCmd, "ca", "export",
		"--ca-dir", caDir,
		"--format", "der",
		"--out", outPath,
	)

	assertNoError(t, err)
	assertFileExists(t, outPath)
}

func TestF_CA_Export_BundleInvalid(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	caDir := tc.path("ca")

	// Create CA
	_, _ = executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Test CA",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
	)

	resetCAFlags()

	_, err := executeCommand(rootCmd, "ca", "export",
		"--ca-dir", caDir,
		"--bundle", "invalid",
	)

	assertError(t, err)
}

func TestF_CA_Export_CANotFound(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	_, err := executeCommand(rootCmd, "ca", "export",
		"--ca-dir", tc.path("nonexistent"),
	)

	assertError(t, err)
}

func TestF_CA_Export_ToStdout(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	caDir := tc.path("ca")

	// Create CA
	_, err := executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Test CA",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
	)
	assertNoError(t, err)

	resetCAFlags()

	// Export to stdout (no --out flag)
	_, err = executeCommand(rootCmd, "ca", "export",
		"--ca-dir", caDir,
	)

	assertNoError(t, err)
}

func TestF_CA_Export_AllVersions(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	caDir := tc.path("ca")

	// Create CA
	_, err := executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Test CA",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
	)
	assertNoError(t, err)

	resetCAFlags()

	// Rotate to create a version
	_, err = executeCommand(rootCmd, "ca", "rotate",
		"--ca-dir", caDir,
		"--profile", "ec/root-ca",
	)
	assertNoError(t, err)

	resetCAFlags()

	// Export all versions
	outPath := tc.path("all.pem")
	_, err = executeCommand(rootCmd, "ca", "export",
		"--ca-dir", caDir,
		"--all",
		"--out", outPath,
	)

	assertNoError(t, err)
	assertFileExists(t, outPath)
}

func TestF_CA_Export_AllVersions_NonVersioned(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	caDir := tc.path("ca")

	// Create CA (no rotation = non-versioned)
	_, err := executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Test CA",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
	)
	assertNoError(t, err)

	resetCAFlags()

	// Export with --all on non-versioned CA
	outPath := tc.path("all.pem")
	_, err = executeCommand(rootCmd, "ca", "export",
		"--ca-dir", caDir,
		"--all",
		"--out", outPath,
	)

	assertNoError(t, err)
	assertFileExists(t, outPath)
}

func TestF_CA_Export_Version(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	caDir := tc.path("ca")

	// Create CA
	_, err := executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Test CA",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
	)
	assertNoError(t, err)

	resetCAFlags()

	// Rotate to create a version
	_, err = executeCommand(rootCmd, "ca", "rotate",
		"--ca-dir", caDir,
		"--profile", "ec/root-ca",
	)
	assertNoError(t, err)

	resetCAFlags()

	// Export v1 (original)
	outPath := tc.path("v1.pem")
	_, err = executeCommand(rootCmd, "ca", "export",
		"--ca-dir", caDir,
		"--version", "v1",
		"--out", outPath,
	)

	assertNoError(t, err)
	assertFileExists(t, outPath)
}

func TestF_CA_Export_Version_V2(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	caDir := tc.path("ca")

	// Create CA
	_, err := executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Test CA",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
	)
	assertNoError(t, err)

	resetCAFlags()

	// Rotate to create a version
	_, err = executeCommand(rootCmd, "ca", "rotate",
		"--ca-dir", caDir,
		"--profile", "ec/root-ca",
	)
	assertNoError(t, err)

	resetCAFlags()

	// Get the pending version ID from VersionStore
	vs := ca.NewVersionStore(caDir)
	versions, err := vs.ListVersions()
	assertNoError(t, err)

	// Find the pending version (should be the second one after rotate)
	var pendingVersionID string
	for _, v := range versions {
		if v.Status == ca.VersionStatusPending {
			pendingVersionID = v.ID
			break
		}
	}
	if pendingVersionID == "" {
		t.Fatal("expected a pending version after rotate")
	}

	// Export the pending version
	outPath := tc.path("v2.pem")
	_, err = executeCommand(rootCmd, "ca", "export",
		"--ca-dir", caDir,
		"--version", pendingVersionID,
		"--out", outPath,
	)

	assertNoError(t, err)
	assertFileExists(t, outPath)
}

func TestF_CA_Export_Version_NonVersioned(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	caDir := tc.path("ca")

	// Create CA (no rotation = non-versioned)
	_, err := executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Test CA",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
	)
	assertNoError(t, err)

	resetCAFlags()

	// Try to export with --version on non-versioned CA
	_, err = executeCommand(rootCmd, "ca", "export",
		"--ca-dir", caDir,
		"--version", "v2",
	)

	assertError(t, err) // CA is not versioned
}

func TestF_CA_Export_VersionNotFound(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	caDir := tc.path("ca")

	// Create CA
	_, err := executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Test CA",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
	)
	assertNoError(t, err)

	resetCAFlags()

	// Rotate to create a version
	_, err = executeCommand(rootCmd, "ca", "rotate",
		"--ca-dir", caDir,
		"--profile", "ec/root-ca",
	)
	assertNoError(t, err)

	resetCAFlags()

	// Try to export non-existent version
	_, err = executeCommand(rootCmd, "ca", "export",
		"--ca-dir", caDir,
		"--version", "v99",
	)

	assertError(t, err)
}

func TestF_CA_Export_DER_MultiCert(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	caDir := tc.path("ca")

	// Create CA with multiple profiles (multi-profile creates multiple certs in v1)
	_, err := executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Test CA",
		"--profile", "ec/root-ca",
		"--profile", "rsa/root-ca",
		"--ca-dir", caDir,
	)
	assertNoError(t, err)

	resetCAFlags()

	// Try to export all in DER format (should fail - DER only supports single cert)
	_, err = executeCommand(rootCmd, "ca", "export",
		"--ca-dir", caDir,
		"--all",
		"--format", "der",
		"--out", tc.path("all.der"),
	)

	assertError(t, err)
}

// =============================================================================
// CA List Tests
// =============================================================================

func TestF_CA_List(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create a CA in a subdirectory
	caDir := tc.path("my-ca")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Test CA",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
	)
	assertNoError(t, err)

	resetCAFlags()

	// List CAs
	_, err = executeCommand(rootCmd, "ca", "list", "--dir", tc.tempDir)

	assertNoError(t, err)
}

func TestF_CA_List_EmptyDirectory(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// List CAs in empty directory
	_, err := executeCommand(rootCmd, "ca", "list", "--dir", tc.tempDir)

	assertNoError(t, err)
}

func TestF_CA_List_DirectoryInvalid(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	_, err := executeCommand(rootCmd, "ca", "list", "--dir", tc.path("nonexistent"))

	assertError(t, err)
}

// =============================================================================
// CA Rotate Tests
// =============================================================================

func TestF_CA_Rotate_DryRun(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	caDir := tc.path("ca")

	// Create CA
	_, err := executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Test CA",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
	)
	assertNoError(t, err)

	resetCAFlags()

	// Dry-run rotation (profile required since metadata doesn't store it)
	_, err = executeCommand(rootCmd, "ca", "rotate",
		"--ca-dir", caDir,
		"--profile", "ec/root-ca",
		"--dry-run",
	)

	assertNoError(t, err)
}

func TestF_CA_Rotate_WithProfile(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	caDir := tc.path("ca")

	// Create CA
	_, err := executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Test CA",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
	)
	assertNoError(t, err)

	resetCAFlags()

	// Rotate with new profile (dry-run to avoid full rotation)
	_, err = executeCommand(rootCmd, "ca", "rotate",
		"--ca-dir", caDir,
		"--profile", "ml/root-ca",
		"--dry-run",
	)

	assertNoError(t, err)
}

func TestF_CA_Rotate_CANotFound(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	_, err := executeCommand(rootCmd, "ca", "rotate",
		"--ca-dir", tc.path("nonexistent"),
	)

	assertError(t, err)
}

func TestF_CA_Rotate_Execute(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	caDir := tc.path("ca")

	// Create CA
	_, err := executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Test CA",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
	)
	assertNoError(t, err)

	resetCAFlags()

	// Execute rotation (creates pending version)
	_, err = executeCommand(rootCmd, "ca", "rotate",
		"--ca-dir", caDir,
		"--profile", "ec/root-ca",
	)

	assertNoError(t, err)

	// Verify versions directory was created
	assertFileExists(t, filepath.Join(caDir, "versions"))
}

// =============================================================================
// CA Versions Tests
// =============================================================================

func TestF_CA_Versions_NotVersioned(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	caDir := tc.path("ca")

	// Create CA (not versioned yet)
	_, err := executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Test CA",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
	)
	assertNoError(t, err)

	resetCAFlags()

	// List versions (CA not versioned)
	_, err = executeCommand(rootCmd, "ca", "versions", "--ca-dir", caDir)

	assertNoError(t, err) // Should succeed with message about no versioning
}

func TestF_CA_Versions_AfterRotate(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	caDir := tc.path("ca")

	// Create CA
	_, err := executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Test CA",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
	)
	assertNoError(t, err)

	resetCAFlags()

	// Rotate to create versions
	_, err = executeCommand(rootCmd, "ca", "rotate",
		"--ca-dir", caDir,
		"--profile", "ec/root-ca",
	)
	assertNoError(t, err)

	resetCAFlags()

	// List versions
	_, err = executeCommand(rootCmd, "ca", "versions", "--ca-dir", caDir)

	assertNoError(t, err)
}

func TestF_CA_Versions_CANotFound(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Note: ca versions doesn't error on nonexistent CA, it just reports no versioning
	_, err := executeCommand(rootCmd, "ca", "versions", "--ca-dir", tc.path("nonexistent"))

	assertNoError(t, err) // Command succeeds with "CA does not use versioning" message
}

// =============================================================================
// CA Activate Tests
// =============================================================================

func TestF_CA_Activate_VersionMissing(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	caDir := tc.path("ca")

	// Create and rotate CA
	_, _ = executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Test CA",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
	)

	resetCAFlags()
	_, _ = executeCommand(rootCmd, "ca", "rotate",
		"--ca-dir", caDir,
		"--profile", "ec/root-ca",
	)

	resetCAFlags()

	// Activate without version flag
	_, err := executeCommand(rootCmd, "ca", "activate", "--ca-dir", caDir)

	assertError(t, err) // --version is required
}

func TestF_CA_Activate_NotVersioned(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	caDir := tc.path("ca")

	// Create CA without rotation
	_, _ = executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Test CA",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
	)

	resetCAFlags()

	// Try to activate (CA not versioned)
	_, err := executeCommand(rootCmd, "ca", "activate",
		"--ca-dir", caDir,
		"--version", "v20251229_test",
	)

	assertError(t, err)
}

func TestF_CA_Activate_VersionNotFound(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	caDir := tc.path("ca")

	// Create and rotate CA
	_, _ = executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Test CA",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
	)

	resetCAFlags()
	_, _ = executeCommand(rootCmd, "ca", "rotate",
		"--ca-dir", caDir,
		"--profile", "ec/root-ca",
	)

	resetCAFlags()

	// Activate nonexistent version
	_, err := executeCommand(rootCmd, "ca", "activate",
		"--ca-dir", caDir,
		"--version", "nonexistent_version",
	)

	assertError(t, err)
}

func TestF_CA_Activate_CANotFound(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	_, err := executeCommand(rootCmd, "ca", "activate",
		"--ca-dir", tc.path("nonexistent"),
		"--version", "v1",
	)

	assertError(t, err)
}

func TestF_CA_Activate_V1_OriginalCA(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	caDir := tc.path("ca")

	// Create and rotate CA
	_, err := executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Test CA",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
	)
	assertNoError(t, err)

	resetCAFlags()
	_, err = executeCommand(rootCmd, "ca", "rotate",
		"--ca-dir", caDir,
		"--profile", "ec/root-ca",
	)
	assertNoError(t, err)

	resetCAFlags()

	// Try to activate v1 (original CA - cannot be activated)
	_, err = executeCommand(rootCmd, "ca", "activate",
		"--ca-dir", caDir,
		"--version", "v1",
	)

	assertError(t, err) // v1 cannot be activated
}

func TestF_CA_Activate_V2_Success(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	caDir := tc.path("ca")

	// Create and rotate CA
	_, err := executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Test CA",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
	)
	assertNoError(t, err)

	resetCAFlags()
	_, err = executeCommand(rootCmd, "ca", "rotate",
		"--ca-dir", caDir,
		"--profile", "ec/root-ca",
	)
	assertNoError(t, err)

	resetCAFlags()

	// Activate v2 (the first rotated version)
	_, err = executeCommand(rootCmd, "ca", "activate",
		"--ca-dir", caDir,
		"--version", "v2",
	)

	assertNoError(t, err)
}

func TestF_CA_Activate_AlreadyActive(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	caDir := tc.path("ca")

	// Create and rotate CA
	_, err := executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Test CA",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
	)
	assertNoError(t, err)

	resetCAFlags()
	_, err = executeCommand(rootCmd, "ca", "rotate",
		"--ca-dir", caDir,
		"--profile", "ec/root-ca",
	)
	assertNoError(t, err)

	resetCAFlags()

	// Activate v2
	_, err = executeCommand(rootCmd, "ca", "activate",
		"--ca-dir", caDir,
		"--version", "v2",
	)
	assertNoError(t, err)

	resetCAFlags()

	// Try to activate v2 again (already active)
	_, err = executeCommand(rootCmd, "ca", "activate",
		"--ca-dir", caDir,
		"--version", "v2",
	)

	assertError(t, err) // Already active
}

// =============================================================================
// Helper to expose tempDir for ca list test
// =============================================================================

func init() {
	// Make tempDir accessible for TestCAList
	_ = os.MkdirAll("/tmp", 0755)
}

// =============================================================================
// Crypto-Agility Integration Tests
// =============================================================================

func TestA_CA_Export_Chain_WithCrossSign(t *testing.T) {
	tc := newTestContext(t)
	caDir := tc.path("ca")

	// Initialize CA
	resetCAFlags()
	_, err := executeCommand(rootCmd, "ca", "init",
		"--ca-dir", caDir,
		"--profile", "ec/root-ca",
		"--var", "cn=Original CA",
		"--passphrase", "test",
	)
	if err != nil {
		t.Fatalf("failed to init CA: %v", err)
	}

	// Rotate with cross-sign
	resetCAFlags()
	_, err = executeCommand(rootCmd, "ca", "rotate",
		"--ca-dir", caDir,
		"--profile", "ec/root-ca",
		"--passphrase", "test",
		"--cross-sign",
	)
	if err != nil {
		t.Fatalf("failed to rotate CA: %v", err)
	}

	// Activate the new version
	resetCAFlags()
	_, err = executeCommand(rootCmd, "ca", "activate",
		"--ca-dir", caDir,
		"--version", "v2",
	)
	if err != nil {
		t.Fatalf("failed to activate CA: %v", err)
	}

	// Export with bundle=chain
	outPath := tc.path("chain.pem")
	resetCAFlags()
	_, err = executeCommand(rootCmd, "ca", "export",
		"--ca-dir", caDir,
		"--bundle", "chain",
		"--out", outPath,
	)
	assertNoError(t, err)
	assertFileExists(t, outPath)

	// Verify the output contains multiple certificates (CA cert + cross-signed cert)
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	certCount := strings.Count(string(data), "-----BEGIN CERTIFICATE-----")
	// Should have: 1 CA cert + 1 cross-signed cert = 2
	if certCount < 2 {
		t.Errorf("Expected at least 2 certificates in chain (CA + cross-signed), got %d", certCount)
	}
}

func TestA_CA_Export_Chain_NoCrossSign(t *testing.T) {
	tc := newTestContext(t)
	caDir := tc.path("ca")

	// Initialize CA without rotation
	resetCAFlags()
	_, err := executeCommand(rootCmd, "ca", "init",
		"--ca-dir", caDir,
		"--profile", "ec/root-ca",
		"--var", "cn=Simple CA",
	)
	if err != nil {
		t.Fatalf("failed to init CA: %v", err)
	}

	// Export with bundle=chain
	outPath := tc.path("chain.pem")
	resetCAFlags()
	_, err = executeCommand(rootCmd, "ca", "export",
		"--ca-dir", caDir,
		"--bundle", "chain",
		"--out", outPath,
	)
	assertNoError(t, err)
	assertFileExists(t, outPath)

	// Verify the output contains just the CA certificate
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	certCount := strings.Count(string(data), "-----BEGIN CERTIFICATE-----")
	// Should have: 1 CA cert only
	if certCount != 1 {
		t.Errorf("Expected 1 certificate (CA only), got %d", certCount)
	}
}

// =============================================================================
// CA Multi-Profile Rotation Tests
// =============================================================================

func TestF_CA_Rotate_MultiProfile_DryRun(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	caDir := tc.path("ca")

	// Create CA with single profile
	_, err := executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Test CA",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
	)
	assertNoError(t, err)

	resetCAFlags()

	// Dry-run multi-profile rotation
	_, err = executeCommand(rootCmd, "ca", "rotate",
		"--ca-dir", caDir,
		"--profile", "ec/root-ca",
		"--profile", "ml/root-ca",
		"--dry-run",
	)

	assertNoError(t, err)
}

func TestF_CA_Rotate_MultiProfile_Execute(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	caDir := tc.path("ca")

	// Create CA
	_, err := executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Test CA",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
	)
	assertNoError(t, err)

	resetCAFlags()

	// Execute multi-profile rotation
	_, err = executeCommand(rootCmd, "ca", "rotate",
		"--ca-dir", caDir,
		"--profile", "ec/root-ca",
		"--profile", "ml/root-ca",
	)

	assertNoError(t, err)

	// Verify versions directory was created
	assertFileExists(t, filepath.Join(caDir, "versions"))
}

func TestF_CA_Rotate_MultiProfile_InvalidProfile(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	caDir := tc.path("ca")

	// Create CA
	_, err := executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Test CA",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
	)
	assertNoError(t, err)

	resetCAFlags()

	// Try multi-profile rotation with invalid profile
	_, err = executeCommand(rootCmd, "ca", "rotate",
		"--ca-dir", caDir,
		"--profile", "ec/root-ca",
		"--profile", "nonexistent/profile",
	)

	assertError(t, err)
}
