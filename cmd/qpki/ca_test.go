package main

import (
	"os"
	"path/filepath"
	"testing"
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
	caInitProfile = ""

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
	caRotateProfile = ""
	caRotatePassphrase = ""
	caRotateCrossSign = "auto"
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
		name        string
		profile     string
		expectedKey string // Expected key filename (new naming: ca.<algorithm>.key)
		wantErr     bool
	}{
		{"[Functional] CA Init: EC Root CA", "ec/root-ca", "ca.ecdsa-p384.key", false},
		{"[Functional] CA Init: EC Issuing CA Profile", "ec/issuing-ca", "ca.ecdsa-p256.key", false},
		{"[Functional] CA Init: ML-DSA Root CA", "ml/root-ca", "ca.ml-dsa-87.key", false},
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
				"--dir", caDir,
			}

			_, err := executeCommand(rootCmd, args...)

			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				assertFileExists(t, filepath.Join(caDir, "ca.crt"))
				assertFileExists(t, filepath.Join(caDir, "private", tt.expectedKey))
				assertFileExists(t, filepath.Join(caDir, "ca.meta.json"))
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
		"--dir", caDir,
		"--passphrase", "secret123",
	)

	assertNoError(t, err)
	assertFileExists(t, filepath.Join(caDir, "ca.crt"))
	assertFileExists(t, filepath.Join(caDir, "private", "ca.ecdsa-p384.key"))
}

func TestF_CA_Init_ProfileMissing(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	_, err := executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Test CA",
		"--dir", tc.path("ca"),
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
		"--dir", caDir,
	)
	assertNoError(t, err)

	resetCAFlags()

	// Try to create second CA in same location
	_, err = executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Second CA",
		"--profile", "ec/root-ca",
		"--dir", caDir,
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
		"--dir", rootDir,
	)
	assertNoError(t, err)

	resetCAFlags()

	// Create subordinate CA
	_, err = executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Issuing CA",
		"--profile", "ec/issuing-ca",
		"--dir", subDir,
		"--parent", rootDir,
	)

	assertNoError(t, err)
	assertFileExists(t, filepath.Join(subDir, "ca.crt"))
	assertFileExists(t, filepath.Join(subDir, "chain.crt"))
	assertFileExists(t, filepath.Join(subDir, "private", "ca.ecdsa-p256.key"))
	assertFileExists(t, filepath.Join(subDir, "ca.meta.json"))
}

func TestF_CA_Init_Subordinate_ParentNotFound(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	_, err := executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Issuing CA",
		"--profile", "ec/issuing-ca",
		"--dir", tc.path("sub-ca"),
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
		"--dir", caDir,
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
		"--dir", caDir,
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
		"--dir", caDir,
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
				"--dir", caDir,
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
		"--dir", caDir,
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
		"--dir", caDir,
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
		"--dir", caDir,
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
		"--dir", caDir,
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
		"--dir", caDir,
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
		"--dir", caDir,
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
		"--dir", caDir,
	)
	assertNoError(t, err)

	resetCAFlags()

	// Rotate to create a version (v2)
	_, err = executeCommand(rootCmd, "ca", "rotate",
		"--ca-dir", caDir,
		"--profile", "ec/root-ca",
	)
	assertNoError(t, err)

	resetCAFlags()

	// Export v2 (first rotated version)
	outPath := tc.path("v2.pem")
	_, err = executeCommand(rootCmd, "ca", "export",
		"--ca-dir", caDir,
		"--version", "v2",
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
		"--dir", caDir,
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
		"--dir", caDir,
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

	// Create CA
	_, err := executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Test CA",
		"--profile", "ec/root-ca",
		"--dir", caDir,
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
		"--dir", caDir,
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
		"--dir", caDir,
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
		"--dir", caDir,
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

func TestF_CA_Rotate_CrossSignInvalid(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	caDir := tc.path("ca")

	// Create CA
	_, _ = executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Test CA",
		"--profile", "ec/root-ca",
		"--dir", caDir,
	)

	resetCAFlags()

	_, err := executeCommand(rootCmd, "ca", "rotate",
		"--ca-dir", caDir,
		"--cross-sign", "invalid",
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
		"--dir", caDir,
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
		"--dir", caDir,
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
		"--dir", caDir,
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
		"--dir", caDir,
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
		"--dir", caDir,
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
		"--dir", caDir,
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
		"--dir", caDir,
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
		"--dir", caDir,
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
		"--dir", caDir,
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
