package main

import (
	"testing"
)

// resetProfileFlags resets all profile command flags to their default values.
func resetProfileFlags() {
	profileCADir = "./ca"
	profileOverwrite = false
	profileExportAll = false
}

// =============================================================================
// Profile List Tests
// =============================================================================

func TestF_ProfileList(t *testing.T) {
	resetProfileFlags()

	_, err := executeCommand(rootCmd, "profile", "list")
	assertNoError(t, err)
}

// =============================================================================
// Profile Info Tests
// =============================================================================

func TestF_ProfileInfo(t *testing.T) {
	tests := []struct {
		name    string
		profile string
		wantErr bool
	}{
		{"[Functional] ProfileInfo: ECRootCA", "ec/root-ca", false},
		{"[Functional] ProfileInfo: ECTLSServer", "ec/tls-server", false},
		{"[Functional] ProfileInfo: MLDSARootCA", "ml/root-ca", false},
		{"[Functional] ProfileInfo: ProfileNotFound", "nonexistent/profile", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetProfileFlags()

			_, err := executeCommand(rootCmd, "profile", "info", tt.profile)

			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestF_ProfileInfo_MissingArg(t *testing.T) {
	resetProfileFlags()

	_, err := executeCommand(rootCmd, "profile", "info")
	assertError(t, err)
}

// =============================================================================
// Profile Show Tests
// =============================================================================

func TestF_ProfileShow(t *testing.T) {
	tests := []struct {
		name    string
		profile string
		wantErr bool
	}{
		{"[Functional] ProfileShow: ECRootCA", "ec/root-ca", false},
		{"[Functional] ProfileShow: ECTLSServer", "ec/tls-server", false},
		{"[Functional] ProfileShow: ProfileNotFound", "nonexistent/profile", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetProfileFlags()

			_, err := executeCommand(rootCmd, "profile", "show", tt.profile)

			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// =============================================================================
// Profile Vars Tests
// =============================================================================

func TestF_ProfileVars(t *testing.T) {
	tests := []struct {
		name    string
		profile string
		wantErr bool
	}{
		{"[Functional] ProfileVars: ECTLSServer", "ec/tls-server", false},
		{"[Functional] ProfileVars: ECTLSClient", "ec/tls-client", false},
		{"[Functional] ProfileVars: ProfileNotFound", "nonexistent/profile", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetProfileFlags()

			_, err := executeCommand(rootCmd, "profile", "vars", tt.profile)

			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// =============================================================================
// Profile Lint Tests
// =============================================================================

func TestF_ProfileLint_ValidProfile(t *testing.T) {
	tc := newTestContext(t)
	resetProfileFlags()

	// Create a valid profile YAML
	profileContent := `name: test-profile
description: Test Profile
algorithm: ecdsa-p256
validity: 8760h
extensions:
  keyUsage:
    critical: true
    usages:
      - digitalSignature
`
	profilePath := tc.writeFile("test-profile.yaml", profileContent)

	_, err := executeCommand(rootCmd, "profile", "lint", profilePath)
	assertNoError(t, err)
}

func TestF_ProfileLint_InvalidProfile(t *testing.T) {
	tc := newTestContext(t)
	resetProfileFlags()

	// Create an invalid profile YAML (missing required fields)
	invalidContent := `name: incomplete
# missing algorithm and other required fields
`
	invalidPath := tc.writeFile("invalid-profile.yaml", invalidContent)

	_, err := executeCommand(rootCmd, "profile", "lint", invalidPath)
	assertError(t, err)
}

func TestF_ProfileLint_FileNotFound(t *testing.T) {
	tc := newTestContext(t)
	resetProfileFlags()

	_, err := executeCommand(rootCmd, "profile", "lint", tc.path("nonexistent.yaml"))
	assertError(t, err)
}

// =============================================================================
// Profile Export Tests
// =============================================================================

func TestF_ProfileExport(t *testing.T) {
	tc := newTestContext(t)
	resetProfileFlags()

	outPath := tc.path("exported-profile.yaml")

	_, err := executeCommand(rootCmd, "profile", "export", "ec/root-ca", outPath)
	assertNoError(t, err)
	assertFileExists(t, outPath)
	assertFileNotEmpty(t, outPath)
}

func TestF_ProfileExport_ProfileNotFound(t *testing.T) {
	tc := newTestContext(t)
	resetProfileFlags()

	_, err := executeCommand(rootCmd, "profile", "export", "nonexistent/profile", tc.path("out.yaml"))
	assertError(t, err)
}
