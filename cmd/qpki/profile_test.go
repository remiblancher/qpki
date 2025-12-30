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

func TestProfileList(t *testing.T) {
	resetProfileFlags()

	_, err := executeCommand(rootCmd, "profile", "list")
	assertNoError(t, err)
}

// =============================================================================
// Profile Info Tests
// =============================================================================

func TestProfileInfo(t *testing.T) {
	tests := []struct {
		name    string
		profile string
		wantErr bool
	}{
		{"EC root CA profile", "ec/root-ca", false},
		{"EC TLS server profile", "ec/tls-server", false},
		{"ML-DSA root CA profile", "ml/root-ca", false},
		{"nonexistent profile", "nonexistent/profile", true},
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

func TestProfileInfo_MissingArg(t *testing.T) {
	resetProfileFlags()

	_, err := executeCommand(rootCmd, "profile", "info")
	assertError(t, err)
}

// =============================================================================
// Profile Show Tests
// =============================================================================

func TestProfileShow(t *testing.T) {
	tests := []struct {
		name    string
		profile string
		wantErr bool
	}{
		{"EC root CA profile", "ec/root-ca", false},
		{"EC TLS server profile", "ec/tls-server", false},
		{"nonexistent profile", "nonexistent/profile", true},
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

func TestProfileVars(t *testing.T) {
	tests := []struct {
		name    string
		profile string
		wantErr bool
	}{
		{"EC TLS server profile", "ec/tls-server", false},
		{"EC TLS client profile", "ec/tls-client", false},
		{"nonexistent profile", "nonexistent/profile", true},
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

func TestProfileLint_ValidProfile(t *testing.T) {
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

func TestProfileLint_InvalidProfile(t *testing.T) {
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

func TestProfileLint_FileNotFound(t *testing.T) {
	tc := newTestContext(t)
	resetProfileFlags()

	_, err := executeCommand(rootCmd, "profile", "lint", tc.path("nonexistent.yaml"))
	assertError(t, err)
}

// =============================================================================
// Profile Export Tests
// =============================================================================

func TestProfileExport(t *testing.T) {
	tc := newTestContext(t)
	resetProfileFlags()

	outPath := tc.path("exported-profile.yaml")

	_, err := executeCommand(rootCmd, "profile", "export", "ec/root-ca", outPath)
	assertNoError(t, err)
	assertFileExists(t, outPath)
	assertFileNotEmpty(t, outPath)
}

func TestProfileExport_NonexistentProfile(t *testing.T) {
	tc := newTestContext(t)
	resetProfileFlags()

	_, err := executeCommand(rootCmd, "profile", "export", "nonexistent/profile", tc.path("out.yaml"))
	assertError(t, err)
}
