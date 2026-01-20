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

func TestF_Profile_List(t *testing.T) {
	resetProfileFlags()

	_, err := executeCommand(rootCmd, "profile", "list")
	assertNoError(t, err)
}

// =============================================================================
// Profile Info Tests
// =============================================================================

func TestF_Profile_Info(t *testing.T) {
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

func TestF_Profile_Info_MissingArg(t *testing.T) {
	resetProfileFlags()

	_, err := executeCommand(rootCmd, "profile", "info")
	assertError(t, err)
}

// =============================================================================
// Profile Show Tests
// =============================================================================

func TestF_Profile_Show(t *testing.T) {
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

func TestF_Profile_Vars(t *testing.T) {
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

func TestF_Profile_Lint_ValidProfile(t *testing.T) {
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

func TestF_Profile_Lint_InvalidProfile(t *testing.T) {
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

func TestF_Profile_Lint_FileNotFound(t *testing.T) {
	tc := newTestContext(t)
	resetProfileFlags()

	_, err := executeCommand(rootCmd, "profile", "lint", tc.path("nonexistent.yaml"))
	assertError(t, err)
}

// =============================================================================
// Profile Export Tests
// =============================================================================

func TestF_Profile_Export(t *testing.T) {
	tc := newTestContext(t)
	resetProfileFlags()

	outPath := tc.path("exported-profile.yaml")

	_, err := executeCommand(rootCmd, "profile", "export", "ec/root-ca", outPath)
	assertNoError(t, err)
	assertFileExists(t, outPath)
	assertFileNotEmpty(t, outPath)
}

func TestF_Profile_Export_ProfileNotFound(t *testing.T) {
	tc := newTestContext(t)
	resetProfileFlags()

	_, err := executeCommand(rootCmd, "profile", "export", "nonexistent/profile", tc.path("out.yaml"))
	assertError(t, err)
}

// =============================================================================
// Helper Function Unit Tests
// =============================================================================

func TestU_FormatDefaultValue(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected string
	}{
		{
			name:     "Empty string",
			input:    "",
			expected: `""`,
		},
		{
			name:     "Non-empty string",
			input:    "hello",
			expected: "hello",
		},
		{
			name:     "Empty slice interface",
			input:    []interface{}{},
			expected: "[]",
		},
		{
			name:     "Non-empty slice interface",
			input:    []interface{}{"a", "b"},
			expected: "[a b]",
		},
		{
			name:     "Empty string slice",
			input:    []string{},
			expected: "[]",
		},
		{
			name:     "Non-empty string slice",
			input:    []string{"a", "b", "c"},
			expected: "a, b, c",
		},
		{
			name:     "Integer",
			input:    42,
			expected: "42",
		},
		{
			name:     "Boolean",
			input:    true,
			expected: "true",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatDefaultValue(tt.input)
			if result != tt.expected {
				t.Errorf("formatDefaultValue(%v) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// =============================================================================
// Profile Install Tests
// =============================================================================

func TestF_Profile_Install(t *testing.T) {
	tc := newTestContext(t)
	resetProfileFlags()

	// Use a fresh directory
	profileCADir = tc.path("ca")

	_, err := executeCommand(rootCmd, "profile", "install", "--dir", tc.path("ca"))
	assertNoError(t, err)

	// Verify profiles directory was created
	assertFileExists(t, tc.path("ca/profiles"))
}

func TestF_Profile_Install_Overwrite(t *testing.T) {
	tc := newTestContext(t)
	resetProfileFlags()

	// First install
	_, err := executeCommand(rootCmd, "profile", "install", "--dir", tc.path("ca"))
	assertNoError(t, err)

	// Second install with overwrite
	_, err = executeCommand(rootCmd, "profile", "install", "--dir", tc.path("ca"), "--overwrite")
	assertNoError(t, err)
}

// =============================================================================
// Profile Export All Tests
// =============================================================================

func TestF_Profile_Export_All(t *testing.T) {
	tc := newTestContext(t)
	resetProfileFlags()

	destDir := tc.path("exported-profiles")

	_, err := executeCommand(rootCmd, "profile", "export", "--all", destDir)
	assertNoError(t, err)

	// Verify the directory was created and contains files
	assertFileExists(t, destDir)
}

func TestF_Profile_Export_All_MissingArg(t *testing.T) {
	resetProfileFlags()

	_, err := executeCommand(rootCmd, "profile", "export", "--all")
	assertError(t, err) // Should error: destination directory required
}

func TestF_Profile_Export_MissingArgs(t *testing.T) {
	resetProfileFlags()

	_, err := executeCommand(rootCmd, "profile", "export", "ec/root-ca")
	assertError(t, err) // Should error: missing file argument
}
