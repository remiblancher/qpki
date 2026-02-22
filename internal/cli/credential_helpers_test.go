package cli

import (
	"testing"

	"github.com/remiblancher/qpki/internal/profile"
)

// =============================================================================
// FormatRotateKeyInfo Tests
// =============================================================================

func TestU_FormatRotateKeyInfo(t *testing.T) {
	tests := []struct {
		name       string
		keepKeys   bool
		hsmEnabled bool
		expected   string
	}{
		{
			name:       "[Unit] FormatRotateKeyInfo: keep existing keys",
			keepKeys:   true,
			hsmEnabled: false,
			expected:   "existing keys",
		},
		{
			name:       "[Unit] FormatRotateKeyInfo: new keys with HSM",
			keepKeys:   false,
			hsmEnabled: true,
			expected:   "new keys (HSM)",
		},
		{
			name:       "[Unit] FormatRotateKeyInfo: new software keys",
			keepKeys:   false,
			hsmEnabled: false,
			expected:   "new keys",
		},
		{
			name:       "[Unit] FormatRotateKeyInfo: keep keys takes precedence",
			keepKeys:   true,
			hsmEnabled: true,
			expected:   "existing keys",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatRotateKeyInfo(tt.keepKeys, tt.hsmEnabled)
			if result != tt.expected {
				t.Errorf("FormatRotateKeyInfo() = %s, want %s", result, tt.expected)
			}
		})
	}
}

// =============================================================================
// ConfigureHSMKeyProvider Tests
// =============================================================================

func TestU_ConfigureHSMKeyProvider(t *testing.T) {
	t.Run("[Unit] ConfigureHSMKeyProvider: returns nil for empty path", func(t *testing.T) {
		err := ConfigureHSMKeyProvider(nil, "", "test-key")
		if err != nil {
			t.Errorf("ConfigureHSMKeyProvider() with empty path should return nil, got %v", err)
		}
	})

	t.Run("[Unit] ConfigureHSMKeyProvider: fails for non-existent config file", func(t *testing.T) {
		err := ConfigureHSMKeyProvider(nil, "/non/existent/hsm-config.yaml", "test-key")
		if err == nil {
			t.Error("ConfigureHSMKeyProvider() should fail for non-existent config file")
		}
	})
}

// =============================================================================
// LoadEnrollProfiles Tests
// =============================================================================

func TestU_LoadEnrollProfiles(t *testing.T) {
	t.Run("[Unit] LoadEnrollProfiles: loads builtin profile from empty directory", func(t *testing.T) {
		tmpDir := t.TempDir()
		// ec/tls-server is a builtin profile, so it should be found even with empty CA dir
		profiles, err := LoadEnrollProfiles(tmpDir, []string{"ec/tls-server"})
		if err != nil {
			t.Errorf("LoadEnrollProfiles() error = %v", err)
		}
		if len(profiles) != 1 {
			t.Errorf("LoadEnrollProfiles() returned %d profiles, want 1", len(profiles))
		}
	})

	t.Run("[Unit] LoadEnrollProfiles: fails for non-existent profile name", func(t *testing.T) {
		tmpDir := t.TempDir()
		_, err := LoadEnrollProfiles(tmpDir, []string{"non-existent/profile"})
		if err == nil {
			t.Error("LoadEnrollProfiles() should fail for non-existent profile")
		}
	})

	t.Run("[Unit] LoadEnrollProfiles: fails for non-existent profile file path", func(t *testing.T) {
		tmpDir := t.TempDir()
		_, err := LoadEnrollProfiles(tmpDir, []string{"/non/existent/profile.yaml"})
		if err == nil {
			t.Error("LoadEnrollProfiles() should fail for non-existent profile file")
		}
	})
}

// =============================================================================
// ResolveProfilesToObjects Tests
// =============================================================================

func TestU_ResolveProfilesToObjects(t *testing.T) {
	t.Run("[Unit] ResolveProfilesToObjects: returns empty for empty names", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := profile.NewFileStore(tmpDir)

		profiles, err := ResolveProfilesToObjects(store, []string{})
		if err != nil {
			t.Errorf("ResolveProfilesToObjects() error = %v", err)
		}
		if len(profiles) != 0 {
			t.Errorf("ResolveProfilesToObjects() returned %d profiles, want 0", len(profiles))
		}
	})

	t.Run("[Unit] ResolveProfilesToObjects: fails for non-existent profile", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := profile.NewFileStore(tmpDir)

		_, err := ResolveProfilesToObjects(store, []string{"non-existent-profile"})
		if err == nil {
			t.Error("ResolveProfilesToObjects() should fail for non-existent profile")
		}
	})
}

// =============================================================================
// ResolveProfilesTemplates Tests
// =============================================================================

func TestU_ResolveProfilesTemplates(t *testing.T) {
	t.Run("[Unit] ResolveProfilesTemplates: handles empty profiles", func(t *testing.T) {
		result, err := ResolveProfilesTemplates([]*profile.Profile{}, profile.VariableValues{})
		if err != nil {
			t.Errorf("ResolveProfilesTemplates() error = %v", err)
		}
		if len(result) != 0 {
			t.Errorf("ResolveProfilesTemplates() returned %d profiles, want 0", len(result))
		}
	})

	t.Run("[Unit] ResolveProfilesTemplates: handles nil variables", func(t *testing.T) {
		prof := &profile.Profile{
			Name: "test-profile",
		}

		result, err := ResolveProfilesTemplates([]*profile.Profile{prof}, nil)
		if err != nil {
			t.Errorf("ResolveProfilesTemplates() error = %v", err)
		}
		if len(result) != 1 {
			t.Errorf("ResolveProfilesTemplates() returned %d profiles, want 1", len(result))
		}
	})
}

// =============================================================================
// ValidateEnrollVariables Tests
// =============================================================================

func TestU_ValidateEnrollVariables(t *testing.T) {
	t.Run("[Unit] ValidateEnrollVariables: returns input for empty profiles", func(t *testing.T) {
		vars := profile.VariableValues{"key": "value"}

		result, err := ValidateEnrollVariables([]*profile.Profile{}, vars)
		if err != nil {
			t.Errorf("ValidateEnrollVariables() error = %v", err)
		}
		if result["key"] != "value" {
			t.Error("ValidateEnrollVariables() should return input variables for empty profiles")
		}
	})

	t.Run("[Unit] ValidateEnrollVariables: returns input for profile without variables", func(t *testing.T) {
		prof := &profile.Profile{
			Name:      "test-profile",
			Variables: nil,
		}
		vars := profile.VariableValues{"key": "value"}

		result, err := ValidateEnrollVariables([]*profile.Profile{prof}, vars)
		if err != nil {
			t.Errorf("ValidateEnrollVariables() error = %v", err)
		}
		if result["key"] != "value" {
			t.Error("ValidateEnrollVariables() should return input variables for profile without variables")
		}
	})
}

// =============================================================================
// Integration notes for remaining credential helpers
// =============================================================================

// The following functions require full CA setup and are better tested
// through integration/acceptance tests:
// - ExecuteEnrollment (requires ca.CA with signer loaded)
// - PrintEnrollmentSuccess (mainly prints output)
// - PrepareEnrollVariablesAndProfiles (combines multiple operations)
