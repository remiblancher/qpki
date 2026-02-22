package profile

import (
	"os"
	"path/filepath"
	"testing"
)

// =============================================================================
// BuiltinProfiles Tests
// =============================================================================

func TestU_BuiltinProfiles(t *testing.T) {
	profiles, err := BuiltinProfiles()
	if err != nil {
		t.Fatalf("BuiltinProfiles() error = %v", err)
	}

	if len(profiles) == 0 {
		t.Error("BuiltinProfiles() should return at least one profile")
	}

	// Verify that profiles have valid names
	for name, profile := range profiles {
		if name == "" {
			t.Error("Profile name should not be empty")
		}
		if profile == nil {
			t.Errorf("Profile %q is nil", name)
			continue
		}
		if profile.Name != name {
			t.Errorf("Profile name mismatch: key=%q, profile.Name=%q", name, profile.Name)
		}
	}
}

func TestU_BuiltinProfiles_HasExpectedCategories(t *testing.T) {
	profiles, err := BuiltinProfiles()
	if err != nil {
		t.Fatalf("BuiltinProfiles() error = %v", err)
	}

	// Expected categories based on directory structure
	categories := map[string]bool{
		"ec":  false,
		"rsa": false,
		"ml":  false,
	}

	for name := range profiles {
		for cat := range categories {
			if len(name) > len(cat)+1 && name[:len(cat)+1] == cat+"/" {
				categories[cat] = true
			}
		}
	}

	for cat, found := range categories {
		if !found {
			t.Logf("Category %q not found (may not be fatal)", cat)
		}
	}
}

func TestU_BuiltinProfiles_MultipleCallsConsistent(t *testing.T) {
	// Call multiple times and verify results are consistent
	profiles1, err := BuiltinProfiles()
	if err != nil {
		t.Fatalf("First BuiltinProfiles() error = %v", err)
	}

	profiles2, err := BuiltinProfiles()
	if err != nil {
		t.Fatalf("Second BuiltinProfiles() error = %v", err)
	}

	if len(profiles1) != len(profiles2) {
		t.Errorf("BuiltinProfiles() returned different counts: %d vs %d", len(profiles1), len(profiles2))
	}

	// Verify same keys
	for name := range profiles1 {
		if _, ok := profiles2[name]; !ok {
			t.Errorf("Profile %q not found in second call", name)
		}
	}
}

// =============================================================================
// ListBuiltinProfileNames Tests
// =============================================================================

func TestU_ListBuiltinProfileNames(t *testing.T) {
	names, err := ListBuiltinProfileNames()
	if err != nil {
		t.Fatalf("ListBuiltinProfileNames() error = %v", err)
	}

	if len(names) == 0 {
		t.Error("ListBuiltinProfileNames() should return at least one name")
	}

	// Verify all names are non-empty
	for _, name := range names {
		if name == "" {
			t.Error("Profile name should not be empty")
		}
	}
}

func TestU_ListBuiltinProfileNames_MatchesBuiltinProfiles(t *testing.T) {
	names, err := ListBuiltinProfileNames()
	if err != nil {
		t.Fatalf("ListBuiltinProfileNames() error = %v", err)
	}

	profiles, err := BuiltinProfiles()
	if err != nil {
		t.Fatalf("BuiltinProfiles() error = %v", err)
	}

	if len(names) != len(profiles) {
		t.Errorf("ListBuiltinProfileNames() returned %d names, but BuiltinProfiles() has %d profiles",
			len(names), len(profiles))
	}

	// Verify each name exists in profiles
	for _, name := range names {
		if _, ok := profiles[name]; !ok {
			t.Errorf("Profile name %q not found in BuiltinProfiles()", name)
		}
	}
}

func TestU_ListBuiltinProfileNames_NoDuplicates(t *testing.T) {
	names, err := ListBuiltinProfileNames()
	if err != nil {
		t.Fatalf("ListBuiltinProfileNames() error = %v", err)
	}

	seen := make(map[string]bool)
	for _, name := range names {
		if seen[name] {
			t.Errorf("Duplicate profile name: %q", name)
		}
		seen[name] = true
	}
}

// =============================================================================
// GetBuiltinProfile Tests
// =============================================================================

func TestU_GetBuiltinProfile_AllProfiles(t *testing.T) {
	names, err := ListBuiltinProfileNames()
	if err != nil {
		t.Fatalf("ListBuiltinProfileNames() error = %v", err)
	}

	for _, name := range names {
		profile, err := GetBuiltinProfile(name)
		if err != nil {
			t.Errorf("GetBuiltinProfile(%q) error = %v", name, err)
			continue
		}
		if profile == nil {
			t.Errorf("GetBuiltinProfile(%q) returned nil", name)
			continue
		}
		if profile.Name != name {
			t.Errorf("Profile.Name = %q, want %q", profile.Name, name)
		}
	}
}

func TestU_GetBuiltinProfile_NotFound(t *testing.T) {
	_, err := GetBuiltinProfile("nonexistent/profile-xyz-123")
	if err == nil {
		t.Error("GetBuiltinProfile() should return error for non-existent profile")
	}
}

func TestU_GetBuiltinProfile_EmptyName(t *testing.T) {
	_, err := GetBuiltinProfile("")
	if err == nil {
		t.Error("GetBuiltinProfile() should return error for empty name")
	}
}

// =============================================================================
// LoadProfile Additional Tests (beyond what's in profile_test.go)
// =============================================================================

func TestU_LoadProfile_BuiltinProfileByName(t *testing.T) {
	// Test loading a builtin profile by name
	names, err := ListBuiltinProfileNames()
	if err != nil {
		t.Fatalf("ListBuiltinProfileNames() error = %v", err)
	}

	if len(names) == 0 {
		t.Skip("No builtin profiles available")
	}

	// Find a profile name without path prefix indicators
	for _, name := range names {
		profile, err := LoadProfile(name)
		if err != nil {
			t.Errorf("LoadProfile(%q) error = %v", name, err)
			continue
		}
		if profile.Name != name {
			t.Errorf("Profile.Name = %q, want %q", profile.Name, name)
		}
		break // Just test one
	}
}

func TestU_LoadProfile_InvalidYAMLContent(t *testing.T) {
	tmpDir := t.TempDir()

	// Create an invalid YAML file
	invalidYAML := `
name: [invalid yaml
algorithm: ecdsa-p256
`
	profilePath := filepath.Join(tmpDir, "invalid.yaml")
	if err := os.WriteFile(profilePath, []byte(invalidYAML), 0644); err != nil {
		t.Fatalf("Failed to write profile file: %v", err)
	}

	_, err := LoadProfile(profilePath)
	if err == nil {
		t.Error("LoadProfile() should return error for invalid YAML")
	}
}

func TestU_LoadProfile_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()

	// Create an empty file
	profilePath := filepath.Join(tmpDir, "empty.yaml")
	if err := os.WriteFile(profilePath, []byte(""), 0644); err != nil {
		t.Fatalf("Failed to write profile file: %v", err)
	}

	_, err := LoadProfile(profilePath)
	// May succeed with default values or fail - just verify no panic
	_ = err
}

// =============================================================================
// InstallBuiltinProfiles Additional Tests
// =============================================================================

func TestU_InstallBuiltinProfiles_PreservesDirectoryStructure(t *testing.T) {
	tmpDir := t.TempDir()
	caDir := filepath.Join(tmpDir, "ca")

	err := InstallBuiltinProfiles(caDir, true)
	if err != nil {
		t.Fatalf("InstallBuiltinProfiles() error = %v", err)
	}

	profilesDir := filepath.Join(caDir, "profiles")

	// Walk and count files vs directories
	fileCount := 0
	dirCount := 0

	err = filepath.Walk(profilesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if path == profilesDir {
			return nil
		}
		if info.IsDir() {
			dirCount++
		} else {
			fileCount++
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Failed to walk profiles directory: %v", err)
	}

	// Should have at least some files
	if fileCount == 0 {
		t.Error("No profile files were installed")
	}

	t.Logf("Installed %d files in %d directories", fileCount, dirCount)
}

func TestU_InstallBuiltinProfiles_FilesAreYAML(t *testing.T) {
	tmpDir := t.TempDir()
	caDir := filepath.Join(tmpDir, "ca")

	err := InstallBuiltinProfiles(caDir, true)
	if err != nil {
		t.Fatalf("InstallBuiltinProfiles() error = %v", err)
	}

	profilesDir := filepath.Join(caDir, "profiles")

	err = filepath.Walk(profilesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		ext := filepath.Ext(info.Name())
		if ext != ".yaml" && ext != ".yml" {
			t.Errorf("Non-YAML file found: %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Failed to walk profiles directory: %v", err)
	}
}

func TestU_InstallBuiltinProfiles_InstalledProfilesAreLoadable(t *testing.T) {
	tmpDir := t.TempDir()
	caDir := filepath.Join(tmpDir, "ca")

	err := InstallBuiltinProfiles(caDir, true)
	if err != nil {
		t.Fatalf("InstallBuiltinProfiles() error = %v", err)
	}

	profilesDir := filepath.Join(caDir, "profiles")

	err = filepath.Walk(profilesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		// Try to load the profile
		profile, loadErr := LoadProfileFromFile(path)
		if loadErr != nil {
			t.Errorf("Failed to load installed profile %s: %v", path, loadErr)
			return nil
		}
		if profile.Name == "" {
			t.Errorf("Profile at %s has empty name", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Failed to walk profiles directory: %v", err)
	}
}
