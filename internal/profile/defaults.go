package profile

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

//go:embed builtin/*.yaml
var builtinProfilesFS embed.FS

// BuiltinProfiles returns the predefined profiles.
// These are compiled into the binary and serve as templates.
func BuiltinProfiles() (map[string]*Profile, error) {
	profiles := make(map[string]*Profile)

	entries, err := builtinProfilesFS.ReadDir("builtin")
	if err != nil {
		return nil, fmt.Errorf("failed to read embedded builtin profiles: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		data, err := builtinProfilesFS.ReadFile("builtin/" + entry.Name())
		if err != nil {
			return nil, fmt.Errorf("failed to read %s: %w", entry.Name(), err)
		}

		profile, err := LoadProfileFromBytes(data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse %s: %w", entry.Name(), err)
		}

		profiles[profile.Name] = profile
	}

	return profiles, nil
}

// InstallBuiltinProfiles copies the builtin profiles to the CA's profiles directory.
// If overwrite is false, existing files are not replaced.
func InstallBuiltinProfiles(caPath string, overwrite bool) error {
	profilesDir := filepath.Join(caPath, "profiles")

	// Create directory if it doesn't exist
	if err := os.MkdirAll(profilesDir, 0755); err != nil {
		return fmt.Errorf("failed to create profiles directory: %w", err)
	}

	// Walk through embedded files
	err := fs.WalkDir(builtinProfilesFS, "builtin", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		// Read embedded file
		data, err := builtinProfilesFS.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", path, err)
		}

		// Destination path
		destPath := filepath.Join(profilesDir, d.Name())

		// Check if file exists
		if !overwrite {
			if _, err := os.Stat(destPath); err == nil {
				// File exists, skip
				return nil
			}
		}

		// Write file
		if err := os.WriteFile(destPath, data, 0644); err != nil {
			return fmt.Errorf("failed to write %s: %w", destPath, err)
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to install builtin profiles: %w", err)
	}

	return nil
}

// ListBuiltinProfileNames returns the names of all builtin profiles.
func ListBuiltinProfileNames() ([]string, error) {
	entries, err := builtinProfilesFS.ReadDir("builtin")
	if err != nil {
		return nil, fmt.Errorf("failed to read embedded builtin profiles: %w", err)
	}

	var names []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		// Parse to get the name
		data, err := builtinProfilesFS.ReadFile("builtin/" + entry.Name())
		if err != nil {
			continue
		}

		profile, err := LoadProfileFromBytes(data)
		if err != nil {
			continue
		}

		names = append(names, profile.Name)
	}

	return names, nil
}

// GetBuiltinProfile returns a specific builtin profile by name.
func GetBuiltinProfile(name string) (*Profile, error) {
	profiles, err := BuiltinProfiles()
	if err != nil {
		return nil, err
	}

	profile, ok := profiles[name]
	if !ok {
		return nil, fmt.Errorf("builtin profile not found: %s", name)
	}

	return profile, nil
}
