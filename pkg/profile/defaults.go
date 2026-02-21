package profile

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/remiblancher/qpki/profiles"
)

// BuiltinProfiles returns the predefined profiles.
// These are compiled into the binary and serve as templates.
// Profiles are organized in subdirectories: ec/, rsa/, ml/, slh/, hybrid/catalyst/, hybrid/composite/
func BuiltinProfiles() (map[string]*Profile, error) {
	result := make(map[string]*Profile)

	// Walk through all embedded files recursively
	err := fs.WalkDir(profiles.FS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		// Only process YAML files
		if filepath.Ext(d.Name()) != ".yaml" && filepath.Ext(d.Name()) != ".yml" {
			return nil
		}

		data, err := profiles.FS.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", path, err)
		}

		profile, err := LoadProfileFromBytes(data)
		if err != nil {
			return fmt.Errorf("failed to parse %s: %w", path, err)
		}

		// Use the profile name from YAML (e.g., "rsa/root-ca")
		result[profile.Name] = profile
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to load builtin profiles: %w", err)
	}

	return result, nil
}

// InstallBuiltinProfiles copies the builtin profiles to the CA's profiles directory.
// If overwrite is false, existing files are not replaced.
// Preserves the directory structure (ec/, rsa/, ml/, slh/, hybrid/).
func InstallBuiltinProfiles(caPath string, overwrite bool) error {
	profilesDir := filepath.Join(caPath, "profiles")

	// Create directory if it doesn't exist
	if err := os.MkdirAll(profilesDir, 0755); err != nil {
		return fmt.Errorf("failed to create profiles directory: %w", err)
	}

	// Walk through embedded files
	err := fs.WalkDir(profiles.FS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Path is already relative (no "builtin" prefix)
		relPath := path

		if d.IsDir() {
			// Create subdirectory
			if relPath != "." {
				subDir := filepath.Join(profilesDir, relPath)
				if err := os.MkdirAll(subDir, 0755); err != nil {
					return fmt.Errorf("failed to create directory %s: %w", subDir, err)
				}
			}
			return nil
		}

		// Only process YAML files
		if filepath.Ext(d.Name()) != ".yaml" && filepath.Ext(d.Name()) != ".yml" {
			return nil
		}

		// Read embedded file
		data, err := profiles.FS.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", path, err)
		}

		// Destination path (preserve directory structure)
		destPath := filepath.Join(profilesDir, relPath)

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
// Names are in the format "category/name" (e.g., "rsa/root-ca", "hybrid/catalyst/tls-server").
func ListBuiltinProfileNames() ([]string, error) {
	var names []string

	err := fs.WalkDir(profiles.FS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		// Only process YAML files
		if filepath.Ext(d.Name()) != ".yaml" && filepath.Ext(d.Name()) != ".yml" {
			return nil
		}

		// Parse to get the name
		data, err := profiles.FS.ReadFile(path)
		if err != nil {
			return nil // Skip on error
		}

		profile, err := LoadProfileFromBytes(data)
		if err != nil {
			return nil // Skip on error
		}

		names = append(names, profile.Name)
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to list builtin profiles: %w", err)
	}

	return names, nil
}

// GetBuiltinProfile returns a specific builtin profile by name.
func GetBuiltinProfile(name string) (*Profile, error) {
	builtinProfiles, err := BuiltinProfiles()
	if err != nil {
		return nil, err
	}

	profile, ok := builtinProfiles[name]
	if !ok {
		return nil, fmt.Errorf("builtin profile not found: %s", name)
	}

	return profile, nil
}

// LoadProfile loads a profile by name or file path.
// File paths are detected by:
//   - Starting with "/" (absolute path)
//   - Starting with "." (relative path like ./profile.yaml)
//   - Ending with ".yaml" or ".yml"
//
// Otherwise, it's treated as a builtin profile name (e.g., "ec/root-ca").
func LoadProfile(nameOrPath string) (*Profile, error) {
	// Detect if this is a file path
	if strings.HasPrefix(nameOrPath, "/") ||
		strings.HasPrefix(nameOrPath, ".") ||
		strings.HasSuffix(nameOrPath, ".yaml") ||
		strings.HasSuffix(nameOrPath, ".yml") {
		return LoadProfileFromFile(nameOrPath)
	}
	return GetBuiltinProfile(nameOrPath)
}
