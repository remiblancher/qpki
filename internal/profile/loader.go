package profile

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/remiblancher/post-quantum-pki/internal/crypto"
	"gopkg.in/yaml.v3"
)

// profileYAML is the YAML representation of a Profile.
// Supports both simple (1 algo) and Catalyst (2 algos) profiles.
type profileYAML struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`

	// Subject DN configuration (flat map with {{ template }} values)
	// Example: cn: "{{ cn }}", o: "{{ organization }}", ou: "Servers"
	Subject map[string]string `yaml:"subject,omitempty"`

	// Algorithm configuration (mutually exclusive options)
	Algorithm  string   `yaml:"algorithm,omitempty"`  // Simple profile: single algorithm
	Algorithms []string `yaml:"algorithms,omitempty"` // Catalyst profile: 2 algorithms

	// Mode: empty/"simple" for single algo, "catalyst" for dual-key
	Mode string `yaml:"mode,omitempty"`

	Validity   string            `yaml:"validity"` // Duration string like "8760h" or "365d"
	Extensions *ExtensionsConfig `yaml:"extensions,omitempty"`

	// Declarative variables for template substitution
	Variables map[string]*Variable `yaml:"variables,omitempty"`

	// Signature optionally overrides the signature algorithm configuration
	Signature *SignatureAlgoConfig `yaml:"signature,omitempty"`
}

// LoadProfileFromFile loads a profile from a YAML file.
func LoadProfileFromFile(path string) (*Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read profile file: %w", err)
	}

	return LoadProfileFromBytes(data)
}

// LoadProfileFromBytes loads a profile from YAML bytes.
func LoadProfileFromBytes(data []byte) (*Profile, error) {
	var py profileYAML
	if err := yaml.Unmarshal(data, &py); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	return profileYAMLToProfile(&py)
}

// profileYAMLToProfile converts the YAML representation to a Profile.
func profileYAMLToProfile(py *profileYAML) (*Profile, error) {
	p := &Profile{
		Name:        py.Name,
		Description: py.Description,
		Extensions:  py.Extensions,
		Variables:   py.Variables,
		Signature:   py.Signature,
	}

	// Copy subject configuration (new format: flat map with templates)
	// The subject map contains template strings like "{{ cn }}" that will
	// be resolved at enrollment time using the TemplateEngine.
	if len(py.Subject) > 0 {
		p.Subject = &SubjectConfig{
			Fixed: py.Subject,
		}
	}

	// Set variable names from map keys
	for name, v := range p.Variables {
		v.Name = name
	}

	// Parse algorithm configuration
	if err := parseAlgorithmConfig(py, p); err != nil {
		return nil, fmt.Errorf("algorithm config: %w", err)
	}

	// Parse validity duration
	validity, err := parseDuration(py.Validity)
	if err != nil {
		return nil, fmt.Errorf("invalid validity: %w", err)
	}
	p.Validity = validity

	// Validate the profile
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("profile validation failed: %w", err)
	}

	return p, nil
}

// parseAlgorithmConfig parses algorithm configuration from YAML.
func parseAlgorithmConfig(py *profileYAML, p *Profile) error {
	// Determine mode
	mode := Mode(py.Mode)
	if mode == "" {
		mode = ModeSimple
	}

	// Check for conflicting configuration
	if py.Algorithm != "" && len(py.Algorithms) > 0 {
		return fmt.Errorf("cannot specify both 'algorithm' and 'algorithms'")
	}

	switch mode {
	case ModeSimple, "":
		// Simple mode: use 'algorithm' field or first element of 'algorithms'
		if py.Algorithm != "" {
			p.Algorithm = crypto.AlgorithmID(py.Algorithm)
		} else if len(py.Algorithms) > 0 {
			p.Algorithm = crypto.AlgorithmID(py.Algorithms[0])
		} else {
			return fmt.Errorf("algorithm is required")
		}
		p.Mode = ModeSimple

	case ModeCatalyst, ModeComposite:
		// Catalyst/Composite mode: requires exactly 2 algorithms in 'algorithms' list
		if len(py.Algorithms) != 2 {
			return fmt.Errorf("%s mode requires exactly 2 algorithms in 'algorithms' list, got %d", mode, len(py.Algorithms))
		}
		p.Algorithms = make([]crypto.AlgorithmID, 2)
		p.Algorithms[0] = crypto.AlgorithmID(py.Algorithms[0])
		p.Algorithms[1] = crypto.AlgorithmID(py.Algorithms[1])
		p.Mode = mode

	default:
		return fmt.Errorf("invalid mode: %q (expected 'simple', 'catalyst', or 'composite')", py.Mode)
	}

	return nil
}

// parseDuration parses a duration string that can include days.
// Supported formats: "8760h", "365d", "1y", "30d12h"
func parseDuration(s string) (time.Duration, error) {
	if s == "" {
		return 0, fmt.Errorf("duration is empty")
	}

	// Try standard Go duration first
	if d, err := time.ParseDuration(s); err == nil {
		return d, nil
	}

	// Handle custom formats with days/years
	var total time.Duration
	remaining := s

	// Parse years
	if idx := findSuffix(remaining, "y"); idx >= 0 {
		years, err := parseInt(remaining[:idx])
		if err != nil {
			return 0, fmt.Errorf("invalid years: %w", err)
		}
		total += time.Duration(years) * 365 * 24 * time.Hour
		remaining = remaining[idx+1:]
	}

	// Parse days
	if idx := findSuffix(remaining, "d"); idx >= 0 {
		days, err := parseInt(remaining[:idx])
		if err != nil {
			return 0, fmt.Errorf("invalid days: %w", err)
		}
		total += time.Duration(days) * 24 * time.Hour
		remaining = remaining[idx+1:]
	}

	// Parse remaining as standard duration
	if remaining != "" {
		d, err := time.ParseDuration(remaining)
		if err != nil {
			return 0, fmt.Errorf("invalid duration: %w", err)
		}
		total += d
	}

	return total, nil
}

func findSuffix(s, suffix string) int {
	for i := 0; i < len(s); i++ {
		if s[i:i+1] == suffix {
			return i
		}
	}
	return -1
}

func parseInt(s string) (int, error) {
	var n int
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid number: %s", s)
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}

// LoadProfilesFromDirectory loads all profiles from a directory.
// Returns a map of profile name to Profile.
func LoadProfilesFromDirectory(dir string) (map[string]*Profile, error) {
	profiles := make(map[string]*Profile)

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return profiles, nil // Empty directory is OK
		}
		return nil, fmt.Errorf("failed to read profiles directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			// Recurse into subdirectories
			subdir := filepath.Join(dir, entry.Name())
			subProfiles, err := LoadProfilesFromDirectory(subdir)
			if err != nil {
				return nil, err
			}
			for name, p := range subProfiles {
				if _, exists := profiles[name]; exists {
					return nil, fmt.Errorf("duplicate profile name: %s", name)
				}
				profiles[name] = p
			}
			continue
		}

		name := entry.Name()
		if filepath.Ext(name) != ".yaml" && filepath.Ext(name) != ".yml" {
			continue
		}

		path := filepath.Join(dir, name)
		profile, err := LoadProfileFromFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to load profile from %s: %w", name, err)
		}

		if _, exists := profiles[profile.Name]; exists {
			return nil, fmt.Errorf("duplicate profile name: %s", profile.Name)
		}

		profiles[profile.Name] = profile
	}

	return profiles, nil
}

// SaveProfileToFile saves a profile to a YAML file.
func SaveProfileToFile(p *Profile, path string) error {
	py := profileToYAML(p)

	data, err := yaml.Marshal(py)
	if err != nil {
		return fmt.Errorf("failed to marshal profile: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write profile file: %w", err)
	}

	return nil
}

// profileToYAML converts a Profile to its YAML representation.
func profileToYAML(p *Profile) *profileYAML {
	py := &profileYAML{
		Name:        p.Name,
		Description: p.Description,
		Extensions:  p.Extensions,
		Variables:   p.Variables,
		Signature:   p.Signature,
	}

	// Convert subject (new format: flat map with templates)
	if p.Subject != nil && len(p.Subject.Fixed) > 0 {
		py.Subject = p.Subject.Fixed
	}

	// Convert algorithm configuration
	if p.IsHybrid() {
		py.Mode = string(p.Mode)
		py.Algorithms = make([]string, len(p.Algorithms))
		for i, alg := range p.Algorithms {
			py.Algorithms[i] = string(alg)
		}
	} else {
		py.Algorithm = string(p.GetAlgorithm())
	}

	// Format validity as hours or days
	hours := int(p.Validity.Hours())
	if hours%24 == 0 && hours >= 24 {
		py.Validity = fmt.Sprintf("%dd", hours/24)
	} else {
		py.Validity = p.Validity.String()
	}

	return py
}

// ProfileStore provides access to profiles for a CA.
type ProfileStore struct {
	basePath string
	profiles map[string]*Profile
}

// NewProfileStore creates a new ProfileStore for the given CA path.
func NewProfileStore(caPath string) *ProfileStore {
	return &ProfileStore{
		basePath: filepath.Join(caPath, "profiles"),
		profiles: make(map[string]*Profile),
	}
}

// Load loads all profiles from builtin profiles and CA's profiles directory.
// Custom profiles from the CA directory override builtin profiles with the same name.
func (ps *ProfileStore) Load() error {
	// Start with builtin profiles
	builtins, err := BuiltinProfiles()
	if err != nil {
		return fmt.Errorf("failed to load builtin profiles: %w", err)
	}

	// Copy builtins to profiles map
	for name, p := range builtins {
		ps.profiles[name] = p
	}

	// Load custom profiles (overrides builtins with same name)
	customProfiles, err := LoadProfilesFromDirectory(ps.basePath)
	if err != nil {
		return err
	}

	// Custom profiles override builtins
	for name, p := range customProfiles {
		ps.profiles[name] = p
	}

	return nil
}

// Get returns a profile by name.
func (ps *ProfileStore) Get(name string) (*Profile, bool) {
	p, ok := ps.profiles[name]
	return p, ok
}

// List returns all loaded profile names.
func (ps *ProfileStore) List() []string {
	names := make([]string, 0, len(ps.profiles))
	for name := range ps.profiles {
		names = append(names, name)
	}
	return names
}

// All returns all loaded profiles.
func (ps *ProfileStore) All() map[string]*Profile {
	return ps.profiles
}

// Save saves a profile to the CA's profiles directory.
func (ps *ProfileStore) Save(p *Profile) error {
	// Ensure directory exists
	if err := os.MkdirAll(ps.basePath, 0755); err != nil {
		return fmt.Errorf("failed to create profiles directory: %w", err)
	}

	path := filepath.Join(ps.basePath, p.Name+".yaml")
	if err := SaveProfileToFile(p, path); err != nil {
		return err
	}

	ps.profiles[p.Name] = p
	return nil
}

// BasePath returns the profiles directory path.
func (ps *ProfileStore) BasePath() string {
	return ps.basePath
}
