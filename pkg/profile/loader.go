package profile

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/remiblancher/qpki/pkg/crypto"
	"gopkg.in/yaml.v3"
)

// loaderTemplateVarRegex matches {{ variable_name }} patterns for template detection.
var loaderTemplateVarRegex = regexp.MustCompile(`\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\}\}`)

// containsTemplate returns true if the string contains a {{ variable }} template.
func containsTemplate(s string) bool {
	return loaderTemplateVarRegex.MatchString(s)
}

// profileYAML is the YAML representation of a Profile.
// Supports both simple (1 algo) and Catalyst (2 algos) profiles.
type profileYAML struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`

	// Subject DN configuration with optional per-attribute encoding.
	// Supports two formats:
	//   Simple: cn: "{{ cn }}"
	//   With encoding: cn: { value: "{{ cn }}", encoding: printable }
	Subject *subjectYAML `yaml:"subject,omitempty"`

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

// subjectYAML handles flexible YAML parsing for subject DN configuration.
// Attributes can be either strings or objects with value/encoding fields.
type subjectYAML struct {
	Attrs map[string]interface{} `yaml:"-"` // Populated during UnmarshalYAML
}

// UnmarshalYAML implements custom unmarshaling to handle mixed attribute formats.
func (s *subjectYAML) UnmarshalYAML(value *yaml.Node) error {
	s.Attrs = make(map[string]interface{})

	if value.Kind != yaml.MappingNode {
		return fmt.Errorf("subject must be a mapping")
	}

	// Process key-value pairs
	for i := 0; i < len(value.Content); i += 2 {
		keyNode := value.Content[i]
		valNode := value.Content[i+1]

		key := keyNode.Value

		// Handle attribute value (string or object)
		switch valNode.Kind {
		case yaml.ScalarNode:
			// Simple format: cn: "value"
			s.Attrs[key] = valNode.Value
		case yaml.MappingNode:
			// Extended format: cn: { value: "...", encoding: "..." }
			var attr SubjectAttribute
			if err := valNode.Decode(&attr); err != nil {
				return fmt.Errorf("invalid attribute %q: %w", key, err)
			}
			s.Attrs[key] = &attr
		default:
			return fmt.Errorf("invalid attribute %q: must be string or object", key)
		}
	}

	return nil
}

// parseSubjectConfig converts subjectYAML to SubjectConfig.
func parseSubjectConfig(sy *subjectYAML) *SubjectConfig {
	cfg := &SubjectConfig{
		Fixed: make(map[string]string),
		Attrs: make(map[string]*SubjectAttribute),
	}

	for key, val := range sy.Attrs {
		switch v := val.(type) {
		case string:
			// Simple format: store in both Fixed (for compatibility) and Attrs
			cfg.Fixed[key] = v
			cfg.Attrs[key] = &SubjectAttribute{Value: v}
		case *SubjectAttribute:
			// Extended format with encoding
			cfg.Fixed[key] = v.Value
			cfg.Attrs[key] = v
		}
	}

	return cfg
}

// subjectConfigToYAML converts SubjectConfig back to subjectYAML for serialization.
func subjectConfigToYAML(cfg *SubjectConfig) *subjectYAML {
	sy := &subjectYAML{
		Attrs: make(map[string]interface{}),
	}

	// Use Attrs if available (preserves encoding info), else use Fixed
	if len(cfg.Attrs) > 0 {
		for key, attr := range cfg.Attrs {
			if attr.Encoding != "" {
				// Has explicit encoding, use extended format
				sy.Attrs[key] = attr
			} else {
				// No explicit encoding, use simple format
				sy.Attrs[key] = attr.Value
			}
		}
	} else {
		// Legacy: use Fixed map
		for key, val := range cfg.Fixed {
			sy.Attrs[key] = val
		}
	}

	return sy
}

// MarshalYAML implements custom marshaling for subjectYAML.
func (s *subjectYAML) MarshalYAML() (interface{}, error) {
	// Build a map that can be marshaled to YAML
	result := make(map[string]interface{})

	for key, val := range s.Attrs {
		result[key] = val
	}

	return result, nil
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

	// Copy subject configuration with encoding support
	if py.Subject != nil && len(py.Subject.Attrs) > 0 {
		p.Subject = parseSubjectConfig(py.Subject)

		// Validate RFC 5280 encoding requirements
		if err := ValidateSubjectEncoding(p.Subject); err != nil {
			return nil, fmt.Errorf("subject encoding: %w", err)
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

	// Parse validity duration (or store template for later resolution)
	if containsTemplate(py.Validity) {
		p.ValidityTemplate = py.Validity
		p.Validity = 0 // Will be resolved at enrollment time
	} else {
		validity, err := parseDuration(py.Validity)
		if err != nil {
			return nil, fmt.Errorf("invalid validity: %w", err)
		}
		p.Validity = validity
	}

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
	py := ProfileToYAML(p)

	data, err := yaml.Marshal(py)
	if err != nil {
		return fmt.Errorf("failed to marshal profile: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write profile file: %w", err)
	}

	return nil
}

// ProfileToYAML converts a Profile to its YAML representation.
func ProfileToYAML(p *Profile) *profileYAML {
	py := &profileYAML{
		Name:        p.Name,
		Description: p.Description,
		Extensions:  p.Extensions,
		Variables:   p.Variables,
		Signature:   p.Signature,
	}

	// Convert subject configuration
	if p.Subject != nil && (len(p.Subject.Fixed) > 0 || len(p.Subject.Attrs) > 0) {
		py.Subject = subjectConfigToYAML(p.Subject)
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

	// Format validity as hours or days (or preserve template)
	if p.ValidityTemplate != "" {
		py.Validity = p.ValidityTemplate
	} else {
		hours := int(p.Validity.Hours())
		if hours%24 == 0 && hours >= 24 {
			py.Validity = fmt.Sprintf("%dd", hours/24)
		} else {
			py.Validity = p.Validity.String()
		}
	}

	return py
}

// Store provides access to certificate profiles.
type Store interface {
	Load() error
	Get(name string) (*Profile, bool)
	List() []string
	All() map[string]*Profile
	Save(p *Profile) error
	BasePath() string
}

// FileStore implements Store using the filesystem.
type FileStore struct {
	basePath string
	profiles map[string]*Profile
}

// Compile-time interface check.
var _ Store = (*FileStore)(nil)

// NewFileStore creates a new file-based profile store.
func NewFileStore(caPath string) *FileStore {
	return &FileStore{
		basePath: filepath.Join(caPath, "profiles"),
		profiles: make(map[string]*Profile),
	}
}

// NewProfileStore creates a new profile store (alias for NewFileStore).
// Deprecated: Use NewFileStore for explicit type.
func NewProfileStore(caPath string) *FileStore {
	return NewFileStore(caPath)
}

// Load loads all profiles from builtin profiles and CA's profiles directory.
// Custom profiles from the CA directory override builtin profiles with the same name.
func (s *FileStore) Load() error {
	// Start with builtin profiles
	builtins, err := BuiltinProfiles()
	if err != nil {
		return fmt.Errorf("failed to load builtin profiles: %w", err)
	}

	// Copy builtins to profiles map
	for name, p := range builtins {
		s.profiles[name] = p
	}

	// Load custom profiles (overrides builtins with same name)
	customProfiles, err := LoadProfilesFromDirectory(s.basePath)
	if err != nil {
		return err
	}

	// Custom profiles override builtins
	for name, p := range customProfiles {
		s.profiles[name] = p
	}

	return nil
}

// Get returns a profile by name.
func (s *FileStore) Get(name string) (*Profile, bool) {
	p, ok := s.profiles[name]
	return p, ok
}

// List returns all loaded profile names.
func (s *FileStore) List() []string {
	names := make([]string, 0, len(s.profiles))
	for name := range s.profiles {
		names = append(names, name)
	}
	return names
}

// All returns all loaded profiles.
func (s *FileStore) All() map[string]*Profile {
	return s.profiles
}

// Save saves a profile to the CA's profiles directory.
func (s *FileStore) Save(p *Profile) error {
	// Ensure directory exists
	if err := os.MkdirAll(s.basePath, 0755); err != nil {
		return fmt.Errorf("failed to create profiles directory: %w", err)
	}

	path := filepath.Join(s.basePath, p.Name+".yaml")
	if err := SaveProfileToFile(p, path); err != nil {
		return err
	}

	s.profiles[p.Name] = p
	return nil
}

// BasePath returns the profiles directory path.
func (s *FileStore) BasePath() string {
	return s.basePath
}
