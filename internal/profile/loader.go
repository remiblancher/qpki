package profile

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/remiblancher/pki/internal/crypto"
	"gopkg.in/yaml.v3"
)

// profileYAML is the YAML representation of a Profile.
// It supports both the new simplified format and the legacy format.
type profileYAML struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`

	// Subject DN configuration (new format)
	Subject *SubjectYAML `yaml:"subject,omitempty"`

	Signature signatureYAML `yaml:"signature"`

	Encryption *encryptionYAML `yaml:"encryption,omitempty"`

	Validity   string            `yaml:"validity"` // Duration string like "8760h" or "365d"
	Extensions *ExtensionsConfig `yaml:"extensions,omitempty"`
}

// SubjectYAML defines subject DN configuration in YAML.
type SubjectYAML struct {
	Fixed    map[string]string `yaml:"fixed,omitempty"`
	Required []string          `yaml:"required,omitempty"`
	Optional []string          `yaml:"optional,omitempty"`
}

// signatureYAML supports both new and legacy signature formats.
type signatureYAML struct {
	// New format - simple mode
	Algorithm string   `yaml:"algorithm,omitempty"`
	KeyUsage  []string `yaml:"keyUsage,omitempty"`

	// New format - hybrid mode
	Mode      string `yaml:"mode,omitempty"`      // "catalyst" or "composite"
	Classical string `yaml:"classical,omitempty"` // e.g. "ec-p256"
	PQC       string `yaml:"pqc,omitempty"`       // e.g. "ml-dsa-65"

	// Legacy format
	Required   bool `yaml:"required,omitempty"`
	Algorithms struct {
		Primary     string `yaml:"primary,omitempty"`
		Alternative string `yaml:"alternative,omitempty"`
	} `yaml:"algorithms,omitempty"`
}

// encryptionYAML supports both new and legacy encryption formats.
type encryptionYAML struct {
	// New format
	Algorithm string   `yaml:"algorithm,omitempty"`
	KeyUsage  []string `yaml:"keyUsage,omitempty"`

	// Legacy format
	Required   bool   `yaml:"required,omitempty"`
	Mode       string `yaml:"mode,omitempty"`
	Algorithms struct {
		Primary     string `yaml:"primary,omitempty"`
		Alternative string `yaml:"alternative,omitempty"`
	} `yaml:"algorithms,omitempty"`
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
// It automatically detects and handles both new and legacy YAML formats.
func profileYAMLToProfile(py *profileYAML) (*Profile, error) {
	p := &Profile{
		Name:        py.Name,
		Description: py.Description,
		Extensions:  py.Extensions,
	}

	// Copy subject configuration
	if py.Subject != nil {
		p.Subject = &SubjectConfig{
			Fixed:    py.Subject.Fixed,
			Required: py.Subject.Required,
			Optional: py.Subject.Optional,
		}
	}

	// Parse signature config - detect format
	if err := parseSignatureConfig(py, p); err != nil {
		return nil, fmt.Errorf("signature config: %w", err)
	}

	// Parse encryption config - detect format
	if err := parseEncryptionConfig(py, p); err != nil {
		return nil, fmt.Errorf("encryption config: %w", err)
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

// parseSignatureConfig parses signature configuration, supporting both formats.
func parseSignatureConfig(py *profileYAML, p *Profile) error {
	sig := &py.Signature

	// Detect format: new format uses "algorithm" or "classical"+"pqc"
	isNewSimpleFormat := sig.Algorithm != ""
	isNewHybridFormat := sig.Classical != "" && sig.PQC != ""
	isLegacyFormat := sig.Algorithms.Primary != ""

	switch {
	case isNewSimpleFormat:
		// New simple format: signature.algorithm + signature.keyUsage
		p.Signature.Required = true
		p.Signature.Mode = SignatureSimple
		p.Signature.Algorithms.Primary = parseAlgorithmID(sig.Algorithm)

	case isNewHybridFormat:
		// New hybrid format: signature.mode + signature.classical + signature.pqc
		p.Signature.Required = true
		mode := sig.Mode
		if mode == "catalyst" {
			p.Signature.Mode = SignatureHybridCombined
		} else if mode == "composite" {
			// Composite also uses combined mode internally
			p.Signature.Mode = SignatureHybridCombined
		} else {
			return fmt.Errorf("unknown hybrid mode: %s (expected 'catalyst' or 'composite')", mode)
		}
		p.Signature.Algorithms.Primary = parseAlgorithmID(sig.Classical)
		p.Signature.Algorithms.Alternative = parseAlgorithmID(sig.PQC)

	case isLegacyFormat:
		// Legacy format: signature.required + signature.mode + signature.algorithms
		p.Signature.Required = sig.Required
		p.Signature.Mode = SignatureMode(sig.Mode)
		p.Signature.Algorithms.Primary = parseAlgorithmID(sig.Algorithms.Primary)
		p.Signature.Algorithms.Alternative = parseAlgorithmID(sig.Algorithms.Alternative)

	default:
		return fmt.Errorf("invalid signature configuration: no algorithm specified")
	}

	return nil
}

// parseEncryptionConfig parses encryption configuration, supporting both formats.
func parseEncryptionConfig(py *profileYAML, p *Profile) error {
	enc := py.Encryption

	// No encryption section means no encryption required
	if enc == nil {
		p.Encryption.Required = false
		p.Encryption.Mode = EncryptionNone
		return nil
	}

	// Detect format: new format uses "algorithm"
	isNewFormat := enc.Algorithm != ""
	isLegacyFormat := enc.Algorithms.Primary != "" || enc.Required

	switch {
	case isNewFormat:
		// New format: encryption.algorithm + encryption.keyUsage
		p.Encryption.Required = true
		p.Encryption.Mode = EncryptionSimple
		p.Encryption.Algorithms.Primary = parseAlgorithmID(enc.Algorithm)

	case isLegacyFormat:
		// Legacy format
		p.Encryption.Required = enc.Required
		p.Encryption.Mode = EncryptionMode(enc.Mode)
		p.Encryption.Algorithms.Primary = parseAlgorithmID(enc.Algorithms.Primary)
		p.Encryption.Algorithms.Alternative = parseAlgorithmID(enc.Algorithms.Alternative)

	default:
		// Empty encryption section - no encryption
		p.Encryption.Required = false
		p.Encryption.Mode = EncryptionNone
	}

	return nil
}

// parseAlgorithmID converts a string to an AlgorithmID.
// Accepts various formats: "ecdsa-p256", "ECDSA-P256", "ml-dsa-65", etc.
func parseAlgorithmID(s string) crypto.AlgorithmID {
	if s == "" {
		return ""
	}
	return crypto.AlgorithmID(s)
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
// Uses the new simplified format for output.
func profileToYAML(p *Profile) *profileYAML {
	py := &profileYAML{
		Name:        p.Name,
		Description: p.Description,
		Extensions:  p.Extensions,
	}

	// Convert signature to new format
	if p.IsHybridSignature() {
		py.Signature.Mode = "catalyst" // Default to catalyst for hybrid
		if p.Signature.Mode == SignatureHybridSeparate {
			py.Signature.Mode = "separate"
		}
		py.Signature.Classical = string(p.Signature.Algorithms.Primary)
		py.Signature.PQC = string(p.Signature.Algorithms.Alternative)
	} else {
		py.Signature.Algorithm = string(p.Signature.Algorithms.Primary)
	}

	// Convert encryption to new format
	if p.Encryption.Required && p.Encryption.Mode != EncryptionNone {
		py.Encryption = &encryptionYAML{
			Algorithm: string(p.Encryption.Algorithms.Primary),
		}
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
