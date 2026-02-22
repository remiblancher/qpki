// Package pki provides the public API for qpki.
// This file exposes profile operations from internal/profile.
package pki

import (
	"crypto/x509/pkix"
	"time"

	"github.com/remiblancher/qpki/internal/profile"
)

// Re-export types from internal/profile
type (
	// ProfileDef represents a certificate profile definition.
	ProfileDef = profile.Profile

	// Profile is an alias for ProfileDef for compatibility.
	Profile = profile.Profile

	// VariableValues holds profile variable values.
	VariableValues = profile.VariableValues

	// ExtensionsConfig holds certificate extension configuration.
	ExtensionsConfig = profile.ExtensionsConfig

	// BasicConstraintsConfig holds basic constraints configuration.
	BasicConstraintsConfig = profile.BasicConstraintsConfig

	// KeyUsageConfig holds key usage configuration.
	KeyUsageConfig = profile.KeyUsageConfig

	// ExtKeyUsageConfig holds extended key usage configuration.
	ExtKeyUsageConfig = profile.ExtKeyUsageConfig

	// SubjectAltNameConfig holds SAN configuration.
	SubjectAltNameConfig = profile.SubjectAltNameConfig

	// ProfileError wraps profile errors.
	ProfileError = profile.ProfileError

	// ProfileValidationError represents a validation error.
	ProfileValidationError = profile.ValidationError
)

// LoadProfile loads a profile by name.
func LoadProfile(name string) (*ProfileDef, error) {
	return profile.LoadProfile(name)
}

// ListProfiles lists all available profile names.
func ListProfiles() ([]string, error) {
	return profile.ListBuiltinProfileNames()
}

// BuildSubjectFromProfile builds a pkix.Name from profile and variables.
func BuildSubjectFromProfile(prof *ProfileDef, vars VariableValues) (pkix.Name, error) {
	return profile.BuildSubjectFromProfile(prof, vars)
}

// ResolveProfileExtensions resolves profile extensions with variables.
func ResolveProfileExtensions(prof *ProfileDef, vars VariableValues) (*ExtensionsConfig, error) {
	return profile.ResolveProfileExtensions(prof, vars)
}

// GetProfileValidity returns the profile's validity duration.
func GetProfileValidity(prof *ProfileDef) time.Duration {
	return prof.Validity
}

// GetProfileAlgorithm returns the profile's algorithm.
func GetProfileAlgorithm(prof *ProfileDef) AlgorithmID {
	return AlgorithmID(prof.GetAlgorithm())
}

// GetProfileMode returns the profile's issuance mode.
func GetProfileMode(prof *ProfileDef) string {
	return string(prof.Mode)
}

// LoadProfileFromBytes loads a profile from YAML bytes.
func LoadProfileFromBytes(data []byte) (*Profile, error) {
	return profile.LoadProfileFromBytes(data)
}
