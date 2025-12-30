// Package profile provides certificate profiles for the PKI.
//
// A profile defines a complete certificate enrollment policy including:
//   - Algorithm choice (1 algo = simple, 2 algos = Catalyst)
//   - Validity period
//   - X.509 extensions
//
// Design principle: 1 Profile = 1 Certificate
// Bundles are created by combining multiple profiles via --profiles flag.
package profile

import (
	"fmt"
	"time"

	"github.com/remiblancher/post-quantum-pki/internal/crypto"
)

// Mode defines how a certificate is configured.
type Mode string

const (
	// ModeSimple uses a single algorithm (signature or KEM).
	ModeSimple Mode = "simple"

	// ModeCatalyst uses two algorithms in a single dual-key certificate
	// (ITU-T X.509 Section 9.8).
	ModeCatalyst Mode = "catalyst"

	// ModeComposite uses two algorithms in IETF composite format
	// (draft-ounsworth-pq-composite-sigs). Both signatures must validate.
	ModeComposite Mode = "composite"
)

// SubjectConfig defines subject DN configuration.
// With the declarative variable format, subject fields use {{ variable }} templates
// that are resolved at enrollment time. Required/optional constraints are defined
// in the variables section of the profile.
type SubjectConfig struct {
	// Fixed contains DN attribute templates (e.g., "cn": "{{ cn }}", "o": "ACME").
	// Template variables like {{ cn }} are resolved using the profile's variables.
	// Static values (without {{ }}) are used as-is.
	Fixed map[string]string `yaml:"fixed,omitempty" json:"fixed,omitempty"`
}

// Profile defines a certificate type.
// Design: 1 profile = 1 certificate.
// Use multiple profiles to create bundles.
type Profile struct {
	// Name is the unique identifier for this profile.
	Name string `yaml:"name" json:"name"`

	// Description provides a human-readable description.
	Description string `yaml:"description" json:"description"`

	// Subject defines the subject DN configuration.
	Subject *SubjectConfig `yaml:"subject,omitempty" json:"subject,omitempty"`

	// Algorithm is the single algorithm for simple profiles.
	// Used when Mode is empty or "simple".
	Algorithm crypto.AlgorithmID `yaml:"algorithm,omitempty" json:"algorithm,omitempty"`

	// Algorithms is the list of algorithms for Catalyst profiles (exactly 2).
	// First is classical, second is PQC.
	Algorithms []crypto.AlgorithmID `yaml:"algorithms,omitempty" json:"algorithms,omitempty"`

	// Mode defines how the certificate is configured.
	// Empty or "simple" = single algorithm, "catalyst" = dual-key.
	Mode Mode `yaml:"mode,omitempty" json:"mode,omitempty"`

	// Validity is the default certificate validity period.
	Validity time.Duration `yaml:"validity" json:"validity"`

	// Extensions defines X.509 extensions with configurable criticality.
	Extensions *ExtensionsConfig `yaml:"extensions,omitempty" json:"extensions,omitempty"`

	// Variables defines declarative input variables for the profile.
	// Variables are declared in YAML and can be referenced in templates using {{ var }}.
	Variables map[string]*Variable `yaml:"variables,omitempty" json:"variables,omitempty"`

	// Signature optionally overrides the signature algorithm configuration.
	// If not specified, values are inferred from the key algorithm.
	Signature *SignatureAlgoConfig `yaml:"signature,omitempty" json:"signature,omitempty"`
}

// Validate checks that the profile configuration is valid.
func (p *Profile) Validate() error {
	if p.Name == "" {
		return fmt.Errorf("profile name is required")
	}

	// Validate algorithm configuration
	if err := p.validateAlgorithm(); err != nil {
		return fmt.Errorf("algorithm config: %w", err)
	}

	// Validate validity
	if p.Validity <= 0 {
		return fmt.Errorf("validity must be positive")
	}

	return nil
}

func (p *Profile) validateAlgorithm() error {
	switch p.Mode {
	case "", ModeSimple:
		// Simple mode: single algorithm required
		if p.Algorithm == "" && len(p.Algorithms) == 0 {
			return fmt.Errorf("algorithm is required")
		}
		if p.Algorithm != "" && !p.Algorithm.IsValid() {
			return fmt.Errorf("invalid algorithm: %s", p.Algorithm)
		}
		// If algorithms list is used, only first one matters for simple mode
		if len(p.Algorithms) > 0 && !p.Algorithms[0].IsValid() {
			return fmt.Errorf("invalid algorithm: %s", p.Algorithms[0])
		}

	case ModeCatalyst, ModeComposite:
		// Catalyst/Composite mode: exactly 2 algorithms required
		if len(p.Algorithms) != 2 {
			return fmt.Errorf("%s mode requires exactly 2 algorithms, got %d", p.Mode, len(p.Algorithms))
		}
		if !p.Algorithms[0].IsValid() {
			return fmt.Errorf("invalid classical algorithm: %s", p.Algorithms[0])
		}
		if !p.Algorithms[1].IsValid() {
			return fmt.Errorf("invalid PQC algorithm: %s", p.Algorithms[1])
		}
		// First should be classical, second should be PQC
		if p.Algorithms[0].IsPQC() && !p.Algorithms[0].IsKEM() {
			return fmt.Errorf("first algorithm should be classical for %s (got %s)", p.Mode, p.Algorithms[0])
		}
		if !p.Algorithms[1].IsPQC() {
			return fmt.Errorf("second algorithm should be PQC for %s (got %s)", p.Mode, p.Algorithms[1])
		}

	default:
		return fmt.Errorf("invalid mode: %s (expected 'simple', 'catalyst', or 'composite')", p.Mode)
	}

	return nil
}

// GetAlgorithm returns the primary algorithm for this profile.
// For simple mode, returns Algorithm or Algorithms[0].
// For catalyst mode, returns Algorithms[0] (classical).
func (p *Profile) GetAlgorithm() crypto.AlgorithmID {
	if len(p.Algorithms) > 0 {
		return p.Algorithms[0]
	}
	return p.Algorithm
}

// GetAlternativeAlgorithm returns the second algorithm if present.
// Returns empty if there is only one algorithm.
func (p *Profile) GetAlternativeAlgorithm() crypto.AlgorithmID {
	if len(p.Algorithms) > 1 {
		return p.Algorithms[1]
	}
	return ""
}

// IsCatalyst returns true if this is a Catalyst (dual-key) profile.
func (p *Profile) IsCatalyst() bool {
	return p.Mode == ModeCatalyst && len(p.Algorithms) == 2
}

// IsComposite returns true if this is an IETF composite profile.
func (p *Profile) IsComposite() bool {
	return p.Mode == ModeComposite && len(p.Algorithms) == 2
}

// IsHybrid returns true if this is a hybrid profile (catalyst or composite).
func (p *Profile) IsHybrid() bool {
	return p.IsCatalyst() || p.IsComposite()
}

// IsKEM returns true if this profile is for a KEM certificate.
func (p *Profile) IsKEM() bool {
	return p.GetAlgorithm().IsKEM()
}

// IsSignature returns true if this profile is for a signature certificate.
func (p *Profile) IsSignature() bool {
	alg := p.GetAlgorithm()
	return !alg.IsKEM() && alg != ""
}

// String returns a human-readable summary of the profile.
func (p *Profile) String() string {
	var algoDesc string
	if p.IsCatalyst() {
		algoDesc = fmt.Sprintf("catalyst (%s + %s)", p.Algorithms[0], p.Algorithms[1])
	} else if p.IsComposite() {
		algoDesc = fmt.Sprintf("composite (%s + %s)", p.Algorithms[0], p.Algorithms[1])
	} else {
		algoDesc = string(p.GetAlgorithm())
	}

	return fmt.Sprintf("Profile[%s]: algo=%s, validity=%s", p.Name, algoDesc, p.Validity)
}

// CertificateCount returns 1 (each profile produces exactly one certificate).
func (p *Profile) CertificateCount() int {
	return 1
}
