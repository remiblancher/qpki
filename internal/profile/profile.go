// Package profile provides certificate profiles for the PKI.
//
// A profile defines a complete certificate enrollment policy including:
//   - Signature requirements (simple or hybrid)
//   - Encryption requirements (none, simple, or hybrid)
//   - Algorithm choices
//   - Validity period
//   - X.509 extensions
//
// Profiles are stored as YAML files within the CA directory and can be
// predefined (shipped with the PKI) or custom (created by administrators).
package profile

import (
	"fmt"
	"time"

	"github.com/remiblancher/pki/internal/crypto"
)

// SignatureMode defines how signature certificates are configured.
type SignatureMode string

const (
	// SignatureSimple uses a single signature algorithm.
	SignatureSimple SignatureMode = "simple"

	// SignatureHybridCombined uses both classical and PQC algorithms in a single
	// Catalyst certificate (ITU-T X.509 Section 9.8).
	SignatureHybridCombined SignatureMode = "hybrid-combined"

	// SignatureHybridSeparate uses two separate certificates (classical and PQC)
	// linked via RelatedCertificate extension.
	SignatureHybridSeparate SignatureMode = "hybrid-separate"
)

// EncryptionMode defines how encryption certificates are configured.
type EncryptionMode string

const (
	// EncryptionNone means no encryption certificate is issued.
	EncryptionNone EncryptionMode = "none"

	// EncryptionSimple uses a single encryption algorithm.
	EncryptionSimple EncryptionMode = "simple"

	// EncryptionHybridCombined uses both classical and PQC KEM in a single
	// Catalyst certificate.
	EncryptionHybridCombined EncryptionMode = "hybrid-combined"

	// EncryptionHybridSeparate uses two separate KEM certificates
	// linked via RelatedCertificate extension.
	EncryptionHybridSeparate EncryptionMode = "hybrid-separate"
)

// SignatureConfig defines the signature certificate configuration.
type SignatureConfig struct {
	// Required indicates if a signature certificate is required (always true in practice).
	Required bool `yaml:"required" json:"required"`

	// Mode defines how signature certificates are configured.
	Mode SignatureMode `yaml:"mode" json:"mode"`

	// Algorithms specifies the algorithms to use.
	// For simple mode: only Primary is used.
	// For hybrid modes: both Primary (classical) and Alternative (PQC) are used.
	Algorithms AlgorithmPair `yaml:"algorithms" json:"algorithms"`

	// AlgoConfig specifies the detailed signature algorithm configuration.
	// Includes hash algorithm, signature scheme (ECDSA, RSA-PSS, etc.), and parameters.
	// If nil, defaults are inferred from the key type in Algorithms.Primary.
	AlgoConfig *SignatureAlgoConfig `yaml:"algo_config,omitempty" json:"algo_config,omitempty"`

	// AltAlgoConfig specifies the signature algorithm configuration for the alternative
	// (PQC) key in hybrid modes. Only used when Mode is hybrid-combined or hybrid-separate.
	// For PQC algorithms, this is typically nil as they have integrated hash functions.
	AltAlgoConfig *SignatureAlgoConfig `yaml:"alt_algo_config,omitempty" json:"alt_algo_config,omitempty"`
}

// EncryptionConfig defines the encryption certificate configuration.
type EncryptionConfig struct {
	// Required indicates if an encryption certificate is required.
	Required bool `yaml:"required" json:"required"`

	// Mode defines how encryption certificates are configured.
	Mode EncryptionMode `yaml:"mode" json:"mode"`

	// Algorithms specifies the algorithms to use.
	Algorithms AlgorithmPair `yaml:"algorithms" json:"algorithms"`
}

// AlgorithmPair holds primary and alternative algorithms.
type AlgorithmPair struct {
	// Primary is the main algorithm (classical for hybrid, or the only one for simple).
	Primary crypto.AlgorithmID `yaml:"primary" json:"primary"`

	// Alternative is the secondary algorithm (PQC for hybrid).
	Alternative crypto.AlgorithmID `yaml:"alternative,omitempty" json:"alternative,omitempty"`
}

// SubjectConfig defines subject DN configuration.
type SubjectConfig struct {
	// Fixed contains fixed DN attributes (e.g., "c": "FR", "o": "ACME").
	Fixed map[string]string `yaml:"fixed,omitempty" json:"fixed,omitempty"`

	// Required lists DN attributes that must be provided.
	Required []string `yaml:"required,omitempty" json:"required,omitempty"`

	// Optional lists DN attributes that may be provided.
	Optional []string `yaml:"optional,omitempty" json:"optional,omitempty"`
}

// Profile defines a complete certificate enrollment policy.
// It specifies what certificates should be issued for a subject and with what algorithms.
type Profile struct {
	// Name is the unique identifier for this profile.
	Name string `yaml:"name" json:"name"`

	// Description provides a human-readable description.
	Description string `yaml:"description" json:"description"`

	// Subject defines the subject DN configuration.
	// Fixed values are used as defaults, CLI flags can override them.
	Subject *SubjectConfig `yaml:"subject,omitempty" json:"subject,omitempty"`

	// Signature defines the signature certificate configuration.
	Signature SignatureConfig `yaml:"signature" json:"signature"`

	// Encryption defines the encryption certificate configuration.
	Encryption EncryptionConfig `yaml:"encryption" json:"encryption"`

	// Validity is the default certificate validity period.
	Validity time.Duration `yaml:"validity" json:"validity"`

	// Extensions defines X.509 extensions with configurable criticality.
	// If nil, no extensions are applied (explicit configuration only).
	Extensions *ExtensionsConfig `yaml:"extensions,omitempty" json:"extensions,omitempty"`
}

// Validate checks that the profile configuration is valid.
func (p *Profile) Validate() error {
	if p.Name == "" {
		return fmt.Errorf("profile name is required")
	}

	// Validate signature configuration
	if err := p.validateSignature(); err != nil {
		return fmt.Errorf("signature config: %w", err)
	}

	// Validate encryption configuration
	if err := p.validateEncryption(); err != nil {
		return fmt.Errorf("encryption config: %w", err)
	}

	// Validate validity
	if p.Validity <= 0 {
		return fmt.Errorf("validity must be positive")
	}

	return nil
}

func (p *Profile) validateSignature() error {
	if !p.Signature.Required {
		// Signature is always required (CSR needs signature)
		return fmt.Errorf("signature is always required")
	}

	switch p.Signature.Mode {
	case SignatureSimple:
		if p.Signature.Algorithms.Primary == "" {
			return fmt.Errorf("primary algorithm is required for simple mode")
		}
		if !p.Signature.Algorithms.Primary.IsValid() {
			return fmt.Errorf("invalid primary algorithm: %s", p.Signature.Algorithms.Primary)
		}

	case SignatureHybridCombined, SignatureHybridSeparate:
		if p.Signature.Algorithms.Primary == "" {
			return fmt.Errorf("primary (classical) algorithm is required for hybrid mode")
		}
		if p.Signature.Algorithms.Alternative == "" {
			return fmt.Errorf("alternative (PQC) algorithm is required for hybrid mode")
		}
		if !p.Signature.Algorithms.Primary.IsValid() {
			return fmt.Errorf("invalid primary algorithm: %s", p.Signature.Algorithms.Primary)
		}
		if !p.Signature.Algorithms.Alternative.IsValid() {
			return fmt.Errorf("invalid alternative algorithm: %s", p.Signature.Algorithms.Alternative)
		}
		// For hybrid signature, primary should be classical and alternative should be PQC
		if p.Signature.Algorithms.Primary.IsPQC() {
			return fmt.Errorf("primary algorithm should be classical for hybrid signature")
		}
		if !p.Signature.Algorithms.Alternative.IsPQC() {
			return fmt.Errorf("alternative algorithm should be PQC for hybrid signature")
		}

	default:
		return fmt.Errorf("invalid signature mode: %s", p.Signature.Mode)
	}

	// Validate algo config if specified
	if p.Signature.AlgoConfig != nil {
		if err := p.Signature.AlgoConfig.Validate(); err != nil {
			return fmt.Errorf("algo_config: %w", err)
		}
	}

	// Validate alt algo config if specified
	if p.Signature.AltAlgoConfig != nil {
		if p.Signature.Mode == SignatureSimple {
			return fmt.Errorf("alt_algo_config only valid for hybrid modes")
		}
		if err := p.Signature.AltAlgoConfig.Validate(); err != nil {
			return fmt.Errorf("alt_algo_config: %w", err)
		}
	}

	return nil
}

// GetResolvedAlgoConfig returns the resolved signature algorithm configuration
// for the primary key. If AlgoConfig is nil, it creates a default based on
// the primary algorithm.
func (p *Profile) GetResolvedAlgoConfig() (*SignatureAlgoConfig, []string) {
	if p.Signature.AlgoConfig != nil {
		return p.Signature.AlgoConfig.Resolve()
	}

	// Create default config from primary algorithm
	defaultConfig := &SignatureAlgoConfig{
		Key: p.Signature.Algorithms.Primary,
	}
	return defaultConfig.Resolve()
}

// GetResolvedAltAlgoConfig returns the resolved signature algorithm configuration
// for the alternative (PQC) key in hybrid modes. Returns nil for simple mode.
func (p *Profile) GetResolvedAltAlgoConfig() (*SignatureAlgoConfig, []string) {
	if p.Signature.Mode == SignatureSimple {
		return nil, nil
	}

	if p.Signature.AltAlgoConfig != nil {
		return p.Signature.AltAlgoConfig.Resolve()
	}

	// Create default config from alternative algorithm
	// For PQC algorithms, this will have empty scheme/hash (integrated)
	defaultConfig := &SignatureAlgoConfig{
		Key: p.Signature.Algorithms.Alternative,
	}
	return defaultConfig.Resolve()
}

func (p *Profile) validateEncryption() error {
	if !p.Encryption.Required {
		if p.Encryption.Mode != EncryptionNone && p.Encryption.Mode != "" {
			return fmt.Errorf("mode should be 'none' or empty when encryption is not required")
		}
		return nil
	}

	switch p.Encryption.Mode {
	case EncryptionNone:
		// Valid - no encryption

	case EncryptionSimple:
		if p.Encryption.Algorithms.Primary == "" {
			return fmt.Errorf("primary algorithm is required for simple encryption")
		}
		if !p.Encryption.Algorithms.Primary.IsValid() {
			return fmt.Errorf("invalid encryption algorithm: %s", p.Encryption.Algorithms.Primary)
		}

	case EncryptionHybridCombined, EncryptionHybridSeparate:
		if p.Encryption.Algorithms.Primary == "" {
			return fmt.Errorf("primary algorithm is required for hybrid encryption")
		}
		if p.Encryption.Algorithms.Alternative == "" {
			return fmt.Errorf("alternative algorithm is required for hybrid encryption")
		}
		if !p.Encryption.Algorithms.Primary.IsValid() {
			return fmt.Errorf("invalid primary encryption algorithm: %s", p.Encryption.Algorithms.Primary)
		}
		if !p.Encryption.Algorithms.Alternative.IsValid() {
			return fmt.Errorf("invalid alternative encryption algorithm: %s", p.Encryption.Algorithms.Alternative)
		}

	default:
		return fmt.Errorf("invalid encryption mode: %s", p.Encryption.Mode)
	}

	return nil
}

// CertificateCount returns the number of certificates that will be issued
// for this profile.
func (p *Profile) CertificateCount() int {
	count := 0

	// Signature certificates
	switch p.Signature.Mode {
	case SignatureSimple, SignatureHybridCombined:
		count += 1
	case SignatureHybridSeparate:
		count += 2
	}

	// Encryption certificates
	if p.Encryption.Required {
		switch p.Encryption.Mode {
		case EncryptionSimple, EncryptionHybridCombined:
			count += 1
		case EncryptionHybridSeparate:
			count += 2
		}
	}

	return count
}

// IsHybridSignature returns true if the profile uses hybrid signature.
func (p *Profile) IsHybridSignature() bool {
	return p.Signature.Mode == SignatureHybridCombined || p.Signature.Mode == SignatureHybridSeparate
}

// IsCatalystSignature returns true if signature uses Catalyst (combined hybrid).
func (p *Profile) IsCatalystSignature() bool {
	return p.Signature.Mode == SignatureHybridCombined
}

// IsHybridEncryption returns true if the profile uses hybrid encryption.
func (p *Profile) IsHybridEncryption() bool {
	return p.Encryption.Mode == EncryptionHybridCombined || p.Encryption.Mode == EncryptionHybridSeparate
}

// IsCatalystEncryption returns true if encryption uses Catalyst (combined hybrid).
func (p *Profile) IsCatalystEncryption() bool {
	return p.Encryption.Mode == EncryptionHybridCombined
}

// RequiresEncryption returns true if the profile includes encryption certificates.
func (p *Profile) RequiresEncryption() bool {
	return p.Encryption.Required && p.Encryption.Mode != EncryptionNone
}

// String returns a human-readable summary of the profile.
func (p *Profile) String() string {
	var sigDesc string
	if p.Signature.Mode == SignatureSimple {
		sigDesc = string(p.Signature.Algorithms.Primary)
	} else {
		sigDesc = fmt.Sprintf("%s (%s + %s)",
			p.Signature.Mode,
			p.Signature.Algorithms.Primary,
			p.Signature.Algorithms.Alternative)
	}

	encDesc := "none"
	if p.Encryption.Required && p.Encryption.Mode != EncryptionNone {
		if p.Encryption.Mode == EncryptionSimple {
			encDesc = string(p.Encryption.Algorithms.Primary)
		} else {
			encDesc = fmt.Sprintf("%s (%s + %s)",
				p.Encryption.Mode,
				p.Encryption.Algorithms.Primary,
				p.Encryption.Algorithms.Alternative)
		}
	}

	return fmt.Sprintf("Profile[%s]: sig=%s, enc=%s, validity=%s, certs=%d",
		p.Name, sigDesc, encDesc, p.Validity, p.CertificateCount())
}
