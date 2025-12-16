// Package policy provides certificate policy templates (gammes) for the PKI.
//
// A gamme defines a complete certificate enrollment policy including:
//   - Signature requirements (simple or hybrid)
//   - Encryption requirements (none, simple, or hybrid)
//   - Algorithm choices
//   - Validity period
//
// Gammes are stored as YAML files within the CA directory and can be
// predefined (shipped with the PKI) or custom (created by administrators).
package policy

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

// Gamme defines a complete certificate enrollment policy.
// It specifies what certificates should be issued for a subject and with what algorithms.
type Gamme struct {
	// Name is the unique identifier for this gamme.
	Name string `yaml:"name" json:"name"`

	// Description provides a human-readable description.
	Description string `yaml:"description" json:"description"`

	// Signature defines the signature certificate configuration.
	Signature SignatureConfig `yaml:"signature" json:"signature"`

	// Encryption defines the encryption certificate configuration.
	Encryption EncryptionConfig `yaml:"encryption" json:"encryption"`

	// Validity is the default certificate validity period.
	Validity time.Duration `yaml:"validity" json:"validity"`
}

// Validate checks that the gamme configuration is valid.
func (g *Gamme) Validate() error {
	if g.Name == "" {
		return fmt.Errorf("gamme name is required")
	}

	// Validate signature configuration
	if err := g.validateSignature(); err != nil {
		return fmt.Errorf("signature config: %w", err)
	}

	// Validate encryption configuration
	if err := g.validateEncryption(); err != nil {
		return fmt.Errorf("encryption config: %w", err)
	}

	// Validate validity
	if g.Validity <= 0 {
		return fmt.Errorf("validity must be positive")
	}

	return nil
}

func (g *Gamme) validateSignature() error {
	if !g.Signature.Required {
		// Signature is always required (CSR needs signature)
		return fmt.Errorf("signature is always required")
	}

	switch g.Signature.Mode {
	case SignatureSimple:
		if g.Signature.Algorithms.Primary == "" {
			return fmt.Errorf("primary algorithm is required for simple mode")
		}
		if !g.Signature.Algorithms.Primary.IsValid() {
			return fmt.Errorf("invalid primary algorithm: %s", g.Signature.Algorithms.Primary)
		}

	case SignatureHybridCombined, SignatureHybridSeparate:
		if g.Signature.Algorithms.Primary == "" {
			return fmt.Errorf("primary (classical) algorithm is required for hybrid mode")
		}
		if g.Signature.Algorithms.Alternative == "" {
			return fmt.Errorf("alternative (PQC) algorithm is required for hybrid mode")
		}
		if !g.Signature.Algorithms.Primary.IsValid() {
			return fmt.Errorf("invalid primary algorithm: %s", g.Signature.Algorithms.Primary)
		}
		if !g.Signature.Algorithms.Alternative.IsValid() {
			return fmt.Errorf("invalid alternative algorithm: %s", g.Signature.Algorithms.Alternative)
		}
		// For hybrid signature, primary should be classical and alternative should be PQC
		if g.Signature.Algorithms.Primary.IsPQC() {
			return fmt.Errorf("primary algorithm should be classical for hybrid signature")
		}
		if !g.Signature.Algorithms.Alternative.IsPQC() {
			return fmt.Errorf("alternative algorithm should be PQC for hybrid signature")
		}

	default:
		return fmt.Errorf("invalid signature mode: %s", g.Signature.Mode)
	}

	return nil
}

func (g *Gamme) validateEncryption() error {
	if !g.Encryption.Required {
		if g.Encryption.Mode != EncryptionNone && g.Encryption.Mode != "" {
			return fmt.Errorf("mode should be 'none' or empty when encryption is not required")
		}
		return nil
	}

	switch g.Encryption.Mode {
	case EncryptionNone:
		// Valid - no encryption

	case EncryptionSimple:
		if g.Encryption.Algorithms.Primary == "" {
			return fmt.Errorf("primary algorithm is required for simple encryption")
		}
		if !g.Encryption.Algorithms.Primary.IsValid() {
			return fmt.Errorf("invalid encryption algorithm: %s", g.Encryption.Algorithms.Primary)
		}

	case EncryptionHybridCombined, EncryptionHybridSeparate:
		if g.Encryption.Algorithms.Primary == "" {
			return fmt.Errorf("primary algorithm is required for hybrid encryption")
		}
		if g.Encryption.Algorithms.Alternative == "" {
			return fmt.Errorf("alternative algorithm is required for hybrid encryption")
		}
		if !g.Encryption.Algorithms.Primary.IsValid() {
			return fmt.Errorf("invalid primary encryption algorithm: %s", g.Encryption.Algorithms.Primary)
		}
		if !g.Encryption.Algorithms.Alternative.IsValid() {
			return fmt.Errorf("invalid alternative encryption algorithm: %s", g.Encryption.Algorithms.Alternative)
		}

	default:
		return fmt.Errorf("invalid encryption mode: %s", g.Encryption.Mode)
	}

	return nil
}

// CertificateCount returns the number of certificates that will be issued
// for this gamme.
func (g *Gamme) CertificateCount() int {
	count := 0

	// Signature certificates
	switch g.Signature.Mode {
	case SignatureSimple, SignatureHybridCombined:
		count += 1
	case SignatureHybridSeparate:
		count += 2
	}

	// Encryption certificates
	if g.Encryption.Required {
		switch g.Encryption.Mode {
		case EncryptionSimple, EncryptionHybridCombined:
			count += 1
		case EncryptionHybridSeparate:
			count += 2
		}
	}

	return count
}

// IsHybridSignature returns true if the gamme uses hybrid signature.
func (g *Gamme) IsHybridSignature() bool {
	return g.Signature.Mode == SignatureHybridCombined || g.Signature.Mode == SignatureHybridSeparate
}

// IsCatalystSignature returns true if signature uses Catalyst (combined hybrid).
func (g *Gamme) IsCatalystSignature() bool {
	return g.Signature.Mode == SignatureHybridCombined
}

// IsHybridEncryption returns true if the gamme uses hybrid encryption.
func (g *Gamme) IsHybridEncryption() bool {
	return g.Encryption.Mode == EncryptionHybridCombined || g.Encryption.Mode == EncryptionHybridSeparate
}

// IsCatalystEncryption returns true if encryption uses Catalyst (combined hybrid).
func (g *Gamme) IsCatalystEncryption() bool {
	return g.Encryption.Mode == EncryptionHybridCombined
}

// RequiresEncryption returns true if the gamme includes encryption certificates.
func (g *Gamme) RequiresEncryption() bool {
	return g.Encryption.Required && g.Encryption.Mode != EncryptionNone
}

// String returns a human-readable summary of the gamme.
func (g *Gamme) String() string {
	var sigDesc string
	if g.Signature.Mode == SignatureSimple {
		sigDesc = string(g.Signature.Algorithms.Primary)
	} else {
		sigDesc = fmt.Sprintf("%s (%s + %s)",
			g.Signature.Mode,
			g.Signature.Algorithms.Primary,
			g.Signature.Algorithms.Alternative)
	}

	encDesc := "none"
	if g.Encryption.Required && g.Encryption.Mode != EncryptionNone {
		if g.Encryption.Mode == EncryptionSimple {
			encDesc = string(g.Encryption.Algorithms.Primary)
		} else {
			encDesc = fmt.Sprintf("%s (%s + %s)",
				g.Encryption.Mode,
				g.Encryption.Algorithms.Primary,
				g.Encryption.Algorithms.Alternative)
		}
	}

	return fmt.Sprintf("Gamme[%s]: sig=%s, enc=%s, validity=%s, certs=%d",
		g.Name, sigDesc, encDesc, g.Validity, g.CertificateCount())
}
