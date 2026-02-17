// Package profile provides certificate profiles for the PKI.
package profile

import (
	"crypto"
	"crypto/x509"
	"fmt"

	pkicrypto "github.com/remiblancher/post-quantum-pki/pkg/crypto"
)

// HashAlgorithm identifies a hash algorithm for signature operations.
type HashAlgorithm string

// Supported hash algorithms.
const (
	HashSHA256   HashAlgorithm = "sha256"
	HashSHA384   HashAlgorithm = "sha384"
	HashSHA512   HashAlgorithm = "sha512"
	HashSHA3_256 HashAlgorithm = "sha3-256"
	HashSHA3_384 HashAlgorithm = "sha3-384"
	HashSHA3_512 HashAlgorithm = "sha3-512"
)

// IsValid returns true if the hash algorithm is recognized.
func (h HashAlgorithm) IsValid() bool {
	switch h {
	case HashSHA256, HashSHA384, HashSHA512,
		HashSHA3_256, HashSHA3_384, HashSHA3_512:
		return true
	default:
		return false
	}
}

// CryptoHash returns the corresponding crypto.Hash value.
func (h HashAlgorithm) CryptoHash() crypto.Hash {
	switch h {
	case HashSHA256:
		return crypto.SHA256
	case HashSHA384:
		return crypto.SHA384
	case HashSHA512:
		return crypto.SHA512
	case HashSHA3_256:
		return crypto.SHA3_256
	case HashSHA3_384:
		return crypto.SHA3_384
	case HashSHA3_512:
		return crypto.SHA3_512
	default:
		return 0
	}
}

// SizeBytes returns the hash output size in bytes.
func (h HashAlgorithm) SizeBytes() int {
	switch h {
	case HashSHA256, HashSHA3_256:
		return 32
	case HashSHA384, HashSHA3_384:
		return 48
	case HashSHA512, HashSHA3_512:
		return 64
	default:
		return 0
	}
}

// SignatureScheme identifies how signatures are computed.
type SignatureScheme string

// Supported signature schemes.
const (
	// SchemeECDSA is the standard ECDSA scheme with configurable hash.
	SchemeECDSA SignatureScheme = "ecdsa"

	// SchemePKCS1v15 is RSA PKCS#1 v1.5 signature (legacy).
	SchemePKCS1v15 SignatureScheme = "pkcs1v15"

	// SchemeRSASSAPSS is RSA-PSS signature (recommended for RSA).
	SchemeRSASSAPSS SignatureScheme = "rsassa-pss"

	// SchemeEd25519 is pure EdDSA with Ed25519 (no external hash).
	SchemeEd25519 SignatureScheme = "ed25519"

	// SchemeEd25519ph is pre-hashed EdDSA with Ed25519.
	SchemeEd25519ph SignatureScheme = "ed25519ph"

	// SchemeEd448 is pure EdDSA with Ed448 (no external hash).
	SchemeEd448 SignatureScheme = "ed448"

	// SchemeEd448ph is pre-hashed EdDSA with Ed448.
	SchemeEd448ph SignatureScheme = "ed448ph"
)

// IsValid returns true if the signature scheme is recognized.
func (s SignatureScheme) IsValid() bool {
	switch s {
	case SchemeECDSA, SchemePKCS1v15, SchemeRSASSAPSS,
		SchemeEd25519, SchemeEd25519ph, SchemeEd448, SchemeEd448ph:
		return true
	default:
		return false
	}
}

// RequiresHash returns true if the scheme uses an external hash algorithm.
func (s SignatureScheme) RequiresHash() bool {
	switch s {
	case SchemeECDSA, SchemePKCS1v15, SchemeRSASSAPSS, SchemeEd25519ph, SchemeEd448ph:
		return true
	case SchemeEd25519, SchemeEd448:
		return false
	default:
		return false
	}
}

// IsPure returns true for pure EdDSA schemes (no pre-hashing).
func (s SignatureScheme) IsPure() bool {
	return s == SchemeEd25519 || s == SchemeEd448
}

// PSSParams holds RSA-PSS specific parameters.
type PSSParams struct {
	// SaltLength is the salt length in bytes.
	// Use -1 for hash length (recommended), 0 for auto, or explicit value.
	SaltLength int `yaml:"salt_length" json:"salt_length"`

	// MGF is the Mask Generation Function hash algorithm.
	// Defaults to the same as the signature hash if not specified.
	MGF HashAlgorithm `yaml:"mgf,omitempty" json:"mgf,omitempty"`
}

// SignatureAlgoConfig defines the complete signature algorithm configuration.
// This specifies HOW to sign (hash, scheme, parameters) rather than WHAT key to use.
type SignatureAlgoConfig struct {
	// Key specifies the key type (e.g., "ec-p384", "rsa-4096").
	// This is the same as AlgorithmID in the profile's AlgorithmPair.
	Key pkicrypto.AlgorithmID `yaml:"key,omitempty" json:"key,omitempty"`

	// Scheme specifies the signature scheme (e.g., "ecdsa", "rsassa-pss").
	// If not specified, it will be inferred from the key type.
	Scheme SignatureScheme `yaml:"scheme,omitempty" json:"scheme,omitempty"`

	// Hash specifies the hash algorithm (e.g., "sha384", "sha3-256").
	// If not specified, it will be inferred from the key type.
	Hash HashAlgorithm `yaml:"hash,omitempty" json:"hash,omitempty"`

	// PSS contains RSA-PSS specific parameters.
	// Only applicable when Scheme is "rsassa-pss".
	PSS *PSSParams `yaml:"pss,omitempty" json:"pss,omitempty"`
}

// Resolve fills in default values based on the key type.
// Returns a new SignatureAlgoConfig with all fields populated.
func (c *SignatureAlgoConfig) Resolve() (*SignatureAlgoConfig, []string) {
	resolved := &SignatureAlgoConfig{
		Key:    c.Key,
		Scheme: c.Scheme,
		Hash:   c.Hash,
		PSS:    c.PSS,
	}
	var warnings []string

	// Infer scheme from key type if not specified
	if resolved.Scheme == "" {
		resolved.Scheme = inferScheme(resolved.Key)
	}

	// Infer hash from key type if not specified
	if resolved.Hash == "" && resolved.Scheme.RequiresHash() {
		resolved.Hash = inferHash(resolved.Key)
	}

	// Set default PSS parameters if using RSA-PSS
	if resolved.Scheme == SchemeRSASSAPSS && resolved.PSS == nil {
		resolved.PSS = &PSSParams{
			SaltLength: -1, // Hash length (recommended)
		}
	}

	// Set MGF default for PSS
	if resolved.PSS != nil && resolved.PSS.MGF == "" {
		resolved.PSS.MGF = resolved.Hash
	}

	// Check for non-standard combinations and add warnings
	warnings = append(warnings, checkCombination(resolved)...)

	return resolved, warnings
}

// Validate checks that the configuration is valid.
func (c *SignatureAlgoConfig) Validate() error {
	if c.Key == "" {
		return fmt.Errorf("key type is required")
	}

	if !c.Key.IsValid() {
		return fmt.Errorf("invalid key type: %s", c.Key)
	}

	if c.Scheme != "" && !c.Scheme.IsValid() {
		return fmt.Errorf("invalid signature scheme: %s", c.Scheme)
	}

	if c.Hash != "" && !c.Hash.IsValid() {
		return fmt.Errorf("invalid hash algorithm: %s", c.Hash)
	}

	// Validate scheme/key compatibility
	if c.Scheme != "" {
		if err := validateSchemeKeyCompat(c.Scheme, c.Key); err != nil {
			return err
		}
	}

	// Validate PSS params
	if c.PSS != nil {
		if c.Scheme != SchemeRSASSAPSS {
			return fmt.Errorf("PSS parameters only valid with rsassa-pss scheme")
		}
		if c.PSS.MGF != "" && !c.PSS.MGF.IsValid() {
			return fmt.Errorf("invalid MGF hash algorithm: %s", c.PSS.MGF)
		}
	}

	return nil
}

// X509SignatureAlgorithm returns the x509.SignatureAlgorithm for this config.
// Returns 0 for PQC algorithms (not supported by Go's crypto/x509).
func (c *SignatureAlgoConfig) X509SignatureAlgorithm() x509.SignatureAlgorithm {
	resolved, _ := c.Resolve()

	// PQC algorithms don't have x509.SignatureAlgorithm
	if resolved.Key.IsPQC() {
		return 0
	}

	// Map scheme + hash to x509.SignatureAlgorithm
	switch resolved.Scheme {
	case SchemeECDSA:
		switch resolved.Hash {
		case HashSHA256, HashSHA3_256:
			return x509.ECDSAWithSHA256
		case HashSHA384, HashSHA3_384:
			return x509.ECDSAWithSHA384
		case HashSHA512, HashSHA3_512:
			return x509.ECDSAWithSHA512
		}

	case SchemePKCS1v15:
		switch resolved.Hash {
		case HashSHA256, HashSHA3_256:
			return x509.SHA256WithRSA
		case HashSHA384, HashSHA3_384:
			return x509.SHA384WithRSA
		case HashSHA512, HashSHA3_512:
			return x509.SHA512WithRSA
		}

	case SchemeRSASSAPSS:
		switch resolved.Hash {
		case HashSHA256, HashSHA3_256:
			return x509.SHA256WithRSAPSS
		case HashSHA384, HashSHA3_384:
			return x509.SHA384WithRSAPSS
		case HashSHA512, HashSHA3_512:
			return x509.SHA512WithRSAPSS
		}

	case SchemeEd25519:
		return x509.PureEd25519
	}

	return 0
}

// inferScheme returns the default signature scheme for a key type.
func inferScheme(key pkicrypto.AlgorithmID) SignatureScheme {
	switch key {
	case pkicrypto.AlgECDSAP256, pkicrypto.AlgECDSAP384, pkicrypto.AlgECDSAP521,
		pkicrypto.AlgECP256, pkicrypto.AlgECP384, pkicrypto.AlgECP521:
		return SchemeECDSA

	case pkicrypto.AlgRSA2048, pkicrypto.AlgRSA4096:
		return SchemeRSASSAPSS // PSS is recommended over PKCS#1 v1.5

	case pkicrypto.AlgEd25519:
		return SchemeEd25519

	default:
		// PQC algorithms don't need an external scheme
		return ""
	}
}

// inferHash returns the default hash algorithm for a key type.
func inferHash(key pkicrypto.AlgorithmID) HashAlgorithm {
	switch key {
	case pkicrypto.AlgECDSAP256, pkicrypto.AlgECP256:
		return HashSHA256

	case pkicrypto.AlgECDSAP384, pkicrypto.AlgECP384:
		return HashSHA384

	case pkicrypto.AlgECDSAP521, pkicrypto.AlgECP521:
		return HashSHA512

	case pkicrypto.AlgRSA2048, pkicrypto.AlgRSA4096:
		return HashSHA256

	default:
		return ""
	}
}

// validateSchemeKeyCompat checks if a scheme is compatible with a key type.
func validateSchemeKeyCompat(scheme SignatureScheme, key pkicrypto.AlgorithmID) error {
	switch scheme {
	case SchemeECDSA:
		if !isECKey(key) {
			return fmt.Errorf("ecdsa scheme requires EC key, got %s", key)
		}

	case SchemePKCS1v15, SchemeRSASSAPSS:
		if !isRSAKey(key) {
			return fmt.Errorf("%s scheme requires RSA key, got %s", scheme, key)
		}

	case SchemeEd25519, SchemeEd25519ph:
		if key != pkicrypto.AlgEd25519 {
			return fmt.Errorf("%s scheme requires ed25519 key, got %s", scheme, key)
		}
	}

	return nil
}

// checkCombination returns warnings for non-standard but valid combinations.
func checkCombination(c *SignatureAlgoConfig) []string {
	var warnings []string

	// Check hash/curve alignment for ECDSA
	if c.Scheme == SchemeECDSA {
		expectedHash := inferHash(c.Key)
		if c.Hash != expectedHash && expectedHash != "" {
			warnings = append(warnings,
				fmt.Sprintf("non-standard combination: %s with %s (expected %s)", c.Key, c.Hash, expectedHash))
		}
	}

	// Warn about PKCS#1 v1.5 (legacy)
	if c.Scheme == SchemePKCS1v15 {
		warnings = append(warnings, "pkcs1v15 is legacy; consider rsassa-pss for new deployments")
	}

	// Warn about pre-hashed EdDSA
	if c.Scheme == SchemeEd25519ph || c.Scheme == SchemeEd448ph {
		warnings = append(warnings,
			fmt.Sprintf("%s (pre-hashed) is rarely needed; consider pure %s",
				c.Scheme, SignatureScheme(string(c.Scheme)[:len(c.Scheme)-2])))
	}

	return warnings
}

// isECKey returns true for EC/ECDSA key types.
func isECKey(key pkicrypto.AlgorithmID) bool {
	switch key {
	case pkicrypto.AlgECDSAP256, pkicrypto.AlgECDSAP384, pkicrypto.AlgECDSAP521,
		pkicrypto.AlgECP256, pkicrypto.AlgECP384, pkicrypto.AlgECP521:
		return true
	default:
		return false
	}
}

// isRSAKey returns true for RSA key types.
func isRSAKey(key pkicrypto.AlgorithmID) bool {
	switch key {
	case pkicrypto.AlgRSA2048, pkicrypto.AlgRSA4096:
		return true
	default:
		return false
	}
}

// AllHashAlgorithms returns all supported hash algorithms.
func AllHashAlgorithms() []HashAlgorithm {
	return []HashAlgorithm{
		HashSHA256, HashSHA384, HashSHA512,
		HashSHA3_256, HashSHA3_384, HashSHA3_512,
	}
}

// AllSignatureSchemes returns all supported signature schemes.
func AllSignatureSchemes() []SignatureScheme {
	return []SignatureScheme{
		SchemeECDSA, SchemePKCS1v15, SchemeRSASSAPSS,
		SchemeEd25519, SchemeEd25519ph, SchemeEd448, SchemeEd448ph,
	}
}
