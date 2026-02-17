package crypto

import (
	"crypto"
	"crypto/rsa"
)

// SignerOptsConfig holds configuration for signature operations.
// This allows specifying the hash algorithm, signature scheme, and parameters.
type SignerOptsConfig struct {
	// Hash is the hash algorithm to use.
	Hash crypto.Hash

	// UsePSS indicates whether to use RSA-PSS instead of PKCS#1 v1.5.
	// Only applicable for RSA keys.
	UsePSS bool

	// PSSOptions contains RSA-PSS specific options.
	// Only used when UsePSS is true.
	PSSOptions *rsa.PSSOptions
}

// HashFunc returns the hash function used for this signer opts.
func (o *SignerOptsConfig) HashFunc() crypto.Hash {
	return o.Hash
}

// DefaultSignerOpts returns the default signer options for an algorithm.
func DefaultSignerOpts(alg AlgorithmID) *SignerOptsConfig {
	switch alg {
	case AlgECDSAP256, AlgECP256:
		return &SignerOptsConfig{Hash: crypto.SHA256}

	case AlgECDSAP384, AlgECP384:
		return &SignerOptsConfig{Hash: crypto.SHA384}

	case AlgECDSAP521, AlgECP521:
		return &SignerOptsConfig{Hash: crypto.SHA512}

	case AlgRSA2048, AlgRSA4096:
		// Default to RSA-PSS with SHA-256
		return &SignerOptsConfig{
			Hash:   crypto.SHA256,
			UsePSS: true,
			PSSOptions: &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       crypto.SHA256,
			},
		}

	case AlgEd25519:
		// Ed25519 doesn't use external hash
		return &SignerOptsConfig{Hash: 0}

	default:
		// PQC algorithms don't use external hash
		return &SignerOptsConfig{Hash: 0}
	}
}

// RSAPKCSSignerOpts returns signer options for RSA PKCS#1 v1.5.
func RSAPKCSSignerOpts(hash crypto.Hash) *SignerOptsConfig {
	return &SignerOptsConfig{
		Hash:   hash,
		UsePSS: false,
	}
}

// RSAPSSSignerOpts returns signer options for RSA-PSS.
func RSAPSSSignerOpts(hash crypto.Hash, saltLength int) *SignerOptsConfig {
	return &SignerOptsConfig{
		Hash:   hash,
		UsePSS: true,
		PSSOptions: &rsa.PSSOptions{
			SaltLength: saltLength,
			Hash:       hash,
		},
	}
}

// RSAPSSSignerOptsWithMGF returns signer options for RSA-PSS with custom MGF.
func RSAPSSSignerOptsWithMGF(hash crypto.Hash, saltLength int, mgfHash crypto.Hash) *SignerOptsConfig {
	// Note: Go's crypto/rsa doesn't support custom MGF hash different from signature hash.
	// The MGF hash is always the same as the signature hash in the standard library.
	// We accept the parameter for API consistency but use the signature hash.
	return &SignerOptsConfig{
		Hash:   hash,
		UsePSS: true,
		PSSOptions: &rsa.PSSOptions{
			SaltLength: saltLength,
			Hash:       hash, // MGF hash is always same as signature hash in Go
		},
	}
}
