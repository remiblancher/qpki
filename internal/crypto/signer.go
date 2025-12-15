package crypto

import (
	"crypto"
	"io"
)

// Signer extends crypto.Signer with algorithm metadata.
// It provides a unified interface for both classical and PQC signing operations.
type Signer interface {
	crypto.Signer

	// Algorithm returns the algorithm identifier for this signer.
	Algorithm() AlgorithmID
}

// SignerType identifies the type of signer backend.
type SignerType string

const (
	SignerTypeSoftware SignerType = "software"
	SignerTypePKCS11   SignerType = "pkcs11"
)

// SignerConfig holds configuration for loading or creating a signer.
type SignerConfig struct {
	// Type specifies the signer backend ("software" or "pkcs11").
	Type SignerType `json:"type" yaml:"type"`

	// KeyPath is the path to the private key file (for software signers).
	KeyPath string `json:"key_path,omitempty" yaml:"key_path,omitempty"`

	// Algorithm specifies the algorithm to use.
	Algorithm AlgorithmID `json:"algorithm,omitempty" yaml:"algorithm,omitempty"`

	// PKCS11 configuration (for PKCS#11 signers).
	PKCS11URI      string `json:"pkcs11_uri,omitempty" yaml:"pkcs11_uri,omitempty"`
	PKCS11Lib      string `json:"pkcs11_lib,omitempty" yaml:"pkcs11_lib,omitempty"`
	PKCS11Token    string `json:"pkcs11_token,omitempty" yaml:"pkcs11_token,omitempty"`
	PKCS11Pin      string `json:"pkcs11_pin,omitempty" yaml:"pkcs11_pin,omitempty"`
	PKCS11KeyLabel string `json:"pkcs11_key_label,omitempty" yaml:"pkcs11_key_label,omitempty"`

	// Passphrase for encrypted private keys.
	// Can be a literal value or "env:VAR_NAME" to read from environment.
	Passphrase string `json:"-" yaml:"-"`
}

// SignerProvider creates and manages signers.
type SignerProvider interface {
	// LoadSigner loads an existing signer from the configuration.
	LoadSigner(cfg SignerConfig) (Signer, error)

	// GenerateAndSave generates a new key pair, saves it, and returns the signer.
	GenerateAndSave(alg AlgorithmID, cfg SignerConfig) (Signer, error)
}

// HybridSigner combines a classical signer with a PQC signer.
type HybridSigner interface {
	Signer

	// ClassicalSigner returns the classical (non-PQC) signer.
	ClassicalSigner() Signer

	// PQCSigner returns the PQC signer.
	PQCSigner() Signer

	// SignHybrid signs the message with both classical and PQC algorithms.
	// Returns classical signature, PQC signature, and any error.
	SignHybrid(rand io.Reader, message []byte) (classical, pqc []byte, err error)
}

// Verifier provides signature verification.
type Verifier interface {
	// Verify verifies a signature against a message.
	Verify(message, signature []byte) bool

	// Algorithm returns the algorithm used for verification.
	Algorithm() AlgorithmID
}

// VerifierFromPublicKey creates a Verifier from a public key.
func VerifierFromPublicKey(alg AlgorithmID, pub crypto.PublicKey) (Verifier, error) {
	return &publicKeyVerifier{
		alg: alg,
		pub: pub,
	}, nil
}

// publicKeyVerifier implements Verifier for public keys.
type publicKeyVerifier struct {
	alg AlgorithmID
	pub crypto.PublicKey
}

func (v *publicKeyVerifier) Algorithm() AlgorithmID {
	return v.alg
}

func (v *publicKeyVerifier) Verify(message, signature []byte) bool {
	return Verify(v.alg, v.pub, message, signature)
}
