package cose

import (
	"crypto"
	"fmt"

	gocose "github.com/veraison/go-cose"
)

// Verifier implements gocose.Verifier for signature verification.
type Verifier struct {
	publicKey crypto.PublicKey
	algorithm gocose.Algorithm
}

// NewVerifier creates a new COSE verifier from a public key.
func NewVerifier(pub crypto.PublicKey) (*Verifier, error) {
	alg, err := COSEAlgorithmFromKey(pub)
	if err != nil {
		return nil, fmt.Errorf("failed to determine algorithm: %w", err)
	}
	return &Verifier{
		publicKey: pub,
		algorithm: alg,
	}, nil
}

// NewVerifierWithAlgorithm creates a new COSE verifier with an explicit algorithm.
func NewVerifierWithAlgorithm(pub crypto.PublicKey, alg gocose.Algorithm) *Verifier {
	return &Verifier{
		publicKey: pub,
		algorithm: alg,
	}
}

// Algorithm returns the COSE algorithm identifier.
func (v *Verifier) Algorithm() gocose.Algorithm {
	return v.algorithm
}

// Verify verifies the signature over the given data.
// For COSE Sign1/Sign, the data is the Sig_structure (to-be-signed bytes).
func (v *Verifier) Verify(data, signature []byte) error {
	return Verify(v.publicKey, v.algorithm, data, signature)
}

// PublicKey returns the public key used for verification.
func (v *Verifier) PublicKey() crypto.PublicKey {
	return v.publicKey
}
