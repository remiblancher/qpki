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
