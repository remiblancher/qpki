// Package crypto provides cryptographic primitives for the PKI.
// This file defines PQC public key types used across the codebase.
// These types are defined separately from pkcs11.go to ensure they are
// available even when CGO is disabled (for cross-compilation).
package crypto

// MLDSAPublicKey represents an ML-DSA (FIPS 204) public key.
// Used for HSM-backed ML-DSA keys where the raw public key bytes
// are extracted from the HSM.
type MLDSAPublicKey struct {
	Algorithm AlgorithmID
	PublicKey []byte
}

// Bytes returns the raw public key bytes for computing Subject Key ID.
func (k *MLDSAPublicKey) Bytes() []byte {
	return k.PublicKey
}

// MLKEMPublicKey represents an ML-KEM (FIPS 203) public key.
// Used for HSM-backed ML-KEM keys where the raw public key bytes
// are extracted from the HSM.
type MLKEMPublicKey struct {
	Algorithm AlgorithmID
	PublicKey []byte
}

// Bytes returns the raw public key bytes.
func (k *MLKEMPublicKey) Bytes() []byte {
	return k.PublicKey
}
