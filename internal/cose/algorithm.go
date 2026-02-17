// Package cose implements COSE (RFC 9052) and CWT (RFC 8392) signing and verification.
// It supports classical, post-quantum, and hybrid cryptographic algorithms.
package cose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/cloudflare/circl/sign/slhdsa"
	gocose "github.com/veraison/go-cose"

	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
)

// COSE Algorithm IDs.
// Classical algorithms are from IANA COSE Algorithms Registry.
// PQC algorithms follow draft-ietf-cose-dilithium-04 for ML-DSA
// and use private-use range for SLH-DSA.
const (
	// Classical algorithms (IANA registered)
	AlgES256 gocose.Algorithm = -7  // ECDSA w/ SHA-256
	AlgES384 gocose.Algorithm = -35 // ECDSA w/ SHA-384
	AlgES512 gocose.Algorithm = -36 // ECDSA w/ SHA-512
	AlgEdDSA gocose.Algorithm = -8  // EdDSA (Ed25519/Ed448)
	AlgPS256 gocose.Algorithm = -37 // RSASSA-PSS w/ SHA-256
	AlgPS384 gocose.Algorithm = -38 // RSASSA-PSS w/ SHA-384
	AlgPS512 gocose.Algorithm = -39 // RSASSA-PSS w/ SHA-512

	// ML-DSA algorithms (draft-ietf-cose-dilithium-04)
	AlgMLDSA44 gocose.Algorithm = -48
	AlgMLDSA65 gocose.Algorithm = -49
	AlgMLDSA87 gocose.Algorithm = -50

	// SLH-DSA algorithms (private-use range, no IETF draft yet)
	// Using -70020 to -70031 for SHA2 and SHAKE variants
	AlgSLHDSASHA2128s  gocose.Algorithm = -70020
	AlgSLHDSASHA2128f  gocose.Algorithm = -70021
	AlgSLHDSASHA2192s  gocose.Algorithm = -70022
	AlgSLHDSASHA2192f  gocose.Algorithm = -70023
	AlgSLHDSASHA2256s  gocose.Algorithm = -70024
	AlgSLHDSASHA2256f  gocose.Algorithm = -70025
	AlgSLHDSASHAKE128s gocose.Algorithm = -70026
	AlgSLHDSASHAKE128f gocose.Algorithm = -70027
	AlgSLHDSASHAKE192s gocose.Algorithm = -70028
	AlgSLHDSASHAKE192f gocose.Algorithm = -70029
	AlgSLHDSASHAKE256s gocose.Algorithm = -70030
	AlgSLHDSASHAKE256f gocose.Algorithm = -70031
)

// COSEAlgorithmFromPKI converts a pkicrypto.AlgorithmID to a COSE Algorithm.
func COSEAlgorithmFromPKI(alg pkicrypto.AlgorithmID) (gocose.Algorithm, error) {
	switch alg {
	// ECDSA
	case pkicrypto.AlgECDSAP256, pkicrypto.AlgECP256:
		return AlgES256, nil
	case pkicrypto.AlgECDSAP384, pkicrypto.AlgECP384:
		return AlgES384, nil
	case pkicrypto.AlgECDSAP521, pkicrypto.AlgECP521:
		return AlgES512, nil
	// EdDSA
	case pkicrypto.AlgEd25519, pkicrypto.AlgEd448:
		return AlgEdDSA, nil
	// RSA
	case pkicrypto.AlgRSA2048, pkicrypto.AlgRSA4096:
		return AlgPS256, nil
	// ML-DSA
	case pkicrypto.AlgMLDSA44:
		return AlgMLDSA44, nil
	case pkicrypto.AlgMLDSA65:
		return AlgMLDSA65, nil
	case pkicrypto.AlgMLDSA87:
		return AlgMLDSA87, nil
	// SLH-DSA SHA2
	case pkicrypto.AlgSLHDSASHA2128s:
		return AlgSLHDSASHA2128s, nil
	case pkicrypto.AlgSLHDSASHA2128f:
		return AlgSLHDSASHA2128f, nil
	case pkicrypto.AlgSLHDSASHA2192s:
		return AlgSLHDSASHA2192s, nil
	case pkicrypto.AlgSLHDSASHA2192f:
		return AlgSLHDSASHA2192f, nil
	case pkicrypto.AlgSLHDSASHA2256s:
		return AlgSLHDSASHA2256s, nil
	case pkicrypto.AlgSLHDSASHA2256f:
		return AlgSLHDSASHA2256f, nil
	// SLH-DSA SHAKE
	case pkicrypto.AlgSLHDSASHAKE128s:
		return AlgSLHDSASHAKE128s, nil
	case pkicrypto.AlgSLHDSASHAKE128f:
		return AlgSLHDSASHAKE128f, nil
	case pkicrypto.AlgSLHDSASHAKE192s:
		return AlgSLHDSASHAKE192s, nil
	case pkicrypto.AlgSLHDSASHAKE192f:
		return AlgSLHDSASHAKE192f, nil
	case pkicrypto.AlgSLHDSASHAKE256s:
		return AlgSLHDSASHAKE256s, nil
	case pkicrypto.AlgSLHDSASHAKE256f:
		return AlgSLHDSASHAKE256f, nil
	default:
		return 0, fmt.Errorf("unsupported algorithm for COSE: %s", alg)
	}
}

// PKIAlgorithmFromCOSE converts a COSE Algorithm to a pkicrypto.AlgorithmID.
// Note: This may return a default variant when multiple PKI algorithms map to the same COSE algorithm.
func PKIAlgorithmFromCOSE(alg gocose.Algorithm) (pkicrypto.AlgorithmID, error) {
	switch alg {
	// Classical
	case AlgES256:
		return pkicrypto.AlgECDSAP256, nil
	case AlgES384:
		return pkicrypto.AlgECDSAP384, nil
	case AlgES512:
		return pkicrypto.AlgECDSAP521, nil
	case AlgEdDSA:
		return pkicrypto.AlgEd25519, nil // Default to Ed25519
	case AlgPS256, AlgPS384, AlgPS512:
		return pkicrypto.AlgRSA4096, nil // Default to RSA-4096
	// ML-DSA
	case AlgMLDSA44:
		return pkicrypto.AlgMLDSA44, nil
	case AlgMLDSA65:
		return pkicrypto.AlgMLDSA65, nil
	case AlgMLDSA87:
		return pkicrypto.AlgMLDSA87, nil
	// SLH-DSA SHA2
	case AlgSLHDSASHA2128s:
		return pkicrypto.AlgSLHDSASHA2128s, nil
	case AlgSLHDSASHA2128f:
		return pkicrypto.AlgSLHDSASHA2128f, nil
	case AlgSLHDSASHA2192s:
		return pkicrypto.AlgSLHDSASHA2192s, nil
	case AlgSLHDSASHA2192f:
		return pkicrypto.AlgSLHDSASHA2192f, nil
	case AlgSLHDSASHA2256s:
		return pkicrypto.AlgSLHDSASHA2256s, nil
	case AlgSLHDSASHA2256f:
		return pkicrypto.AlgSLHDSASHA2256f, nil
	// SLH-DSA SHAKE
	case AlgSLHDSASHAKE128s:
		return pkicrypto.AlgSLHDSASHAKE128s, nil
	case AlgSLHDSASHAKE128f:
		return pkicrypto.AlgSLHDSASHAKE128f, nil
	case AlgSLHDSASHAKE192s:
		return pkicrypto.AlgSLHDSASHAKE192s, nil
	case AlgSLHDSASHAKE192f:
		return pkicrypto.AlgSLHDSASHAKE192f, nil
	case AlgSLHDSASHAKE256s:
		return pkicrypto.AlgSLHDSASHAKE256s, nil
	case AlgSLHDSASHAKE256f:
		return pkicrypto.AlgSLHDSASHAKE256f, nil
	default:
		return "", fmt.Errorf("unsupported COSE algorithm: %d", alg)
	}
}

// COSEAlgorithmFromKey determines the COSE algorithm from a public key.
func COSEAlgorithmFromKey(key crypto.PublicKey) (gocose.Algorithm, error) {
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve.Params().BitSize {
		case 256:
			return AlgES256, nil
		case 384:
			return AlgES384, nil
		case 521:
			return AlgES512, nil
		default:
			return 0, fmt.Errorf("unsupported ECDSA curve size: %d", k.Curve.Params().BitSize)
		}
	case ed25519.PublicKey:
		return AlgEdDSA, nil
	case *rsa.PublicKey:
		return AlgPS256, nil // Default to PS256 for RSA
	// ML-DSA (circl library types)
	case *mldsa44.PublicKey:
		return AlgMLDSA44, nil
	case *mldsa65.PublicKey:
		return AlgMLDSA65, nil
	case *mldsa87.PublicKey:
		return AlgMLDSA87, nil
	// ML-DSA (HSM wrapper type)
	case *pkicrypto.MLDSAPublicKey:
		return COSEAlgorithmFromPKI(k.Algorithm)
	// SLH-DSA
	case *slhdsa.PublicKey:
		return algorithmFromSLHDSAKey(k)
	default:
		return 0, fmt.Errorf("unsupported key type: %T", key)
	}
}

// algorithmFromSLHDSAKey determines the COSE algorithm from an SLH-DSA public key.
func algorithmFromSLHDSAKey(key *slhdsa.PublicKey) (gocose.Algorithm, error) {
	// SLH-DSA keys have an ID field that identifies the algorithm variant
	switch key.ID {
	// SHA2 variants
	case slhdsa.SHA2_128s:
		return AlgSLHDSASHA2128s, nil
	case slhdsa.SHA2_128f:
		return AlgSLHDSASHA2128f, nil
	case slhdsa.SHA2_192s:
		return AlgSLHDSASHA2192s, nil
	case slhdsa.SHA2_192f:
		return AlgSLHDSASHA2192f, nil
	case slhdsa.SHA2_256s:
		return AlgSLHDSASHA2256s, nil
	case slhdsa.SHA2_256f:
		return AlgSLHDSASHA2256f, nil
	// SHAKE variants
	case slhdsa.SHAKE_128s:
		return AlgSLHDSASHAKE128s, nil
	case slhdsa.SHAKE_128f:
		return AlgSLHDSASHAKE128f, nil
	case slhdsa.SHAKE_192s:
		return AlgSLHDSASHAKE192s, nil
	case slhdsa.SHAKE_192f:
		return AlgSLHDSASHAKE192f, nil
	case slhdsa.SHAKE_256s:
		return AlgSLHDSASHAKE256s, nil
	case slhdsa.SHAKE_256f:
		return AlgSLHDSASHAKE256f, nil
	default:
		return 0, fmt.Errorf("unsupported SLH-DSA ID: %v", key.ID)
	}
}

// AlgorithmName returns a human-readable name for a COSE algorithm.
func AlgorithmName(alg gocose.Algorithm) string {
	switch alg {
	case AlgES256:
		return "ES256"
	case AlgES384:
		return "ES384"
	case AlgES512:
		return "ES512"
	case AlgEdDSA:
		return "EdDSA"
	case AlgPS256:
		return "PS256"
	case AlgPS384:
		return "PS384"
	case AlgPS512:
		return "PS512"
	case AlgMLDSA44:
		return "ML-DSA-44"
	case AlgMLDSA65:
		return "ML-DSA-65"
	case AlgMLDSA87:
		return "ML-DSA-87"
	case AlgSLHDSASHA2128s:
		return "SLH-DSA-SHA2-128s"
	case AlgSLHDSASHA2128f:
		return "SLH-DSA-SHA2-128f"
	case AlgSLHDSASHA2192s:
		return "SLH-DSA-SHA2-192s"
	case AlgSLHDSASHA2192f:
		return "SLH-DSA-SHA2-192f"
	case AlgSLHDSASHA2256s:
		return "SLH-DSA-SHA2-256s"
	case AlgSLHDSASHA2256f:
		return "SLH-DSA-SHA2-256f"
	case AlgSLHDSASHAKE128s:
		return "SLH-DSA-SHAKE-128s"
	case AlgSLHDSASHAKE128f:
		return "SLH-DSA-SHAKE-128f"
	case AlgSLHDSASHAKE192s:
		return "SLH-DSA-SHAKE-192s"
	case AlgSLHDSASHAKE192f:
		return "SLH-DSA-SHAKE-192f"
	case AlgSLHDSASHAKE256s:
		return "SLH-DSA-SHAKE-256s"
	case AlgSLHDSASHAKE256f:
		return "SLH-DSA-SHAKE-256f"
	default:
		return fmt.Sprintf("Unknown(%d)", alg)
	}
}

// IsPQCAlgorithm returns true if the COSE algorithm is post-quantum.
func IsPQCAlgorithm(alg gocose.Algorithm) bool {
	switch alg {
	case AlgMLDSA44, AlgMLDSA65, AlgMLDSA87,
		AlgSLHDSASHA2128s, AlgSLHDSASHA2128f,
		AlgSLHDSASHA2192s, AlgSLHDSASHA2192f,
		AlgSLHDSASHA2256s, AlgSLHDSASHA2256f,
		AlgSLHDSASHAKE128s, AlgSLHDSASHAKE128f,
		AlgSLHDSASHAKE192s, AlgSLHDSASHAKE192f,
		AlgSLHDSASHAKE256s, AlgSLHDSASHAKE256f:
		return true
	default:
		return false
	}
}

// IsClassicalAlgorithm returns true if the COSE algorithm is classical (non-PQC).
func IsClassicalAlgorithm(alg gocose.Algorithm) bool {
	switch alg {
	case AlgES256, AlgES384, AlgES512, AlgEdDSA, AlgPS256, AlgPS384, AlgPS512:
		return true
	default:
		return false
	}
}
