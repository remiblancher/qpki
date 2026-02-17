// Package crypto provides cryptographic primitives for the PKI.
// It supports classical algorithms (ECDSA, Ed25519, RSA) and post-quantum
// algorithms (ML-DSA, SLH-DSA, ML-KEM) via the cloudflare/circl library.
package crypto

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
)

// AlgorithmID identifies a cryptographic algorithm.
type AlgorithmID string

// Classical signature algorithms.
const (
	AlgECDSAP256 AlgorithmID = "ecdsa-p256"
	AlgECDSAP384 AlgorithmID = "ecdsa-p384"
	AlgECDSAP521 AlgorithmID = "ecdsa-p521"
	AlgEd25519   AlgorithmID = "ed25519"
	AlgEd448     AlgorithmID = "ed448"
	AlgRSA2048   AlgorithmID = "rsa-2048"
	AlgRSA4096   AlgorithmID = "rsa-4096"
)

// EC key type aliases (preferred names - same keys, multi-purpose ECDSA/ECDH).
const (
	AlgECP256 AlgorithmID = "ec-p256"
	AlgECP384 AlgorithmID = "ec-p384"
	AlgECP521 AlgorithmID = "ec-p521"
)

// Post-quantum signature algorithms (FIPS 204 ML-DSA).
const (
	AlgMLDSA44 AlgorithmID = "ml-dsa-44"
	AlgMLDSA65 AlgorithmID = "ml-dsa-65"
	AlgMLDSA87 AlgorithmID = "ml-dsa-87"
)

// Post-quantum signature algorithms (FIPS 205 SLH-DSA, RFC 9814).
// Variants: s = small signatures (~8KB), f = fast signing (~17-50KB).
// SHA2 variants use SHA-256/SHA-512, SHAKE variants use SHAKE128/SHAKE256.
const (
	// SHA2 variants (RFC 9814 OIDs 20-25)
	AlgSLHDSASHA2128s AlgorithmID = "slh-dsa-sha2-128s"
	AlgSLHDSASHA2128f AlgorithmID = "slh-dsa-sha2-128f"
	AlgSLHDSASHA2192s AlgorithmID = "slh-dsa-sha2-192s"
	AlgSLHDSASHA2192f AlgorithmID = "slh-dsa-sha2-192f"
	AlgSLHDSASHA2256s AlgorithmID = "slh-dsa-sha2-256s"
	AlgSLHDSASHA2256f AlgorithmID = "slh-dsa-sha2-256f"

	// SHAKE variants (RFC 9814 OIDs 26-31)
	AlgSLHDSASHAKE128s AlgorithmID = "slh-dsa-shake-128s"
	AlgSLHDSASHAKE128f AlgorithmID = "slh-dsa-shake-128f"
	AlgSLHDSASHAKE192s AlgorithmID = "slh-dsa-shake-192s"
	AlgSLHDSASHAKE192f AlgorithmID = "slh-dsa-shake-192f"
	AlgSLHDSASHAKE256s AlgorithmID = "slh-dsa-shake-256s"
	AlgSLHDSASHAKE256f AlgorithmID = "slh-dsa-shake-256f"

	// Aliases for backwards compatibility (deprecated, use SHA2 variants)
	AlgSLHDSA128s AlgorithmID = AlgSLHDSASHA2128s
	AlgSLHDSA128f AlgorithmID = AlgSLHDSASHA2128f
	AlgSLHDSA192s AlgorithmID = AlgSLHDSASHA2192s
	AlgSLHDSA192f AlgorithmID = AlgSLHDSASHA2192f
	AlgSLHDSA256s AlgorithmID = AlgSLHDSASHA2256s
	AlgSLHDSA256f AlgorithmID = AlgSLHDSASHA2256f
)

// Post-quantum KEM algorithms (FIPS 203 ML-KEM).
const (
	AlgMLKEM512  AlgorithmID = "ml-kem-512"
	AlgMLKEM768  AlgorithmID = "ml-kem-768"
	AlgMLKEM1024 AlgorithmID = "ml-kem-1024"
)

// Hybrid algorithms (classical + PQC).
const (
	AlgHybridP256MLDSA44    AlgorithmID = "hybrid-p256-mldsa44"
	AlgHybridP384MLDSA65    AlgorithmID = "hybrid-p384-mldsa65"
	AlgHybridX25519MLKEM768 AlgorithmID = "hybrid-x25519-mlkem768"
)

// AlgorithmType categorizes algorithms.
type AlgorithmType int

const (
	TypeUnknown AlgorithmType = iota
	TypeClassicalSignature
	TypePQCSignature
	TypePQCKEM
	TypeHybrid
)

// algorithmInfo holds metadata about an algorithm.
type algorithmInfo struct {
	Type        AlgorithmType
	OID         asn1.ObjectIdentifier
	X509SigAlg  x509.SignatureAlgorithm
	KeySizeBits int
	Description string
}

// algorithms maps AlgorithmID to its metadata.
var algorithms = map[AlgorithmID]algorithmInfo{
	// Classical ECDSA
	AlgECDSAP256: {
		Type:        TypeClassicalSignature,
		OID:         asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7},
		X509SigAlg:  x509.ECDSAWithSHA256,
		KeySizeBits: 256,
		Description: "ECDSA with P-256 curve",
	},
	AlgECDSAP384: {
		Type:        TypeClassicalSignature,
		OID:         asn1.ObjectIdentifier{1, 3, 132, 0, 34},
		X509SigAlg:  x509.ECDSAWithSHA384,
		KeySizeBits: 384,
		Description: "ECDSA with P-384 curve",
	},
	AlgECDSAP521: {
		Type:        TypeClassicalSignature,
		OID:         asn1.ObjectIdentifier{1, 3, 132, 0, 35},
		X509SigAlg:  x509.ECDSAWithSHA512,
		KeySizeBits: 521,
		Description: "ECDSA with P-521 curve",
	},

	// EC key type aliases (preferred names for profiles)
	AlgECP256: {
		Type:        TypeClassicalSignature,
		OID:         asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7},
		X509SigAlg:  x509.ECDSAWithSHA256,
		KeySizeBits: 256,
		Description: "EC P-256 key (ECDSA/ECDH)",
	},
	AlgECP384: {
		Type:        TypeClassicalSignature,
		OID:         asn1.ObjectIdentifier{1, 3, 132, 0, 34},
		X509SigAlg:  x509.ECDSAWithSHA384,
		KeySizeBits: 384,
		Description: "EC P-384 key (ECDSA/ECDH)",
	},
	AlgECP521: {
		Type:        TypeClassicalSignature,
		OID:         asn1.ObjectIdentifier{1, 3, 132, 0, 35},
		X509SigAlg:  x509.ECDSAWithSHA512,
		KeySizeBits: 521,
		Description: "EC P-521 key (ECDSA/ECDH)",
	},

	// Edwards curves
	AlgEd25519: {
		Type:        TypeClassicalSignature,
		OID:         asn1.ObjectIdentifier{1, 3, 101, 112},
		X509SigAlg:  x509.PureEd25519,
		KeySizeBits: 256,
		Description: "Ed25519 (EdDSA with Curve25519)",
	},
	AlgEd448: {
		Type:        TypeClassicalSignature,
		OID:         asn1.ObjectIdentifier{1, 3, 101, 113},
		X509SigAlg:  0, // Go's x509 doesn't support Ed448 yet
		KeySizeBits: 448,
		Description: "Ed448 (EdDSA with Curve448)",
	},

	// RSA
	AlgRSA2048: {
		Type:        TypeClassicalSignature,
		OID:         asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1},
		X509SigAlg:  x509.SHA256WithRSA,
		KeySizeBits: 2048,
		Description: "RSA 2048-bit (legacy)",
	},
	AlgRSA4096: {
		Type:        TypeClassicalSignature,
		OID:         asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1},
		X509SigAlg:  x509.SHA256WithRSA,
		KeySizeBits: 4096,
		Description: "RSA 4096-bit",
	},

	// PQC Signatures (ML-DSA, FIPS 204)
	AlgMLDSA44: {
		Type:        TypePQCSignature,
		OID:         asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17},
		X509SigAlg:  0,
		KeySizeBits: 0, // Variable
		Description: "ML-DSA-44 (NIST Level 1)",
	},
	AlgMLDSA65: {
		Type:        TypePQCSignature,
		OID:         asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18},
		X509SigAlg:  0,
		KeySizeBits: 0,
		Description: "ML-DSA-65 (NIST Level 3)",
	},
	AlgMLDSA87: {
		Type:        TypePQCSignature,
		OID:         asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19},
		X509SigAlg:  0,
		KeySizeBits: 0,
		Description: "ML-DSA-87 (NIST Level 5)",
	},

	// PQC Signatures (SLH-DSA, FIPS 205, RFC 9814) - Hash-based stateless signatures
	// SHA2 variants (OIDs 20-25)
	AlgSLHDSASHA2128s: {
		Type:        TypePQCSignature,
		OID:         asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 20},
		X509SigAlg:  0,
		KeySizeBits: 0,
		Description: "SLH-DSA-SHA2-128s (NIST Level 1, small)",
	},
	AlgSLHDSASHA2128f: {
		Type:        TypePQCSignature,
		OID:         asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 21},
		X509SigAlg:  0,
		KeySizeBits: 0,
		Description: "SLH-DSA-SHA2-128f (NIST Level 1, fast)",
	},
	AlgSLHDSASHA2192s: {
		Type:        TypePQCSignature,
		OID:         asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 22},
		X509SigAlg:  0,
		KeySizeBits: 0,
		Description: "SLH-DSA-SHA2-192s (NIST Level 3, small)",
	},
	AlgSLHDSASHA2192f: {
		Type:        TypePQCSignature,
		OID:         asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 23},
		X509SigAlg:  0,
		KeySizeBits: 0,
		Description: "SLH-DSA-SHA2-192f (NIST Level 3, fast)",
	},
	AlgSLHDSASHA2256s: {
		Type:        TypePQCSignature,
		OID:         asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 24},
		X509SigAlg:  0,
		KeySizeBits: 0,
		Description: "SLH-DSA-SHA2-256s (NIST Level 5, small)",
	},
	AlgSLHDSASHA2256f: {
		Type:        TypePQCSignature,
		OID:         asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 25},
		X509SigAlg:  0,
		KeySizeBits: 0,
		Description: "SLH-DSA-SHA2-256f (NIST Level 5, fast)",
	},
	// SHAKE variants (OIDs 26-31)
	AlgSLHDSASHAKE128s: {
		Type:        TypePQCSignature,
		OID:         asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 26},
		X509SigAlg:  0,
		KeySizeBits: 0,
		Description: "SLH-DSA-SHAKE-128s (NIST Level 1, small)",
	},
	AlgSLHDSASHAKE128f: {
		Type:        TypePQCSignature,
		OID:         asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 27},
		X509SigAlg:  0,
		KeySizeBits: 0,
		Description: "SLH-DSA-SHAKE-128f (NIST Level 1, fast)",
	},
	AlgSLHDSASHAKE192s: {
		Type:        TypePQCSignature,
		OID:         asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 28},
		X509SigAlg:  0,
		KeySizeBits: 0,
		Description: "SLH-DSA-SHAKE-192s (NIST Level 3, small)",
	},
	AlgSLHDSASHAKE192f: {
		Type:        TypePQCSignature,
		OID:         asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 29},
		X509SigAlg:  0,
		KeySizeBits: 0,
		Description: "SLH-DSA-SHAKE-192f (NIST Level 3, fast)",
	},
	AlgSLHDSASHAKE256s: {
		Type:        TypePQCSignature,
		OID:         asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 30},
		X509SigAlg:  0,
		KeySizeBits: 0,
		Description: "SLH-DSA-SHAKE-256s (NIST Level 5, small)",
	},
	AlgSLHDSASHAKE256f: {
		Type:        TypePQCSignature,
		OID:         asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 31},
		X509SigAlg:  0,
		KeySizeBits: 0,
		Description: "SLH-DSA-SHAKE-256f (NIST Level 5, fast)",
	},

	// PQC KEM (ML-KEM, FIPS 203)
	AlgMLKEM512: {
		Type:        TypePQCKEM,
		OID:         asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 1},
		X509SigAlg:  0,
		KeySizeBits: 0,
		Description: "ML-KEM-512 (NIST Level 1)",
	},
	AlgMLKEM768: {
		Type:        TypePQCKEM,
		OID:         asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 2},
		X509SigAlg:  0,
		KeySizeBits: 0,
		Description: "ML-KEM-768 (NIST Level 3)",
	},
	AlgMLKEM1024: {
		Type:        TypePQCKEM,
		OID:         asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 3},
		X509SigAlg:  0,
		KeySizeBits: 0,
		Description: "ML-KEM-1024 (NIST Level 5)",
	},

	// Hybrid algorithms
	AlgHybridP256MLDSA44: {
		Type:        TypeHybrid,
		OID:         asn1.ObjectIdentifier{2, 999, 1, 1, 1}, // Experimental arc
		X509SigAlg:  x509.ECDSAWithSHA256,
		KeySizeBits: 0,
		Description: "Hybrid ECDSA-P256 + ML-DSA-44",
	},
	AlgHybridP384MLDSA65: {
		Type:        TypeHybrid,
		OID:         asn1.ObjectIdentifier{2, 999, 1, 1, 2},
		X509SigAlg:  x509.ECDSAWithSHA384,
		KeySizeBits: 0,
		Description: "Hybrid ECDSA-P384 + ML-DSA-65",
	},
	AlgHybridX25519MLKEM768: {
		Type:        TypeHybrid,
		OID:         asn1.ObjectIdentifier{2, 999, 1, 2, 1},
		X509SigAlg:  0,
		KeySizeBits: 0,
		Description: "Hybrid X25519 + ML-KEM-768",
	},
}

// IsValid returns true if the algorithm is recognized.
func (a AlgorithmID) IsValid() bool {
	_, ok := algorithms[a]
	return ok
}

// Type returns the algorithm type.
func (a AlgorithmID) Type() AlgorithmType {
	if info, ok := algorithms[a]; ok {
		return info.Type
	}
	return TypeUnknown
}

// IsClassical returns true for classical (non-PQC) algorithms.
func (a AlgorithmID) IsClassical() bool {
	return a.Type() == TypeClassicalSignature
}

// IsPQC returns true for post-quantum algorithms.
func (a AlgorithmID) IsPQC() bool {
	t := a.Type()
	return t == TypePQCSignature || t == TypePQCKEM
}

// IsHybrid returns true for hybrid algorithms.
func (a AlgorithmID) IsHybrid() bool {
	return a.Type() == TypeHybrid
}

// IsSignature returns true for signature algorithms (classical or PQC).
func (a AlgorithmID) IsSignature() bool {
	t := a.Type()
	return t == TypeClassicalSignature || t == TypePQCSignature
}

// IsKEM returns true for Key Encapsulation Mechanism algorithms.
func (a AlgorithmID) IsKEM() bool {
	return a.Type() == TypePQCKEM
}

// OID returns the ASN.1 Object Identifier for this algorithm.
func (a AlgorithmID) OID() asn1.ObjectIdentifier {
	if info, ok := algorithms[a]; ok {
		return info.OID
	}
	return nil
}

// X509SignatureAlgorithm returns the x509.SignatureAlgorithm if applicable.
// Returns 0 for algorithms not supported by Go's crypto/x509.
func (a AlgorithmID) X509SignatureAlgorithm() x509.SignatureAlgorithm {
	if info, ok := algorithms[a]; ok {
		return info.X509SigAlg
	}
	return 0
}

// Description returns a human-readable description of the algorithm.
func (a AlgorithmID) Description() string {
	if info, ok := algorithms[a]; ok {
		return info.Description
	}
	return "Unknown algorithm"
}

// String returns the algorithm identifier as a string.
func (a AlgorithmID) String() string {
	return string(a)
}

// Family returns the algorithm family for grouping (e.g., "ec", "rsa", "ml-dsa").
// Used for CRL organization and directory structure in multi-profile versions.
func (a AlgorithmID) Family() string {
	switch a {
	case AlgECDSAP256, AlgECDSAP384, AlgECDSAP521, AlgECP256, AlgECP384, AlgECP521:
		return "ec"
	case AlgEd25519, AlgEd448:
		return "ed"
	case AlgRSA2048, AlgRSA4096:
		return "rsa"
	case AlgMLDSA44, AlgMLDSA65, AlgMLDSA87:
		return "ml-dsa"
	case AlgSLHDSASHA2128s, AlgSLHDSASHA2128f, AlgSLHDSASHA2192s, AlgSLHDSASHA2192f, AlgSLHDSASHA2256s, AlgSLHDSASHA2256f,
		AlgSLHDSASHAKE128s, AlgSLHDSASHAKE128f, AlgSLHDSASHAKE192s, AlgSLHDSASHAKE192f, AlgSLHDSASHAKE256s, AlgSLHDSASHAKE256f:
		return "slh-dsa"
	case AlgMLKEM512, AlgMLKEM768, AlgMLKEM1024:
		return "ml-kem"
	case AlgHybridP256MLDSA44, AlgHybridP384MLDSA65:
		return "hybrid"
	case AlgHybridX25519MLKEM768:
		return "hybrid-kem"
	default:
		return "unknown"
	}
}

// ParseAlgorithm parses a string into an AlgorithmID.
// Returns an error if the algorithm is not recognized.
func ParseAlgorithm(s string) (AlgorithmID, error) {
	alg := AlgorithmID(s)
	if !alg.IsValid() {
		return "", fmt.Errorf("unknown algorithm: %s", s)
	}
	return alg, nil
}

// AllAlgorithms returns a list of all supported algorithm IDs.
func AllAlgorithms() []AlgorithmID {
	result := make([]AlgorithmID, 0, len(algorithms))
	for alg := range algorithms {
		result = append(result, alg)
	}
	return result
}

// SignatureAlgorithms returns all algorithms that can be used for signing.
func SignatureAlgorithms() []AlgorithmID {
	var result []AlgorithmID
	for alg := range algorithms {
		if alg.IsSignature() || alg.IsHybrid() {
			result = append(result, alg)
		}
	}
	return result
}

// ClassicalAlgorithms returns all classical (non-PQC) algorithms.
func ClassicalAlgorithms() []AlgorithmID {
	var result []AlgorithmID
	for alg := range algorithms {
		if alg.IsClassical() {
			result = append(result, alg)
		}
	}
	return result
}

// PQCAlgorithms returns all post-quantum algorithms.
func PQCAlgorithms() []AlgorithmID {
	var result []AlgorithmID
	for alg := range algorithms {
		if alg.IsPQC() {
			result = append(result, alg)
		}
	}
	return result
}

// AlgUnknown represents an unknown or unsupported algorithm.
const AlgUnknown AlgorithmID = ""

// AlgorithmFromOID returns the AlgorithmID for a given OID.
// Returns AlgUnknown if the OID is not recognized.
func AlgorithmFromOID(oid asn1.ObjectIdentifier) AlgorithmID {
	for alg, info := range algorithms {
		if oid.Equal(info.OID) {
			return alg
		}
	}
	return AlgUnknown
}
