package x509util

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"

	"github.com/remiblancher/pki/internal/crypto"
)

// HybridPolicy defines how the hybrid public key should be used.
type HybridPolicy int

const (
	// HybridPolicyInformational means the PQC key is for information only.
	// Verifiers may ignore it if they don't support PQC.
	HybridPolicyInformational HybridPolicy = 0

	// HybridPolicyMustVerifyBoth means both classical and PQC signatures
	// must be verified for the certificate to be considered valid.
	HybridPolicyMustVerifyBoth HybridPolicy = 1

	// HybridPolicyPQCPreferred means PQC should be preferred if supported,
	// but classical verification alone is acceptable.
	HybridPolicyPQCPreferred HybridPolicy = 2
)

// HybridPublicKeyInfo represents the ASN.1 structure for the hybrid extension.
//
//	HybridPublicKeyInfo ::= SEQUENCE {
//	    algorithm   AlgorithmIdentifier,
//	    publicKey   BIT STRING,
//	    policy      [0] INTEGER OPTIONAL
//	}
type HybridPublicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
	Policy    int `asn1:"optional,tag:0"`
}

// EncodeHybridExtension creates an X.509 extension containing PQC public key material.
//
// The extension is marked as non-critical, meaning parsers that don't understand it
// can safely ignore it. The classical certificate remains fully valid.
//
// Parameters:
//   - alg: The PQC algorithm (e.g., ml-dsa-65, ml-kem-768)
//   - publicKey: The raw public key bytes
//   - policy: How the hybrid key should be used
//
// Example:
//
//	ext, err := EncodeHybridExtension(crypto.AlgMLDSA65, pubKeyBytes, HybridPolicyInformational)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	// Add ext to certificate's ExtraExtensions
func EncodeHybridExtension(alg crypto.AlgorithmID, publicKey []byte, policy HybridPolicy) (pkix.Extension, error) {
	if !alg.IsPQC() && !alg.IsHybrid() {
		return pkix.Extension{}, fmt.Errorf("algorithm %s is not PQC or hybrid", alg)
	}

	algOID := alg.OID()
	if algOID == nil {
		return pkix.Extension{}, fmt.Errorf("no OID defined for algorithm %s", alg)
	}

	info := HybridPublicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: algOID,
		},
		PublicKey: asn1.BitString{
			Bytes:     publicKey,
			BitLength: len(publicKey) * 8,
		},
		Policy: int(policy),
	}

	value, err := asn1.Marshal(info)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("failed to marshal hybrid extension: %w", err)
	}

	return pkix.Extension{
		Id:       OIDHybridPublicKeyExtension,
		Critical: false, // Non-critical: unknown parsers can ignore it
		Value:    value,
	}, nil
}

// DecodeHybridExtension parses a hybrid public key extension.
//
// Returns the algorithm, public key bytes, and policy.
func DecodeHybridExtension(ext pkix.Extension) (crypto.AlgorithmID, []byte, HybridPolicy, error) {
	if !OIDEqual(ext.Id, OIDHybridPublicKeyExtension) {
		return "", nil, 0, fmt.Errorf("not a hybrid public key extension: %s", ext.Id)
	}

	var info HybridPublicKeyInfo
	rest, err := asn1.Unmarshal(ext.Value, &info)
	if err != nil {
		return "", nil, 0, fmt.Errorf("failed to unmarshal hybrid extension: %w", err)
	}
	if len(rest) > 0 {
		return "", nil, 0, fmt.Errorf("trailing data in hybrid extension")
	}

	// Map OID back to AlgorithmID
	alg, err := oidToAlgorithm(info.Algorithm.Algorithm)
	if err != nil {
		return "", nil, 0, err
	}

	return alg, info.PublicKey.Bytes, HybridPolicy(info.Policy), nil
}

// oidToAlgorithm maps an OID to an AlgorithmID.
func oidToAlgorithm(oid asn1.ObjectIdentifier) (crypto.AlgorithmID, error) {
	switch {
	case OIDEqual(oid, OIDMLDSA44):
		return crypto.AlgMLDSA44, nil
	case OIDEqual(oid, OIDMLDSA65):
		return crypto.AlgMLDSA65, nil
	case OIDEqual(oid, OIDMLDSA87):
		return crypto.AlgMLDSA87, nil
	case OIDEqual(oid, OIDMLKEM512):
		return crypto.AlgMLKEM512, nil
	case OIDEqual(oid, OIDMLKEM768):
		return crypto.AlgMLKEM768, nil
	case OIDEqual(oid, OIDMLKEM1024):
		return crypto.AlgMLKEM1024, nil
	default:
		return "", fmt.Errorf("unknown PQC algorithm OID: %s", oid)
	}
}

// FindHybridExtension searches for the hybrid public key extension in a list of extensions.
// Returns nil if not found.
func FindHybridExtension(extensions []pkix.Extension) *pkix.Extension {
	for i := range extensions {
		if OIDEqual(extensions[i].Id, OIDHybridPublicKeyExtension) {
			return &extensions[i]
		}
	}
	return nil
}

// HasHybridExtension returns true if the certificate has a hybrid public key extension.
func HasHybridExtension(extensions []pkix.Extension) bool {
	return FindHybridExtension(extensions) != nil
}

// HybridExtensionInfo provides a convenient way to access hybrid extension data.
type HybridExtensionInfo struct {
	Algorithm crypto.AlgorithmID
	PublicKey []byte
	Policy    HybridPolicy
}

// ParseHybridExtension parses the hybrid extension from a certificate's extensions.
// Returns nil if no hybrid extension is present.
func ParseHybridExtension(extensions []pkix.Extension) (*HybridExtensionInfo, error) {
	ext := FindHybridExtension(extensions)
	if ext == nil {
		return nil, nil
	}

	alg, pubKey, policy, err := DecodeHybridExtension(*ext)
	if err != nil {
		return nil, err
	}

	return &HybridExtensionInfo{
		Algorithm: alg,
		PublicKey: pubKey,
		Policy:    policy,
	}, nil
}

// String returns a human-readable description of the hybrid policy.
func (p HybridPolicy) String() string {
	switch p {
	case HybridPolicyInformational:
		return "informational"
	case HybridPolicyMustVerifyBoth:
		return "must-verify-both"
	case HybridPolicyPQCPreferred:
		return "pqc-preferred"
	default:
		return fmt.Sprintf("unknown(%d)", p)
	}
}
