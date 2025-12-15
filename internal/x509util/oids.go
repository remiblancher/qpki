// Package x509util provides utilities for X.509 certificate handling,
// including OID definitions, certificate building, and custom extensions.
package x509util

import (
	"encoding/asn1"
)

// Standard X.509 OIDs.
var (
	// Key Usage extension
	OIDExtKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 15}

	// Extended Key Usage extension
	OIDExtExtKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}

	// Basic Constraints extension
	OIDExtBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}

	// Subject Alternative Name extension
	OIDExtSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

	// Authority Key Identifier extension
	OIDExtAuthorityKeyId = asn1.ObjectIdentifier{2, 5, 29, 35}

	// Subject Key Identifier extension
	OIDExtSubjectKeyId = asn1.ObjectIdentifier{2, 5, 29, 14}

	// CRL Distribution Points extension
	OIDExtCRLDistributionPoints = asn1.ObjectIdentifier{2, 5, 29, 31}

	// Authority Information Access extension
	OIDExtAuthorityInfoAccess = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}

	// Certificate Policies extension
	OIDExtCertificatePolicies = asn1.ObjectIdentifier{2, 5, 29, 32}
)

// Extended Key Usage OIDs.
var (
	OIDExtKeyUsageServerAuth      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	OIDExtKeyUsageClientAuth      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
	OIDExtKeyUsageCodeSigning     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}
	OIDExtKeyUsageEmailProtection = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}
	OIDExtKeyUsageTimeStamping    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	OIDExtKeyUsageOCSPSigning     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}
)

// Signature Algorithm OIDs (classical).
var (
	// ECDSA with SHA-256
	OIDSignatureECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	// ECDSA with SHA-384
	OIDSignatureECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	// ECDSA with SHA-512
	OIDSignatureECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}

	// Ed25519
	OIDSignatureEd25519 = asn1.ObjectIdentifier{1, 3, 101, 112}
	// Ed448
	OIDSignatureEd448 = asn1.ObjectIdentifier{1, 3, 101, 113}

	// RSA with SHA-256
	OIDSignatureRSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	// RSA with SHA-384
	OIDSignatureRSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	// RSA with SHA-512
	OIDSignatureRSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
)

// Elliptic Curve OIDs.
var (
	OIDNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	OIDNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	OIDNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
)

// Post-Quantum Cryptography OIDs (NIST FIPS 204 / FIPS 203).
var (
	// ML-DSA (Module-Lattice Digital Signature Algorithm) - FIPS 204
	OIDMLDSA44 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	OIDMLDSA65 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	OIDMLDSA87 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}

	// ML-KEM (Module-Lattice Key Encapsulation Mechanism) - FIPS 203
	OIDMLKEM512  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 1}
	OIDMLKEM768  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 2}
	OIDMLKEM1024 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 3}
)

// Hybrid Extension OIDs (experimental arc 2.999.x).
// These are used for the custom hybrid public key extension.
var (
	// OIDHybridPublicKeyExtension is the OID for our hybrid public key X.509 extension.
	// This extension carries PQC public key material alongside the classical certificate.
	// Arc: 2.999.1 (experimental)
	OIDHybridPublicKeyExtension = asn1.ObjectIdentifier{2, 999, 1, 1}

	// OIDHybridSignature is for hybrid signature algorithms.
	OIDHybridSignatureP256MLDSA44 = asn1.ObjectIdentifier{2, 999, 1, 2, 1}
	OIDHybridSignatureP384MLDSA65 = asn1.ObjectIdentifier{2, 999, 1, 2, 2}

	// OIDHybridKEM is for hybrid KEM algorithms.
	OIDHybridKEMX25519MLKEM768 = asn1.ObjectIdentifier{2, 999, 1, 3, 1}
)

// OIDEqual compares two OIDs for equality.
func OIDEqual(a, b asn1.ObjectIdentifier) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// OIDToString converts an OID to its dotted string representation.
func OIDToString(oid asn1.ObjectIdentifier) string {
	return oid.String()
}
