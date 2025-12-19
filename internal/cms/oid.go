// Package cms implements a minimal CMS (Cryptographic Message Syntax) for TSA.
// Based on RFC 5652 (CMS) and RFC 3161 (TSP).
package cms

import "encoding/asn1"

// CMS/PKCS#7 OIDs
var (
	// Content types
	OIDData       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	OIDSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}

	// TSP content type (RFC 3161)
	OIDTSTInfo = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}

	// Signed attributes
	OIDContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	OIDMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	OIDSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}

	// Signing certificate attribute (RFC 5035)
	OIDSigningCertificateV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
)

// Hash algorithm OIDs
var (
	OIDSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OIDSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	OIDSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	OIDSHA3_256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 8}
	OIDSHA3_384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 9}
	OIDSHA3_512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 10}

	OIDSHAKE256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 12}
)

// Signature algorithm OIDs
var (
	// ECDSA
	OIDECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	OIDECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	OIDECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}

	// Ed25519
	OIDEd25519 = asn1.ObjectIdentifier{1, 3, 101, 112}

	// RSA
	OIDSHA256WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	OIDSHA384WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	OIDSHA512WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}

	// ML-DSA (FIPS 204)
	OIDMLDSA44 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	OIDMLDSA65 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	OIDMLDSA87 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}

	// SLH-DSA (FIPS 205) - using placeholder OIDs
	OIDSLHDSA128s = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 20}
	OIDSLHDSA128f = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 21}
	OIDSLHDSA192s = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 22}
	OIDSLHDSA192f = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 23}
	OIDSLHDSA256s = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 24}
	OIDSLHDSA256f = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 25}
)
