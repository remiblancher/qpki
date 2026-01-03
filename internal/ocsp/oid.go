package ocsp

import "encoding/asn1"

// OCSP OIDs per RFC 6960
var (
	// id-pkix-ocsp OBJECT IDENTIFIER ::= { id-ad-ocsp }
	// id-ad-ocsp OBJECT IDENTIFIER ::= { iso(1) identified-organization(3)
	//   dod(6) internet(1) security(5) mechanisms(5) pkix(7) ad(48) 1 }
	OIDPKIXOcsp = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}

	// id-pkix-ocsp-basic OBJECT IDENTIFIER ::= { id-pkix-ocsp 1 }
	OIDOcspBasic = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}

	// id-pkix-ocsp-nonce OBJECT IDENTIFIER ::= { id-pkix-ocsp 2 }
	OIDOcspNonce = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}

	// id-pkix-ocsp-crl OBJECT IDENTIFIER ::= { id-pkix-ocsp 3 }
	OIDOcspCRL = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 3}

	// id-pkix-ocsp-response OBJECT IDENTIFIER ::= { id-pkix-ocsp 4 }
	OIDOcspResponse = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 4}

	// id-pkix-ocsp-nocheck OBJECT IDENTIFIER ::= { id-pkix-ocsp 5 }
	OIDOcspNoCheck = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}

	// id-pkix-ocsp-archive-cutoff OBJECT IDENTIFIER ::= { id-pkix-ocsp 6 }
	OIDOcspArchiveCutoff = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 6}

	// id-pkix-ocsp-service-locator OBJECT IDENTIFIER ::= { id-pkix-ocsp 7 }
	OIDOcspServiceLocator = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 7}

	// id-kp-OCSPSigning OBJECT IDENTIFIER ::= { id-kp 9 }
	OIDExtKeyUsageOCSPSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}
)

// Hash algorithm OIDs
var (
	OIDSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	OIDSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OIDSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	OIDSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)

// Signature algorithm OIDs
var (
	// RSA
	OIDSHA256WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	OIDSHA384WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	OIDSHA512WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}

	// ECDSA
	OIDECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	OIDECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	OIDECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}

	// Ed25519
	OIDEd25519 = asn1.ObjectIdentifier{1, 3, 101, 112}

	// ML-DSA (FIPS 204)
	OIDMLDSA44 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	OIDMLDSA65 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	OIDMLDSA87 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}

	// SLH-DSA (FIPS 205)
	OIDSLHDSA128s = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 20}
	OIDSLHDSA128f = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 21}
	OIDSLHDSA192s = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 22}
	OIDSLHDSA192f = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 23}
	OIDSLHDSA256s = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 24}
	OIDSLHDSA256f = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 25}
)
