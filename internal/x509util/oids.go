// Package x509util provides utilities for X.509 certificate handling,
// including OID definitions, certificate building, and custom extensions.
package x509util

import (
	"encoding/asn1"
	"fmt"
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

	// Name Constraints extension
	OIDExtNameConstraints = asn1.ObjectIdentifier{2, 5, 29, 30}
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

	// RSA with SHA-256
	OIDSignatureRSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	// RSA with SHA-384
	OIDSignatureRSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	// RSA with SHA-512
	OIDSignatureRSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
)

// Elliptic Curve OIDs.
var (
	// OIDPublicKeyECDSA is the OID for EC public keys (id-ecPublicKey).
	OIDPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}

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

	// SLH-DSA (Stateless Hash-Based Digital Signature Algorithm) - FIPS 205, RFC 9814
	// SHA2 variants (OIDs 20-25)
	OIDSLHDSA128s = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 20}
	OIDSLHDSA128f = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 21}
	OIDSLHDSA192s = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 22}
	OIDSLHDSA192f = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 23}
	OIDSLHDSA256s = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 24}
	OIDSLHDSA256f = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 25}

	// SHAKE variants (OIDs 26-31) - RFC 9814
	OIDSLHDSASHAKE128s = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 26}
	OIDSLHDSASHAKE128f = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 27}
	OIDSLHDSASHAKE192s = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 28}
	OIDSLHDSASHAKE192f = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 29}
	OIDSLHDSASHAKE256s = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 30}
	OIDSLHDSASHAKE256f = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 31}
)

// Catalyst Extensions OIDs (ITU-T X.509 Section 9.8).
// These are the standard OIDs for hybrid certificates with alternative keys/signatures.
var (
	// OIDAltSubjectPublicKeyInfo carries the alternative (PQC) public key.
	// ITU-T X.509 (2019) Section 9.8
	OIDAltSubjectPublicKeyInfo = asn1.ObjectIdentifier{2, 5, 29, 72}

	// OIDAltSignatureAlgorithm identifies the algorithm used for the alternative signature.
	// ITU-T X.509 (2019) Section 9.8
	OIDAltSignatureAlgorithm = asn1.ObjectIdentifier{2, 5, 29, 73}

	// OIDAltSignatureValue contains the alternative signature value.
	// ITU-T X.509 (2019) Section 9.8
	OIDAltSignatureValue = asn1.ObjectIdentifier{2, 5, 29, 74}
)

// Hybrid Extension OIDs (experimental arc 2.999.x).
// These are used for the custom hybrid public key extension.
// DEPRECATED: Use Catalyst extensions (OIDAltSubjectPublicKeyInfo, etc.) instead.
var (
	// OIDHybridPublicKeyExtension is the OID for our hybrid public key X.509 extension.
	// This extension carries PQC public key material alongside the classical certificate.
	// Arc: 2.999.1 (experimental)
	// DEPRECATED: Use OIDAltSubjectPublicKeyInfo instead.
	OIDHybridPublicKeyExtension = asn1.ObjectIdentifier{2, 999, 1, 1}

	// OIDHybridSignature is for hybrid signature algorithms.
	// DEPRECATED: Use Catalyst extensions instead.
	OIDHybridSignatureP256MLDSA44 = asn1.ObjectIdentifier{2, 999, 1, 2, 1}
	OIDHybridSignatureP384MLDSA65 = asn1.ObjectIdentifier{2, 999, 1, 2, 2}

	// OIDHybridKEM is for hybrid KEM algorithms.
	// DEPRECATED: Use Catalyst extensions instead.
	OIDHybridKEMX25519MLKEM768 = asn1.ObjectIdentifier{2, 999, 1, 3, 1}
)

// RelatedCertificate OID (draft-ietf-lamps-cert-binding-for-multi-auth).
// This extension links related certificates for multi-algorithm authentication.
var (
	// OIDRelatedCertificate is the OID for the RelatedCertificate extension.
	// From draft-ietf-lamps-cert-binding-for-multi-auth-06.
	// Arc: id-pe 101 (1.3.6.1.5.5.7.1.101)
	OIDRelatedCertificate = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 101}

	// OIDRelatedCertRequest is the attribute OID for CSR relatedCertRequest.
	// From draft-ietf-lamps-cert-binding-for-multi-auth-06.
	// Arc: id-aa 102 (1.2.840.113549.1.9.16.2.102)
	OIDRelatedCertRequest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 102}
)

// QCStatements OIDs (RFC 3739 / ETSI EN 319 412-5).
// Used for eIDAS qualified certificates.
var (
	// OIDQCStatements is the OID for the QCStatements extension (RFC 3739).
	// id-pe-qcStatements (1.3.6.1.5.5.7.1.3)
	OIDQCStatements = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 3}

	// OIDQcCompliance indicates the certificate is an EU qualified certificate (ETSI EN 319 412-5).
	// id-etsi-qcs-QcCompliance (0.4.0.1862.1.1)
	OIDQcCompliance = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 1}

	// OIDQcRetentionPeriod specifies the retention period for certificate info (ETSI EN 319 412-5).
	// id-etsi-qcs-QcRetentionPeriod (0.4.0.1862.1.3)
	OIDQcRetentionPeriod = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 3}

	// OIDQcSSCD indicates the certificate is issued by a QSCD (ETSI EN 319 412-5).
	// id-etsi-qcs-QcSSCD (0.4.0.1862.1.4)
	OIDQcSSCD = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 4}

	// OIDQcPDS references PKI Disclosure Statements (ETSI EN 319 412-5).
	// id-etsi-qcs-QcPDS (0.4.0.1862.1.5)
	OIDQcPDS = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 5}

	// OIDQcType specifies the type of qualified certificate (ETSI EN 319 412-5).
	// id-etsi-qcs-QcType (0.4.0.1862.1.6)
	OIDQcType = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 6}
)

// QcType OID values (ETSI EN 319 412-5).
// These identify the type of qualified certificate.
var (
	// OIDQcTypeESign indicates electronic signature (natural person).
	// id-etsi-qct-esign (0.4.0.1862.1.6.1)
	OIDQcTypeESign = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 6, 1}

	// OIDQcTypeESeal indicates electronic seal (legal person).
	// id-etsi-qct-eseal (0.4.0.1862.1.6.2)
	OIDQcTypeESeal = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 6, 2}

	// OIDQcTypeWeb indicates qualified website authentication (QWAC).
	// id-etsi-qct-web (0.4.0.1862.1.6.3)
	OIDQcTypeWeb = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 6, 3}
)

// Timestamp Token QCStatements OIDs (ETSI EN 319 422).
// Used in TSTInfo extensions for eIDAS qualified timestamps.
var (
	// OIDesi4QtstStatement1 indicates the timestamp claims to be a qualified
	// electronic time stamp per EU Regulation 910/2014 (eIDAS).
	// id-etsi-tst-qtstStatement-1 (0.4.0.19422.1.1)
	// ETSI EN 319 422 Section 9.1
	OIDesi4QtstStatement1 = asn1.ObjectIdentifier{0, 4, 0, 19422, 1, 1}
)

// IETF Composite Signature OIDs (draft-ietf-lamps-pq-composite-sigs-13).
// These combine ML-DSA with classical algorithms in a single composite signature.
// Only IANA-allocated OIDs are supported.
// IETF arc: 1.3.6.1.5.5.7.6.x (id-smime algorithms)
// Source: https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/13/
var (
	// OIDMLDSA65ECDSAP256SHA512 is ML-DSA-65 + ECDSA-P256 with SHA-512.
	// NIST Level 3 PQC + ~128-bit classical security.
	OIDMLDSA65ECDSAP256SHA512 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 45}

	// OIDMLDSA65ECDSAP384SHA512 is ML-DSA-65 + ECDSA-P384 with SHA-512.
	// NIST Level 3 PQC + ~192-bit classical security.
	OIDMLDSA65ECDSAP384SHA512 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 46}

	// OIDMLDSA87ECDSAP521SHA512 is ML-DSA-87 + ECDSA-P521 with SHA-512.
	// NIST Level 5 PQC + ~256-bit classical security.
	OIDMLDSA87ECDSAP521SHA512 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 54}
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

// IsCompositeOID checks if an OID is a composite signature algorithm.
func IsCompositeOID(oid asn1.ObjectIdentifier) bool {
	return OIDEqual(oid, OIDMLDSA65ECDSAP256SHA512) ||
		OIDEqual(oid, OIDMLDSA65ECDSAP384SHA512) ||
		OIDEqual(oid, OIDMLDSA87ECDSAP521SHA512)
}

// OIDToString converts an OID to its dotted string representation.
func OIDToString(oid asn1.ObjectIdentifier) string {
	return oid.String()
}

// algorithmNames maps OID string representations to human-readable names.
// Using a map reduces cyclomatic complexity compared to a switch statement.
var algorithmNames = map[string]string{
	// ML-DSA (FIPS 204)
	"2.16.840.1.101.3.4.3.17": "ML-DSA-44",
	"2.16.840.1.101.3.4.3.18": "ML-DSA-65",
	"2.16.840.1.101.3.4.3.19": "ML-DSA-87",

	// SLH-DSA (FIPS 205)
	"2.16.840.1.101.3.4.3.20": "SLH-DSA-128s",
	"2.16.840.1.101.3.4.3.21": "SLH-DSA-128f",
	"2.16.840.1.101.3.4.3.22": "SLH-DSA-192s",
	"2.16.840.1.101.3.4.3.23": "SLH-DSA-192f",
	"2.16.840.1.101.3.4.3.24": "SLH-DSA-256s",
	"2.16.840.1.101.3.4.3.25": "SLH-DSA-256f",

	// ML-KEM (FIPS 203)
	"2.16.840.1.101.3.4.4.1": "ML-KEM-512",
	"2.16.840.1.101.3.4.4.2": "ML-KEM-768",
	"2.16.840.1.101.3.4.4.3": "ML-KEM-1024",

	// ECDSA
	"1.2.840.10045.4.3.2": "ECDSA-SHA256",
	"1.2.840.10045.4.3.3": "ECDSA-SHA384",
	"1.2.840.10045.4.3.4": "ECDSA-SHA512",

	// Ed25519
	"1.3.101.112": "Ed25519",

	// RSA
	"1.2.840.113549.1.1.11": "RSA-SHA256",
	"1.2.840.113549.1.1.12": "RSA-SHA384",
	"1.2.840.113549.1.1.13": "RSA-SHA512",

	// Composite Signatures (IETF draft-ietf-lamps-pq-composite-sigs-13)
	"1.3.6.1.5.5.7.6.45": "MLDSA65-ECDSA-P256-SHA512",
	"1.3.6.1.5.5.7.6.46": "MLDSA65-ECDSA-P384-SHA512",
	"1.3.6.1.5.5.7.6.54": "MLDSA87-ECDSA-P521-SHA512",
}

// AlgorithmName returns a human-readable name for an algorithm OID.
// Returns the OID string representation if unknown.
func AlgorithmName(oid asn1.ObjectIdentifier) string {
	if name, ok := algorithmNames[oid.String()]; ok {
		return name
	}
	return oid.String()
}

// IsPQCSignatureAlgorithmOID checks if a raw TBS certificate uses a PQC signature algorithm.
// It parses the TBS to extract the signatureAlgorithm OID and checks against known PQC OIDs.
func IsPQCSignatureAlgorithmOID(rawTBS []byte) bool {
	// Parse TBS structure to extract signatureAlgorithm
	// TBSCertificate ::= SEQUENCE {
	//   version         [0] EXPLICIT Version DEFAULT v1,
	//   serialNumber    CertificateSerialNumber,
	//   signature       AlgorithmIdentifier,
	//   ...
	// }
	var tbs struct {
		Raw          asn1.RawContent
		Version      int `asn1:"optional,explicit,default:0,tag:0"`
		SerialNumber asn1.RawValue
		SigAlg       struct {
			Algorithm asn1.ObjectIdentifier
		}
	}
	if _, err := asn1.Unmarshal(rawTBS, &tbs); err != nil {
		return false
	}

	// Check if the signature algorithm OID is a known PQC algorithm
	return OIDEqual(tbs.SigAlg.Algorithm, OIDMLDSA44) ||
		OIDEqual(tbs.SigAlg.Algorithm, OIDMLDSA65) ||
		OIDEqual(tbs.SigAlg.Algorithm, OIDMLDSA87) ||
		// SLH-DSA SHA2 variants
		OIDEqual(tbs.SigAlg.Algorithm, OIDSLHDSA128s) ||
		OIDEqual(tbs.SigAlg.Algorithm, OIDSLHDSA128f) ||
		OIDEqual(tbs.SigAlg.Algorithm, OIDSLHDSA192s) ||
		OIDEqual(tbs.SigAlg.Algorithm, OIDSLHDSA192f) ||
		OIDEqual(tbs.SigAlg.Algorithm, OIDSLHDSA256s) ||
		OIDEqual(tbs.SigAlg.Algorithm, OIDSLHDSA256f) ||
		// SLH-DSA SHAKE variants (RFC 9814)
		OIDEqual(tbs.SigAlg.Algorithm, OIDSLHDSASHAKE128s) ||
		OIDEqual(tbs.SigAlg.Algorithm, OIDSLHDSASHAKE128f) ||
		OIDEqual(tbs.SigAlg.Algorithm, OIDSLHDSASHAKE192s) ||
		OIDEqual(tbs.SigAlg.Algorithm, OIDSLHDSASHAKE192f) ||
		OIDEqual(tbs.SigAlg.Algorithm, OIDSLHDSASHAKE256s) ||
		OIDEqual(tbs.SigAlg.Algorithm, OIDSLHDSASHAKE256f)
}

// ExtractSignatureAlgorithmOID extracts the signature algorithm OID from certificate raw bytes.
// This is useful when Go's x509 package doesn't recognize the algorithm (returns 0).
func ExtractSignatureAlgorithmOID(rawCert []byte) (asn1.ObjectIdentifier, error) {
	// Certificate ::= SEQUENCE {
	//   tbsCertificate       TBSCertificate,
	//   signatureAlgorithm   AlgorithmIdentifier,
	//   signatureValue       BIT STRING
	// }
	var cert struct {
		TBS    asn1.RawValue
		SigAlg struct {
			Algorithm asn1.ObjectIdentifier
		}
	}
	_, err := asn1.Unmarshal(rawCert, &cert)
	if err != nil {
		return nil, err
	}
	return cert.SigAlg.Algorithm, nil
}

// ExtractTBSAndSignature extracts the TBS (To Be Signed) certificate data and signature
// from a raw certificate. This is used for PQC certificate verification since Go's x509
// package doesn't support PQC signature verification.
func ExtractTBSAndSignature(rawCert []byte) (tbsData []byte, signature []byte, err error) {
	// Certificate ::= SEQUENCE {
	//   tbsCertificate       TBSCertificate,
	//   signatureAlgorithm   AlgorithmIdentifier,
	//   signatureValue       BIT STRING
	// }
	var cert struct {
		TBS       asn1.RawValue
		SigAlg    asn1.RawValue
		Signature asn1.BitString
	}
	_, err = asn1.Unmarshal(rawCert, &cert)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	return cert.TBS.FullBytes, cert.Signature.Bytes, nil
}

// ExtractPublicKeyAlgorithmOID extracts the public key algorithm OID from certificate raw bytes.
// This is useful when Go's x509 package doesn't recognize the algorithm (returns 0).
func ExtractPublicKeyAlgorithmOID(rawCert []byte) (asn1.ObjectIdentifier, error) {
	// Certificate ::= SEQUENCE {
	//   tbsCertificate       TBSCertificate,
	//   ...
	// }
	// TBSCertificate ::= SEQUENCE {
	//   version         [0] EXPLICIT Version DEFAULT v1,
	//   serialNumber    CertificateSerialNumber,
	//   signature       AlgorithmIdentifier,
	//   issuer          Name,
	//   validity        Validity,
	//   subject         Name,
	//   subjectPublicKeyInfo SubjectPublicKeyInfo,
	//   ...
	// }
	// SubjectPublicKeyInfo ::= SEQUENCE {
	//   algorithm        AlgorithmIdentifier,
	//   subjectPublicKey BIT STRING
	// }
	var cert struct {
		TBS struct {
			Raw          asn1.RawContent
			Version      int `asn1:"optional,explicit,default:0,tag:0"`
			SerialNumber asn1.RawValue
			SigAlg       asn1.RawValue
			Issuer       asn1.RawValue
			Validity     asn1.RawValue
			Subject      asn1.RawValue
			SPKI         struct {
				Algorithm struct {
					Algorithm asn1.ObjectIdentifier
				}
			}
		}
	}
	_, err := asn1.Unmarshal(rawCert, &cert)
	if err != nil {
		return nil, err
	}
	return cert.TBS.SPKI.Algorithm.Algorithm, nil
}

// ExtractCSRSignatureAlgorithmOID extracts the signature algorithm OID from CSR raw bytes.
func ExtractCSRSignatureAlgorithmOID(rawCSR []byte) (asn1.ObjectIdentifier, error) {
	// CertificationRequest ::= SEQUENCE {
	//   certificationRequestInfo CertificationRequestInfo,
	//   signatureAlgorithm       AlgorithmIdentifier,
	//   signature                BIT STRING
	// }
	var csr struct {
		RequestInfo asn1.RawValue
		SigAlg      struct {
			Algorithm asn1.ObjectIdentifier
		}
	}
	_, err := asn1.Unmarshal(rawCSR, &csr)
	if err != nil {
		return nil, err
	}
	return csr.SigAlg.Algorithm, nil
}

// ExtractCSRPublicKeyAlgorithmOID extracts the public key algorithm OID from CSR raw bytes.
func ExtractCSRPublicKeyAlgorithmOID(rawCSR []byte) (asn1.ObjectIdentifier, error) {
	// CertificationRequest ::= SEQUENCE {
	//   certificationRequestInfo CertificationRequestInfo,
	//   ...
	// }
	// CertificationRequestInfo ::= SEQUENCE {
	//   version       INTEGER,
	//   subject       Name,
	//   subjectPKInfo SubjectPublicKeyInfo,
	//   attributes    [0] Attributes
	// }
	var csr struct {
		RequestInfo struct {
			Version int
			Subject asn1.RawValue
			SPKI    struct {
				Algorithm struct {
					Algorithm asn1.ObjectIdentifier
				}
			}
		}
	}
	_, err := asn1.Unmarshal(rawCSR, &csr)
	if err != nil {
		return nil, err
	}
	return csr.RequestInfo.SPKI.Algorithm.Algorithm, nil
}

// ExtractCRLSignatureAlgorithmOID extracts the signature algorithm OID from CRL raw bytes.
func ExtractCRLSignatureAlgorithmOID(rawCRL []byte) (asn1.ObjectIdentifier, error) {
	// CertificateList ::= SEQUENCE {
	//   tbsCertList        TBSCertList,
	//   signatureAlgorithm AlgorithmIdentifier,
	//   signatureValue     BIT STRING
	// }
	var crl struct {
		TBSCertList asn1.RawValue
		SigAlg      struct {
			Algorithm asn1.ObjectIdentifier
		}
	}
	_, err := asn1.Unmarshal(rawCRL, &crl)
	if err != nil {
		return nil, err
	}
	return crl.SigAlg.Algorithm, nil
}
