// Package x509util provides certificate type detection functions.
package x509util

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
)

// ExtractSPKIAlgorithmOID extracts the algorithm OID from RawSubjectPublicKeyInfo.
// This works on parsed x509.Certificate objects, not raw bytes.
func ExtractSPKIAlgorithmOID(rawSPKI []byte) (asn1.ObjectIdentifier, error) {
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(rawSPKI, &spki); err != nil {
		return nil, err
	}
	return spki.Algorithm.Algorithm, nil
}

// IsPQCOID checks if an OID is a pure PQC signature algorithm (ML-DSA or SLH-DSA).
// This does NOT include Composite algorithms.
func IsPQCOID(oid asn1.ObjectIdentifier) bool {
	// ML-DSA (FIPS 204)
	if OIDEqual(oid, OIDMLDSA44) ||
		OIDEqual(oid, OIDMLDSA65) ||
		OIDEqual(oid, OIDMLDSA87) {
		return true
	}
	// SLH-DSA (FIPS 205)
	if OIDEqual(oid, OIDSLHDSA128s) ||
		OIDEqual(oid, OIDSLHDSA128f) ||
		OIDEqual(oid, OIDSLHDSA192s) ||
		OIDEqual(oid, OIDSLHDSA192f) ||
		OIDEqual(oid, OIDSLHDSA256s) ||
		OIDEqual(oid, OIDSLHDSA256f) {
		return true
	}
	return false
}

// IsCompositeCertificate checks if a certificate uses a Composite public key algorithm.
// Composite certificates have a combined ECDSA+ML-DSA key in the SPKI.
// Standard: IETF draft-ietf-lamps-pq-composite-sigs-13
func IsCompositeCertificate(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	spkiOID, err := ExtractSPKIAlgorithmOID(cert.RawSubjectPublicKeyInfo)
	if err != nil {
		return false
	}
	return IsCompositeOID(spkiOID)
}

// IsCatalystCertificate checks if a certificate is a Catalyst hybrid certificate.
// Catalyst certificates have the altSubjectPublicKeyInfo extension (OID 2.5.29.72)
// which carries an alternative (PQC) public key alongside the classical key.
// Standard: ITU-T X.509 Section 9.8
func IsCatalystCertificate(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDAltSubjectPublicKeyInfo) {
			return true
		}
	}
	return false
}

// IsPQCCertificate checks if a certificate uses a pure PQC public key algorithm.
// This returns true for ML-DSA and SLH-DSA certificates, but NOT for:
// - Composite certificates (combined key)
// - Catalyst certificates (dual keys in extensions)
// - Classical certificates (ECDSA, RSA, Ed25519)
func IsPQCCertificate(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	// Catalyst certificates have a classical primary key with PQC in extension
	if IsCatalystCertificate(cert) {
		return false
	}
	spkiOID, err := ExtractSPKIAlgorithmOID(cert.RawSubjectPublicKeyInfo)
	if err != nil {
		return false
	}
	// Check for pure PQC algorithms (not Composite)
	return IsPQCOID(spkiOID) && !IsCompositeOID(spkiOID)
}

// IsClassicalCertificate checks if a certificate uses a classical public key algorithm.
// This returns true for ECDSA, RSA, and Ed25519 certificates.
func IsClassicalCertificate(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	// Catalyst certificates have classical primary key
	if IsCatalystCertificate(cert) {
		return true // Catalyst uses classical for primary operations
	}
	// Check that it's not PQC or Composite
	spkiOID, err := ExtractSPKIAlgorithmOID(cert.RawSubjectPublicKeyInfo)
	if err != nil {
		// If we can't parse, assume classical (Go parsed it)
		return cert.PublicKey != nil
	}
	return !IsPQCOID(spkiOID) && !IsCompositeOID(spkiOID)
}

// CertificateType represents the cryptographic type of a certificate.
type CertificateType int

const (
	// CertTypeUnknown indicates the certificate type could not be determined.
	CertTypeUnknown CertificateType = iota
	// CertTypeClassical indicates a classical certificate (ECDSA, RSA, Ed25519).
	CertTypeClassical
	// CertTypePQC indicates a pure PQC certificate (ML-DSA, SLH-DSA).
	CertTypePQC
	// CertTypeComposite indicates a Composite certificate (IETF combined key).
	CertTypeComposite
	// CertTypeCatalyst indicates a Catalyst certificate (ITU-T dual keys).
	CertTypeCatalyst
)

// String returns the string representation of the certificate type.
func (t CertificateType) String() string {
	switch t {
	case CertTypeClassical:
		return "Classical"
	case CertTypePQC:
		return "PQC"
	case CertTypeComposite:
		return "Composite"
	case CertTypeCatalyst:
		return "Catalyst"
	default:
		return "Unknown"
	}
}

// GetCertificateType determines the cryptographic type of a certificate.
// The detection order matters:
// 1. Catalyst (has altSubjectPublicKeyInfo extension)
// 2. Composite (SPKI OID is a Composite algorithm)
// 3. PQC (SPKI OID is ML-DSA or SLH-DSA)
// 4. Classical (everything else that Go can parse)
func GetCertificateType(cert *x509.Certificate) CertificateType {
	if cert == nil {
		return CertTypeUnknown
	}

	// Check Catalyst first (extension-based detection)
	if IsCatalystCertificate(cert) {
		return CertTypeCatalyst
	}

	// Check Composite (SPKI OID-based detection)
	if IsCompositeCertificate(cert) {
		return CertTypeComposite
	}

	// Check PQC (SPKI OID-based detection)
	if IsPQCCertificate(cert) {
		return CertTypePQC
	}

	// Default to Classical if Go parsed the public key
	if cert.PublicKey != nil {
		return CertTypeClassical
	}

	return CertTypeUnknown
}
