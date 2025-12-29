package x509util

import (
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"

	"github.com/remiblancher/post-quantum-pki/internal/crypto"
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

// =============================================================================
// Catalyst Extensions (ITU-T X.509 Section 9.8)
// =============================================================================

// AltSubjectPublicKeyInfo represents the alternative public key in a Catalyst certificate.
// This follows the SubjectPublicKeyInfo structure from X.509.
//
//	AltSubjectPublicKeyInfo ::= SEQUENCE {
//	    algorithm        AlgorithmIdentifier,
//	    subjectPublicKey BIT STRING
//	}
type AltSubjectPublicKeyInfo struct {
	Algorithm        pkix.AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

// CatalystExtensions holds all three Catalyst extensions for a hybrid certificate.
type CatalystExtensions struct {
	// AltPublicKey is the alternative (typically PQC) public key
	AltPublicKey *AltSubjectPublicKeyInfo
	// AltSigAlgorithm is the algorithm used for the alternative signature
	AltSigAlgorithm pkix.AlgorithmIdentifier
	// AltSignature is the alternative signature value
	AltSignature []byte
}

// EncodeAltSubjectPublicKeyInfo creates the AltSubjectPublicKeyInfo extension.
// This extension carries the alternative (PQC) public key in a Catalyst certificate.
//
// Parameters:
//   - alg: The algorithm for the alternative key (e.g., ML-DSA-65)
//   - publicKey: The raw public key bytes
//
// Returns a non-critical X.509 extension.
func EncodeAltSubjectPublicKeyInfo(alg crypto.AlgorithmID, publicKey []byte) (pkix.Extension, error) {
	algOID := alg.OID()
	if algOID == nil {
		return pkix.Extension{}, fmt.Errorf("no OID defined for algorithm %s", alg)
	}

	info := AltSubjectPublicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: algOID,
		},
		SubjectPublicKey: asn1.BitString{
			Bytes:     publicKey,
			BitLength: len(publicKey) * 8,
		},
	}

	value, err := asn1.Marshal(info)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("failed to marshal AltSubjectPublicKeyInfo: %w", err)
	}

	return pkix.Extension{
		Id:       OIDAltSubjectPublicKeyInfo,
		Critical: false, // Non-critical for backward compatibility
		Value:    value,
	}, nil
}

// DecodeAltSubjectPublicKeyInfo parses the AltSubjectPublicKeyInfo extension.
//
// Returns the algorithm and public key bytes.
func DecodeAltSubjectPublicKeyInfo(ext pkix.Extension) (crypto.AlgorithmID, []byte, error) {
	if !OIDEqual(ext.Id, OIDAltSubjectPublicKeyInfo) {
		return "", nil, fmt.Errorf("not an AltSubjectPublicKeyInfo extension: %s", ext.Id)
	}

	var info AltSubjectPublicKeyInfo
	rest, err := asn1.Unmarshal(ext.Value, &info)
	if err != nil {
		return "", nil, fmt.Errorf("failed to unmarshal AltSubjectPublicKeyInfo: %w", err)
	}
	if len(rest) > 0 {
		return "", nil, fmt.Errorf("trailing data in AltSubjectPublicKeyInfo")
	}

	alg, err := oidToAlgorithm(info.Algorithm.Algorithm)
	if err != nil {
		return "", nil, err
	}

	return alg, info.SubjectPublicKey.Bytes, nil
}

// EncodeAltSignatureAlgorithm creates the AltSignatureAlgorithm extension.
// This extension identifies the algorithm used for the alternative signature.
//
// Parameters:
//   - alg: The signature algorithm (e.g., ML-DSA-65)
//
// Returns a non-critical X.509 extension.
func EncodeAltSignatureAlgorithm(alg crypto.AlgorithmID) (pkix.Extension, error) {
	algOID := alg.OID()
	if algOID == nil {
		return pkix.Extension{}, fmt.Errorf("no OID defined for algorithm %s", alg)
	}

	algId := pkix.AlgorithmIdentifier{
		Algorithm: algOID,
	}

	value, err := asn1.Marshal(algId)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("failed to marshal AltSignatureAlgorithm: %w", err)
	}

	return pkix.Extension{
		Id:       OIDAltSignatureAlgorithm,
		Critical: false,
		Value:    value,
	}, nil
}

// DecodeAltSignatureAlgorithm parses the AltSignatureAlgorithm extension.
//
// Returns the algorithm identifier.
func DecodeAltSignatureAlgorithm(ext pkix.Extension) (crypto.AlgorithmID, error) {
	if !OIDEqual(ext.Id, OIDAltSignatureAlgorithm) {
		return "", fmt.Errorf("not an AltSignatureAlgorithm extension: %s", ext.Id)
	}

	var algId pkix.AlgorithmIdentifier
	rest, err := asn1.Unmarshal(ext.Value, &algId)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal AltSignatureAlgorithm: %w", err)
	}
	if len(rest) > 0 {
		return "", fmt.Errorf("trailing data in AltSignatureAlgorithm")
	}

	return oidToAlgorithm(algId.Algorithm)
}

// EncodeAltSignatureValue creates the AltSignatureValue extension.
// This extension contains the alternative signature value.
//
// Parameters:
//   - signature: The raw signature bytes
//
// Returns a non-critical X.509 extension.
func EncodeAltSignatureValue(signature []byte) (pkix.Extension, error) {
	// The signature is encoded as a BIT STRING
	sigBitString := asn1.BitString{
		Bytes:     signature,
		BitLength: len(signature) * 8,
	}

	value, err := asn1.Marshal(sigBitString)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("failed to marshal AltSignatureValue: %w", err)
	}

	return pkix.Extension{
		Id:       OIDAltSignatureValue,
		Critical: false,
		Value:    value,
	}, nil
}

// DecodeAltSignatureValue parses the AltSignatureValue extension.
//
// Returns the signature bytes.
func DecodeAltSignatureValue(ext pkix.Extension) ([]byte, error) {
	if !OIDEqual(ext.Id, OIDAltSignatureValue) {
		return nil, fmt.Errorf("not an AltSignatureValue extension: %s", ext.Id)
	}

	var sigBitString asn1.BitString
	rest, err := asn1.Unmarshal(ext.Value, &sigBitString)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal AltSignatureValue: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data in AltSignatureValue")
	}

	return sigBitString.Bytes, nil
}

// FindCatalystExtensions searches for all Catalyst extensions in a certificate.
// Returns nil if no Catalyst extensions are found.
func FindCatalystExtensions(extensions []pkix.Extension) *CatalystExtensions {
	var result CatalystExtensions
	found := false

	for _, ext := range extensions {
		switch {
		case OIDEqual(ext.Id, OIDAltSubjectPublicKeyInfo):
			var info AltSubjectPublicKeyInfo
			if _, err := asn1.Unmarshal(ext.Value, &info); err == nil {
				result.AltPublicKey = &info
				found = true
			}
		case OIDEqual(ext.Id, OIDAltSignatureAlgorithm):
			var algId pkix.AlgorithmIdentifier
			if _, err := asn1.Unmarshal(ext.Value, &algId); err == nil {
				result.AltSigAlgorithm = algId
				found = true
			}
		case OIDEqual(ext.Id, OIDAltSignatureValue):
			var sigBitString asn1.BitString
			if _, err := asn1.Unmarshal(ext.Value, &sigBitString); err == nil {
				result.AltSignature = sigBitString.Bytes
				found = true
			}
		}
	}

	if !found {
		return nil
	}
	return &result
}

// HasCatalystExtensions returns true if the certificate has Catalyst extensions.
func HasCatalystExtensions(extensions []pkix.Extension) bool {
	return FindCatalystExtensions(extensions) != nil
}

// IsCatalystComplete returns true if all three Catalyst extensions are present.
func IsCatalystComplete(extensions []pkix.Extension) bool {
	cat := FindCatalystExtensions(extensions)
	if cat == nil {
		return false
	}
	return cat.AltPublicKey != nil &&
		cat.AltSigAlgorithm.Algorithm != nil &&
		len(cat.AltSignature) > 0
}

// CatalystInfo provides a convenient way to access Catalyst certificate data.
type CatalystInfo struct {
	AltAlgorithm crypto.AlgorithmID
	AltPublicKey []byte
	AltSigAlg    crypto.AlgorithmID
	AltSignature []byte
}

// ParseCatalystExtensions parses all Catalyst extensions from a certificate.
// Returns nil if no Catalyst extensions are present.
// Returns an error if extensions are present but malformed.
func ParseCatalystExtensions(extensions []pkix.Extension) (*CatalystInfo, error) {
	cat := FindCatalystExtensions(extensions)
	if cat == nil {
		return nil, nil
	}

	info := &CatalystInfo{}

	// Parse AltSubjectPublicKeyInfo
	if cat.AltPublicKey != nil {
		alg, err := oidToAlgorithm(cat.AltPublicKey.Algorithm.Algorithm)
		if err != nil {
			return nil, fmt.Errorf("invalid AltSubjectPublicKeyInfo algorithm: %w", err)
		}
		info.AltAlgorithm = alg
		info.AltPublicKey = cat.AltPublicKey.SubjectPublicKey.Bytes
	}

	// Parse AltSignatureAlgorithm
	if cat.AltSigAlgorithm.Algorithm != nil {
		alg, err := oidToAlgorithm(cat.AltSigAlgorithm.Algorithm)
		if err != nil {
			return nil, fmt.Errorf("invalid AltSignatureAlgorithm: %w", err)
		}
		info.AltSigAlg = alg
	}

	// Copy AltSignatureValue
	info.AltSignature = cat.AltSignature

	return info, nil
}

// ReconstructTBSWithoutAltSigValue reconstructs the TBSCertificate bytes
// without the AltSignatureValue extension.
//
// This is necessary for Catalyst signature verification because the PQC signature
// is computed over the TBS without AltSignatureValue (which would create a
// circular dependency). The classical signature is over the final TBS with all extensions.
//
// According to ITU-T X.509 Section 9.8:
// "The alternative signature value is calculated as defined in clause 7, using
// the alternative signature algorithm, except that the tbsCertificate that is
// signed shall not contain the subjectAltSignatureValue extension."
func ReconstructTBSWithoutAltSigValue(rawTBS []byte) ([]byte, error) {
	// Parse the TBS to find and extract extensions
	var tbs tbsCertificateForReconstruction
	rest, err := asn1.Unmarshal(rawTBS, &tbs)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TBS: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data after TBS")
	}

	// Filter out AltSignatureValue extension
	var filteredExtensions []pkix.Extension
	for _, ext := range tbs.Extensions {
		if !OIDEqual(ext.Id, OIDAltSignatureValue) {
			filteredExtensions = append(filteredExtensions, ext)
		}
	}

	// Build new TBS with filtered extensions
	newTBS := tbsCertificateForReconstruction{
		Version:            tbs.Version,
		SerialNumber:       tbs.SerialNumber,
		SignatureAlgorithm: tbs.SignatureAlgorithm,
		Issuer:             tbs.Issuer,
		Validity:           tbs.Validity,
		Subject:            tbs.Subject,
		PublicKey:          tbs.PublicKey,
		IssuerUniqueId:     tbs.IssuerUniqueId,
		SubjectUniqueId:    tbs.SubjectUniqueId,
		Extensions:         filteredExtensions,
	}

	// Re-encode TBS without AltSignatureValue
	result, err := asn1.Marshal(newTBS)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal modified TBS: %w", err)
	}

	return result, nil
}

// tbsCertificateForReconstruction is the ASN.1 structure for TBSCertificate.
// Used for parsing and re-encoding the TBS without AltSignatureValue.
type tbsCertificateForReconstruction struct {
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       asn1.RawValue
	SignatureAlgorithm asn1.RawValue
	Issuer             asn1.RawValue
	Validity           asn1.RawValue
	Subject            asn1.RawValue
	PublicKey          asn1.RawValue
	IssuerUniqueId     asn1.BitString   `asn1:"optional,tag:1"`
	SubjectUniqueId    asn1.BitString   `asn1:"optional,tag:2"`
	Extensions         []pkix.Extension `asn1:"optional,explicit,tag:3"`
}

// =============================================================================
// RelatedCertificate Extension (draft-ietf-lamps-cert-binding-for-multi-auth)
// =============================================================================

// RelatedCertificate represents a reference to a related certificate.
// This is used to link certificates for multi-algorithm authentication,
// for example linking a PQC signing certificate to a classical signing certificate,
// or linking an encryption certificate to a signing certificate.
//
//	RelatedCertificate ::= SEQUENCE {
//	    hashAlgorithm       AlgorithmIdentifier,
//	    certHash            OCTET STRING,
//	    issuerSerial        IssuerAndSerialNumber OPTIONAL
//	}
type RelatedCertificate struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	CertHash      []byte
	IssuerSerial  IssuerAndSerialNumber `asn1:"optional"`
}

// IssuerAndSerialNumber identifies a certificate by issuer and serial.
//
//	IssuerAndSerialNumber ::= SEQUENCE {
//	    issuer              Name,
//	    serialNumber        CertificateSerialNumber
//	}
type IssuerAndSerialNumber struct {
	Issuer       asn1.RawValue
	SerialNumber asn1.RawValue
}

// SHA-256 OID for RelatedCertificate hash algorithm.
var oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}

// EncodeRelatedCertificate creates a RelatedCertificate extension.
//
// The extension contains a cryptographic hash of the related certificate,
// binding this certificate to another certificate in the same trust chain.
//
// Parameters:
//   - relatedCert: The certificate to link to
//
// Returns a non-critical X.509 extension.
func EncodeRelatedCertificate(relatedCert *x509.Certificate) (pkix.Extension, error) {
	if relatedCert == nil {
		return pkix.Extension{}, fmt.Errorf("related certificate is nil")
	}

	// Compute SHA-256 hash of the related certificate
	hash := sha256.Sum256(relatedCert.Raw)

	// Build IssuerAndSerialNumber
	issuerBytes, err := asn1.Marshal(relatedCert.Issuer.ToRDNSequence())
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("failed to marshal issuer: %w", err)
	}

	serialBytes, err := asn1.Marshal(relatedCert.SerialNumber)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("failed to marshal serial number: %w", err)
	}

	relCert := RelatedCertificate{
		HashAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: oidSHA256,
		},
		CertHash: hash[:],
		IssuerSerial: IssuerAndSerialNumber{
			Issuer:       asn1.RawValue{FullBytes: issuerBytes},
			SerialNumber: asn1.RawValue{FullBytes: serialBytes},
		},
	}

	value, err := asn1.Marshal(relCert)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("failed to marshal RelatedCertificate: %w", err)
	}

	return pkix.Extension{
		Id:       OIDRelatedCertificate,
		Critical: false, // Non-critical for backward compatibility
		Value:    value,
	}, nil
}

// DecodeRelatedCertificate parses a RelatedCertificate extension.
func DecodeRelatedCertificate(ext pkix.Extension) (*RelatedCertificate, error) {
	if !OIDEqual(ext.Id, OIDRelatedCertificate) {
		return nil, fmt.Errorf("not a RelatedCertificate extension: %s", ext.Id)
	}

	var relCert RelatedCertificate
	rest, err := asn1.Unmarshal(ext.Value, &relCert)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal RelatedCertificate: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data in RelatedCertificate")
	}

	return &relCert, nil
}

// FindRelatedCertificateExtension searches for the RelatedCertificate extension.
// Returns nil if not found.
func FindRelatedCertificateExtension(extensions []pkix.Extension) *pkix.Extension {
	for i := range extensions {
		if OIDEqual(extensions[i].Id, OIDRelatedCertificate) {
			return &extensions[i]
		}
	}
	return nil
}

// HasRelatedCertificate returns true if the certificate has a RelatedCertificate extension.
func HasRelatedCertificate(extensions []pkix.Extension) bool {
	return FindRelatedCertificateExtension(extensions) != nil
}

// VerifyRelatedCertificate verifies that the RelatedCertificate extension
// correctly references the given certificate.
func VerifyRelatedCertificate(ext *RelatedCertificate, candidate *x509.Certificate) bool {
	if ext == nil || candidate == nil {
		return false
	}

	// Verify hash
	expectedHash := sha256.Sum256(candidate.Raw)
	if len(ext.CertHash) != len(expectedHash) {
		return false
	}
	for i := range ext.CertHash {
		if ext.CertHash[i] != expectedHash[i] {
			return false
		}
	}

	return true
}

// RelatedCertificateInfo provides a convenient way to access related certificate data.
type RelatedCertificateInfo struct {
	HashAlgorithm string
	CertHash      []byte
	HasIssuer     bool
}

// ParseRelatedCertificate parses the RelatedCertificate extension from a certificate.
// Returns nil if no RelatedCertificate extension is present.
func ParseRelatedCertificate(extensions []pkix.Extension) (*RelatedCertificateInfo, error) {
	ext := FindRelatedCertificateExtension(extensions)
	if ext == nil {
		return nil, nil
	}

	relCert, err := DecodeRelatedCertificate(*ext)
	if err != nil {
		return nil, err
	}

	algName := "SHA-256"
	if !OIDEqual(relCert.HashAlgorithm.Algorithm, oidSHA256) {
		algName = relCert.HashAlgorithm.Algorithm.String()
	}

	return &RelatedCertificateInfo{
		HashAlgorithm: algName,
		CertHash:      relCert.CertHash,
		HasIssuer:     len(relCert.IssuerSerial.Issuer.FullBytes) > 0,
	}, nil
}
