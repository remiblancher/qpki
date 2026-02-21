package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	pkicrypto "github.com/remiblancher/qpki/pkg/crypto"
	"github.com/remiblancher/qpki/pkg/x509util"
)

// CompositeVerifyResult holds the result of verifying a composite certificate.
type CompositeVerifyResult struct {
	Valid          bool
	Algorithm      *CompositeAlgorithm
	MLDSAValid     bool
	ClassicalValid bool
	Error          error
}

// VerifyCompositeCertificate verifies both signatures in a composite certificate.
// Per draft-ietf-lamps-pq-composite-sigs-13, BOTH signatures MUST be valid.
func VerifyCompositeCertificate(cert, issuer *x509.Certificate) (*CompositeVerifyResult, error) {
	result := &CompositeVerifyResult{}

	// Extract signature algorithm OID
	sigAlgOID, err := x509util.ExtractSignatureAlgorithmOID(cert.Raw)
	if err != nil {
		return nil, fmt.Errorf("failed to extract signature algorithm: %w", err)
	}

	// Get composite algorithm
	compAlg, err := GetCompositeAlgorithmByOID(sigAlgOID)
	if err != nil {
		return nil, fmt.Errorf("not a composite certificate: %w", err)
	}
	result.Algorithm = compAlg

	// Parse issuer's composite public key
	issuerSigAlgOID, err := x509util.ExtractSignatureAlgorithmOID(issuer.Raw)
	if err != nil {
		return nil, fmt.Errorf("failed to extract issuer signature algorithm: %w", err)
	}

	if !IsCompositeOID(issuerSigAlgOID) {
		return nil, fmt.Errorf("issuer is not a composite certificate")
	}

	pqcPub, classicalPub, err := parseCompositePublicKeyFromCert(issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to parse issuer composite public key: %w", err)
	}

	// Get TBS bytes directly from parsed certificate
	tbsBytes := cert.RawTBSCertificate

	// Get signature bytes directly from parsed certificate
	signatureBytes := cert.Signature

	// Parse composite signature
	var compSig CompositeSignatureValue
	_, err = asn1.Unmarshal(signatureBytes, &compSig)
	if err != nil {
		return nil, fmt.Errorf("failed to parse composite signature: %w", err)
	}

	// Build domain separator
	domainSep, err := BuildDomainSeparator(compAlg.OID)
	if err != nil {
		return nil, fmt.Errorf("failed to build domain separator: %w", err)
	}

	// Reconstruct message: M' = DomainSeparator || TBS
	messageToVerify := append(domainSep, tbsBytes...)

	// Verify ML-DSA signature
	result.MLDSAValid = verifyMLDSA(compAlg.PQCAlg, pqcPub, messageToVerify, compSig.MLDSASig.Bytes)

	// Verify classical (ECDSA) signature
	h := sha512.New()
	h.Write(messageToVerify)
	digest := h.Sum(nil)

	result.ClassicalValid = verifyECDSA(classicalPub, digest, compSig.ClassicalSig.Bytes)

	// Per spec, BOTH must be valid
	result.Valid = result.MLDSAValid && result.ClassicalValid

	if !result.Valid {
		if !result.MLDSAValid && !result.ClassicalValid {
			result.Error = fmt.Errorf("both ML-DSA and classical signatures invalid")
		} else if !result.MLDSAValid {
			result.Error = fmt.Errorf("ML-DSA signature invalid")
		} else {
			result.Error = fmt.Errorf("classical signature invalid")
		}
	}

	return result, nil
}

// parseCompositePublicKeyFromCert extracts both public keys from a composite certificate.
// Per draft-ietf-lamps-pq-composite-sigs-13, the encoding is:
//
//	CompositeSignaturePublicKey ::= SEQUENCE SIZE (2) OF BIT STRING
func parseCompositePublicKeyFromCert(cert *x509.Certificate) (pqcPub, classicalPub crypto.PublicKey, err error) {
	// Use Go's parsed RawSubjectPublicKeyInfo
	spkiBytes := cert.RawSubjectPublicKeyInfo

	// Parse SPKI
	var spki publicKeyInfo
	_, err = asn1.Unmarshal(spkiBytes, &spki)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse SPKI: %w", err)
	}

	// The public key bytes contain a CompositeSignaturePublicKey
	// CompositeSignaturePublicKey ::= SEQUENCE SIZE (2) OF BIT STRING
	var compPK CompositeSignaturePublicKey
	_, err = asn1.Unmarshal(spki.PublicKey.Bytes, &compPK)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse composite public key: %w", err)
	}

	// Get algorithm from OID
	compAlg, err := GetCompositeAlgorithmByOID(spki.Algorithm.Algorithm)
	if err != nil {
		return nil, nil, fmt.Errorf("unknown composite algorithm: %w", err)
	}

	// Parse ML-DSA public key from raw bytes
	pqcPub, err = parseMLDSAPublicKey(compAlg.PQCAlg, compPK.MLDSAKey.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse ML-DSA key: %w", err)
	}

	// Parse classical public key (ECDSA) from raw bytes
	classicalPub, err = parseClassicalPublicKeyFromBytes(compAlg.ClassicalAlg, compPK.ClassicalKey.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse classical key: %w", err)
	}

	return pqcPub, classicalPub, nil
}

// parseMLDSAPublicKey parses an ML-DSA public key from raw bytes.
func parseMLDSAPublicKey(alg pkicrypto.AlgorithmID, data []byte) (crypto.PublicKey, error) {
	switch alg {
	case pkicrypto.AlgMLDSA65:
		pub := new(mldsa65.PublicKey)
		if err := pub.UnmarshalBinary(data); err != nil {
			return nil, err
		}
		return pub, nil
	case pkicrypto.AlgMLDSA87:
		pub := new(mldsa87.PublicKey)
		if err := pub.UnmarshalBinary(data); err != nil {
			return nil, err
		}
		return pub, nil
	default:
		return nil, fmt.Errorf("unsupported ML-DSA algorithm: %s", alg)
	}
}

// parseClassicalPublicKeyFromBytes parses an ECDSA public key from raw bytes.
// The raw bytes are the uncompressed EC point (0x04 || X || Y).
func parseClassicalPublicKeyFromBytes(alg pkicrypto.AlgorithmID, data []byte) (crypto.PublicKey, error) {
	// Determine the curve OID based on algorithm
	var curveOID asn1.ObjectIdentifier
	switch alg {
	case pkicrypto.AlgECDSAP256:
		curveOID = x509util.OIDNamedCurveP256
	case pkicrypto.AlgECDSAP384:
		curveOID = x509util.OIDNamedCurveP384
	case pkicrypto.AlgECDSAP521:
		curveOID = x509util.OIDNamedCurveP521
	default:
		return nil, fmt.Errorf("unsupported classical algorithm: %s", alg)
	}

	// Build SPKI structure with EC public key
	spki := publicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm:  x509util.OIDPublicKeyECDSA,
			Parameters: asn1.RawValue{FullBytes: mustMarshal(curveOID)},
		},
		PublicKey: asn1.BitString{
			Bytes:     data,
			BitLength: len(data) * 8,
		},
	}

	// Marshal back to DER for Go's x509 parser
	der, err := asn1.Marshal(spki)
	if err != nil {
		return nil, err
	}

	return x509.ParsePKIXPublicKey(der)
}

// mustMarshal marshals a value or panics.
func mustMarshal(v interface{}) []byte {
	data, err := asn1.Marshal(v)
	if err != nil {
		panic(err)
	}
	return data
}

// VerifyCompositeSignature verifies a Composite signature over arbitrary data.
// This is used for OCSP, TSA, and CMS signature verification.
// The signature must be the ASN.1-encoded CompositeSignatureValue.
func VerifyCompositeSignature(data, signature []byte, signerCert *x509.Certificate, sigAlgOID asn1.ObjectIdentifier) error {
	// Get composite algorithm
	compAlg, err := GetCompositeAlgorithmByOID(sigAlgOID)
	if err != nil {
		return fmt.Errorf("not a composite signature: %w", err)
	}

	// Parse the signer's composite public key
	pqcPub, classicalPub, err := parseCompositePublicKeyFromCert(signerCert)
	if err != nil {
		return fmt.Errorf("failed to parse composite public key: %w", err)
	}

	// Parse composite signature
	var compSig CompositeSignatureValue
	_, err = asn1.Unmarshal(signature, &compSig)
	if err != nil {
		return fmt.Errorf("failed to parse composite signature: %w", err)
	}

	// Build domain separator
	domainSep, err := BuildDomainSeparator(compAlg.OID)
	if err != nil {
		return fmt.Errorf("failed to build domain separator: %w", err)
	}

	// Reconstruct message: M' = DomainSeparator || data
	messageToVerify := append(domainSep, data...)

	// Verify ML-DSA signature
	mldsaValid := verifyMLDSA(compAlg.PQCAlg, pqcPub, messageToVerify, compSig.MLDSASig.Bytes)
	if !mldsaValid {
		return fmt.Errorf("ML-DSA signature verification failed")
	}

	// Verify classical (ECDSA) signature
	h := sha512.New()
	h.Write(messageToVerify)
	digest := h.Sum(nil)

	classicalValid := verifyECDSA(classicalPub, digest, compSig.ClassicalSig.Bytes)
	if !classicalValid {
		return fmt.Errorf("classical (ECDSA) signature verification failed")
	}

	return nil
}

// verifyMLDSA verifies an ML-DSA (FIPS 204) signature.
func verifyMLDSA(alg pkicrypto.AlgorithmID, pub crypto.PublicKey, message, sig []byte) bool {
	switch alg {
	case pkicrypto.AlgMLDSA65:
		key, ok := pub.(*mldsa65.PublicKey)
		if !ok {
			return false
		}
		return mldsa65.Verify(key, message, nil, sig)
	case pkicrypto.AlgMLDSA87:
		key, ok := pub.(*mldsa87.PublicKey)
		if !ok {
			return false
		}
		return mldsa87.Verify(key, message, nil, sig)
	default:
		return false
	}
}

// verifyECDSA verifies an ECDSA signature.
func verifyECDSA(pub crypto.PublicKey, digest, sig []byte) bool {
	key, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return false
	}
	return ecdsa.VerifyASN1(key, digest, sig)
}
