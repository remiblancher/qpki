package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/cloudflare/circl/sign/dilithium/mode5"
	pkicrypto "github.com/remiblancher/pki/internal/crypto"
	"github.com/remiblancher/pki/internal/x509util"
)

// CompositeVerifyResult holds the result of verifying a composite certificate.
type CompositeVerifyResult struct {
	Valid         bool
	Algorithm     *CompositeAlgorithm
	MLDSAValid    bool
	ClassicalValid bool
	Error         error
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
func parseCompositePublicKeyFromCert(cert *x509.Certificate) (pqcPub, classicalPub crypto.PublicKey, err error) {
	// Use Go's parsed RawSubjectPublicKeyInfo
	spkiBytes := cert.RawSubjectPublicKeyInfo

	// Parse SPKI
	var spki publicKeyInfo
	_, err = asn1.Unmarshal(spkiBytes, &spki)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse SPKI: %w", err)
	}

	// The public key bytes contain a CompositePublicKey
	var compPK CompositePublicKey
	_, err = asn1.Unmarshal(spki.PublicKey.Bytes, &compPK)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse composite public key: %w", err)
	}

	// Get algorithm from OID
	compAlg, err := GetCompositeAlgorithmByOID(spki.Algorithm.Algorithm)
	if err != nil {
		return nil, nil, fmt.Errorf("unknown composite algorithm: %w", err)
	}

	// Parse ML-DSA public key
	pqcPub, err = parseMLDSAPublicKey(compAlg.PQCAlg, compPK.MLDSAKey.PublicKey.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse ML-DSA key: %w", err)
	}

	// Parse classical public key (ECDSA)
	classicalPub, err = parseClassicalPublicKey(compPK.ClassicalKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse classical key: %w", err)
	}

	return pqcPub, classicalPub, nil
}

// parseMLDSAPublicKey parses an ML-DSA public key from raw bytes.
func parseMLDSAPublicKey(alg pkicrypto.AlgorithmID, data []byte) (crypto.PublicKey, error) {
	switch alg {
	case pkicrypto.AlgMLDSA65:
		pub := new(mode3.PublicKey)
		if err := pub.UnmarshalBinary(data); err != nil {
			return nil, err
		}
		return pub, nil
	case pkicrypto.AlgMLDSA87:
		pub := new(mode5.PublicKey)
		if err := pub.UnmarshalBinary(data); err != nil {
			return nil, err
		}
		return pub, nil
	default:
		return nil, fmt.Errorf("unsupported ML-DSA algorithm: %s", alg)
	}
}

// parseClassicalPublicKey parses an ECDSA public key from SPKI format.
func parseClassicalPublicKey(spki publicKeyInfo) (crypto.PublicKey, error) {
	// Marshal back to DER for Go's x509 parser
	der, err := asn1.Marshal(spki)
	if err != nil {
		return nil, err
	}

	return x509.ParsePKIXPublicKey(der)
}

// verifyMLDSA verifies an ML-DSA signature.
func verifyMLDSA(alg pkicrypto.AlgorithmID, pub crypto.PublicKey, message, sig []byte) bool {
	switch alg {
	case pkicrypto.AlgMLDSA65:
		key, ok := pub.(*mode3.PublicKey)
		if !ok {
			return false
		}
		return mode3.Verify(key, message, sig)
	case pkicrypto.AlgMLDSA87:
		key, ok := pub.(*mode5.PublicKey)
		if !ok {
			return false
		}
		return mode5.Verify(key, message, sig)
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

// extractTBS extracts the TBSCertificate from a DER-encoded certificate.
func extractTBS(certDER []byte) ([]byte, error) {
	var cert struct {
		TBSCertificate asn1.RawValue
		SignatureAlg   pkix.AlgorithmIdentifier
		SignatureValue asn1.BitString
	}
	_, err := asn1.Unmarshal(certDER, &cert)
	if err != nil {
		return nil, err
	}
	return cert.TBSCertificate.FullBytes, nil
}

// extractSignature extracts the signature bytes from a DER-encoded certificate.
func extractSignature(certDER []byte) ([]byte, error) {
	var cert struct {
		TBSCertificate asn1.RawValue
		SignatureAlg   pkix.AlgorithmIdentifier
		SignatureValue asn1.BitString
	}
	_, err := asn1.Unmarshal(certDER, &cert)
	if err != nil {
		return nil, err
	}
	return cert.SignatureValue.Bytes, nil
}

// extractSPKI extracts the SubjectPublicKeyInfo from a DER-encoded certificate.
func extractSPKI(certDER []byte) ([]byte, error) {
	// Parse outer certificate structure
	var outer struct {
		TBSCertificate asn1.RawValue
		// We don't need the rest
	}
	_, err := asn1.Unmarshal(certDER, &outer)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// TBSCertificate.FullBytes contains the full SEQUENCE including tag
	// We need to parse it properly
	tbsContent := outer.TBSCertificate.FullBytes

	// Parse TBSCertificate fields in order
	// TBSCertificate ::= SEQUENCE {
	//   version         [0] EXPLICIT Version DEFAULT v1,
	//   serialNumber         CertificateSerialNumber,
	//   signature            AlgorithmIdentifier,
	//   issuer               Name,
	//   validity             Validity,
	//   subject              Name,
	//   subjectPublicKeyInfo SubjectPublicKeyInfo,
	//   ...
	// }

	// Skip the outer SEQUENCE tag and length
	rest := tbsContent
	if len(rest) < 2 {
		return nil, fmt.Errorf("TBS too short")
	}

	// Parse the SEQUENCE header
	if rest[0] != 0x30 { // SEQUENCE tag
		return nil, fmt.Errorf("expected SEQUENCE, got tag 0x%02x", rest[0])
	}

	// Get length
	lenByte := rest[1]
	var headerLen int
	if lenByte < 0x80 {
		headerLen = 2
	} else {
		numLenBytes := int(lenByte & 0x7f)
		headerLen = 2 + numLenBytes
	}
	rest = rest[headerLen:]

	// Skip version [0] EXPLICIT if present
	if len(rest) > 0 && rest[0] == 0xa0 { // context-specific tag 0
		lenByte := rest[1]
		var fieldLen int
		if lenByte < 0x80 {
			fieldLen = 2 + int(lenByte)
		} else {
			numLenBytes := int(lenByte & 0x7f)
			totalLen := 0
			for i := 0; i < numLenBytes; i++ {
				totalLen = totalLen<<8 | int(rest[2+i])
			}
			fieldLen = 2 + numLenBytes + totalLen
		}
		rest = rest[fieldLen:]
	}

	// Skip 5 more fields: serialNumber, signature, issuer, validity, subject
	for i := 0; i < 5; i++ {
		if len(rest) < 2 {
			return nil, fmt.Errorf("TBS too short at field %d", i)
		}
		lenByte := rest[1]
		var fieldLen int
		if lenByte < 0x80 {
			fieldLen = 2 + int(lenByte)
		} else {
			numLenBytes := int(lenByte & 0x7f)
			totalLen := 0
			for j := 0; j < numLenBytes; j++ {
				totalLen = totalLen<<8 | int(rest[2+j])
			}
			fieldLen = 2 + numLenBytes + totalLen
		}
		rest = rest[fieldLen:]
	}

	// Now rest starts with SubjectPublicKeyInfo
	if len(rest) < 2 {
		return nil, fmt.Errorf("no SPKI found")
	}

	// Get SPKI length
	lenByte = rest[1]
	var spkiLen int
	var spkiHeaderLen int
	if lenByte < 0x80 {
		spkiLen = int(lenByte)
		spkiHeaderLen = 2
	} else {
		numLenBytes := int(lenByte & 0x7f)
		spkiLen = 0
		for i := 0; i < numLenBytes; i++ {
			spkiLen = spkiLen<<8 | int(rest[2+i])
		}
		spkiHeaderLen = 2 + numLenBytes
	}

	return rest[:spkiHeaderLen+spkiLen], nil
}
