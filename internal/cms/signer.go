package cms

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"hash"
	"sort"
	"time"

	"github.com/cloudflare/circl/sign/slhdsa"
	"github.com/remiblancher/post-quantum-pki/internal/ca"
	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
)

// SignerConfig contains options for signing.
type SignerConfig struct {
	Certificate  *x509.Certificate
	Signer       crypto.Signer
	DigestAlg    crypto.Hash
	IncludeCerts bool
	SigningTime  time.Time
	ContentType  asn1.ObjectIdentifier
	Detached     bool // If true, content is not included in SignedData
}

// Sign creates a CMS SignedData structure.
func Sign(content []byte, config *SignerConfig) ([]byte, error) {
	if config.Certificate == nil {
		return nil, fmt.Errorf("certificate is required")
	}
	if config.Signer == nil {
		return nil, fmt.Errorf("signer is required")
	}
	if config.DigestAlg == 0 {
		config.DigestAlg = crypto.SHA256
	}
	if config.SigningTime.IsZero() {
		config.SigningTime = time.Now().UTC()
	}
	if len(config.ContentType) == 0 {
		config.ContentType = OIDData
	}

	// Compute content digest
	digest, err := computeDigest(content, config.DigestAlg)
	if err != nil {
		return nil, fmt.Errorf("failed to compute digest: %w", err)
	}

	// Build signed attributes
	signedAttrs, err := buildSignedAttrs(config.ContentType, digest, config.SigningTime)
	if err != nil {
		return nil, fmt.Errorf("failed to build signed attributes: %w", err)
	}

	// Sort attributes in DER order (required for SET OF encoding)
	// This sorted list is used both for signing AND for storage in SignerInfo
	signedAttrs, err = sortAttributes(signedAttrs)
	if err != nil {
		return nil, fmt.Errorf("failed to sort signed attributes: %w", err)
	}

	// Marshal signed attributes for signing
	signedAttrsDER, err := MarshalSignedAttrs(signedAttrs)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signed attributes: %w", err)
	}

	// Sign the attributes
	signature, err := signData(signedAttrsDER, config.Signer, config.DigestAlg)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	// Get algorithm identifiers
	digestAlgID := getDigestAlgorithmIdentifier(config.DigestAlg)
	sigAlgID, err := getSignatureAlgorithmIdentifier(config.Signer, config.DigestAlg)
	if err != nil {
		return nil, fmt.Errorf("failed to get signature algorithm: %w", err)
	}

	// Build SignerInfo
	signerInfo := SignerInfo{
		Version: 1,
		SID: IssuerAndSerialNumber{
			Issuer:       asn1.RawValue{FullBytes: config.Certificate.RawIssuer},
			SerialNumber: config.Certificate.SerialNumber,
		},
		DigestAlgorithm:    digestAlgID,
		SignedAttrs:        signedAttrs,
		SignatureAlgorithm: sigAlgID,
		Signature:          signature,
	}

	// Build EncapsulatedContentInfo
	encapContent := EncapsulatedContentInfo{
		EContentType: config.ContentType,
	}
	// For attached signatures, include the content
	if !config.Detached {
		// EContent is [0] EXPLICIT OCTET STRING
		// We need to encode the OCTET STRING first, then wrap it in [0] EXPLICIT
		octetString, err := asn1.Marshal(content)
		if err != nil {
			return nil, fmt.Errorf("failed to encode content: %w", err)
		}
		// Use RawValue with Class and Tag to tell asn1 to output as [0]
		// The Bytes field contains the OCTET STRING (already encoded)
		encapContent.EContent = asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      octetString,
		}
	}

	// Build SignedData
	signedData := SignedData{
		Version:          1,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{digestAlgID},
		EncapContentInfo: encapContent,
		SignerInfos:      []SignerInfo{signerInfo},
	}

	// Marshal SignedData first without certificates
	signedDataDER, err := asn1.Marshal(signedData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal SignedData: %w", err)
	}

	// Include certificates if requested - inject them manually
	if config.IncludeCerts {
		signedDataDER, err = injectCertificates(signedDataDER, config.Certificate.Raw)
		if err != nil {
			return nil, fmt.Errorf("failed to inject certificates: %w", err)
		}
	}

	// Wrap in ContentInfo
	contentInfo := ContentInfo{
		ContentType: OIDSignedData,
		Content:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: signedDataDER},
	}

	return asn1.Marshal(contentInfo)
}

func buildSignedAttrs(contentType asn1.ObjectIdentifier, digest []byte, signingTime time.Time) ([]Attribute, error) {
	ctAttr, err := NewContentTypeAttr(contentType)
	if err != nil {
		return nil, err
	}

	mdAttr, err := NewMessageDigestAttr(digest)
	if err != nil {
		return nil, err
	}

	stAttr, err := NewSigningTimeAttr(signingTime)
	if err != nil {
		return nil, err
	}

	return []Attribute{ctAttr, mdAttr, stAttr}, nil
}

// sortAttributes sorts attributes by their DER encoding for SET OF compliance.
func sortAttributes(attrs []Attribute) ([]Attribute, error) {
	type attrWithEncoding struct {
		attr    Attribute
		encoded []byte
	}

	items := make([]attrWithEncoding, len(attrs))
	for i, attr := range attrs {
		encoded, err := asn1.Marshal(attr)
		if err != nil {
			return nil, err
		}
		items[i] = attrWithEncoding{attr: attr, encoded: encoded}
	}

	sort.Slice(items, func(i, j int) bool {
		return bytes.Compare(items[i].encoded, items[j].encoded) < 0
	})

	result := make([]Attribute, len(attrs))
	for i, item := range items {
		result[i] = item.attr
	}
	return result, nil
}

func computeDigest(data []byte, alg crypto.Hash) ([]byte, error) {
	var h hash.Hash
	switch alg {
	case crypto.SHA256:
		h = sha256.New()
	case crypto.SHA384:
		h = sha512.New384()
	case crypto.SHA512:
		h = sha512.New()
	default:
		return nil, fmt.Errorf("unsupported digest algorithm: %v", alg)
	}
	h.Write(data)
	return h.Sum(nil), nil
}

func signData(data []byte, signer crypto.Signer, digestAlg crypto.Hash) ([]byte, error) {
	// Check if this is a HybridSigner (Composite signature)
	if hybridSigner, ok := signer.(pkicrypto.HybridSigner); ok {
		sig, err := signComposite(data, hybridSigner)
		if err == nil {
			return sig, nil
		}
		// If Composite signature failed (e.g., Catalyst which uses different algorithm combo),
		// fall back to classical signature only
		classical := hybridSigner.ClassicalSigner()
		digest, err := computeDigest(data, digestAlg)
		if err != nil {
			return nil, err
		}
		return classical.Sign(rand.Reader, digest, digestAlg)
	}

	// For Ed25519, sign the data directly (no digest)
	if _, ok := signer.Public().(ed25519.PublicKey); ok {
		return signer.Sign(rand.Reader, data, crypto.Hash(0))
	}

	// For PQC algorithms (ML-DSA, SLH-DSA), sign the data directly
	// Check if this is a PQC signer by checking if it doesn't have standard public key types
	pubKey := signer.Public()
	switch pubKey.(type) {
	case *ecdsa.PublicKey, *rsa.PublicKey, ed25519.PublicKey:
		// Standard algorithm - compute digest first
		digest, err := computeDigest(data, digestAlg)
		if err != nil {
			return nil, err
		}
		return signer.Sign(rand.Reader, digest, digestAlg)
	default:
		// PQC algorithm - sign data directly (pure mode per RFC 9882)
		return signer.Sign(rand.Reader, data, crypto.Hash(0))
	}
}

// signComposite creates a Composite signature using both classical and PQC signers.
// Returns an error if the algorithm combination is not a valid Composite algorithm
// (e.g., Catalyst uses P-384 + ML-DSA-65 which is not a Composite combination).
func signComposite(data []byte, hybridSigner pkicrypto.HybridSigner) ([]byte, error) {
	classical := hybridSigner.ClassicalSigner()
	pqc := hybridSigner.PQCSigner()

	// Get the composite algorithm based on the signer algorithms
	compAlg, err := ca.GetCompositeAlgorithm(classical.Algorithm(), pqc.Algorithm())
	if err != nil {
		return nil, err // Not a valid Composite combination
	}

	// Create Composite signature using the CA package
	return ca.CreateCompositeSignature(data, compAlg, pqc, classical)
}

func getDigestAlgorithmIdentifier(alg crypto.Hash) pkix.AlgorithmIdentifier {
	switch alg {
	case crypto.SHA256:
		return pkix.AlgorithmIdentifier{Algorithm: OIDSHA256}
	case crypto.SHA384:
		return pkix.AlgorithmIdentifier{Algorithm: OIDSHA384}
	case crypto.SHA512:
		return pkix.AlgorithmIdentifier{Algorithm: OIDSHA512}
	default:
		return pkix.AlgorithmIdentifier{Algorithm: OIDSHA256}
	}
}

func getSignatureAlgorithmIdentifier(signer crypto.Signer, digestAlg crypto.Hash) (pkix.AlgorithmIdentifier, error) {
	// Check for HybridSigner (Composite)
	if hybridSigner, ok := signer.(pkicrypto.HybridSigner); ok {
		classical := hybridSigner.ClassicalSigner()
		pqc := hybridSigner.PQCSigner()
		compAlg, err := ca.GetCompositeAlgorithm(classical.Algorithm(), pqc.Algorithm())
		if err == nil {
			return pkix.AlgorithmIdentifier{Algorithm: compAlg.OID}, nil
		}
		// Not a valid Composite combination (e.g., Catalyst uses P-384 + ML-DSA-65)
		// Fall back to classical signature algorithm
		return getClassicalSignatureAlgorithmIdentifier(classical.Public(), digestAlg)
	}

	switch pub := signer.Public().(type) {
	case *ecdsa.PublicKey:
		switch digestAlg {
		case crypto.SHA256:
			return pkix.AlgorithmIdentifier{Algorithm: OIDECDSAWithSHA256}, nil
		case crypto.SHA384:
			return pkix.AlgorithmIdentifier{Algorithm: OIDECDSAWithSHA384}, nil
		case crypto.SHA512:
			return pkix.AlgorithmIdentifier{Algorithm: OIDECDSAWithSHA512}, nil
		default:
			return pkix.AlgorithmIdentifier{}, fmt.Errorf("unsupported ECDSA digest: %v", digestAlg)
		}
	case ed25519.PublicKey:
		return pkix.AlgorithmIdentifier{Algorithm: OIDEd25519}, nil
	case *rsa.PublicKey:
		switch digestAlg {
		case crypto.SHA256:
			return pkix.AlgorithmIdentifier{Algorithm: OIDSHA256WithRSA}, nil
		case crypto.SHA384:
			return pkix.AlgorithmIdentifier{Algorithm: OIDSHA384WithRSA}, nil
		case crypto.SHA512:
			return pkix.AlgorithmIdentifier{Algorithm: OIDSHA512WithRSA}, nil
		default:
			return pkix.AlgorithmIdentifier{}, fmt.Errorf("unsupported RSA digest: %v", digestAlg)
		}
	default:
		// Try to detect PQC algorithms by examining the public key
		// This is a placeholder - actual implementation depends on the crypto package
		return detectPQCAlgorithm(pub)
	}
}

// getClassicalSignatureAlgorithmIdentifier returns the algorithm identifier for classical signatures.
// Used for Catalyst fallback when Composite is not applicable.
func getClassicalSignatureAlgorithmIdentifier(pub crypto.PublicKey, digestAlg crypto.Hash) (pkix.AlgorithmIdentifier, error) {
	switch pub.(type) {
	case *ecdsa.PublicKey:
		switch digestAlg {
		case crypto.SHA256:
			return pkix.AlgorithmIdentifier{Algorithm: OIDECDSAWithSHA256}, nil
		case crypto.SHA384:
			return pkix.AlgorithmIdentifier{Algorithm: OIDECDSAWithSHA384}, nil
		case crypto.SHA512:
			return pkix.AlgorithmIdentifier{Algorithm: OIDECDSAWithSHA512}, nil
		default:
			return pkix.AlgorithmIdentifier{}, fmt.Errorf("unsupported ECDSA digest: %v", digestAlg)
		}
	case *rsa.PublicKey:
		switch digestAlg {
		case crypto.SHA256:
			return pkix.AlgorithmIdentifier{Algorithm: OIDSHA256WithRSA}, nil
		case crypto.SHA384:
			return pkix.AlgorithmIdentifier{Algorithm: OIDSHA384WithRSA}, nil
		case crypto.SHA512:
			return pkix.AlgorithmIdentifier{Algorithm: OIDSHA512WithRSA}, nil
		default:
			return pkix.AlgorithmIdentifier{}, fmt.Errorf("unsupported RSA digest: %v", digestAlg)
		}
	case ed25519.PublicKey:
		return pkix.AlgorithmIdentifier{Algorithm: OIDEd25519}, nil
	default:
		return pkix.AlgorithmIdentifier{}, fmt.Errorf("unsupported classical public key type: %T", pub)
	}
}

func detectPQCAlgorithm(pub interface{}) (pkix.AlgorithmIdentifier, error) {
	// Check for SLH-DSA (can be value or pointer type)
	switch slhPub := pub.(type) {
	case *slhdsa.PublicKey:
		oid := slhdsaIDToOID(slhPub.ID)
		if oid == nil {
			return pkix.AlgorithmIdentifier{}, fmt.Errorf("unknown SLH-DSA ID: %v", slhPub.ID)
		}
		return pkix.AlgorithmIdentifier{Algorithm: oid}, nil
	case slhdsa.PublicKey:
		oid := slhdsaIDToOID(slhPub.ID)
		if oid == nil {
			return pkix.AlgorithmIdentifier{}, fmt.Errorf("unknown SLH-DSA ID: %v", slhPub.ID)
		}
		return pkix.AlgorithmIdentifier{Algorithm: oid}, nil
	}

	// Check if the public key type name contains ML-DSA
	// This is implementation-specific and depends on the circl library
	// The circl library uses mode2, mode3, mode5 for ML-DSA-44, ML-DSA-65, ML-DSA-87
	typeName := fmt.Sprintf("%T", pub)
	switch typeName {
	case "*mode2.PublicKey":
		return pkix.AlgorithmIdentifier{Algorithm: OIDMLDSA44}, nil
	case "*mode3.PublicKey":
		return pkix.AlgorithmIdentifier{Algorithm: OIDMLDSA65}, nil
	case "*mode5.PublicKey":
		return pkix.AlgorithmIdentifier{Algorithm: OIDMLDSA87}, nil
	default:
		return pkix.AlgorithmIdentifier{}, fmt.Errorf("unsupported public key type: %T", pub)
	}
}

// slhdsaIDToOID maps SLH-DSA ID to the corresponding OID.
func slhdsaIDToOID(id slhdsa.ID) asn1.ObjectIdentifier {
	switch id {
	case slhdsa.SHA2_128s:
		return OIDSLHDSA128s
	case slhdsa.SHA2_128f:
		return OIDSLHDSA128f
	case slhdsa.SHA2_192s:
		return OIDSLHDSA192s
	case slhdsa.SHA2_192f:
		return OIDSLHDSA192f
	case slhdsa.SHA2_256s:
		return OIDSLHDSA256s
	case slhdsa.SHA2_256f:
		return OIDSLHDSA256f
	default:
		return nil
	}
}

// injectCertificates injects a certificate into a SignedData structure.
// This is needed because Go's asn1 package doesn't properly handle the
// IMPLICIT [0] tag for the certificates field.
func injectCertificates(signedDataDER []byte, certDER []byte) ([]byte, error) {
	// Parse the SignedData to find where to inject
	// SignedData ::= SEQUENCE {
	//   version CMSVersion,
	//   digestAlgorithms DigestAlgorithmIdentifiers,
	//   encapContentInfo EncapsulatedContentInfo,
	//   certificates [0] IMPLICIT CertificateSet OPTIONAL,  <- inject here
	//   crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
	//   signerInfos SignerInfos }

	// Build the certificates field: IMPLICIT [0] containing the certificate
	// Tag 0xA0 = context-specific, constructed, tag 0
	certField := make([]byte, 0, len(certDER)+4)
	certField = append(certField, 0xA0) // IMPLICIT [0] tag

	// Encode length
	certLen := len(certDER)
	if certLen < 128 {
		certField = append(certField, byte(certLen))
	} else if certLen < 256 {
		certField = append(certField, 0x81, byte(certLen))
	} else {
		certField = append(certField, 0x82, byte(certLen>>8), byte(certLen))
	}
	certField = append(certField, certDER...)

	// Parse SignedData to find injection point (after encapContentInfo, before signerInfos)
	// For simplicity, we'll rebuild the SEQUENCE with the certificates inserted
	if len(signedDataDER) < 2 {
		return nil, fmt.Errorf("invalid SignedData: too short")
	}

	// Get the total length and find where to insert
	// The SignedData SEQUENCE tag is 0x30
	if signedDataDER[0] != 0x30 {
		return nil, fmt.Errorf("invalid SignedData: expected SEQUENCE")
	}

	// Calculate new total length
	_, contentStart := parseASN1Length(signedDataDER[1:])
	contentStart++ // account for the tag byte

	// New content = old content + certificates field
	newContent := make([]byte, 0, len(signedDataDER)+len(certField))
	oldContent := signedDataDER[contentStart:]

	// Find the signerInfos SET (last element) - it starts with 0x31
	// We need to insert certificates before it
	insertPos := findSignerInfosPosition(oldContent)
	if insertPos < 0 {
		return nil, fmt.Errorf("could not find signerInfos in SignedData")
	}

	newContent = append(newContent, oldContent[:insertPos]...)
	newContent = append(newContent, certField...)
	newContent = append(newContent, oldContent[insertPos:]...)

	// Build new SignedData with updated length
	result := make([]byte, 0, len(newContent)+4)
	result = append(result, 0x30) // SEQUENCE tag

	// Encode new length
	newLen := len(newContent)
	if newLen < 128 {
		result = append(result, byte(newLen))
	} else if newLen < 256 {
		result = append(result, 0x81, byte(newLen))
	} else if newLen < 65536 {
		result = append(result, 0x82, byte(newLen>>8), byte(newLen))
	} else {
		result = append(result, 0x83, byte(newLen>>16), byte(newLen>>8), byte(newLen))
	}
	result = append(result, newContent...)

	return result, nil
}

// parseASN1Length parses an ASN.1 length and returns the length value and bytes consumed.
func parseASN1Length(data []byte) (int, int) {
	if len(data) == 0 {
		return 0, 0
	}
	if data[0] < 128 {
		return int(data[0]), 1
	}
	numBytes := int(data[0] & 0x7f)
	if numBytes > len(data)-1 {
		return 0, 0
	}
	length := 0
	for i := 0; i < numBytes; i++ {
		length = length<<8 | int(data[1+i])
	}
	return length, numBytes + 1
}

// findSignerInfosPosition finds the position of the signerInfos SET in SignedData content.
// SignedData structure:
//
//	version           INTEGER
//	digestAlgorithms  SET OF (tag 0x31)
//	encapContentInfo  SEQUENCE (tag 0x30)
//	certificates      [0] IMPLICIT OPTIONAL (tag 0xA0)
//	crls              [1] IMPLICIT OPTIONAL (tag 0xA1)
//	signerInfos       SET OF (tag 0x31)
//
// We need to find the signerInfos SET, which is the last element.
func findSignerInfosPosition(content []byte) int {
	pos := 0

	// 1. Skip version (INTEGER, tag 0x02)
	if pos >= len(content) || content[pos] != 0x02 {
		return -1
	}
	pos++
	length, lenBytes := parseASN1Length(content[pos:])
	pos += lenBytes + length

	// 2. Skip digestAlgorithms (SET, tag 0x31)
	if pos >= len(content) || content[pos] != 0x31 {
		return -1
	}
	pos++
	length, lenBytes = parseASN1Length(content[pos:])
	pos += lenBytes + length

	// 3. Skip encapContentInfo (SEQUENCE, tag 0x30)
	if pos >= len(content) || content[pos] != 0x30 {
		return -1
	}
	pos++
	length, lenBytes = parseASN1Length(content[pos:])
	pos += lenBytes + length

	// 4. Skip certificates [0] IMPLICIT if present (tag 0xA0)
	if pos < len(content) && content[pos] == 0xA0 {
		pos++
		length, lenBytes = parseASN1Length(content[pos:])
		pos += lenBytes + length
	}

	// 5. Skip crls [1] IMPLICIT if present (tag 0xA1)
	if pos < len(content) && content[pos] == 0xA1 {
		pos++
		length, lenBytes = parseASN1Length(content[pos:])
		pos += lenBytes + length
	}

	// 6. signerInfos (SET, tag 0x31) should be here
	if pos >= len(content) || content[pos] != 0x31 {
		return -1
	}

	return pos
}
