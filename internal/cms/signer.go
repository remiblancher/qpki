package cms

import (
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
	"time"
)

// SignerConfig contains options for signing.
type SignerConfig struct {
	Certificate    *x509.Certificate
	Signer         crypto.Signer
	DigestAlg      crypto.Hash
	IncludeCerts   bool
	SigningTime    time.Time
	ContentType    asn1.ObjectIdentifier
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
		SID: SignerIdentifier{
			IssuerAndSerialNumber: IssuerAndSerialNumber{
				Issuer:       asn1.RawValue{FullBytes: config.Certificate.RawIssuer},
				SerialNumber: config.Certificate.SerialNumber,
			},
		},
		DigestAlgorithm:    digestAlgID,
		SignedAttrs:        signedAttrs,
		SignatureAlgorithm: sigAlgID,
		Signature:          signature,
	}

	// Build EncapsulatedContentInfo
	encapContent := EncapsulatedContentInfo{
		EContentType: config.ContentType,
		EContent:     asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagOctetString, Bytes: content},
	}

	// Build SignedData
	signedData := SignedData{
		Version:          1,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{digestAlgID},
		EncapContentInfo: encapContent,
		SignerInfos:      []SignerInfo{signerInfo},
	}

	// Include certificates if requested
	if config.IncludeCerts {
		signedData.Certificates = rawCertificates{Raw: config.Certificate.Raw}
	}

	// Marshal SignedData
	signedDataDER, err := asn1.Marshal(signedData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal SignedData: %w", err)
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

func detectPQCAlgorithm(pub interface{}) (pkix.AlgorithmIdentifier, error) {
	// Check if the public key type name contains ML-DSA or SLH-DSA
	typeName := fmt.Sprintf("%T", pub)

	// ML-DSA detection based on public key size or type
	// This is implementation-specific and depends on the circl library
	switch typeName {
	case "*mldsa44.PublicKey":
		return pkix.AlgorithmIdentifier{Algorithm: OIDMLDSA44}, nil
	case "*mldsa65.PublicKey":
		return pkix.AlgorithmIdentifier{Algorithm: OIDMLDSA65}, nil
	case "*mldsa87.PublicKey":
		return pkix.AlgorithmIdentifier{Algorithm: OIDMLDSA87}, nil
	default:
		// For unknown types, try to use the algorithm from the certificate if available
		return pkix.AlgorithmIdentifier{}, fmt.Errorf("unsupported public key type: %T", pub)
	}
}
