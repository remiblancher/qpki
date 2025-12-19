package cms

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"sort"
	"time"
)

// ContentInfo represents the top-level CMS structure (RFC 5652 Section 3).
type ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

// SignedData represents CMS SignedData (RFC 5652 Section 5).
type SignedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo EncapsulatedContentInfo
	Certificates     rawCertificates `asn1:"optional,tag:0"`
	CRLs             []asn1.RawValue `asn1:"optional,set,tag:1"`
	SignerInfos      []SignerInfo    `asn1:"set"`
}

// rawCertificates is used to handle the IMPLICIT tag [0] for certificates.
type rawCertificates struct {
	Raw asn1.RawContent
}

// EncapsulatedContentInfo represents the content being signed (RFC 5652 Section 5.2).
// Note: EContent is [0] EXPLICIT OCTET STRING - we handle the tagging in the RawValue
// rather than using struct tags, because Go's asn1 doesn't properly apply tags to RawValue.
type EncapsulatedContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     asn1.RawValue `asn1:"optional"`
}

// SignerInfo contains the signature and related info (RFC 5652 Section 5.3).
// Note: SID is IssuerAndSerialNumber directly (not wrapped in SignerIdentifier)
// because SignerIdentifier is a CHOICE in ASN.1, not a SEQUENCE.
type SignerInfo struct {
	Version            int
	SID                IssuerAndSerialNumber
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        []Attribute `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      []Attribute `asn1:"optional,tag:1"`
}

// IssuerAndSerialNumber identifies a certificate by issuer and serial.
type IssuerAndSerialNumber struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

// Attribute represents a CMS attribute (RFC 5652 Section 5.3).
type Attribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

// NewAttribute creates a new attribute with a single value.
func NewAttribute(oid asn1.ObjectIdentifier, value interface{}) (Attribute, error) {
	encoded, err := asn1.Marshal(value)
	if err != nil {
		return Attribute{}, err
	}
	return Attribute{
		Type:   oid,
		Values: []asn1.RawValue{{FullBytes: encoded}},
	}, nil
}

// NewContentTypeAttr creates a content-type attribute.
func NewContentTypeAttr(contentType asn1.ObjectIdentifier) (Attribute, error) {
	return NewAttribute(OIDContentType, contentType)
}

// NewMessageDigestAttr creates a message-digest attribute.
func NewMessageDigestAttr(digest []byte) (Attribute, error) {
	return NewAttribute(OIDMessageDigest, digest)
}

// NewSigningTimeAttr creates a signing-time attribute.
func NewSigningTimeAttr(t time.Time) (Attribute, error) {
	return NewAttribute(OIDSigningTime, t.UTC())
}

// MarshalSignedAttrs marshals signed attributes for signing.
// Per RFC 5652, signed attributes must be DER-encoded as a SET OF.
// DER requires SET OF elements to be sorted by their DER encoding.
func MarshalSignedAttrs(attrs []Attribute) ([]byte, error) {
	// First, encode each attribute individually and sort
	encodedAttrs := make([][]byte, len(attrs))
	for i, attr := range attrs {
		encoded, err := asn1.Marshal(attr)
		if err != nil {
			return nil, err
		}
		encodedAttrs[i] = encoded
	}

	// Sort by DER encoding (lexicographic byte comparison)
	sort.Slice(encodedAttrs, func(i, j int) bool {
		return bytes.Compare(encodedAttrs[i], encodedAttrs[j]) < 0
	})

	// Calculate total length
	totalLen := 0
	for _, enc := range encodedAttrs {
		totalLen += len(enc)
	}

	// Build SET OF with sorted elements
	result := make([]byte, 0, totalLen+4)
	result = append(result, 0x31) // SET tag

	// Encode length
	if totalLen < 128 {
		result = append(result, byte(totalLen))
	} else if totalLen < 256 {
		result = append(result, 0x81, byte(totalLen))
	} else {
		result = append(result, 0x82, byte(totalLen>>8), byte(totalLen))
	}

	// Append sorted elements
	for _, enc := range encodedAttrs {
		result = append(result, enc...)
	}

	return result, nil
}
