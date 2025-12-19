package cms

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
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
	Certificates     rawCertificates       `asn1:"optional,tag:0"`
	CRLs             []asn1.RawValue       `asn1:"optional,set,tag:1"`
	SignerInfos      []SignerInfo          `asn1:"set"`
}

// rawCertificates is used to handle the IMPLICIT tag [0] for certificates.
type rawCertificates struct {
	Raw asn1.RawContent
}

// EncapsulatedContentInfo represents the content being signed (RFC 5652 Section 5.2).
type EncapsulatedContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     asn1.RawValue `asn1:"optional,explicit,tag:0"`
}

// SignerInfo contains the signature and related info (RFC 5652 Section 5.3).
type SignerInfo struct {
	Version            int
	SID                SignerIdentifier
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        []Attribute `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      []Attribute `asn1:"optional,tag:1"`
}

// SignerIdentifier identifies the signer's certificate.
type SignerIdentifier struct {
	IssuerAndSerialNumber IssuerAndSerialNumber
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
func MarshalSignedAttrs(attrs []Attribute) ([]byte, error) {
	// Marshal as IMPLICIT SET (tag 0x31 for SET OF)
	encoded, err := asn1.Marshal(attrs)
	if err != nil {
		return nil, err
	}
	// Replace the SEQUENCE tag (0x30) with SET tag (0x31)
	if len(encoded) > 0 && encoded[0] == 0x30 {
		encoded[0] = 0x31
	}
	return encoded, nil
}
