package cms

import (
	"encoding/asn1"
	"fmt"
)

// ParseContentInfo parses a CMS ContentInfo structure.
// This is the top-level wrapper for all CMS message types.
func ParseContentInfo(data []byte) (*ContentInfo, error) {
	var ci ContentInfo
	_, err := asn1.Unmarshal(data, &ci)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ContentInfo: %w", err)
	}
	return &ci, nil
}

// ParseSignedData parses a CMS SignedData structure from raw DER bytes.
// The input should be a complete ContentInfo containing SignedData.
func ParseSignedData(data []byte) (*SignedData, error) {
	var ci ContentInfo
	_, err := asn1.Unmarshal(data, &ci)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ContentInfo: %w", err)
	}

	if !ci.ContentType.Equal(OIDSignedData) {
		return nil, fmt.Errorf("not a SignedData structure, got OID %v", ci.ContentType)
	}

	var sd SignedData
	_, err = asn1.Unmarshal(ci.Content.Bytes, &sd)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SignedData: %w", err)
	}

	return &sd, nil
}

// ParseEnvelopedData parses a CMS EnvelopedData structure from raw DER bytes.
// The input should be a complete ContentInfo containing EnvelopedData.
func ParseEnvelopedData(data []byte) (*EnvelopedData, error) {
	var ci ContentInfo
	_, err := asn1.Unmarshal(data, &ci)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ContentInfo: %w", err)
	}

	if !ci.ContentType.Equal(OIDEnvelopedData) {
		return nil, fmt.Errorf("not an EnvelopedData structure, got OID %v", ci.ContentType)
	}

	var env EnvelopedData
	_, err = asn1.Unmarshal(ci.Content.Bytes, &env)
	if err != nil {
		return nil, fmt.Errorf("failed to parse EnvelopedData: %w", err)
	}

	return &env, nil
}
