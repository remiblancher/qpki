package cose

import (
	"crypto/x509"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	gocose "github.com/veraison/go-cose"
)

// CBOR tags for COSE messages.
const (
	CBORTagSign1 = 18 // COSE_Sign1
	CBORTagSign  = 98 // COSE_Sign
)

// Parse parses a CBOR-encoded COSE message and returns a Message.
// It auto-detects the message type (Sign1, Sign, CWT).
func Parse(data []byte) (*Message, error) {
	// Detect message type from CBOR tag
	msgType, err := detectMessageType(data)
	if err != nil {
		return nil, fmt.Errorf("failed to detect message type: %w", err)
	}

	switch msgType {
	case TypeSign1:
		return parseSign1(data)
	case TypeSign:
		return parseSign(data)
	default:
		return nil, fmt.Errorf("unknown message type")
	}
}

// ParseSign1 parses a COSE Sign1 message.
func ParseSign1(data []byte) (*Message, error) {
	return parseSign1(data)
}

// ParseSign parses a COSE Sign message.
func ParseSign(data []byte) (*Message, error) {
	return parseSign(data)
}

// ParseCWT parses a CWT (CBOR Web Token).
// A CWT is a COSE Sign1 or Sign message with claims in the payload.
func ParseCWT(data []byte) (*Message, error) {
	msg, err := Parse(data)
	if err != nil {
		return nil, err
	}

	// Parse claims from payload
	claims := &Claims{}
	if err := claims.UnmarshalCBOR(msg.Payload); err != nil {
		return nil, fmt.Errorf("failed to parse CWT claims: %w", err)
	}
	msg.Claims = claims
	msg.Type = TypeCWT

	return msg, nil
}

// detectMessageType detects the COSE message type from the CBOR tag.
func detectMessageType(data []byte) (MessageType, error) {
	if len(data) < 1 {
		return 0, fmt.Errorf("data too short")
	}

	// Check for CBOR tag
	// Tag encoding in CBOR:
	//   0xc0-0xd7 = tags 0-23 (tag value = byte - 0xc0)
	//   0xd8 <1-byte tag> = tags 24-255
	//   0xd9 <2-byte tag> = tags 256-65535
	//
	// COSE_Sign1 uses tag 18: 0xd2 (0xc0 + 18)
	// COSE_Sign uses tag 98: 0xd8 0x62 (98 in hex is 0x62)

	switch {
	case data[0] == 0xd2: // Tag 18 = COSE_Sign1
		return TypeSign1, nil

	case data[0] >= 0xc0 && data[0] <= 0xd7:
		// Tags 0-23: single byte
		tag := int(data[0] - 0xc0)
		if tag == CBORTagSign1 {
			return TypeSign1, nil
		}
		// Unknown tag in 0-23 range, try to parse as array
		return TypeSign1, nil

	case data[0] == 0xd8: // 1-byte tag follows (tags 24-255)
		if len(data) < 2 {
			return 0, fmt.Errorf("truncated tag")
		}
		tag := int(data[1])
		switch tag {
		case CBORTagSign1:
			return TypeSign1, nil
		case CBORTagSign:
			return TypeSign, nil
		}

	case data[0] == 0xd9: // 2-byte tag follows (tags 256-65535)
		if len(data) < 3 {
			return 0, fmt.Errorf("truncated tag")
		}
		// For now, we don't use tags this large
	}

	// Try to parse as untagged array
	// COSE Sign1 is a 4-element array
	// COSE Sign is a 4-element array with the 4th element being an array of signatures
	if data[0]&0xf0 == 0x80 || data[0]&0xf0 == 0x90 { // Array (small or large)
		return TypeSign1, nil // Default to Sign1 for untagged
	}

	return 0, fmt.Errorf("unable to detect message type from CBOR")
}

// parseSign1 parses a COSE Sign1 message.
func parseSign1(data []byte) (*Message, error) {
	var sign1 gocose.Sign1Message
	if err := cbor.Unmarshal(data, &sign1); err != nil {
		return nil, fmt.Errorf("failed to parse Sign1 message: %w", err)
	}

	msg := &Message{
		Type:       TypeSign1,
		Payload:    sign1.Payload,
		RawMessage: data,
	}

	// Extract signature info
	sigInfo := SignatureInfo{}

	// Get algorithm from protected header
	if alg, err := sign1.Headers.Protected.Algorithm(); err == nil {
		sigInfo.Algorithm = alg
		if IsPQCAlgorithm(alg) {
			msg.Mode = ModePQC
		} else {
			msg.Mode = ModeClassical
		}
	}

	// Get Key ID
	if kid, ok := sign1.Headers.Protected[gocose.HeaderLabelKeyID]; ok {
		if b, ok := kid.([]byte); ok {
			sigInfo.KeyID = b
		}
	}

	// Get certificate from x5chain if present
	if x5chain, ok := sign1.Headers.Protected[HeaderX5Chain]; ok {
		sigInfo.Certificate = extractCertFromX5Chain(x5chain)
	}

	// Get content type
	if ct, ok := sign1.Headers.Protected[gocose.HeaderLabelContentType]; ok {
		if s, ok := ct.(string); ok {
			msg.ContentType = s
		}
	}

	msg.Signatures = []SignatureInfo{sigInfo}

	// Check if this is a CWT based on content type
	if msg.ContentType == "application/cwt" {
		msg.Type = TypeCWT
		claims := &Claims{}
		if err := claims.UnmarshalCBOR(msg.Payload); err == nil {
			msg.Claims = claims
		}
	}

	return msg, nil
}

// parseSign parses a COSE Sign message.
func parseSign(data []byte) (*Message, error) {
	var sign gocose.SignMessage
	if err := cbor.Unmarshal(data, &sign); err != nil {
		return nil, fmt.Errorf("failed to parse Sign message: %w", err)
	}

	msg := &Message{
		Type:       TypeSign,
		Payload:    sign.Payload,
		RawMessage: data,
	}

	// Determine signing mode based on signatures
	hasClassical := false
	hasPQC := false

	for _, sig := range sign.Signatures {
		sigInfo := SignatureInfo{}

		// Get algorithm
		if alg, err := sig.Headers.Protected.Algorithm(); err == nil {
			sigInfo.Algorithm = alg
			if IsPQCAlgorithm(alg) {
				hasPQC = true
			} else {
				hasClassical = true
			}
		}

		// Get Key ID
		if kid, ok := sig.Headers.Protected[gocose.HeaderLabelKeyID]; ok {
			if b, ok := kid.([]byte); ok {
				sigInfo.KeyID = b
			}
		}

		// Get certificate from x5chain if present
		if x5chain, ok := sig.Headers.Protected[HeaderX5Chain]; ok {
			sigInfo.Certificate = extractCertFromX5Chain(x5chain)
		}

		msg.Signatures = append(msg.Signatures, sigInfo)
	}

	// Determine mode
	if hasClassical && hasPQC {
		msg.Mode = ModeHybrid
	} else if hasPQC {
		msg.Mode = ModePQC
	} else {
		msg.Mode = ModeClassical
	}

	// Get content type from message headers
	if ct, ok := sign.Headers.Protected[gocose.HeaderLabelContentType]; ok {
		if s, ok := ct.(string); ok {
			msg.ContentType = s
		}
	}

	// Check if this is a CWT based on content type
	if msg.ContentType == "application/cwt" {
		msg.Type = TypeCWT
		claims := &Claims{}
		if err := claims.UnmarshalCBOR(msg.Payload); err == nil {
			msg.Claims = claims
		}
	}

	return msg, nil
}

// extractCertFromX5Chain extracts the first certificate from an x5chain header value.
func extractCertFromX5Chain(x5chain interface{}) *x509.Certificate {
	switch v := x5chain.(type) {
	case []byte:
		// Single certificate
		cert, err := x509.ParseCertificate(v)
		if err == nil {
			return cert
		}
	case []interface{}:
		// Array of certificates
		if len(v) > 0 {
			if b, ok := v[0].([]byte); ok {
				cert, err := x509.ParseCertificate(b)
				if err == nil {
					return cert
				}
			}
		}
	case [][]byte:
		// Array of byte arrays
		if len(v) > 0 {
			cert, err := x509.ParseCertificate(v[0])
			if err == nil {
				return cert
			}
		}
	}
	return nil
}
