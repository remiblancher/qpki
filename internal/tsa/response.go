// Package tsa implements RFC 3161 Time-Stamp Protocol.
package tsa

import (
	"encoding/asn1"
	"fmt"
)

// PKIStatus values (RFC 3161 Section 2.4.2).
const (
	StatusGranted                = 0
	StatusGrantedWithMods        = 1
	StatusRejection              = 2
	StatusWaiting                = 3
	StatusRevocationWarning      = 4
	StatusRevocationNotification = 5
)

// PKIFailureInfo values (RFC 3161 Section 2.4.2).
const (
	FailBadAlg              = 0  // Unrecognized or unsupported algorithm
	FailBadRequest          = 2  // Transaction not permitted or supported
	FailBadDataFormat       = 5  // The data submitted has the wrong format
	FailTimeNotAvailable    = 14 // TSA's time source is not available
	FailUnacceptedPolicy    = 15 // The requested policy is not supported
	FailUnacceptedExtension = 16 // The requested extension is not supported
	FailAddInfoNotAvailable = 17 // The additional information requested could not be understood
	FailSystemFailure       = 25 // System failure
)

// TimeStampResp represents the timestamp response (RFC 3161 Section 2.4.2).
type TimeStampResp struct {
	Status         PKIStatusInfo
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

// PKIStatusInfo contains the status of the request (RFC 3161 Section 2.4.2).
type PKIStatusInfo struct {
	Status       int
	StatusString []string       `asn1:"optional"`
	FailInfo     asn1.BitString `asn1:"optional"`
}

// Response represents a complete timestamp response.
type Response struct {
	Status PKIStatusInfo
	Token  *Token
}

// NewGrantedResponse creates a successful timestamp response.
func NewGrantedResponse(token *Token) *Response {
	return &Response{
		Status: PKIStatusInfo{
			Status: StatusGranted,
		},
		Token: token,
	}
}

// NewRejectionResponse creates a rejection response with the specified failure info.
func NewRejectionResponse(failInfo int, message string) *Response {
	status := PKIStatusInfo{
		Status: StatusRejection,
	}
	if message != "" {
		status.StatusString = []string{message}
	}
	// Set the failure bit
	status.FailInfo = failInfoBitString(failInfo)
	return &Response{
		Status: status,
	}
}

// failInfoBitString creates a BitString with the specified failure bit set.
func failInfoBitString(bit int) asn1.BitString {
	// PKIFailureInfo is a BIT STRING with max 26 bits
	bytes := make([]byte, 4)
	byteIdx := bit / 8
	bitIdx := uint(7 - (bit % 8))
	if byteIdx < 4 {
		bytes[byteIdx] = 1 << bitIdx
	}
	// Calculate padding bits
	length := (bit / 8) + 1
	padding := (8 - (bit % 8 + 1)) % 8
	return asn1.BitString{
		Bytes:     bytes[:length],
		BitLength: length*8 - padding,
	}
}

// Marshal encodes the response as DER.
func (r *Response) Marshal() ([]byte, error) {
	resp := TimeStampResp{
		Status: r.Status,
	}

	// Include token if granted
	if r.Token != nil && r.Status.Status == StatusGranted {
		resp.TimeStampToken = asn1.RawValue{FullBytes: r.Token.SignedData}
	}

	return asn1.Marshal(resp)
}

// ParseResponse parses a DER-encoded TimeStampResp.
func ParseResponse(data []byte) (*Response, error) {
	var resp TimeStampResp
	rest, err := asn1.Unmarshal(data, &resp)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TimeStampResp: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data after TimeStampResp")
	}

	response := &Response{
		Status: resp.Status,
	}

	// Parse token if present
	if len(resp.TimeStampToken.FullBytes) > 0 {
		token, err := ParseToken(resp.TimeStampToken.FullBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse token: %w", err)
		}
		response.Token = token
	}

	return response, nil
}

// IsGranted returns true if the response indicates success.
func (r *Response) IsGranted() bool {
	return r.Status.Status == StatusGranted || r.Status.Status == StatusGrantedWithMods
}

// StatusString returns a human-readable status string.
func (r *Response) StatusString() string {
	switch r.Status.Status {
	case StatusGranted:
		return "granted"
	case StatusGrantedWithMods:
		return "granted with modifications"
	case StatusRejection:
		return "rejection"
	case StatusWaiting:
		return "waiting"
	case StatusRevocationWarning:
		return "revocation warning"
	case StatusRevocationNotification:
		return "revocation notification"
	default:
		return fmt.Sprintf("unknown status %d", r.Status.Status)
	}
}

// FailureString returns a human-readable failure reason.
func (r *Response) FailureString() string {
	if r.Status.FailInfo.BitLength == 0 {
		if len(r.Status.StatusString) > 0 {
			return r.Status.StatusString[0]
		}
		return ""
	}

	// Check which bit is set
	for i := 0; i < r.Status.FailInfo.BitLength; i++ {
		byteIdx := i / 8
		bitIdx := uint(7 - (i % 8))
		if byteIdx < len(r.Status.FailInfo.Bytes) && (r.Status.FailInfo.Bytes[byteIdx]&(1<<bitIdx)) != 0 {
			return failureInfoString(i)
		}
	}

	return "unknown failure"
}

// failureInfoString returns a human-readable string for a failure bit.
func failureInfoString(bit int) string {
	switch bit {
	case FailBadAlg:
		return "unrecognized or unsupported algorithm"
	case FailBadRequest:
		return "transaction not permitted or supported"
	case FailBadDataFormat:
		return "data submitted has wrong format"
	case FailTimeNotAvailable:
		return "time source not available"
	case FailUnacceptedPolicy:
		return "requested policy not supported"
	case FailUnacceptedExtension:
		return "requested extension not supported"
	case FailAddInfoNotAvailable:
		return "additional information not available"
	case FailSystemFailure:
		return "system failure"
	default:
		return fmt.Sprintf("failure bit %d", bit)
	}
}
