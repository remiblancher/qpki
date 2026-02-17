// Package dto provides Data Transfer Objects for the REST API.
package dto

import (
	"encoding/base64"
	"fmt"
)

// BinaryData represents binary data with encoding metadata.
type BinaryData struct {
	// Data is the encoded content (base64 or PEM).
	Data string `json:"data"`

	// Encoding specifies the encoding format: "base64" (default) or "pem".
	Encoding string `json:"encoding,omitempty"`
}

// Decode decodes the binary data based on its encoding.
func (b *BinaryData) Decode() ([]byte, error) {
	if b == nil {
		return nil, fmt.Errorf("binary data is nil")
	}
	switch b.Encoding {
	case "pem", "":
		// PEM data is returned as-is (it's text)
		return []byte(b.Data), nil
	case "base64":
		return base64.StdEncoding.DecodeString(b.Data)
	default:
		return nil, fmt.Errorf("unsupported encoding: %s", b.Encoding)
	}
}

// APIError represents a standardized error response.
type APIError struct {
	// Code is a machine-readable error code.
	Code string `json:"code"`

	// Message is a human-readable error message.
	Message string `json:"message"`

	// Details provides additional context about the error.
	Details map[string]string `json:"details,omitempty"`
}

// HealthResponse represents the health check response.
type HealthResponse struct {
	// Status is "ok" or "degraded".
	Status string `json:"status"`

	// Version is the server version.
	Version string `json:"version"`

	// Services lists enabled services and their status.
	Services map[string]string `json:"services,omitempty"`
}

// ReadyResponse represents the readiness check response.
type ReadyResponse struct {
	// Ready indicates if the server is ready to accept requests.
	Ready bool `json:"ready"`

	// Checks lists individual readiness checks.
	Checks map[string]bool `json:"checks,omitempty"`
}

// AlgorithmInfo describes a cryptographic algorithm.
type AlgorithmInfo struct {
	// ID is the algorithm identifier (e.g., "ml-dsa-65", "ecdsa-p384").
	ID string `json:"id"`

	// Family is the algorithm family: "classical", "pqc", "hybrid", "composite".
	Family string `json:"family"`

	// Type is the algorithm type: "signature" or "kem".
	Type string `json:"type"`

	// Description provides additional information.
	Description string `json:"description,omitempty"`
}

// SubjectInfo represents X.509 subject information.
type SubjectInfo struct {
	CommonName         string `json:"cn,omitempty"`
	Organization       string `json:"o,omitempty"`
	OrganizationalUnit string `json:"ou,omitempty"`
	Country            string `json:"c,omitempty"`
	State              string `json:"st,omitempty"`
	Locality           string `json:"l,omitempty"`
}

// ValidityInfo represents certificate validity period.
type ValidityInfo struct {
	NotBefore string `json:"not_before"` // RFC3339 format
	NotAfter  string `json:"not_after"`  // RFC3339 format
}

// PaginationRequest for list endpoints.
type PaginationRequest struct {
	Limit  int    `json:"limit,omitempty"`  // Default: 100
	Offset int    `json:"offset,omitempty"` // Default: 0
	Filter string `json:"filter,omitempty"` // Optional filter expression
}

// PaginationResponse for list responses.
type PaginationResponse struct {
	Total   int  `json:"total"`
	Limit   int  `json:"limit"`
	Offset  int  `json:"offset"`
	HasMore bool `json:"has_more"`
}
