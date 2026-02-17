// Package tsa implements RFC 3161 Time-Stamp Protocol.
package tsa

import (
	"errors"
	"fmt"
)

// TSAError represents a Time-Stamp Authority operation error with structured context.
// It supports errors.Is() and errors.As() for improved error handling.
type TSAError struct {
	Op  string // Operation: "request", "response", "verify", "sign", "parse"
	Err error  // Underlying error
}

// Error implements the error interface.
func (e *TSAError) Error() string {
	return fmt.Sprintf("tsa %s: %v", e.Op, e.Err)
}

// Unwrap returns the underlying error for errors.Is/As support.
func (e *TSAError) Unwrap() error { return e.Err }

// NewTSAError creates a new TSAError with the given operation and error.
func NewTSAError(op string, err error) *TSAError {
	return &TSAError{Op: op, Err: err}
}

// Sentinel errors for TSA operations.
// Use errors.Is() to check for these errors through the error chain.
var (
	// ErrInvalidRequest indicates the timestamp request is malformed.
	ErrInvalidRequest = errors.New("invalid timestamp request")

	// ErrInvalidResponse indicates the timestamp response is malformed.
	ErrInvalidResponse = errors.New("invalid timestamp response")

	// ErrVerificationFailed indicates timestamp verification failed.
	ErrVerificationFailed = errors.New("timestamp verification failed")

	// ErrHashMismatch indicates the message digest does not match.
	ErrHashMismatch = errors.New("message digest mismatch")

	// ErrNonceMismatch indicates the nonce in response does not match request.
	ErrNonceMismatch = errors.New("nonce mismatch")

	// ErrPolicyMismatch indicates the policy OID does not match.
	ErrPolicyMismatch = errors.New("policy OID mismatch")

	// ErrCertificateRequired indicates a TSA certificate is required but missing.
	ErrCertificateRequired = errors.New("TSA certificate required")

	// ErrUnsupportedHashAlgorithm indicates the hash algorithm is not supported.
	ErrUnsupportedHashAlgorithm = errors.New("unsupported hash algorithm")

	// ErrTimestampExpired indicates the timestamp token has expired.
	ErrTimestampExpired = errors.New("timestamp expired")

	// ErrInvalidToken indicates the timestamp token is invalid.
	ErrInvalidToken = errors.New("invalid timestamp token")
)
