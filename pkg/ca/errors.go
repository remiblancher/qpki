// Package ca provides certificate authority functionality.
package ca

import (
	"errors"
	"fmt"
)

// CAError represents a Certificate Authority operation error with structured context.
// It supports errors.Is() and errors.As() for improved error handling.
type CAError struct {
	Op     string // Operation: "init", "issue", "revoke", "rotate", "get", "verify", "enroll"
	Serial string // Certificate serial number (if applicable)
	Err    error  // Underlying error
}

// Error implements the error interface.
func (e *CAError) Error() string {
	if e.Serial != "" {
		return fmt.Sprintf("ca %s [%s]: %v", e.Op, e.Serial, e.Err)
	}
	return fmt.Sprintf("ca %s: %v", e.Op, e.Err)
}

// Unwrap returns the underlying error for errors.Is/As support.
func (e *CAError) Unwrap() error { return e.Err }

// NewCAError creates a new CAError with the given operation and error.
func NewCAError(op string, err error) *CAError {
	return &CAError{Op: op, Err: err}
}

// NewCAErrorWithSerial creates a new CAError with operation, serial, and error.
func NewCAErrorWithSerial(op, serial string, err error) *CAError {
	return &CAError{Op: op, Serial: serial, Err: err}
}

// Sentinel errors for CA operations.
// Use errors.Is() to check for these errors through the error chain.
var (
	// ErrCertNotFound indicates the requested certificate was not found.
	ErrCertNotFound = errors.New("certificate not found")

	// ErrCertRevoked indicates the certificate has already been revoked.
	ErrCertRevoked = errors.New("certificate already revoked")

	// ErrCertExpired indicates the certificate has expired.
	ErrCertExpired = errors.New("certificate expired")

	// ErrProfileNotFound indicates the requested profile was not found.
	ErrProfileNotFound = errors.New("profile not found")

	// ErrInvalidCSR indicates the certificate signing request is invalid.
	ErrInvalidCSR = errors.New("invalid CSR")

	// ErrCANotInitialized indicates the CA has not been initialized.
	ErrCANotInitialized = errors.New("CA not initialized")

	// ErrInvalidCertificate indicates the certificate is malformed or invalid.
	ErrInvalidCertificate = errors.New("invalid certificate")

	// ErrChainVerification indicates certificate chain verification failed.
	ErrChainVerification = errors.New("certificate chain verification failed")

	// ErrKeyMismatch indicates the private key does not match the certificate.
	ErrKeyMismatch = errors.New("key does not match certificate")

	// ErrRotationFailed indicates CA key/certificate rotation failed.
	ErrRotationFailed = errors.New("rotation failed")

	// ErrCRLGeneration indicates CRL generation failed.
	ErrCRLGeneration = errors.New("CRL generation failed")
)
