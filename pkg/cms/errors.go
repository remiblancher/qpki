// Package cms implements Cryptographic Message Syntax (RFC 5652).
package cms

import (
	"errors"
	"fmt"
)

// CMSError represents a CMS operation error with structured context.
// It supports errors.Is() and errors.As() for improved error handling.
type CMSError struct {
	Op  string // Operation: "sign", "verify", "encrypt", "decrypt", "parse", "envelop"
	Err error  // Underlying error
}

// Error implements the error interface.
func (e *CMSError) Error() string {
	return fmt.Sprintf("cms %s: %v", e.Op, e.Err)
}

// Unwrap returns the underlying error for errors.Is/As support.
func (e *CMSError) Unwrap() error { return e.Err }

// NewCMSError creates a new CMSError with the given operation and error.
func NewCMSError(op string, err error) *CMSError {
	return &CMSError{Op: op, Err: err}
}

// Sentinel errors for CMS operations.
// Use errors.Is() to check for these errors through the error chain.
var (
	// ErrInvalidSignature indicates signature verification failed.
	ErrInvalidSignature = errors.New("invalid signature")

	// ErrNoCertificate indicates no certificate was found in the CMS structure.
	ErrNoCertificate = errors.New("no certificate found")

	// ErrDecryptFailed indicates decryption of the CMS content failed.
	ErrDecryptFailed = errors.New("decryption failed")

	// ErrEncryptFailed indicates encryption of the CMS content failed.
	ErrEncryptFailed = errors.New("encryption failed")

	// ErrInvalidContent indicates the CMS content is malformed.
	ErrInvalidContent = errors.New("invalid CMS content")

	// ErrNoSigner indicates no signer information was found.
	ErrNoSigner = errors.New("no signer information")

	// ErrUnsupportedAlgorithm indicates an unsupported cryptographic algorithm.
	ErrUnsupportedAlgorithm = errors.New("unsupported algorithm")

	// ErrMissingAttribute indicates a required signed attribute is missing.
	ErrMissingAttribute = errors.New("missing signed attribute")

	// ErrInvalidRecipient indicates the recipient information is invalid.
	ErrInvalidRecipient = errors.New("invalid recipient information")

	// ErrNoRecipient indicates no matching recipient was found for decryption.
	ErrNoRecipient = errors.New("no matching recipient")
)
