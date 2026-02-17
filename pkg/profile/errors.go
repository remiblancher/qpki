// Package profile handles certificate profile validation and configuration.
package profile

import (
	"errors"
	"fmt"
)

// ProfileError represents a certificate profile operation error with structured context.
// It supports errors.Is() and errors.As() for improved error handling.
type ProfileError struct {
	Name string // Profile name
	Err  error  // Underlying error
}

// Error implements the error interface.
func (e *ProfileError) Error() string {
	if e.Name != "" {
		return fmt.Sprintf("profile %q: %v", e.Name, e.Err)
	}
	return fmt.Sprintf("profile: %v", e.Err)
}

// Unwrap returns the underlying error for errors.Is/As support.
func (e *ProfileError) Unwrap() error { return e.Err }

// NewProfileError creates a new ProfileError with the given name and error.
func NewProfileError(name string, err error) *ProfileError {
	return &ProfileError{Name: name, Err: err}
}

// ValidationError represents a specific validation failure within a profile.
type ValidationError struct {
	Field   string // Field that failed validation
	Value   string // The invalid value (if safe to include)
	Message string // Description of the validation failure
}

// Error implements the error interface.
func (e *ValidationError) Error() string {
	if e.Value != "" {
		return fmt.Sprintf("validation failed for %s=%q: %s", e.Field, e.Value, e.Message)
	}
	return fmt.Sprintf("validation failed for %s: %s", e.Field, e.Message)
}

// NewValidationError creates a new ValidationError.
func NewValidationError(field, value, message string) *ValidationError {
	return &ValidationError{Field: field, Value: value, Message: message}
}

// Sentinel errors for profile operations.
// Use errors.Is() to check for these errors through the error chain.
var (
	// ErrProfileNotFound indicates the requested profile was not found.
	ErrProfileNotFound = errors.New("profile not found")

	// ErrInvalidProfile indicates the profile configuration is invalid.
	ErrInvalidProfile = errors.New("invalid profile configuration")

	// ErrExtensionInvalid indicates an X.509 extension is invalid.
	ErrExtensionInvalid = errors.New("invalid extension")

	// ErrExtensionConflict indicates conflicting extension configurations.
	ErrExtensionConflict = errors.New("extension conflict")

	// ErrConstraintViolation indicates a certificate constraint was violated.
	ErrConstraintViolation = errors.New("constraint violation")

	// ErrTemplateInvalid indicates the profile template is invalid.
	ErrTemplateInvalid = errors.New("invalid template")

	// ErrVariableUndefined indicates a required variable is not defined.
	ErrVariableUndefined = errors.New("undefined variable")

	// ErrVariableInvalid indicates a variable value is invalid.
	ErrVariableInvalid = errors.New("invalid variable value")

	// ErrKeyUsageInvalid indicates invalid key usage configuration.
	ErrKeyUsageInvalid = errors.New("invalid key usage")

	// ErrValidityInvalid indicates invalid validity period configuration.
	ErrValidityInvalid = errors.New("invalid validity period")
)
