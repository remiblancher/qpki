// Package errors provides error handling and HTTP status code mapping.
package errors

import (
	"errors"
	"net/http"

	"github.com/remiblancher/post-quantum-pki/internal/api/dto"
	"github.com/remiblancher/post-quantum-pki/pkg/ca"
)

// Error codes for API responses.
const (
	CodeInvalidRequest   = "INVALID_REQUEST"
	CodeNotFound         = "NOT_FOUND"
	CodeAlreadyExists    = "ALREADY_EXISTS"
	CodeUnauthorized     = "UNAUTHORIZED"
	CodeForbidden        = "FORBIDDEN"
	CodeValidation       = "VALIDATION_ERROR"
	CodeCryptoError      = "CRYPTO_ERROR"
	CodeInternal         = "INTERNAL_ERROR"
	CodeCertNotFound     = "CERT_NOT_FOUND"
	CodeCertRevoked      = "CERT_REVOKED"
	CodeCertExpired      = "CERT_EXPIRED"
	CodeProfileNotFound  = "PROFILE_NOT_FOUND"
	CodeInvalidCSR       = "INVALID_CSR"
	CodeCANotInitialized = "CA_NOT_INITIALIZED"
	CodeChainVerify      = "CHAIN_VERIFICATION_FAILED"
	CodeKeyMismatch      = "KEY_MISMATCH"
	CodeHSMError         = "HSM_ERROR"
)

// MapError maps an internal error to an HTTP status code and APIError.
func MapError(err error) (int, *dto.APIError) {
	if err == nil {
		return http.StatusOK, nil
	}

	// Check for known CA errors
	switch {
	case errors.Is(err, ca.ErrCertNotFound):
		return http.StatusNotFound, &dto.APIError{
			Code:    CodeCertNotFound,
			Message: err.Error(),
		}
	case errors.Is(err, ca.ErrProfileNotFound):
		return http.StatusNotFound, &dto.APIError{
			Code:    CodeProfileNotFound,
			Message: err.Error(),
		}
	case errors.Is(err, ca.ErrCertRevoked):
		return http.StatusConflict, &dto.APIError{
			Code:    CodeCertRevoked,
			Message: err.Error(),
		}
	case errors.Is(err, ca.ErrCertExpired):
		return http.StatusGone, &dto.APIError{
			Code:    CodeCertExpired,
			Message: err.Error(),
		}
	case errors.Is(err, ca.ErrInvalidCSR):
		return http.StatusBadRequest, &dto.APIError{
			Code:    CodeInvalidCSR,
			Message: err.Error(),
		}
	case errors.Is(err, ca.ErrCANotInitialized):
		return http.StatusPreconditionFailed, &dto.APIError{
			Code:    CodeCANotInitialized,
			Message: err.Error(),
		}
	case errors.Is(err, ca.ErrChainVerification):
		return http.StatusUnprocessableEntity, &dto.APIError{
			Code:    CodeChainVerify,
			Message: err.Error(),
		}
	case errors.Is(err, ca.ErrKeyMismatch):
		return http.StatusUnprocessableEntity, &dto.APIError{
			Code:    CodeKeyMismatch,
			Message: err.Error(),
		}
	}

	// Check for CAError with operation context
	var caErr *ca.CAError
	if errors.As(err, &caErr) {
		return http.StatusInternalServerError, &dto.APIError{
			Code:    "CA_" + caErr.Op + "_ERROR",
			Message: caErr.Error(),
			Details: map[string]string{
				"operation": caErr.Op,
				"serial":    caErr.Serial,
			},
		}
	}

	// Default internal error
	return http.StatusInternalServerError, &dto.APIError{
		Code:    CodeInternal,
		Message: "An internal error occurred",
	}
}

// NewBadRequest creates a bad request error.
func NewBadRequest(message string) *dto.APIError {
	return &dto.APIError{
		Code:    CodeInvalidRequest,
		Message: message,
	}
}

// NewNotFound creates a not found error.
func NewNotFound(resource, id string) *dto.APIError {
	return &dto.APIError{
		Code:    CodeNotFound,
		Message: resource + " not found",
		Details: map[string]string{"id": id},
	}
}

// NewValidationError creates a validation error.
func NewValidationError(message string, details map[string]string) *dto.APIError {
	return &dto.APIError{
		Code:    CodeValidation,
		Message: message,
		Details: details,
	}
}
