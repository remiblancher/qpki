// Package pki provides the public API for qpki.
// This file exposes OCSP operations from internal/ocsp.
package pki

import (
	"crypto"
	"crypto/x509"
	"net/http"

	"github.com/remiblancher/qpki/internal/ocsp"
)

// Re-export OCSP types
type (
	// OCSPRequest represents an OCSP request.
	OCSPRequest = ocsp.OCSPRequest

	// OCSPResponse represents an OCSP response.
	OCSPResponse = ocsp.OCSPResponse

	// OCSPSingleRequest represents a single certificate request.
	OCSPSingleRequest = ocsp.Request

	// OCSPCertID identifies a certificate.
	OCSPCertID = ocsp.CertID

	// OCSPResponderConfig holds OCSP responder configuration.
	OCSPResponderConfig = ocsp.ResponderConfig

	// OCSPResponder is an OCSP responder.
	OCSPResponder = ocsp.Responder

	// OCSPStatusInfo holds certificate status info.
	OCSPStatusInfo = ocsp.StatusInfo

	// OCSPResponseBuilder builds OCSP responses.
	OCSPResponseBuilder = ocsp.ResponseBuilder

	// OCSPCertStatus represents the revocation status of a certificate.
	OCSPCertStatus = ocsp.CertStatus

	// OCSPRevocationReason represents the reason for revocation.
	OCSPRevocationReason = ocsp.RevocationReason

	// OCSPResponseStatus represents the status of an OCSP response.
	OCSPResponseStatus = ocsp.ResponseStatus

	// OCSPVerifyConfig contains options for verifying an OCSP response.
	OCSPVerifyConfig = ocsp.VerifyConfig

	// OCSPVerifyResult contains the result of OCSP response verification.
	OCSPVerifyResult = ocsp.VerifyResult
)

// OCSP certificate status constants.
const (
	OCSPCertStatusGood    = ocsp.CertStatusGood
	OCSPCertStatusRevoked = ocsp.CertStatusRevoked
	OCSPCertStatusUnknown = ocsp.CertStatusUnknown
)

// OCSP response status constants.
const (
	OCSPStatusSuccessful       = ocsp.StatusSuccessful
	OCSPStatusMalformedRequest = ocsp.StatusMalformedRequest
	OCSPStatusInternalError    = ocsp.StatusInternalError
	OCSPStatusTryLater         = ocsp.StatusTryLater
	OCSPStatusSigRequired      = ocsp.StatusSigRequired
	OCSPStatusUnauthorized     = ocsp.StatusUnauthorized
)

// OCSP revocation reason constants.
const (
	OCSPReasonUnspecified          = ocsp.ReasonUnspecified
	OCSPReasonKeyCompromise        = ocsp.ReasonKeyCompromise
	OCSPReasonCACompromise         = ocsp.ReasonCACompromise
	OCSPReasonAffiliationChanged   = ocsp.ReasonAffiliationChanged
	OCSPReasonSuperseded           = ocsp.ReasonSuperseded
	OCSPReasonCessationOfOperation = ocsp.ReasonCessationOfOperation
	OCSPReasonCertificateHold      = ocsp.ReasonCertificateHold
	OCSPReasonRemoveFromCRL        = ocsp.ReasonRemoveFromCRL
	OCSPReasonPrivilegeWithdrawn   = ocsp.ReasonPrivilegeWithdrawn
	OCSPReasonAACompromise         = ocsp.ReasonAACompromise
)

// OCSPParseRequest parses an OCSP request.
func OCSPParseRequest(data []byte) (*OCSPRequest, error) {
	return ocsp.ParseRequest(data)
}

// OCSPParseRequestFromHTTP parses an OCSP request from HTTP.
func OCSPParseRequestFromHTTP(r *http.Request) (*OCSPRequest, error) {
	return ocsp.ParseRequestFromHTTP(r)
}

// OCSPParseResponse parses an OCSP response.
func OCSPParseResponse(data []byte) (*OCSPResponse, error) {
	return ocsp.ParseResponse(data)
}

// OCSPNewResponder creates a new OCSP responder.
func OCSPNewResponder(config *OCSPResponderConfig) (*OCSPResponder, error) {
	return ocsp.NewResponder(config)
}

// OCSPNewResponseBuilder creates a new response builder.
func OCSPNewResponseBuilder(responderCert *x509.Certificate, signer crypto.Signer) *OCSPResponseBuilder {
	return ocsp.NewResponseBuilder(responderCert, signer)
}

// OCSPCreateRequest creates an OCSP request.
func OCSPCreateRequest(issuer *x509.Certificate, certs []*x509.Certificate, hashAlg crypto.Hash) (*OCSPRequest, error) {
	return ocsp.CreateRequest(issuer, certs, hashAlg)
}

// OCSPNewErrorResponse creates an error response.
func OCSPNewErrorResponse(status ocsp.ResponseStatus) ([]byte, error) {
	return ocsp.NewErrorResponse(status)
}

// OCSPNewMalformedResponse creates a malformed request response.
func OCSPNewMalformedResponse() ([]byte, error) {
	return ocsp.NewMalformedResponse()
}

// OCSPNewInternalErrorResponse creates an internal error response.
func OCSPNewInternalErrorResponse() ([]byte, error) {
	return ocsp.NewInternalErrorResponse()
}

// OCSPVerify verifies an OCSP response.
func OCSPVerify(responseData []byte, config *OCSPVerifyConfig) (*OCSPVerifyResult, error) {
	return ocsp.Verify(responseData, config)
}

// NewOCSPResponder creates a new OCSP responder (alias for OCSPNewResponder).
func NewOCSPResponder(config *OCSPResponderConfig) (*OCSPResponder, error) {
	return ocsp.NewResponder(config)
}
