// Package pki provides the public API for qpki.
// This file exposes TSA operations from internal/tsa.
package pki

import (
	"context"
	"crypto"
	"math/big"

	"github.com/remiblancher/qpki/internal/tsa"
)

// Re-export TSA types
type (
	// TSATimeStampReq represents a TSA request.
	TSATimeStampReq = tsa.TimeStampReq

	// TSAResponse represents a parsed timestamp response.
	TSAResponse = tsa.Response

	// TSAToken represents a timestamp token.
	TSAToken = tsa.Token

	// TSATokenConfig holds configuration for token creation.
	TSATokenConfig = tsa.TokenConfig

	// TSAVerifyConfig holds configuration for verification.
	TSAVerifyConfig = tsa.VerifyConfig

	// TSAVerifyResult holds the result of verification.
	TSAVerifyResult = tsa.VerifyResult

	// TSAError wraps TSA errors.
	TSAError = tsa.TSAError

	// TSASerialGenerator generates serial numbers.
	TSASerialGenerator = tsa.SerialGenerator

	// TSAMessageImprint represents a hash of the data to timestamp.
	TSAMessageImprint = tsa.MessageImprint

	// TSARandomSerialGenerator generates random serial numbers.
	TSARandomSerialGenerator = tsa.RandomSerialGenerator
)

// TSACreateRequest creates a timestamp request.
func TSACreateRequest(data []byte, hashAlg crypto.Hash, nonce *big.Int, certReq bool) (*TSATimeStampReq, error) {
	return tsa.CreateRequest(data, hashAlg, nonce, certReq)
}

// TSAParseRequest parses a timestamp request.
func TSAParseRequest(data []byte) (*TSATimeStampReq, error) {
	return tsa.ParseRequest(data)
}

// TSACreateToken creates a timestamp token.
func TSACreateToken(ctx context.Context, req *TSATimeStampReq, config *TSATokenConfig, serialGen TSASerialGenerator) (*TSAToken, error) {
	return tsa.CreateToken(ctx, req, config, serialGen)
}

// TSAParseToken parses a timestamp token.
func TSAParseToken(data []byte) (*TSAToken, error) {
	return tsa.ParseToken(data)
}

// TSAParseResponse parses a timestamp response.
func TSAParseResponse(data []byte) (*TSAResponse, error) {
	return tsa.ParseResponse(data)
}

// TSAVerify verifies a timestamp.
func TSAVerify(ctx context.Context, tokenData []byte, config *TSAVerifyConfig) (*TSAVerifyResult, error) {
	return tsa.Verify(ctx, tokenData, config)
}

// TSANewGrantedResponse creates a granted response.
func TSANewGrantedResponse(token *TSAToken) *TSAResponse {
	return tsa.NewGrantedResponse(token)
}

// TSANewRejectionResponse creates a rejection response.
func TSANewRejectionResponse(failInfo int, message string) *TSAResponse {
	return tsa.NewRejectionResponse(failInfo, message)
}

// TSANewMessageImprint creates a new message imprint.
func TSANewMessageImprint(hashAlg crypto.Hash, digest []byte) TSAMessageImprint {
	return tsa.NewMessageImprint(hashAlg, digest)
}
