// Package pki provides the public API for qpki.
// This file exposes COSE operations from internal/cose.
package pki

import (
	"context"
	"crypto"
	"time"

	"github.com/remiblancher/qpki/internal/cose"
	gocose "github.com/veraison/go-cose"
)

// Re-export gocose.Algorithm type.
type COSEAlgorithm = gocose.Algorithm

// Re-export COSE types
type (
	// COSEMessage represents a COSE message.
	COSEMessage = cose.Message

	// COSEMessageConfig holds configuration for COSE message creation.
	COSEMessageConfig = cose.MessageConfig

	// COSECWTConfig holds configuration for CWT creation.
	COSECWTConfig = cose.CWTConfig

	// COSEVerifyConfig holds configuration for COSE verification.
	COSEVerifyConfig = cose.VerifyConfig

	// COSEVerifyResult holds the result of verification.
	COSEVerifyResult = cose.VerifyResult

	// COSEClaims represents CWT claims.
	COSEClaims = cose.Claims

	// COSEInfo holds COSE message info.
	COSEInfo = cose.Info

	// COSESigner is a COSE signer.
	COSESigner = cose.Signer

	// COSEVerifier is a COSE verifier.
	COSEVerifier = cose.Verifier

	// COSEMessageType represents the type of COSE message.
	COSEMessageType = cose.MessageType

	// COSESigningMode represents the cryptographic mode.
	COSESigningMode = cose.SigningMode
)

// COSE message type constants.
const (
	COSETypeCWT   = cose.TypeCWT
	COSETypeSign1 = cose.TypeSign1
	COSETypeSign  = cose.TypeSign
)

// COSE signing mode constants.
const (
	COSEModeClassical = cose.ModeClassical
	COSEModePQC       = cose.ModePQC
	COSEModeHybrid    = cose.ModeHybrid
)

// COSENewSigner creates a new COSE signer.
func COSENewSigner(s crypto.Signer) (*COSESigner, error) {
	return cose.NewSigner(s)
}

// COSENewVerifier creates a new COSE verifier.
func COSENewVerifier(pub crypto.PublicKey) (*COSEVerifier, error) {
	return cose.NewVerifier(pub)
}

// COSENewClaims creates new CWT claims.
func COSENewClaims() *COSEClaims {
	return cose.NewClaims()
}

// COSEParse parses a COSE message.
func COSEParse(data []byte) (*COSEMessage, error) {
	return cose.Parse(data)
}

// COSEParseSign1 parses a COSE Sign1 message.
func COSEParseSign1(data []byte) (*COSEMessage, error) {
	return cose.ParseSign1(data)
}

// COSEParseCWT parses a COSE CWT.
func COSEParseCWT(data []byte) (*COSEMessage, error) {
	return cose.ParseCWT(data)
}

// COSEVerifySign1 verifies a COSE Sign1 message.
func COSEVerifySign1(data []byte, config *COSEVerifyConfig) (*COSEVerifyResult, error) {
	return cose.VerifySign1(data, config)
}

// COSEVerifyCWT verifies a CWT.
func COSEVerifyCWT(data []byte, config *COSEVerifyConfig) (*COSEVerifyResult, error) {
	return cose.VerifyCWT(data, config)
}

// COSEVerifyWithTime verifies with a specific time.
func COSEVerifyWithTime(data []byte, config *COSEVerifyConfig, t time.Time) (*COSEVerifyResult, error) {
	return cose.VerifyWithTime(data, config, t)
}

// COSEGetInfo gets info about a COSE message.
func COSEGetInfo(data []byte) (*COSEInfo, error) {
	return cose.GetInfo(data)
}

// COSEIssueCWT creates a CWT (CBOR Web Token) with the given claims.
func COSEIssueCWT(ctx context.Context, config *COSECWTConfig) ([]byte, error) {
	return cose.IssueCWT(ctx, config)
}

// COSEIssueSign1 creates a COSE Sign1 message (single signature).
func COSEIssueSign1(ctx context.Context, payload []byte, config *COSEMessageConfig) ([]byte, error) {
	return cose.IssueSign1(ctx, payload, config)
}

// COSEIssueSign creates a COSE Sign message (multiple signatures, for hybrid mode).
func COSEIssueSign(ctx context.Context, payload []byte, config *COSEMessageConfig) ([]byte, error) {
	return cose.IssueSign(ctx, payload, config)
}

// COSEVerifySign verifies a COSE Sign message (multi-signature/hybrid).
func COSEVerifySign(data []byte, config *COSEVerifyConfig) (*COSEVerifyResult, error) {
	return cose.VerifySign(data, config)
}

// COSEAlgorithmName returns a human-readable name for a COSE algorithm.
func COSEAlgorithmName(alg COSEAlgorithm) string {
	return cose.AlgorithmName(alg)
}
