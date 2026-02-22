// Package pki provides the public API for qpki.
// This file exposes CMS operations from internal/cms.
package pki

import (
	"context"

	"github.com/remiblancher/qpki/internal/cms"
)

// Re-export CMS types
type (
	// SignedData represents a CMS SignedData structure.
	CMSSignedData = cms.SignedData

	// EnvelopedData represents a CMS EnvelopedData structure.
	CMSEnvelopedData = cms.EnvelopedData

	// SignerConfig holds options for CMS signing.
	CMSSignerConfig = cms.SignerConfig

	// EncryptOptions holds options for CMS encryption.
	CMSEncryptOptions = cms.EncryptOptions

	// DecryptOptions holds options for CMS decryption.
	CMSDecryptOptions = cms.DecryptOptions

	// DecryptResult holds the decryption result.
	CMSDecryptResult = cms.DecryptResult

	// VerifyConfig holds options for CMS verification.
	CMSVerifyConfig = cms.VerifyConfig

	// VerifyResult holds the verification result.
	CMSVerifyResult = cms.VerifyResult

	// ContentInfo represents CMS ContentInfo.
	CMSContentInfo = cms.ContentInfo

	// CMSError wraps CMS errors.
	CMSError = cms.CMSError
)

// CMSSign creates a CMS SignedData structure.
func CMSSign(ctx context.Context, content []byte, config *CMSSignerConfig) ([]byte, error) {
	return cms.Sign(ctx, content, config)
}

// CMSVerify verifies a CMS SignedData structure.
func CMSVerify(ctx context.Context, signedDataDER []byte, config *CMSVerifyConfig) (*CMSVerifyResult, error) {
	return cms.Verify(ctx, signedDataDER, config)
}

// CMSEncrypt creates a CMS EnvelopedData structure.
func CMSEncrypt(ctx context.Context, data []byte, opts *CMSEncryptOptions) ([]byte, error) {
	return cms.Encrypt(ctx, data, opts)
}

// CMSDecrypt decrypts a CMS EnvelopedData structure.
func CMSDecrypt(ctx context.Context, data []byte, opts *CMSDecryptOptions) (*CMSDecryptResult, error) {
	return cms.Decrypt(ctx, data, opts)
}

// CMSParseSignedData parses a CMS SignedData structure.
func CMSParseSignedData(data []byte) (*CMSSignedData, error) {
	return cms.ParseSignedData(data)
}

// CMSParseEnvelopedData parses a CMS EnvelopedData structure.
func CMSParseEnvelopedData(data []byte) (*CMSEnvelopedData, error) {
	return cms.ParseEnvelopedData(data)
}

// CMSParseContentInfo parses CMS ContentInfo.
func CMSParseContentInfo(data []byte) (*CMSContentInfo, error) {
	return cms.ParseContentInfo(data)
}
