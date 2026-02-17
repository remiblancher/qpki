package dto

// CMSSignRequest represents a CMS signing request.
type CMSSignRequest struct {
	// Data is the data to sign.
	Data BinaryData `json:"data"`

	// Detached creates a detached signature (no encapsulated content).
	Detached bool `json:"detached,omitempty"`

	// IncludeChain includes the certificate chain in the signature.
	IncludeChain bool `json:"include_chain,omitempty"`

	// Passphrase is the signer key passphrase.
	Passphrase string `json:"passphrase,omitempty"`

	// SignerID identifies the signing credential.
	SignerID string `json:"signer_id,omitempty"`
}

// CMSSignResponse represents the result of CMS signing.
type CMSSignResponse struct {
	// Signature is the CMS SignedData structure.
	Signature BinaryData `json:"signature"`

	// Algorithm is the signature algorithm used.
	Algorithm AlgorithmInfo `json:"algorithm"`

	// SignerInfo contains signer certificate details.
	SignerInfo *CertChainItem `json:"signer_info,omitempty"`
}

// CMSVerifyRequest represents a CMS verification request.
type CMSVerifyRequest struct {
	// Signature is the CMS SignedData to verify.
	Signature BinaryData `json:"signature"`

	// Data is the original data (required for detached signatures).
	Data *BinaryData `json:"data,omitempty"`

	// TrustAnchors are additional trust anchors.
	TrustAnchors []BinaryData `json:"trust_anchors,omitempty"`

	// CheckRevocation enables revocation checking.
	CheckRevocation bool `json:"check_revocation,omitempty"`
}

// CMSVerifyResponse represents the result of CMS verification.
type CMSVerifyResponse struct {
	// Valid indicates if the signature is valid.
	Valid bool `json:"valid"`

	// Errors lists verification errors.
	Errors []string `json:"errors,omitempty"`

	// Signers lists verified signers.
	Signers []CMSSignerInfo `json:"signers,omitempty"`

	// Content is the extracted content (if encapsulated).
	Content *BinaryData `json:"content,omitempty"`
}

// CMSSignerInfo contains information about a CMS signer.
type CMSSignerInfo struct {
	// Subject is the signer certificate subject.
	Subject string `json:"subject"`

	// Issuer is the signer certificate issuer.
	Issuer string `json:"issuer"`

	// Serial is the signer certificate serial.
	Serial string `json:"serial"`

	// Algorithm is the signature algorithm.
	Algorithm string `json:"algorithm"`

	// SignedAt is the signing timestamp (if available).
	SignedAt string `json:"signed_at,omitempty"`
}

// CMSEncryptRequest represents a CMS encryption request.
type CMSEncryptRequest struct {
	// Data is the data to encrypt.
	Data BinaryData `json:"data"`

	// Recipients are the recipient certificates.
	Recipients []BinaryData `json:"recipients"`

	// Algorithm is the content encryption algorithm.
	Algorithm string `json:"algorithm,omitempty"`
}

// CMSEncryptResponse represents the result of CMS encryption.
type CMSEncryptResponse struct {
	// EncryptedData is the CMS EnvelopedData structure.
	EncryptedData BinaryData `json:"encrypted_data"`

	// Algorithm is the encryption algorithm used.
	Algorithm string `json:"algorithm"`

	// RecipientCount is the number of recipients.
	RecipientCount int `json:"recipient_count"`
}

// CMSDecryptRequest represents a CMS decryption request.
type CMSDecryptRequest struct {
	// EncryptedData is the CMS EnvelopedData to decrypt.
	EncryptedData BinaryData `json:"encrypted_data"`

	// RecipientID identifies the recipient credential.
	RecipientID string `json:"recipient_id,omitempty"`

	// Passphrase is the recipient key passphrase.
	Passphrase string `json:"passphrase,omitempty"`
}

// CMSDecryptResponse represents the result of CMS decryption.
type CMSDecryptResponse struct {
	// Data is the decrypted content.
	Data BinaryData `json:"data"`

	// ContentType is the content type OID.
	ContentType string `json:"content_type,omitempty"`
}

// CMSInfoRequest represents a CMS info request.
type CMSInfoRequest struct {
	// Data is the CMS structure to analyze.
	Data BinaryData `json:"data"`
}

// CMSInfoResponse represents CMS structure information.
type CMSInfoResponse struct {
	// Type is the CMS content type.
	Type string `json:"type"`

	// Version is the CMS version.
	Version int `json:"version"`

	// Signers lists signer information (for SignedData).
	Signers []CMSSignerInfo `json:"signers,omitempty"`

	// Recipients lists recipient information (for EnvelopedData).
	Recipients []CMSRecipientInfo `json:"recipients,omitempty"`

	// HasEncapsulatedContent indicates if content is embedded.
	HasEncapsulatedContent bool `json:"has_encapsulated_content,omitempty"`

	// ContentType is the encapsulated content type.
	ContentType string `json:"content_type,omitempty"`
}

// CMSRecipientInfo contains information about a CMS recipient.
type CMSRecipientInfo struct {
	// Type is the recipient type (e.g., "keyTransport", "keyAgreement").
	Type string `json:"type"`

	// Issuer is the recipient certificate issuer.
	Issuer string `json:"issuer,omitempty"`

	// Serial is the recipient certificate serial.
	Serial string `json:"serial,omitempty"`

	// Algorithm is the key encryption algorithm.
	Algorithm string `json:"algorithm"`
}
