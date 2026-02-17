package dto

// COSESignRequest represents a COSE signing request.
type COSESignRequest struct {
	// Payload is the data to sign.
	Payload BinaryData `json:"payload"`

	// Detached creates a detached signature.
	Detached bool `json:"detached,omitempty"`

	// Protected are protected header parameters.
	Protected map[string]interface{} `json:"protected,omitempty"`

	// Unprotected are unprotected header parameters.
	Unprotected map[string]interface{} `json:"unprotected,omitempty"`

	// SignerID identifies the signing credential.
	SignerID string `json:"signer_id,omitempty"`

	// Passphrase is the signer key passphrase.
	Passphrase string `json:"passphrase,omitempty"`

	// MultiSign creates COSE_Sign (multiple signers) instead of COSE_Sign1.
	MultiSign bool `json:"multi_sign,omitempty"`
}

// COSESignResponse represents the result of COSE signing.
type COSESignResponse struct {
	// Signature is the COSE_Sign1 or COSE_Sign structure.
	Signature BinaryData `json:"signature"`

	// Algorithm is the signature algorithm used.
	Algorithm AlgorithmInfo `json:"algorithm"`

	// Type is "COSE_Sign1" or "COSE_Sign".
	Type string `json:"type"`
}

// COSEVerifyRequest represents a COSE verification request.
type COSEVerifyRequest struct {
	// Signature is the COSE structure to verify.
	Signature BinaryData `json:"signature"`

	// Payload is the detached payload (if applicable).
	Payload *BinaryData `json:"payload,omitempty"`

	// TrustAnchors are certificates to trust.
	TrustAnchors []BinaryData `json:"trust_anchors,omitempty"`
}

// COSEVerifyResponse represents the result of COSE verification.
type COSEVerifyResponse struct {
	// Valid indicates if the signature is valid.
	Valid bool `json:"valid"`

	// Errors lists verification errors.
	Errors []string `json:"errors,omitempty"`

	// Payload is the verified payload.
	Payload *BinaryData `json:"payload,omitempty"`

	// Protected are the protected headers.
	Protected map[string]interface{} `json:"protected,omitempty"`

	// SignerInfo contains signer details.
	SignerInfo *COSESignerInfo `json:"signer_info,omitempty"`
}

// COSESignerInfo contains COSE signer information.
type COSESignerInfo struct {
	// Algorithm is the COSE algorithm ID.
	Algorithm int `json:"algorithm"`

	// AlgorithmName is the algorithm name.
	AlgorithmName string `json:"algorithm_name"`

	// KeyID is the key identifier.
	KeyID string `json:"key_id,omitempty"`

	// Certificate is the signer certificate (if embedded).
	Certificate *BinaryData `json:"certificate,omitempty"`
}

// COSEInfoRequest represents a COSE info request.
type COSEInfoRequest struct {
	// Data is the COSE structure to analyze.
	Data BinaryData `json:"data"`
}

// COSEInfoResponse represents COSE structure information.
type COSEInfoResponse struct {
	// Type is the COSE message type.
	Type string `json:"type"`

	// Protected are protected headers.
	Protected map[string]interface{} `json:"protected,omitempty"`

	// Unprotected are unprotected headers.
	Unprotected map[string]interface{} `json:"unprotected,omitempty"`

	// PayloadSize is the payload size in bytes.
	PayloadSize int `json:"payload_size,omitempty"`

	// HasPayload indicates if payload is embedded.
	HasPayload bool `json:"has_payload"`

	// Signers lists signer information.
	Signers []COSESignerInfo `json:"signers,omitempty"`
}

// CWTIssueRequest represents a CWT (CBOR Web Token) issuance request.
type CWTIssueRequest struct {
	// Claims are the CWT claims.
	Claims CWTClaims `json:"claims"`

	// SignerID identifies the signing credential.
	SignerID string `json:"signer_id,omitempty"`

	// Passphrase is the signer key passphrase.
	Passphrase string `json:"passphrase,omitempty"`
}

// CWTClaims represents standard CWT claims.
type CWTClaims struct {
	// Issuer (iss) claim.
	Issuer string `json:"iss,omitempty"`

	// Subject (sub) claim.
	Subject string `json:"sub,omitempty"`

	// Audience (aud) claim.
	Audience string `json:"aud,omitempty"`

	// ExpirationTime (exp) claim - Unix timestamp.
	ExpirationTime int64 `json:"exp,omitempty"`

	// NotBefore (nbf) claim - Unix timestamp.
	NotBefore int64 `json:"nbf,omitempty"`

	// IssuedAt (iat) claim - Unix timestamp.
	IssuedAt int64 `json:"iat,omitempty"`

	// CWTID (cti) claim.
	CWTID string `json:"cti,omitempty"`

	// Custom claims.
	Custom map[string]interface{} `json:"custom,omitempty"`
}

// CWTIssueResponse represents the result of CWT issuance.
type CWTIssueResponse struct {
	// Token is the signed CWT.
	Token BinaryData `json:"token"`

	// Algorithm is the signature algorithm.
	Algorithm AlgorithmInfo `json:"algorithm"`
}

// CWTVerifyRequest represents a CWT verification request.
type CWTVerifyRequest struct {
	// Token is the CWT to verify.
	Token BinaryData `json:"token"`

	// TrustAnchors are certificates to trust.
	TrustAnchors []BinaryData `json:"trust_anchors,omitempty"`

	// RequiredClaims are claims that must be present.
	RequiredClaims []string `json:"required_claims,omitempty"`
}

// CWTVerifyResponse represents the result of CWT verification.
type CWTVerifyResponse struct {
	// Valid indicates if the token is valid.
	Valid bool `json:"valid"`

	// Errors lists verification errors.
	Errors []string `json:"errors,omitempty"`

	// Claims are the verified claims.
	Claims *CWTClaims `json:"claims,omitempty"`

	// SignerInfo contains signer details.
	SignerInfo *COSESignerInfo `json:"signer_info,omitempty"`
}
