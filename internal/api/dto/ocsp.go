package dto

// OCSPQueryRequest represents an OCSP query request.
type OCSPQueryRequest struct {
	// Serial is the certificate serial number to check.
	Serial string `json:"serial,omitempty"`

	// Certificate is the certificate to check.
	Certificate *BinaryData `json:"certificate,omitempty"`

	// IssuerCert is the issuer certificate (for hash calculation).
	IssuerCert *BinaryData `json:"issuer_cert,omitempty"`

	// Nonce adds a nonce for replay protection.
	Nonce bool `json:"nonce,omitempty"`

	// Passphrase is the OCSP responder key passphrase.
	Passphrase string `json:"passphrase,omitempty"`
}

// OCSPQueryResponse represents the OCSP query result.
type OCSPQueryResponse struct {
	// Response is the OCSP response.
	Response BinaryData `json:"response"`

	// Status is the certificate status.
	Status OCSPStatus `json:"status"`

	// ProducedAt is when the response was produced.
	ProducedAt string `json:"produced_at"`

	// ThisUpdate is the response validity start.
	ThisUpdate string `json:"this_update"`

	// NextUpdate is the response validity end.
	NextUpdate string `json:"next_update,omitempty"`
}

// OCSPStatus represents certificate status from OCSP.
type OCSPStatus struct {
	// Status is "good", "revoked", or "unknown".
	Status string `json:"status"`

	// RevokedAt is present if status is "revoked".
	RevokedAt string `json:"revoked_at,omitempty"`

	// RevocationReason is present if status is "revoked".
	RevocationReason string `json:"revocation_reason,omitempty"`
}

// OCSPVerifyRequest represents an OCSP response verification request.
type OCSPVerifyRequest struct {
	// Response is the OCSP response to verify.
	Response BinaryData `json:"response"`

	// Certificate is the certificate that was checked.
	Certificate *BinaryData `json:"certificate,omitempty"`

	// IssuerCert is the issuer certificate.
	IssuerCert *BinaryData `json:"issuer_cert,omitempty"`

	// TrustAnchors are additional trust anchors.
	TrustAnchors []BinaryData `json:"trust_anchors,omitempty"`
}

// OCSPVerifyResponse represents the result of OCSP verification.
type OCSPVerifyResponse struct {
	// Valid indicates if the OCSP response is valid.
	Valid bool `json:"valid"`

	// Errors lists verification errors.
	Errors []string `json:"errors,omitempty"`

	// Status contains the certificate status.
	Status *OCSPStatus `json:"status,omitempty"`

	// ResponderInfo contains responder details.
	ResponderInfo *OCSPResponderInfo `json:"responder_info,omitempty"`
}

// OCSPResponderInfo contains OCSP responder information.
type OCSPResponderInfo struct {
	// Name is the responder name.
	Name string `json:"name,omitempty"`

	// KeyHash is the responder key hash.
	KeyHash string `json:"key_hash,omitempty"`

	// Certificate is the responder certificate info.
	Certificate *CertChainItem `json:"certificate,omitempty"`
}
