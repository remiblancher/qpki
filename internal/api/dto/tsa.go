package dto

// TSASignRequest represents a timestamp signing request.
type TSASignRequest struct {
	// Data is the data to timestamp (will be hashed).
	Data *BinaryData `json:"data,omitempty"`

	// Hash is a pre-computed hash to timestamp.
	Hash *BinaryData `json:"hash,omitempty"`

	// HashAlgorithm is the hash algorithm (required with Hash).
	HashAlgorithm string `json:"hash_algorithm,omitempty"`

	// Policy is the TSA policy OID.
	Policy string `json:"policy,omitempty"`

	// Nonce is an optional nonce for replay protection.
	Nonce string `json:"nonce,omitempty"`

	// CertReq requests the TSA certificate in the response.
	CertReq bool `json:"cert_req,omitempty"`

	// Passphrase is the TSA key passphrase.
	Passphrase string `json:"passphrase,omitempty"`
}

// TSASignResponse represents the result of timestamp signing.
type TSASignResponse struct {
	// Token is the RFC 3161 timestamp token.
	Token BinaryData `json:"token"`

	// Time is the timestamp time.
	Time string `json:"time"`

	// Serial is the timestamp serial number.
	Serial string `json:"serial"`

	// Algorithm is the signature algorithm.
	Algorithm AlgorithmInfo `json:"algorithm"`

	// Policy is the TSA policy OID.
	Policy string `json:"policy,omitempty"`
}

// TSAVerifyRequest represents a timestamp verification request.
type TSAVerifyRequest struct {
	// Token is the timestamp token to verify.
	Token BinaryData `json:"token"`

	// Data is the original data (for hash verification).
	Data *BinaryData `json:"data,omitempty"`

	// Hash is the original hash (alternative to Data).
	Hash *BinaryData `json:"hash,omitempty"`

	// TrustAnchors are TSA certificates to trust.
	TrustAnchors []BinaryData `json:"trust_anchors,omitempty"`
}

// TSAVerifyResponse represents the result of timestamp verification.
type TSAVerifyResponse struct {
	// Valid indicates if the timestamp is valid.
	Valid bool `json:"valid"`

	// Errors lists verification errors.
	Errors []string `json:"errors,omitempty"`

	// Info contains timestamp information.
	Info *TSAInfo `json:"info,omitempty"`
}

// TSAInfo contains timestamp information.
type TSAInfo struct {
	// Time is the timestamp time.
	Time string `json:"time"`

	// Serial is the timestamp serial number.
	Serial string `json:"serial"`

	// Policy is the TSA policy OID.
	Policy string `json:"policy"`

	// HashAlgorithm is the hash algorithm used.
	HashAlgorithm string `json:"hash_algorithm"`

	// Hash is the timestamped hash (hex).
	Hash string `json:"hash"`

	// Nonce is the nonce (if present).
	Nonce string `json:"nonce,omitempty"`

	// TSACertificate contains TSA certificate info.
	TSACertificate *CertChainItem `json:"tsa_certificate,omitempty"`

	// Ordering indicates if ordering is guaranteed.
	Ordering bool `json:"ordering"`
}

// TSAInfoRequest represents a timestamp info request.
type TSAInfoRequest struct {
	// Token is the timestamp token to analyze.
	Token BinaryData `json:"token"`
}

// TSAInfoResponse is an alias for TSAInfo.
type TSAInfoResponse = TSAInfo
