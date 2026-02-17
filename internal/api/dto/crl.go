package dto

// CRLGenerateRequest represents a CRL generation request.
type CRLGenerateRequest struct {
	// Profile is the CRL profile name.
	Profile string `json:"profile,omitempty"`

	// ValidityDays is the CRL validity in days.
	ValidityDays int `json:"validity_days,omitempty"`

	// Passphrase is the CA key passphrase.
	Passphrase string `json:"passphrase,omitempty"`

	// Delta generates a delta CRL.
	Delta bool `json:"delta,omitempty"`
}

// CRLGenerateResponse represents the result of CRL generation.
type CRLGenerateResponse struct {
	// CRL is the generated CRL.
	CRL BinaryData `json:"crl"`

	// Number is the CRL number.
	Number string `json:"number"`

	// ThisUpdate is the CRL issue time.
	ThisUpdate string `json:"this_update"`

	// NextUpdate is the next CRL issue time.
	NextUpdate string `json:"next_update"`

	// RevokedCount is the number of revoked certificates.
	RevokedCount int `json:"revoked_count"`

	// IsDelta indicates if this is a delta CRL.
	IsDelta bool `json:"is_delta"`
}

// CRLListResponse represents a list of CRLs.
type CRLListResponse struct {
	// CRLs is the list of CRL summaries.
	CRLs []CRLListItem `json:"crls"`

	// Pagination contains pagination information.
	Pagination PaginationResponse `json:"pagination"`
}

// CRLListItem represents a CRL in a list.
type CRLListItem struct {
	// ID is the CRL identifier.
	ID string `json:"id"`

	// Number is the CRL number.
	Number string `json:"number"`

	// ThisUpdate is the CRL issue time.
	ThisUpdate string `json:"this_update"`

	// NextUpdate is the next CRL issue time.
	NextUpdate string `json:"next_update"`

	// RevokedCount is the number of revoked certificates.
	RevokedCount int `json:"revoked_count"`

	// IsDelta indicates if this is a delta CRL.
	IsDelta bool `json:"is_delta"`
}

// CRLInfoResponse represents detailed CRL information.
type CRLInfoResponse struct {
	// Number is the CRL number.
	Number string `json:"number"`

	// Issuer is the CRL issuer.
	Issuer SubjectInfo `json:"issuer"`

	// ThisUpdate is the CRL issue time.
	ThisUpdate string `json:"this_update"`

	// NextUpdate is the next CRL issue time.
	NextUpdate string `json:"next_update"`

	// Algorithm is the signature algorithm.
	Algorithm AlgorithmInfo `json:"algorithm"`

	// RevokedCertificates lists revoked certificates.
	RevokedCertificates []CRLEntry `json:"revoked_certificates,omitempty"`

	// IsDelta indicates if this is a delta CRL.
	IsDelta bool `json:"is_delta"`

	// DeltaCRLIndicator is present for delta CRLs.
	DeltaCRLIndicator string `json:"delta_crl_indicator,omitempty"`
}

// CRLEntry represents a revoked certificate in a CRL.
type CRLEntry struct {
	// Serial is the certificate serial number.
	Serial string `json:"serial"`

	// RevokedAt is the revocation time.
	RevokedAt string `json:"revoked_at"`

	// Reason is the revocation reason.
	Reason string `json:"reason,omitempty"`
}

// CRLVerifyRequest represents a CRL verification request.
type CRLVerifyRequest struct {
	// CRL is the CRL to verify.
	CRL BinaryData `json:"crl"`

	// IssuerCert is the issuer certificate.
	IssuerCert *BinaryData `json:"issuer_cert,omitempty"`

	// TrustAnchors are additional trust anchors.
	TrustAnchors []BinaryData `json:"trust_anchors,omitempty"`
}

// CRLVerifyResponse represents the result of CRL verification.
type CRLVerifyResponse struct {
	// Valid indicates if the CRL is valid.
	Valid bool `json:"valid"`

	// Errors lists verification errors.
	Errors []string `json:"errors,omitempty"`

	// Info contains CRL information.
	Info *CRLInfoResponse `json:"info,omitempty"`
}
