package dto

// CertIssueRequest represents a certificate issuance request.
type CertIssueRequest struct {
	// Profile is the certificate profile name (required).
	Profile string `json:"profile"`

	// CSR is the certificate signing request.
	CSR *BinaryData `json:"csr,omitempty"`

	// Variables are template variables for the certificate.
	Variables map[string]string `json:"variables,omitempty"`

	// ValidityDays overrides the profile's default validity period.
	ValidityDays int `json:"validity_days,omitempty"`

	// Passphrase is the CA key passphrase (if required).
	Passphrase string `json:"passphrase,omitempty"`
}

// CertIssueResponse represents the result of certificate issuance.
type CertIssueResponse struct {
	// Serial is the certificate serial number (hex).
	Serial string `json:"serial"`

	// Subject is the certificate subject.
	Subject SubjectInfo `json:"subject"`

	// Issuer is the certificate issuer.
	Issuer SubjectInfo `json:"issuer"`

	// Algorithm describes the signing algorithm.
	Algorithm AlgorithmInfo `json:"algorithm"`

	// Validity is the certificate validity period.
	Validity ValidityInfo `json:"validity"`

	// Fingerprint is the SHA-256 fingerprint.
	Fingerprint string `json:"fingerprint"`

	// Certificate is the PEM-encoded certificate.
	Certificate string `json:"certificate"`

	// Chain is the PEM-encoded certificate chain (optional).
	Chain string `json:"chain,omitempty"`
}

// CertInfoResponse represents certificate information.
type CertInfoResponse struct {
	// Serial is the certificate serial number (hex).
	Serial string `json:"serial"`

	// Subject is the certificate subject.
	Subject SubjectInfo `json:"subject"`

	// Issuer is the certificate issuer.
	Issuer SubjectInfo `json:"issuer"`

	// Algorithm describes the signing algorithm.
	Algorithm AlgorithmInfo `json:"algorithm"`

	// Validity is the certificate validity period.
	Validity ValidityInfo `json:"validity"`

	// Fingerprint is the SHA-256 fingerprint.
	Fingerprint string `json:"fingerprint"`

	// Status is "valid", "revoked", or "expired".
	Status string `json:"status"`

	// RevocationInfo is present if the certificate is revoked.
	RevocationInfo *RevocationInfo `json:"revocation,omitempty"`

	// KeyUsage lists the key usage flags.
	KeyUsage []string `json:"key_usage,omitempty"`

	// ExtKeyUsage lists the extended key usage OIDs.
	ExtKeyUsage []string `json:"ext_key_usage,omitempty"`

	// SANs lists the Subject Alternative Names.
	SANs *SANInfo `json:"sans,omitempty"`

	// Certificate is the PEM-encoded certificate.
	Certificate string `json:"certificate,omitempty"`
}

// RevocationInfo contains certificate revocation details.
type RevocationInfo struct {
	// RevokedAt is the revocation timestamp.
	RevokedAt string `json:"revoked_at"`

	// Reason is the revocation reason code.
	Reason string `json:"reason"`

	// ReasonCode is the numeric reason code (RFC 5280).
	ReasonCode int `json:"reason_code"`
}

// SANInfo contains Subject Alternative Names.
type SANInfo struct {
	// DNSNames lists DNS names.
	DNSNames []string `json:"dns_names,omitempty"`

	// EmailAddresses lists email addresses.
	EmailAddresses []string `json:"emails,omitempty"`

	// IPAddresses lists IP addresses.
	IPAddresses []string `json:"ips,omitempty"`

	// URIs lists URIs.
	URIs []string `json:"uris,omitempty"`
}

// CertListResponse represents a list of certificates.
type CertListResponse struct {
	// Certificates is the list of certificate summaries.
	Certificates []CertListItem `json:"certificates"`

	// Pagination contains pagination information.
	Pagination PaginationResponse `json:"pagination"`
}

// CertListItem represents a certificate in a list.
type CertListItem struct {
	// Serial is the certificate serial number (hex).
	Serial string `json:"serial"`

	// Subject is the certificate subject CN.
	Subject string `json:"subject"`

	// Status is "valid", "revoked", or "expired".
	Status string `json:"status"`

	// NotAfter is the expiration timestamp.
	NotAfter string `json:"not_after"`

	// Algorithm is the algorithm ID.
	Algorithm string `json:"algorithm"`
}

// CertRevokeRequest represents a certificate revocation request.
type CertRevokeRequest struct {
	// Reason is the revocation reason.
	// Valid values: "unspecified", "key_compromise", "ca_compromise",
	// "affiliation_changed", "superseded", "cessation_of_operation",
	// "certificate_hold", "remove_from_crl", "privilege_withdrawn", "aa_compromise".
	Reason string `json:"reason,omitempty"`

	// Passphrase is the CA key passphrase (if required).
	Passphrase string `json:"passphrase,omitempty"`
}

// CertRevokeResponse represents the result of certificate revocation.
type CertRevokeResponse struct {
	// Serial is the revoked certificate serial number.
	Serial string `json:"serial"`

	// RevokedAt is the revocation timestamp.
	RevokedAt string `json:"revoked_at"`

	// Reason is the revocation reason.
	Reason string `json:"reason"`

	// CRL is the updated CRL (if generated).
	CRL *BinaryData `json:"crl,omitempty"`
}

// CertVerifyRequest represents a certificate verification request.
type CertVerifyRequest struct {
	// Certificate is the certificate to verify.
	Certificate BinaryData `json:"certificate"`

	// Chain is an optional certificate chain.
	Chain []BinaryData `json:"chain,omitempty"`

	// TrustAnchors are additional trust anchors.
	TrustAnchors []BinaryData `json:"trust_anchors,omitempty"`

	// CheckRevocation enables OCSP/CRL checking.
	CheckRevocation bool `json:"check_revocation,omitempty"`

	// At is the verification time (RFC3339). Defaults to now.
	At string `json:"at,omitempty"`
}

// CertVerifyResponse represents the result of certificate verification.
type CertVerifyResponse struct {
	// Valid indicates if the certificate is valid.
	Valid bool `json:"valid"`

	// Errors lists validation errors.
	Errors []string `json:"errors,omitempty"`

	// Warnings lists validation warnings.
	Warnings []string `json:"warnings,omitempty"`

	// Chain is the verified certificate chain.
	Chain []CertChainItem `json:"chain,omitempty"`

	// RevocationStatus is the revocation status (if checked).
	RevocationStatus *RevocationStatus `json:"revocation_status,omitempty"`
}

// CertChainItem represents a certificate in a chain.
type CertChainItem struct {
	// Subject is the certificate subject.
	Subject string `json:"subject"`

	// Issuer is the certificate issuer.
	Issuer string `json:"issuer"`

	// Serial is the serial number.
	Serial string `json:"serial"`

	// NotAfter is the expiration timestamp.
	NotAfter string `json:"not_after"`
}

// RevocationStatus represents revocation check results.
type RevocationStatus struct {
	// Checked indicates if revocation was checked.
	Checked bool `json:"checked"`

	// Revoked indicates if any certificate is revoked.
	Revoked bool `json:"revoked"`

	// Method is "ocsp" or "crl".
	Method string `json:"method,omitempty"`

	// Details provides per-certificate status.
	Details []RevocationDetail `json:"details,omitempty"`
}

// RevocationDetail represents per-certificate revocation status.
type RevocationDetail struct {
	// Serial is the certificate serial.
	Serial string `json:"serial"`

	// Status is "good", "revoked", or "unknown".
	Status string `json:"status"`

	// RevokedAt is present if revoked.
	RevokedAt string `json:"revoked_at,omitempty"`

	// Reason is present if revoked.
	Reason string `json:"reason,omitempty"`
}
