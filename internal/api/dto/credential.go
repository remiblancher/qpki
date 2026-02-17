package dto

// CredentialEnrollRequest represents a credential enrollment request.
type CredentialEnrollRequest struct {
	// Profile is the certificate profile name.
	Profile string `json:"profile"`

	// Variables are template variables.
	Variables map[string]string `json:"variables,omitempty"`

	// CSR is an optional CSR (if not provided, keys are generated).
	CSR *BinaryData `json:"csr,omitempty"`

	// Passphrase protects the private key.
	Passphrase string `json:"passphrase,omitempty"`

	// CAPassphrase is the CA key passphrase.
	CAPassphrase string `json:"ca_passphrase,omitempty"`

	// ValidityDays overrides the profile's validity.
	ValidityDays int `json:"validity_days,omitempty"`
}

// CredentialEnrollResponse represents the result of enrollment.
type CredentialEnrollResponse struct {
	// ID is the credential identifier.
	ID string `json:"id"`

	// Certificate is the issued certificate.
	Certificate BinaryData `json:"certificate"`

	// Chain is the certificate chain.
	Chain []BinaryData `json:"chain,omitempty"`

	// PrivateKey is the private key (if generated).
	PrivateKey *BinaryData `json:"private_key,omitempty"`

	// Subject is the certificate subject.
	Subject SubjectInfo `json:"subject"`

	// Validity is the certificate validity.
	Validity ValidityInfo `json:"validity"`

	// Algorithm is the key algorithm.
	Algorithm AlgorithmInfo `json:"algorithm"`
}

// CredentialInfoResponse represents credential information.
type CredentialInfoResponse struct {
	// ID is the credential identifier.
	ID string `json:"id"`

	// Subject is the certificate subject.
	Subject SubjectInfo `json:"subject"`

	// Issuer is the certificate issuer.
	Issuer SubjectInfo `json:"issuer"`

	// Serial is the certificate serial.
	Serial string `json:"serial"`

	// Validity is the certificate validity.
	Validity ValidityInfo `json:"validity"`

	// Algorithm is the key algorithm.
	Algorithm AlgorithmInfo `json:"algorithm"`

	// Status is "valid", "revoked", or "expired".
	Status string `json:"status"`

	// KeyUsage lists key usage flags.
	KeyUsage []string `json:"key_usage,omitempty"`

	// ExtKeyUsage lists extended key usage OIDs.
	ExtKeyUsage []string `json:"ext_key_usage,omitempty"`

	// Certificate is the PEM-encoded certificate.
	Certificate string `json:"certificate,omitempty"`
}

// CredentialListResponse represents a list of credentials.
type CredentialListResponse struct {
	// Credentials is the list of credential summaries.
	Credentials []CredentialListItem `json:"credentials"`

	// Pagination contains pagination information.
	Pagination PaginationResponse `json:"pagination"`
}

// CredentialListItem represents a credential in a list.
type CredentialListItem struct {
	// ID is the credential identifier.
	ID string `json:"id"`

	// Subject is the certificate subject CN.
	Subject string `json:"subject"`

	// Status is "valid", "revoked", or "expired".
	Status string `json:"status"`

	// ExpiresAt is the expiration timestamp.
	ExpiresAt string `json:"expires_at"`

	// Algorithm is the algorithm ID.
	Algorithm string `json:"algorithm"`
}

// CredentialRotateRequest represents a credential rotation request.
type CredentialRotateRequest struct {
	// Passphrase is the current key passphrase.
	Passphrase string `json:"passphrase,omitempty"`

	// NewPassphrase is the new key passphrase.
	NewPassphrase string `json:"new_passphrase,omitempty"`

	// CAPassphrase is the CA key passphrase.
	CAPassphrase string `json:"ca_passphrase,omitempty"`
}

// CredentialRotateResponse represents the result of rotation.
type CredentialRotateResponse struct {
	// ID is the credential identifier.
	ID string `json:"id"`

	// Certificate is the new certificate.
	Certificate BinaryData `json:"certificate"`

	// PrivateKey is the new private key.
	PrivateKey *BinaryData `json:"private_key,omitempty"`

	// OldSerial is the old certificate serial.
	OldSerial string `json:"old_serial"`

	// NewSerial is the new certificate serial.
	NewSerial string `json:"new_serial"`
}

// CredentialRevokeRequest represents a credential revocation request.
type CredentialRevokeRequest struct {
	// Reason is the revocation reason.
	Reason string `json:"reason,omitempty"`

	// CAPassphrase is the CA key passphrase.
	CAPassphrase string `json:"ca_passphrase,omitempty"`
}

// CredentialRevokeResponse represents the result of revocation.
type CredentialRevokeResponse struct {
	// ID is the credential identifier.
	ID string `json:"id"`

	// RevokedAt is the revocation timestamp.
	RevokedAt string `json:"revoked_at"`

	// Reason is the revocation reason.
	Reason string `json:"reason"`
}

// CredentialExportRequest represents a credential export request.
type CredentialExportRequest struct {
	// Format is the export format: "pem", "pkcs12", "jks".
	Format string `json:"format,omitempty"`

	// Passphrase is the key passphrase.
	Passphrase string `json:"passphrase,omitempty"`

	// ExportPassphrase is the PKCS#12/JKS password.
	ExportPassphrase string `json:"export_passphrase,omitempty"`

	// IncludeChain includes the certificate chain.
	IncludeChain bool `json:"include_chain,omitempty"`
}

// CredentialExportResponse represents the exported credential.
type CredentialExportResponse struct {
	// Data is the exported credential data.
	Data BinaryData `json:"data"`

	// Format is the export format used.
	Format string `json:"format"`

	// Filename is a suggested filename.
	Filename string `json:"filename,omitempty"`
}
