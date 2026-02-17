package dto

// CAInitRequest represents a CA initialization request.
type CAInitRequest struct {
	// Profile is the CA profile name (required).
	Profile string `json:"profile"`

	// Profiles allows specifying multiple profiles for multi-algorithm CAs.
	Profiles []string `json:"profiles,omitempty"`

	// Variables are template variables for the certificate.
	Variables map[string]string `json:"variables"`

	// ValidityYears overrides the profile's default validity period.
	ValidityYears int `json:"validity_years,omitempty"`

	// PathLen sets the maximum path length constraint.
	PathLen int `json:"path_len,omitempty"`

	// Passphrase protects the private key (optional).
	Passphrase string `json:"passphrase,omitempty"`

	// ParentCA is the path to the parent CA for subordinate CAs.
	ParentCA string `json:"parent_ca,omitempty"`

	// ParentPassphrase is the parent CA's key passphrase.
	ParentPassphrase string `json:"parent_passphrase,omitempty"`

	// HSM configuration (optional).
	HSMConfig    string `json:"hsm_config,omitempty"`
	KeyLabel     string `json:"key_label,omitempty"`
	KeyID        string `json:"key_id,omitempty"`
	UseExistingKey bool `json:"use_existing_key,omitempty"`
}

// CAInitResponse represents the result of CA initialization.
type CAInitResponse struct {
	// ID is the CA identifier (directory name).
	ID string `json:"id"`

	// Subject is the CA certificate subject.
	Subject SubjectInfo `json:"subject"`

	// Algorithm describes the signing algorithm.
	Algorithm AlgorithmInfo `json:"algorithm"`

	// HybridAlgorithm is present for hybrid/composite CAs.
	HybridAlgorithm *AlgorithmInfo `json:"hybrid_algorithm,omitempty"`

	// Validity is the certificate validity period.
	Validity ValidityInfo `json:"validity"`

	// Serial is the certificate serial number (hex).
	Serial string `json:"serial"`

	// Fingerprint is the SHA-256 fingerprint.
	Fingerprint string `json:"fingerprint"`

	// Certificate is the PEM-encoded CA certificate.
	Certificate string `json:"certificate"`

	// CADir is the path to the CA directory.
	CADir string `json:"ca_dir"`
}

// CAInfoResponse represents CA information.
type CAInfoResponse struct {
	// ID is the CA identifier.
	ID string `json:"id"`

	// Subject is the CA certificate subject.
	Subject SubjectInfo `json:"subject"`

	// Issuer is the certificate issuer (same as Subject for root CAs).
	Issuer SubjectInfo `json:"issuer"`

	// Algorithm describes the signing algorithm.
	Algorithm AlgorithmInfo `json:"algorithm"`

	// HybridAlgorithm is present for hybrid/composite CAs.
	HybridAlgorithm *AlgorithmInfo `json:"hybrid_algorithm,omitempty"`

	// Validity is the certificate validity period.
	Validity ValidityInfo `json:"validity"`

	// Serial is the certificate serial number (hex).
	Serial string `json:"serial"`

	// Fingerprint is the SHA-256 fingerprint.
	Fingerprint string `json:"fingerprint"`

	// IsRoot indicates if this is a root CA (self-signed).
	IsRoot bool `json:"is_root"`

	// PathLen is the maximum path length constraint (-1 for unlimited).
	PathLen int `json:"path_len"`

	// Versions lists available CA versions (for multi-version CAs).
	Versions []CAVersionInfo `json:"versions,omitempty"`

	// ActiveVersion is the currently active version ID.
	ActiveVersion string `json:"active_version,omitempty"`

	// Certificate is the PEM-encoded CA certificate.
	Certificate string `json:"certificate,omitempty"`
}

// CAVersionInfo represents a CA version.
type CAVersionInfo struct {
	// ID is the version identifier.
	ID string `json:"id"`

	// Algorithms lists the algorithms in this version.
	Algorithms []string `json:"algorithms"`

	// Profiles lists the profiles used for this version.
	Profiles []string `json:"profiles,omitempty"`

	// CreatedAt is the version creation timestamp.
	CreatedAt string `json:"created_at"`

	// Active indicates if this is the active version.
	Active bool `json:"active"`
}

// CAListResponse represents a list of CAs.
type CAListResponse struct {
	// CAs is the list of CA summaries.
	CAs []CAListItem `json:"cas"`

	// Pagination contains pagination information.
	Pagination PaginationResponse `json:"pagination"`
}

// CAListItem represents a CA in a list.
type CAListItem struct {
	// ID is the CA identifier.
	ID string `json:"id"`

	// Subject is the CA common name.
	Subject string `json:"subject"`

	// Type is "root" or "subordinate".
	Type string `json:"type"`

	// Algorithm is the primary algorithm ID.
	Algorithm string `json:"algorithm"`

	// ExpiresAt is the expiration timestamp.
	ExpiresAt string `json:"expires_at"`

	// IsHybrid indicates if this is a hybrid CA.
	IsHybrid bool `json:"is_hybrid,omitempty"`
}

// CARotateRequest represents a CA key rotation request.
type CARotateRequest struct {
	// Passphrase is the current key passphrase.
	Passphrase string `json:"passphrase,omitempty"`

	// NewPassphrase is the new key passphrase.
	NewPassphrase string `json:"new_passphrase,omitempty"`

	// CrossSign requests cross-signing with the old key.
	CrossSign bool `json:"cross_sign,omitempty"`
}

// CARotateResponse represents the result of CA rotation.
type CARotateResponse struct {
	// NewVersion is the new version identifier.
	NewVersion string `json:"new_version"`

	// OldVersion is the previous version identifier.
	OldVersion string `json:"old_version"`

	// Certificate is the new PEM-encoded CA certificate.
	Certificate string `json:"certificate"`

	// CrossSignCertificate is the cross-signed certificate (if requested).
	CrossSignCertificate string `json:"cross_sign_certificate,omitempty"`
}

// CAActivateRequest represents a CA version activation request.
type CAActivateRequest struct {
	// Version is the version ID to activate.
	Version string `json:"version"`
}

// CAActivateResponse represents the result of CA activation.
type CAActivateResponse struct {
	// ActiveVersion is the now-active version ID.
	ActiveVersion string `json:"active_version"`

	// PreviousVersion is the previously active version ID.
	PreviousVersion string `json:"previous_version"`
}

// CAExportRequest represents a CA export request.
type CAExportRequest struct {
	// Bundle is the bundle type: "ca", "chain", or "root".
	Bundle string `json:"bundle,omitempty"`

	// Format is the output format: "pem" or "der".
	Format string `json:"format,omitempty"`

	// Version is the specific version to export.
	Version string `json:"version,omitempty"`
}

// CAExportResponse represents a CA export response.
type CAExportResponse struct {
	// Certificates is the list of PEM or base64-encoded certificates.
	Certificates []BinaryData `json:"certificates"`

	// Bundle indicates what was exported.
	Bundle string `json:"bundle"`
}
