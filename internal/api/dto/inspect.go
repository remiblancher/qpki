package dto

// InspectRequest represents an auto-detect inspection request.
type InspectRequest struct {
	// Data is the data to inspect.
	Data BinaryData `json:"data"`
}

// InspectResponse represents inspection results.
type InspectResponse struct {
	// Type is the detected type.
	Type string `json:"type"`

	// Format is the detected format (PEM, DER, etc.).
	Format string `json:"format"`

	// Details contains type-specific information.
	Details interface{} `json:"details,omitempty"`

	// Errors lists any detection errors.
	Errors []string `json:"errors,omitempty"`
}

// InspectType constants for detected types.
const (
	InspectTypeCertificate = "certificate"
	InspectTypeCSR         = "csr"
	InspectTypeCRL         = "crl"
	InspectTypePrivateKey  = "private_key"
	InspectTypePublicKey   = "public_key"
	InspectTypeCMS         = "cms"
	InspectTypeCOSE        = "cose"
	InspectTypeTSAToken    = "tsa_token"
	InspectTypeOCSP        = "ocsp"
	InspectTypeUnknown     = "unknown"
)
