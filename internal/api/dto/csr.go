package dto

// CSRGenerateRequest represents a CSR generation request.
type CSRGenerateRequest struct {
	// Profile is the certificate profile name.
	Profile string `json:"profile,omitempty"`

	// Algorithm is the key algorithm.
	Algorithm string `json:"algorithm,omitempty"`

	// Subject is the CSR subject.
	Subject SubjectInfo `json:"subject"`

	// DNSNames are DNS SANs.
	DNSNames []string `json:"dns_names,omitempty"`

	// IPAddresses are IP SANs.
	IPAddresses []string `json:"ip_addresses,omitempty"`

	// EmailAddresses are email SANs.
	EmailAddresses []string `json:"email_addresses,omitempty"`

	// URIs are URI SANs.
	URIs []string `json:"uris,omitempty"`

	// Passphrase protects the generated private key.
	Passphrase string `json:"passphrase,omitempty"`
}

// CSRGenerateResponse represents the result of CSR generation.
type CSRGenerateResponse struct {
	// CSR is the generated CSR.
	CSR BinaryData `json:"csr"`

	// PrivateKey is the generated private key.
	PrivateKey BinaryData `json:"private_key"`

	// Algorithm is the key algorithm.
	Algorithm AlgorithmInfo `json:"algorithm"`

	// Subject is the CSR subject.
	Subject SubjectInfo `json:"subject"`
}

// CSRInfoRequest represents a CSR info request.
type CSRInfoRequest struct {
	// CSR is the CSR to analyze.
	CSR BinaryData `json:"csr"`
}

// CSRInfoResponse represents CSR information.
type CSRInfoResponse struct {
	// Subject is the CSR subject.
	Subject SubjectInfo `json:"subject"`

	// Algorithm is the public key algorithm.
	Algorithm AlgorithmInfo `json:"algorithm"`

	// SignatureAlgorithm is the signature algorithm.
	SignatureAlgorithm string `json:"signature_algorithm"`

	// PublicKeyInfo describes the public key.
	PublicKeyInfo PublicKeyInfo `json:"public_key"`

	// SANs are Subject Alternative Names.
	SANs *SANInfo `json:"sans,omitempty"`

	// Attributes are CSR attributes.
	Attributes map[string]string `json:"attributes,omitempty"`
}

// PublicKeyInfo describes a public key.
type PublicKeyInfo struct {
	// Algorithm is the key algorithm.
	Algorithm string `json:"algorithm"`

	// Size is the key size in bits.
	Size int `json:"size,omitempty"`

	// Curve is the EC curve name.
	Curve string `json:"curve,omitempty"`
}

// CSRVerifyRequest represents a CSR verification request.
type CSRVerifyRequest struct {
	// CSR is the CSR to verify.
	CSR BinaryData `json:"csr"`
}

// CSRVerifyResponse represents the result of CSR verification.
type CSRVerifyResponse struct {
	// Valid indicates if the CSR signature is valid.
	Valid bool `json:"valid"`

	// Errors lists verification errors.
	Errors []string `json:"errors,omitempty"`

	// Info contains CSR information.
	Info *CSRInfoResponse `json:"info,omitempty"`
}
