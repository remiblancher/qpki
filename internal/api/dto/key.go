package dto

// KeyGenerateRequest represents a key generation request.
type KeyGenerateRequest struct {
	// Algorithm is the key algorithm.
	Algorithm string `json:"algorithm"`

	// Passphrase protects the private key.
	Passphrase string `json:"passphrase,omitempty"`

	// Label is a key label (for HSM keys).
	Label string `json:"label,omitempty"`
}

// KeyGenerateResponse represents the result of key generation.
type KeyGenerateResponse struct {
	// PublicKey is the public key.
	PublicKey BinaryData `json:"public_key"`

	// PrivateKey is the private key (for software keys).
	PrivateKey *BinaryData `json:"private_key,omitempty"`

	// Algorithm describes the algorithm.
	Algorithm AlgorithmInfo `json:"algorithm"`

	// Fingerprint is the key fingerprint.
	Fingerprint string `json:"fingerprint"`

	// Label is the key label (for HSM keys).
	Label string `json:"label,omitempty"`

	// ID is the key ID (for HSM keys).
	ID string `json:"id,omitempty"`
}

// KeyInfoRequest represents a key info request.
type KeyInfoRequest struct {
	// Key is the key to analyze.
	Key BinaryData `json:"key"`
}

// KeyInfoResponse represents key information.
type KeyInfoResponse struct {
	// Type is "public" or "private".
	Type string `json:"type"`

	// Algorithm describes the algorithm.
	Algorithm AlgorithmInfo `json:"algorithm"`

	// Size is the key size in bits.
	Size int `json:"size,omitempty"`

	// Curve is the EC curve name.
	Curve string `json:"curve,omitempty"`

	// Fingerprint is the key fingerprint.
	Fingerprint string `json:"fingerprint"`

	// IsEncrypted indicates if the private key is encrypted.
	IsEncrypted bool `json:"is_encrypted,omitempty"`
}
