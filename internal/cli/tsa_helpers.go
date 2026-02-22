package cli

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// TSACAConfig holds CA configuration for TSA verification.
type TSACAConfig struct {
	Roots       *x509.CertPool
	RootCertRaw []byte
}

// LoadTSACAConfig loads CA certificates for TSA verification.
func LoadTSACAConfig(caPath string) (*TSACAConfig, error) {
	if caPath == "" {
		return &TSACAConfig{}, nil
	}

	roots, err := LoadCertPool(caPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load CA: %w", err)
	}

	cfg := &TSACAConfig{Roots: roots}

	// Also load the raw CA certificate for PQC verification
	caPEM, err := os.ReadFile(caPath)
	if err == nil {
		if block, _ := pem.Decode(caPEM); block != nil {
			cfg.RootCertRaw = block.Bytes
		}
	}

	return cfg, nil
}
