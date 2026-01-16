package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// tsaCAConfig holds CA configuration for TSA verification.
type tsaCAConfig struct {
	Roots       *x509.CertPool
	RootCertRaw []byte
}

// loadTSACAConfig loads CA certificates for TSA verification.
func loadTSACAConfig(caPath string) (*tsaCAConfig, error) {
	if caPath == "" {
		return &tsaCAConfig{}, nil
	}

	roots, err := loadCertPool(caPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load CA: %w", err)
	}

	cfg := &tsaCAConfig{Roots: roots}

	// Also load the raw CA certificate for PQC verification
	caPEM, err := os.ReadFile(caPath)
	if err == nil {
		if block, _ := pem.Decode(caPEM); block != nil {
			cfg.RootCertRaw = block.Bytes
		}
	}

	return cfg, nil
}
