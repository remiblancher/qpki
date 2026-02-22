package cli

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"

	"github.com/remiblancher/qpki/internal/crypto"
)

// FirstOrEmpty returns the first element of a slice or an empty string.
func FirstOrEmpty(s []string) string {
	if len(s) > 0 {
		return s[0]
	}
	return ""
}

// LoadCertFromPath loads a certificate from a PEM file.
func LoadCertFromPath(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

// SaveCertToPath saves a certificate to a PEM file.
func SaveCertToPath(path string, cert *x509.Certificate) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer func() { _ = f.Close() }()

	return WriteCertPEM(f, cert)
}

// WriteCertPEM writes a certificate as PEM to a writer.
func WriteCertPEM(w io.Writer, cert *x509.Certificate) error {
	return pem.Encode(w, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}

// ParseCertificatesPEM parses multiple certificates from PEM data.
func ParseCertificatesPEM(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		data = rest

		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// CopyFile copies a file from src to dst.
func CopyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0600)
}

// IsCompatibleAlgorithm checks if two algorithms are compatible.
func IsCompatibleAlgorithm(profile, hsm crypto.AlgorithmID) bool {
	return profile == hsm
}

// LoadCertPool loads a certificate pool from a PEM file.
func LoadCertPool(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("failed to parse certificates")
	}

	return pool, nil
}
