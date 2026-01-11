package ca

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/remiblancher/post-quantum-pki/internal/audit"
)

// GenerateCRL generates a Certificate Revocation List.
//
// For PQC signers (ML-DSA, SLH-DSA), this delegates to GeneratePQCCRL since
// Go's crypto/x509.CreateRevocationList doesn't support PQC algorithms.
func (ca *CA) GenerateCRL(nextUpdate time.Time) ([]byte, error) {
	if ca.signer == nil {
		return nil, fmt.Errorf("CA signer not loaded - call LoadSigner first")
	}

	// Delegate to PQC implementation if using a PQC signer
	if ca.IsPQCSigner() {
		crlDER, err := ca.GeneratePQCCRL(nextUpdate)
		if err != nil {
			return nil, err
		}

		// Save CRL
		if err := ca.store.SaveCRL(context.Background(), crlDER); err != nil {
			return nil, fmt.Errorf("failed to save CRL: %w", err)
		}

		// Get count of revoked certs for audit
		entries, _ := ca.store.ReadIndex(context.Background())
		revokedCount := 0
		for _, e := range entries {
			if e.Status == "R" {
				revokedCount++
			}
		}

		// Audit: CRL generated successfully
		if err := audit.LogCRLGenerated(ca.store.BasePath(), revokedCount, true); err != nil {
			return nil, err
		}

		return crlDER, nil
	}

	// Get all revoked certificates
	entries, err := ca.store.ReadIndex(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to read index: %w", err)
	}

	var revokedCerts []pkix.RevokedCertificate
	for _, entry := range entries {
		if entry.Status != "R" {
			continue
		}

		revoked := pkix.RevokedCertificate{
			SerialNumber:   new(big.Int).SetBytes(entry.Serial),
			RevocationTime: entry.Revocation,
		}
		revokedCerts = append(revokedCerts, revoked)
	}

	// Get CRL number
	crlNumber, err := ca.store.NextCRLNumber(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get CRL number: %w", err)
	}

	template := &x509.RevocationList{
		RevokedCertificates: revokedCerts,
		Number:              new(big.Int).SetBytes(crlNumber),
		ThisUpdate:          time.Now().UTC(),
		NextUpdate:          nextUpdate,
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, template, ca.cert, ca.signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create CRL: %w", err)
	}

	// Save CRL
	if err := ca.store.SaveCRL(context.Background(), crlDER); err != nil {
		return nil, fmt.Errorf("failed to save CRL: %w", err)
	}

	// Audit: CRL generated successfully
	if err := audit.LogCRLGenerated(ca.store.BasePath(), len(revokedCerts), true); err != nil {
		return nil, err
	}

	return crlDER, nil
}

// GetCertificateAlgorithmFamily determines the algorithm family for a certificate.
func GetCertificateAlgorithmFamily(cert *x509.Certificate) string {
	sigAlgStr := strings.ToLower(cert.SignatureAlgorithm.String())

	switch {
	case strings.Contains(sigAlgStr, "ecdsa"):
		return "ec"
	case strings.Contains(sigAlgStr, "rsa"):
		return "rsa"
	case strings.Contains(sigAlgStr, "ed25519"):
		return "ed"
	case strings.Contains(sigAlgStr, "ml-dsa") || strings.Contains(sigAlgStr, "mldsa"):
		return "ml-dsa"
	case strings.Contains(sigAlgStr, "slh-dsa") || strings.Contains(sigAlgStr, "slhdsa"):
		return "slh-dsa"
	default:
		// Try to infer from public key type
		switch cert.PublicKeyAlgorithm.String() {
		case "ECDSA":
			return "ec"
		case "RSA":
			return "rsa"
		case "Ed25519":
			return "ed"
		default:
			return "unknown"
		}
	}
}
