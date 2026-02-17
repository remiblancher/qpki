package ca

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"

	"github.com/remiblancher/post-quantum-pki/pkg/audit"
)

// GenerateCRLForAlgorithm generates a CRL for a specific algorithm family.
// It includes only certificates from the given algorithm family.
func (ca *CA) GenerateCRLForAlgorithm(algoFamily string, nextUpdate time.Time) ([]byte, error) {
	if ca.signer == nil {
		return nil, fmt.Errorf("CA signer not loaded - call LoadSigner first")
	}

	// For PQC signers, delegate to PQC implementation
	if ca.IsPQCSigner() {
		return ca.generatePQCCRLForAlgorithm(algoFamily, nextUpdate)
	}

	// Get all revoked certificates for this algorithm family
	entries, err := ca.store.ReadIndex(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to read index: %w", err)
	}

	var revokedCerts []pkix.RevokedCertificate
	for _, entry := range entries {
		if entry.Status != "R" {
			continue
		}

		// Check if certificate belongs to this algorithm family
		cert, err := ca.store.LoadCert(context.Background(), entry.Serial)
		if err != nil || cert == nil {
			continue
		}

		certAlgoFamily := GetCertificateAlgorithmFamily(cert)
		if certAlgoFamily != algoFamily {
			continue
		}

		revoked := pkix.RevokedCertificate{
			SerialNumber:   new(big.Int).SetBytes(entry.Serial),
			RevocationTime: entry.Revocation,
		}
		revokedCerts = append(revokedCerts, revoked)
	}

	// Get shared CRL number
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

	// Get signer algorithm for CRL filename
	signerAlgo := ca.signer.Algorithm()

	// Save CRL for this algorithm
	if err := ca.store.SaveCRLForAlgorithm(context.Background(), crlDER, string(signerAlgo)); err != nil {
		return nil, fmt.Errorf("failed to save CRL: %w", err)
	}

	// Audit: CRL generated successfully
	if err := audit.LogCRLGenerated(ca.store.BasePath(), len(revokedCerts), true); err != nil {
		return nil, err
	}

	return crlDER, nil
}

// generatePQCCRLForAlgorithm generates a PQC CRL for a specific algorithm family.
func (ca *CA) generatePQCCRLForAlgorithm(algoFamily string, nextUpdate time.Time) ([]byte, error) {
	// Get all revoked certificates for this algorithm family
	entries, err := ca.store.ReadIndex(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to read index: %w", err)
	}

	var revokedCerts []pkix.RevokedCertificate
	for _, entry := range entries {
		if entry.Status != "R" {
			continue
		}

		// Check if certificate belongs to this algorithm family
		cert, err := ca.store.LoadCert(context.Background(), entry.Serial)
		if err != nil || cert == nil {
			continue
		}

		certAlgoFamily := GetCertificateAlgorithmFamily(cert)
		if certAlgoFamily != algoFamily {
			continue
		}

		revoked := pkix.RevokedCertificate{
			SerialNumber:   new(big.Int).SetBytes(entry.Serial),
			RevocationTime: entry.Revocation,
		}
		revokedCerts = append(revokedCerts, revoked)
	}

	// Get shared CRL number
	crlNumber, err := ca.store.NextCRLNumber(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get CRL number: %w", err)
	}

	// Create CRL using PQC-specific implementation
	crlDER, err := ca.GeneratePQCCRLWithEntries(revokedCerts, crlNumber, nextUpdate)
	if err != nil {
		return nil, err
	}

	// Get signer algorithm for CRL filename
	signerAlgo := ca.signer.Algorithm()

	// Save CRL for this algorithm
	if err := ca.store.SaveCRLForAlgorithm(context.Background(), crlDER, string(signerAlgo)); err != nil {
		return nil, fmt.Errorf("failed to save CRL: %w", err)
	}

	// Audit: CRL generated successfully
	if err := audit.LogCRLGenerated(ca.store.BasePath(), len(revokedCerts), true); err != nil {
		return nil, err
	}

	return crlDER, nil
}

// GenerateAllCRLs generates CRLs for all algorithm families with revoked certificates.
func (ca *CA) GenerateAllCRLs(nextUpdate time.Time) (map[string][]byte, error) {
	if ca.signer == nil {
		return nil, fmt.Errorf("CA signer not loaded - call LoadSigner first")
	}

	// Find all algorithm families with revoked certificates
	entries, err := ca.store.ReadIndex(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to read index: %w", err)
	}

	algoFamilies := make(map[string]bool)
	for _, entry := range entries {
		if entry.Status != "R" {
			continue
		}

		cert, err := ca.store.LoadCert(context.Background(), entry.Serial)
		if err != nil || cert == nil {
			continue
		}

		algoFamily := GetCertificateAlgorithmFamily(cert)
		algoFamilies[algoFamily] = true
	}

	// Generate CRL for each algorithm family
	results := make(map[string][]byte)
	for algoFamily := range algoFamilies {
		crlDER, err := ca.GenerateCRLForAlgorithm(algoFamily, nextUpdate)
		if err != nil {
			return nil, fmt.Errorf("failed to generate CRL for %s: %w", algoFamily, err)
		}
		results[algoFamily] = crlDER
	}

	// Also generate legacy CRL for backward compatibility
	crlDER, err := ca.GenerateCRL(nextUpdate)
	if err != nil {
		return nil, fmt.Errorf("failed to generate legacy CRL: %w", err)
	}
	results["legacy"] = crlDER

	return results, nil
}
