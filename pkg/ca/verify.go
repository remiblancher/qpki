// Package ca provides certificate chain verification functionality.
package ca

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/remiblancher/post-quantum-pki/pkg/x509util"
)

// VerifyChainConfig holds configuration for chain verification.
type VerifyChainConfig struct {
	// Leaf is the end-entity certificate to verify
	Leaf *x509.Certificate

	// Intermediates are intermediate certificates in order (closest to leaf first)
	Intermediates []*x509.Certificate

	// Root is the trust anchor (root CA certificate)
	Root *x509.Certificate

	// Time is the time at which to verify the chain (use time.Now() for current time)
	Time time.Time
}

// VerifyChain verifies a certificate chain sequentially.
// The chain is verified from leaf -> intermediates -> root.
// Each link is verified for:
// - Time validity (NotBefore/NotAfter)
// - CA status (BasicConstraints.IsCA)
// - KeyUsage (KeyUsageCertSign)
// - Signature (using appropriate algorithm for PQC/Hybrid/Classical)
func VerifyChain(cfg VerifyChainConfig) error {
	if cfg.Leaf == nil {
		return errors.New("leaf certificate is required")
	}
	if cfg.Root == nil {
		return errors.New("root certificate is required")
	}
	if cfg.Time.IsZero() {
		cfg.Time = time.Now()
	}

	// Build chain: leaf -> intermediates -> root
	chain := make([]*x509.Certificate, 0, 2+len(cfg.Intermediates))
	chain = append(chain, cfg.Leaf)
	chain = append(chain, cfg.Intermediates...)
	chain = append(chain, cfg.Root)

	// Verify each link
	for i := 0; i < len(chain)-1; i++ {
		child := chain[i]
		issuer := chain[i+1]
		if err := verifyLink(child, issuer, cfg.Time); err != nil {
			return fmt.Errorf("chain verification failed at level %d (%s -> %s): %w",
				i, child.Subject.CommonName, issuer.Subject.CommonName, err)
		}
	}

	return nil
}

// verifyLink verifies a single child-issuer relationship.
func verifyLink(child, issuer *x509.Certificate, now time.Time) error {
	// 1. Time validity for child
	if now.Before(child.NotBefore) {
		return fmt.Errorf("certificate not yet valid (NotBefore: %s)", child.NotBefore.Format("2006-01-02"))
	}
	if now.After(child.NotAfter) {
		return fmt.Errorf("certificate expired (NotAfter: %s)", child.NotAfter.Format("2006-01-02"))
	}

	// 2. Time validity for issuer
	if now.Before(issuer.NotBefore) {
		return fmt.Errorf("issuer certificate not yet valid (NotBefore: %s)", issuer.NotBefore.Format("2006-01-02"))
	}
	if now.After(issuer.NotAfter) {
		return fmt.Errorf("issuer certificate expired (NotAfter: %s)", issuer.NotAfter.Format("2006-01-02"))
	}

	// 3. Issuer must be a CA
	if !issuer.IsCA {
		return errors.New("issuer is not a CA (BasicConstraints.IsCA = false)")
	}

	// 4. Issuer must have KeyUsageCertSign
	// Note: KeyUsage may be 0 if not set, which we allow for flexibility
	if issuer.KeyUsage != 0 && issuer.KeyUsage&x509.KeyUsageCertSign == 0 {
		return errors.New("issuer cannot sign certificates (missing KeyUsageCertSign)")
	}

	// 5. Verify signature based on certificate type
	return VerifySignature(child, issuer)
}

// VerifySignature verifies the signature on a certificate based on its type.
// It dispatches to the appropriate verification function for:
// - Composite certificates (IETF draft)
// - Catalyst certificates (ITU-T hybrid)
// - Pure PQC certificates (ML-DSA, etc.)
// - Classical certificates (RSA, ECDSA)
func VerifySignature(child, issuer *x509.Certificate) error {
	// Check Composite first (IETF)
	if IsCompositeCertificate(child) {
		result, err := VerifyCompositeCertificate(child, issuer)
		if err != nil {
			return fmt.Errorf("composite verification error: %w", err)
		}
		if !result.Valid {
			if result.Error != nil {
				return fmt.Errorf("composite signature invalid: %w", result.Error)
			}
			return errors.New("composite signature verification failed")
		}
		return nil
	}

	// Check Catalyst (ITU-T hybrid)
	if IsCatalystCertificate(child) {
		valid, err := VerifyCatalystSignatures(child, issuer)
		if err != nil {
			return fmt.Errorf("catalyst verification error: %w", err)
		}
		if !valid {
			return errors.New("catalyst dual-signature verification failed")
		}
		return nil
	}

	// Check pure PQC
	if IsPQCCertificate(child) {
		valid, err := VerifyPQCCertificateRaw(child.Raw, issuer)
		if err != nil {
			return fmt.Errorf("PQC verification error: %w", err)
		}
		if !valid {
			return errors.New("PQC signature verification failed")
		}
		return nil
	}

	// Classical certificate - use stdlib
	if err := child.CheckSignatureFrom(issuer); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}
	return nil
}

// IsPQCCertificate checks if a certificate uses a PQC signature algorithm.
func IsPQCCertificate(cert *x509.Certificate) bool {
	// Go's x509 marks unknown algorithms as UnknownSignatureAlgorithm
	if cert.SignatureAlgorithm != x509.UnknownSignatureAlgorithm {
		return false
	}

	// Check if it's a known PQC algorithm by parsing the raw signature algorithm OID
	return x509util.IsPQCSignatureAlgorithmOID(cert.RawTBSCertificate)
}

// IsCatalystCertificate checks if a certificate is a Catalyst hybrid certificate.
// Catalyst certificates contain an AltSignatureValue extension (OID 2.5.29.74).
func IsCatalystCertificate(cert *x509.Certificate) bool {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(x509util.OIDAltSignatureValue) {
			return true
		}
	}
	return false
}
