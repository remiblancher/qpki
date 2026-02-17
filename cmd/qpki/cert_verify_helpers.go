package main

import (
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/remiblancher/post-quantum-pki/pkg/ca"
)

// verifyResult holds the verification result.
type verifyResult struct {
	IsValid        bool
	StatusMsg      string
	RevocationInfo string
	ExpiredInfo    string
}

// verifyCertificateSignature verifies the certificate signature based on cert type.
func verifyCertificateSignature(cert, caCert *x509.Certificate, intermediates []*x509.Certificate) error {
	if len(intermediates) > 0 {
		// Chain verification with intermediates
		return ca.VerifyChain(ca.VerifyChainConfig{
			Leaf:          cert,
			Intermediates: intermediates,
			Root:          caCert,
			Time:          time.Now(),
		})
	}

	// Direct verification based on certificate type
	if ca.IsCompositeCertificate(cert) {
		result, err := ca.VerifyCompositeCertificate(cert, caCert)
		if err != nil {
			return err
		}
		if !result.Valid {
			return result.Error
		}
		return nil
	}

	if ca.IsCatalystCertificate(cert) {
		valid, err := ca.VerifyCatalystSignatures(cert, caCert)
		if err != nil {
			return err
		}
		if !valid {
			return fmt.Errorf("catalyst dual-signature verification failed")
		}
		return nil
	}

	if ca.IsPQCCertificate(cert) {
		valid, err := ca.VerifyPQCCertificateRaw(cert.Raw, caCert)
		if err != nil {
			return err
		}
		if !valid {
			return fmt.Errorf("PQC signature verification failed")
		}
		return nil
	}

	// Standard X.509 verification
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	opts := x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: time.Now(),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	_, err := cert.Verify(opts)
	return err
}

// checkValidityPeriod checks the certificate's validity period.
func checkValidityPeriod(cert *x509.Certificate) (valid bool, statusMsg, expiredInfo string) {
	now := time.Now()
	if now.Before(cert.NotBefore) {
		daysUntil := int(cert.NotBefore.Sub(now).Hours() / 24)
		return false, "NOT YET VALID", fmt.Sprintf("  Not valid until: %s (%d days)", cert.NotBefore.Format("2006-01-02"), daysUntil)
	}
	if now.After(cert.NotAfter) {
		daysAgo := int(now.Sub(cert.NotAfter).Hours() / 24)
		return false, "EXPIRED", fmt.Sprintf("  Expired:    %s (%d days ago)", cert.NotAfter.Format("2006-01-02"), daysAgo)
	}
	return true, "", ""
}

// checkRevocationStatus checks if a certificate is revoked via CRL or OCSP.
func checkRevocationStatus(cert, caCert *x509.Certificate, crlFile, ocspURL string) (revoked bool, info string, err error) {
	if crlFile != "" {
		revoked, reason, revokedAt, err := checkCRL(cert, caCert, crlFile)
		if err != nil {
			return false, "", fmt.Errorf("CRL check failed: %w", err)
		}
		if revoked {
			return true, fmt.Sprintf("  Revoked:    %s\n  Reason:     %s", revokedAt.Format("2006-01-02"), reason), nil
		}
		return false, "  Revocation: Not revoked (CRL)", nil
	}

	if ocspURL != "" {
		revoked, reason, revokedAt, err := checkOCSP(cert, caCert, ocspURL)
		if err != nil {
			return false, "", fmt.Errorf("OCSP check failed: %w", err)
		}
		if revoked {
			return true, fmt.Sprintf("  Revoked:    %s\n  Reason:     %s", revokedAt.Format("2006-01-02"), reason), nil
		}
		return false, "  Revocation: Not revoked (OCSP)", nil
	}

	return false, "  Revocation: Not checked (use --crl or --ocsp)", nil
}

// printVerifyResult prints the verification result.
func printVerifyResult(cert *x509.Certificate, result *verifyResult) {
	if result.IsValid {
		fmt.Printf("%s%s Certificate is %s%s\n", colorGreen, "✓", result.StatusMsg, colorReset)
	} else {
		fmt.Printf("%s%s Certificate is %s%s\n", colorRed, "✗", result.StatusMsg, colorReset)
	}

	fmt.Printf("  Subject:    %s\n", cert.Subject.CommonName)
	fmt.Printf("  Issuer:     %s\n", cert.Issuer.CommonName)
	fmt.Printf("  Serial:     %s\n", strings.ToUpper(hex.EncodeToString(cert.SerialNumber.Bytes())))

	if result.ExpiredInfo != "" {
		fmt.Println(result.ExpiredInfo)
	} else {
		fmt.Printf("  Valid:      %s to %s\n",
			cert.NotBefore.Format("2006-01-02"),
			cert.NotAfter.Format("2006-01-02"))
	}

	fmt.Println(result.RevocationInfo)
}
