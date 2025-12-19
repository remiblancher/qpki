package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/remiblancher/pki/internal/audit"
	"github.com/remiblancher/pki/internal/ocsp"
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify a certificate's validity and revocation status",
	Long: `Verify that a certificate is valid and optionally check revocation status.

Checks performed:
  - Certificate signature (signed by CA)
  - Validity period (not before / not after)
  - Critical extensions

Revocation checking (optional):
  --crl   Check against a local CRL file
  --ocsp  Query an OCSP responder

Examples:
  # Basic validation
  pki verify --cert server.crt --ca ca.crt

  # With CRL check
  pki verify --cert server.crt --ca ca.crt --crl ca.crl

  # With OCSP check
  pki verify --cert server.crt --ca ca.crt --ocsp http://localhost:8080`,
	RunE:          runVerify,
	SilenceUsage:  true,
	SilenceErrors: true,
}

var (
	verifyCertFile string
	verifyCAFile   string
	verifyCRLFile  string
	verifyOCSPURL  string
)

func init() {
	flags := verifyCmd.Flags()
	flags.StringVar(&verifyCertFile, "cert", "", "Certificate to verify (PEM)")
	flags.StringVar(&verifyCAFile, "ca", "", "CA certificate (PEM)")
	flags.StringVar(&verifyCRLFile, "crl", "", "CRL file for revocation check (PEM/DER)")
	flags.StringVar(&verifyOCSPURL, "ocsp", "", "OCSP responder URL")

	_ = verifyCmd.MarkFlagRequired("cert")
	_ = verifyCmd.MarkFlagRequired("ca")

	rootCmd.AddCommand(verifyCmd)
}

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
)

func runVerify(cmd *cobra.Command, args []string) error {
	// Load certificate
	cert, err := loadCertificate(verifyCertFile)
	if err != nil {
		return fmt.Errorf("failed to load certificate: %w", err)
	}

	// Load CA certificate
	caCert, err := loadCertificate(verifyCAFile)
	if err != nil {
		return fmt.Errorf("failed to load CA certificate: %w", err)
	}

	// Collect verification results
	var (
		isValid        = true
		statusMsg      string
		revocationInfo string
		expiredInfo    string
	)

	// Check chain of trust
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	opts := x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: time.Now(),
	}
	_, chainErr := cert.Verify(opts)

	// Check validity period
	now := time.Now()
	if now.Before(cert.NotBefore) {
		isValid = false
		statusMsg = "NOT YET VALID"
		daysUntil := int(cert.NotBefore.Sub(now).Hours() / 24)
		expiredInfo = fmt.Sprintf("  Not valid until: %s (%d days)", cert.NotBefore.Format("2006-01-02"), daysUntil)
	} else if now.After(cert.NotAfter) {
		isValid = false
		statusMsg = "EXPIRED"
		daysAgo := int(now.Sub(cert.NotAfter).Hours() / 24)
		expiredInfo = fmt.Sprintf("  Expired:    %s (%d days ago)", cert.NotAfter.Format("2006-01-02"), daysAgo)
	} else if chainErr != nil {
		isValid = false
		statusMsg = "INVALID SIGNATURE"
	}

	// Check revocation if requested
	var revoked bool
	var revokedReason string
	var revokedAt time.Time

	if verifyCRLFile != "" {
		revoked, revokedReason, revokedAt, err = checkCRL(cert, caCert, verifyCRLFile)
		if err != nil {
			return fmt.Errorf("CRL check failed: %w", err)
		}
		if revoked {
			isValid = false
			statusMsg = "REVOKED"
			revocationInfo = fmt.Sprintf("  Revoked:    %s\n  Reason:     %s",
				revokedAt.Format("2006-01-02"), revokedReason)
		} else {
			revocationInfo = "  Revocation: Not revoked (CRL)"
		}
	} else if verifyOCSPURL != "" {
		revoked, revokedReason, revokedAt, err = checkOCSP(cert, caCert, verifyOCSPURL)
		if err != nil {
			return fmt.Errorf("OCSP check failed: %w", err)
		}
		if revoked {
			isValid = false
			statusMsg = "REVOKED"
			revocationInfo = fmt.Sprintf("  Revoked:    %s\n  Reason:     %s",
				revokedAt.Format("2006-01-02"), revokedReason)
		} else {
			revocationInfo = "  Revocation: Not revoked (OCSP)"
		}
	} else {
		revocationInfo = "  Revocation: Not checked (use --crl or --ocsp)"
	}

	// Set valid status message if still valid
	if isValid {
		statusMsg = "VALID"
	}

	// Print results with colors
	if isValid {
		fmt.Printf("%s%s Certificate is %s%s\n", colorGreen, "✓", statusMsg, colorReset)
	} else {
		fmt.Printf("%s%s Certificate is %s%s\n", colorRed, "✗", statusMsg, colorReset)
	}

	fmt.Printf("  Subject:    %s\n", cert.Subject.CommonName)
	fmt.Printf("  Issuer:     %s\n", cert.Issuer.CommonName)
	fmt.Printf("  Serial:     %s\n", strings.ToUpper(hex.EncodeToString(cert.SerialNumber.Bytes())))

	if expiredInfo != "" {
		fmt.Println(expiredInfo)
	} else {
		fmt.Printf("  Valid:      %s to %s\n",
			cert.NotBefore.Format("2006-01-02"),
			cert.NotAfter.Format("2006-01-02"))
	}

	fmt.Println(revocationInfo)

	// Log audit event
	result := audit.ResultSuccess
	if !isValid {
		result = audit.ResultFailure
	}
	_ = audit.Log(audit.NewEvent(audit.EventOCSPVerify, result).
		WithObject(audit.Object{
			Type:   "certificate",
			Serial: hex.EncodeToString(cert.SerialNumber.Bytes()),
			Path:   verifyCertFile,
		}).
		WithContext(audit.Context{
			Status:   statusMsg,
			Verified: isValid,
		}))

	if !isValid {
		return fmt.Errorf("certificate verification failed: %s", statusMsg)
	}

	return nil
}

// checkCRL checks if a certificate is revoked using a CRL file.
func checkCRL(cert, issuer *x509.Certificate, crlPath string) (revoked bool, reason string, revokedAt time.Time, err error) {
	// Read CRL file
	data, err := os.ReadFile(crlPath)
	if err != nil {
		return false, "", time.Time{}, fmt.Errorf("failed to read CRL: %w", err)
	}

	// Try PEM first
	var crlDER []byte
	if block, _ := pem.Decode(data); block != nil {
		crlDER = block.Bytes
	} else {
		// Assume DER
		crlDER = data
	}

	// Parse CRL
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		return false, "", time.Time{}, fmt.Errorf("failed to parse CRL: %w", err)
	}

	// Verify CRL signature
	if err := crl.CheckSignatureFrom(issuer); err != nil {
		return false, "", time.Time{}, fmt.Errorf("CRL signature verification failed: %w", err)
	}

	// Check if CRL is current
	if time.Now().After(crl.NextUpdate) {
		fmt.Printf("%sWarning: CRL has expired (NextUpdate: %s)%s\n",
			colorYellow, crl.NextUpdate.Format("2006-01-02"), colorReset)
	}

	// Search for certificate serial in revoked list
	for _, revCert := range crl.RevokedCertificateEntries {
		if revCert.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			reasonStr := getRevocationReasonString(revCert.ReasonCode)
			return true, reasonStr, revCert.RevocationTime, nil
		}
	}

	return false, "", time.Time{}, nil
}

// checkOCSP checks if a certificate is revoked using OCSP.
func checkOCSP(cert, issuer *x509.Certificate, ocspURL string) (revoked bool, reason string, revokedAt time.Time, err error) {
	// Generate nonce
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return false, "", time.Time{}, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Create OCSP request
	req, err := ocsp.CreateRequestWithNonce(issuer, []*x509.Certificate{cert}, crypto.SHA256, nonce)
	if err != nil {
		return false, "", time.Time{}, fmt.Errorf("failed to create OCSP request: %w", err)
	}

	reqData, err := req.Marshal()
	if err != nil {
		return false, "", time.Time{}, fmt.Errorf("failed to marshal OCSP request: %w", err)
	}

	// Send HTTP request
	resp, err := http.Post(ocspURL, "application/ocsp-request", bytes.NewReader(reqData))
	if err != nil {
		return false, "", time.Time{}, fmt.Errorf("OCSP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, "", time.Time{}, fmt.Errorf("OCSP server returned status %d", resp.StatusCode)
	}

	// Read response
	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, "", time.Time{}, fmt.Errorf("failed to read OCSP response: %w", err)
	}

	// Verify response
	verifyConfig := &ocsp.VerifyConfig{
		IssuerCert:  issuer,
		Certificate: cert,
	}

	result, err := ocsp.Verify(respData, verifyConfig)
	if err != nil {
		return false, "", time.Time{}, fmt.Errorf("OCSP verification failed: %w", err)
	}

	if result.CertStatus == ocsp.CertStatusRevoked {
		reasonStr := getOCSPRevocationReasonString(result.RevocationReason)
		return true, reasonStr, result.RevocationTime, nil
	}

	return false, "", time.Time{}, nil
}

// getRevocationReasonString returns a human-readable revocation reason from CRL.
func getRevocationReasonString(code int) string {
	reasons := map[int]string{
		0:  "unspecified",
		1:  "keyCompromise",
		2:  "cACompromise",
		3:  "affiliationChanged",
		4:  "superseded",
		5:  "cessationOfOperation",
		6:  "certificateHold",
		8:  "removeFromCRL",
		9:  "privilegeWithdrawn",
		10: "aACompromise",
	}
	if r, ok := reasons[code]; ok {
		return r
	}
	return fmt.Sprintf("unknown (%d)", code)
}

// getOCSPRevocationReasonString returns a human-readable revocation reason from OCSP.
func getOCSPRevocationReasonString(reason ocsp.RevocationReason) string {
	reasons := map[ocsp.RevocationReason]string{
		0:  "unspecified",
		1:  "keyCompromise",
		2:  "cACompromise",
		3:  "affiliationChanged",
		4:  "superseded",
		5:  "cessationOfOperation",
		6:  "certificateHold",
		8:  "removeFromCRL",
		9:  "privilegeWithdrawn",
		10: "aACompromise",
	}
	if r, ok := reasons[reason]; ok {
		return r
	}
	return fmt.Sprintf("unknown (%d)", reason)
}
