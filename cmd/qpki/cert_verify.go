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
	"time"

	"github.com/spf13/cobra"

	"github.com/remiblancher/post-quantum-pki/internal/audit"
	"github.com/remiblancher/post-quantum-pki/internal/ca"
	"github.com/remiblancher/post-quantum-pki/internal/ocsp"
)

var verifyCmd = &cobra.Command{
	Use:   "verify <certificate>",
	Short: "Verify a certificate's validity and revocation status",
	Long: `Verify that a certificate is valid and optionally check revocation status.

Checks performed:
  - Certificate signature (signed by CA)
  - Validity period (not before / not after)
  - CA constraints (BasicConstraints, KeyUsage)
  - Critical extensions

Chain verification (optional):
  --chain  Intermediate certificate(s) for chain verification

Revocation checking (optional):
  --crl   Check against a local CRL file
  --ocsp  Query an OCSP responder

Examples:
  # Basic validation (leaf directly signed by CA)
  qpki cert verify server.crt --ca ca.crt

  # Chain verification (leaf -> intermediate -> root)
  qpki cert verify server.crt --ca root.crt --chain intermediate.crt

  # Cross-signing after CA rotation (credential -> CA v2 -> CA v1)
  qpki cert verify credential.crt --ca ca-v1.crt --chain ca-v2-crosssigned.crt

  # With CRL check
  qpki cert verify server.crt --ca ca.crt --crl ca.crl

  # With OCSP check
  qpki cert verify server.crt --ca ca.crt --ocsp http://localhost:8080`,
	Args:          cobra.ExactArgs(1),
	RunE:          runVerify,
	SilenceUsage:  true,
	SilenceErrors: true,
}

var (
	verifyCertFile   string
	verifyCAFile     string
	verifyChainFiles []string
	verifyCRLFile    string
	verifyOCSPURL    string
)

func init() {
	flags := verifyCmd.Flags()
	flags.StringVar(&verifyCAFile, "ca", "", "CA certificate / trust anchor (PEM)")
	flags.StringArrayVar(&verifyChainFiles, "chain", nil, "Intermediate certificate(s) in order, closest to leaf first (PEM)")
	flags.StringVar(&verifyCRLFile, "crl", "", "CRL file for revocation check (PEM/DER)")
	flags.StringVar(&verifyOCSPURL, "ocsp", "", "OCSP responder URL")

	_ = verifyCmd.MarkFlagRequired("ca")

	// Add verify as a subcommand of cert (was: rootCmd.AddCommand(verifyCmd))
	certCmd.AddCommand(verifyCmd)
}

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
)

func runVerify(cmd *cobra.Command, args []string) error {
	verifyCertFile = args[0]

	// Load certificate and CA
	cert, err := loadCertificate(verifyCertFile)
	if err != nil {
		return fmt.Errorf("failed to load certificate: %w", err)
	}

	caCerts, err := loadAllCertificates(verifyCAFile)
	if err != nil {
		return fmt.Errorf("failed to load CA certificate(s): %w", err)
	}

	caCert := findMatchingCA(cert, caCerts)
	if caCert == nil {
		caCert = caCerts[0]
	}

	// Load intermediate certificates
	var intermediates []*x509.Certificate
	for _, chainFile := range verifyChainFiles {
		chainCert, err := loadCertificate(chainFile)
		if err != nil {
			return fmt.Errorf("failed to load chain certificate %s: %w", chainFile, err)
		}
		intermediates = append(intermediates, chainCert)
	}

	// Initialize result
	result := &verifyResult{IsValid: true}

	// Check signature
	chainErr := verifyCertificateSignature(cert, caCert, intermediates)

	// Check validity period
	validPeriod, statusMsg, expiredInfo := checkValidityPeriod(cert)
	if !validPeriod {
		result.IsValid = false
		result.StatusMsg = statusMsg
		result.ExpiredInfo = expiredInfo
	} else if chainErr != nil {
		result.IsValid = false
		result.StatusMsg = "INVALID SIGNATURE"
	}

	// Check revocation
	revoked, revocationInfo, err := checkRevocationStatus(cert, caCert, verifyCRLFile, verifyOCSPURL)
	if err != nil {
		return err
	}
	if revoked {
		result.IsValid = false
		result.StatusMsg = "REVOKED"
	}
	result.RevocationInfo = revocationInfo

	// Set valid status if still valid
	if result.IsValid {
		result.StatusMsg = "VALID"
	}

	// Print results
	printVerifyResult(cert, result)

	// Log audit event
	auditResult := audit.ResultSuccess
	if !result.IsValid {
		auditResult = audit.ResultFailure
	}
	_ = audit.Log(audit.NewEvent(audit.EventOCSPVerify, auditResult).
		WithObject(audit.Object{
			Type:   "certificate",
			Serial: hex.EncodeToString(cert.SerialNumber.Bytes()),
			Path:   verifyCertFile,
		}).
		WithContext(audit.Context{
			Status:   result.StatusMsg,
			Verified: result.IsValid,
		}))

	if !result.IsValid {
		return fmt.Errorf("certificate verification failed: %s", result.StatusMsg)
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

	// Verify CRL signature - handle PQC and classical algorithms
	var sigErr error

	// Check if CRL uses a PQC signature algorithm
	sigAlgOID, extractErr := ca.ExtractCRLSignatureAlgorithmOID(crlDER)
	if extractErr == nil && ca.IsPQCSignatureOID(sigAlgOID) {
		// Use PQC verification
		valid, verifyErr := ca.VerifyPQCCRL(crlDER, issuer)
		if verifyErr != nil {
			sigErr = verifyErr
		} else if !valid {
			sigErr = fmt.Errorf("PQC signature verification failed")
		}
	} else {
		// Use standard Go verification for classical algorithms
		sigErr = crl.CheckSignatureFrom(issuer)
	}

	if sigErr != nil {
		return false, "", time.Time{}, fmt.Errorf("CRL signature verification failed: %w", sigErr)
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
	defer func() { _ = resp.Body.Close() }()

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

// loadAllCertificates loads all certificates from a PEM file (trust bundle).
func loadAllCertificates(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var certs []*x509.Certificate
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificate: %w", err)
			}
			certs = append(certs, cert)
		}
		data = rest
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in file")
	}

	return certs, nil
}

// findMatchingCA finds the CA certificate that matches the certificate's Authority Key Identifier.
func findMatchingCA(cert *x509.Certificate, caCerts []*x509.Certificate) *x509.Certificate {
	// If cert has no Authority Key ID, we can't match
	if len(cert.AuthorityKeyId) == 0 {
		return nil
	}

	// Find CA with matching Subject Key ID
	for _, ca := range caCerts {
		if bytes.Equal(ca.SubjectKeyId, cert.AuthorityKeyId) {
			return ca
		}
	}

	return nil
}
