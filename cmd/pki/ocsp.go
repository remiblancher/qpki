package main

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/remiblancher/post-quantum-pki/internal/audit"
	"github.com/remiblancher/post-quantum-pki/internal/ca"
	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
	"github.com/remiblancher/post-quantum-pki/internal/ocsp"
)

var ocspCmd = &cobra.Command{
	Use:   "ocsp",
	Short: "OCSP operations (RFC 6960)",
	Long: `OCSP (Online Certificate Status Protocol) operations per RFC 6960.

This command provides:
  - sign:   Create an OCSP response for a certificate
  - verify: Verify an OCSP response
  - serve:  Start an HTTP OCSP responder

Supports all PKI algorithms including post-quantum (ML-DSA, SLH-DSA).

Examples:
  # Create an OCSP response (good status)
  pki ocsp sign --serial 0A1B2C --status good --ca ca.crt --cert responder.crt --key responder.key -o response.ocsp

  # Create an OCSP response (revoked status)
  pki ocsp sign --serial 0A1B2C --status revoked --revocation-time 2024-01-15T10:00:00Z --ca ca.crt --cert responder.crt --key responder.key -o response.ocsp

  # Verify an OCSP response
  pki ocsp verify --response response.ocsp --ca ca.crt

  # Start an OCSP responder server
  pki ocsp serve --port 8080 --ca-dir /path/to/ca --cert responder.crt --key responder.key`,
}

// OCSP sign command
var ocspSignCmd = &cobra.Command{
	Use:   "sign",
	Short: "Create an OCSP response for a certificate",
	Long: `Create an OCSP response for a certificate identified by serial number.

The response is signed by the OCSP responder's private key.
If no responder certificate is provided, the CA certificate is used (CA-signed mode).

Examples:
  # Good status
  pki ocsp sign --serial 0A1B2C --status good --ca ca.crt --cert responder.crt --key responder.key -o response.ocsp

  # Revoked status with reason
  pki ocsp sign --serial 0A1B2C --status revoked --revocation-time 2024-01-15T10:00:00Z --revocation-reason keyCompromise --ca ca.crt --cert responder.crt --key responder.key -o response.ocsp

  # Unknown status
  pki ocsp sign --serial 0A1B2C --status unknown --ca ca.crt --key ca.key -o response.ocsp`,
	RunE: runOCSPSign,
}

// OCSP verify command
var ocspVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify an OCSP response",
	Long: `Verify an OCSP response signature and display status.

Examples:
  # Verify response with CA certificate
  pki ocsp verify --response response.ocsp --ca ca.crt

  # Verify and check against specific certificate
  pki ocsp verify --response response.ocsp --ca ca.crt --cert server.crt`,
	RunE: runOCSPVerify,
}

// OCSP serve command
var ocspServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start an HTTP OCSP responder",
	Long: `Start an HTTP OCSP responder server (RFC 6960).

The server supports both GET and POST requests:
  - GET:  /{base64-encoded-request}
  - POST: Binary request body with Content-Type: application/ocsp-request

Modes:
  - Delegated: Use a dedicated OCSP responder certificate (with EKU OCSPSigning)
  - CA-signed: Use the CA certificate directly (if no responder cert provided)

Examples:
  # Start with delegated responder certificate
  pki ocsp serve --port 8080 --ca-dir /path/to/ca --cert responder.crt --key responder.key

  # Start with CA-signed responses
  pki ocsp serve --port 8080 --ca-dir /path/to/ca

  # With custom validity period
  pki ocsp serve --port 8080 --ca-dir /path/to/ca --validity 2h`,
	RunE: runOCSPServe,
}

// Command flags
var (
	// ocsp sign flags
	ocspSignSerial          string
	ocspSignStatus          string
	ocspSignRevocationTime  string
	ocspSignRevocationReason string
	ocspSignCA              string
	ocspSignCert            string
	ocspSignKey             string
	ocspSignPassphrase      string
	ocspSignOutput          string
	ocspSignValidity        string

	// ocsp verify flags
	ocspVerifyResponse string
	ocspVerifyCA       string
	ocspVerifyCert     string

	// ocsp serve flags
	ocspServePort       int
	ocspServeCADir      string
	ocspServeCert       string
	ocspServeKey        string
	ocspServePassphrase string
	ocspServeValidity   string
	ocspServeCopyNonce  bool
)

func init() {
	// ocsp sign flags
	ocspSignCmd.Flags().StringVar(&ocspSignSerial, "serial", "", "Certificate serial number (hex)")
	ocspSignCmd.Flags().StringVar(&ocspSignStatus, "status", "good", "Certificate status (good, revoked, unknown)")
	ocspSignCmd.Flags().StringVar(&ocspSignRevocationTime, "revocation-time", "", "Revocation time (RFC3339 format)")
	ocspSignCmd.Flags().StringVar(&ocspSignRevocationReason, "revocation-reason", "", "Revocation reason (keyCompromise, caCompromise, affiliationChanged, superseded, cessationOfOperation, certificateHold, removeFromCRL, privilegeWithdrawn, aaCompromise)")
	ocspSignCmd.Flags().StringVar(&ocspSignCA, "ca", "", "CA certificate (PEM)")
	ocspSignCmd.Flags().StringVar(&ocspSignCert, "cert", "", "Responder certificate (PEM, optional)")
	ocspSignCmd.Flags().StringVar(&ocspSignKey, "key", "", "Responder private key (PEM)")
	ocspSignCmd.Flags().StringVar(&ocspSignPassphrase, "passphrase", "", "Key passphrase")
	ocspSignCmd.Flags().StringVarP(&ocspSignOutput, "out", "o", "", "Output file")
	ocspSignCmd.Flags().StringVar(&ocspSignValidity, "validity", "1h", "Response validity period")

	_ = ocspSignCmd.MarkFlagRequired("serial")
	_ = ocspSignCmd.MarkFlagRequired("ca")
	_ = ocspSignCmd.MarkFlagRequired("key")
	_ = ocspSignCmd.MarkFlagRequired("out")

	// ocsp verify flags
	ocspVerifyCmd.Flags().StringVar(&ocspVerifyResponse, "response", "", "OCSP response file")
	ocspVerifyCmd.Flags().StringVar(&ocspVerifyCA, "ca", "", "CA certificate (PEM)")
	ocspVerifyCmd.Flags().StringVar(&ocspVerifyCert, "cert", "", "Certificate to verify (PEM, optional)")

	_ = ocspVerifyCmd.MarkFlagRequired("response")

	// ocsp serve flags
	ocspServeCmd.Flags().IntVar(&ocspServePort, "port", 8080, "HTTP port")
	ocspServeCmd.Flags().StringVar(&ocspServeCADir, "ca-dir", "", "CA directory (contains ca.crt, ca.key, index.txt)")
	ocspServeCmd.Flags().StringVar(&ocspServeCert, "cert", "", "Responder certificate (PEM, optional)")
	ocspServeCmd.Flags().StringVar(&ocspServeKey, "key", "", "Responder private key (PEM, optional)")
	ocspServeCmd.Flags().StringVar(&ocspServePassphrase, "passphrase", "", "Key passphrase")
	ocspServeCmd.Flags().StringVar(&ocspServeValidity, "validity", "1h", "Response validity period")
	ocspServeCmd.Flags().BoolVar(&ocspServeCopyNonce, "copy-nonce", true, "Copy nonce from request to response")

	_ = ocspServeCmd.MarkFlagRequired("ca-dir")

	// Add subcommands
	ocspCmd.AddCommand(ocspSignCmd)
	ocspCmd.AddCommand(ocspVerifyCmd)
	ocspCmd.AddCommand(ocspServeCmd)
}

func runOCSPSign(cmd *cobra.Command, args []string) error {
	// Parse serial number
	serialBytes, err := hex.DecodeString(ocspSignSerial)
	if err != nil {
		return fmt.Errorf("invalid serial number: %w", err)
	}
	serial := new(big.Int).SetBytes(serialBytes)

	// Parse status
	var certStatus ocsp.CertStatus
	switch strings.ToLower(ocspSignStatus) {
	case "good":
		certStatus = ocsp.CertStatusGood
	case "revoked":
		certStatus = ocsp.CertStatusRevoked
	case "unknown":
		certStatus = ocsp.CertStatusUnknown
	default:
		return fmt.Errorf("invalid status: %s (must be good, revoked, or unknown)", ocspSignStatus)
	}

	// Parse revocation time if revoked
	var revocationTime time.Time
	if certStatus == ocsp.CertStatusRevoked {
		if ocspSignRevocationTime == "" {
			revocationTime = time.Now()
		} else {
			revocationTime, err = time.Parse(time.RFC3339, ocspSignRevocationTime)
			if err != nil {
				return fmt.Errorf("invalid revocation time: %w", err)
			}
		}
	}

	// Parse revocation reason
	revocationReason := parseOCSPRevocationReason(ocspSignRevocationReason)

	// Load CA certificate
	caCert, err := loadCertificate(ocspSignCA)
	if err != nil {
		return fmt.Errorf("failed to load CA certificate: %w", err)
	}

	// Load responder certificate (optional - use CA if not provided)
	var responderCert *x509.Certificate
	if ocspSignCert != "" {
		responderCert, err = loadCertificate(ocspSignCert)
		if err != nil {
			return fmt.Errorf("failed to load responder certificate: %w", err)
		}
	} else {
		responderCert = caCert
	}

	// Load private key
	signer, err := pkicrypto.LoadPrivateKey(ocspSignKey, []byte(ocspSignPassphrase))
	if err != nil {
		return fmt.Errorf("failed to load private key: %w", err)
	}

	// Parse validity
	validity, err := time.ParseDuration(ocspSignValidity)
	if err != nil {
		return fmt.Errorf("invalid validity duration: %w", err)
	}

	// Create CertID
	certID, err := ocsp.NewCertIDFromSerial(crypto.SHA256, caCert, serial)
	if err != nil {
		return fmt.Errorf("failed to create CertID: %w", err)
	}

	// Build response
	now := time.Now().UTC()
	builder := ocsp.NewResponseBuilder(responderCert, signer)

	switch certStatus {
	case ocsp.CertStatusGood:
		builder.AddGood(certID, now, now.Add(validity))
	case ocsp.CertStatusRevoked:
		builder.AddRevoked(certID, now, now.Add(validity), revocationTime, revocationReason)
	case ocsp.CertStatusUnknown:
		builder.AddUnknown(certID, now, now.Add(validity))
	}

	responseData, err := builder.Build()
	if err != nil {
		return fmt.Errorf("failed to build OCSP response: %w", err)
	}

	// Write output
	if err := os.WriteFile(ocspSignOutput, responseData, 0644); err != nil {
		return fmt.Errorf("failed to write response: %w", err)
	}

	// Log audit event
	_ = audit.Log(audit.NewEvent(audit.EventOCSPSign, audit.ResultSuccess).
		WithObject(audit.Object{
			Type: "ocsp-response",
			Path: ocspSignOutput,
		}).
		WithContext(audit.Context{
			Serial: ocspSignSerial,
			Status: ocspSignStatus,
		}))

	fmt.Printf("OCSP response written to %s\n", ocspSignOutput)
	fmt.Printf("  Serial:     %s\n", ocspSignSerial)
	fmt.Printf("  Status:     %s\n", certStatus)
	if certStatus == ocsp.CertStatusRevoked {
		fmt.Printf("  Revoked:    %s\n", revocationTime.Format(time.RFC3339))
		if ocspSignRevocationReason != "" {
			fmt.Printf("  Reason:     %s\n", ocspSignRevocationReason)
		}
	}
	fmt.Printf("  Valid For:  %s\n", validity)

	return nil
}

func runOCSPVerify(cmd *cobra.Command, args []string) error {
	// Read response
	responseData, err := os.ReadFile(ocspVerifyResponse)
	if err != nil {
		return fmt.Errorf("failed to read response file: %w", err)
	}

	// Build verify config
	config := &ocsp.VerifyConfig{
		CurrentTime: time.Now(),
	}

	// Load CA certificate if provided
	if ocspVerifyCA != "" {
		caCert, err := loadCertificate(ocspVerifyCA)
		if err != nil {
			return fmt.Errorf("failed to load CA certificate: %w", err)
		}
		config.IssuerCert = caCert
	} else {
		config.SkipSignatureVerify = true
	}

	// Load certificate to verify if provided
	if ocspVerifyCert != "" {
		cert, err := loadCertificate(ocspVerifyCert)
		if err != nil {
			return fmt.Errorf("failed to load certificate: %w", err)
		}
		config.Certificate = cert
	}

	// Verify
	result, err := ocsp.Verify(responseData, config)
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	// Check response status
	if result.Status != ocsp.StatusSuccessful {
		fmt.Printf("OCSP Response Status: %s\n", result.Status)
		return nil
	}

	// Log audit event
	_ = audit.Log(audit.NewEvent(audit.EventOCSPVerify, audit.ResultSuccess).
		WithObject(audit.Object{
			Type: "ocsp-response",
			Path: ocspVerifyResponse,
		}).
		WithContext(audit.Context{
			Status:   result.CertStatus.String(),
			Verified: true,
		}))

	fmt.Printf("OCSP Response Verification: OK\n")
	fmt.Printf("  Response Status:   %s\n", result.Status)
	fmt.Printf("  Certificate Status: %s\n", result.CertStatus)
	if result.SerialNumber != nil {
		fmt.Printf("  Serial Number:     %X\n", result.SerialNumber.Bytes())
	}
	fmt.Printf("  Produced At:       %s\n", result.ProducedAt.Format(time.RFC3339))
	fmt.Printf("  This Update:       %s\n", result.ThisUpdate.Format(time.RFC3339))
	if !result.NextUpdate.IsZero() {
		fmt.Printf("  Next Update:       %s\n", result.NextUpdate.Format(time.RFC3339))
	}
	if result.CertStatus == ocsp.CertStatusRevoked {
		fmt.Printf("  Revocation Time:   %s\n", result.RevocationTime.Format(time.RFC3339))
		if result.RevocationReason != 0 {
			fmt.Printf("  Revocation Reason: %s\n", revocationReasonString(result.RevocationReason))
		}
	}
	if result.ResponderCert != nil {
		fmt.Printf("  Responder:         %s\n", result.ResponderCert.Subject.CommonName)
	}

	return nil
}

func runOCSPServe(cmd *cobra.Command, args []string) error {
	// Load CA store
	store := ca.NewStore(ocspServeCADir)

	// Load CA certificate
	caCertPath := ocspServeCADir + "/ca.crt"
	caCert, err := loadCertificate(caCertPath)
	if err != nil {
		return fmt.Errorf("failed to load CA certificate: %w", err)
	}

	// Load responder certificate and key
	var responderCert *x509.Certificate
	var signer crypto.Signer

	if ocspServeCert != "" && ocspServeKey != "" {
		// Delegated responder mode
		responderCert, err = loadCertificate(ocspServeCert)
		if err != nil {
			return fmt.Errorf("failed to load responder certificate: %w", err)
		}
		signer, err = pkicrypto.LoadPrivateKey(ocspServeKey, []byte(ocspServePassphrase))
		if err != nil {
			return fmt.Errorf("failed to load responder key: %w", err)
		}
	} else {
		// CA-signed mode
		responderCert = caCert
		caKeyPath := ocspServeCADir + "/ca.key"
		signer, err = pkicrypto.LoadPrivateKey(caKeyPath, []byte(ocspServePassphrase))
		if err != nil {
			return fmt.Errorf("failed to load CA key: %w", err)
		}
	}

	// Parse validity
	validity, err := time.ParseDuration(ocspServeValidity)
	if err != nil {
		return fmt.Errorf("invalid validity duration: %w", err)
	}

	// Create responder
	responder, err := ocsp.NewResponder(&ocsp.ResponderConfig{
		ResponderCert: responderCert,
		Signer:        signer,
		CACert:        caCert,
		CAStore:       store,
		Validity:      validity,
		CopyNonce:     ocspServeCopyNonce,
		IncludeCerts:  true,
	})
	if err != nil {
		return fmt.Errorf("failed to create responder: %w", err)
	}

	// Create HTTP handler
	handler := &ocspHandler{responder: responder}

	// Log startup
	_ = audit.Log(audit.NewEvent(audit.EventOCSPServe, audit.ResultSuccess).
		WithContext(audit.Context{
			Port: ocspServePort,
		}))

	fmt.Printf("Starting OCSP responder on port %d\n", ocspServePort)
	fmt.Printf("  CA:         %s\n", caCert.Subject.CommonName)
	fmt.Printf("  Responder:  %s\n", responderCert.Subject.CommonName)
	fmt.Printf("  Validity:   %s\n", validity)
	fmt.Printf("  Copy Nonce: %v\n", ocspServeCopyNonce)
	fmt.Printf("\nEndpoints:\n")
	fmt.Printf("  GET  /{base64-request}\n")
	fmt.Printf("  POST / (Content-Type: application/ocsp-request)\n")

	addr := fmt.Sprintf(":%d", ocspServePort)
	return http.ListenAndServe(addr, handler)
}

// ocspHandler handles HTTP OCSP requests.
type ocspHandler struct {
	responder *ocsp.Responder
}

func (h *ocspHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var responseData []byte
	var err error

	// Parse request from HTTP
	req, err := ocsp.ParseRequestFromHTTP(r)
	if err != nil {
		responseData, _ = ocsp.NewMalformedResponse()
	} else {
		responseData, err = h.responder.Respond(req)
		if err != nil {
			responseData, _ = ocsp.NewInternalErrorResponse()
		}
	}

	// Log request
	_ = audit.Log(audit.NewEvent(audit.EventOCSPRequest, audit.ResultSuccess).
		WithContext(audit.Context{
			Method: r.Method,
		}))

	// Write response
	w.Header().Set("Content-Type", "application/ocsp-response")
	w.Header().Set("Cache-Control", "max-age=3600")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(responseData)
}

// Helper functions

func parseOCSPRevocationReason(reason string) ocsp.RevocationReason {
	switch strings.ToLower(reason) {
	case "keycompromise":
		return ocsp.ReasonKeyCompromise
	case "cacompromise":
		return ocsp.ReasonCACompromise
	case "affiliationchanged":
		return ocsp.ReasonAffiliationChanged
	case "superseded":
		return ocsp.ReasonSuperseded
	case "cessationofoperation":
		return ocsp.ReasonCessationOfOperation
	case "certificatehold":
		return ocsp.ReasonCertificateHold
	case "removefromcrl":
		return ocsp.ReasonRemoveFromCRL
	case "privilegewithdrawn":
		return ocsp.ReasonPrivilegeWithdrawn
	case "aacompromise":
		return ocsp.ReasonAACompromise
	default:
		return ocsp.ReasonUnspecified
	}
}

func revocationReasonString(reason ocsp.RevocationReason) string {
	switch reason {
	case ocsp.ReasonKeyCompromise:
		return "keyCompromise"
	case ocsp.ReasonCACompromise:
		return "caCompromise"
	case ocsp.ReasonAffiliationChanged:
		return "affiliationChanged"
	case ocsp.ReasonSuperseded:
		return "superseded"
	case ocsp.ReasonCessationOfOperation:
		return "cessationOfOperation"
	case ocsp.ReasonCertificateHold:
		return "certificateHold"
	case ocsp.ReasonRemoveFromCRL:
		return "removeFromCRL"
	case ocsp.ReasonPrivilegeWithdrawn:
		return "privilegeWithdrawn"
	case ocsp.ReasonAACompromise:
		return "aaCompromise"
	default:
		return "unspecified"
	}
}

// ocspInfoCmd displays information about an OCSP response
var ocspInfoCmd = &cobra.Command{
	Use:   "info [response-file]",
	Short: "Display information about an OCSP response",
	Long: `Display detailed information about an OCSP response.

Example:
  pki ocsp info response.ocsp`,
	Args: cobra.ExactArgs(1),
	RunE: runOCSPInfo,
}

func init() {
	ocspCmd.AddCommand(ocspInfoCmd)
}

func runOCSPInfo(cmd *cobra.Command, args []string) error {
	// Read response
	responseData, err := os.ReadFile(args[0])
	if err != nil {
		return fmt.Errorf("failed to read response file: %w", err)
	}

	// Get response info
	info, err := ocsp.GetResponseInfo(responseData)
	if err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	fmt.Printf("OCSP Response Information\n")
	fmt.Printf("=========================\n\n")
	fmt.Printf("Response Status: %s\n", info.Status)

	if info.Status != ocsp.StatusSuccessful {
		return nil
	}

	fmt.Printf("Produced At:     %s\n", info.ProducedAt.Format(time.RFC3339))
	fmt.Printf("Signature Alg:   %s\n", info.SignatureAlg)

	if len(info.Nonce) > 0 {
		fmt.Printf("Nonce:           %X\n", info.Nonce)
	}

	if len(info.ResponderCerts) > 0 {
		fmt.Printf("\nResponder Certificate:\n")
		cert := info.ResponderCerts[0]
		fmt.Printf("  Subject:  %s\n", cert.Subject.CommonName)
		fmt.Printf("  Issuer:   %s\n", cert.Issuer.CommonName)
		fmt.Printf("  Serial:   %X\n", cert.SerialNumber.Bytes())
	}

	fmt.Printf("\nCertificate Statuses:\n")
	for i, cs := range info.CertStatuses {
		fmt.Printf("\n  [%d] Serial: %X\n", i+1, cs.SerialNumber.Bytes())
		fmt.Printf("      Status:      %s\n", cs.Status)
		fmt.Printf("      This Update: %s\n", cs.ThisUpdate.Format(time.RFC3339))
		if !cs.NextUpdate.IsZero() {
			fmt.Printf("      Next Update: %s\n", cs.NextUpdate.Format(time.RFC3339))
		}
		if cs.Status == ocsp.CertStatusRevoked {
			fmt.Printf("      Revoked At:  %s\n", cs.RevocationTime.Format(time.RFC3339))
			fmt.Printf("      Reason:      %s\n", revocationReasonString(cs.RevocationReason))
		}
	}

	return nil
}

// ocspRequestCmd creates an OCSP request
var ocspRequestCmd = &cobra.Command{
	Use:   "request",
	Short: "Create an OCSP request",
	Long: `Create an OCSP request for one or more certificates.

Examples:
  # Create request for a certificate
  pki ocsp request --issuer ca.crt --cert server.crt -o request.ocsp

  # Create request with nonce
  pki ocsp request --issuer ca.crt --cert server.crt --nonce -o request.ocsp`,
	RunE: runOCSPRequest,
}

var (
	ocspRequestIssuer string
	ocspRequestCert   string
	ocspRequestNonce  bool
	ocspRequestOutput string
)

func init() {
	ocspRequestCmd.Flags().StringVar(&ocspRequestIssuer, "issuer", "", "Issuer certificate (PEM)")
	ocspRequestCmd.Flags().StringVar(&ocspRequestCert, "cert", "", "Certificate to check (PEM)")
	ocspRequestCmd.Flags().BoolVar(&ocspRequestNonce, "nonce", false, "Include nonce extension")
	ocspRequestCmd.Flags().StringVarP(&ocspRequestOutput, "out", "o", "", "Output file")

	_ = ocspRequestCmd.MarkFlagRequired("issuer")
	_ = ocspRequestCmd.MarkFlagRequired("cert")
	_ = ocspRequestCmd.MarkFlagRequired("out")

	ocspCmd.AddCommand(ocspRequestCmd)
}

func runOCSPRequest(cmd *cobra.Command, args []string) error {
	// Load issuer certificate
	issuer, err := loadCertificate(ocspRequestIssuer)
	if err != nil {
		return fmt.Errorf("failed to load issuer certificate: %w", err)
	}

	// Load certificate to check
	cert, err := loadCertificate(ocspRequestCert)
	if err != nil {
		return fmt.Errorf("failed to load certificate: %w", err)
	}

	// Create request
	var req *ocsp.OCSPRequest
	if ocspRequestNonce {
		// Generate random nonce
		nonce := make([]byte, 16)
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return fmt.Errorf("failed to generate nonce: %w", err)
		}
		req, err = ocsp.CreateRequestWithNonce(issuer, []*x509.Certificate{cert}, crypto.SHA256, nonce)
	} else {
		req, err = ocsp.CreateRequest(issuer, []*x509.Certificate{cert}, crypto.SHA256)
	}
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Marshal request
	data, err := req.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	// Write output
	if err := os.WriteFile(ocspRequestOutput, data, 0644); err != nil {
		return fmt.Errorf("failed to write request: %w", err)
	}

	fmt.Printf("OCSP request written to %s\n", ocspRequestOutput)
	fmt.Printf("  Issuer:  %s\n", issuer.Subject.CommonName)
	fmt.Printf("  Cert:    %s\n", cert.Subject.CommonName)
	fmt.Printf("  Serial:  %X\n", cert.SerialNumber.Bytes())
	if ocspRequestNonce {
		fmt.Printf("  Nonce:   included\n")
	}

	return nil
}
