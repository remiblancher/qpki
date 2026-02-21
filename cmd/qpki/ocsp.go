package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/remiblancher/qpki/pkg/audit"
	"github.com/remiblancher/qpki/pkg/ca"
	"github.com/remiblancher/qpki/pkg/credential"
	pkicrypto "github.com/remiblancher/qpki/pkg/crypto"
	"github.com/remiblancher/qpki/pkg/ocsp"
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
  pki ocsp sign --serial 0A1B2C --status good --ca ca.crt --cert responder.crt --key responder.key --out response.ocsp

  # Create an OCSP response (revoked status)
  pki ocsp sign --serial 0A1B2C --status revoked --revocation-time 2024-01-15T10:00:00Z --ca ca.crt --cert responder.crt --key responder.key --out response.ocsp

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
  pki ocsp sign --serial 0A1B2C --status good --ca ca.crt --cert responder.crt --key responder.key --out response.ocsp

  # Revoked status with reason
  pki ocsp sign --serial 0A1B2C --status revoked --revocation-time 2024-01-15T10:00:00Z --revocation-reason keyCompromise --ca ca.crt --cert responder.crt --key responder.key --out response.ocsp

  # Unknown status
  pki ocsp sign --serial 0A1B2C --status unknown --ca ca.crt --key ca.key --out response.ocsp`,
	RunE: runOCSPSign,
}

// OCSP verify command
var ocspVerifyCmd = &cobra.Command{
	Use:   "verify <response-file>",
	Short: "Verify an OCSP response",
	Long: `Verify an OCSP response signature and display status.

Examples:
  # Verify response with CA certificate
  qpki ocsp verify response.ocsp --ca ca.crt

  # Verify and check against specific certificate
  qpki ocsp verify response.ocsp --ca ca.crt --cert server.crt`,
	Args: cobra.ExactArgs(1),
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
	ocspSignSerial           string
	ocspSignStatus           string
	ocspSignRevocationTime   string
	ocspSignRevocationReason string
	ocspSignCA               string
	ocspSignCert             string
	ocspSignKey              string
	ocspSignPassphrase       string
	ocspSignOutput           string
	ocspSignValidity         string
	ocspSignHSMConfig        string
	ocspSignKeyLabel         string
	ocspSignKeyID            string
	ocspSignCredential       string
	ocspSignCredDir          string

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
	ocspServeHSMConfig  string
	ocspServeKeyLabel   string
	ocspServeKeyID      string
	ocspServePIDFile    string
	ocspServeCredential string
	ocspServeCredDir    string

	// ocsp stop flags
	ocspStopPort    int
	ocspStopPIDFile string
)

func init() {
	// ocsp sign flags
	ocspSignCmd.Flags().StringVar(&ocspSignSerial, "serial", "", "Certificate serial number (hex)")
	ocspSignCmd.Flags().StringVar(&ocspSignStatus, "status", "good", "Certificate status (good, revoked, unknown)")
	ocspSignCmd.Flags().StringVar(&ocspSignRevocationTime, "revocation-time", "", "Revocation time (RFC3339 format)")
	ocspSignCmd.Flags().StringVar(&ocspSignRevocationReason, "revocation-reason", "", "Revocation reason (keyCompromise, caCompromise, affiliationChanged, superseded, cessationOfOperation, certificateHold, removeFromCRL, privilegeWithdrawn, aaCompromise)")
	ocspSignCmd.Flags().StringVar(&ocspSignCA, "ca", "", "CA certificate (PEM)")
	ocspSignCmd.Flags().StringVar(&ocspSignCert, "cert", "", "Responder certificate (PEM, optional)")
	ocspSignCmd.Flags().StringVar(&ocspSignKey, "key", "", "Responder private key (PEM, required unless --hsm-config)")
	ocspSignCmd.Flags().StringVar(&ocspSignPassphrase, "passphrase", "", "Key passphrase")
	ocspSignCmd.Flags().StringVarP(&ocspSignOutput, "out", "o", "", "Output file")
	ocspSignCmd.Flags().StringVar(&ocspSignValidity, "validity", "1h", "Response validity period")
	ocspSignCmd.Flags().StringVar(&ocspSignHSMConfig, "hsm-config", "", "HSM configuration file (YAML)")
	ocspSignCmd.Flags().StringVar(&ocspSignKeyLabel, "key-label", "", "HSM key label (CKA_LABEL)")
	ocspSignCmd.Flags().StringVar(&ocspSignKeyID, "key-id", "", "HSM key ID (CKA_ID, hex)")
	ocspSignCmd.Flags().StringVar(&ocspSignCredential, "credential", "", "Credential ID to use for signing (alternative to --cert/--key)")
	ocspSignCmd.Flags().StringVar(&ocspSignCredDir, "cred-dir", "./credentials", "Credentials directory")

	_ = ocspSignCmd.MarkFlagRequired("serial")
	_ = ocspSignCmd.MarkFlagRequired("ca")
	_ = ocspSignCmd.MarkFlagRequired("out")

	// ocsp verify flags
	ocspVerifyCmd.Flags().StringVar(&ocspVerifyCA, "ca", "", "CA certificate (PEM)")
	ocspVerifyCmd.Flags().StringVar(&ocspVerifyCert, "cert", "", "Certificate to verify (PEM, optional)")

	// ocsp serve flags
	ocspServeCmd.Flags().IntVar(&ocspServePort, "port", 8080, "HTTP port")
	ocspServeCmd.Flags().StringVar(&ocspServeCADir, "ca-dir", "", "CA directory (contains ca.crt, ca.key, index.txt)")
	ocspServeCmd.Flags().StringVar(&ocspServeCert, "cert", "", "Responder certificate (PEM, optional)")
	ocspServeCmd.Flags().StringVar(&ocspServeKey, "key", "", "Responder private key (PEM, optional unless --hsm-config)")
	ocspServeCmd.Flags().StringVar(&ocspServePassphrase, "passphrase", "", "Key passphrase")
	ocspServeCmd.Flags().StringVar(&ocspServeValidity, "validity", "1h", "Response validity period")
	ocspServeCmd.Flags().BoolVar(&ocspServeCopyNonce, "copy-nonce", true, "Copy nonce from request to response")
	ocspServeCmd.Flags().StringVar(&ocspServeHSMConfig, "hsm-config", "", "HSM configuration file (YAML)")
	ocspServeCmd.Flags().StringVar(&ocspServeKeyLabel, "key-label", "", "HSM key label (CKA_LABEL)")
	ocspServeCmd.Flags().StringVar(&ocspServeKeyID, "key-id", "", "HSM key ID (CKA_ID, hex)")
	ocspServeCmd.Flags().StringVar(&ocspServePIDFile, "pid-file", "", "PID file path (default: /tmp/qpki-ocsp-{port}.pid)")
	ocspServeCmd.Flags().StringVar(&ocspServeCredential, "credential", "", "Credential ID to use for signing (alternative to --cert/--key)")
	ocspServeCmd.Flags().StringVar(&ocspServeCredDir, "cred-dir", "./credentials", "Credentials directory")

	_ = ocspServeCmd.MarkFlagRequired("ca-dir")

	// Add subcommands
	ocspCmd.AddCommand(ocspSignCmd)
	ocspCmd.AddCommand(ocspVerifyCmd)
	ocspCmd.AddCommand(ocspServeCmd)
}

func runOCSPSign(cmd *cobra.Command, args []string) error {
	// Parse inputs
	serial, err := parseOCSPSerial(ocspSignSerial)
	if err != nil {
		return err
	}

	certStatus, err := parseOCSPCertStatus(ocspSignStatus)
	if err != nil {
		return err
	}

	var revocationTime time.Time
	if certStatus == ocsp.CertStatusRevoked {
		revocationTime, err = parseOCSPRevocationTime(ocspSignRevocationTime)
		if err != nil {
			return err
		}
	}

	// Load CA certificate
	caCert, err := loadCertificate(ocspSignCA)
	if err != nil {
		return fmt.Errorf("failed to load CA certificate: %w", err)
	}

	var responderCert *x509.Certificate
	var signer crypto.Signer

	// Load responder certificate and key from credential or from files
	if ocspSignCredential != "" {
		// Use credential store
		credDir, err := filepath.Abs(ocspSignCredDir)
		if err != nil {
			return fmt.Errorf("invalid credentials directory: %w", err)
		}
		store := credential.NewFileStore(credDir)
		passphrase := []byte(ocspSignPassphrase)

		responderCert, signer, err = credential.LoadSigner(cmd.Context(), store, ocspSignCredential, passphrase)
		if err != nil {
			return fmt.Errorf("failed to load credential %s: %w", ocspSignCredential, err)
		}

		// Validate certificate has OCSP signing EKU
		if err := credential.ValidateForOCSP(responderCert); err != nil {
			return fmt.Errorf("credential %s: %w", ocspSignCredential, err)
		}
	} else if ocspSignCert != "" {
		// Use certificate and key files
		responderCert, err = loadCertificate(ocspSignCert)
		if err != nil {
			return fmt.Errorf("failed to load responder certificate: %w", err)
		}

		signer, err = loadOCSPSigner(ocspSignHSMConfig, ocspSignKey, ocspSignPassphrase, ocspSignKeyLabel, ocspSignKeyID, responderCert)
		if err != nil {
			return err
		}
	} else {
		// CA-signed mode: use CA certificate
		responderCert = caCert
		signer, err = loadOCSPSigner(ocspSignHSMConfig, ocspSignKey, ocspSignPassphrase, ocspSignKeyLabel, ocspSignKeyID, responderCert)
		if err != nil {
			return err
		}
	}

	// Parse validity
	validity, err := time.ParseDuration(ocspSignValidity)
	if err != nil {
		return fmt.Errorf("invalid validity duration: %w", err)
	}

	// Build response
	params := &ocspSignParams{
		Serial:           serial,
		CertStatus:       certStatus,
		RevocationTime:   revocationTime,
		RevocationReason: parseOCSPRevocationReason(ocspSignRevocationReason),
		CACert:           caCert,
		ResponderCert:    responderCert,
		Signer:           signer,
		Validity:         validity,
	}

	responseData, err := buildOCSPSignResponse(params)
	if err != nil {
		return err
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

	printOCSPSignResult(ocspSignOutput, ocspSignSerial, certStatus, revocationTime, ocspSignRevocationReason, validity)
	return nil
}

func runOCSPVerify(cmd *cobra.Command, args []string) error {
	// Get response file from positional argument
	ocspVerifyResponse = args[0]

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
	store := ca.NewFileStore(ocspServeCADir)

	// Load CA certificate
	caCertPath := ocspServeCADir + "/ca.crt"
	caCert, err := loadCertificate(caCertPath)
	if err != nil {
		return fmt.Errorf("failed to load CA certificate: %w", err)
	}

	// Load responder certificate and key
	var responderCert *x509.Certificate
	var signer crypto.Signer

	if ocspServeCredential != "" {
		// Use credential store
		credDir, err := filepath.Abs(ocspServeCredDir)
		if err != nil {
			return fmt.Errorf("invalid credentials directory: %w", err)
		}
		credStore := credential.NewFileStore(credDir)
		passphrase := []byte(ocspServePassphrase)

		responderCert, signer, err = credential.LoadSigner(cmd.Context(), credStore, ocspServeCredential, passphrase)
		if err != nil {
			return fmt.Errorf("failed to load credential %s: %w", ocspServeCredential, err)
		}

		// Validate certificate has OCSP signing EKU
		if err := credential.ValidateForOCSP(responderCert); err != nil {
			return fmt.Errorf("credential %s: %w", ocspServeCredential, err)
		}
	} else if ocspServeCert != "" && (ocspServeKey != "" || ocspServeHSMConfig != "") {
		// Delegated responder mode
		responderCert, err = loadCertificate(ocspServeCert)
		if err != nil {
			return fmt.Errorf("failed to load responder certificate: %w", err)
		}

		var keyCfg pkicrypto.KeyStorageConfig
		if ocspServeHSMConfig != "" {
			// HSM mode
			hsmCfg, err := pkicrypto.LoadHSMConfig(ocspServeHSMConfig)
			if err != nil {
				return fmt.Errorf("failed to load HSM config: %w", err)
			}
			pin, err := hsmCfg.GetPIN()
			if err != nil {
				return fmt.Errorf("failed to get HSM PIN: %w", err)
			}
			keyCfg = pkicrypto.KeyStorageConfig{
				Type:           pkicrypto.KeyProviderTypePKCS11,
				PKCS11Lib:      hsmCfg.PKCS11.Lib,
				PKCS11Token:    hsmCfg.PKCS11.Token,
				PKCS11Pin:      pin,
				PKCS11KeyLabel: ocspServeKeyLabel,
				PKCS11KeyID:    ocspServeKeyID,
			}
			if keyCfg.PKCS11KeyLabel == "" && keyCfg.PKCS11KeyID == "" {
				return fmt.Errorf("--key-label or --key-id required with --hsm-config")
			}
		} else {
			// Software mode
			keyCfg = pkicrypto.KeyStorageConfig{
				Type:       pkicrypto.KeyProviderTypeSoftware,
				KeyPath:    ocspServeKey,
				Passphrase: ocspServePassphrase,
			}
		}
		km := pkicrypto.NewKeyProvider(keyCfg)
		signer, err = km.Load(keyCfg)
		if err != nil {
			return fmt.Errorf("failed to load responder key: %w", err)
		}
	} else {
		// CA-signed mode
		responderCert = caCert
		caKeyPath := ocspServeCADir + "/ca.key"
		keyCfg := pkicrypto.KeyStorageConfig{
			Type:       pkicrypto.KeyProviderTypeSoftware,
			KeyPath:    caKeyPath,
			Passphrase: ocspServePassphrase,
		}
		km := pkicrypto.NewKeyProvider(keyCfg)
		signer, err = km.Load(keyCfg)
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

	// Determine PID file path
	pidFile := ocspServePIDFile
	if pidFile == "" {
		pidFile = fmt.Sprintf("/tmp/qpki-ocsp-%d.pid", ocspServePort)
	}

	// Write PID file
	if err := writePIDFile(pidFile); err != nil {
		return fmt.Errorf("failed to write PID file: %w", err)
	}
	defer removePIDFile(pidFile)

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
	fmt.Printf("  PID File:   %s\n", pidFile)
	fmt.Printf("\nEndpoints:\n")
	fmt.Printf("  GET  /{base64-request}\n")
	fmt.Printf("  POST / (Content-Type: application/ocsp-request)\n")
	fmt.Printf("\nUse 'qpki ocsp stop --port %d' or Ctrl+C to stop\n", ocspServePort)

	addr := fmt.Sprintf(":%d", ocspServePort)
	server := &http.Server{
		Addr:    addr,
		Handler: handler,
	}

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	errChan := make(chan error, 1)
	go func() {
		errChan <- server.ListenAndServe()
	}()

	select {
	case err := <-errChan:
		if err != nil && err != http.ErrServerClosed {
			return err
		}
	case sig := <-sigChan:
		fmt.Printf("\nReceived signal %v, shutting down...\n", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			return fmt.Errorf("shutdown error: %w", err)
		}
		fmt.Println("OCSP responder stopped")
	}

	return nil
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
		responseData, err = h.responder.Respond(r.Context(), req)
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

// ocspStopCmd stops a running OCSP responder
var ocspStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop a running OCSP responder",
	Long: `Stop a running OCSP responder server.

The command reads the PID from the PID file and sends a SIGTERM signal.

Examples:
  # Stop responder on default port
  qpki ocsp stop --port 8080

  # Stop using custom PID file
  qpki ocsp stop --pid-file /var/run/ocsp.pid`,
	RunE: runOCSPStop,
}

func init() {
	ocspStopCmd.Flags().IntVar(&ocspStopPort, "port", 8080, "Port to derive default PID file path")
	ocspStopCmd.Flags().StringVar(&ocspStopPIDFile, "pid-file", "", "PID file path (default: /tmp/qpki-ocsp-{port}.pid)")

	ocspCmd.AddCommand(ocspStopCmd)
}

func runOCSPStop(cmd *cobra.Command, args []string) error {
	// Determine PID file path
	pidFile := ocspStopPIDFile
	if pidFile == "" {
		pidFile = fmt.Sprintf("/tmp/qpki-ocsp-%d.pid", ocspStopPort)
	}

	// Read PID from file
	pidData, err := os.ReadFile(pidFile)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("OCSP responder not running (PID file not found: %s)", pidFile)
		}
		return fmt.Errorf("failed to read PID file: %w", err)
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(pidData)))
	if err != nil {
		return fmt.Errorf("invalid PID in file: %w", err)
	}

	// Find the process
	process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("failed to find process %d: %w", pid, err)
	}

	// Send SIGTERM
	if err := process.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("failed to send signal to process %d: %w", pid, err)
	}

	fmt.Printf("Sent stop signal to OCSP responder (PID %d)\n", pid)
	return nil
}

// writePIDFile writes the current process PID to the specified file
func writePIDFile(path string) error {
	pid := os.Getpid()
	return os.WriteFile(path, []byte(strconv.Itoa(pid)), 0644)
}

// removePIDFile removes the PID file if it exists
func removePIDFile(path string) {
	_ = os.Remove(path)
}

// ocspRequestCmd creates an OCSP request
var ocspRequestCmd = &cobra.Command{
	Use:   "request",
	Short: "Create an OCSP request",
	Long: `Create an OCSP request for one or more certificates.

Examples:
  # Create request for a certificate
  pki ocsp request --issuer ca.crt --cert server.crt --out request.ocsp

  # Create request with nonce
  pki ocsp request --issuer ca.crt --cert server.crt --nonce --out request.ocsp`,
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
