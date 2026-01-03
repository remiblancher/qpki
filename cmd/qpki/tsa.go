package main

import (
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/remiblancher/post-quantum-pki/internal/audit"
	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
	"github.com/remiblancher/post-quantum-pki/internal/tsa"
)

var tsaCmd = &cobra.Command{
	Use:   "tsa",
	Short: "Timestamping operations (RFC 3161)",
	Long: `Timestamping Authority operations per RFC 3161.

This command provides:
  - sign:   Create a timestamp token for a file (CLI mode)
  - verify: Verify a timestamp token
  - serve:  Start an RFC 3161 HTTP server

Supports all PKI algorithms including post-quantum (ML-DSA, SLH-DSA).

Examples:
  # Sign a file locally
  pki tsa sign --data file.txt --cert tsa.crt --key tsa.key -o token.tsr

  # Verify a token
  pki tsa verify --token token.tsr --data file.txt --ca ca.crt

  # Start RFC 3161 server
  pki tsa serve --port 8318 --cert tsa.crt --key tsa.key`,
}

// TSA sign command
var tsaSignCmd = &cobra.Command{
	Use:   "sign",
	Short: "Create a timestamp token for a file",
	Long: `Create a timestamp token for a file.

The token contains a cryptographic proof that the data existed at a specific time.
Supports all PKI signature algorithms including post-quantum.

Examples:
  # Sign with SHA-256 hash
  pki tsa sign --data file.txt --cert tsa.crt --key tsa.key -o token.tsr

  # Sign with SHA-512 hash
  pki tsa sign --data file.txt --cert tsa.crt --key tsa.key --hash sha512 -o token.tsr

  # Sign with custom policy OID
  pki tsa sign --data file.txt --cert tsa.crt --key tsa.key --policy "1.3.6.1.4.1.99999.2.1" -o token.tsr`,
	RunE: runTSASign,
}

// TSA verify command
var tsaVerifyCmd = &cobra.Command{
	Use:   "verify <token-file>",
	Short: "Verify a timestamp token",
	Long: `Verify a timestamp token.

Verifies:
  - The token signature is valid
  - The signer certificate chain is trusted
  - The data hash matches the token (if --data provided)

Examples:
  # Verify token and data
  qpki tsa verify token.tsr --data file.txt --ca ca.crt

  # Verify token only (no data check)
  qpki tsa verify token.tsr --ca ca.crt`,
	Args: cobra.ExactArgs(1),
	RunE: runTSAVerify,
}

// TSA serve command
var tsaServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start RFC 3161 HTTP timestamp server",
	Long: `Start an RFC 3161 compliant HTTP timestamp server.

The server accepts POST requests with TimeStampReq and returns TimeStampResp.
Supports all PKI signature algorithms including post-quantum (ML-DSA).

HTTP API:
  POST / with Content-Type: application/timestamp-query
  Returns Content-Type: application/timestamp-reply

Examples:
  # Start server on port 8318
  pki tsa serve --port 8318 --cert tsa.crt --key tsa.key

  # With custom policy and accuracy
  pki tsa serve --port 8318 --cert tsa.crt --key tsa.key \
    --policy "1.3.6.1.4.1.99999.2.1" --accuracy 1

  # With TLS
  pki tsa serve --port 8318 --cert tsa.crt --key tsa.key \
    --tls-cert server.crt --tls-key server.key`,
	RunE: runTSAServe,
}

// TSA request command
var tsaRequestCmd = &cobra.Command{
	Use:   "request",
	Short: "Create a timestamp request",
	Long: `Create an RFC 3161 timestamp request for a file.

The request can be sent to a TSA server to obtain a timestamp token.

Examples:
  # Create request with SHA-256 hash
  pki tsa request --data file.txt -o request.tsq

  # Create request with SHA-512 hash
  pki tsa request --data file.txt --hash sha512 -o request.tsq

  # Create request with nonce
  pki tsa request --data file.txt --nonce -o request.tsq`,
	RunE: runTSARequest,
}

// TSA info command
var tsaInfoCmd = &cobra.Command{
	Use:   "info <token-file>",
	Short: "Display timestamp token information",
	Long: `Display detailed information about a timestamp token.

Shows serial number, generation time, policy, hash algorithm, and signer information.

Examples:
  qpki tsa info token.tsr`,
	Args: cobra.ExactArgs(1),
	RunE: runTSAInfo,
}

// Command flags
var (
	// tsa request flags
	tsaRequestData   string
	tsaRequestHash   string
	tsaRequestNonce  bool
	tsaRequestOutput string
	// tsa sign flags
	tsaSignData       string
	tsaSignCert       string
	tsaSignKey        string
	tsaSignPassphrase string
	tsaSignHash       string
	tsaSignPolicy     string
	tsaSignOutput     string
	tsaSignIncludeTSA bool
	tsaSignHSMConfig  string
	tsaSignKeyLabel   string
	tsaSignKeyID      string

	// tsa verify flags
	tsaVerifyToken string
	tsaVerifyData  string
	tsaVerifyCA    string

	// tsa serve flags
	tsaServePort       int
	tsaServeCert       string
	tsaServeKey        string
	tsaServePassphrase string
	tsaServePolicy     string
	tsaServeAccuracy   int
	tsaServeTLSCert    string
	tsaServeTLSKey     string
	tsaServeHSMConfig  string
	tsaServeKeyLabel   string
	tsaServeKeyID      string
)

func init() {
	// tsa sign flags
	tsaSignCmd.Flags().StringVar(&tsaSignData, "data", "", "File to timestamp (required)")
	tsaSignCmd.Flags().StringVar(&tsaSignCert, "cert", "", "TSA certificate (PEM)")
	tsaSignCmd.Flags().StringVar(&tsaSignKey, "key", "", "TSA private key (PEM, required unless --hsm-config)")
	tsaSignCmd.Flags().StringVar(&tsaSignPassphrase, "passphrase", "", "Key passphrase")
	tsaSignCmd.Flags().StringVar(&tsaSignHash, "hash", "sha256", "Hash algorithm (sha256, sha384, sha512)")
	tsaSignCmd.Flags().StringVar(&tsaSignPolicy, "policy", "1.3.6.1.4.1.99999.2.1", "TSA policy OID")
	tsaSignCmd.Flags().StringVarP(&tsaSignOutput, "out", "o", "", "Output file (required)")
	tsaSignCmd.Flags().BoolVar(&tsaSignIncludeTSA, "include-tsa", true, "Include TSA name in token")
	tsaSignCmd.Flags().StringVar(&tsaSignHSMConfig, "hsm-config", "", "HSM configuration file (YAML)")
	tsaSignCmd.Flags().StringVar(&tsaSignKeyLabel, "key-label", "", "HSM key label (CKA_LABEL)")
	tsaSignCmd.Flags().StringVar(&tsaSignKeyID, "key-id", "", "HSM key ID (CKA_ID, hex)")
	_ = tsaSignCmd.MarkFlagRequired("data")
	_ = tsaSignCmd.MarkFlagRequired("cert")
	_ = tsaSignCmd.MarkFlagRequired("out")

	// tsa verify flags
	tsaVerifyCmd.Flags().StringVar(&tsaVerifyData, "data", "", "Original data file")
	tsaVerifyCmd.Flags().StringVar(&tsaVerifyCA, "ca", "", "CA certificate(s) for verification")

	// tsa serve flags
	tsaServeCmd.Flags().IntVar(&tsaServePort, "port", 8318, "HTTP server port")
	tsaServeCmd.Flags().StringVar(&tsaServeCert, "cert", "", "TSA certificate (PEM)")
	tsaServeCmd.Flags().StringVar(&tsaServeKey, "key", "", "TSA private key (PEM, required unless --hsm-config)")
	tsaServeCmd.Flags().StringVar(&tsaServePassphrase, "passphrase", "", "Key passphrase")
	tsaServeCmd.Flags().StringVar(&tsaServePolicy, "policy", "1.3.6.1.4.1.99999.2.1", "TSA policy OID")
	tsaServeCmd.Flags().IntVar(&tsaServeAccuracy, "accuracy", 1, "Timestamp accuracy in seconds")
	tsaServeCmd.Flags().StringVar(&tsaServeTLSCert, "tls-cert", "", "TLS certificate for HTTPS")
	tsaServeCmd.Flags().StringVar(&tsaServeTLSKey, "tls-key", "", "TLS private key for HTTPS")
	tsaServeCmd.Flags().StringVar(&tsaServeHSMConfig, "hsm-config", "", "HSM configuration file (YAML)")
	tsaServeCmd.Flags().StringVar(&tsaServeKeyLabel, "key-label", "", "HSM key label (CKA_LABEL)")
	tsaServeCmd.Flags().StringVar(&tsaServeKeyID, "key-id", "", "HSM key ID (CKA_ID, hex)")
	_ = tsaServeCmd.MarkFlagRequired("cert")

	// tsa request flags
	tsaRequestCmd.Flags().StringVar(&tsaRequestData, "data", "", "File to timestamp (required)")
	tsaRequestCmd.Flags().StringVar(&tsaRequestHash, "hash", "sha256", "Hash algorithm (sha256, sha384, sha512)")
	tsaRequestCmd.Flags().BoolVar(&tsaRequestNonce, "nonce", false, "Include random nonce")
	tsaRequestCmd.Flags().StringVarP(&tsaRequestOutput, "out", "o", "", "Output file (required)")
	_ = tsaRequestCmd.MarkFlagRequired("data")
	_ = tsaRequestCmd.MarkFlagRequired("out")

	// Add subcommands
	tsaCmd.AddCommand(tsaRequestCmd)
	tsaCmd.AddCommand(tsaSignCmd)
	tsaCmd.AddCommand(tsaVerifyCmd)
	tsaCmd.AddCommand(tsaServeCmd)
	tsaCmd.AddCommand(tsaInfoCmd)
}

func runTSARequest(cmd *cobra.Command, args []string) error {
	// Load data
	data, err := os.ReadFile(tsaRequestData)
	if err != nil {
		return fmt.Errorf("failed to read data file: %w", err)
	}

	// Parse hash algorithm
	hashAlg, err := parseHashAlgorithm(tsaRequestHash)
	if err != nil {
		return err
	}

	// Generate nonce if requested
	var nonce *big.Int
	if tsaRequestNonce {
		nonce = big.NewInt(time.Now().UnixNano())
	}

	// Create request
	req, err := tsa.CreateRequest(data, hashAlg, nonce, false)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Marshal request
	reqData, err := req.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	// Write output
	if err := os.WriteFile(tsaRequestOutput, reqData, 0644); err != nil {
		return fmt.Errorf("failed to write request: %w", err)
	}

	fmt.Printf("Timestamp request written to %s\n", tsaRequestOutput)
	fmt.Printf("  Hash:  %s\n", tsaRequestHash)
	if tsaRequestNonce {
		fmt.Printf("  Nonce: %d\n", nonce)
	}

	return nil
}

func runTSASign(cmd *cobra.Command, args []string) error {
	// Load data to timestamp
	data, err := os.ReadFile(tsaSignData)
	if err != nil {
		return fmt.Errorf("failed to read data file: %w", err)
	}

	// Compute hash
	hashAlg, err := parseHashAlgorithm(tsaSignHash)
	if err != nil {
		return err
	}

	hash, err := computeFileHash(data, hashAlg)
	if err != nil {
		return fmt.Errorf("failed to compute hash: %w", err)
	}

	// Load certificate
	cert, err := loadCertificate(tsaSignCert)
	if err != nil {
		return fmt.Errorf("failed to load certificate: %w", err)
	}

	// Load private key using KeyManager
	var keyCfg pkicrypto.KeyStorageConfig
	if tsaSignHSMConfig != "" {
		// HSM mode
		hsmCfg, err := pkicrypto.LoadHSMConfig(tsaSignHSMConfig)
		if err != nil {
			return fmt.Errorf("failed to load HSM config: %w", err)
		}
		pin, err := hsmCfg.GetPIN()
		if err != nil {
			return fmt.Errorf("failed to get HSM PIN: %w", err)
		}
		keyCfg = pkicrypto.KeyStorageConfig{
			Type:           pkicrypto.KeyManagerTypePKCS11,
			PKCS11Lib:      hsmCfg.PKCS11.Lib,
			PKCS11Token:    hsmCfg.PKCS11.Token,
			PKCS11Pin:      pin,
			PKCS11KeyLabel: tsaSignKeyLabel,
			PKCS11KeyID:    tsaSignKeyID,
		}
		if keyCfg.PKCS11KeyLabel == "" && keyCfg.PKCS11KeyID == "" {
			return fmt.Errorf("--key-label or --key-id required with --hsm-config")
		}
	} else {
		// Software mode
		if tsaSignKey == "" {
			return fmt.Errorf("--key required for software mode (or use --hsm-config for HSM)")
		}
		keyCfg = pkicrypto.KeyStorageConfig{
			Type:       pkicrypto.KeyManagerTypeSoftware,
			KeyPath:    tsaSignKey,
			Passphrase: tsaSignPassphrase,
		}
	}
	km := pkicrypto.NewKeyManager(keyCfg)
	signer, err := km.Load(keyCfg)
	if err != nil {
		return fmt.Errorf("failed to load private key: %w", err)
	}

	// Parse policy OID
	policy, err := parseOID(tsaSignPolicy)
	if err != nil {
		return fmt.Errorf("invalid policy OID: %w", err)
	}

	// Create timestamp request
	req := &tsa.TimeStampReq{
		Version:        1,
		MessageImprint: tsa.NewMessageImprint(hashAlg, hash),
		Nonce:          big.NewInt(time.Now().UnixNano()),
		CertReq:        true,
	}

	// Create token
	config := &tsa.TokenConfig{
		Certificate: cert,
		Signer:      signer,
		Policy:      policy,
		IncludeTSA:  tsaSignIncludeTSA,
	}

	token, err := tsa.CreateToken(req, config, &tsa.RandomSerialGenerator{})
	if err != nil {
		return fmt.Errorf("failed to create token: %w", err)
	}

	// Create response
	resp := tsa.NewGrantedResponse(token)
	respData, err := resp.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal response: %w", err)
	}

	// Write output
	if err := os.WriteFile(tsaSignOutput, respData, 0644); err != nil {
		return fmt.Errorf("failed to write token: %w", err)
	}

	// Log audit event
	_ = audit.Log(audit.NewEvent(audit.EventTSASign, audit.ResultSuccess).
		WithObject(audit.Object{
			Type:   "token",
			Serial: token.SerialNumber().String(),
			Path:   tsaSignOutput,
		}).
		WithContext(audit.Context{
			Algorithm: tsaSignHash,
			Policy:    tsaSignPolicy,
			GenTime:   token.GenTime().Format(time.RFC3339),
		}))

	fmt.Printf("Timestamp token created:\n")
	fmt.Printf("  Serial:    %s\n", token.SerialNumber())
	fmt.Printf("  Time:      %s\n", token.GenTime().Format(time.RFC3339))
	fmt.Printf("  Policy:    %s\n", policy)
	fmt.Printf("  Hash:      %s\n", strings.ToUpper(tsaSignHash))
	fmt.Printf("  Output:    %s\n", tsaSignOutput)

	return nil
}

func runTSAVerify(cmd *cobra.Command, args []string) error {
	// Get token file from positional argument
	tsaVerifyToken = args[0]

	// Load token
	tokenData, err := os.ReadFile(tsaVerifyToken)
	if err != nil {
		return fmt.Errorf("failed to read token file: %w", err)
	}

	// Parse as response first (tokens from 'tsa sign' are TimeStampResp)
	resp, err := tsa.ParseResponse(tokenData)
	if err != nil {
		// Try parsing as raw token
		token, err := tsa.ParseToken(tokenData)
		if err != nil {
			return fmt.Errorf("failed to parse token: %w", err)
		}
		resp = &tsa.Response{Token: token}
	}

	if !resp.IsGranted() {
		return fmt.Errorf("token status: %s - %s", resp.StatusString(), resp.FailureString())
	}

	token := resp.Token
	if token == nil {
		return fmt.Errorf("no token in response")
	}

	// Load CA certificates
	var roots *x509.CertPool
	if tsaVerifyCA != "" {
		roots, err = loadCertPool(tsaVerifyCA)
		if err != nil {
			return fmt.Errorf("failed to load CA: %w", err)
		}
	}

	// Load data if provided
	var data []byte
	if tsaVerifyData != "" {
		data, err = os.ReadFile(tsaVerifyData)
		if err != nil {
			return fmt.Errorf("failed to read data file: %w", err)
		}
	}

	// Verify token
	config := &tsa.VerifyConfig{
		Roots: roots,
		Data:  data,
	}

	result, err := tsa.Verify(token.SignedData, config)
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	// Display results
	fmt.Println("Timestamp Token Verification:")
	fmt.Printf("  Status:     %s\n", formatBool(result.Verified, "VALID", "INVALID"))
	fmt.Printf("  Serial:     %s\n", token.SerialNumber())
	fmt.Printf("  Time:       %s\n", token.GenTime().Format(time.RFC3339))
	fmt.Printf("  Policy:     %s\n", token.Policy())

	if result.SignerCert != nil {
		fmt.Printf("  Signer:     %s\n", result.SignerCert.Subject.CommonName)
		fmt.Printf("  Issuer:     %s\n", result.SignerCert.Issuer.CommonName)
	}

	if len(data) > 0 {
		fmt.Printf("  Data Match: %s\n", formatBool(result.HashMatch, "YES", "NO"))
		if !result.HashMatch {
			return fmt.Errorf("data hash does not match token")
		}
	}

	// Log audit event
	_ = audit.Log(audit.NewEvent(audit.EventTSAVerify, audit.ResultSuccess).
		WithObject(audit.Object{
			Type:   "token",
			Serial: token.SerialNumber().String(),
			Path:   tsaVerifyToken,
		}).
		WithContext(audit.Context{
			GenTime:   token.GenTime().Format(time.RFC3339),
			Verified:  result.Verified,
			HashMatch: result.HashMatch,
		}))

	return nil
}

func runTSAInfo(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	// Read token file
	tokenData, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read token file: %w", err)
	}

	// Parse as response first (tokens from 'tsa sign' are TimeStampResp)
	resp, err := tsa.ParseResponse(tokenData)
	if err != nil {
		// Try parsing as raw token
		token, err := tsa.ParseToken(tokenData)
		if err != nil {
			return fmt.Errorf("failed to parse token: %w", err)
		}
		resp = &tsa.Response{Token: token}
	}

	// Display response status
	fmt.Println("Timestamp Response:")
	fmt.Printf("  Status:       %s\n", resp.StatusString())
	if !resp.IsGranted() {
		fmt.Printf("  Failure:      %s\n", resp.FailureString())
		return nil
	}

	token := resp.Token
	if token == nil {
		return fmt.Errorf("no token in response")
	}

	if token.Info == nil {
		return fmt.Errorf("no TSTInfo in token")
	}

	info := token.Info

	fmt.Println("\nTimestamp Token:")
	fmt.Printf("  Version:      %d\n", info.Version)
	fmt.Printf("  Serial:       %s\n", info.SerialNumber.String())
	fmt.Printf("  Gen Time:     %s\n", info.GenTime.Format(time.RFC3339))
	fmt.Printf("  Policy:       %s\n", info.Policy.String())

	// Display message imprint (hash info)
	hashAlg, err := token.HashAlgorithm()
	if err == nil {
		fmt.Printf("  Hash Alg:     %s\n", hashAlg.String())
	}

	// Display accuracy if present
	if !info.Accuracy.IsZero() {
		fmt.Printf("  Accuracy:     %ds %dms %dµs\n", info.Accuracy.Seconds, info.Accuracy.Millis, info.Accuracy.Micros)
	}

	// Display ordering flag
	fmt.Printf("  Ordering:     %v\n", info.Ordering)

	// Display nonce if present
	if info.Nonce != nil {
		fmt.Printf("  Nonce:        %s\n", info.Nonce.String())
	}

	return nil
}

func runTSAServe(cmd *cobra.Command, args []string) error {
	// Load certificate
	cert, err := loadCertificate(tsaServeCert)
	if err != nil {
		return fmt.Errorf("failed to load certificate: %w", err)
	}

	// Verify TSA certificate has timeStamping EKU
	hasTimestampEKU := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageTimeStamping {
			hasTimestampEKU = true
			break
		}
	}
	if !hasTimestampEKU {
		fmt.Println("WARNING: Certificate does not have timeStamping EKU")
	}

	// Load private key using KeyManager
	var keyCfg pkicrypto.KeyStorageConfig
	if tsaServeHSMConfig != "" {
		// HSM mode
		hsmCfg, err := pkicrypto.LoadHSMConfig(tsaServeHSMConfig)
		if err != nil {
			return fmt.Errorf("failed to load HSM config: %w", err)
		}
		pin, err := hsmCfg.GetPIN()
		if err != nil {
			return fmt.Errorf("failed to get HSM PIN: %w", err)
		}
		keyCfg = pkicrypto.KeyStorageConfig{
			Type:           pkicrypto.KeyManagerTypePKCS11,
			PKCS11Lib:      hsmCfg.PKCS11.Lib,
			PKCS11Token:    hsmCfg.PKCS11.Token,
			PKCS11Pin:      pin,
			PKCS11KeyLabel: tsaServeKeyLabel,
			PKCS11KeyID:    tsaServeKeyID,
		}
		if keyCfg.PKCS11KeyLabel == "" && keyCfg.PKCS11KeyID == "" {
			return fmt.Errorf("--key-label or --key-id required with --hsm-config")
		}
	} else {
		// Software mode
		if tsaServeKey == "" {
			return fmt.Errorf("--key required for software mode (or use --hsm-config for HSM)")
		}
		keyCfg = pkicrypto.KeyStorageConfig{
			Type:       pkicrypto.KeyManagerTypeSoftware,
			KeyPath:    tsaServeKey,
			Passphrase: tsaServePassphrase,
		}
	}
	km := pkicrypto.NewKeyManager(keyCfg)
	signer, err := km.Load(keyCfg)
	if err != nil {
		return fmt.Errorf("failed to load private key: %w", err)
	}

	// Parse policy OID
	policy, err := parseOID(tsaServePolicy)
	if err != nil {
		return fmt.Errorf("invalid policy OID: %w", err)
	}

	// Create TSA server
	server := &tsaServer{
		cert:      cert,
		signer:    signer,
		policy:    policy,
		accuracy:  tsaServeAccuracy,
		serialGen: &tsa.RandomSerialGenerator{},
	}

	// Create HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/", server.handleRequest)

	addr := fmt.Sprintf(":%d", tsaServePort)

	fmt.Printf("Starting RFC 3161 Timestamp Server\n")
	fmt.Printf("  Address:    http://localhost%s/\n", addr)
	fmt.Printf("  Policy:     %s\n", policy)
	fmt.Printf("  Accuracy:   %d seconds\n", tsaServeAccuracy)
	fmt.Printf("  Algorithm:  %s\n", cert.SignatureAlgorithm)
	fmt.Printf("\nUse Ctrl+C to stop\n\n")

	// Log startup
	_ = audit.Log(audit.NewEvent(audit.EventTSAServe, audit.ResultSuccess).
		WithObject(audit.Object{
			Type: "server",
			Path: addr,
		}).
		WithContext(audit.Context{
			Policy:   tsaServePolicy,
			Accuracy: tsaServeAccuracy,
		}))

	if tsaServeTLSCert != "" && tsaServeTLSKey != "" {
		fmt.Println("TLS enabled")
		return http.ListenAndServeTLS(addr, tsaServeTLSCert, tsaServeTLSKey, mux)
	}

	return http.ListenAndServe(addr, mux)
}

// tsaServer implements the RFC 3161 HTTP handler
type tsaServer struct {
	cert      *x509.Certificate
	signer    crypto.Signer
	policy    asn1.ObjectIdentifier
	accuracy  int
	serialGen tsa.SerialGenerator
}

func (s *tsaServer) handleRequest(w http.ResponseWriter, r *http.Request) {
	// Only accept POST
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check content type
	contentType := r.Header.Get("Content-Type")
	if !strings.HasPrefix(contentType, "application/timestamp-query") {
		http.Error(w, "Invalid content type", http.StatusBadRequest)
		return
	}

	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.sendError(w, tsa.FailBadDataFormat, "Failed to read request")
		return
	}

	// Parse timestamp request
	req, err := tsa.ParseRequest(body)
	if err != nil {
		s.sendError(w, tsa.FailBadDataFormat, err.Error())
		return
	}

	// Log request
	_ = audit.Log(audit.NewEvent(audit.EventTSARequest, audit.ResultSuccess).
		WithActor(audit.Actor{
			Type: "client",
			ID:   r.RemoteAddr,
		}).
		WithObject(audit.Object{
			Type: "request",
		}).
		WithContext(audit.Context{
			Algorithm: req.MessageImprint.HashAlgorithm.Algorithm.String(),
		}))

	// Create token
	config := &tsa.TokenConfig{
		Certificate: s.cert,
		Signer:      s.signer,
		Policy:      s.policy,
		Accuracy:    tsa.Accuracy{Seconds: s.accuracy},
		IncludeTSA:  true,
	}

	token, err := tsa.CreateToken(req, config, s.serialGen)
	if err != nil {
		s.sendError(w, tsa.FailSystemFailure, err.Error())
		return
	}

	// Create response
	resp := tsa.NewGrantedResponse(token)
	respData, err := resp.Marshal()
	if err != nil {
		s.sendError(w, tsa.FailSystemFailure, err.Error())
		return
	}

	// Log response
	_ = audit.Log(audit.NewEvent(audit.EventTSAResponse, audit.ResultSuccess).
		WithObject(audit.Object{
			Type:   "token",
			Serial: token.SerialNumber().String(),
		}).
		WithContext(audit.Context{
			GenTime: token.GenTime().Format(time.RFC3339),
		}))

	// Send response
	w.Header().Set("Content-Type", "application/timestamp-reply")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respData)
}

func (s *tsaServer) sendError(w http.ResponseWriter, failInfo int, message string) {
	resp := tsa.NewRejectionResponse(failInfo, message)
	respData, _ := resp.Marshal()

	_ = audit.Log(audit.NewEvent(audit.EventTSAResponse, audit.ResultFailure).
		WithObject(audit.Object{
			Type: "token",
		}).
		WithContext(audit.Context{
			Reason: message,
		}))

	w.Header().Set("Content-Type", "application/timestamp-reply")
	w.WriteHeader(http.StatusOK) // RFC 3161 returns 200 even for rejections
	_, _ = w.Write(respData)
}

// Helper functions

func parseHashAlgorithm(name string) (crypto.Hash, error) {
	switch strings.ToLower(name) {
	case "sha256", "sha-256":
		return crypto.SHA256, nil
	case "sha384", "sha-384":
		return crypto.SHA384, nil
	case "sha512", "sha-512":
		return crypto.SHA512, nil
	case "sha3-256":
		return crypto.SHA3_256, nil
	case "sha3-384":
		return crypto.SHA3_384, nil
	case "sha3-512":
		return crypto.SHA3_512, nil
	default:
		return 0, fmt.Errorf("unsupported hash algorithm: %s", name)
	}
}

func computeFileHash(data []byte, alg crypto.Hash) ([]byte, error) {
	switch alg {
	case crypto.SHA256:
		h := sha256.Sum256(data)
		return h[:], nil
	case crypto.SHA384:
		h := sha512.Sum384(data)
		return h[:], nil
	case crypto.SHA512:
		h := sha512.Sum512(data)
		return h[:], nil
	default:
		return nil, fmt.Errorf("unsupported hash algorithm: %v", alg)
	}
}

func loadCertificate(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}

	return x509.ParseCertificate(block.Bytes)
}

func loadCertPool(path string) (*x509.CertPool, error) {
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

func parseOID(s string) (asn1.ObjectIdentifier, error) {
	var oid asn1.ObjectIdentifier
	parts := strings.Split(s, ".")
	for _, p := range parts {
		var n int
		if _, err := fmt.Sscanf(p, "%d", &n); err != nil {
			return nil, fmt.Errorf("invalid OID component: %s", p)
		}
		oid = append(oid, n)
	}
	return oid, nil
}

func formatBool(b bool, t, f string) string {
	if b {
		return t
	}
	return f
}
