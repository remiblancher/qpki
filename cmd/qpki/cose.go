package main

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/remiblancher/qpki/pkg/audit"
	"github.com/remiblancher/qpki/pkg/cose"
	"github.com/remiblancher/qpki/pkg/credential"
)

var coseCmd = &cobra.Command{
	Use:   "cose",
	Short: "COSE/CWT operations (RFC 9052, RFC 8392)",
	Long: `COSE (CBOR Object Signing) and CWT (CBOR Web Token) operations.

This command provides:
  - sign:   Create COSE Sign1, Sign, or CWT messages
  - verify: Verify COSE signed messages
  - info:   Display message information

Supports classical, post-quantum (ML-DSA, SLH-DSA), and hybrid cryptography.

Message Types:
  - cwt:   CBOR Web Token (RFC 8392) - signed claims for auth/IAM
  - sign1: COSE Sign1 (RFC 9052) - single signature on arbitrary data
  - sign:  COSE Sign (RFC 9052) - multiple signatures (hybrid mode)

Examples:
  # Create a CWT with claims
  qpki cose sign --type cwt --iss "https://issuer.example.com" --sub "user-42" \
    --exp 1h --cert signer.crt --key signer.key -o token.cbor

  # Create a COSE Sign1 message
  qpki cose sign --type sign1 --data file.txt --cert signer.crt --key signer.key -o signed.cbor

  # Create a hybrid CWT (classical + PQC signatures)
  qpki cose sign --type cwt --iss "https://issuer.example.com" --sub "user-42" \
    --cert classical.crt --key classical.key \
    --pqc-cert pqc.crt --pqc-key pqc.key -o hybrid-token.cbor

  # Verify a CWT
  qpki cose verify token.cbor --ca ca.crt

  # Display message info
  qpki cose info token.cbor`,
}

// COSE sign command
var coseSignCmd = &cobra.Command{
	Use:   "sign",
	Short: "Create a COSE signed message or CWT",
	Long: `Create a COSE Sign1, Sign, or CWT message.

For CWT (CBOR Web Token), provide claims using --iss, --sub, --aud, --exp, and --claim.
For Sign1/Sign, provide the data to sign using --data.

Signing Mode:
  - Classical: Use --cert and --key for ECDSA, Ed25519, or RSA
  - PQC:       Use --cert and --key with ML-DSA or SLH-DSA keys
  - Hybrid:    Use both --cert/--key (classical) and --pqc-cert/--pqc-key (PQC)

Custom Claims:
  Use --claim to add custom claims with negative integer keys (private-use space).
  Format: --claim "-1=value" --claim "-2=another"

Examples:
  # CWT with 1-hour expiration
  qpki cose sign --type cwt --iss "https://auth.example.com" --sub "user123" \
    --exp 1h --cert signer.crt --key signer.key -o token.cbor

  # CWT with custom claims
  qpki cose sign --type cwt --iss "https://auth.example.com" --sub "user123" \
    --exp 24h --claim "-1=admin" --claim "-2=tenant-acme" \
    --cert signer.crt --key signer.key -o token.cbor

  # Sign arbitrary data
  qpki cose sign --type sign1 --data document.pdf --cert signer.crt --key signer.key -o doc.cbor

  # Hybrid signature (classical + PQC)
  qpki cose sign --type cwt --iss "https://auth.example.com" --sub "user123" --exp 1h \
    --cert classical.crt --key classical.key \
    --pqc-cert mldsa.crt --pqc-key mldsa.key -o hybrid.cbor`,
	RunE: runCOSESign,
}

// COSE verify command
var coseVerifyCmd = &cobra.Command{
	Use:   "verify <message-file>",
	Short: "Verify a COSE signed message or CWT",
	Long: `Verify a COSE Sign1, Sign, or CWT message.

For CWT, validates both the signature and the time-based claims (exp, nbf).
Use --no-check-exp to skip expiration checking.

For hybrid messages (COSE Sign), ALL signatures must be valid.

Examples:
  # Verify a CWT
  qpki cose verify token.cbor --ca ca.crt

  # Verify without checking expiration
  qpki cose verify token.cbor --ca ca.crt --no-check-exp

  # Verify with explicit public key
  qpki cose verify signed.cbor --cert signer.crt`,
	Args: cobra.ExactArgs(1),
	RunE: runCOSEVerify,
}

// COSE info command
var coseInfoCmd = &cobra.Command{
	Use:   "info <message-file>",
	Short: "Display COSE message information",
	Long: `Display detailed information about a COSE message.

Shows message type, signing mode, algorithms, claims (for CWT),
certificates, and payload information.

Examples:
  qpki cose info token.cbor
  qpki cose info signed.cbor`,
	Args: cobra.ExactArgs(1),
	RunE: runCOSEInfo,
}

// Command flags
var (
	// cose sign flags
	coseSignType         string
	coseSignData         string
	coseSignCert         string
	coseSignKey          string
	coseSignPQCCert      string
	coseSignPQCKey       string
	coseSignPassphrase   string
	coseSignOutput       string
	coseSignIss          string
	coseSignSub          string
	coseSignAud          string
	coseSignExp          string
	coseSignClaims       []string
	coseSignIncludeCerts bool
	coseSignHSMConfig    string
	coseSignKeyLabel     string
	coseSignKeyID        string
	coseSignCredential   string
	coseSignCredDir      string

	// cose verify flags
	coseVerifyCert      string
	coseVerifyCA        string
	coseVerifyData      string
	coseVerifyNoCheckExp bool

	// cose info flags - none needed
)

func init() {
	// cose sign flags
	coseSignCmd.Flags().StringVar(&coseSignType, "type", "cwt", "Message type: cwt, sign1, sign")
	coseSignCmd.Flags().StringVar(&coseSignData, "data", "", "Data file to sign (for sign1/sign types)")
	coseSignCmd.Flags().StringVar(&coseSignCert, "cert", "", "Signer certificate (PEM)")
	coseSignCmd.Flags().StringVar(&coseSignKey, "key", "", "Signer private key (PEM)")
	coseSignCmd.Flags().StringVar(&coseSignPQCCert, "pqc-cert", "", "PQC signer certificate for hybrid mode (PEM)")
	coseSignCmd.Flags().StringVar(&coseSignPQCKey, "pqc-key", "", "PQC signer private key for hybrid mode (PEM)")
	coseSignCmd.Flags().StringVar(&coseSignPassphrase, "passphrase", "", "Key passphrase")
	coseSignCmd.Flags().StringVarP(&coseSignOutput, "out", "o", "", "Output file (required)")
	coseSignCmd.Flags().StringVar(&coseSignIss, "iss", "", "CWT issuer claim")
	coseSignCmd.Flags().StringVar(&coseSignSub, "sub", "", "CWT subject claim")
	coseSignCmd.Flags().StringVar(&coseSignAud, "aud", "", "CWT audience claim")
	coseSignCmd.Flags().StringVar(&coseSignExp, "exp", "", "CWT expiration (duration: 1h, 24h, 30m)")
	coseSignCmd.Flags().StringArrayVar(&coseSignClaims, "claim", nil, "Custom claims (format: key=value, e.g. -1=admin)")
	coseSignCmd.Flags().BoolVar(&coseSignIncludeCerts, "include-certs", false, "Include certificate chain in message")
	coseSignCmd.Flags().StringVar(&coseSignHSMConfig, "hsm-config", "", "HSM configuration file (YAML)")
	coseSignCmd.Flags().StringVar(&coseSignKeyLabel, "key-label", "", "HSM key label (CKA_LABEL)")
	coseSignCmd.Flags().StringVar(&coseSignKeyID, "key-id", "", "HSM key ID (CKA_ID, hex)")
	coseSignCmd.Flags().StringVar(&coseSignCredential, "credential", "", "Credential ID to use for signing")
	coseSignCmd.Flags().StringVar(&coseSignCredDir, "cred-dir", "./credentials", "Credentials directory")
	_ = coseSignCmd.MarkFlagRequired("out")

	// cose verify flags
	coseVerifyCmd.Flags().StringVar(&coseVerifyCert, "cert", "", "Signer certificate for verification (PEM)")
	coseVerifyCmd.Flags().StringVar(&coseVerifyCA, "ca", "", "CA certificate(s) for chain verification")
	coseVerifyCmd.Flags().StringVar(&coseVerifyData, "data", "", "Original data file (for detached signatures)")
	coseVerifyCmd.Flags().BoolVar(&coseVerifyNoCheckExp, "no-check-exp", false, "Skip expiration checking for CWT")

	// Add subcommands
	coseCmd.AddCommand(coseSignCmd)
	coseCmd.AddCommand(coseVerifyCmd)
	coseCmd.AddCommand(coseInfoCmd)
}

func runCOSESign(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	// Determine message type
	var msgType cose.MessageType
	switch strings.ToLower(coseSignType) {
	case "cwt":
		msgType = cose.TypeCWT
	case "sign1":
		msgType = cose.TypeSign1
	case "sign":
		msgType = cose.TypeSign
	default:
		return fmt.Errorf("invalid message type: %s (use cwt, sign1, or sign)", coseSignType)
	}

	// Load certificate and key
	var cert *x509.Certificate
	var signer crypto.Signer
	var pqcCert *x509.Certificate
	var pqcSigner crypto.Signer
	var err error

	// Load from credential or from files
	if coseSignCredential != "" {
		credDir, err := filepath.Abs(coseSignCredDir)
		if err != nil {
			return fmt.Errorf("invalid credentials directory: %w", err)
		}
		store := credential.NewFileStore(credDir)
		passphrase := []byte(coseSignPassphrase)

		cert, signer, err = credential.LoadSigner(ctx, store, coseSignCredential, passphrase)
		if err != nil {
			return fmt.Errorf("failed to load credential %s: %w", coseSignCredential, err)
		}
	} else if coseSignCert != "" {
		cert, err = loadCertificate(coseSignCert)
		if err != nil {
			return fmt.Errorf("failed to load certificate: %w", err)
		}

		signer, err = loadSigningKey(coseSignHSMConfig, coseSignKey, coseSignPassphrase, coseSignKeyLabel, coseSignKeyID, cert)
		if err != nil {
			return fmt.Errorf("failed to load private key: %w", err)
		}
	}

	// Load PQC key pair for hybrid mode
	if coseSignPQCCert != "" {
		pqcCert, err = loadCertificate(coseSignPQCCert)
		if err != nil {
			return fmt.Errorf("failed to load PQC certificate: %w", err)
		}
	}
	if coseSignPQCKey != "" {
		pqcSigner, err = loadSigningKey("", coseSignPQCKey, coseSignPassphrase, "", "", pqcCert)
		if err != nil {
			return fmt.Errorf("failed to load PQC private key: %w", err)
		}
	}

	// Require at least one signer
	if signer == nil && pqcSigner == nil {
		return fmt.Errorf("either --cert/--key, --credential, or --pqc-cert/--pqc-key is required")
	}

	var output []byte

	switch msgType {
	case cose.TypeCWT:
		// Build claims
		claims := cose.NewClaims()
		claims.Issuer = coseSignIss
		claims.Subject = coseSignSub
		claims.Audience = coseSignAud

		// Parse expiration
		if coseSignExp != "" {
			exp, err := time.ParseDuration(coseSignExp)
			if err != nil {
				return fmt.Errorf("invalid expiration duration: %w", err)
			}
			claims.SetExpiration(exp)
		}

		// Parse custom claims
		for _, claimStr := range coseSignClaims {
			parts := strings.SplitN(claimStr, "=", 2)
			if len(parts) != 2 {
				return fmt.Errorf("invalid claim format: %s (use key=value)", claimStr)
			}
			key, err := strconv.ParseInt(parts[0], 10, 64)
			if err != nil {
				return fmt.Errorf("invalid claim key: %s (must be integer)", parts[0])
			}
			if err := claims.SetCustom(key, parts[1]); err != nil {
				return fmt.Errorf("failed to set claim: %w", err)
			}
		}

		config := &cose.CWTConfig{
			MessageConfig: cose.MessageConfig{
				Type:             msgType,
				Certificate:      cert,
				Signer:           signer,
				PQCCertificate:   pqcCert,
				PQCSigner:        pqcSigner,
				IncludeCertChain: coseSignIncludeCerts,
			},
			Claims:       claims,
			AutoIssuedAt: true,
			AutoCWTID:    true,
		}

		output, err = cose.IssueCWT(ctx, config)
		if err != nil {
			return fmt.Errorf("failed to create CWT: %w", err)
		}

	case cose.TypeSign1, cose.TypeSign:
		// Read data to sign
		if coseSignData == "" {
			return fmt.Errorf("--data is required for sign1/sign message types")
		}
		data, err := os.ReadFile(coseSignData)
		if err != nil {
			return fmt.Errorf("failed to read data file: %w", err)
		}

		config := &cose.MessageConfig{
			Type:             msgType,
			Certificate:      cert,
			Signer:           signer,
			PQCCertificate:   pqcCert,
			PQCSigner:        pqcSigner,
			IncludeCertChain: coseSignIncludeCerts,
		}

		if msgType == cose.TypeSign || (signer != nil && pqcSigner != nil) {
			output, err = cose.IssueSign(ctx, data, config)
		} else {
			output, err = cose.IssueSign1(ctx, data, config)
		}
		if err != nil {
			return fmt.Errorf("failed to create COSE message: %w", err)
		}
	}

	// Write output
	if err := os.WriteFile(coseSignOutput, output, 0644); err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}

	// Audit log
	mode := "classical"
	if signer != nil && pqcSigner != nil {
		mode = "hybrid"
	} else if pqcSigner != nil {
		mode = "pqc"
	}
	_ = audit.Log(audit.NewEvent(audit.EventCOSESign, audit.ResultSuccess).
		WithContext(audit.Context{Reason: fmt.Sprintf("type=%s, mode=%s, output=%s", msgType.String(), mode, coseSignOutput)}))

	fmt.Printf("Created %s message: %s\n", msgType, coseSignOutput)
	return nil
}

func runCOSEVerify(cmd *cobra.Command, args []string) error {
	inputFile := args[0]

	// Read message
	data, err := os.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read message file: %w", err)
	}

	// Build verification config
	config := &cose.VerifyConfig{
		CheckExpiration: !coseVerifyNoCheckExp,
	}

	// Load CA certificates
	if coseVerifyCA != "" {
		pool, certs, err := loadCertPoolWithCerts(coseVerifyCA)
		if err != nil {
			return fmt.Errorf("failed to load CA certificates: %w", err)
		}
		config.Roots = pool
		config.RootCerts = certs // Needed for PQC certificate chain verification
	}

	// Load signer certificate
	if coseVerifyCert != "" {
		cert, err := loadCertificate(coseVerifyCert)
		if err != nil {
			return fmt.Errorf("failed to load certificate: %w", err)
		}
		config.Certificate = cert
	}

	// Auto-detect message type and verify appropriately
	var result *cose.VerifyResult

	// Try CWT first (includes claims validation)
	result, err = cose.VerifyCWT(data, config)
	if err != nil {
		// If CWT parsing failed (e.g., payload is not CWT claims), try Sign1/Sign
		result, err = cose.VerifySign1(data, config)
		if err != nil {
			result, err = cose.VerifySign(data, config)
			if err != nil {
				return fmt.Errorf("verification failed: %w", err)
			}
		}
	}

	// Print result
	if result.Valid {
		fmt.Println("Verification: VALID")
	} else {
		fmt.Println("Verification: INVALID")
		for _, w := range result.Warnings {
			fmt.Printf("  - %s\n", w)
		}
	}

	fmt.Printf("Mode: %s\n", result.Mode)
	fmt.Printf("Algorithms: ")
	for i, alg := range result.Algorithms {
		if i > 0 {
			fmt.Print(", ")
		}
		fmt.Print(cose.AlgorithmName(alg))
	}
	fmt.Println()

	if result.Claims != nil {
		fmt.Println("\nCWT Claims:")
		if result.Claims.Issuer != "" {
			fmt.Printf("  Issuer:  %s\n", result.Claims.Issuer)
		}
		if result.Claims.Subject != "" {
			fmt.Printf("  Subject: %s\n", result.Claims.Subject)
		}
		if !result.Claims.Expiration.IsZero() {
			status := ""
			if result.Claims.IsExpired() {
				status = " [EXPIRED]"
			}
			fmt.Printf("  Expires: %s%s\n", result.Claims.Expiration.Format(time.RFC3339), status)
		}
	}

	// Audit log
	auditResult := audit.ResultSuccess
	if !result.Valid {
		auditResult = audit.ResultFailure
	}
	_ = audit.Log(audit.NewEvent(audit.EventCOSEVerify, auditResult).
		WithContext(audit.Context{Reason: fmt.Sprintf("input=%s, mode=%s", inputFile, result.Mode.String())}))

	if !result.Valid {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

// loadCertPoolWithCerts loads certificates from a PEM file and returns both
// a CertPool and the individual certificates. This is needed for PQC certificate
// chain verification since Go's CertPool doesn't expose the certificates directly.
func loadCertPoolWithCerts(path string) (*x509.CertPool, []*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}

	pool := x509.NewCertPool()
	var certs []*x509.Certificate

	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
			}
			pool.AddCert(cert)
			certs = append(certs, cert)
		}
		data = rest
	}

	if len(certs) == 0 {
		return nil, nil, fmt.Errorf("no certificates found in %s", path)
	}

	return pool, certs, nil
}

func runCOSEInfo(cmd *cobra.Command, args []string) error {
	inputFile := args[0]

	// Read message
	data, err := os.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read message file: %w", err)
	}

	// Get and print info
	info, err := cose.GetInfo(data)
	if err != nil {
		return fmt.Errorf("failed to parse message: %w", err)
	}

	info.Print(os.Stdout)
	return nil
}
