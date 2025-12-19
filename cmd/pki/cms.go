package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/remiblancher/pki/internal/audit"
	"github.com/remiblancher/pki/internal/cms"
	pkicrypto "github.com/remiblancher/pki/internal/crypto"
)

var cmsCmd = &cobra.Command{
	Use:   "cms",
	Short: "CMS SignedData operations (RFC 5652)",
	Long: `CMS (Cryptographic Message Syntax) operations per RFC 5652.

This command provides:
  - sign:   Create a CMS SignedData signature
  - verify: Verify a CMS SignedData signature

Supports all PKI algorithms including post-quantum (ML-DSA, SLH-DSA).

Examples:
  # Sign a file (detached signature)
  pki cms sign --data file.txt --cert signer.crt --key signer.key -o file.p7s

  # Sign with attached content
  pki cms sign --data file.txt --cert signer.crt --key signer.key --detached=false -o file.p7s

  # Verify a detached signature
  pki cms verify --signature file.p7s --data file.txt --ca ca.crt

  # Verify with attached content
  pki cms verify --signature file.p7s --ca ca.crt`,
}

// CMS sign command
var cmsSignCmd = &cobra.Command{
	Use:   "sign",
	Short: "Create a CMS SignedData signature",
	Long: `Create a CMS SignedData signature for a file.

By default, creates a detached signature (content not included in output).
Use --detached=false to include the content in the SignedData structure.

Supports all PKI signature algorithms including post-quantum.

Examples:
  # Detached signature (default)
  pki cms sign --data file.txt --cert signer.crt --key signer.key -o file.p7s

  # Attached signature
  pki cms sign --data file.txt --cert signer.crt --key signer.key --detached=false -o file.p7s

  # With SHA-512 hash
  pki cms sign --data file.txt --cert signer.crt --key signer.key --hash sha512 -o file.p7s

  # Include certificate chain
  pki cms sign --data file.txt --cert signer.crt --key signer.key --include-certs -o file.p7s`,
	RunE: runCMSSign,
}

// CMS verify command
var cmsVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify a CMS SignedData signature",
	Long: `Verify a CMS SignedData signature.

For detached signatures, provide the original data with --data.
For attached signatures, the data is extracted from the SignedData structure.

Examples:
  # Verify detached signature
  pki cms verify --signature file.p7s --data file.txt --ca ca.crt

  # Verify attached signature (data extracted automatically)
  pki cms verify --signature file.p7s --ca ca.crt

  # Verify without CA check (signature only)
  pki cms verify --signature file.p7s --data file.txt`,
	RunE: runCMSVerify,
}

// Command flags
var (
	// cms sign flags
	cmsSignData         string
	cmsSignCert         string
	cmsSignKey          string
	cmsSignPassphrase   string
	cmsSignHash         string
	cmsSignOutput       string
	cmsSignDetached     bool
	cmsSignIncludeCerts bool

	// cms verify flags
	cmsVerifySignature string
	cmsVerifyData      string
	cmsVerifyCA        string
)

func init() {
	// cms sign flags
	cmsSignCmd.Flags().StringVar(&cmsSignData, "data", "", "File to sign (required)")
	cmsSignCmd.Flags().StringVar(&cmsSignCert, "cert", "", "Signer certificate (PEM)")
	cmsSignCmd.Flags().StringVar(&cmsSignKey, "key", "", "Signer private key (PEM)")
	cmsSignCmd.Flags().StringVar(&cmsSignPassphrase, "passphrase", "", "Key passphrase")
	cmsSignCmd.Flags().StringVar(&cmsSignHash, "hash", "sha256", "Hash algorithm (sha256, sha384, sha512)")
	cmsSignCmd.Flags().StringVarP(&cmsSignOutput, "out", "o", "", "Output file (required)")
	cmsSignCmd.Flags().BoolVar(&cmsSignDetached, "detached", true, "Create detached signature (content not included)")
	cmsSignCmd.Flags().BoolVar(&cmsSignIncludeCerts, "include-certs", true, "Include signer certificate in output")

	_ = cmsSignCmd.MarkFlagRequired("data")
	_ = cmsSignCmd.MarkFlagRequired("cert")
	_ = cmsSignCmd.MarkFlagRequired("key")
	_ = cmsSignCmd.MarkFlagRequired("out")

	// cms verify flags
	cmsVerifyCmd.Flags().StringVar(&cmsVerifySignature, "signature", "", "Signature file (.p7s)")
	cmsVerifyCmd.Flags().StringVar(&cmsVerifyData, "data", "", "Original data file (for detached signatures)")
	cmsVerifyCmd.Flags().StringVar(&cmsVerifyCA, "ca", "", "CA certificate for chain verification")

	_ = cmsVerifyCmd.MarkFlagRequired("signature")

	// Add subcommands
	cmsCmd.AddCommand(cmsSignCmd)
	cmsCmd.AddCommand(cmsVerifyCmd)
}

func runCMSSign(cmd *cobra.Command, args []string) error {
	// Read data to sign
	data, err := os.ReadFile(cmsSignData)
	if err != nil {
		return fmt.Errorf("failed to read data file: %w", err)
	}

	// Load certificate
	certPEM, err := os.ReadFile(cmsSignCert)
	if err != nil {
		return fmt.Errorf("failed to read certificate: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf("invalid certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Load private key
	signer, err := pkicrypto.LoadPrivateKey(cmsSignKey, []byte(cmsSignPassphrase))
	if err != nil {
		return fmt.Errorf("failed to load private key: %w", err)
	}

	// Parse hash algorithm
	hashAlg, err := parseHashAlgorithm(cmsSignHash)
	if err != nil {
		return fmt.Errorf("invalid hash algorithm: %w", err)
	}

	// Create signature
	config := &cms.SignerConfig{
		Certificate:  cert,
		Signer:       signer,
		DigestAlg:    hashAlg,
		IncludeCerts: cmsSignIncludeCerts,
		Detached:     cmsSignDetached,
		ContentType:  cms.OIDData,
	}

	signedData, err := cms.Sign(data, config)
	if err != nil {
		return fmt.Errorf("failed to sign: %w", err)
	}

	// Write output
	if err := os.WriteFile(cmsSignOutput, signedData, 0644); err != nil {
		return fmt.Errorf("failed to write signature: %w", err)
	}

	// Log audit event
	_ = audit.Log(audit.NewEvent(audit.EventCMSSign, audit.ResultSuccess).
		WithObject(audit.Object{
			Type: "signature",
			Path: cmsSignOutput,
		}).
		WithContext(audit.Context{
			Algorithm: cmsSignHash,
			Detached:  cmsSignDetached,
		}))

	fmt.Printf("Signature written to %s\n", cmsSignOutput)
	if cmsSignDetached {
		fmt.Printf("  Type:       detached\n")
	} else {
		fmt.Printf("  Type:       attached\n")
	}
	fmt.Printf("  Hash:       %s\n", cmsSignHash)
	fmt.Printf("  Signer:     %s\n", cert.Subject.CommonName)

	return nil
}

func runCMSVerify(cmd *cobra.Command, args []string) error {
	// Read signature
	signatureData, err := os.ReadFile(cmsVerifySignature)
	if err != nil {
		return fmt.Errorf("failed to read signature file: %w", err)
	}

	// Build verify config
	config := &cms.VerifyConfig{}

	// Read data if provided (for detached signatures)
	if cmsVerifyData != "" {
		data, err := os.ReadFile(cmsVerifyData)
		if err != nil {
			return fmt.Errorf("failed to read data file: %w", err)
		}
		config.Data = data
	}

	// Load CA certificate if provided
	if cmsVerifyCA != "" {
		caPEM, err := os.ReadFile(cmsVerifyCA)
		if err != nil {
			return fmt.Errorf("failed to read CA certificate: %w", err)
		}

		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(caPEM) {
			return fmt.Errorf("failed to parse CA certificate")
		}
		config.Roots = roots
	} else {
		config.SkipCertVerify = true
	}

	// Verify
	result, err := cms.Verify(signatureData, config)
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	// Log audit event
	_ = audit.Log(audit.NewEvent(audit.EventCMSVerify, audit.ResultSuccess).
		WithObject(audit.Object{
			Type: "signature",
			Path: cmsVerifySignature,
		}).
		WithContext(audit.Context{
			Verified: true,
		}))

	fmt.Printf("Signature verification: OK\n")
	fmt.Printf("  Signer:       %s\n", result.SignerCert.Subject.CommonName)
	fmt.Printf("  Issuer:       %s\n", result.SignerCert.Issuer.CommonName)
	if !result.SigningTime.IsZero() {
		fmt.Printf("  Signing Time: %s\n", result.SigningTime.Format(time.RFC3339))
	}
	if len(result.Content) > 0 {
		fmt.Printf("  Content Size: %d bytes\n", len(result.Content))
	}

	return nil
}
