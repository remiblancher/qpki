package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/remiblancher/post-quantum-pki/internal/audit"
	"github.com/remiblancher/post-quantum-pki/internal/cms"
	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
)

var cmsCmd = &cobra.Command{
	Use:   "cms",
	Short: "CMS operations (RFC 5652)",
	Long: `CMS (Cryptographic Message Syntax) operations per RFC 5652.

This command provides:
  - sign:    Create a CMS SignedData signature
  - verify:  Verify a CMS SignedData signature
  - encrypt: Encrypt data using CMS EnvelopedData
  - decrypt: Decrypt CMS EnvelopedData

Supports all PKI algorithms including post-quantum (ML-DSA, SLH-DSA, ML-KEM).

Examples:
  # Sign a file (detached signature)
  pki cms sign --data file.txt --cert signer.crt --key signer.key -o file.p7s

  # Verify a detached signature
  pki cms verify --signature file.p7s --data file.txt --ca ca.crt

  # Encrypt for a recipient
  pki cms encrypt --recipient bob.crt --in secret.txt --out secret.p7m

  # Decrypt with private key
  pki cms decrypt --key bob.key --in secret.p7m --out secret.txt`,
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

// CMS encrypt command
var cmsEncryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "Encrypt data using CMS EnvelopedData",
	Long: `Encrypt data using CMS EnvelopedData (RFC 5652 Section 6).

The data is encrypted with a random AES key, which is then encrypted
for each recipient using their public key from their certificate.

Supported key types:
  - RSA:    Uses RSA-OAEP with SHA-256
  - EC:     Uses ECDH with AES Key Wrap
  - ML-KEM: Uses ML-KEM encapsulation with AES Key Wrap (post-quantum)

Examples:
  # Encrypt for a single recipient
  pki cms encrypt --recipient bob.crt --in secret.txt --out secret.p7m

  # Encrypt for multiple recipients
  pki cms encrypt --recipient alice.crt --recipient bob.crt --in data.txt --out data.p7m

  # Use AES-256-CBC instead of AES-256-GCM
  pki cms encrypt --recipient bob.crt --in data.txt --out data.p7m --content-enc aes-256-cbc`,
	RunE: runCMSEncrypt,
}

// CMS decrypt command
var cmsDecryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt CMS EnvelopedData",
	Long: `Decrypt CMS EnvelopedData (RFC 5652 Section 6).

Decrypts the content using the recipient's private key.
The matching RecipientInfo is found automatically based on the key type.

Examples:
  # Decrypt with private key
  pki cms decrypt --key bob.key --in secret.p7m --out secret.txt

  # Decrypt with encrypted private key
  pki cms decrypt --key bob.key --passphrase "secret" --in data.p7m --out data.txt

  # Decrypt specifying the certificate (for matching)
  pki cms decrypt --key bob.key --cert bob.crt --in data.p7m --out data.txt`,
	RunE: runCMSDecrypt,
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

	// cms encrypt flags
	cmsEncryptRecipients []string
	cmsEncryptInput      string
	cmsEncryptOutput     string
	cmsEncryptContentEnc string

	// cms decrypt flags
	cmsDecryptKey        string
	cmsDecryptCert       string
	cmsDecryptPassphrase string
	cmsDecryptInput      string
	cmsDecryptOutput     string
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

	// cms encrypt flags
	cmsEncryptCmd.Flags().StringArrayVarP(&cmsEncryptRecipients, "recipient", "r", nil, "Recipient certificate(s) (PEM)")
	cmsEncryptCmd.Flags().StringVarP(&cmsEncryptInput, "in", "i", "", "Input file to encrypt")
	cmsEncryptCmd.Flags().StringVarP(&cmsEncryptOutput, "out", "o", "", "Output file (.p7m)")
	cmsEncryptCmd.Flags().StringVar(&cmsEncryptContentEnc, "content-enc", "aes-256-gcm", "Content encryption (aes-256-gcm, aes-256-cbc, aes-128-gcm)")

	_ = cmsEncryptCmd.MarkFlagRequired("recipient")
	_ = cmsEncryptCmd.MarkFlagRequired("in")
	_ = cmsEncryptCmd.MarkFlagRequired("out")

	// cms decrypt flags
	cmsDecryptCmd.Flags().StringVarP(&cmsDecryptKey, "key", "k", "", "Private key file (PEM)")
	cmsDecryptCmd.Flags().StringVarP(&cmsDecryptCert, "cert", "c", "", "Certificate for recipient matching (optional)")
	cmsDecryptCmd.Flags().StringVar(&cmsDecryptPassphrase, "passphrase", "", "Key passphrase")
	cmsDecryptCmd.Flags().StringVarP(&cmsDecryptInput, "in", "i", "", "Input file (.p7m)")
	cmsDecryptCmd.Flags().StringVarP(&cmsDecryptOutput, "out", "o", "", "Output file")

	_ = cmsDecryptCmd.MarkFlagRequired("key")
	_ = cmsDecryptCmd.MarkFlagRequired("in")
	_ = cmsDecryptCmd.MarkFlagRequired("out")

	// Add subcommands
	cmsCmd.AddCommand(cmsSignCmd)
	cmsCmd.AddCommand(cmsVerifyCmd)
	cmsCmd.AddCommand(cmsEncryptCmd)
	cmsCmd.AddCommand(cmsDecryptCmd)
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

func runCMSEncrypt(cmd *cobra.Command, args []string) error {
	// Read input data
	data, err := os.ReadFile(cmsEncryptInput)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	// Load recipient certificates
	var recipients []*x509.Certificate
	for _, certPath := range cmsEncryptRecipients {
		certPEM, err := os.ReadFile(certPath)
		if err != nil {
			return fmt.Errorf("failed to read certificate %s: %w", certPath, err)
		}

		block, _ := pem.Decode(certPEM)
		if block == nil || block.Type != "CERTIFICATE" {
			return fmt.Errorf("invalid certificate PEM: %s", certPath)
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse certificate %s: %w", certPath, err)
		}
		recipients = append(recipients, cert)
	}

	// Parse content encryption algorithm
	var contentEnc cms.ContentEncryptionAlgorithm
	switch cmsEncryptContentEnc {
	case "aes-256-gcm", "":
		contentEnc = cms.AES256GCM
	case "aes-256-cbc":
		contentEnc = cms.AES256CBC
	case "aes-128-gcm":
		contentEnc = cms.AES128GCM
	default:
		return fmt.Errorf("unsupported content encryption: %s", cmsEncryptContentEnc)
	}

	// Encrypt
	opts := &cms.EncryptOptions{
		Recipients:        recipients,
		ContentEncryption: contentEnc,
	}

	encrypted, err := cms.Encrypt(data, opts)
	if err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}

	// Write output
	if err := os.WriteFile(cmsEncryptOutput, encrypted, 0644); err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}

	// Log audit event
	_ = audit.Log(audit.NewEvent(audit.EventCMSEncrypt, audit.ResultSuccess).
		WithObject(audit.Object{
			Type: "encrypted",
			Path: cmsEncryptOutput,
		}).
		WithContext(audit.Context{
			Algorithm: cmsEncryptContentEnc,
		}))

	fmt.Printf("Encrypted to %s\n", cmsEncryptOutput)
	fmt.Printf("  Recipients:   %d\n", len(recipients))
	for _, cert := range recipients {
		fmt.Printf("    - %s\n", cert.Subject.CommonName)
	}
	fmt.Printf("  Content Enc:  %s\n", cmsEncryptContentEnc)
	fmt.Printf("  Input Size:   %d bytes\n", len(data))
	fmt.Printf("  Output Size:  %d bytes\n", len(encrypted))

	return nil
}

func runCMSDecrypt(cmd *cobra.Command, args []string) error {
	// Read encrypted data
	encryptedData, err := os.ReadFile(cmsDecryptInput)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	// Load private key
	privateKey, err := pkicrypto.LoadPrivateKey(cmsDecryptKey, []byte(cmsDecryptPassphrase))
	if err != nil {
		return fmt.Errorf("failed to load private key: %w", err)
	}

	// Build decrypt options
	opts := &cms.DecryptOptions{
		PrivateKey: privateKey,
	}

	// Load certificate if provided (for recipient matching)
	if cmsDecryptCert != "" {
		certPEM, err := os.ReadFile(cmsDecryptCert)
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
		opts.Certificate = cert
	}

	// Decrypt
	result, err := cms.Decrypt(encryptedData, opts)
	if err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}

	// Write output
	if err := os.WriteFile(cmsDecryptOutput, result.Content, 0644); err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}

	// Log audit event
	_ = audit.Log(audit.NewEvent(audit.EventCMSDecrypt, audit.ResultSuccess).
		WithObject(audit.Object{
			Type: "decrypted",
			Path: cmsDecryptOutput,
		}))

	fmt.Printf("Decrypted to %s\n", cmsDecryptOutput)
	fmt.Printf("  Output Size: %d bytes\n", len(result.Content))

	return nil
}
