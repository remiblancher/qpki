package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/remiblancher/post-quantum-pki/internal/audit"
	"github.com/remiblancher/post-quantum-pki/internal/cms"
	"github.com/remiblancher/post-quantum-pki/internal/credential"
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
  pki cms sign --data file.txt --cert signer.crt --key signer.key --out file.p7s

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
  pki cms sign --data file.txt --cert signer.crt --key signer.key --out file.p7s

  # Attached signature
  pki cms sign --data file.txt --cert signer.crt --key signer.key --detached=false --out file.p7s

  # With SHA-512 hash
  pki cms sign --data file.txt --cert signer.crt --key signer.key --hash sha512 --out file.p7s

  # Include certificate chain
  pki cms sign --data file.txt --cert signer.crt --key signer.key --include-certs --out file.p7s`,
	RunE: runCMSSign,
}

// CMS verify command
var cmsVerifyCmd = &cobra.Command{
	Use:   "verify <signature-file>",
	Short: "Verify a CMS SignedData signature",
	Long: `Verify a CMS SignedData signature.

For detached signatures, provide the original data with --data.
For attached signatures, the data is extracted from the SignedData structure.

Examples:
  # Verify detached signature
  qpki cms verify file.p7s --data file.txt --ca ca.crt

  # Verify attached signature (data extracted automatically)
  qpki cms verify file.p7s --ca ca.crt

  # Verify without CA check (signature only)
  qpki cms verify file.p7s --data file.txt`,
	Args: cobra.ExactArgs(1),
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

// CMS info command
var cmsInfoCmd = &cobra.Command{
	Use:   "info <file>",
	Short: "Display CMS message information",
	Long: `Display detailed information about a CMS message.

Supports both SignedData (.p7s) and EnvelopedData (.p7m) messages.
Shows content type, signers, recipients, algorithms, and certificates.

Examples:
  qpki cms info signature.p7s
  qpki cms info encrypted.p7m`,
	Args: cobra.ExactArgs(1),
	RunE: runCMSInfo,
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
	cmsSignHSMConfig    string
	cmsSignKeyLabel     string
	cmsSignKeyID        string
	cmsSignCredential   string
	cmsSignCredDir      string

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
	cmsDecryptHSMConfig  string
	cmsDecryptKeyLabel   string
	cmsDecryptKeyID      string
	cmsDecryptCredential string
	cmsDecryptCredDir    string
)

func init() {
	// cms sign flags
	cmsSignCmd.Flags().StringVar(&cmsSignData, "data", "", "File to sign (required)")
	cmsSignCmd.Flags().StringVar(&cmsSignCert, "cert", "", "Signer certificate (PEM)")
	cmsSignCmd.Flags().StringVar(&cmsSignKey, "key", "", "Signer private key (PEM, required unless --hsm-config)")
	cmsSignCmd.Flags().StringVar(&cmsSignPassphrase, "passphrase", "", "Key passphrase")
	cmsSignCmd.Flags().StringVar(&cmsSignHash, "hash", "sha256", "Hash algorithm (sha256, sha384, sha512)")
	cmsSignCmd.Flags().StringVarP(&cmsSignOutput, "out", "o", "", "Output file (required)")
	cmsSignCmd.Flags().BoolVar(&cmsSignDetached, "detached", true, "Create detached signature (content not included)")
	cmsSignCmd.Flags().BoolVar(&cmsSignIncludeCerts, "include-certs", true, "Include signer certificate in output")
	cmsSignCmd.Flags().StringVar(&cmsSignHSMConfig, "hsm-config", "", "HSM configuration file (YAML)")
	cmsSignCmd.Flags().StringVar(&cmsSignKeyLabel, "key-label", "", "HSM key label (CKA_LABEL)")
	cmsSignCmd.Flags().StringVar(&cmsSignKeyID, "key-id", "", "HSM key ID (CKA_ID, hex)")
	cmsSignCmd.Flags().StringVar(&cmsSignCredential, "credential", "", "Credential ID to use for signing (alternative to --cert/--key)")
	cmsSignCmd.Flags().StringVar(&cmsSignCredDir, "cred-dir", "./credentials", "Credentials directory")

	_ = cmsSignCmd.MarkFlagRequired("data")
	_ = cmsSignCmd.MarkFlagRequired("out")

	// cms verify flags
	cmsVerifyCmd.Flags().StringVar(&cmsVerifyData, "data", "", "Original data file (for detached signatures)")
	cmsVerifyCmd.Flags().StringVar(&cmsVerifyCA, "ca", "", "CA certificate for chain verification")

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
	cmsDecryptCmd.Flags().StringVar(&cmsDecryptHSMConfig, "hsm-config", "", "HSM configuration file (YAML)")
	cmsDecryptCmd.Flags().StringVar(&cmsDecryptKeyLabel, "key-label", "", "HSM key label (CKA_LABEL)")
	cmsDecryptCmd.Flags().StringVar(&cmsDecryptKeyID, "key-id", "", "HSM key ID (CKA_ID, hex)")
	cmsDecryptCmd.Flags().StringVar(&cmsDecryptCredential, "credential", "", "Credential ID to use for decryption (alternative to --key)")
	cmsDecryptCmd.Flags().StringVar(&cmsDecryptCredDir, "cred-dir", "./credentials", "Credentials directory")

	_ = cmsDecryptCmd.MarkFlagRequired("in")
	_ = cmsDecryptCmd.MarkFlagRequired("out")

	// Add subcommands
	cmsCmd.AddCommand(cmsSignCmd)
	cmsCmd.AddCommand(cmsVerifyCmd)
	cmsCmd.AddCommand(cmsEncryptCmd)
	cmsCmd.AddCommand(cmsDecryptCmd)
	cmsCmd.AddCommand(cmsInfoCmd)
}

func runCMSSign(cmd *cobra.Command, args []string) error {
	data, err := os.ReadFile(cmsSignData)
	if err != nil {
		return fmt.Errorf("failed to read data file: %w", err)
	}

	var cert *x509.Certificate
	var signer crypto.Signer

	// Load certificate and key from credential or from files
	if cmsSignCredential != "" {
		// Use credential store
		credDir, err := filepath.Abs(cmsSignCredDir)
		if err != nil {
			return fmt.Errorf("invalid credentials directory: %w", err)
		}
		store := credential.NewFileStore(credDir)
		passphrase := []byte(cmsSignPassphrase)

		cert, signer, err = credential.LoadSigner(cmd.Context(), store, cmsSignCredential, passphrase)
		if err != nil {
			return fmt.Errorf("failed to load credential %s: %w", cmsSignCredential, err)
		}
	} else if cmsSignCert != "" {
		// Use certificate and key files
		cert, err = loadSigningCert(cmsSignCert)
		if err != nil {
			return err
		}

		signer, err = loadSigningKey(cmsSignHSMConfig, cmsSignKey, cmsSignPassphrase, cmsSignKeyLabel, cmsSignKeyID)
		if err != nil {
			return fmt.Errorf("failed to load private key: %w", err)
		}
	} else {
		return fmt.Errorf("either --credential or --cert is required")
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

	signedData, err := cms.Sign(context.Background(), data, config)
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
	// Get signature file from positional argument
	cmsVerifySignature = args[0]

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

		// Parse and filter CA certificates from the PEM file
		// This allows passing a chain file containing signer + CA certs
		caCerts, rootCert, err := parseCACertsFromPEM(caPEM)
		if err != nil {
			return fmt.Errorf("failed to parse CA certificates: %w", err)
		}

		if len(caCerts) == 0 {
			return fmt.Errorf("no CA certificates found in %s", cmsVerifyCA)
		}

		roots := x509.NewCertPool()
		for _, cert := range caCerts {
			roots.AddCert(cert)
		}
		config.Roots = roots

		// Extract raw root CA certificate for PQC chain verification
		if rootCert != nil {
			config.RootCertRaw = rootCert.Raw
		}
	} else {
		config.SkipCertVerify = true
	}

	// Verify
	result, err := cms.Verify(context.Background(), signatureData, config)
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

	encrypted, err := cms.Encrypt(context.Background(), data, opts)
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
	encryptedData, err := os.ReadFile(cmsDecryptInput)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	var privKey interface{}
	var cert *x509.Certificate

	// Load certificate and key from credential or from files
	if cmsDecryptCredential != "" {
		// Use credential store with multi-version support
		// This allows decryption with old keys after key rotation
		credDir, err := filepath.Abs(cmsDecryptCredDir)
		if err != nil {
			return fmt.Errorf("invalid credentials directory: %w", err)
		}
		store := credential.NewFileStore(credDir)
		passphrase := []byte(cmsDecryptPassphrase)

		// Extract recipient matchers from CMS message to find the correct key
		matchers, err := cms.ExtractRecipientMatchers(encryptedData)
		if err != nil {
			// Fallback to loading active key if we can't extract matchers
			cert, privKey, err = credential.LoadDecryptionKey(cmd.Context(), store, cmsDecryptCredential, passphrase)
			if err != nil {
				return fmt.Errorf("failed to load credential %s: %w", cmsDecryptCredential, err)
			}
		} else {
			// Try each matcher to find the corresponding key from any version
			var found bool
			for _, matcher := range matchers {
				cert, privKey, err = credential.FindDecryptionKeyByRecipient(cmd.Context(), store, cmsDecryptCredential, matcher, passphrase)
				if err == nil {
					found = true
					break
				}
			}
			if !found {
				// No matching key found in any version, try the active key as last resort
				cert, privKey, err = credential.LoadDecryptionKey(cmd.Context(), store, cmsDecryptCredential, passphrase)
				if err != nil {
					return fmt.Errorf("no matching decryption key found for credential %s", cmsDecryptCredential)
				}
			}
		}
	} else if cmsDecryptKey != "" {
		// Use key file
		if cmsDecryptHSMConfig != "" {
			return fmt.Errorf("HSM decryption not yet supported: CMS decrypt requires direct access to the private key")
		}

		privKey, err = loadDecryptionKey(cmsDecryptKey, cmsDecryptPassphrase)
		if err != nil {
			return err
		}

		if cmsDecryptCert != "" {
			cert, err = loadDecryptionCert(cmsDecryptCert)
			if err != nil {
				return err
			}
		}
	} else {
		return fmt.Errorf("either --credential or --key is required")
	}

	opts := &cms.DecryptOptions{PrivateKey: privKey, Certificate: cert}

	result, err := cms.Decrypt(context.Background(), encryptedData, opts)
	if err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}

	if err := os.WriteFile(cmsDecryptOutput, result.Content, 0644); err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}

	_ = audit.Log(audit.NewEvent(audit.EventCMSDecrypt, audit.ResultSuccess).
		WithObject(audit.Object{Type: "decrypted", Path: cmsDecryptOutput}))

	fmt.Printf("Decrypted to %s\n", cmsDecryptOutput)
	fmt.Printf("  Output Size: %d bytes\n", len(result.Content))
	return nil
}

func runCMSInfo(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	// Read CMS message
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Parse ContentInfo to determine message type
	info, err := cms.ParseContentInfo(data)
	if err != nil {
		return fmt.Errorf("failed to parse CMS message: %w", err)
	}

	fmt.Println("CMS Message:")
	fmt.Printf("  Content Type: %s\n", formatCMSContentType(info.ContentType))

	switch {
	case info.ContentType.Equal(cms.OIDSignedData):
		return displaySignedDataInfo(data)
	case info.ContentType.Equal(cms.OIDEnvelopedData):
		return displayEnvelopedDataInfo(data)
	default:
		fmt.Printf("  (Unknown content type, cannot display details)\n")
	}

	return nil
}

func displaySignedDataInfo(data []byte) error {
	// Parse SignedData
	signedData, err := cms.ParseSignedData(data)
	if err != nil {
		return fmt.Errorf("failed to parse SignedData: %w", err)
	}

	fmt.Printf("  Version:      %d\n", signedData.Version)

	// Display digest algorithms
	if len(signedData.DigestAlgorithms) > 0 {
		fmt.Printf("  Digest Algs:  ")
		for i, alg := range signedData.DigestAlgorithms {
			if i > 0 {
				fmt.Printf(", ")
			}
			fmt.Printf("%s", formatAlgorithmOID(alg.Algorithm))
		}
		fmt.Println()
	}

	// Display content info
	contentType := signedData.EncapContentInfo.EContentType
	fmt.Printf("  Content Type: %s\n", formatCMSContentType(contentType))

	// Check if content is detached
	if len(signedData.EncapContentInfo.EContent.Bytes) == 0 {
		fmt.Printf("  Content:      (detached)\n")
	} else {
		fmt.Printf("  Content:      %d bytes\n", len(signedData.EncapContentInfo.EContent.Bytes))
	}

	// Display signer info
	fmt.Printf("  Signers:      %d\n", len(signedData.SignerInfos))
	for i, si := range signedData.SignerInfos {
		fmt.Printf("\n  Signer %d:\n", i+1)
		fmt.Printf("    Version:    %d\n", si.Version)
		fmt.Printf("    Serial:     %s\n", si.SID.SerialNumber.String())
		fmt.Printf("    Digest Alg: %s\n", formatAlgorithmOID(si.DigestAlgorithm.Algorithm))
		fmt.Printf("    Sig Alg:    %s\n", formatAlgorithmOID(si.SignatureAlgorithm.Algorithm))
		fmt.Printf("    Signature:  %d bytes\n", len(si.Signature))

		// Display signing time if present
		signingTime := extractCMSSigningTime(si.SignedAttrs)
		if !signingTime.IsZero() {
			fmt.Printf("    Signed At:  %s\n", signingTime.Format(time.RFC3339))
		}
	}

	// Display certificates if present
	certs, err := cms.ParseCertificates(signedData.Certificates.Raw)
	if err == nil && len(certs) > 0 {
		fmt.Printf("\n  Certificates: %d\n", len(certs))
		for i, cert := range certs {
			fmt.Printf("    [%d] %s\n", i+1, cert.Subject.String())
		}
	}

	return nil
}

func displayEnvelopedDataInfo(data []byte) error {
	// Parse EnvelopedData
	env, err := cms.ParseEnvelopedData(data)
	if err != nil {
		return fmt.Errorf("failed to parse EnvelopedData: %w", err)
	}

	fmt.Printf("  Version:       %d\n", env.Version)
	fmt.Printf("  Recipients:    %d\n", len(env.RecipientInfos))

	// Display content encryption
	fmt.Printf("  Content Enc:   %s\n", formatAlgorithmOID(env.EncryptedContentInfo.ContentEncryptionAlgorithm.Algorithm))
	fmt.Printf("  Content Type:  %s\n", formatCMSContentType(env.EncryptedContentInfo.ContentType))

	if len(env.EncryptedContentInfo.EncryptedContent) > 0 {
		fmt.Printf("  Encrypted:     %d bytes\n", len(env.EncryptedContentInfo.EncryptedContent))
	}

	// Display recipient info
	for i, riRaw := range env.RecipientInfos {
		fmt.Printf("\n  Recipient %d:\n", i+1)

		ri, err := cms.ParseRecipientInfo(riRaw)
		if err != nil {
			fmt.Printf("    (failed to parse: %v)\n", err)
			continue
		}

		switch v := ri.(type) {
		case *cms.KeyTransRecipientInfo:
			fmt.Printf("    Type:       KeyTransRecipientInfo (RSA)\n")
			fmt.Printf("    Version:    %d\n", v.Version)
			if v.RID.IssuerAndSerial != nil {
				fmt.Printf("    Serial:     %s\n", v.RID.IssuerAndSerial.SerialNumber.String())
			}
			fmt.Printf("    Key Enc:    %s\n", formatAlgorithmOID(v.KeyEncryptionAlgorithm.Algorithm))
		case *cms.KeyAgreeRecipientInfo:
			fmt.Printf("    Type:       KeyAgreeRecipientInfo (ECDH)\n")
			fmt.Printf("    Version:    %d\n", v.Version)
			fmt.Printf("    Key Agree:  %s\n", formatAlgorithmOID(v.KeyEncryptionAlgorithm.Algorithm))
			fmt.Printf("    Recipients: %d\n", len(v.RecipientEncryptedKeys))
		case *cms.KEMRecipientInfo:
			fmt.Printf("    Type:       KEMRecipientInfo (ML-KEM)\n")
			fmt.Printf("    Version:    %d\n", v.Version)
			fmt.Printf("    KEM Alg:    %s\n", formatAlgorithmOID(v.KEM.Algorithm))
			fmt.Printf("    KDF Alg:    %s\n", formatAlgorithmOID(v.KDF.Algorithm))
		default:
			fmt.Printf("    Type:       Unknown\n")
		}
	}

	return nil
}

func formatCMSContentType(oid asn1.ObjectIdentifier) string {
	switch {
	case oid.Equal(cms.OIDData):
		return "Data (1.2.840.113549.1.7.1)"
	case oid.Equal(cms.OIDSignedData):
		return "SignedData (1.2.840.113549.1.7.2)"
	case oid.Equal(cms.OIDEnvelopedData):
		return "EnvelopedData (1.2.840.113549.1.7.3)"
	case oid.Equal(cms.OIDTSTInfo):
		return "TSTInfo (1.2.840.113549.1.9.16.1.4)"
	default:
		return oid.String()
	}
}

// cmsAlgorithmNames maps OID string representations to human-readable names.
// Initialized once from the cms package OIDs.
var cmsAlgorithmNames = map[string]string{
	// Digest algorithms
	cms.OIDSHA256.String():   "SHA-256",
	cms.OIDSHA384.String():   "SHA-384",
	cms.OIDSHA512.String():   "SHA-512",
	cms.OIDSHA3_256.String(): "SHA3-256",
	cms.OIDSHA3_384.String(): "SHA3-384",
	cms.OIDSHA3_512.String(): "SHA3-512",
	// Signature algorithms
	cms.OIDECDSAWithSHA256.String(): "ECDSA-SHA256",
	cms.OIDECDSAWithSHA384.String(): "ECDSA-SHA384",
	cms.OIDECDSAWithSHA512.String(): "ECDSA-SHA512",
	cms.OIDEd25519.String():         "Ed25519",
	cms.OIDSHA256WithRSA.String():   "RSA-SHA256",
	cms.OIDSHA384WithRSA.String():   "RSA-SHA384",
	cms.OIDSHA512WithRSA.String():   "RSA-SHA512",
	// PQC signature algorithms
	cms.OIDMLDSA44.String():    "ML-DSA-44",
	cms.OIDMLDSA65.String():    "ML-DSA-65",
	cms.OIDMLDSA87.String():    "ML-DSA-87",
	cms.OIDSLHDSA128s.String(): "SLH-DSA-128s",
	cms.OIDSLHDSA128f.String(): "SLH-DSA-128f",
	cms.OIDSLHDSA192s.String(): "SLH-DSA-192s",
	cms.OIDSLHDSA192f.String(): "SLH-DSA-192f",
	cms.OIDSLHDSA256s.String(): "SLH-DSA-256s",
	cms.OIDSLHDSA256f.String(): "SLH-DSA-256f",
	// Content encryption
	cms.OIDAES128GCM.String(): "AES-128-GCM",
	cms.OIDAES256GCM.String(): "AES-256-GCM",
	cms.OIDAES128CBC.String(): "AES-128-CBC",
	cms.OIDAES256CBC.String(): "AES-256-CBC",
	// Key encryption
	cms.OIDRSAOAEP.String():          "RSA-OAEP",
	cms.OIDRSAES.String():            "RSA-PKCS1",
	cms.OIDECDHStdSHA256KDF.String(): "ECDH-SHA256-KDF",
	cms.OIDECDHStdSHA384KDF.String(): "ECDH-SHA384-KDF",
	// KEM algorithms
	cms.OIDMLKEM512.String():  "ML-KEM-512",
	cms.OIDMLKEM768.String():  "ML-KEM-768",
	cms.OIDMLKEM1024.String(): "ML-KEM-1024",
	// KDF algorithms
	cms.OIDHKDFSHA256.String(): "HKDF-SHA256",
	cms.OIDHKDFSHA384.String(): "HKDF-SHA384",
	cms.OIDHKDFSHA512.String(): "HKDF-SHA512",
	// Key wrap
	cms.OIDAESWrap128.String(): "AES-128-Wrap",
	cms.OIDAESWrap256.String(): "AES-256-Wrap",
}

func formatAlgorithmOID(oid asn1.ObjectIdentifier) string {
	if name, ok := cmsAlgorithmNames[oid.String()]; ok {
		return name
	}
	return oid.String()
}

func extractCMSSigningTime(attrs []cms.Attribute) time.Time {
	for _, attr := range attrs {
		if attr.Type.Equal(cms.OIDSigningTime) && len(attr.Values) > 0 {
			var t time.Time
			if _, err := asn1.Unmarshal(attr.Values[0].FullBytes, &t); err == nil {
				return t
			}
		}
	}
	return time.Time{}
}

// parseCACertsFromPEM parses all certificates from PEM data and returns only CA certificates.
// Returns the filtered certificates and the root CA certificate (for PQC verification).
func parseCACertsFromPEM(pemData []byte) (caCerts []*x509.Certificate, rootCert *x509.Certificate, err error) {
	var allCerts []*x509.Certificate
	rest := pemData

	// Parse all certificates from PEM
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			continue // Skip unparseable certificates
		}
		allCerts = append(allCerts, cert)
	}

	if len(allCerts) == 0 {
		return nil, nil, fmt.Errorf("no certificates found in PEM data")
	}

	// Filter only CA certificates (IsCA=true)
	for _, cert := range allCerts {
		if cert.IsCA {
			caCerts = append(caCerts, cert)
			// Root CA is self-signed (issuer == subject)
			if cert.Subject.String() == cert.Issuer.String() {
				rootCert = cert
			}
		}
	}

	// If no CA found but only one cert provided, use it (backward compatibility)
	if len(caCerts) == 0 && len(allCerts) == 1 {
		caCerts = allCerts
		rootCert = allCerts[0]
	}

	// If no root found, use the first CA certificate
	if rootCert == nil && len(caCerts) > 0 {
		rootCert = caCerts[0]
	}

	return caCerts, rootCert, nil
}
