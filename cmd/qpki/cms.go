package main

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
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

	_ = cmsSignCmd.MarkFlagRequired("data")
	_ = cmsSignCmd.MarkFlagRequired("cert")
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

	// Load private key using KeyProvider
	var keyCfg pkicrypto.KeyStorageConfig
	if cmsSignHSMConfig != "" {
		// HSM mode
		hsmCfg, err := pkicrypto.LoadHSMConfig(cmsSignHSMConfig)
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
			PKCS11KeyLabel: cmsSignKeyLabel,
			PKCS11KeyID:    cmsSignKeyID,
		}
		if keyCfg.PKCS11KeyLabel == "" && keyCfg.PKCS11KeyID == "" {
			return fmt.Errorf("--key-label or --key-id required with --hsm-config")
		}
	} else {
		// Software mode
		if cmsSignKey == "" {
			return fmt.Errorf("--key required for software mode (or use --hsm-config for HSM)")
		}
		keyCfg = pkicrypto.KeyStorageConfig{
			Type:       pkicrypto.KeyProviderTypeSoftware,
			KeyPath:    cmsSignKey,
			Passphrase: cmsSignPassphrase,
		}
	}
	km := pkicrypto.NewKeyProvider(keyCfg)
	signer, err := km.Load(keyCfg)
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

		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(caPEM) {
			return fmt.Errorf("failed to parse CA certificate")
		}
		config.Roots = roots

		// Extract raw CA certificate for PQC chain verification
		block, _ := pem.Decode(caPEM)
		if block != nil {
			config.RootCertRaw = block.Bytes
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
	// Read encrypted data
	encryptedData, err := os.ReadFile(cmsDecryptInput)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	// Load private key
	if cmsDecryptHSMConfig != "" {
		// HSM mode - check if HSM decryption is supported
		// Note: HSM decryption requires the CMS library to support a Decrypter interface,
		// which performs the decryption operation on the HSM. This is not yet implemented.
		return fmt.Errorf("HSM decryption not yet supported: CMS decrypt requires direct access to the private key. " +
			"For HSM-stored keys, export the key to software or use a software key for decryption")
	}
	if cmsDecryptKey == "" {
		return fmt.Errorf("--key required for software mode (HSM decryption not yet supported)")
	}

	// Detect key type by reading PEM header
	keyData, err := os.ReadFile(cmsDecryptKey)
	if err != nil {
		return fmt.Errorf("failed to read key file: %w", err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return fmt.Errorf("no PEM block found in key file")
	}

	var privKey interface{}
	if block.Type == "PRIVATE KEY" {
		// PKCS#8 format - try ML-KEM loader first
		passphrase := pkicrypto.ResolvePassphrase(cmsDecryptPassphrase)
		kemPair, err := pkicrypto.LoadKEMPrivateKey(cmsDecryptKey, passphrase)
		if err == nil {
			privKey = kemPair.PrivateKey
		} else {
			// Not ML-KEM - try standard loader (RSA, EC, etc.)
			keyCfg := pkicrypto.KeyStorageConfig{
				Type:       pkicrypto.KeyProviderTypeSoftware,
				KeyPath:    cmsDecryptKey,
				Passphrase: cmsDecryptPassphrase,
			}
			km := pkicrypto.NewKeyProvider(keyCfg)
			signer, err := km.Load(keyCfg)
			if err != nil {
				return fmt.Errorf("failed to load private key: %w", err)
			}
			softSigner, ok := signer.(*pkicrypto.SoftwareSigner)
			if !ok {
				return fmt.Errorf("CMS decrypt requires a software key (HSM decryption not yet supported)")
			}
			privKey = softSigner.PrivateKey()
		}
	} else {
		// Signing key (RSA, EC, etc.) - use standard loader
		keyCfg := pkicrypto.KeyStorageConfig{
			Type:       pkicrypto.KeyProviderTypeSoftware,
			KeyPath:    cmsDecryptKey,
			Passphrase: cmsDecryptPassphrase,
		}
		km := pkicrypto.NewKeyProvider(keyCfg)
		signer, err := km.Load(keyCfg)
		if err != nil {
			return fmt.Errorf("failed to load private key: %w", err)
		}
		softSigner, ok := signer.(*pkicrypto.SoftwareSigner)
		if !ok {
			return fmt.Errorf("CMS decrypt requires a software key (HSM decryption not yet supported)")
		}
		privKey = softSigner.PrivateKey()
	}

	opts := &cms.DecryptOptions{
		PrivateKey: privKey,
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
	result, err := cms.Decrypt(context.Background(), encryptedData, opts)
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

func formatAlgorithmOID(oid asn1.ObjectIdentifier) string {
	switch {
	// Digest algorithms
	case oid.Equal(cms.OIDSHA256):
		return "SHA-256"
	case oid.Equal(cms.OIDSHA384):
		return "SHA-384"
	case oid.Equal(cms.OIDSHA512):
		return "SHA-512"
	case oid.Equal(cms.OIDSHA3_256):
		return "SHA3-256"
	case oid.Equal(cms.OIDSHA3_384):
		return "SHA3-384"
	case oid.Equal(cms.OIDSHA3_512):
		return "SHA3-512"
	// Signature algorithms
	case oid.Equal(cms.OIDECDSAWithSHA256):
		return "ECDSA-SHA256"
	case oid.Equal(cms.OIDECDSAWithSHA384):
		return "ECDSA-SHA384"
	case oid.Equal(cms.OIDECDSAWithSHA512):
		return "ECDSA-SHA512"
	case oid.Equal(cms.OIDEd25519):
		return "Ed25519"
	case oid.Equal(cms.OIDSHA256WithRSA):
		return "RSA-SHA256"
	case oid.Equal(cms.OIDSHA384WithRSA):
		return "RSA-SHA384"
	case oid.Equal(cms.OIDSHA512WithRSA):
		return "RSA-SHA512"
	// PQC signature algorithms
	case oid.Equal(cms.OIDMLDSA44):
		return "ML-DSA-44"
	case oid.Equal(cms.OIDMLDSA65):
		return "ML-DSA-65"
	case oid.Equal(cms.OIDMLDSA87):
		return "ML-DSA-87"
	case oid.Equal(cms.OIDSLHDSA128s):
		return "SLH-DSA-128s"
	case oid.Equal(cms.OIDSLHDSA128f):
		return "SLH-DSA-128f"
	case oid.Equal(cms.OIDSLHDSA192s):
		return "SLH-DSA-192s"
	case oid.Equal(cms.OIDSLHDSA192f):
		return "SLH-DSA-192f"
	case oid.Equal(cms.OIDSLHDSA256s):
		return "SLH-DSA-256s"
	case oid.Equal(cms.OIDSLHDSA256f):
		return "SLH-DSA-256f"
	// Content encryption
	case oid.Equal(cms.OIDAES128GCM):
		return "AES-128-GCM"
	case oid.Equal(cms.OIDAES256GCM):
		return "AES-256-GCM"
	case oid.Equal(cms.OIDAES128CBC):
		return "AES-128-CBC"
	case oid.Equal(cms.OIDAES256CBC):
		return "AES-256-CBC"
	// Key encryption
	case oid.Equal(cms.OIDRSAOAEP):
		return "RSA-OAEP"
	case oid.Equal(cms.OIDRSAES):
		return "RSA-PKCS1"
	case oid.Equal(cms.OIDECDHStdSHA256KDF):
		return "ECDH-SHA256-KDF"
	case oid.Equal(cms.OIDECDHStdSHA384KDF):
		return "ECDH-SHA384-KDF"
	// KEM algorithms
	case oid.Equal(cms.OIDMLKEM512):
		return "ML-KEM-512"
	case oid.Equal(cms.OIDMLKEM768):
		return "ML-KEM-768"
	case oid.Equal(cms.OIDMLKEM1024):
		return "ML-KEM-1024"
	// KDF algorithms
	case oid.Equal(cms.OIDHKDFSHA256):
		return "HKDF-SHA256"
	case oid.Equal(cms.OIDHKDFSHA384):
		return "HKDF-SHA384"
	case oid.Equal(cms.OIDHKDFSHA512):
		return "HKDF-SHA512"
	// Key wrap
	case oid.Equal(cms.OIDAESWrap128):
		return "AES-128-Wrap"
	case oid.Equal(cms.OIDAESWrap256):
		return "AES-256-Wrap"
	default:
		return oid.String()
	}
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
