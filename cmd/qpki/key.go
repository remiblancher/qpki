package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/spf13/cobra"

	"github.com/remiblancher/post-quantum-pki/internal/crypto"
)

var keyCmd = &cobra.Command{
	Use:   "key",
	Short: "Key management commands",
	Long:  `Commands for generating and managing cryptographic keys.`,
}

var keyGenCmd = &cobra.Command{
	Use:   "gen",
	Short: "Generate a cryptographic key pair",
	Long: `Generate a new cryptographic key pair.

Output modes (mutually exclusive):
  --out FILE        Save key to file (software mode)
  --hsm-config FILE Generate key in HSM (requires --key-label)

Supported algorithms:
  Classical (file and HSM):
    ecdsa-p256   - ECDSA with P-256 curve (default)
    ecdsa-p384   - ECDSA with P-384 curve
    ecdsa-p521   - ECDSA with P-521 curve
    ed25519      - Ed25519 (EdDSA) [file only]
    ed448        - Ed448 (EdDSA) [file only]
    rsa-2048     - RSA 2048-bit
    rsa-3072     - RSA 3072-bit [HSM only]
    rsa-4096     - RSA 4096-bit

  Post-Quantum Signature (file only):
    ml-dsa-44         - ML-DSA-44 (NIST Level 1)
    ml-dsa-65         - ML-DSA-65 (NIST Level 3)
    ml-dsa-87         - ML-DSA-87 (NIST Level 5)

  SLH-DSA SHA2 variants (RFC 9814):
    slh-dsa-sha2-128s - SLH-DSA-SHA2-128s (Level 1, small sig)
    slh-dsa-sha2-128f - SLH-DSA-SHA2-128f (Level 1, fast)
    slh-dsa-sha2-192s - SLH-DSA-SHA2-192s (Level 3, small sig)
    slh-dsa-sha2-192f - SLH-DSA-SHA2-192f (Level 3, fast)
    slh-dsa-sha2-256s - SLH-DSA-SHA2-256s (Level 5, small sig)
    slh-dsa-sha2-256f - SLH-DSA-SHA2-256f (Level 5, fast)

  SLH-DSA SHAKE variants (RFC 9814):
    slh-dsa-shake-128s - SLH-DSA-SHAKE-128s (Level 1, small sig)
    slh-dsa-shake-128f - SLH-DSA-SHAKE-128f (Level 1, fast)
    slh-dsa-shake-192s - SLH-DSA-SHAKE-192s (Level 3, small sig)
    slh-dsa-shake-192f - SLH-DSA-SHAKE-192f (Level 3, fast)
    slh-dsa-shake-256s - SLH-DSA-SHAKE-256s (Level 5, small sig)
    slh-dsa-shake-256f - SLH-DSA-SHAKE-256f (Level 5, fast)

  Post-Quantum KEM (file only):
    ml-kem-512   - ML-KEM-512 (NIST Level 1)
    ml-kem-768   - ML-KEM-768 (NIST Level 3)
    ml-kem-1024  - ML-KEM-1024 (NIST Level 5)

Examples:
  # Generate signature key
  qpki key gen --algorithm ecdsa-p384 --out key.pem
  qpki key gen --algorithm ml-dsa-65 --out pqc-sign.pem

  # Generate KEM key (for encryption)
  qpki key gen --algorithm ml-kem-768 --out pqc-kem.pem

  # Generate key in HSM
  export HSM_PIN="****"
  qpki key gen --algorithm ecdsa-p384 --hsm-config ./hsm.yaml --key-label "my-key"`,
	RunE: runKeyGen,
}

var keyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List keys in directory or HSM token",
	Long: `List all private keys in a directory or HSM token.

For directory mode (--dir):
  - Lists all PEM key files in the directory
  - Shows algorithm, encryption status

For HSM mode (--hsm-config):
  - Lists all private keys in the HSM token
  - Shows key label, ID, type, signing capability
  - Requires authentication (PIN)

Examples:
  # List keys in a directory
  qpki key list --dir /path/to/keys

  # List keys in HSM
  export HSM_PIN="****"
  qpki key list --hsm-config ./hsm.yaml`,
	RunE: runKeyList,
}

var keyInfoCmd = &cobra.Command{
	Use:   "info <keyfile>",
	Short: "Display information about a private key",
	Long: `Display information about a private key file.

Shows algorithm, key size, encryption status, and format.

Examples:
  pki key info private.key
  pki key info encrypted.key --passphrase secret`,
	Args: cobra.ExactArgs(1),
	RunE: runKeyInfo,
}

var keyPubCmd = &cobra.Command{
	Use:   "pub",
	Short: "Extract public key from private key",
	Long: `Extract the public key from a private key file.

The output is a PEM-encoded public key that can be shared freely.

Examples:
  # Extract public key from ECDSA key
  qpki key pub --key private.pem --out public.pem

  # Extract from encrypted key
  qpki key pub --key encrypted.key --passphrase secret --out public.pem

  # Extract from PQC key
  qpki key pub --key mldsa.key --out mldsa.pub`,
	RunE: runKeyPub,
}

var keyConvertCmd = &cobra.Command{
	Use:   "convert <input>",
	Short: "Convert private key format",
	Long: `Convert a private key between formats.

Supported conversions:
  - Add/remove passphrase encryption
  - PEM to DER format
  - DER to PEM format

Examples:
  # Add passphrase to unencrypted key
  pki key convert key.pem --new-passphrase secret --out encrypted.pem

  # Remove passphrase from encrypted key
  pki key convert encrypted.pem --passphrase secret --out plain.pem

  # Convert PEM to DER
  pki key convert key.pem --format der --out key.der`,
	Args: cobra.ExactArgs(1),
	RunE: runKeyConvert,
}

var (
	keyGenAlgorithm  string
	keyGenOutput     string
	keyGenPassphrase string
	keyGenHSMConfig  string
	keyGenKeyLabel   string
	keyGenKeyID      string

	keyListHSMConfig string
	keyListDir       string

	keyInfoPassphrase string

	keyPubKey        string
	keyPubOut        string
	keyPubPassphrase string

	keyConvertOut        string
	keyConvertFormat     string
	keyConvertPassphrase string
	keyConvertNewPass    string
)

func init() {
	keyCmd.AddCommand(keyGenCmd)
	keyCmd.AddCommand(keyPubCmd)
	keyCmd.AddCommand(keyListCmd)
	keyCmd.AddCommand(keyInfoCmd)
	keyCmd.AddCommand(keyConvertCmd)

	// gen flags
	flags := keyGenCmd.Flags()
	flags.StringVarP(&keyGenAlgorithm, "algorithm", "a", "ecdsa-p256", "Key algorithm")
	flags.StringVarP(&keyGenOutput, "out", "o", "", "Output file (mutually exclusive with --hsm-config)")
	flags.StringVarP(&keyGenPassphrase, "passphrase", "p", "", "Passphrase for encryption (file mode only)")
	// HSM flags
	flags.StringVar(&keyGenHSMConfig, "hsm-config", "", "Path to HSM configuration file (mutually exclusive with --out)")
	flags.StringVar(&keyGenKeyLabel, "key-label", "", "Key label in HSM (required with --hsm-config)")
	flags.StringVar(&keyGenKeyID, "key-id", "", "Key ID in hex (optional, auto-generated if not specified)")

	// pub flags
	keyPubCmd.Flags().StringVarP(&keyPubKey, "key", "k", "", "Input private key file (required)")
	keyPubCmd.Flags().StringVarP(&keyPubOut, "out", "o", "", "Output public key file (required)")
	keyPubCmd.Flags().StringVar(&keyPubPassphrase, "passphrase", "", "Passphrase for encrypted key")
	_ = keyPubCmd.MarkFlagRequired("key")
	_ = keyPubCmd.MarkFlagRequired("out")

	// list flags
	keyListCmd.Flags().StringVar(&keyListHSMConfig, "hsm-config", "", "Path to HSM configuration file")
	keyListCmd.Flags().StringVar(&keyListDir, "dir", "", "Directory containing key files")

	// info flags
	keyInfoCmd.Flags().StringVarP(&keyInfoPassphrase, "passphrase", "p", "", "Key passphrase")

	// convert flags
	keyConvertCmd.Flags().StringVarP(&keyConvertOut, "out", "o", "", "Output file (required)")
	keyConvertCmd.Flags().StringVar(&keyConvertFormat, "format", "pem", "Output format: pem, der")
	keyConvertCmd.Flags().StringVarP(&keyConvertPassphrase, "passphrase", "p", "", "Input passphrase")
	keyConvertCmd.Flags().StringVar(&keyConvertNewPass, "new-passphrase", "", "Output passphrase (PEM only)")
	_ = keyConvertCmd.MarkFlagRequired("out")
}

func runKeyGen(cmd *cobra.Command, args []string) error {
	// Validate mutually exclusive flags
	if keyGenHSMConfig != "" && keyGenOutput != "" {
		return fmt.Errorf("--out and --hsm-config are mutually exclusive")
	}
	if keyGenHSMConfig == "" && keyGenOutput == "" {
		return fmt.Errorf("either --out or --hsm-config is required")
	}
	if keyGenHSMConfig != "" && keyGenKeyLabel == "" {
		return fmt.Errorf("--key-label is required with --hsm-config")
	}
	if keyGenHSMConfig != "" && keyGenPassphrase != "" {
		return fmt.Errorf("--passphrase is only valid with --out (file mode)")
	}

	// Dispatch to appropriate handler
	if keyGenHSMConfig != "" {
		return runKeyGenHSM()
	}
	return runKeyGenFile()
}

func runKeyGenFile() error {
	alg, err := crypto.ParseAlgorithm(keyGenAlgorithm)
	if err != nil {
		return fmt.Errorf("invalid algorithm: %w", err)
	}

	// Check if algorithm is supported for key generation
	if !alg.IsSignature() && !alg.IsKEM() {
		return fmt.Errorf("algorithm %s is not suitable for key generation", alg)
	}

	fmt.Printf("Generating %s key pair...\n", alg.Description())

	// Handle KEM algorithms separately
	if alg.IsKEM() {
		return runKeyGenKEM(alg)
	}

	// Use KeyProvider to generate signature keys
	keyCfg := crypto.KeyStorageConfig{
		Type:       crypto.KeyProviderTypeSoftware,
		KeyPath:    keyGenOutput,
		Passphrase: keyGenPassphrase,
	}
	km := crypto.NewKeyProvider(keyCfg)
	_, err = km.Generate(alg, keyCfg)
	if err != nil {
		return fmt.Errorf("failed to generate key pair: %w", err)
	}

	fmt.Printf("Private key saved to: %s\n", keyGenOutput)
	if keyGenPassphrase == "" {
		fmt.Println("WARNING: Private key is not encrypted.")
	} else {
		fmt.Println("Private key is encrypted with passphrase.")
	}

	return nil
}

func runKeyGenKEM(alg crypto.AlgorithmID) error {
	// Generate KEM key pair
	kp, err := crypto.GenerateKEMKeyPair(alg)
	if err != nil {
		return fmt.Errorf("failed to generate KEM key pair: %w", err)
	}

	// Save to file
	passphrase := []byte(keyGenPassphrase)
	if err := kp.SavePrivateKey(keyGenOutput, passphrase); err != nil {
		return fmt.Errorf("failed to save KEM private key: %w", err)
	}

	fmt.Printf("Private key saved to: %s\n", keyGenOutput)
	if keyGenPassphrase == "" {
		fmt.Println("WARNING: Private key is not encrypted.")
	} else {
		fmt.Println("Private key is encrypted with passphrase.")
	}

	return nil
}

func runKeyGenHSM() error {
	cfg, err := crypto.LoadHSMConfig(keyGenHSMConfig)
	if err != nil {
		return fmt.Errorf("failed to load HSM config: %w", err)
	}

	pin, err := cfg.GetPIN()
	if err != nil {
		return fmt.Errorf("failed to get PIN: %w", err)
	}

	// Validate algorithm for HSM
	alg := crypto.AlgorithmID(keyGenAlgorithm)
	switch alg {
	case "ecdsa-p256", "ecdsa-p384", "ecdsa-p521", "rsa-2048", "rsa-3072", "rsa-4096":
		// OK - classical algorithms supported by standard PKCS#11
	case "ml-dsa-44", "ml-dsa-65", "ml-dsa-87", "ml-kem-512", "ml-kem-768", "ml-kem-1024":
		// OK - PQC algorithms supported by Utimaco QuantumProtect (vendor extension)
	default:
		return fmt.Errorf("algorithm %s is not supported by HSM (supported: ecdsa-p256, ecdsa-p384, ecdsa-p521, rsa-2048, rsa-3072, rsa-4096, ml-dsa-44, ml-dsa-65, ml-dsa-87)", keyGenAlgorithm)
	}

	fmt.Printf("Generating %s key in HSM...\n", alg)
	fmt.Printf("  Token:     %s\n", cfg.PKCS11.Token)
	fmt.Printf("  Label:     %s\n", keyGenKeyLabel)

	// Use KeyProvider to generate the key in HSM
	keyCfg := crypto.KeyStorageConfig{
		Type:           crypto.KeyProviderTypePKCS11,
		PKCS11Lib:      cfg.PKCS11.Lib,
		PKCS11Token:    cfg.PKCS11.Token,
		PKCS11Pin:      pin,
		PKCS11KeyLabel: keyGenKeyLabel,
		PKCS11KeyID:    keyGenKeyID,
	}
	km := crypto.NewKeyProvider(keyCfg)
	_, err = km.Generate(alg, keyCfg)
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	fmt.Printf("\nKey generated successfully!\n")
	fmt.Printf("  Label:     %s\n", keyGenKeyLabel)
	if keyGenKeyID != "" {
		fmt.Printf("  ID:        %s\n", keyGenKeyID)
	}

	fmt.Printf("\nTo use this key for CA initialization:\n")
	fmt.Printf("  qpki ca init --hsm-config %s --key-label %q --profile ec/root-ca --var cn=\"My CA\" --ca-dir ./ca\n",
		keyGenHSMConfig, keyGenKeyLabel)

	return nil
}

func runKeyPub(cmd *cobra.Command, args []string) error {
	passphrase := []byte(keyPubPassphrase)

	// First, check if this is a KEM key by peeking at the PEM type
	isKEM, err := isKEMKeyFile(keyPubKey)
	if err != nil {
		return fmt.Errorf("failed to read key file: %w", err)
	}

	var pubKey interface{}
	var alg crypto.AlgorithmID

	if isKEM {
		// Load as KEM key
		kp, err := crypto.LoadKEMPrivateKey(keyPubKey, passphrase)
		if err != nil {
			return fmt.Errorf("failed to load KEM private key: %w", err)
		}
		pubKey = kp.PublicKey
		alg = kp.Algorithm
	} else {
		// Load as signature key
		signer, err := crypto.LoadPrivateKey(keyPubKey, passphrase)
		if err != nil {
			return fmt.Errorf("failed to load private key: %w", err)
		}
		pubKey = signer.Public()
		alg = signer.Algorithm()
	}

	// Marshal and determine PEM type based on algorithm
	var pemBlock *pem.Block

	switch alg {
	case crypto.AlgECDSAP256, crypto.AlgECDSAP384, crypto.AlgECDSAP521,
		crypto.AlgECP256, crypto.AlgECP384, crypto.AlgECP521,
		crypto.AlgEd25519, crypto.AlgEd448, crypto.AlgRSA2048, crypto.AlgRSA4096:
		// Classical keys: use PKIX format
		pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
		if err != nil {
			return fmt.Errorf("failed to marshal public key: %w", err)
		}
		pemBlock = &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubKeyBytes,
		}

	default:
		// PQC keys (signature and KEM): use raw bytes with custom PEM type
		pubKeyBytes, err := crypto.PublicKeyBytes(pubKey)
		if err != nil {
			return fmt.Errorf("failed to marshal PQC public key: %w", err)
		}
		pemType := pqcPublicKeyPEMType(alg)
		pemBlock = &pem.Block{
			Type:  pemType,
			Bytes: pubKeyBytes,
		}
	}

	// Write to file
	outFile, err := os.Create(keyPubOut)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}

	if err := pem.Encode(outFile, pemBlock); err != nil {
		closeErr := outFile.Close()
		if closeErr != nil {
			return fmt.Errorf("failed to write public key: %w (close error: %v)", err, closeErr)
		}
		return fmt.Errorf("failed to write public key: %w", err)
	}

	if err := outFile.Close(); err != nil {
		return fmt.Errorf("failed to close output file: %w", err)
	}

	fmt.Printf("Public key extracted to: %s\n", keyPubOut)
	fmt.Printf("Algorithm: %s\n", alg.Description())

	return nil
}

// isKEMKeyFile checks if a PEM file contains a KEM private key.
// With PKCS#8 format, this requires attempting to load the key
// since all keys use "PRIVATE KEY" PEM type.
func isKEMKeyFile(path string) (bool, error) {
	// Try to load as KEM key - if it succeeds, it's a KEM key
	_, err := crypto.LoadKEMPrivateKey(path, nil)
	if err == nil {
		return true, nil
	}
	// Not a KEM key (or invalid/encrypted)
	return false, nil
}

// pqcPublicKeyPEMType returns the PEM type for a PQC public key.
func pqcPublicKeyPEMType(alg crypto.AlgorithmID) string {
	switch alg {
	// ML-DSA (signature)
	case crypto.AlgMLDSA44:
		return "ML-DSA-44 PUBLIC KEY"
	case crypto.AlgMLDSA65:
		return "ML-DSA-65 PUBLIC KEY"
	case crypto.AlgMLDSA87:
		return "ML-DSA-87 PUBLIC KEY"
	// SLH-DSA SHA2 variants (signature)
	case crypto.AlgSLHDSASHA2128s:
		return "SLH-DSA-SHA2-128s PUBLIC KEY"
	case crypto.AlgSLHDSASHA2128f:
		return "SLH-DSA-SHA2-128f PUBLIC KEY"
	case crypto.AlgSLHDSASHA2192s:
		return "SLH-DSA-SHA2-192s PUBLIC KEY"
	case crypto.AlgSLHDSASHA2192f:
		return "SLH-DSA-SHA2-192f PUBLIC KEY"
	case crypto.AlgSLHDSASHA2256s:
		return "SLH-DSA-SHA2-256s PUBLIC KEY"
	case crypto.AlgSLHDSASHA2256f:
		return "SLH-DSA-SHA2-256f PUBLIC KEY"
	// SLH-DSA SHAKE variants (signature)
	case crypto.AlgSLHDSASHAKE128s:
		return "SLH-DSA-SHAKE-128s PUBLIC KEY"
	case crypto.AlgSLHDSASHAKE128f:
		return "SLH-DSA-SHAKE-128f PUBLIC KEY"
	case crypto.AlgSLHDSASHAKE192s:
		return "SLH-DSA-SHAKE-192s PUBLIC KEY"
	case crypto.AlgSLHDSASHAKE192f:
		return "SLH-DSA-SHAKE-192f PUBLIC KEY"
	case crypto.AlgSLHDSASHAKE256s:
		return "SLH-DSA-SHAKE-256s PUBLIC KEY"
	case crypto.AlgSLHDSASHAKE256f:
		return "SLH-DSA-SHAKE-256f PUBLIC KEY"
	// ML-KEM (encryption)
	case crypto.AlgMLKEM512:
		return "ML-KEM-512 PUBLIC KEY"
	case crypto.AlgMLKEM768:
		return "ML-KEM-768 PUBLIC KEY"
	case crypto.AlgMLKEM1024:
		return "ML-KEM-1024 PUBLIC KEY"
	default:
		return "PUBLIC KEY"
	}
}

func runKeyList(cmd *cobra.Command, args []string) error {
	// Validate flags
	if keyListHSMConfig != "" && keyListDir != "" {
		return fmt.Errorf("--hsm-config and --dir are mutually exclusive")
	}
	if keyListHSMConfig == "" && keyListDir == "" {
		return fmt.Errorf("either --hsm-config or --dir is required")
	}

	if keyListHSMConfig != "" {
		return runKeyListHSM()
	}
	return runKeyListDir()
}

func runKeyListHSM() error {
	cfg, err := crypto.LoadHSMConfig(keyListHSMConfig)
	if err != nil {
		return fmt.Errorf("failed to load HSM config: %w", err)
	}

	pin, err := cfg.GetPIN()
	if err != nil {
		return fmt.Errorf("failed to get PIN: %w", err)
	}

	keys, err := crypto.ListHSMKeys(cfg.PKCS11.Lib, cfg.PKCS11.Token, pin)
	if err != nil {
		return fmt.Errorf("failed to list HSM keys: %w", err)
	}

	if len(keys) == 0 {
		fmt.Println("No private keys found in token.")
		return nil
	}

	fmt.Printf("Private keys in token %q:\n\n", cfg.PKCS11.Token)

	for _, key := range keys {
		fmt.Printf("  Label:   %s\n", key.Label)
		fmt.Printf("  ID:      %s\n", key.ID)
		fmt.Printf("  Type:    %s\n", key.Type)
		fmt.Printf("  CanSign: %v\n", key.CanSign)
		fmt.Println()
	}

	return nil
}

func runKeyListDir() error {
	// Read directory
	entries, err := os.ReadDir(keyListDir)
	if err != nil {
		return fmt.Errorf("failed to read directory: %w", err)
	}

	var keys []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		// Check for key file extensions
		if hasKeyExtension(name) {
			keys = append(keys, name)
		}
	}

	if len(keys) == 0 {
		fmt.Printf("No private key files found in %s\n", keyListDir)
		return nil
	}

	fmt.Printf("Private keys in %s:\n\n", keyListDir)

	for _, keyFile := range keys {
		keyPath := keyListDir + "/" + keyFile
		printKeyInfo(keyPath)
	}

	return nil
}

func hasKeyExtension(name string) bool {
	for _, ext := range []string{".pem", ".key"} {
		if len(name) > len(ext) && name[len(name)-len(ext):] == ext {
			return true
		}
	}
	return false
}

func printKeyInfo(keyPath string) {
	data, err := os.ReadFile(keyPath)
	if err != nil {
		fmt.Printf("  %s: error reading file\n", keyPath)
		return
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return // Not a PEM file
	}

	// Check if it's a private key
	if !isPrivateKeyPEM(block.Type) {
		return
	}

	encrypted := x509.IsEncryptedPEMBlock(block) //nolint:staticcheck

	// Try to determine algorithm from PEM type
	alg := algorithmFromPEMType(block.Type)

	fmt.Printf("  %s\n", keyPath)
	fmt.Printf("    Type:      %s\n", block.Type)
	if alg != "" {
		fmt.Printf("    Algorithm: %s\n", alg)
	}
	fmt.Printf("    Encrypted: %v\n", encrypted)
	fmt.Println()
}

func isPrivateKeyPEM(pemType string) bool {
	switch pemType {
	case "PRIVATE KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY",
		"ML-DSA-44 PRIVATE KEY", "ML-DSA-65 PRIVATE KEY", "ML-DSA-87 PRIVATE KEY",
		"SLH-DSA-SHAKE-128S PRIVATE KEY", "SLH-DSA-SHAKE-128F PRIVATE KEY",
		"SLH-DSA-SHAKE-192S PRIVATE KEY", "SLH-DSA-SHAKE-192F PRIVATE KEY",
		"SLH-DSA-SHAKE-256S PRIVATE KEY", "SLH-DSA-SHAKE-256F PRIVATE KEY",
		"ENCRYPTED PRIVATE KEY":
		return true
	}
	return false
}

func algorithmFromPEMType(pemType string) string {
	switch pemType {
	case "EC PRIVATE KEY":
		return "ECDSA"
	case "RSA PRIVATE KEY":
		return "RSA"
	case "ML-DSA-44 PRIVATE KEY":
		return "ML-DSA-44"
	case "ML-DSA-65 PRIVATE KEY":
		return "ML-DSA-65"
	case "ML-DSA-87 PRIVATE KEY":
		return "ML-DSA-87"
	case "SLH-DSA-SHAKE-128S PRIVATE KEY":
		return "SLH-DSA-SHAKE-128s"
	case "SLH-DSA-SHAKE-128F PRIVATE KEY":
		return "SLH-DSA-SHAKE-128f"
	case "SLH-DSA-SHAKE-192S PRIVATE KEY":
		return "SLH-DSA-SHAKE-192s"
	case "SLH-DSA-SHAKE-192F PRIVATE KEY":
		return "SLH-DSA-SHAKE-192f"
	case "SLH-DSA-SHAKE-256S PRIVATE KEY":
		return "SLH-DSA-SHAKE-256s"
	case "SLH-DSA-SHAKE-256F PRIVATE KEY":
		return "SLH-DSA-SHAKE-256f"
	case "PRIVATE KEY":
		return "PKCS#8 (EC/RSA/Ed25519)"
	case "ENCRYPTED PRIVATE KEY":
		return "PKCS#8 (encrypted)"
	}
	return ""
}

func runKeyInfo(cmd *cobra.Command, args []string) error {
	keyFile := args[0]

	// Read PEM file
	data, err := os.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("failed to read key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return fmt.Errorf("no PEM block found in %s", keyFile)
	}

	encrypted := x509.IsEncryptedPEMBlock(block) //nolint:staticcheck
	pemType := block.Type

	// If encrypted and no passphrase, show limited info
	if encrypted && keyInfoPassphrase == "" {
		fmt.Printf("File:       %s\n", keyFile)
		fmt.Printf("Format:     %s (encrypted)\n", pemType)
		fmt.Println("Encrypted:  Yes")
		fmt.Println("\nNote: Provide --passphrase to see full key details.")
		return nil
	}

	// Load the key to get algorithm info
	passphrase := []byte(keyInfoPassphrase)
	signer, err := crypto.LoadPrivateKey(keyFile, passphrase)
	if err != nil {
		return fmt.Errorf("failed to load key: %w", err)
	}

	alg := signer.Algorithm()
	keySize := getKeySize(signer)

	fmt.Printf("File:       %s\n", keyFile)
	fmt.Printf("Algorithm:  %s\n", alg.Description())
	fmt.Printf("Key Size:   %s\n", keySize)
	fmt.Printf("Encrypted:  %v\n", encrypted)
	fmt.Printf("Format:     %s\n", pemType)

	return nil
}

// getKeySize returns a human-readable key size string.
func getKeySize(signer *crypto.SoftwareSigner) string {
	pub := signer.Public()
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return fmt.Sprintf("%d bits", k.Curve.Params().BitSize)
	case ed25519.PublicKey:
		return "256 bits"
	case ed448.PublicKey:
		return "448 bits"
	case *rsa.PublicKey:
		return fmt.Sprintf("%d bits", k.N.BitLen())
	default:
		// PQC algorithms - report NIST security level
		alg := signer.Algorithm()
		switch alg {
		case crypto.AlgMLDSA44:
			return "NIST Level 1 (2528 bytes)"
		case crypto.AlgMLDSA65:
			return "NIST Level 3 (4032 bytes)"
		case crypto.AlgMLDSA87:
			return "NIST Level 5 (4896 bytes)"
		case crypto.AlgSLHDSA128s, crypto.AlgSLHDSA128f:
			return "NIST Level 1"
		case crypto.AlgSLHDSA192s, crypto.AlgSLHDSA192f:
			return "NIST Level 3"
		case crypto.AlgSLHDSA256s, crypto.AlgSLHDSA256f:
			return "NIST Level 5"
		default:
			return "unknown"
		}
	}
}

func runKeyConvert(cmd *cobra.Command, args []string) error {
	inputFile := args[0]

	// Load the input key
	passphrase := []byte(keyConvertPassphrase)
	signer, err := crypto.LoadPrivateKey(inputFile, passphrase)
	if err != nil {
		return fmt.Errorf("failed to load key: %w", err)
	}

	switch keyConvertFormat {
	case "pem":
		// Save as PEM with optional new passphrase
		newPass := []byte(keyConvertNewPass)
		if err := signer.SavePrivateKey(keyConvertOut, newPass); err != nil {
			return fmt.Errorf("failed to save key: %w", err)
		}

		fmt.Printf("Converted key saved to: %s\n", keyConvertOut)
		if len(newPass) > 0 {
			fmt.Println("Output key is encrypted.")
		} else {
			fmt.Println("Output key is NOT encrypted.")
		}

	case "der":
		// Save as DER (raw binary)
		if keyConvertNewPass != "" {
			return fmt.Errorf("DER format does not support encryption; use PEM for encrypted output")
		}

		derBytes, err := marshalPrivateKeyDER(signer)
		if err != nil {
			return fmt.Errorf("failed to marshal key to DER: %w", err)
		}

		if err := os.WriteFile(keyConvertOut, derBytes, 0600); err != nil {
			return fmt.Errorf("failed to write DER file: %w", err)
		}

		fmt.Printf("DER key saved to: %s\n", keyConvertOut)

	default:
		return fmt.Errorf("unsupported output format: %s (use 'pem' or 'der')", keyConvertFormat)
	}

	return nil
}

// marshalPrivateKeyDER marshals a private key to DER format.
func marshalPrivateKeyDER(signer *crypto.SoftwareSigner) ([]byte, error) {
	priv := signer.PrivateKey()

	switch k := priv.(type) {
	case *ecdsa.PrivateKey, ed25519.PrivateKey, ed448.PrivateKey, *rsa.PrivateKey:
		// Use PKCS#8 for classical keys
		return x509.MarshalPKCS8PrivateKey(priv)
	default:
		// PQC keys - return raw bytes
		// Note: There's no standard DER format for PQC keys yet
		return nil, fmt.Errorf("DER export not supported for %T; use PEM format", k)
	}
}
