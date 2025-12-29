package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

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

Supported algorithms:
  Classical:
    ecdsa-p256   - ECDSA with P-256 curve (default)
    ecdsa-p384   - ECDSA with P-384 curve
    ecdsa-p521   - ECDSA with P-521 curve
    ed25519      - Ed25519 (EdDSA)
    rsa-2048     - RSA 2048-bit
    rsa-4096     - RSA 4096-bit

  Post-Quantum (FIPS 204 ML-DSA):
    ml-dsa-44    - ML-DSA-44 (NIST Level 1)
    ml-dsa-65    - ML-DSA-65 (NIST Level 3)
    ml-dsa-87    - ML-DSA-87 (NIST Level 5)

  Post-Quantum (FIPS 205 SLH-DSA):
    slh-dsa-128f - SLH-DSA-SHA2-128f (NIST Level 1, fast)
    slh-dsa-128s - SLH-DSA-SHA2-128s (NIST Level 1, small)
    slh-dsa-192f - SLH-DSA-SHA2-192f (NIST Level 3, fast)
    slh-dsa-192s - SLH-DSA-SHA2-192s (NIST Level 3, small)
    slh-dsa-256f - SLH-DSA-SHA2-256f (NIST Level 5, fast)
    slh-dsa-256s - SLH-DSA-SHA2-256s (NIST Level 5, small)

Examples:
  # Generate an ECDSA P-256 key
  pki key gen --algorithm ecdsa-p256 --out key.pem

  # Generate an ML-DSA-65 key with passphrase
  pki key gen --algorithm ml-dsa-65 --out pqc-key.pem --passphrase secret`,
	RunE: runKeyGen,
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

	keyInfoPassphrase string

	keyConvertOut        string
	keyConvertFormat     string
	keyConvertPassphrase string
	keyConvertNewPass    string
)

func init() {
	keyCmd.AddCommand(keyGenCmd)
	keyCmd.AddCommand(keyInfoCmd)
	keyCmd.AddCommand(keyConvertCmd)

	// gen flags
	flags := keyGenCmd.Flags()
	flags.StringVarP(&keyGenAlgorithm, "algorithm", "a", "ecdsa-p256", "Key algorithm")
	flags.StringVarP(&keyGenOutput, "out", "o", "", "Output file (required)")
	flags.StringVarP(&keyGenPassphrase, "passphrase", "p", "", "Passphrase for encryption (or env:VAR_NAME)")
	_ = keyGenCmd.MarkFlagRequired("out")

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
	alg, err := crypto.ParseAlgorithm(keyGenAlgorithm)
	if err != nil {
		return fmt.Errorf("invalid algorithm: %w", err)
	}

	if !alg.IsSignature() {
		return fmt.Errorf("algorithm %s is not suitable for key generation (use a signature algorithm)", alg)
	}

	fmt.Printf("Generating %s key pair...\n", alg.Description())

	signer, err := crypto.GenerateSoftwareSigner(alg)
	if err != nil {
		return fmt.Errorf("failed to generate key pair: %w", err)
	}

	passphrase := []byte(keyGenPassphrase)
	if err := signer.SavePrivateKey(keyGenOutput, passphrase); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}

	fmt.Printf("Private key saved to: %s\n", keyGenOutput)
	if len(passphrase) == 0 {
		fmt.Println("WARNING: Private key is not encrypted.")
	} else {
		fmt.Println("Private key is encrypted with passphrase.")
	}

	return nil
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
	case *ecdsa.PrivateKey, ed25519.PrivateKey, *rsa.PrivateKey:
		// Use PKCS#8 for classical keys
		return x509.MarshalPKCS8PrivateKey(priv)
	default:
		// PQC keys - return raw bytes
		// Note: There's no standard DER format for PQC keys yet
		return nil, fmt.Errorf("DER export not supported for %T; use PEM format", k)
	}
}
