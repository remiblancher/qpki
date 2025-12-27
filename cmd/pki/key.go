package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/remiblancher/pki/internal/crypto"
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

var (
	keyGenAlgorithm  string
	keyGenOutput     string
	keyGenPassphrase string
)

func init() {
	keyCmd.AddCommand(keyGenCmd)

	flags := keyGenCmd.Flags()
	flags.StringVarP(&keyGenAlgorithm, "algorithm", "a", "ecdsa-p256", "Key algorithm")
	flags.StringVarP(&keyGenOutput, "out", "o", "", "Output file (required)")
	flags.StringVarP(&keyGenPassphrase, "passphrase", "p", "", "Passphrase for encryption (or env:VAR_NAME)")

	_ = keyGenCmd.MarkFlagRequired("out")
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
