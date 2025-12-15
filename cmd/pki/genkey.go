package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/remiblancher/pki/internal/crypto"
)

var genkeyCmd = &cobra.Command{
	Use:   "genkey",
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

Examples:
  # Generate an ECDSA P-256 key
  pki genkey --algorithm ecdsa-p256 --out key.pem

  # Generate an ML-DSA-65 key with passphrase
  pki genkey --algorithm ml-dsa-65 --out pqc-key.pem --passphrase secret`,
	RunE: runGenkey,
}

var (
	genkeyAlgorithm  string
	genkeyOutput     string
	genkeyPassphrase string
)

func init() {
	flags := genkeyCmd.Flags()
	flags.StringVarP(&genkeyAlgorithm, "algorithm", "a", "ecdsa-p256", "Key algorithm")
	flags.StringVarP(&genkeyOutput, "out", "o", "", "Output file (required)")
	flags.StringVarP(&genkeyPassphrase, "passphrase", "p", "", "Passphrase for encryption (or env:VAR_NAME)")

	_ = genkeyCmd.MarkFlagRequired("out")
}

func runGenkey(cmd *cobra.Command, args []string) error {
	alg, err := crypto.ParseAlgorithm(genkeyAlgorithm)
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

	passphrase := []byte(genkeyPassphrase)
	if err := signer.SavePrivateKey(genkeyOutput, passphrase); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}

	fmt.Printf("Private key saved to: %s\n", genkeyOutput)
	if len(passphrase) == 0 {
		fmt.Println("WARNING: Private key is not encrypted.")
	} else {
		fmt.Println("Private key is encrypted with passphrase.")
	}

	return nil
}
