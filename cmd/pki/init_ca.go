package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/remiblancher/pki/internal/ca"
	"github.com/remiblancher/pki/internal/crypto"
)

var initCACmd = &cobra.Command{
	Use:   "init-ca",
	Short: "Initialize a new Certificate Authority",
	Long: `Initialize a new Certificate Authority with a self-signed root certificate.

The CA will be created in the specified directory with the following structure:
  {dir}/
    ├── ca.crt           # CA certificate (PEM)
    ├── private/
    │   └── ca.key       # CA private key (PEM, optionally encrypted)
    ├── certs/           # Issued certificates
    ├── crl/             # Certificate Revocation Lists
    ├── index.txt        # Certificate database
    └── serial           # Serial number counter

Examples:
  # Create a root CA with ECDSA P-256
  pki init-ca --name "My Root CA" --dir ./myca

  # Create a CA with ML-DSA-65 (PQC)
  pki init-ca --name "PQC Root CA" --algorithm ml-dsa-65 --dir ./pqc-ca

  # Create a hybrid CA (ECDSA + ML-DSA)
  pki init-ca --name "Hybrid Root CA" --algorithm ecdsa-p384 \
    --hybrid-algorithm ml-dsa-65 --dir ./hybrid-ca`,
	RunE: runInitCA,
}

var (
	caDir             string
	caName            string
	caOrg             string
	caCountry         string
	caAlgorithm       string
	caValidityYears   int
	caPathLen         int
	caPassphrase      string
	caHybridAlgorithm string
)

func init() {
	flags := initCACmd.Flags()
	flags.StringVarP(&caDir, "dir", "d", "./ca", "Directory for the CA")
	flags.StringVarP(&caName, "name", "n", "", "CA common name (required)")
	flags.StringVarP(&caOrg, "org", "o", "", "Organization name")
	flags.StringVarP(&caCountry, "country", "c", "", "Country code (e.g., US, FR)")
	flags.StringVarP(&caAlgorithm, "algorithm", "a", "ecdsa-p256", "Signature algorithm")
	flags.IntVar(&caValidityYears, "validity", 10, "Validity period in years")
	flags.IntVar(&caPathLen, "path-len", 1, "Maximum path length constraint (-1 for unlimited)")
	flags.StringVarP(&caPassphrase, "passphrase", "p", "", "Passphrase for private key (or env:VAR_NAME)")
	flags.StringVar(&caHybridAlgorithm, "hybrid-algorithm", "", "PQC algorithm for hybrid extension")

	_ = initCACmd.MarkFlagRequired("name")
}

func runInitCA(cmd *cobra.Command, args []string) error {
	// Validate algorithm
	alg, err := crypto.ParseAlgorithm(caAlgorithm)
	if err != nil {
		return fmt.Errorf("invalid algorithm: %w", err)
	}

	if !alg.IsSignature() {
		return fmt.Errorf("algorithm %s is not suitable for signing", alg)
	}

	// Expand path
	absDir, err := filepath.Abs(caDir)
	if err != nil {
		return fmt.Errorf("invalid directory path: %w", err)
	}

	// Check if directory already exists
	store := ca.NewStore(absDir)
	if store.Exists() {
		return fmt.Errorf("CA already exists at %s", absDir)
	}

	// Build configuration
	cfg := ca.Config{
		CommonName:    caName,
		Organization:  caOrg,
		Country:       caCountry,
		Algorithm:     alg,
		ValidityYears: caValidityYears,
		PathLen:       caPathLen,
		Passphrase:    caPassphrase,
	}

	// Configure hybrid if requested
	if caHybridAlgorithm != "" {
		hybridAlg, err := crypto.ParseAlgorithm(caHybridAlgorithm)
		if err != nil {
			return fmt.Errorf("invalid hybrid algorithm: %w", err)
		}

		if !hybridAlg.IsPQC() {
			return fmt.Errorf("hybrid algorithm must be a PQC algorithm, got: %s", hybridAlg)
		}

		cfg.HybridConfig = &ca.HybridConfig{
			Algorithm: hybridAlg,
			// Default to informational policy for CA
			Policy: 0, // HybridPolicyInformational
		}
	}

	// Initialize CA
	fmt.Printf("Initializing CA at %s...\n", absDir)
	fmt.Printf("  Algorithm: %s\n", alg.Description())
	if cfg.HybridConfig != nil {
		fmt.Printf("  Hybrid PQC: %s\n", cfg.HybridConfig.Algorithm.Description())
	}

	newCA, err := ca.Initialize(store, cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize CA: %w", err)
	}

	cert := newCA.Certificate()
	fmt.Printf("\nCA initialized successfully!\n")
	fmt.Printf("  Subject:     %s\n", cert.Subject.String())
	fmt.Printf("  Serial:      %X\n", cert.SerialNumber.Bytes())
	fmt.Printf("  Not Before:  %s\n", cert.NotBefore.Format("2006-01-02 15:04:05"))
	fmt.Printf("  Not After:   %s\n", cert.NotAfter.Format("2006-01-02 15:04:05"))
	fmt.Printf("  Certificate: %s\n", store.CACertPath())
	fmt.Printf("  Private Key: %s\n", store.CAKeyPath())

	if caPassphrase == "" {
		fmt.Fprintf(os.Stderr, "\nWARNING: Private key is not encrypted. Use --passphrase for production.\n")
	}

	return nil
}
