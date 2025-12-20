package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/remiblancher/pki/internal/ca"
	"github.com/remiblancher/pki/internal/crypto"
	"github.com/remiblancher/pki/internal/profile"
)

var initCACmd = &cobra.Command{
	Use:   "init-ca",
	Short: "Initialize a new Certificate Authority",
	Long: `Initialize a new Certificate Authority.

By default, creates a self-signed root CA. With --parent, creates a subordinate
CA signed by the specified parent CA.

The CA will be created in the specified directory with the following structure:
  {dir}/
    ├── ca.crt           # CA certificate (PEM)
    ├── chain.crt        # Certificate chain (subordinate CA only)
    ├── private/
    │   └── ca.key       # CA private key (PEM, optionally encrypted)
    ├── certs/           # Issued certificates
    ├── crl/             # Certificate Revocation Lists
    ├── index.txt        # Certificate database
    └── serial           # Serial number counter

Examples:
  # Create a root CA with ECDSA P-256
  pki init-ca --name "My Root CA" --dir ./root-ca

  # Create a root CA using a profile
  pki init-ca --name "My Root CA" --profile ec/root-ca --dir ./root-ca

  # Create a hybrid root CA using a profile
  pki init-ca --name "Hybrid Root CA" --profile hybrid/catalyst/root-ca --dir ./hybrid-ca

  # Create a subordinate CA signed by the root
  pki init-ca --name "Issuing CA" --dir ./issuing-ca --parent ./root-ca

  # Create a subordinate CA using a profile
  pki init-ca --name "Issuing CA" --profile ec/issuing-ca --dir ./issuing-ca --parent ./root-ca

  # Create a CA with ML-DSA-65 (PQC)
  pki init-ca --name "PQC Root CA" --algorithm ml-dsa-65 --dir ./pqc-ca

  # Create a hybrid CA (ECDSA + ML-DSA) without profile
  pki init-ca --name "Hybrid Root CA" --algorithm ecdsa-p384 \
    --hybrid-algorithm ml-dsa-65 --dir ./hybrid-ca`,
	RunE: runInitCA,
}

var (
	caDir              string
	caName             string
	caOrg              string
	caCountry          string
	caAlgorithm        string
	caValidityYears    int
	caPathLen          int
	caPassphrase       string
	caHybridAlgorithm  string
	caParentDir        string
	caParentPassphrase string
	caProfile          string
)

func init() {
	flags := initCACmd.Flags()
	flags.StringVarP(&caDir, "dir", "d", "./ca", "Directory for the CA")
	flags.StringVarP(&caName, "name", "n", "", "CA common name (required)")
	flags.StringVarP(&caOrg, "org", "o", "", "Organization name")
	flags.StringVarP(&caCountry, "country", "c", "", "Country code (e.g., US, FR)")
	flags.StringVarP(&caProfile, "profile", "P", "", "CA profile (e.g., ec/root-ca, hybrid/catalyst/issuing-ca)")
	flags.StringVarP(&caAlgorithm, "algorithm", "a", "ecdsa-p256", "Signature algorithm")
	flags.IntVar(&caValidityYears, "validity", 10, "Validity period in years")
	flags.IntVar(&caPathLen, "path-len", 1, "Maximum path length constraint (-1 for unlimited)")
	flags.StringVarP(&caPassphrase, "passphrase", "p", "", "Passphrase for private key (or env:VAR_NAME)")
	flags.StringVar(&caHybridAlgorithm, "hybrid-algorithm", "", "PQC algorithm for hybrid extension")
	flags.StringVar(&caParentDir, "parent", "", "Parent CA directory (creates subordinate CA)")
	flags.StringVar(&caParentPassphrase, "parent-passphrase", "", "Parent CA private key passphrase")

	_ = initCACmd.MarkFlagRequired("name")
}

func runInitCA(cmd *cobra.Command, args []string) error {
	// Delegate to subordinate CA initialization if parent is specified
	if caParentDir != "" {
		return runInitSubordinateCA(cmd, args)
	}

	var alg crypto.AlgorithmID
	var hybridAlg crypto.AlgorithmID
	var validityYears int
	var pathLen int
	var err error

	// Load profile if specified
	if caProfile != "" {
		prof, err := profile.GetBuiltinProfile(caProfile)
		if err != nil {
			return fmt.Errorf("failed to load profile %s: %w", caProfile, err)
		}

		// Extract algorithm from profile
		alg = prof.Signature.Algorithms.Primary
		if !alg.IsValid() {
			return fmt.Errorf("profile %s has invalid algorithm: %s", caProfile, alg)
		}

		// Extract hybrid algorithm if profile is hybrid
		if prof.IsHybridSignature() {
			hybridAlg = prof.Signature.Algorithms.Alternative
		}

		// Extract validity (convert from duration to years)
		validityYears = int(prof.Validity.Hours() / 24 / 365)
		if validityYears < 1 {
			validityYears = 1
		}

		// Extract pathLen from profile extensions
		pathLen = 1 // default
		if prof.Extensions != nil && prof.Extensions.BasicConstraints != nil && prof.Extensions.BasicConstraints.PathLen != nil {
			pathLen = *prof.Extensions.BasicConstraints.PathLen
		}

		// Use profile subject values as defaults (CLI flags can override)
		if prof.Subject != nil && prof.Subject.Fixed != nil {
			if caOrg == "" {
				caOrg = prof.Subject.Fixed["o"]
			}
			if caCountry == "" {
				caCountry = prof.Subject.Fixed["c"]
			}
		}

		fmt.Printf("Using profile: %s\n", caProfile)
	} else {
		// Use flags directly (backward compatibility)
		alg, err = crypto.ParseAlgorithm(caAlgorithm)
		if err != nil {
			return fmt.Errorf("invalid algorithm: %w", err)
		}

		if caHybridAlgorithm != "" {
			hybridAlg, err = crypto.ParseAlgorithm(caHybridAlgorithm)
			if err != nil {
				return fmt.Errorf("invalid hybrid algorithm: %w", err)
			}
		}

		validityYears = caValidityYears
		pathLen = caPathLen
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
		ValidityYears: validityYears,
		PathLen:       pathLen,
		Passphrase:    caPassphrase,
	}

	// Configure hybrid if requested (from profile or flag)
	if hybridAlg != "" {
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

	var newCA *ca.CA
	if cfg.HybridConfig != nil {
		// Use InitializeHybridCA for proper PQC key persistence
		hybridCfg := ca.HybridCAConfig{
			CommonName:         cfg.CommonName,
			Organization:       cfg.Organization,
			Country:            cfg.Country,
			ClassicalAlgorithm: cfg.Algorithm,
			PQCAlgorithm:       cfg.HybridConfig.Algorithm,
			ValidityYears:      cfg.ValidityYears,
			PathLen:            cfg.PathLen,
			Passphrase:         cfg.Passphrase,
		}
		newCA, err = ca.InitializeHybridCA(store, hybridCfg)
	} else {
		newCA, err = ca.Initialize(store, cfg)
	}
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
	if cfg.HybridConfig != nil {
		fmt.Printf("  PQC Key:     %s.pqc\n", store.CAKeyPath())
	}

	if caPassphrase == "" {
		fmt.Fprintf(os.Stderr, "\nWARNING: Private key is not encrypted. Use --passphrase for production.\n")
	}

	return nil
}

// runInitSubordinateCA creates a subordinate CA signed by a parent CA.
func runInitSubordinateCA(cmd *cobra.Command, args []string) error {
	var alg crypto.AlgorithmID
	var validityYears int
	var pathLen int
	var extensions *profile.ExtensionsConfig
	var err error

	// Load profile if specified
	if caProfile != "" {
		prof, err := profile.GetBuiltinProfile(caProfile)
		if err != nil {
			return fmt.Errorf("failed to load profile %s: %w", caProfile, err)
		}

		// Extract algorithm from profile
		alg = prof.Signature.Algorithms.Primary
		if !alg.IsValid() {
			return fmt.Errorf("profile %s has invalid algorithm: %s", caProfile, alg)
		}

		// Extract validity (convert from duration to years)
		validityYears = int(prof.Validity.Hours() / 24 / 365)
		if validityYears < 1 {
			validityYears = 1
		}

		// Extract pathLen from profile extensions
		pathLen = 0 // default for issuing CA
		if prof.Extensions != nil && prof.Extensions.BasicConstraints != nil && prof.Extensions.BasicConstraints.PathLen != nil {
			pathLen = *prof.Extensions.BasicConstraints.PathLen
		}

		// Use profile extensions
		extensions = prof.Extensions

		// Use profile subject values as defaults (CLI flags can override)
		if prof.Subject != nil && prof.Subject.Fixed != nil {
			if caOrg == "" {
				caOrg = prof.Subject.Fixed["o"]
			}
			if caCountry == "" {
				caCountry = prof.Subject.Fixed["c"]
			}
		}

		fmt.Printf("Using profile: %s\n", caProfile)
	} else {
		// Use flags directly (backward compatibility)
		alg, err = crypto.ParseAlgorithm(caAlgorithm)
		if err != nil {
			return fmt.Errorf("invalid algorithm: %w", err)
		}

		validityYears = caValidityYears
		pathLen = caPathLen

		// Build default extensions for subordinate CA
		criticalTrue := true
		extensions = &profile.ExtensionsConfig{
			KeyUsage: &profile.KeyUsageConfig{
				Critical: &criticalTrue,
				Values:   []string{"keyCertSign", "cRLSign"},
			},
			BasicConstraints: &profile.BasicConstraintsConfig{
				Critical: &criticalTrue,
				CA:       true,
				PathLen:  &pathLen,
			},
		}
	}

	if !alg.IsSignature() {
		return fmt.Errorf("algorithm %s is not suitable for signing", alg)
	}

	// Load parent CA
	parentAbsDir, err := filepath.Abs(caParentDir)
	if err != nil {
		return fmt.Errorf("invalid parent directory path: %w", err)
	}

	parentStore := ca.NewStore(parentAbsDir)
	if !parentStore.Exists() {
		return fmt.Errorf("parent CA not found at %s", parentAbsDir)
	}

	parentCA, err := ca.New(parentStore)
	if err != nil {
		return fmt.Errorf("failed to load parent CA: %w", err)
	}

	if err := parentCA.LoadSigner(caParentPassphrase); err != nil {
		return fmt.Errorf("failed to load parent CA signer: %w", err)
	}

	// Expand path for new CA
	absDir, err := filepath.Abs(caDir)
	if err != nil {
		return fmt.Errorf("invalid directory path: %w", err)
	}

	// Check if directory already exists
	store := ca.NewStore(absDir)
	if store.Exists() {
		return fmt.Errorf("CA already exists at %s", absDir)
	}

	// Initialize store directory structure
	if err := store.Init(); err != nil {
		return fmt.Errorf("failed to initialize store: %w", err)
	}

	// Generate CA key pair
	signer, err := crypto.GenerateSoftwareSigner(alg)
	if err != nil {
		return fmt.Errorf("failed to generate CA key: %w", err)
	}

	// Save private key
	passphrase := []byte(caPassphrase)
	if err := signer.SavePrivateKey(store.CAKeyPath(), passphrase); err != nil {
		return fmt.Errorf("failed to save CA key: %w", err)
	}

	// Issue subordinate CA certificate using parent
	fmt.Printf("Initializing subordinate CA at %s...\n", absDir)
	fmt.Printf("  Parent CA:  %s\n", parentCA.Certificate().Subject.String())
	fmt.Printf("  Algorithm:  %s\n", alg.Description())

	// Build subject
	subject := pkix.Name{
		CommonName: caName,
	}
	if caOrg != "" {
		subject.Organization = []string{caOrg}
	}
	if caCountry != "" {
		subject.Country = []string{caCountry}
	}

	// Build template
	template := &x509.Certificate{
		Subject: subject,
	}

	// Issue certificate
	validity := time.Duration(validityYears) * 365 * 24 * time.Hour
	cert, err := parentCA.Issue(ca.IssueRequest{
		Template:   template,
		PublicKey:  signer.Public(),
		Extensions: extensions,
		Validity:   validity,
	})
	if err != nil {
		return fmt.Errorf("failed to issue subordinate CA certificate: %w", err)
	}

	// Save CA certificate
	if err := store.SaveCACert(cert); err != nil {
		return fmt.Errorf("failed to save CA certificate: %w", err)
	}

	// Create certificate chain file
	chainPath := filepath.Join(absDir, "chain.crt")
	chainFile, err := os.Create(chainPath)
	if err != nil {
		return fmt.Errorf("failed to create chain file: %w", err)
	}
	defer chainFile.Close()

	// Write subordinate CA cert first, then parent
	subBlock := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
	if err := pem.Encode(chainFile, subBlock); err != nil {
		return fmt.Errorf("failed to write subordinate certificate to chain: %w", err)
	}

	parentBlock := &pem.Block{Type: "CERTIFICATE", Bytes: parentCA.Certificate().Raw}
	if err := pem.Encode(chainFile, parentBlock); err != nil {
		return fmt.Errorf("failed to write parent certificate to chain: %w", err)
	}

	fmt.Printf("\nSubordinate CA initialized successfully!\n")
	fmt.Printf("  Subject:     %s\n", cert.Subject.String())
	fmt.Printf("  Issuer:      %s\n", cert.Issuer.String())
	fmt.Printf("  Serial:      %X\n", cert.SerialNumber.Bytes())
	fmt.Printf("  Not Before:  %s\n", cert.NotBefore.Format("2006-01-02 15:04:05"))
	fmt.Printf("  Not After:   %s\n", cert.NotAfter.Format("2006-01-02 15:04:05"))
	fmt.Printf("  Certificate: %s\n", store.CACertPath())
	fmt.Printf("  Chain:       %s\n", chainPath)
	fmt.Printf("  Private Key: %s\n", store.CAKeyPath())

	if caPassphrase == "" {
		fmt.Fprintf(os.Stderr, "\nWARNING: Private key is not encrypted. Use --passphrase for production.\n")
	}

	return nil
}
