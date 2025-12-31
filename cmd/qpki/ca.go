package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/remiblancher/post-quantum-pki/internal/ca"
	"github.com/remiblancher/post-quantum-pki/internal/crypto"
	"github.com/remiblancher/post-quantum-pki/internal/profile"
	"github.com/remiblancher/post-quantum-pki/internal/x509util"
)

// caCmd is the parent command for CA operations.
var caCmd = &cobra.Command{
	Use:   "ca",
	Short: "Certificate Authority management",
	Long: `Manage Certificate Authorities.

Commands:
  init    Initialize a new CA (root or subordinate)
  info    Display CA information

Examples:
  # Create a root CA
  pki ca init --name "My Root CA" --profile ec/root-ca --dir ./root-ca

  # Create a subordinate CA
  pki ca init --name "Issuing CA" --profile ec/issuing-ca --dir ./issuing-ca --parent ./root-ca

  # Show CA information
  pki ca info --ca-dir ./root-ca`,
}

var caInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize a new Certificate Authority",
	Long: `Initialize a new Certificate Authority.

Creates a CA using a certificate profile that defines the algorithm, validity,
and extensions. With --parent, creates a subordinate CA signed by the parent.

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

Available profiles (use 'pki profile list' to see all):
  ec/root-ca                   ECDSA P-384 root CA
  ec/issuing-ca                ECDSA P-384 issuing CA
  ml-dsa/root-ca               ML-DSA-65 (PQC) root CA
  hybrid/catalyst/root-ca      ECDSA + ML-DSA catalyst root CA

HSM Support:
  Use --hsm-config with --key-label to initialize a CA using an existing
  key stored in a Hardware Security Module (HSM) via PKCS#11.
  Use --generate-key to generate a new key in the HSM during initialization.
  Note: HSM mode only supports classical profiles (ec/*, rsa/*).

Examples:
  # Create a root CA with ECDSA
  pki ca init --name "My Root CA" --profile ec/root-ca --dir ./root-ca

  # Create a PQC root CA with ML-DSA-65
  pki ca init --name "PQC Root CA" --profile ml-dsa/root-ca --dir ./pqc-ca

  # Create a hybrid (catalyst) root CA
  pki ca init --name "Hybrid Root CA" --profile hybrid/catalyst/root-ca --dir ./hybrid-ca

  # Create a subordinate CA signed by the root
  pki ca init --name "Issuing CA" --profile ec/issuing-ca --dir ./issuing-ca --parent ./root-ca

  # Protect private key with a passphrase
  pki ca init --name "My CA" --profile ec/root-ca --passphrase "secret" --dir ./ca

  # Create a CA using an existing HSM key
  export HSM_PIN="****"
  pki ca init --name "HSM Root CA" --profile ec/root-ca --dir ./hsm-ca \
    --hsm-config ./hsm.yaml --key-label "root-ca-key"

  # Create a CA and generate the key in HSM
  export HSM_PIN="****"
  pki ca init --name "HSM Root CA" --profile ec/root-ca --dir ./hsm-ca \
    --hsm-config ./hsm.yaml --key-label "new-root-key" --generate-key`,
	RunE: runCAInit,
}

var caInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Display CA information",
	Long:  `Display detailed information about a Certificate Authority.`,
	RunE:  runCAInfo,
}

// CRL commands
var crlCmd = &cobra.Command{
	Use:   "crl",
	Short: "CRL management",
	Long:  `Manage Certificate Revocation Lists (CRLs).`,
}

var crlGenCmd = &cobra.Command{
	Use:   "gen",
	Short: "Generate a Certificate Revocation List",
	Long: `Generate a new Certificate Revocation List (CRL).

The CRL contains all revoked certificates and is signed by the CA.
It should be distributed to relying parties for certificate validation.

Examples:
  # Generate CRL valid for 7 days
  pki ca crl gen

  # Generate CRL valid for 30 days
  pki ca crl gen --days 30`,
	RunE: runCRLGen,
}

var caExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export CA certificates",
	Long: `Export CA certificate chain in various formats.

Bundle types:
  ca      - CA certificate only (default)
  chain   - Full certificate chain (CA + parents)
  root    - Root CA certificate only

Examples:
  # Export CA certificate
  pki ca export --ca-dir ./issuing-ca

  # Export full chain to file
  pki ca export --ca-dir ./issuing-ca --bundle chain -o chain.pem

  # Export root only
  pki ca export --ca-dir ./issuing-ca --bundle root -o root.pem

  # Export specific version (for versioned CAs)
  pki ca export --ca-dir ./issuing-ca --version v20240101_abc123 -o v1.pem`,
	RunE: runCAExport,
}

var caListCmd = &cobra.Command{
	Use:   "list",
	Short: "List Certificate Authorities",
	Long: `List all Certificate Authorities in a directory.

Scans subdirectories for CA structures (directories containing ca.crt).

Examples:
  # List CAs in current directory
  pki ca list

  # List CAs in specific directory
  pki ca list --dir ./pki/cas`,
	RunE: runCAList,
}

var (
	crlGenCADir      string
	crlGenDays       int
	crlGenPassphrase string
)

var (
	caExportDir     string
	caExportBundle  string
	caExportOut     string
	caExportFormat  string
	caExportVersion string
	caExportAll     bool

	caListDir string
)

var (
	caInitDir              string
	caInitName             string
	caInitOrg              string
	caInitCountry          string
	caInitValidityYears    int
	caInitPathLen          int
	caInitPassphrase       string
	caInitParentDir        string
	caInitParentPassphrase string
	caInitProfile          string

	// HSM-related flags (only for ca init)
	caInitHSMConfig   string
	caInitKeyLabel    string
	caInitKeyID       string
	caInitGenerateKey bool

	caInfoDir string
)

func init() {
	// Add subcommands
	caCmd.AddCommand(caInitCmd)
	caCmd.AddCommand(caInfoCmd)
	caCmd.AddCommand(crlCmd)
	caCmd.AddCommand(caExportCmd)
	caCmd.AddCommand(caListCmd)

	// CRL subcommands
	crlCmd.AddCommand(crlGenCmd)

	// CRL gen flags
	crlGenCmd.Flags().StringVarP(&crlGenCADir, "ca-dir", "d", "./ca", "CA directory")
	crlGenCmd.Flags().IntVar(&crlGenDays, "days", 7, "CRL validity in days")
	crlGenCmd.Flags().StringVar(&crlGenPassphrase, "ca-passphrase", "", "CA private key passphrase")

	// Export flags
	caExportCmd.Flags().StringVarP(&caExportDir, "ca-dir", "d", "./ca", "CA directory")
	caExportCmd.Flags().StringVarP(&caExportBundle, "bundle", "b", "ca", "Bundle type: ca, chain, root")
	caExportCmd.Flags().StringVarP(&caExportOut, "out", "o", "", "Output file (default: stdout)")
	caExportCmd.Flags().StringVarP(&caExportFormat, "format", "f", "pem", "Output format: pem, der")
	caExportCmd.Flags().StringVarP(&caExportVersion, "version", "v", "", "Export specific CA version (use v1, v2, etc. for ordinal or full version ID)")
	caExportCmd.Flags().BoolVar(&caExportAll, "all", false, "Export all CA versions (for versioned CAs)")

	// List flags
	caListCmd.Flags().StringVarP(&caListDir, "dir", "d", ".", "Directory containing CAs")

	// Init flags
	initFlags := caInitCmd.Flags()
	initFlags.StringVarP(&caInitDir, "dir", "d", "./ca", "Directory for the CA")
	initFlags.StringVarP(&caInitName, "name", "n", "", "CA common name (required)")
	initFlags.StringVarP(&caInitOrg, "org", "o", "", "Organization name")
	initFlags.StringVarP(&caInitCountry, "country", "c", "", "Country code (e.g., US, FR)")
	initFlags.StringVarP(&caInitProfile, "profile", "P", "", "CA profile (e.g., ec/root-ca, hybrid/catalyst/issuing-ca)")
	initFlags.IntVar(&caInitValidityYears, "validity", 10, "Validity period in years (overrides profile)")
	initFlags.IntVar(&caInitPathLen, "path-len", 1, "Maximum path length constraint (overrides profile)")
	initFlags.StringVarP(&caInitPassphrase, "passphrase", "p", "", "Passphrase for private key (or env:VAR_NAME)")
	initFlags.StringVar(&caInitParentDir, "parent", "", "Parent CA directory (creates subordinate CA)")
	initFlags.StringVar(&caInitParentPassphrase, "parent-passphrase", "", "Parent CA private key passphrase")

	// HSM flags (for using existing key in HSM)
	initFlags.StringVar(&caInitHSMConfig, "hsm-config", "", "Path to HSM configuration file (enables HSM mode)")
	initFlags.StringVar(&caInitKeyLabel, "key-label", "", "Key label in HSM (required with --hsm-config)")
	initFlags.StringVar(&caInitKeyID, "key-id", "", "Key ID in HSM (hex, optional with --hsm-config)")
	initFlags.BoolVar(&caInitGenerateKey, "generate-key", false, "Generate new key in HSM (requires --hsm-config and --key-label)")

	_ = caInitCmd.MarkFlagRequired("name")
	_ = caInitCmd.MarkFlagRequired("profile")

	// Info flags
	caInfoCmd.Flags().StringVarP(&caInfoDir, "ca-dir", "d", "./ca", "CA directory")
}

func runCAInit(cmd *cobra.Command, args []string) error {
	// Delegate to subordinate CA initialization if parent is specified
	if caInitParentDir != "" {
		return runCAInitSubordinate(cmd, args)
	}

	// Delegate to HSM initialization if HSM config is specified
	if caInitHSMConfig != "" {
		return runCAInitHSM(cmd, args)
	}

	var alg crypto.AlgorithmID
	var hybridAlg crypto.AlgorithmID
	var validityYears int
	var pathLen int
	var err error

	// Track if this is a composite profile
	var isComposite bool

	// Load profile (required)
	prof, err := profile.LoadProfile(caInitProfile)
	if err != nil {
		return fmt.Errorf("failed to load profile %s: %w", caInitProfile, err)
	}

	// Extract algorithm from profile
	alg = prof.GetAlgorithm()
	if !alg.IsValid() {
		return fmt.Errorf("profile %s has invalid algorithm: %s", caInitProfile, alg)
	}

	// Extract hybrid algorithm if profile is Catalyst or Composite
	if prof.IsCatalyst() {
		hybridAlg = prof.GetAlternativeAlgorithm()
	} else if prof.IsComposite() {
		hybridAlg = prof.GetAlternativeAlgorithm()
		isComposite = true
	}

	// Extract validity (convert from duration to years)
	validityYears = int(prof.Validity.Hours() / 24 / 365)
	if validityYears < 1 {
		validityYears = 1
	}

	// Allow CLI flags to override profile values
	if cmd.Flags().Changed("validity") {
		validityYears = caInitValidityYears
	}

	// Extract pathLen from profile extensions
	pathLen = 1 // default
	if prof.Extensions != nil && prof.Extensions.BasicConstraints != nil && prof.Extensions.BasicConstraints.PathLen != nil {
		pathLen = *prof.Extensions.BasicConstraints.PathLen
	}
	if cmd.Flags().Changed("path-len") {
		pathLen = caInitPathLen
	}

	// Use profile subject values as defaults (CLI flags can override)
	if prof.Subject != nil && prof.Subject.Fixed != nil {
		if caInitOrg == "" {
			caInitOrg = prof.Subject.Fixed["o"]
		}
		if caInitCountry == "" {
			caInitCountry = prof.Subject.Fixed["c"]
		}
	}

	fmt.Printf("Using profile: %s\n", caInitProfile)

	if !alg.IsSignature() {
		return fmt.Errorf("algorithm %s is not suitable for signing", alg)
	}

	// Expand path
	absDir, err := filepath.Abs(caInitDir)
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
		CommonName:    caInitName,
		Organization:  caInitOrg,
		Country:       caInitCountry,
		Algorithm:     alg,
		ValidityYears: validityYears,
		PathLen:       pathLen,
		Passphrase:    caInitPassphrase,
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
	if isComposite && cfg.HybridConfig != nil {
		// Use InitializeCompositeCA for IETF composite signatures
		compositeCfg := ca.CompositeCAConfig{
			CommonName:         cfg.CommonName,
			Organization:       cfg.Organization,
			Country:            cfg.Country,
			ClassicalAlgorithm: cfg.Algorithm,
			PQCAlgorithm:       cfg.HybridConfig.Algorithm,
			ValidityYears:      cfg.ValidityYears,
			PathLen:            cfg.PathLen,
			Passphrase:         cfg.Passphrase,
		}
		newCA, err = ca.InitializeCompositeCA(store, compositeCfg)
	} else if cfg.HybridConfig != nil {
		// Use InitializeHybridCA for Catalyst mode (PQC in extension)
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
	} else if alg.IsPQC() {
		// Use InitializePQCCA for pure PQC certificates (manual DER construction)
		pqcCfg := ca.PQCCAConfig{
			CommonName:    cfg.CommonName,
			Organization:  cfg.Organization,
			Country:       cfg.Country,
			Algorithm:     cfg.Algorithm,
			ValidityYears: cfg.ValidityYears,
			PathLen:       cfg.PathLen,
			Passphrase:    cfg.Passphrase,
		}
		newCA, err = ca.InitializePQCCA(store, pqcCfg)
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
		if isComposite {
			fmt.Printf("  Mode:        Composite (IETF)\n")
		} else {
			fmt.Printf("  Mode:        Catalyst (ITU-T)\n")
		}
		fmt.Printf("  PQC Key:     %s.pqc\n", store.CAKeyPath())
	}

	if caInitPassphrase == "" {
		fmt.Fprintf(os.Stderr, "\nWARNING: Private key is not encrypted. Use --passphrase for production.\n")
	}

	return nil
}

// runCAInitHSM creates a CA using an existing key in an HSM.
func runCAInitHSM(cmd *cobra.Command, args []string) error {
	// Validate HSM flags
	if caInitGenerateKey {
		// For key generation, --key-label is required
		if caInitKeyLabel == "" {
			return fmt.Errorf("--key-label is required when using --generate-key")
		}
	} else {
		// For existing key, either label or ID is required
		if caInitKeyLabel == "" && caInitKeyID == "" {
			return fmt.Errorf("--key-label or --key-id is required when using --hsm-config (or use --generate-key)")
		}
	}

	// Load HSM configuration
	hsmCfg, err := crypto.LoadHSMConfig(caInitHSMConfig)
	if err != nil {
		return fmt.Errorf("failed to load HSM config: %w", err)
	}

	// Load profile
	prof, err := profile.LoadProfile(caInitProfile)
	if err != nil {
		return fmt.Errorf("failed to load profile %s: %w", caInitProfile, err)
	}

	// Get algorithm from profile
	alg := prof.GetAlgorithm()
	if !alg.IsValid() {
		return fmt.Errorf("profile %s has invalid algorithm: %s", caInitProfile, alg)
	}

	// Validate: HSM only supports classical algorithms (no PQC/hybrid)
	if alg.IsPQC() {
		return fmt.Errorf("HSM does not support PQC algorithms. Use a classical profile (ec/*, rsa/*) or remove --hsm-config")
	}
	if prof.IsCatalyst() || prof.IsComposite() {
		return fmt.Errorf("HSM does not support hybrid/composite profiles. Use a classical profile (ec/*, rsa/*) or remove --hsm-config")
	}

	// Extract validity
	validityYears := int(prof.Validity.Hours() / 24 / 365)
	if validityYears < 1 {
		validityYears = 1
	}
	if cmd.Flags().Changed("validity") {
		validityYears = caInitValidityYears
	}

	// Extract pathLen
	pathLen := 1
	if prof.Extensions != nil && prof.Extensions.BasicConstraints != nil && prof.Extensions.BasicConstraints.PathLen != nil {
		pathLen = *prof.Extensions.BasicConstraints.PathLen
	}
	if cmd.Flags().Changed("path-len") {
		pathLen = caInitPathLen
	}

	// Use profile subject values as defaults
	if prof.Subject != nil && prof.Subject.Fixed != nil {
		if caInitOrg == "" {
			caInitOrg = prof.Subject.Fixed["o"]
		}
		if caInitCountry == "" {
			caInitCountry = prof.Subject.Fixed["c"]
		}
	}

	fmt.Printf("Using profile: %s\n", caInitProfile)
	fmt.Printf("HSM config: %s\n", caInitHSMConfig)

	// Expand path
	absDir, err := filepath.Abs(caInitDir)
	if err != nil {
		return fmt.Errorf("invalid directory path: %w", err)
	}

	// Check if directory already exists
	store := ca.NewStore(absDir)
	if store.Exists() {
		return fmt.Errorf("CA already exists at %s", absDir)
	}

	// Generate key in HSM if requested
	keyLabel := caInitKeyLabel
	keyID := caInitKeyID
	if caInitGenerateKey {
		pin, err := hsmCfg.GetPIN()
		if err != nil {
			return fmt.Errorf("failed to get PIN: %w", err)
		}

		fmt.Printf("Generating %s key in HSM...\n", alg)
		genCfg := crypto.GenerateHSMKeyPairConfig{
			ModulePath: hsmCfg.PKCS11.Lib,
			TokenLabel: hsmCfg.PKCS11.Token,
			PIN:        pin,
			KeyLabel:   caInitKeyLabel,
			Algorithm:  alg,
		}

		result, err := crypto.GenerateHSMKeyPair(genCfg)
		if err != nil {
			return fmt.Errorf("failed to generate key in HSM: %w", err)
		}

		fmt.Printf("  Key generated: label=%s, id=%s\n", result.KeyLabel, result.KeyID)
		keyLabel = result.KeyLabel
		keyID = result.KeyID
	}

	// Create PKCS#11 config from HSM config
	pkcs11Cfg, err := hsmCfg.ToPKCS11Config(keyLabel, keyID)
	if err != nil {
		return fmt.Errorf("failed to create PKCS#11 config: %w", err)
	}

	// Create PKCS#11 signer
	fmt.Printf("Connecting to HSM...\n")
	signer, err := crypto.NewPKCS11Signer(*pkcs11Cfg)
	if err != nil {
		return fmt.Errorf("failed to connect to HSM: %w", err)
	}
	defer signer.Close()

	// Verify algorithm matches
	signerAlg := signer.Algorithm()
	if !isCompatibleAlgorithm(alg, signerAlg) {
		return fmt.Errorf("HSM key algorithm %s does not match profile algorithm %s", signerAlg, alg)
	}

	fmt.Printf("Initializing CA at %s...\n", absDir)
	fmt.Printf("  Algorithm: %s (from HSM)\n", signerAlg.Description())

	// Build configuration
	cfg := ca.Config{
		CommonName:    caInitName,
		Organization:  caInitOrg,
		Country:       caInitCountry,
		Algorithm:     signerAlg,
		ValidityYears: validityYears,
		PathLen:       pathLen,
	}

	// Initialize CA with HSM signer
	newCA, err := ca.InitializeWithSigner(store, cfg, signer)
	if err != nil {
		return fmt.Errorf("failed to initialize CA: %w", err)
	}

	// Save HSM configuration reference in the CA directory
	hsmRefPath := filepath.Join(absDir, "hsm.yaml")
	if err := saveHSMReference(hsmRefPath, caInitHSMConfig, keyLabel, keyID); err != nil {
		return fmt.Errorf("failed to save HSM reference: %w", err)
	}

	cert := newCA.Certificate()
	fmt.Printf("\nCA initialized successfully!\n")
	fmt.Printf("  Subject:     %s\n", cert.Subject.String())
	fmt.Printf("  Serial:      %X\n", cert.SerialNumber.Bytes())
	fmt.Printf("  Not Before:  %s\n", cert.NotBefore.Format("2006-01-02 15:04:05"))
	fmt.Printf("  Not After:   %s\n", cert.NotAfter.Format("2006-01-02 15:04:05"))
	fmt.Printf("  Certificate: %s\n", store.CACertPath())
	fmt.Printf("  Key:         HSM (%s)\n", caInitHSMConfig)
	fmt.Printf("  HSM Config:  %s\n", hsmRefPath)

	return nil
}

// isCompatibleAlgorithm checks if two algorithms are compatible (same key type).
func isCompatibleAlgorithm(profile, hsm crypto.AlgorithmID) bool {
	// For now, require exact match or compatible EC curves
	if profile == hsm {
		return true
	}
	// Allow EC curves to match (e.g., profile ecdsa-p384 with HSM ecdsa-p384)
	return false
}

// saveHSMReference saves the HSM reference to the CA directory.
func saveHSMReference(path, hsmConfigPath, keyLabel, keyID string) error {
	content := fmt.Sprintf(`# HSM Configuration Reference
# This CA uses a key stored in an HSM.

hsm_config: %s
key_label: %s
key_id: %s
`, hsmConfigPath, keyLabel, keyID)
	return os.WriteFile(path, []byte(content), 0600)
}

// runCAInitSubordinate creates a subordinate CA signed by a parent CA.
func runCAInitSubordinate(cmd *cobra.Command, args []string) error {
	var alg crypto.AlgorithmID
	var validityYears int
	var extensions *profile.ExtensionsConfig
	var err error

	// Load profile (required)
	prof, err := profile.LoadProfile(caInitProfile)
	if err != nil {
		return fmt.Errorf("failed to load profile %s: %w", caInitProfile, err)
	}

	// Extract algorithm from profile
	alg = prof.GetAlgorithm()
	if !alg.IsValid() {
		return fmt.Errorf("profile %s has invalid algorithm: %s", caInitProfile, alg)
	}

	// Extract validity (convert from duration to years)
	validityYears = int(prof.Validity.Hours() / 24 / 365)
	if validityYears < 1 {
		validityYears = 1
	}

	// Allow CLI flags to override profile values
	if cmd.Flags().Changed("validity") {
		validityYears = caInitValidityYears
	}

	// Use profile extensions (pathLen is defined in profile)
	extensions = prof.Extensions

	// Use profile subject values as defaults (CLI flags can override)
	if prof.Subject != nil && prof.Subject.Fixed != nil {
		if caInitOrg == "" {
			caInitOrg = prof.Subject.Fixed["o"]
		}
		if caInitCountry == "" {
			caInitCountry = prof.Subject.Fixed["c"]
		}
	}

	fmt.Printf("Using profile: %s\n", caInitProfile)

	if !alg.IsSignature() {
		return fmt.Errorf("algorithm %s is not suitable for signing", alg)
	}

	// Load parent CA
	parentAbsDir, err := filepath.Abs(caInitParentDir)
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

	if err := parentCA.LoadSigner(caInitParentPassphrase); err != nil {
		return fmt.Errorf("failed to load parent CA signer: %w", err)
	}

	// Expand path for new CA
	absDir, err := filepath.Abs(caInitDir)
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
	passphrase := []byte(caInitPassphrase)
	if err := signer.SavePrivateKey(store.CAKeyPath(), passphrase); err != nil {
		return fmt.Errorf("failed to save CA key: %w", err)
	}

	// Issue subordinate CA certificate using parent
	fmt.Printf("Initializing subordinate CA at %s...\n", absDir)
	fmt.Printf("  Parent CA:  %s\n", parentCA.Certificate().Subject.String())
	fmt.Printf("  Algorithm:  %s\n", alg.Description())

	// Build subject
	subject := pkix.Name{
		CommonName: caInitName,
	}
	if caInitOrg != "" {
		subject.Organization = []string{caInitOrg}
	}
	if caInitCountry != "" {
		subject.Country = []string{caInitCountry}
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

	if caInitPassphrase == "" {
		fmt.Fprintf(os.Stderr, "\nWARNING: Private key is not encrypted. Use --passphrase for production.\n")
	}

	return nil
}

func runCAInfo(cmd *cobra.Command, args []string) error {
	absDir, err := filepath.Abs(caInfoDir)
	if err != nil {
		return fmt.Errorf("invalid CA directory: %w", err)
	}

	store := ca.NewStore(absDir)
	if !store.Exists() {
		return fmt.Errorf("CA not found at %s", absDir)
	}

	caInstance, err := ca.New(store)
	if err != nil {
		return fmt.Errorf("failed to load CA: %w", err)
	}

	cert := caInstance.Certificate()

	fmt.Printf("CA Information\n")
	fmt.Printf("==============\n\n")
	fmt.Printf("Subject:       %s\n", cert.Subject.String())
	fmt.Printf("Issuer:        %s\n", cert.Issuer.String())
	fmt.Printf("Serial:        %X\n", cert.SerialNumber.Bytes())
	fmt.Printf("Not Before:    %s\n", cert.NotBefore.Format("2006-01-02 15:04:05"))
	fmt.Printf("Not After:     %s\n", cert.NotAfter.Format("2006-01-02 15:04:05"))
	fmt.Printf("Algorithm:     %s\n", getSignatureAlgorithmName(cert))

	// Basic constraints
	if cert.IsCA {
		pathLen := "unlimited"
		if cert.MaxPathLen >= 0 && cert.MaxPathLenZero {
			pathLen = "0"
		} else if cert.MaxPathLen >= 0 {
			pathLen = fmt.Sprintf("%d", cert.MaxPathLen)
		}
		fmt.Printf("CA:            yes (path length: %s)\n", pathLen)
	} else {
		fmt.Printf("CA:            no\n")
	}

	// Self-signed check
	if cert.Subject.String() == cert.Issuer.String() {
		fmt.Printf("Type:          Root CA (self-signed)\n")
	} else {
		fmt.Printf("Type:          Subordinate CA\n")
	}

	fmt.Printf("\nFiles:\n")
	fmt.Printf("  Certificate: %s\n", store.CACertPath())
	fmt.Printf("  Private Key: %s\n", store.CAKeyPath())

	// Check for chain file
	chainPath := filepath.Join(absDir, "chain.crt")
	if _, err := os.Stat(chainPath); err == nil {
		fmt.Printf("  Chain:       %s\n", chainPath)
	}

	// Check for PQC key
	pqcKeyPath := store.CAKeyPath() + ".pqc"
	if _, err := os.Stat(pqcKeyPath); err == nil {
		fmt.Printf("  PQC Key:     %s\n", pqcKeyPath)
	}

	return nil
}

func runCRLGen(cmd *cobra.Command, args []string) error {
	absDir, err := filepath.Abs(crlGenCADir)
	if err != nil {
		return fmt.Errorf("invalid CA directory: %w", err)
	}

	store := ca.NewStore(absDir)
	if !store.Exists() {
		return fmt.Errorf("CA not found at %s", absDir)
	}

	caInstance, err := ca.NewWithSigner(store, nil)
	if err != nil {
		return fmt.Errorf("failed to load CA: %w", err)
	}

	if err := caInstance.LoadSigner(crlGenPassphrase); err != nil {
		return fmt.Errorf("failed to load CA signer: %w", err)
	}

	// Get revoked certificates count
	revoked, err := store.ListRevoked()
	if err != nil {
		return fmt.Errorf("failed to list revoked certificates: %w", err)
	}

	nextUpdate := time.Now().AddDate(0, 0, crlGenDays)
	crlDER, err := caInstance.GenerateCRL(nextUpdate)
	if err != nil {
		return fmt.Errorf("failed to generate CRL: %w", err)
	}

	fmt.Printf("CRL generated successfully.\n")
	fmt.Printf("  Revoked certificates: %d\n", len(revoked))
	fmt.Printf("  CRL file: %s\n", store.CRLPath())
	fmt.Printf("  Size: %d bytes\n", len(crlDER))
	fmt.Printf("  This update: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Printf("  Next update: %s\n", nextUpdate.Format("2006-01-02 15:04:05"))

	return nil
}

func runCAExport(cmd *cobra.Command, args []string) error {
	absDir, err := filepath.Abs(caExportDir)
	if err != nil {
		return fmt.Errorf("invalid CA directory: %w", err)
	}

	var certs []*x509.Certificate

	// Handle --all flag: export all versions
	if caExportAll {
		versionStore := ca.NewVersionStore(absDir)
		if !versionStore.IsVersioned() {
			// Not versioned, just export the current CA
			store := ca.NewStore(absDir)
			if !store.Exists() {
				return fmt.Errorf("CA not found at %s", absDir)
			}
			caCert, err := store.LoadCACert()
			if err != nil {
				return fmt.Errorf("failed to load CA certificate: %w", err)
			}
			certs = append(certs, caCert)
		} else {
			// Export all versions
			versions, err := versionStore.ListVersions()
			if err != nil {
				return fmt.Errorf("failed to list versions: %w", err)
			}

			// Also include the original (non-versioned) CA if it exists
			store := ca.NewStore(absDir)
			if store.Exists() {
				if caCert, err := store.LoadCACert(); err == nil {
					certs = append(certs, caCert)
				}
			}

			// Add all version certificates
			for _, v := range versions {
				versionDir := versionStore.VersionDir(v.ID)
				vStore := ca.NewStore(versionDir)
				if vStore.Exists() {
					if vCert, err := vStore.LoadCACert(); err == nil {
						certs = append(certs, vCert)
					}
				}
			}
		}
	} else {
		// Determine which store to use based on --version flag
		var store *ca.Store
		if caExportVersion != "" {
			// Load from specific version
			versionStore := ca.NewVersionStore(absDir)
			if !versionStore.IsVersioned() {
				return fmt.Errorf("CA is not versioned, cannot use --version flag")
			}

			// Find the version - support both ordinal (v1, v2) and full IDs
			versions, err := versionStore.ListVersions()
			if err != nil {
				return fmt.Errorf("failed to list versions: %w", err)
			}

			var targetVersionID string

			// Check for ordinal reference (v1, v2, v3, etc.)
			if len(caExportVersion) >= 2 && caExportVersion[0] == 'v' {
				if ordinal, err := strconv.Atoi(caExportVersion[1:]); err == nil && ordinal >= 1 {
					// v1 = original CA (non-versioned), v2+ = versions
					if ordinal == 1 {
						// v1 refers to the original CA
						store = ca.NewStore(absDir)
						if !store.Exists() {
							return fmt.Errorf("original CA (v1) not found")
						}
					} else {
						// v2, v3, etc. refer to versioned CAs
						versionIndex := ordinal - 2 // v2 = index 0, v3 = index 1, etc.
						if versionIndex >= len(versions) {
							return fmt.Errorf("version v%d not found (only %d versions exist)", ordinal, len(versions)+1)
						}
						targetVersionID = versions[versionIndex].ID
					}
				}
			}

			// If not ordinal, try full version ID
			if targetVersionID == "" && store == nil {
				for _, v := range versions {
					if v.ID == caExportVersion {
						targetVersionID = v.ID
						break
					}
				}
				if targetVersionID == "" {
					return fmt.Errorf("version not found: %s", caExportVersion)
				}
			}

			if targetVersionID != "" {
				versionDir := versionStore.VersionDir(targetVersionID)
				store = ca.NewStore(versionDir)
			}
		} else {
			store = ca.NewStore(absDir)
		}

		if !store.Exists() {
			return fmt.Errorf("CA not found at %s", store.BasePath())
		}

		// Load CA certificate
		caCert, err := store.LoadCACert()
		if err != nil {
			return fmt.Errorf("failed to load CA certificate: %w", err)
		}

		switch caExportBundle {
		case "ca":
			certs = append(certs, caCert)

		case "chain":
			certs = append(certs, caCert)
			// Try to load chain file
			chainPath := filepath.Join(store.BasePath(), "chain.crt")
			if chainData, err := os.ReadFile(chainPath); err == nil {
				chainCerts, err := parseCertificatesPEM(chainData)
				if err == nil {
					// Skip the first cert (it's the CA cert already added)
					for i, c := range chainCerts {
						if i > 0 {
							certs = append(certs, c)
						}
					}
				}
			}

		case "root":
			// Find root certificate
			chainPath := filepath.Join(store.BasePath(), "chain.crt")
			if chainData, err := os.ReadFile(chainPath); err == nil {
				chainCerts, err := parseCertificatesPEM(chainData)
				if err == nil && len(chainCerts) > 0 {
					// Last cert in chain is the root
					certs = append(certs, chainCerts[len(chainCerts)-1])
				}
			} else {
				// No chain file, CA is probably the root
				certs = append(certs, caCert)
			}

		default:
			return fmt.Errorf("invalid bundle type: %s (use: ca, chain, root)", caExportBundle)
		}
	}

	// Encode certificates
	var output []byte
	if caExportFormat == "der" {
		if len(certs) > 1 {
			return fmt.Errorf("DER format only supports single certificate, use PEM for chain")
		}
		output = certs[0].Raw
	} else {
		for _, cert := range certs {
			block := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
			output = append(output, pem.EncodeToMemory(block)...)
		}
	}

	// Write output
	if caExportOut == "" {
		fmt.Print(string(output))
	} else {
		if err := os.WriteFile(caExportOut, output, 0644); err != nil {
			return fmt.Errorf("failed to write file: %w", err)
		}
		fmt.Printf("Exported %d certificate(s) to %s\n", len(certs), caExportOut)
	}

	return nil
}

func parseCertificatesPEM(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			certs = append(certs, cert)
		}
		data = rest
	}
	return certs, nil
}

func runCAList(cmd *cobra.Command, args []string) error {
	absDir, err := filepath.Abs(caListDir)
	if err != nil {
		return fmt.Errorf("invalid directory: %w", err)
	}

	entries, err := os.ReadDir(absDir)
	if err != nil {
		return fmt.Errorf("failed to read directory: %w", err)
	}

	type caInfo struct {
		Name      string
		Type      string
		Algorithm string
		Expires   time.Time
	}

	var cas []caInfo

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		caDir := filepath.Join(absDir, entry.Name())
		store := ca.NewStore(caDir)
		if !store.Exists() {
			continue
		}

		cert, err := store.LoadCACert()
		if err != nil {
			continue
		}

		caType := "Root CA"
		if cert.Subject.String() != cert.Issuer.String() {
			caType = "Subordinate"
		}

		cas = append(cas, caInfo{
			Name:      entry.Name(),
			Type:      caType,
			Algorithm: getSignatureAlgorithmName(cert),
			Expires:   cert.NotAfter,
		})
	}

	if len(cas) == 0 {
		fmt.Println("No CAs found in", absDir)
		return nil
	}

	// Print table
	fmt.Printf("%-20s %-12s %-20s %s\n", "NAME", "TYPE", "ALGORITHM", "EXPIRES")
	fmt.Printf("%-20s %-12s %-20s %s\n", "----", "----", "---------", "-------")
	for _, c := range cas {
		fmt.Printf("%-20s %-12s %-20s %s\n",
			c.Name,
			c.Type,
			c.Algorithm,
			c.Expires.Format("2006-01-02"),
		)
	}

	return nil
}

// getSignatureAlgorithmName returns a human-readable name for the certificate's signature algorithm.
// For PQC algorithms (ML-DSA, SLH-DSA) that Go's x509 doesn't recognize, it extracts the OID
// from the raw certificate and looks up the name.
func getSignatureAlgorithmName(cert *x509.Certificate) string {
	// If Go's x509 recognizes the algorithm, use its name
	if cert.SignatureAlgorithm != x509.UnknownSignatureAlgorithm {
		return cert.SignatureAlgorithm.String()
	}

	// For unknown algorithms (PQC), extract OID from raw certificate
	oid, err := x509util.ExtractSignatureAlgorithmOID(cert.Raw)
	if err != nil {
		return "Unknown"
	}

	return x509util.AlgorithmName(oid)
}
