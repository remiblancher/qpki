package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
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
  pki ca init --profile ec/root-ca --ca-dir ./root-ca --var cn="My Root CA"

  # Create a subordinate CA
  pki ca init --profile ec/issuing-ca --ca-dir ./issuing-ca --parent ./root-ca --var cn="Issuing CA"

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

Variables:
  Certificate subject fields are passed via --var or --var-file:
    cn           Common Name (required)
    organization Organization name
    country      Country code (2 letters, e.g., FR, US)
    ou           Organizational Unit
    state        State or Province
    locality     Locality/City

  Use 'pki profile vars <profile>' to see all available variables.

Examples:
  # Create a root CA with ECDSA
  pki ca init --profile ec/root-ca --ca-dir ./root-ca --var cn="My Root CA"

  # Create a root CA with full subject
  pki ca init --profile ec/root-ca --ca-dir ./root-ca \
    --var cn="My Root CA" --var organization="ACME Corp" --var country=FR

  # Create a root CA using a variables file
  pki ca init --profile ec/root-ca --ca-dir ./root-ca --var-file ca-vars.yaml

  # Create a PQC root CA with ML-DSA-65
  pki ca init --profile ml-dsa/root-ca --ca-dir ./pqc-ca --var cn="PQC Root CA"

  # Create a hybrid (catalyst) root CA
  pki ca init --profile hybrid/catalyst/root-ca --ca-dir ./hybrid-ca --var cn="Hybrid Root CA"

  # Create a subordinate CA signed by the root
  pki ca init --profile ec/issuing-ca --ca-dir ./issuing-ca --parent ./root-ca --var cn="Issuing CA"

  # Protect private key with a passphrase
  pki ca init --profile ec/root-ca --passphrase "secret" --ca-dir ./ca --var cn="My CA"

  # Create a CA using an existing HSM key
  export HSM_PIN="****"
  pki ca init --profile ec/root-ca --ca-dir ./hsm-ca \
    --hsm-config ./hsm.yaml --key-label "root-ca-key" --var cn="HSM Root CA"

  # Create a CA and generate the key in HSM
  export HSM_PIN="****"
  pki ca init --profile ec/root-ca --ca-dir ./hsm-ca \
    --hsm-config ./hsm.yaml --key-label "new-root-key" --generate-key --var cn="HSM Root CA"`,
	RunE: runCAInit,
}

var caInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Display CA information",
	Long:  `Display detailed information about a Certificate Authority.`,
	RunE:  runCAInfo,
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
	caInitVars             []string // --var key=value
	caInitVarFile          string   // --var-file vars.yaml
	caInitValidityYears    int
	caInitPathLen          int
	caInitPassphrase       string
	caInitParentDir        string
	caInitParentPassphrase string
	caInitProfiles         []string // --profile (repeatable)

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
	caCmd.AddCommand(caExportCmd)
	caCmd.AddCommand(caListCmd)

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
	initFlags.StringVarP(&caInitDir, "ca-dir", "d", "./ca", "CA directory")
	initFlags.StringArrayVarP(&caInitProfiles, "profile", "P", nil, "CA profile (repeatable for multi-profile CA, e.g., ec/root-ca, ml-dsa/root-ca)")
	initFlags.StringArrayVar(&caInitVars, "var", nil, "Variable value (key=value, repeatable)")
	initFlags.StringVar(&caInitVarFile, "var-file", "", "YAML file with variable values")
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

	// Multi-profile initialization if multiple profiles provided
	if len(caInitProfiles) > 1 {
		return runCAInitMultiProfile(cmd, args)
	}

	// Check mutual exclusivity of --var and --var-file
	if caInitVarFile != "" && len(caInitVars) > 0 {
		return fmt.Errorf("--var and --var-file are mutually exclusive")
	}

	// Ensure at least one profile is provided
	if len(caInitProfiles) == 0 {
		return fmt.Errorf("at least one --profile is required")
	}

	var alg crypto.AlgorithmID
	var hybridAlg crypto.AlgorithmID
	var validityYears int
	var pathLen int
	var err error

	// Track if this is a composite profile
	var isComposite bool

	// Load profile (required) - single profile mode
	caInitProfile := caInitProfiles[0]
	prof, err := profile.LoadProfile(caInitProfile)
	if err != nil {
		return fmt.Errorf("failed to load profile %s: %w", caInitProfile, err)
	}

	// Load and validate variables
	varValues, err := profile.LoadVariables(caInitVarFile, caInitVars)
	if err != nil {
		return fmt.Errorf("failed to load variables: %w", err)
	}

	// Validate variables against profile constraints
	if len(prof.Variables) > 0 {
		engine, err := profile.NewTemplateEngine(prof)
		if err != nil {
			return fmt.Errorf("failed to create template engine: %w", err)
		}
		rendered, err := engine.Render(varValues)
		if err != nil {
			return fmt.Errorf("failed to validate variables: %w", err)
		}
		varValues = rendered.ResolvedValues
	}

	// Build subject from variables
	subject, err := profile.BuildSubject(varValues)
	if err != nil {
		return fmt.Errorf("failed to build subject: %w", err)
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

	// Build configuration using subject from variables
	cfg := ca.Config{
		CommonName:    subject.CommonName,
		Organization:  firstOrEmpty(subject.Organization),
		Country:       firstOrEmpty(subject.Country),
		Algorithm:     alg,
		ValidityYears: validityYears,
		PathLen:       pathLen,
		Passphrase:    caInitPassphrase,
		Extensions:    prof.Extensions,
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

	// Load CAInfo to get the versioned cert path
	info, _ := ca.LoadCAInfo(absDir)
	var certPath string
	if info != nil && info.Active != "" {
		activeVer := info.ActiveVersion()
		if activeVer != nil && len(activeVer.Algos) > 0 {
			certPath = info.CertPath(info.Active, activeVer.Algos[0])
		}
	}
	if certPath == "" {
		certPath = store.CACertPath()
	}

	fmt.Printf("\nCA initialized successfully!\n")
	fmt.Printf("  Subject:     %s\n", cert.Subject.String())
	fmt.Printf("  Serial:      %X\n", cert.SerialNumber.Bytes())
	fmt.Printf("  Not Before:  %s\n", cert.NotBefore.Format("2006-01-02 15:04:05"))
	fmt.Printf("  Not After:   %s\n", cert.NotAfter.Format("2006-01-02 15:04:05"))
	fmt.Printf("  Certificate: %s\n", certPath)
	fmt.Printf("  Private Key: %s\n", newCA.DefaultKeyPath())
	if cfg.HybridConfig != nil {
		if isComposite {
			fmt.Printf("  Mode:        Composite (IETF)\n")
		} else {
			fmt.Printf("  Mode:        Catalyst (ITU-T)\n")
		}
		fmt.Printf("  PQC Key:     %s.pqc\n", newCA.DefaultKeyPath())
	}

	if caInitPassphrase == "" {
		fmt.Fprintf(os.Stderr, "\nWARNING: Private key is not encrypted. Use --passphrase for production.\n")
	}

	return nil
}

// runCAInitMultiProfile creates a CA with multiple algorithm profiles.
// Each profile results in a separate CA certificate, stored in version directories by algorithm family.
func runCAInitMultiProfile(cmd *cobra.Command, args []string) error {
	// Check mutual exclusivity of --var and --var-file
	if caInitVarFile != "" && len(caInitVars) > 0 {
		return fmt.Errorf("--var and --var-file are mutually exclusive")
	}

	// Load and validate variables
	varValues, err := profile.LoadVariables(caInitVarFile, caInitVars)
	if err != nil {
		return fmt.Errorf("failed to load variables: %w", err)
	}

	// Load all profiles
	profiles := make([]*profile.Profile, 0, len(caInitProfiles))
	for _, profileName := range caInitProfiles {
		prof, err := profile.LoadProfile(profileName)
		if err != nil {
			return fmt.Errorf("failed to load profile %s: %w", profileName, err)
		}

		// Validate variables against first profile with variables
		if len(prof.Variables) > 0 && len(varValues) > 0 {
			engine, err := profile.NewTemplateEngine(prof)
			if err != nil {
				return fmt.Errorf("failed to create template engine for %s: %w", profileName, err)
			}
			rendered, err := engine.Render(varValues)
			if err != nil {
				return fmt.Errorf("failed to validate variables for %s: %w", profileName, err)
			}
			varValues = rendered.ResolvedValues
		}

		profiles = append(profiles, prof)
	}

	// Build subject from variables
	subject, err := profile.BuildSubject(varValues)
	if err != nil {
		return fmt.Errorf("failed to build subject: %w", err)
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

	fmt.Printf("Initializing multi-profile CA at %s...\n", absDir)
	for _, prof := range profiles {
		fmt.Printf("  Profile: %s (%s)\n", prof.Name, prof.GetAlgorithm().Description())
	}

	// Build multi-profile configuration
	profileConfigs := make([]ca.ProfileInitConfig, 0, len(profiles))
	for _, prof := range profiles {
		validityYears := int(prof.Validity.Hours() / 24 / 365)
		if validityYears < 1 {
			validityYears = 1
		}
		if cmd.Flags().Changed("validity") {
			validityYears = caInitValidityYears
		}

		pathLen := 1
		if prof.Extensions != nil && prof.Extensions.BasicConstraints != nil && prof.Extensions.BasicConstraints.PathLen != nil {
			pathLen = *prof.Extensions.BasicConstraints.PathLen
		}
		if cmd.Flags().Changed("path-len") {
			pathLen = caInitPathLen
		}

		profileConfigs = append(profileConfigs, ca.ProfileInitConfig{
			Profile:       prof,
			ValidityYears: validityYears,
			PathLen:       pathLen,
		})
	}

	cfg := ca.MultiProfileConfig{
		Profiles: profileConfigs,
		Variables: map[string]string{
			"cn":           subject.CommonName,
			"organization": firstOrEmpty(subject.Organization),
			"country":      firstOrEmpty(subject.Country),
		},
		Passphrase: caInitPassphrase,
	}

	// Initialize multi-profile CA
	result, err := ca.InitializeMultiProfile(absDir, cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize multi-profile CA: %w", err)
	}

	fmt.Printf("\nMulti-profile CA initialized successfully!\n")
	fmt.Printf("  Version:     %s\n", result.Info.Active)
	fmt.Printf("  Profiles:    %d\n", len(result.Certificates))

	for algoFamily, cert := range result.Certificates {
		fmt.Printf("\n  [%s]\n", algoFamily)
		fmt.Printf("    Subject:     %s\n", cert.Subject.String())
		fmt.Printf("    Serial:      %X\n", cert.SerialNumber.Bytes())
		fmt.Printf("    Not Before:  %s\n", cert.NotBefore.Format("2006-01-02 15:04:05"))
		fmt.Printf("    Not After:   %s\n", cert.NotAfter.Format("2006-01-02 15:04:05"))
	}

	fmt.Printf("\nTo activate this version:\n")
	fmt.Printf("  pki ca activate --ca-dir %s --version %s\n", absDir, result.Info.Active)

	if caInitPassphrase == "" {
		fmt.Fprintf(os.Stderr, "\nWARNING: Private keys are not encrypted. Use --passphrase for production.\n")
	}

	return nil
}

// runCAInitHSM creates a CA using an existing key in an HSM.
func runCAInitHSM(cmd *cobra.Command, args []string) error {
	// Check mutual exclusivity of --var and --var-file
	if caInitVarFile != "" && len(caInitVars) > 0 {
		return fmt.Errorf("--var and --var-file are mutually exclusive")
	}

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

	// Ensure single profile for HSM mode
	if len(caInitProfiles) != 1 {
		return fmt.Errorf("HSM mode requires exactly one --profile (multi-profile not supported with HSM)")
	}
	caInitProfile := caInitProfiles[0]

	// Load profile
	prof, err := profile.LoadProfile(caInitProfile)
	if err != nil {
		return fmt.Errorf("failed to load profile %s: %w", caInitProfile, err)
	}

	// Load and validate variables
	varValues, err := profile.LoadVariables(caInitVarFile, caInitVars)
	if err != nil {
		return fmt.Errorf("failed to load variables: %w", err)
	}

	// Validate variables against profile constraints
	if len(prof.Variables) > 0 {
		engine, err := profile.NewTemplateEngine(prof)
		if err != nil {
			return fmt.Errorf("failed to create template engine: %w", err)
		}
		rendered, err := engine.Render(varValues)
		if err != nil {
			return fmt.Errorf("failed to validate variables: %w", err)
		}
		varValues = rendered.ResolvedValues
	}

	// Build subject from variables
	subject, err := profile.BuildSubject(varValues)
	if err != nil {
		return fmt.Errorf("failed to build subject: %w", err)
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
	defer func() { _ = signer.Close() }()

	// Verify algorithm matches
	signerAlg := signer.Algorithm()
	if !isCompatibleAlgorithm(alg, signerAlg) {
		return fmt.Errorf("HSM key algorithm %s does not match profile algorithm %s", signerAlg, alg)
	}

	fmt.Printf("Initializing CA at %s...\n", absDir)
	fmt.Printf("  Algorithm: %s (from HSM)\n", signerAlg.Description())

	// Build configuration
	cfg := ca.Config{
		CommonName:    subject.CommonName,
		Organization:  firstOrEmpty(subject.Organization),
		Country:       firstOrEmpty(subject.Country),
		Algorithm:     signerAlg,
		ValidityYears: validityYears,
		PathLen:       pathLen,
		Extensions:    prof.Extensions,
	}

	// Initialize CA with HSM signer
	newCA, err := ca.InitializeWithSigner(store, cfg, signer)
	if err != nil {
		return fmt.Errorf("failed to initialize CA: %w", err)
	}

	// Copy HSM configuration to the CA directory
	hsmRefPath := filepath.Join(absDir, "hsm.yaml")
	if err := copyHSMConfig(caInitHSMConfig, hsmRefPath); err != nil {
		return fmt.Errorf("failed to copy HSM config: %w", err)
	}

	// Add KeyRef for HSM key to the CAInfo created by InitializeWithSigner
	metadata := newCA.Info()
	metadata.AddKey(ca.KeyRef{
		ID:        "default",
		Algorithm: signerAlg,
		Storage:   ca.CreatePKCS11KeyRef("hsm.yaml", keyLabel, keyID),
	})
	if err := metadata.Save(); err != nil {
		return fmt.Errorf("failed to save CA metadata: %w", err)
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
	// Allow EC curves to match (e.g., profile ecdsa-p384 with HSM ecdsa-p384)
	return profile == hsm
}

// copyHSMConfig copies the HSM configuration file to the CA directory.
func copyHSMConfig(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("failed to read source HSM config: %w", err)
	}
	return os.WriteFile(dst, data, 0600)
}

// runCAInitSubordinate creates a subordinate CA signed by a parent CA.
func runCAInitSubordinate(cmd *cobra.Command, args []string) error {
	// Check mutual exclusivity of --var and --var-file
	if caInitVarFile != "" && len(caInitVars) > 0 {
		return fmt.Errorf("--var and --var-file are mutually exclusive")
	}

	// Ensure single profile for subordinate CA mode (for now)
	if len(caInitProfiles) != 1 {
		return fmt.Errorf("subordinate CA requires exactly one --profile (multi-profile subordinate CA not yet supported)")
	}
	caInitProfile := caInitProfiles[0]

	var alg crypto.AlgorithmID
	var validityYears int
	var extensions *profile.ExtensionsConfig
	var err error

	// Load profile (required)
	prof, err := profile.LoadProfile(caInitProfile)
	if err != nil {
		return fmt.Errorf("failed to load profile %s: %w", caInitProfile, err)
	}

	// Load and validate variables
	varValues, err := profile.LoadVariables(caInitVarFile, caInitVars)
	if err != nil {
		return fmt.Errorf("failed to load variables: %w", err)
	}

	// Validate variables against profile constraints
	if len(prof.Variables) > 0 {
		engine, err := profile.NewTemplateEngine(prof)
		if err != nil {
			return fmt.Errorf("failed to create template engine: %w", err)
		}
		rendered, err := engine.Render(varValues)
		if err != nil {
			return fmt.Errorf("failed to validate variables: %w", err)
		}
		varValues = rendered.ResolvedValues
	}

	// Build subject from variables
	subject, err := profile.BuildSubject(varValues)
	if err != nil {
		return fmt.Errorf("failed to build subject: %w", err)
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

	// Get full algorithm ID (e.g., "ecdsa-p256", "ml-dsa-65")
	algoID := string(alg)

	// Create CAInfo first to set up versioned structure
	info := ca.NewCAInfo(ca.Subject{
		CommonName:   subject.CommonName,
		Organization: subject.Organization,
		Country:      subject.Country,
	})
	info.SetBasePath(absDir)
	info.CreateInitialVersion([]string{caInitProfile}, []string{algoID})

	// Create version directory structure (keys/ and certs/)
	if err := info.EnsureVersionDir("v1"); err != nil {
		return fmt.Errorf("failed to create version directory: %w", err)
	}

	// Generate CA key pair at versioned path
	keyPath := info.KeyPath("v1", string(alg))
	keyCfg := crypto.KeyStorageConfig{
		Type:       crypto.KeyProviderTypeSoftware,
		KeyPath:    keyPath,
		Passphrase: caInitPassphrase,
	}
	km := crypto.NewKeyProvider(keyCfg)
	signer, err := km.Generate(alg, keyCfg)
	if err != nil {
		return fmt.Errorf("failed to generate CA key: %w", err)
	}

	// Issue subordinate CA certificate using parent
	fmt.Printf("Initializing subordinate CA at %s...\n", absDir)
	fmt.Printf("  Parent CA:  %s\n", parentCA.Certificate().Subject.String())
	fmt.Printf("  Algorithm:  %s\n", alg.Description())

	// Build template using subject from variables
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

	// Save CA certificate to versioned path
	certPath := info.CertPath("v1", algoID)
	if err := saveCertToPath(certPath, cert); err != nil {
		return fmt.Errorf("failed to save CA certificate: %w", err)
	}

	// Add key reference and save CAInfo
	info.AddKey(ca.KeyRef{
		ID:        "default",
		Algorithm: alg,
		Storage: crypto.StorageRef{
			Type: "software",
			Path: fmt.Sprintf("versions/v1/keys/ca.%s.key", algoID),
		},
	})
	if err := info.Save(); err != nil {
		return fmt.Errorf("failed to save CA info: %w", err)
	}

	// Create certificate chain file
	chainPath := filepath.Join(absDir, "chain.crt")
	chainFile, err := os.Create(chainPath)
	if err != nil {
		return fmt.Errorf("failed to create chain file: %w", err)
	}
	defer func() { _ = chainFile.Close() }()

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
	fmt.Printf("  Certificate: %s\n", certPath)
	fmt.Printf("  Chain:       %s\n", chainPath)
	fmt.Printf("  Private Key: %s\n", keyPath)

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

	// Display key paths from metadata (or fallback for legacy CAs)
	keyPaths := caInstance.KeyPaths()
	if len(keyPaths) == 1 {
		// Single key, show as "Private Key"
		for _, path := range keyPaths {
			fmt.Printf("  Private Key: %s\n", path)
		}
	} else if len(keyPaths) > 1 {
		// Multiple keys, show each with its ID
		for id, path := range keyPaths {
			fmt.Printf("  Key (%s): %s\n", id, path)
		}
	} else {
		// Fallback: no metadata, use legacy path
		fmt.Printf("  Private Key: %s\n", store.CAKeyPath())
	}

	// Check for chain file
	chainPath := filepath.Join(absDir, "chain.crt")
	if _, err := os.Stat(chainPath); err == nil {
		fmt.Printf("  Chain:       %s\n", chainPath)
	}

	return nil
}

// firstOrEmpty returns the first element of a string slice, or empty string if slice is empty.
func firstOrEmpty(s []string) string {
	if len(s) > 0 {
		return s[0]
	}
	return ""
}

func runCAExport(cmd *cobra.Command, args []string) error {
	absDir, err := filepath.Abs(caExportDir)
	if err != nil {
		return fmt.Errorf("invalid CA directory: %w", err)
	}

	var certs []*x509.Certificate

	// Load CAInfo for versioned CAs
	info, _ := ca.LoadCAInfo(absDir)

	// Handle --all flag: export all versions
	if caExportAll {
		if info == nil || len(info.Versions) == 0 {
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
			// Export all versions using CAInfo
			info.SetBasePath(absDir)
			for versionID, ver := range info.Versions {
				for _, algo := range ver.Algos {
					certPath := info.CertPath(versionID, algo)
					if cert, err := loadCertFromPath(certPath); err == nil {
						certs = append(certs, cert)
					}
				}
			}
		}
	} else {
		// Determine which store to use based on --version flag
		var store *ca.Store
		if caExportVersion != "" {
			if info == nil || len(info.Versions) == 0 {
				return fmt.Errorf("CA is not versioned, cannot use --version flag")
			}

			info.SetBasePath(absDir)
			targetVersionID := caExportVersion

			// Check if version exists
			ver, ok := info.Versions[targetVersionID]
			if !ok {
				return fmt.Errorf("version %s not found", targetVersionID)
			}

			// Load certificates from the version using CAInfo paths
			for _, algo := range ver.Algos {
				certPath := info.CertPath(targetVersionID, algo)
				if cert, err := loadCertFromPath(certPath); err == nil {
					certs = append(certs, cert)
				}
			}
			// Fallback: check legacy ca.crt path (for rotate-created versions)
			if len(certs) == 0 {
				legacyCertPath := filepath.Join(absDir, "versions", targetVersionID, "ca.crt")
				if cert, err := loadCertFromPath(legacyCertPath); err == nil {
					certs = append(certs, cert)
				}
			}
		} else {
			store = ca.NewStore(absDir)
		}

		// If we loaded certs from multi-profile version, skip store-based loading
		if len(certs) == 0 {
			if store == nil {
				return fmt.Errorf("no store available and no certificates found")
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

// saveCertToPath saves a certificate to a PEM file.
func saveCertToPath(path string, cert *x509.Certificate) error {
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to create certificate file: %w", err)
	}
	defer func() { _ = f.Close() }()

	if err := pem.Encode(f, block); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	return nil
}

// loadCertFromPath loads a certificate from a PEM file.
func loadCertFromPath(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("no certificate found in %s", path)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}
