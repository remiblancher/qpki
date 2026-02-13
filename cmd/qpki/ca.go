package main

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
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
  Use --hsm-config with --key-label to initialize a CA with HSM key storage.
  By default, a new key is generated in the HSM (like software mode).
  Use --use-existing-key if the key already exists in the HSM.
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

  # Create a CA with HSM key (generates key by default)
  export HSM_PIN="****"
  pki ca init --profile ec/root-ca --ca-dir ./hsm-ca \
    --hsm-config ./hsm.yaml --key-label "root-ca-key" --var cn="HSM Root CA"

  # Create a CA using an existing HSM key
  export HSM_PIN="****"
  pki ca init --profile ec/root-ca --ca-dir ./hsm-ca \
    --hsm-config ./hsm.yaml --key-label "existing-key" --use-existing-key --var cn="HSM Root CA"`,
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
  pki ca export --ca-dir ./issuing-ca --bundle chain --out chain.pem

  # Export root only
  pki ca export --ca-dir ./issuing-ca --bundle root --out root.pem

  # Export specific version (for versioned CAs)
  pki ca export --ca-dir ./issuing-ca --version v20240101_abc123 --out v1.pem`,
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
	caInitHSMConfig      string
	caInitKeyLabel       string
	caInitKeyID          string
	caInitUseExistingKey bool

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

	// HSM flags
	initFlags.StringVar(&caInitHSMConfig, "hsm-config", "", "Path to HSM configuration file (enables HSM mode)")
	initFlags.StringVar(&caInitKeyLabel, "key-label", "", "Key label in HSM (required with --hsm-config)")
	initFlags.StringVar(&caInitKeyID, "key-id", "", "Key ID in HSM (hex, optional with --hsm-config)")
	initFlags.BoolVar(&caInitUseExistingKey, "use-existing-key", false, "Use existing key in HSM instead of generating")

	_ = caInitCmd.MarkFlagRequired("profile")

	// Info flags
	caInfoCmd.Flags().StringVarP(&caInfoDir, "ca-dir", "d", "./ca", "CA directory")
}

func runCAInit(cmd *cobra.Command, args []string) error {
	// Delegate to specialized initializers based on flags
	if caInitParentDir != "" {
		return runCAInitSubordinate(cmd, args)
	}
	if caInitHSMConfig != "" {
		return runCAInitHSM(cmd, args)
	}
	if len(caInitProfiles) > 1 {
		return runCAInitMultiProfile(cmd, args)
	}

	if err := validateCAInitSoftwareFlags(caInitVarFile, caInitVars, caInitProfiles); err != nil {
		return err
	}

	caInitProfile := caInitProfiles[0]
	prof, err := profile.LoadProfile(caInitProfile)
	if err != nil {
		return fmt.Errorf("failed to load profile %s: %w", caInitProfile, err)
	}

	varValues, err := loadAndValidateProfileVariables(prof, caInitVarFile, caInitVars)
	if err != nil {
		return err
	}

	subject, err := profile.BuildSubjectFromProfile(prof, varValues)
	if err != nil {
		return fmt.Errorf("failed to build subject: %w", err)
	}

	algInfo, err := extractProfileAlgorithmInfo(prof)
	if err != nil {
		return err
	}
	applyValidityOverrides(cmd.Flags(), algInfo, caInitValidityYears, caInitPathLen)

	fmt.Printf("Using profile: %s\n", caInitProfile)

	if !algInfo.Algorithm.IsSignature() {
		return fmt.Errorf("algorithm %s is not suitable for signing", algInfo.Algorithm)
	}

	absDir, err := filepath.Abs(caInitDir)
	if err != nil {
		return fmt.Errorf("invalid directory path: %w", err)
	}
	store := ca.NewFileStore(absDir)
	if store.Exists() {
		return fmt.Errorf("CA already exists at %s", absDir)
	}

	cfg, err := buildCAConfigFromProfile(prof, subject, algInfo, caInitPassphrase)
	if err != nil {
		return err
	}

	fmt.Printf("Initializing CA at %s...\n", absDir)
	fmt.Printf("  Algorithm: %s\n", algInfo.Algorithm.Description())
	if cfg.HybridConfig != nil {
		fmt.Printf("  Hybrid PQC: %s\n", cfg.HybridConfig.Algorithm.Description())
	}

	newCA, err := initializeCAByType(store, cfg, algInfo.IsComposite)
	if err != nil {
		return fmt.Errorf("failed to initialize CA: %w", err)
	}

	printCAInitSuccess(newCA, absDir, cfg, algInfo.IsComposite)
	return nil
}

// runCAInitMultiProfile creates a CA with multiple algorithm profiles.
// Each profile results in a separate CA certificate, stored in version directories by algorithm family.
func runCAInitMultiProfile(cmd *cobra.Command, args []string) error {
	if caInitVarFile != "" && len(caInitVars) > 0 {
		return fmt.Errorf("--var and --var-file are mutually exclusive")
	}

	varValues, err := profile.LoadVariables(caInitVarFile, caInitVars)
	if err != nil {
		return fmt.Errorf("failed to load variables: %w", err)
	}

	profiles, varValues, err := loadAndValidateProfiles(caInitProfiles, varValues)
	if err != nil {
		return err
	}

	// Use first profile for subject defaults
	var firstProfile *profile.Profile
	if len(profiles) > 0 {
		firstProfile = profiles[0]
	}
	subject, err := profile.BuildSubjectFromProfile(firstProfile, varValues)
	if err != nil {
		return fmt.Errorf("failed to build subject: %w", err)
	}

	absDir, err := filepath.Abs(caInitDir)
	if err != nil {
		return fmt.Errorf("invalid directory path: %w", err)
	}

	store := ca.NewFileStore(absDir)
	if store.Exists() {
		return fmt.Errorf("CA already exists at %s", absDir)
	}

	fmt.Printf("Initializing multi-profile CA at %s...\n", absDir)
	for _, prof := range profiles {
		fmt.Printf("  Profile: %s (%s)\n", prof.Name, prof.GetAlgorithm().Description())
	}

	profileConfigs := buildProfileConfigs(profiles, cmd.Flags(), caInitValidityYears, caInitPathLen)

	cfg := ca.MultiProfileInitConfig{
		Profiles: profileConfigs,
		Variables: map[string]string{
			"cn":           subject.CommonName,
			"organization": firstOrEmpty(subject.Organization),
			"country":      firstOrEmpty(subject.Country),
		},
		Passphrase: caInitPassphrase,
	}

	result, err := ca.InitializeMultiProfile(absDir, cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize multi-profile CA: %w", err)
	}

	printMultiProfileSuccess(result, absDir, caInitPassphrase)
	return nil
}

// runCAInitHSM creates a CA using an existing key in an HSM.
func runCAInitHSM(cmd *cobra.Command, args []string) error {
	if err := validateCAHSMInitFlags(caInitVarFile, caInitVars, caInitProfiles, caInitUseExistingKey, caInitKeyLabel, caInitKeyID); err != nil {
		return err
	}

	hsmCfg, err := crypto.LoadHSMConfig(caInitHSMConfig)
	if err != nil {
		return fmt.Errorf("failed to load HSM config: %w", err)
	}

	caInitProfile := caInitProfiles[0]
	prof, alg, err := loadAndValidateHSMProfile(caInitProfile)
	if err != nil {
		return err
	}

	varValues, err := loadAndValidateProfileVariables(prof, caInitVarFile, caInitVars)
	if err != nil {
		return err
	}

	subject, err := profile.BuildSubjectFromProfile(prof, varValues)
	if err != nil {
		return fmt.Errorf("failed to build subject: %w", err)
	}

	algInfo, err := extractProfileAlgorithmInfo(prof)
	if err != nil {
		return err
	}
	applyValidityOverrides(cmd.Flags(), algInfo, caInitValidityYears, caInitPathLen)

	fmt.Printf("Using profile: %s\n", caInitProfile)
	fmt.Printf("HSM config: %s\n", caInitHSMConfig)

	absDir, err := filepath.Abs(caInitDir)
	if err != nil {
		return fmt.Errorf("invalid directory path: %w", err)
	}
	store := ca.NewFileStore(absDir)
	if store.Exists() {
		return fmt.Errorf("CA already exists at %s", absDir)
	}

	// Handle Catalyst (hybrid) profiles - requires two keys (classical + PQC)
	if prof.IsCatalyst() {
		return runCAInitHSMCatalyst(cmd, hsmCfg, prof, subject, algInfo, store, absDir)
	}

	// Single-algorithm CA (EC, RSA, or ML-DSA)
	keyLabel, keyID := caInitKeyLabel, caInitKeyID
	if !caInitUseExistingKey {
		// Generate key in HSM by default (like software mode)
		keyLabel, keyID, err = generateHSMKey(hsmCfg, alg, caInitKeyLabel)
		if err != nil {
			return err
		}
	}

	signer, err := setupHSMSignerAndVerify(hsmCfg, keyLabel, keyID, alg)
	if err != nil {
		return err
	}
	defer func() { _ = signer.Close() }()

	signerAlg := signer.Algorithm()
	fmt.Printf("Initializing CA at %s...\n", absDir)
	fmt.Printf("  Algorithm: %s (from HSM)\n", signerAlg.Description())

	cfg := ca.Config{
		CommonName:    subject.CommonName,
		Organization:  firstOrEmpty(subject.Organization),
		Country:       firstOrEmpty(subject.Country),
		Algorithm:     signerAlg,
		ValidityYears: algInfo.ValidityYears,
		PathLen:       algInfo.PathLen,
		Extensions:    prof.Extensions,
	}

	newCA, err := ca.InitializeWithSigner(store, cfg, signer)
	if err != nil {
		return fmt.Errorf("failed to initialize CA: %w", err)
	}

	if err := saveCAHSMMetadata(newCA, absDir, caInitHSMConfig, keyLabel, keyID, signerAlg); err != nil {
		return err
	}

	hsmRefPath := filepath.Join(absDir, "hsm.yaml")
	printCAHSMSuccess(newCA, absDir, caInitHSMConfig, hsmRefPath)
	return nil
}

// runCAInitHSMCatalyst creates a Catalyst (hybrid) CA using HSM keys.
// It generates two keys with the same label (classical EC + PQC ML-DSA) and creates
// a Catalyst certificate with dual signatures.
func runCAInitHSMCatalyst(cmd *cobra.Command, hsmCfg *crypto.HSMConfig, prof *profile.Profile,
	subject pkix.Name, algInfo *profileAlgorithmInfo, store *ca.FileStore, absDir string) error {

	if len(prof.Algorithms) != 2 {
		return fmt.Errorf("Catalyst profile requires exactly 2 algorithms, got %d", len(prof.Algorithms))
	}

	classicalAlg := prof.Algorithms[0]
	pqcAlg := prof.Algorithms[1]

	// Use provided key label or generate one
	keyLabel := caInitKeyLabel
	if keyLabel == "" {
		keyLabel = fmt.Sprintf("catalyst-ca-%d", time.Now().Unix())
	}

	fmt.Printf("Creating Catalyst CA with HSM keys...\n")
	fmt.Printf("  Classical: %s\n", classicalAlg.Description())
	fmt.Printf("  PQC:       %s\n", pqcAlg.Description())
	fmt.Printf("  Key label: %s\n", keyLabel)

	if !caInitUseExistingKey {
		// Generate both keys with the same label (different CKA_KEY_TYPE)
		fmt.Printf("Generating classical key (%s) in HSM...\n", classicalAlg)
		_, _, err := generateHSMKey(hsmCfg, classicalAlg, keyLabel)
		if err != nil {
			return fmt.Errorf("failed to generate classical key: %w", err)
		}

		fmt.Printf("Generating PQC key (%s) in HSM...\n", pqcAlg)
		_, _, err = generateHSMKey(hsmCfg, pqcAlg, keyLabel)
		if err != nil {
			return fmt.Errorf("failed to generate PQC key: %w", err)
		}
	}

	// Create PKCS11 config for hybrid signer
	pin, err := hsmCfg.GetPIN()
	if err != nil {
		return fmt.Errorf("failed to get HSM PIN: %w", err)
	}

	pkcs11Cfg := crypto.PKCS11Config{
		ModulePath: hsmCfg.PKCS11.Lib,
		TokenLabel: hsmCfg.PKCS11.Token,
		PIN:        pin,
		KeyLabel:   keyLabel,
	}

	// Create hybrid signer from two HSM keys
	hybridSigner, err := crypto.NewPKCS11HybridSigner(pkcs11Cfg)
	if err != nil {
		return fmt.Errorf("failed to create hybrid HSM signer: %w", err)
	}
	defer func() { _ = hybridSigner.Close() }()

	fmt.Printf("Initializing Catalyst CA at %s...\n", absDir)

	// Create Catalyst CA with hybrid signer
	cfg := ca.HybridWithSignerConfig{
		CommonName:    subject.CommonName,
		Organization:  firstOrEmpty(subject.Organization),
		Country:       firstOrEmpty(subject.Country),
		ValidityYears: algInfo.ValidityYears,
		PathLen:       algInfo.PathLen,
		HSMConfig:     caInitHSMConfig,
		KeyLabel:      keyLabel,
	}

	newCA, err := ca.InitializeHybridWithSigner(store, cfg, hybridSigner)
	if err != nil {
		return fmt.Errorf("failed to initialize Catalyst CA: %w", err)
	}

	// Copy HSM config to CA directory
	hsmRefPath := filepath.Join(absDir, "hsm.yaml")
	if err := copyHSMConfig(caInitHSMConfig, hsmRefPath); err != nil {
		fmt.Printf("Warning: failed to copy HSM config: %v\n", err)
	}

	// Print success message
	cert := newCA.Certificate()
	fmt.Printf("\nCatalyst CA initialized successfully!\n")
	fmt.Printf("  Subject:     %s\n", cert.Subject.String())
	fmt.Printf("  Classical:   %s\n", hybridSigner.ClassicalSigner().Algorithm().Description())
	fmt.Printf("  PQC:         %s\n", hybridSigner.PQCSigner().Algorithm().Description())
	fmt.Printf("  Key Label:   %s\n", keyLabel)
	fmt.Printf("  HSM Config:  %s\n", hsmRefPath)
	fmt.Printf("  CA Dir:      %s\n", absDir)

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
	if err := validateSubordinateCAFlags(caInitVarFile, caInitVars, caInitProfiles); err != nil {
		return err
	}

	caInitProfile := caInitProfiles[0]
	prof, err := profile.LoadProfile(caInitProfile)
	if err != nil {
		return fmt.Errorf("failed to load profile %s: %w", caInitProfile, err)
	}

	varValues, err := loadAndValidateProfileVariables(prof, caInitVarFile, caInitVars)
	if err != nil {
		return err
	}

	subject, err := profile.BuildSubjectFromProfile(prof, varValues)
	if err != nil {
		return fmt.Errorf("failed to build subject: %w", err)
	}

	algInfo, err := extractProfileAlgorithmInfo(prof)
	if err != nil {
		return err
	}
	applyValidityOverrides(cmd.Flags(), algInfo, caInitValidityYears, caInitPathLen)

	fmt.Printf("Using profile: %s\n", caInitProfile)

	// Catalyst subordinate CAs require special handling
	if algInfo.IsCatalyst {
		return runCAInitSubordinateCatalyst(prof, subject, algInfo)
	}

	if !algInfo.Algorithm.IsSignature() {
		return fmt.Errorf("algorithm %s is not suitable for signing", algInfo.Algorithm)
	}

	parentCA, err := loadParentCA(caInitParentDir, caInitParentPassphrase)
	if err != nil {
		return err
	}
	defer func() { _ = parentCA.Close() }()

	absDir, err := filepath.Abs(caInitDir)
	if err != nil {
		return fmt.Errorf("invalid directory path: %w", err)
	}

	_, info, err := prepareSubordinateCAStore(absDir, caInitProfile, subject, algInfo)
	if err != nil {
		return err
	}

	signer, keyPath, err := generateSubordinateKey(info, algInfo, caInitPassphrase)
	if err != nil {
		return err
	}

	fmt.Printf("Initializing subordinate CA at %s...\n", absDir)
	fmt.Printf("  Parent CA:  %s\n", parentCA.Certificate().Subject.String())
	fmt.Printf("  Algorithm:  %s\n", algInfo.Algorithm.Description())

	validity := time.Duration(algInfo.ValidityYears) * 365 * 24 * time.Hour
	cert, err := parentCA.Issue(context.Background(), ca.IssueRequest{
		Template:   &x509.Certificate{Subject: subject},
		PublicKey:  signer.Public(),
		Extensions: prof.Extensions,
		Validity:   validity,
	})
	if err != nil {
		return fmt.Errorf("failed to issue subordinate CA certificate: %w", err)
	}

	certPath, err := saveSubordinateCAInfo(info, cert, algInfo)
	if err != nil {
		return err
	}

	chainPath := filepath.Join(absDir, "chain.crt")
	if err := createChainFile(chainPath, cert, parentCA.Certificate()); err != nil {
		return err
	}

	printSubordinateCASuccess(cert, certPath, chainPath, keyPath, caInitPassphrase)
	return nil
}

// runCAInitSubordinateCatalyst creates a subordinate CA with Catalyst hybrid mode.
// This handles the special case where both classical and PQC keys are needed.
func runCAInitSubordinateCatalyst(prof *profile.Profile, subject pkix.Name, algInfo *profileAlgorithmInfo) error {
	parentCA, err := loadParentCA(caInitParentDir, caInitParentPassphrase)
	if err != nil {
		return err
	}
	defer func() { _ = parentCA.Close() }()

	absDir, err := filepath.Abs(caInitDir)
	if err != nil {
		return fmt.Errorf("invalid directory path: %w", err)
	}

	// Prepare store with both algorithms
	store, info, err := prepareSubordinateCatalystCAStore(absDir, prof.Name, subject, algInfo)
	if err != nil {
		return err
	}

	// Generate both classical and PQC keys
	hybridSigner, classicalKeyPath, pqcKeyPath, err := generateSubordinateCatalystKeys(info, algInfo, caInitPassphrase)
	if err != nil {
		return err
	}

	fmt.Printf("Initializing Catalyst subordinate CA at %s...\n", absDir)
	fmt.Printf("  Parent CA:       %s\n", parentCA.Certificate().Subject.String())
	fmt.Printf("  Classical Algo:  %s\n", algInfo.Algorithm.Description())
	fmt.Printf("  PQC Algo:        %s\n", algInfo.HybridAlg.Description())

	validity := time.Duration(algInfo.ValidityYears) * 365 * 24 * time.Hour

	// Issue Catalyst certificate using parent CA
	cert, err := parentCA.IssueCatalyst(context.Background(), ca.CatalystRequest{
		Template:           &x509.Certificate{Subject: subject},
		ClassicalPublicKey: hybridSigner.ClassicalSigner().Public(),
		PQCPublicKey:       hybridSigner.PQCSigner().Public(),
		PQCAlgorithm:       algInfo.HybridAlg,
		Extensions:         prof.Extensions,
		Validity:           validity,
	})
	if err != nil {
		return fmt.Errorf("failed to issue Catalyst subordinate CA certificate: %w", err)
	}

	// Save certificate and update CAInfo
	certPath, err := saveSubordinateCatalystCAInfo(store, info, cert, algInfo)
	if err != nil {
		return err
	}

	chainPath := filepath.Join(absDir, "chain.crt")
	if err := createChainFile(chainPath, cert, parentCA.Certificate()); err != nil {
		return err
	}

	printSubordinateCatalystCASuccess(cert, certPath, chainPath, classicalKeyPath, pqcKeyPath, caInitPassphrase)
	return nil
}

func runCAInfo(cmd *cobra.Command, args []string) error {
	absDir, err := filepath.Abs(caInfoDir)
	if err != nil {
		return fmt.Errorf("invalid CA directory: %w", err)
	}

	store := ca.NewFileStore(absDir)
	if !store.Exists() {
		return fmt.Errorf("CA not found at %s", absDir)
	}

	caInstance, err := ca.New(store)
	if err != nil {
		return fmt.Errorf("failed to load CA: %w", err)
	}
	defer func() { _ = caInstance.Close() }()

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

	// Load CAInfo for versioned CAs
	info, _ := ca.LoadCAInfo(absDir)

	// Load certificates based on flags
	var certs []*x509.Certificate
	if caExportAll {
		certs, err = loadAllVersionCerts(absDir, info)
		if err != nil {
			return err
		}
	} else if caExportVersion != "" {
		certs, err = loadVersionCerts(absDir, caExportVersion, info)
		if err != nil {
			return err
		}
	}

	// If no certs loaded yet, use bundle-based loading
	if len(certs) == 0 {
		store := ca.NewFileStore(absDir)
		if !store.Exists() {
			return fmt.Errorf("CA not found at %s", absDir)
		}
		certs, err = loadBundleCerts(store, caExportBundle)
		if err != nil {
			return err
		}
	}

	// Encode and write output
	output, err := encodeCertificates(certs, caExportFormat)
	if err != nil {
		return err
	}

	return writeExportOutput(output, caExportOut, len(certs))
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
		store := ca.NewFileStore(caDir)
		if !store.Exists() {
			continue
		}

		cert, err := store.LoadCACert(context.Background())
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
