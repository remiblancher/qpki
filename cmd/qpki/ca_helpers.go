package main

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/remiblancher/post-quantum-pki/internal/ca"
	"github.com/remiblancher/post-quantum-pki/internal/crypto"
	"github.com/remiblancher/post-quantum-pki/internal/profile"
)

// ctx is the default context for CA operations.
var ctx = context.Background()

// profileAlgorithmInfo holds algorithm information extracted from a profile.
type profileAlgorithmInfo struct {
	Algorithm     crypto.AlgorithmID
	HybridAlg     crypto.AlgorithmID
	IsComposite   bool
	IsCatalyst    bool
	ValidityYears int
	PathLen       int
}

// extractProfileAlgorithmInfo extracts algorithm information from a profile.
func extractProfileAlgorithmInfo(prof *profile.Profile) (*profileAlgorithmInfo, error) {
	info := &profileAlgorithmInfo{}

	// Extract algorithm from profile
	info.Algorithm = prof.GetAlgorithm()
	if !info.Algorithm.IsValid() {
		return nil, fmt.Errorf("profile has invalid algorithm: %s", info.Algorithm)
	}

	// Extract hybrid algorithm if profile is Catalyst or Composite
	if prof.IsCatalyst() {
		info.HybridAlg = prof.GetAlternativeAlgorithm()
		info.IsCatalyst = true
	} else if prof.IsComposite() {
		info.HybridAlg = prof.GetAlternativeAlgorithm()
		info.IsComposite = true
	}

	// Extract validity (convert from duration to years)
	info.ValidityYears = int(prof.Validity.Hours() / 24 / 365)
	if info.ValidityYears < 1 {
		info.ValidityYears = 1
	}

	// Extract pathLen from profile extensions
	info.PathLen = 1 // default
	if prof.Extensions != nil && prof.Extensions.BasicConstraints != nil && prof.Extensions.BasicConstraints.PathLen != nil {
		info.PathLen = *prof.Extensions.BasicConstraints.PathLen
	}

	return info, nil
}

// loadAndValidateProfileVariables loads and validates variables for a profile.
func loadAndValidateProfileVariables(prof *profile.Profile, varFile string, vars []string) (profile.VariableValues, error) {
	varValues, err := profile.LoadVariables(varFile, vars)
	if err != nil {
		return nil, fmt.Errorf("failed to load variables: %w", err)
	}

	// Validate variables against profile constraints
	if len(prof.Variables) > 0 {
		engine, err := profile.NewTemplateEngine(prof)
		if err != nil {
			return nil, fmt.Errorf("failed to create template engine: %w", err)
		}
		rendered, err := engine.Render(varValues)
		if err != nil {
			return nil, fmt.Errorf("failed to validate variables: %w", err)
		}
		varValues = rendered.ResolvedValues
	}

	return varValues, nil
}

// buildCAConfigFromProfile builds a CA configuration from a profile and variables.
func buildCAConfigFromProfile(
	prof *profile.Profile,
	subject pkix.Name,
	algInfo *profileAlgorithmInfo,
	passphrase string,
) (*ca.Config, error) {
	cfg := &ca.Config{
		CommonName:    subject.CommonName,
		Organization:  firstOrEmpty(subject.Organization),
		Country:       firstOrEmpty(subject.Country),
		Algorithm:     algInfo.Algorithm,
		ValidityYears: algInfo.ValidityYears,
		PathLen:       algInfo.PathLen,
		Passphrase:    passphrase,
		Extensions:    prof.Extensions,
	}

	// Configure hybrid if requested
	if algInfo.HybridAlg != "" {
		if !algInfo.HybridAlg.IsPQC() {
			return nil, fmt.Errorf("hybrid algorithm must be a PQC algorithm, got: %s", algInfo.HybridAlg)
		}
		cfg.HybridConfig = &ca.HybridConfig{
			Algorithm: algInfo.HybridAlg,
			Policy:    0, // HybridPolicyInformational
		}
	}

	return cfg, nil
}

// initializeCAByType initializes a CA based on its type (composite, hybrid, PQC, or classical).
func initializeCAByType(store *ca.FileStore, cfg *ca.Config, isComposite bool) (*ca.CA, error) {
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
		return ca.InitializeCompositeCA(store, compositeCfg)
	}

	if cfg.HybridConfig != nil {
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
		return ca.InitializeHybridCA(store, hybridCfg)
	}

	if cfg.Algorithm.IsPQC() {
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
		return ca.InitializePQCCA(store, pqcCfg)
	}

	return ca.Initialize(store, *cfg)
}

// printCAInitSuccess prints the success message after CA initialization.
func printCAInitSuccess(newCA *ca.CA, absDir string, cfg *ca.Config, isComposite bool) {
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
		certPath = newCA.Store().CACertPath()
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

	if cfg.Passphrase == "" {
		fmt.Fprintf(os.Stderr, "\nWARNING: Private key is not encrypted. Use --passphrase for production.\n")
	}
}

// encodeCertificates encodes certificates to PEM or DER format.
func encodeCertificates(certs []*x509.Certificate, format string) ([]byte, error) {
	if format == "der" {
		if len(certs) > 1 {
			return nil, fmt.Errorf("DER format only supports single certificate, use PEM for chain")
		}
		return certs[0].Raw, nil
	}

	// PEM format
	var output []byte
	for _, cert := range certs {
		block := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
		output = append(output, pem.EncodeToMemory(block)...)
	}
	return output, nil
}

// writeExportOutput writes exported certificates to file or stdout.
func writeExportOutput(data []byte, outputPath string, certCount int) error {
	if outputPath == "" {
		fmt.Print(string(data))
		return nil
	}

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}
	fmt.Printf("Exported %d certificate(s) to %s\n", certCount, outputPath)
	return nil
}

// loadAllVersionCerts loads certificates from all versions when --all flag is used.
func loadAllVersionCerts(absDir string, info *ca.CAInfo) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	if info == nil || len(info.Versions) == 0 {
		// Not versioned, just export the current CA
		store := ca.NewFileStore(absDir)
		if !store.Exists() {
			return nil, fmt.Errorf("CA not found at %s", absDir)
		}
		caCert, err := store.LoadCACert(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to load CA certificate: %w", err)
		}
		return []*x509.Certificate{caCert}, nil
	}

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
	return certs, nil
}

// loadVersionCerts loads certificates for a specific version.
func loadVersionCerts(absDir, versionID string, info *ca.CAInfo) ([]*x509.Certificate, error) {
	if info == nil || len(info.Versions) == 0 {
		return nil, fmt.Errorf("CA is not versioned, cannot use --version flag")
	}

	info.SetBasePath(absDir)
	ver, ok := info.Versions[versionID]
	if !ok {
		return nil, fmt.Errorf("version %s not found", versionID)
	}

	var certs []*x509.Certificate
	for _, algo := range ver.Algos {
		certPath := info.CertPath(versionID, algo)
		if cert, err := loadCertFromPath(certPath); err == nil {
			certs = append(certs, cert)
		}
	}

	// Fallback: check legacy ca.crt path (for rotate-created versions)
	if len(certs) == 0 {
		legacyCertPath := filepath.Join(absDir, "versions", versionID, "ca.crt")
		if cert, err := loadCertFromPath(legacyCertPath); err == nil {
			certs = append(certs, cert)
		}
	}

	return certs, nil
}

// validateHSMFlags validates HSM-related command flags.
func validateHSMFlags(generateKey bool, keyLabel, keyID string) error {
	if generateKey {
		if keyLabel == "" {
			return fmt.Errorf("--key-label is required when using --generate-key")
		}
	} else {
		if keyLabel == "" && keyID == "" {
			return fmt.Errorf("--key-label or --key-id is required when using --hsm-config (or use --generate-key)")
		}
	}
	return nil
}

// validateCAHSMInitFlags validates flags for HSM CA initialization.
func validateCAHSMInitFlags(varFile string, vars []string, profiles []string, generateKey bool, keyLabel, keyID string) error {
	if varFile != "" && len(vars) > 0 {
		return fmt.Errorf("--var and --var-file are mutually exclusive")
	}
	if err := validateHSMFlags(generateKey, keyLabel, keyID); err != nil {
		return err
	}
	if len(profiles) != 1 {
		return fmt.Errorf("HSM mode requires exactly one --profile (multi-profile not supported with HSM)")
	}
	return nil
}

// loadAndValidateHSMProfile loads a profile and validates it for HSM use.
func loadAndValidateHSMProfile(profileName string) (*profile.Profile, crypto.AlgorithmID, error) {
	prof, err := profile.LoadProfile(profileName)
	if err != nil {
		return nil, "", fmt.Errorf("failed to load profile %s: %w", profileName, err)
	}

	alg := prof.GetAlgorithm()
	if !alg.IsValid() {
		return nil, "", fmt.Errorf("profile %s has invalid algorithm: %s", profileName, alg)
	}
	if err := validateHSMProfile(prof, alg, profileName); err != nil {
		return nil, "", err
	}

	return prof, alg, nil
}

// validateHSMProfile validates that a profile is compatible with HSM.
func validateHSMProfile(prof *profile.Profile, alg crypto.AlgorithmID, profileName string) error {
	if alg.IsPQC() {
		// Allow PQC algorithms if HSM_PQC_ENABLED is set (e.g., Utimaco QuantumProtect)
		if os.Getenv("HSM_PQC_ENABLED") == "" {
			return fmt.Errorf("HSM does not support PQC algorithms. Set HSM_PQC_ENABLED=1 for PQC-capable HSMs (e.g., Utimaco), or use a classical profile (ec/*, rsa/*)")
		}
	}
	if prof.IsCatalyst() || prof.IsComposite() {
		return fmt.Errorf("HSM does not support hybrid/composite profiles. Use a classical profile (ec/*, rsa/*) or remove --hsm-config")
	}
	return nil
}

// generateHSMKey generates a key in the HSM if requested.
func generateHSMKey(hsmCfg *crypto.HSMConfig, alg crypto.AlgorithmID, keyLabel string) (string, string, error) {
	pin, err := hsmCfg.GetPIN()
	if err != nil {
		return "", "", fmt.Errorf("failed to get PIN: %w", err)
	}

	fmt.Printf("Generating %s key in HSM...\n", alg)
	genCfg := crypto.GenerateHSMKeyPairConfig{
		ModulePath: hsmCfg.PKCS11.Lib,
		TokenLabel: hsmCfg.PKCS11.Token,
		PIN:        pin,
		KeyLabel:   keyLabel,
		Algorithm:  alg,
	}

	result, err := crypto.GenerateHSMKeyPair(genCfg)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate key in HSM: %w", err)
	}

	fmt.Printf("  Key generated: label=%s, id=%s\n", result.KeyLabel, result.KeyID)
	return result.KeyLabel, result.KeyID, nil
}

// loadParentCA loads and initializes the parent CA for subordinate CA creation.
func loadParentCA(parentDir, passphrase string) (*ca.CA, error) {
	parentAbsDir, err := filepath.Abs(parentDir)
	if err != nil {
		return nil, fmt.Errorf("invalid parent directory path: %w", err)
	}

	parentStore := ca.NewFileStore(parentAbsDir)
	if !parentStore.Exists() {
		return nil, fmt.Errorf("parent CA not found at %s", parentAbsDir)
	}

	parentCA, err := ca.New(parentStore)
	if err != nil {
		return nil, fmt.Errorf("failed to load parent CA: %w", err)
	}

	if err := parentCA.LoadSigner(passphrase); err != nil {
		return nil, fmt.Errorf("failed to load parent CA signer: %w", err)
	}

	return parentCA, nil
}

// createChainFile creates a certificate chain file with subordinate and parent certs.
func createChainFile(chainPath string, subCert, parentCert *x509.Certificate) error {
	chainFile, err := os.Create(chainPath)
	if err != nil {
		return fmt.Errorf("failed to create chain file: %w", err)
	}
	defer func() { _ = chainFile.Close() }()

	subBlock := &pem.Block{Type: "CERTIFICATE", Bytes: subCert.Raw}
	if err := pem.Encode(chainFile, subBlock); err != nil {
		return fmt.Errorf("failed to write subordinate certificate to chain: %w", err)
	}

	parentBlock := &pem.Block{Type: "CERTIFICATE", Bytes: parentCert.Raw}
	if err := pem.Encode(chainFile, parentBlock); err != nil {
		return fmt.Errorf("failed to write parent certificate to chain: %w", err)
	}

	return nil
}

// printSubordinateCASuccess prints the success message for subordinate CA creation.
func printSubordinateCASuccess(cert *x509.Certificate, certPath, chainPath, keyPath, passphrase string) {
	fmt.Printf("\nSubordinate CA initialized successfully!\n")
	fmt.Printf("  Subject:     %s\n", cert.Subject.String())
	fmt.Printf("  Issuer:      %s\n", cert.Issuer.String())
	fmt.Printf("  Serial:      %X\n", cert.SerialNumber.Bytes())
	fmt.Printf("  Not Before:  %s\n", cert.NotBefore.Format("2006-01-02 15:04:05"))
	fmt.Printf("  Not After:   %s\n", cert.NotAfter.Format("2006-01-02 15:04:05"))
	fmt.Printf("  Certificate: %s\n", certPath)
	fmt.Printf("  Chain:       %s\n", chainPath)
	fmt.Printf("  Private Key: %s\n", keyPath)

	if passphrase == "" {
		fmt.Fprintf(os.Stderr, "\nWARNING: Private key is not encrypted. Use --passphrase for production.\n")
	}
}

// applyValidityOverrides applies CLI overrides to algorithm info.
func applyValidityOverrides(cmd interface{ Changed(string) bool }, algInfo *profileAlgorithmInfo, validityYears, pathLen int) {
	if cmd.Changed("validity") {
		algInfo.ValidityYears = validityYears
	}
	if cmd.Changed("path-len") {
		algInfo.PathLen = pathLen
	}
}

// setupHSMSignerAndVerify connects to HSM and verifies algorithm compatibility.
func setupHSMSignerAndVerify(hsmCfg *crypto.HSMConfig, keyLabel, keyID string, expectedAlg crypto.AlgorithmID) (*crypto.PKCS11Signer, error) {
	pkcs11Cfg, err := hsmCfg.ToPKCS11Config(keyLabel, keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to create PKCS#11 config: %w", err)
	}

	fmt.Printf("Connecting to HSM...\n")
	signer, err := crypto.NewPKCS11Signer(*pkcs11Cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to HSM: %w", err)
	}

	signerAlg := signer.Algorithm()
	if !isCompatibleAlgorithm(expectedAlg, signerAlg) {
		_ = signer.Close()
		return nil, fmt.Errorf("HSM key algorithm %s does not match profile algorithm %s", signerAlg, expectedAlg)
	}

	return signer, nil
}

// saveCAHSMMetadata copies HSM config and saves CA metadata with key reference.
func saveCAHSMMetadata(newCA *ca.CA, absDir, srcHSMConfig, keyLabel, keyID string, signerAlg crypto.AlgorithmID) error {
	hsmRefPath := filepath.Join(absDir, "hsm.yaml")
	if err := copyHSMConfig(srcHSMConfig, hsmRefPath); err != nil {
		return fmt.Errorf("failed to copy HSM config: %w", err)
	}

	metadata := newCA.Info()
	metadata.AddKey(ca.KeyRef{
		ID:        "default",
		Algorithm: signerAlg,
		Storage:   ca.CreatePKCS11KeyRef("hsm.yaml", keyLabel, keyID),
	})
	if err := metadata.Save(); err != nil {
		return fmt.Errorf("failed to save CA metadata: %w", err)
	}

	return nil
}

// printCAHSMSuccess prints success message for HSM CA initialization.
func printCAHSMSuccess(newCA *ca.CA, absDir, hsmConfig, hsmRefPath string) {
	cert := newCA.Certificate()
	fmt.Printf("\nCA initialized successfully!\n")
	fmt.Printf("  Subject:     %s\n", cert.Subject.String())
	fmt.Printf("  Serial:      %X\n", cert.SerialNumber.Bytes())
	fmt.Printf("  Not Before:  %s\n", cert.NotBefore.Format("2006-01-02 15:04:05"))
	fmt.Printf("  Not After:   %s\n", cert.NotAfter.Format("2006-01-02 15:04:05"))
	fmt.Printf("  Certificate: %s\n", newCA.Store().CACertPath())
	fmt.Printf("  Key:         HSM (%s)\n", hsmConfig)
	fmt.Printf("  HSM Config:  %s\n", hsmRefPath)
}

// loadAndValidateProfiles loads profiles and validates variables against them.
func loadAndValidateProfiles(profileNames []string, varValues profile.VariableValues) ([]*profile.Profile, profile.VariableValues, error) {
	profiles := make([]*profile.Profile, 0, len(profileNames))

	for _, profileName := range profileNames {
		prof, err := profile.LoadProfile(profileName)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to load profile %s: %w", profileName, err)
		}

		if len(prof.Variables) > 0 && len(varValues) > 0 {
			engine, err := profile.NewTemplateEngine(prof)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to create template engine for %s: %w", profileName, err)
			}
			rendered, err := engine.Render(varValues)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to validate variables for %s: %w", profileName, err)
			}
			varValues = rendered.ResolvedValues
		}

		profiles = append(profiles, prof)
	}

	return profiles, varValues, nil
}

// buildProfileConfigs builds profile configurations from profiles and CLI overrides.
func buildProfileConfigs(profiles []*profile.Profile, cmd interface{ Changed(string) bool }, validityYears, pathLen int) []ca.ProfileInitConfig {
	configs := make([]ca.ProfileInitConfig, 0, len(profiles))

	for _, prof := range profiles {
		validity := int(prof.Validity.Hours() / 24 / 365)
		if validity < 1 {
			validity = 1
		}
		if cmd.Changed("validity") {
			validity = validityYears
		}

		pLen := 1
		if prof.Extensions != nil && prof.Extensions.BasicConstraints != nil && prof.Extensions.BasicConstraints.PathLen != nil {
			pLen = *prof.Extensions.BasicConstraints.PathLen
		}
		if cmd.Changed("path-len") {
			pLen = pathLen
		}

		configs = append(configs, ca.ProfileInitConfig{
			Profile:       prof,
			ValidityYears: validity,
			PathLen:       pLen,
		})
	}

	return configs
}

// printMultiProfileSuccess prints success message for multi-profile CA initialization.
func printMultiProfileSuccess(result *ca.MultiProfileInitResult, absDir, passphrase string) {
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

	if passphrase == "" {
		fmt.Fprintf(os.Stderr, "\nWARNING: Private keys are not encrypted. Use --passphrase for production.\n")
	}
}

// prepareSubordinateCAStore validates and prepares the store and CAInfo for subordinate CA.
func prepareSubordinateCAStore(absDir, profileName string, subject pkix.Name, algInfo *profileAlgorithmInfo) (*ca.FileStore, *ca.CAInfo, error) {
	store := ca.NewFileStore(absDir)
	if store.Exists() {
		return nil, nil, fmt.Errorf("CA already exists at %s", absDir)
	}
	if err := store.Init(context.Background()); err != nil {
		return nil, nil, fmt.Errorf("failed to initialize store: %w", err)
	}

	algoID := string(algInfo.Algorithm)
	info := ca.NewCAInfo(ca.Subject{
		CommonName:   subject.CommonName,
		Organization: subject.Organization,
		Country:      subject.Country,
	})
	info.SetBasePath(absDir)
	info.CreateInitialVersion([]string{profileName}, []string{algoID})
	if err := info.EnsureVersionDir("v1"); err != nil {
		return nil, nil, fmt.Errorf("failed to create version directory: %w", err)
	}

	return store, info, nil
}

// generateSubordinateKey generates a key pair for the subordinate CA.
func generateSubordinateKey(info *ca.CAInfo, algInfo *profileAlgorithmInfo, passphrase string) (crypto.Signer, string, error) {
	keyPath := info.KeyPath("v1", string(algInfo.Algorithm))
	keyCfg := crypto.KeyStorageConfig{
		Type:       crypto.KeyProviderTypeSoftware,
		KeyPath:    keyPath,
		Passphrase: passphrase,
	}
	km := crypto.NewKeyProvider(keyCfg)
	signer, err := km.Generate(algInfo.Algorithm, keyCfg)
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate CA key: %w", err)
	}
	return signer, keyPath, nil
}

// saveSubordinateCAInfo saves the certificate and CAInfo for a subordinate CA.
func saveSubordinateCAInfo(info *ca.CAInfo, cert *x509.Certificate, algInfo *profileAlgorithmInfo) (string, error) {
	algoID := string(algInfo.Algorithm)
	certPath := info.CertPath("v1", algoID)
	if err := saveCertToPath(certPath, cert); err != nil {
		return "", fmt.Errorf("failed to save CA certificate: %w", err)
	}

	info.AddKey(ca.KeyRef{
		ID:        "default",
		Algorithm: algInfo.Algorithm,
		Storage: crypto.StorageRef{
			Type: "software",
			Path: fmt.Sprintf("versions/v1/keys/ca.%s.key", algoID),
		},
	})
	if err := info.Save(); err != nil {
		return "", fmt.Errorf("failed to save CA info: %w", err)
	}

	return certPath, nil
}

// prepareSubordinateCatalystCAStore prepares a file store for a Catalyst subordinate CA.
// It creates the version with both classical and PQC algorithms.
func prepareSubordinateCatalystCAStore(absDir, profileName string, subject pkix.Name, algInfo *profileAlgorithmInfo) (*ca.FileStore, *ca.CAInfo, error) {
	store := ca.NewFileStore(absDir)
	if store.Exists() {
		return nil, nil, fmt.Errorf("CA already exists at %s", absDir)
	}
	if err := store.Init(context.Background()); err != nil {
		return nil, nil, fmt.Errorf("failed to initialize store: %w", err)
	}

	info := ca.NewCAInfo(ca.Subject{
		CommonName:   subject.CommonName,
		Organization: subject.Organization,
		Country:      subject.Country,
	})
	info.SetBasePath(absDir)

	// Create version with both algorithms for Catalyst
	classicalAlgoID := string(algInfo.Algorithm)
	pqcAlgoID := string(algInfo.HybridAlg)
	info.CreateInitialVersion([]string{profileName}, []string{classicalAlgoID, pqcAlgoID})

	if err := info.EnsureVersionDir("v1"); err != nil {
		return nil, nil, fmt.Errorf("failed to create version directory: %w", err)
	}

	return store, info, nil
}

// generateSubordinateCatalystKeys generates both classical and PQC key pairs for a Catalyst subordinate CA.
func generateSubordinateCatalystKeys(info *ca.CAInfo, algInfo *profileAlgorithmInfo, passphrase string) (crypto.HybridSigner, string, string, error) {
	classicalKeyPath := info.KeyPath("v1", string(algInfo.Algorithm))
	pqcKeyPath := info.KeyPath("v1", string(algInfo.HybridAlg))

	// Generate hybrid signer (both classical and PQC keys)
	hybridSigner, err := crypto.GenerateHybridSigner(algInfo.Algorithm, algInfo.HybridAlg)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to generate hybrid CA keys: %w", err)
	}

	// Save both keys
	if err := hybridSigner.SaveHybridKeys(classicalKeyPath, pqcKeyPath, []byte(passphrase)); err != nil {
		return nil, "", "", fmt.Errorf("failed to save hybrid CA keys: %w", err)
	}

	return hybridSigner, classicalKeyPath, pqcKeyPath, nil
}

// saveSubordinateCatalystCAInfo saves the certificate and CAInfo for a Catalyst subordinate CA.
func saveSubordinateCatalystCAInfo(store *ca.FileStore, info *ca.CAInfo, cert *x509.Certificate, algInfo *profileAlgorithmInfo) (string, error) {
	// Use Catalyst cert path naming convention
	certPath := info.HybridCertPathForVersion("v1", ca.HybridCertCatalyst, algInfo.Algorithm, algInfo.HybridAlg, false)
	if err := saveCertToPath(certPath, cert); err != nil {
		return "", fmt.Errorf("failed to save CA certificate: %w", err)
	}

	// Add classical key reference
	info.AddKey(ca.KeyRef{
		ID:        "classical",
		Algorithm: algInfo.Algorithm,
		Storage: crypto.StorageRef{
			Type: "software",
			Path: fmt.Sprintf("versions/v1/keys/ca.%s.key", algInfo.Algorithm),
		},
	})

	// Add PQC key reference
	info.AddKey(ca.KeyRef{
		ID:        "pqc",
		Algorithm: algInfo.HybridAlg,
		Storage: crypto.StorageRef{
			Type: "software",
			Path: fmt.Sprintf("versions/v1/keys/ca.%s.key", algInfo.HybridAlg),
		},
	})

	if err := info.Save(); err != nil {
		return "", fmt.Errorf("failed to save CA info: %w", err)
	}

	return certPath, nil
}

// printSubordinateCatalystCASuccess prints success message for Catalyst subordinate CA creation.
func printSubordinateCatalystCASuccess(cert *x509.Certificate, certPath, chainPath, classicalKeyPath, pqcKeyPath, passphrase string) {
	fmt.Printf("\nCatalyst Subordinate CA initialized successfully!\n")
	fmt.Printf("  Subject:         %s\n", cert.Subject.String())
	fmt.Printf("  Issuer:          %s\n", cert.Issuer.String())
	fmt.Printf("  Serial:          %02X\n", cert.SerialNumber.Bytes())
	fmt.Printf("  Not Before:      %s\n", cert.NotBefore.Format("2006-01-02 15:04:05"))
	fmt.Printf("  Not After:       %s\n", cert.NotAfter.Format("2006-01-02 15:04:05"))
	fmt.Printf("  Certificate:     %s\n", certPath)
	fmt.Printf("  Chain:           %s\n", chainPath)
	fmt.Printf("  Classical Key:   %s\n", classicalKeyPath)
	fmt.Printf("  PQC Key:         %s\n", pqcKeyPath)
	fmt.Printf("  Mode:            Catalyst (ITU-T)\n")
	if passphrase == "" {
		fmt.Printf("\nWARNING: Private keys are not encrypted. Use --passphrase for production.\n")
	}
}

// loadBundleCerts loads certificates based on bundle type (ca, chain, root).
func loadBundleCerts(store ca.Store, bundleType string) ([]*x509.Certificate, error) {
	caCert, err := store.LoadCACert(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load CA certificate: %w", err)
	}

	switch bundleType {
	case "ca":
		return []*x509.Certificate{caCert}, nil

	case "chain":
		certs := []*x509.Certificate{caCert}
		// Load cross-signed certificates (for CA rotation scenarios)
		if crossCerts, err := store.LoadCrossSignedCerts(ctx); err == nil && len(crossCerts) > 0 {
			certs = append(certs, crossCerts...)
		}
		// Try to load chain file (parent CA for subordinate CAs)
		chainPath := filepath.Join(store.BasePath(), "chain.crt")
		if chainData, err := os.ReadFile(chainPath); err == nil {
			if chainCerts, err := parseCertificatesPEM(chainData); err == nil {
				// Skip the first cert (it's the CA cert already added)
				for i, c := range chainCerts {
					if i > 0 {
						certs = append(certs, c)
					}
				}
			}
		}
		return certs, nil

	case "root":
		chainPath := filepath.Join(store.BasePath(), "chain.crt")
		if chainData, err := os.ReadFile(chainPath); err == nil {
			if chainCerts, err := parseCertificatesPEM(chainData); err == nil && len(chainCerts) > 0 {
				// Last cert in chain is the root
				return []*x509.Certificate{chainCerts[len(chainCerts)-1]}, nil
			}
		}
		// No chain file, CA is probably the root
		return []*x509.Certificate{caCert}, nil

	default:
		return nil, fmt.Errorf("invalid bundle type: %s (use: ca, chain, root)", bundleType)
	}
}

// validateCAInitSoftwareFlags validates flags for software CA init (non-HSM, single profile).
func validateCAInitSoftwareFlags(varFile string, vars, profiles []string) error {
	if varFile != "" && len(vars) > 0 {
		return fmt.Errorf("--var and --var-file are mutually exclusive")
	}
	if len(profiles) == 0 {
		return fmt.Errorf("at least one --profile is required")
	}
	return nil
}

// validateSubordinateCAFlags validates flags for subordinate CA init.
func validateSubordinateCAFlags(varFile string, vars, profiles []string) error {
	if varFile != "" && len(vars) > 0 {
		return fmt.Errorf("--var and --var-file are mutually exclusive")
	}
	if len(profiles) != 1 {
		return fmt.Errorf("subordinate CA requires exactly one --profile")
	}
	return nil
}
