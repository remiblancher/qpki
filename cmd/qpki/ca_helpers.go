package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/remiblancher/post-quantum-pki/internal/ca"
	"github.com/remiblancher/post-quantum-pki/internal/crypto"
	"github.com/remiblancher/post-quantum-pki/internal/profile"
)

// profileAlgorithmInfo holds algorithm information extracted from a profile.
type profileAlgorithmInfo struct {
	Algorithm      crypto.AlgorithmID
	HybridAlg      crypto.AlgorithmID
	IsComposite    bool
	IsCatalyst     bool
	ValidityYears  int
	PathLen        int
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

// exportCertsResult holds the result of exporting certificates.
type exportCertsResult struct {
	Certificates []*x509.Certificate
	Format       string
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
