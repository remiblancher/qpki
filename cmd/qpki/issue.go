package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/remiblancher/post-quantum-pki/internal/ca"
	"github.com/remiblancher/post-quantum-pki/internal/profile"
)

var issueCmd = &cobra.Command{
	Use:   "issue",
	Short: "Issue a certificate from a CSR",
	Long: `Issue a new certificate from a Certificate Signing Request (CSR).

This command requires a CSR file (--csr). For direct issuance with
automatic key generation, use 'pki credential enroll' instead.

Profiles are organized by category:
  ec/          - ECDSA profiles (modern classical)
  rsa/         - RSA profiles (legacy compatibility)
  ml/          - ML-DSA and ML-KEM profiles (post-quantum)
  slh/         - SLH-DSA profiles (hash-based post-quantum)
  hybrid/catalyst/  - Catalyst hybrid (ITU-T X.509 Section 9.8)
  hybrid/composite/ - IETF composite hybrid

Use 'pki profile list' to see all available profiles.

Examples:
  # Issue from a classical CSR
  pki issue --profile ec/tls-server --csr server.csr --out server.crt

  # Issue from a PQC CSR (ML-DSA)
  pki issue --profile ml/tls-server-sign --csr mldsa.csr --out server.crt

  # Issue from a ML-KEM CSR (requires attestation)
  pki issue --profile ml-kem/client --csr kem.csr --attest-cert sign.crt --out kem.crt

  # Issue from a hybrid CSR
  pki issue --profile hybrid/catalyst/tls-server --csr hybrid.csr --out server.crt`,
	RunE: runIssue,
}

var (
	issueCADir        string
	issueProfile      string
	issueCSRFile      string
	issuePubKeyFile   string
	issueKeyFile      string
	issueCertOut      string
	issueCAPassphrase string
	issueHybridAlg    string
	issueAttestCert   string
	issueVars         []string // --var key=value
	issueVarFile      string   // --var-file vars.yaml
)

func init() {
	flags := issueCmd.Flags()
	flags.StringVarP(&issueCADir, "ca-dir", "d", "./ca", "CA directory")
	flags.StringVarP(&issueProfile, "profile", "P", "", "Certificate profile (required, e.g., ec/tls-server)")
	_ = issueCmd.MarkFlagRequired("profile")
	flags.StringVar(&issueCSRFile, "csr", "", "Certificate Signing Request file (required)")
	_ = issueCmd.MarkFlagRequired("csr")
	flags.StringVar(&issuePubKeyFile, "pubkey", "", "Public key file (alternative to CSR)")
	flags.StringVar(&issueKeyFile, "key", "", "Existing private key file (alternative to CSR)")
	flags.StringVarP(&issueCertOut, "out", "o", "", "Output certificate file")
	flags.StringArrayVar(&issueVars, "var", nil, "Variable value (key=value, repeatable)")
	flags.StringVar(&issueVarFile, "var-file", "", "YAML file with variable values")
	flags.StringVar(&issueCAPassphrase, "ca-passphrase", "", "CA private key passphrase (or env:VAR_NAME)")
	flags.StringVar(&issueHybridAlg, "hybrid", "", "PQC algorithm for hybrid extension")
	flags.StringVar(&issueAttestCert, "attest-cert", "", "Attestation certificate for ML-KEM CSR verification (RFC 9883)")
}

func runIssue(cmd *cobra.Command, args []string) error {
	// Check mutual exclusivity of --var and --var-file
	if issueVarFile != "" && len(issueVars) > 0 {
		return fmt.Errorf("--var and --var-file are mutually exclusive")
	}

	// Load CA
	absDir, _ := filepath.Abs(issueCADir)
	store := ca.NewFileStore(absDir)
	if !store.Exists() {
		return fmt.Errorf("CA not found at %s - run 'pki init-ca' first", absDir)
	}

	caInstance, err := ca.New(store)
	if err != nil {
		return fmt.Errorf("failed to load CA: %w", err)
	}

	// Load profile (supports both builtin names and file paths)
	prof, err := profile.LoadProfile(issueProfile)
	if err != nil {
		return fmt.Errorf("failed to load profile %s: %w", issueProfile, err)
	}

	// Load CA signer based on profile requirements
	if err := loadCASignerForProfile(caInstance, prof, issueCAPassphrase); err != nil {
		return err
	}

	// Parse CSR (handles both classical and PQC algorithms)
	csrResult, err := parseCSRFromFile(issueCSRFile, issueAttestCert)
	if err != nil {
		return err
	}

	// Load variables from file and/or flags
	varValues, err := profile.LoadVariables(issueVarFile, issueVars)
	if err != nil {
		return fmt.Errorf("failed to load variables: %w", err)
	}

	// Merge CSR values into variables
	mergeCSRVariables(varValues, csrResult.Template)

	// Validate and render variables via TemplateEngine if profile has variables
	if len(prof.Variables) > 0 {
		engine, err := profile.NewTemplateEngine(prof)
		if err != nil {
			return fmt.Errorf("failed to create template engine: %w", err)
		}
		rendered, err := engine.Render(varValues)
		if err != nil {
			return fmt.Errorf("variable validation failed: %w", err)
		}
		varValues = rendered.ResolvedValues
	}

	// Resolve profile extensions (substitute SAN template variables)
	resolvedExtensions, err := profile.ResolveProfileExtensions(prof, varValues)
	if err != nil {
		return fmt.Errorf("failed to resolve extensions: %w", err)
	}

	// Issue certificate based on profile mode
	ctx := context.Background()
	var cert interface{ Raw() []byte }

	if prof.IsCatalyst() {
		c, err := issueCatalystCert(ctx, caInstance, prof, csrResult.Template, csrResult.PublicKey, resolvedExtensions)
		if err != nil {
			return err
		}
		cert = &certWrapper{c}
	} else {
		c, err := issueStandardCert(ctx, caInstance, prof, csrResult.Template, csrResult.PublicKey, resolvedExtensions, issueHybridAlg)
		if err != nil {
			return err
		}
		cert = &certWrapper{c}
	}

	// Get the actual certificate
	issuedCert := cert.(*certWrapper).cert

	// Save certificate
	if issueCertOut != "" {
		if err := writeCertificatePEM(issuedCert, issueCertOut); err != nil {
			return err
		}
	}

	// Display result
	printCertificateInfo(issuedCert, issueCertOut, store)

	return nil
}

// certWrapper wraps x509.Certificate to provide a consistent interface.
type certWrapper struct {
	cert *x509.Certificate
}

func (c *certWrapper) Raw() []byte {
	return c.cert.Raw
}

// printCertificateInfo displays the issued certificate information.
func printCertificateInfo(cert *x509.Certificate, certPath string, store *ca.FileStore) {
	fmt.Printf("Certificate issued successfully!\n")
	fmt.Printf("  Subject:    %s\n", cert.Subject.String())
	fmt.Printf("  Serial:     %X\n", cert.SerialNumber.Bytes())
	fmt.Printf("  Not Before: %s\n", cert.NotBefore.Format("2006-01-02 15:04:05"))
	fmt.Printf("  Not After:  %s\n", cert.NotAfter.Format("2006-01-02 15:04:05"))
	fmt.Printf("  Issuer:     %s\n", cert.Issuer.String())

	if certPath != "" {
		fmt.Printf("  Certificate: %s\n", certPath)
	}

	fmt.Printf("  Stored at:   %s\n", store.CertPath(cert.SerialNumber.Bytes()))
}
