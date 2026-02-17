package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/remiblancher/post-quantum-pki/pkg/ca"
	"github.com/remiblancher/post-quantum-pki/pkg/profile"
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
	if issueVarFile != "" && len(issueVars) > 0 {
		return fmt.Errorf("--var and --var-file are mutually exclusive")
	}

	absDir, _ := filepath.Abs(issueCADir)
	store := ca.NewFileStore(absDir)
	if !store.Exists() {
		return fmt.Errorf("CA not found at %s - run 'pki init-ca' first", absDir)
	}

	caInstance, err := ca.New(store)
	if err != nil {
		return fmt.Errorf("failed to load CA: %w", err)
	}
	defer func() { _ = caInstance.Close() }()

	prof, err := profile.LoadProfile(issueProfile)
	if err != nil {
		return fmt.Errorf("failed to load profile %s: %w", issueProfile, err)
	}

	if err := loadCASignerForProfile(caInstance, prof, issueCAPassphrase); err != nil {
		return err
	}

	csrResult, err := parseCSRFromFile(issueCSRFile, issueAttestCert)
	if err != nil {
		return err
	}

	varValues, err := loadAndRenderIssueVariables(prof, issueVarFile, issueVars, csrResult.Template)
	if err != nil {
		return err
	}

	resolvedExtensions, err := profile.ResolveProfileExtensions(prof, varValues)
	if err != nil {
		return fmt.Errorf("failed to resolve extensions: %w", err)
	}

	issuedCert, err := issueCertificateByMode(context.Background(), caInstance, prof, csrResult, resolvedExtensions, issueHybridAlg)
	if err != nil {
		return err
	}

	if issueCertOut != "" {
		if err := writeCertificatePEM(issuedCert, issueCertOut); err != nil {
			return err
		}
	}

	printCertificateInfo(issuedCert, issueCertOut, store)
	return nil
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
