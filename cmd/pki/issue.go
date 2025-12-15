package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/remiblancher/pki/internal/ca"
	"github.com/remiblancher/pki/internal/crypto"
	"github.com/remiblancher/pki/internal/profiles"
	"github.com/remiblancher/pki/internal/x509util"
)

var issueCmd = &cobra.Command{
	Use:   "issue",
	Short: "Issue a new certificate",
	Long: `Issue a new certificate signed by the CA.

The certificate can be issued from:
  1. A Certificate Signing Request (CSR) file
  2. A public key file
  3. Auto-generated key pair

Profiles available:
  tls-server  - TLS server authentication
  tls-client  - TLS client authentication
  root-ca     - Root CA certificate
  issuing-ca  - Subordinate/Issuing CA

Examples:
  # Issue a TLS server certificate with auto-generated key
  pki issue --profile tls-server --cn server.example.com \
    --dns server.example.com,www.example.com \
    --out server.crt --key-out server.key

  # Issue from a CSR
  pki issue --profile tls-server --csr request.csr --out server.crt

  # Issue a subordinate CA
  pki issue --profile issuing-ca --cn "Issuing CA" --out issuing-ca.crt`,
	RunE: runIssue,
}

var (
	issueCADir        string
	issueProfile      string
	issueCommonName   string
	issueDNSNames     []string
	issueIPAddrs      []string
	issueCSRFile      string
	issuePubKeyFile   string
	issueKeyFile      string
	issueCertOut      string
	issueKeyOut       string
	issueAlgorithm    string
	issueValidityDays int
	issueCAPassphrase string
	issueHybridAlg    string
)

func init() {
	flags := issueCmd.Flags()
	flags.StringVarP(&issueCADir, "ca-dir", "d", "./ca", "CA directory")
	flags.StringVarP(&issueProfile, "profile", "P", "tls-server", "Certificate profile")
	flags.StringVar(&issueCommonName, "cn", "", "Subject common name")
	flags.StringSliceVar(&issueDNSNames, "dns", nil, "DNS Subject Alternative Names")
	flags.StringSliceVar(&issueIPAddrs, "ip", nil, "IP Subject Alternative Names")
	flags.StringVar(&issueCSRFile, "csr", "", "Certificate Signing Request file")
	flags.StringVar(&issuePubKeyFile, "pubkey", "", "Public key file (alternative to CSR)")
	flags.StringVar(&issueKeyFile, "key", "", "Existing private key file (alternative to CSR)")
	flags.StringVarP(&issueCertOut, "out", "o", "", "Output certificate file")
	flags.StringVar(&issueKeyOut, "key-out", "", "Output private key file (for auto-generated keys)")
	flags.StringVarP(&issueAlgorithm, "algorithm", "a", "ecdsa-p256", "Key algorithm (for auto-generated keys)")
	flags.IntVar(&issueValidityDays, "days", 0, "Validity period in days (overrides profile default)")
	flags.StringVar(&issueCAPassphrase, "ca-passphrase", "", "CA private key passphrase (or env:VAR_NAME)")
	flags.StringVar(&issueHybridAlg, "hybrid", "", "PQC algorithm for hybrid extension")
}

func runIssue(cmd *cobra.Command, args []string) error {
	// Load CA
	absDir, _ := filepath.Abs(issueCADir)
	store := ca.NewStore(absDir)
	if !store.Exists() {
		return fmt.Errorf("CA not found at %s - run 'pki init-ca' first", absDir)
	}

	caInstance, err := ca.New(store)
	if err != nil {
		return fmt.Errorf("failed to load CA: %w", err)
	}

	if err := caInstance.LoadSigner(issueCAPassphrase); err != nil {
		return fmt.Errorf("failed to load CA signer: %w", err)
	}

	// Get profile
	profile, err := profiles.Get(issueProfile)
	if err != nil {
		return fmt.Errorf("unknown profile: %s", issueProfile)
	}

	// Determine subject public key and template
	var subjectPubKey interface{}
	var template *x509.Certificate
	var generatedKeyPath string

	switch {
	case issueCSRFile != "":
		// Load CSR
		csrData, err := os.ReadFile(issueCSRFile)
		if err != nil {
			return fmt.Errorf("failed to read CSR file: %w", err)
		}

		block, _ := pem.Decode(csrData)
		if block == nil || block.Type != "CERTIFICATE REQUEST" {
			return fmt.Errorf("invalid CSR file")
		}

		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse CSR: %w", err)
		}

		if err := csr.CheckSignature(); err != nil {
			return fmt.Errorf("invalid CSR signature: %w", err)
		}

		subjectPubKey = csr.PublicKey
		template = &x509.Certificate{
			Subject:     csr.Subject,
			DNSNames:    csr.DNSNames,
			IPAddresses: csr.IPAddresses,
		}

	case issueKeyFile != "":
		// Load existing key
		signer, err := crypto.LoadPrivateKey(issueKeyFile, nil)
		if err != nil {
			return fmt.Errorf("failed to load private key: %w", err)
		}
		subjectPubKey = signer.Public()
		template = &x509.Certificate{}

	case issuePubKeyFile != "":
		// Load public key
		return fmt.Errorf("--pubkey not yet implemented - use --csr or --key instead")

	default:
		// Generate new key pair
		alg, err := crypto.ParseAlgorithm(issueAlgorithm)
		if err != nil {
			return fmt.Errorf("invalid algorithm: %w", err)
		}

		kp, err := crypto.GenerateKeyPair(alg)
		if err != nil {
			return fmt.Errorf("failed to generate key pair: %w", err)
		}

		subjectPubKey = kp.PublicKey
		template = &x509.Certificate{}

		// Save private key if output path specified
		if issueKeyOut != "" {
			signer, err := crypto.NewSoftwareSigner(kp)
			if err != nil {
				return fmt.Errorf("failed to create signer: %w", err)
			}

			if err := signer.SavePrivateKey(issueKeyOut, nil); err != nil {
				return fmt.Errorf("failed to save private key: %w", err)
			}
			generatedKeyPath = issueKeyOut
		}
	}

	// Apply command-line overrides
	if issueCommonName != "" {
		template.Subject.CommonName = issueCommonName
	}
	if len(issueDNSNames) > 0 {
		template.DNSNames = issueDNSNames
	}
	if len(issueIPAddrs) > 0 {
		for _, ipStr := range issueIPAddrs {
			ip := net.ParseIP(ipStr)
			if ip == nil {
				return fmt.Errorf("invalid IP address: %s", ipStr)
			}
			template.IPAddresses = append(template.IPAddresses, ip)
		}
	}

	// Build issue request
	req := ca.IssueRequest{
		Template:  template,
		PublicKey: subjectPubKey,
		Profile:   profile,
	}

	// Add hybrid extension if requested
	if issueHybridAlg != "" {
		hybridAlg, err := crypto.ParseAlgorithm(issueHybridAlg)
		if err != nil {
			return fmt.Errorf("invalid hybrid algorithm: %w", err)
		}

		pqcKP, err := crypto.GenerateKeyPair(hybridAlg)
		if err != nil {
			return fmt.Errorf("failed to generate PQC key: %w", err)
		}

		pqcPubBytes, err := pqcKP.PublicKeyBytes()
		if err != nil {
			return fmt.Errorf("failed to get PQC public key: %w", err)
		}

		req.HybridAlgorithm = hybridAlg
		req.HybridPQCKey = pqcPubBytes
		req.HybridPolicy = x509util.HybridPolicyInformational
	}

	// Issue certificate
	cert, err := caInstance.Issue(req)
	if err != nil {
		return fmt.Errorf("failed to issue certificate: %w", err)
	}

	// Save certificate
	if issueCertOut != "" {
		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		if err := os.WriteFile(issueCertOut, pem.EncodeToMemory(block), 0644); err != nil {
			return fmt.Errorf("failed to write certificate: %w", err)
		}
	}

	// Display result
	fmt.Printf("Certificate issued successfully!\n")
	fmt.Printf("  Subject:    %s\n", cert.Subject.String())
	fmt.Printf("  Serial:     %X\n", cert.SerialNumber.Bytes())
	fmt.Printf("  Not Before: %s\n", cert.NotBefore.Format("2006-01-02 15:04:05"))
	fmt.Printf("  Not After:  %s\n", cert.NotAfter.Format("2006-01-02 15:04:05"))
	fmt.Printf("  Issuer:     %s\n", cert.Issuer.String())

	if issueCertOut != "" {
		fmt.Printf("  Certificate: %s\n", issueCertOut)
	}
	if generatedKeyPath != "" {
		fmt.Printf("  Private Key: %s\n", generatedKeyPath)
	}

	// Show store path
	fmt.Printf("  Stored at:   %s\n", store.CertPath(cert.SerialNumber.Bytes()))

	return nil
}
