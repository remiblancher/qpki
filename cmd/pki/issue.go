package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/remiblancher/pki/internal/ca"
	"github.com/remiblancher/pki/internal/crypto"
	"github.com/remiblancher/pki/internal/profile"
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

Profiles are organized by category:
  rsa/         - RSA profiles (legacy compatibility)
  ecdsa/       - ECDSA profiles (modern classical)
  hybrid/catalyst/  - Catalyst hybrid (combined signatures)
  hybrid/composite/ - IETF composite hybrid
  pqc/         - Full post-quantum profiles

Examples: ecdsa/tls-server, hybrid/catalyst/tls-client, pqc/issuing-ca

Use 'pki profile list' to see all available profiles.

Examples:
  # Issue a TLS server certificate with auto-generated key
  pki issue --profile ecdsa/tls-server --cn server.example.com \
    --dns server.example.com,www.example.com \
    --out server.crt --key-out server.key

  # Issue from a CSR with hybrid profile
  pki issue --profile hybrid/catalyst/tls-server --csr request.csr --out server.crt

  # Issue a subordinate CA
  pki issue --profile ecdsa/issuing-ca --cn "Issuing CA" --out issuing-ca.crt`,
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
	flags.StringVarP(&issueProfile, "profile", "P", "", "Certificate profile (required, e.g., ecdsa/tls-server)")
	_ = issueCmd.MarkFlagRequired("profile")
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

	// Load profile (supports both builtin names and file paths)
	prof, err := profile.LoadProfile(issueProfile)
	if err != nil {
		return fmt.Errorf("failed to load profile %s: %w", issueProfile, err)
	}

	// Load CA signer based on profile requirements
	if prof.IsCatalystSignature() {
		// Catalyst mode requires hybrid signer (both classical and PQC keys)
		if err := caInstance.LoadHybridSigner(issueCAPassphrase, issueCAPassphrase); err != nil {
			return fmt.Errorf("failed to load hybrid CA signer: %w", err)
		}
	} else {
		// Standard mode - single signer
		if err := caInstance.LoadSigner(issueCAPassphrase); err != nil {
			return fmt.Errorf("failed to load CA signer: %w", err)
		}
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
		// Use algorithm from profile unless --algorithm was explicitly provided
		var alg crypto.AlgorithmID
		if cmd.Flags().Changed("algorithm") {
			// User explicitly specified algorithm via --algorithm flag
			alg, err = crypto.ParseAlgorithm(issueAlgorithm)
			if err != nil {
				return fmt.Errorf("invalid algorithm: %w", err)
			}
		} else {
			// Use algorithm from profile
			alg = prof.Signature.Algorithms.Primary
			if alg == "" {
				return fmt.Errorf("profile %s does not specify a signature algorithm", issueProfile)
			}
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
	// Note: DNSNames and IPAddresses are handled via profile variable substitution
	// If the profile uses ${DNS}/${IP} variables, they will be substituted below.
	// If no profile SubjectAltName is defined, the values from CSR are used.

	// Build variable map for profile template substitution
	vars := map[string][]string{
		"DNS":   issueDNSNames,
		"IP":    issueIPAddrs,
		"CN":    nil, // CN is handled via template.Subject.CommonName
		"EMAIL": nil, // TODO: add --email flag if needed
		"URI":   nil, // TODO: add --uri flag if needed
	}
	if issueCommonName != "" {
		vars["CN"] = []string{issueCommonName}
	}

	// Substitute variables in profile extensions
	resolvedExtensions, err := prof.Extensions.SubstituteVariables(vars)
	if err != nil {
		return fmt.Errorf("profile requires: %w", err)
	}

	// Issue certificate based on profile mode
	var cert *x509.Certificate

	if prof.IsCatalystSignature() {
		// Catalyst mode: issue certificate with dual signatures
		// Need both classical and PQC keys for the subject

		// Get the algorithms from profile
		classicalAlg := prof.Signature.Algorithms.Primary
		pqcAlg := prof.Signature.Algorithms.Alternative

		// For Catalyst, we need to generate both key types
		// The subjectPubKey from above is the classical key (or from CSR)
		var classicalPubKey interface{}
		var pqcPubKey interface{}

		if issueCSRFile != "" || issueKeyFile != "" {
			// CSR/key provided - use it as classical, generate PQC
			classicalPubKey = subjectPubKey

			pqcKP, err := crypto.GenerateKeyPair(pqcAlg)
			if err != nil {
				return fmt.Errorf("failed to generate PQC key for Catalyst: %w", err)
			}
			pqcPubKey = pqcKP.PublicKey

			// Save PQC private key if output path specified
			if issueKeyOut != "" {
				pqcSigner, err := crypto.NewSoftwareSigner(pqcKP)
				if err != nil {
					return fmt.Errorf("failed to create PQC signer: %w", err)
				}
				pqcKeyPath := issueKeyOut + ".pqc"
				if err := pqcSigner.SavePrivateKey(pqcKeyPath, nil); err != nil {
					return fmt.Errorf("failed to save PQC private key: %w", err)
				}
			}
		} else {
			// Auto-generate both keys
			classicalKP, err := crypto.GenerateKeyPair(classicalAlg)
			if err != nil {
				return fmt.Errorf("failed to generate classical key: %w", err)
			}
			classicalPubKey = classicalKP.PublicKey

			pqcKP, err := crypto.GenerateKeyPair(pqcAlg)
			if err != nil {
				return fmt.Errorf("failed to generate PQC key: %w", err)
			}
			pqcPubKey = pqcKP.PublicKey

			// Save private keys if output path specified
			if issueKeyOut != "" {
				classicalSigner, err := crypto.NewSoftwareSigner(classicalKP)
				if err != nil {
					return fmt.Errorf("failed to create classical signer: %w", err)
				}
				if err := classicalSigner.SavePrivateKey(issueKeyOut, nil); err != nil {
					return fmt.Errorf("failed to save classical private key: %w", err)
				}
				generatedKeyPath = issueKeyOut

				pqcSigner, err := crypto.NewSoftwareSigner(pqcKP)
				if err != nil {
					return fmt.Errorf("failed to create PQC signer: %w", err)
				}
				pqcKeyPath := issueKeyOut + ".pqc"
				if err := pqcSigner.SavePrivateKey(pqcKeyPath, nil); err != nil {
					return fmt.Errorf("failed to save PQC private key: %w", err)
				}
			}
		}

		// Build Catalyst request
		catalystReq := ca.CatalystRequest{
			Template:           template,
			ClassicalPublicKey: classicalPubKey,
			PQCPublicKey:       pqcPubKey,
			PQCAlgorithm:       pqcAlg,
			Extensions:         resolvedExtensions,
			Validity:           prof.Validity,
		}

		cert, err = caInstance.IssueCatalyst(catalystReq)
		if err != nil {
			return fmt.Errorf("failed to issue Catalyst certificate: %w", err)
		}
	} else {
		// Standard or PQC mode
		req := ca.IssueRequest{
			Template:   template,
			PublicKey:  subjectPubKey,
			Extensions: resolvedExtensions,
			Validity:   prof.Validity,
		}

		// Add hybrid extension if requested via --hybrid flag
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

		cert, err = caInstance.Issue(req)
		if err != nil {
			return fmt.Errorf("failed to issue certificate: %w", err)
		}
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
