package main

import (
	gocrypto "crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/remiblancher/post-quantum-pki/internal/ca"
	"github.com/remiblancher/post-quantum-pki/internal/crypto"
	"github.com/remiblancher/post-quantum-pki/internal/profile"
	"github.com/remiblancher/post-quantum-pki/internal/x509util"
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
	issueCommonName   string
	issueDNSNames     []string
	issueIPAddrs      []string
	issueCSRFile      string
	issuePubKeyFile   string
	issueKeyFile      string
	issueCertOut      string
	issueValidityDays int
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
	flags.StringVar(&issueCommonName, "cn", "", "Subject common name")
	flags.StringSliceVar(&issueDNSNames, "dns", nil, "DNS Subject Alternative Names")
	flags.StringSliceVar(&issueIPAddrs, "ip", nil, "IP Subject Alternative Names")
	flags.StringVar(&issueCSRFile, "csr", "", "Certificate Signing Request file (required)")
	_ = issueCmd.MarkFlagRequired("csr")
	flags.StringVar(&issuePubKeyFile, "pubkey", "", "Public key file (alternative to CSR)")
	flags.StringVar(&issueKeyFile, "key", "", "Existing private key file (alternative to CSR)")
	flags.StringVarP(&issueCertOut, "out", "o", "", "Output certificate file")
	flags.IntVar(&issueValidityDays, "days", 0, "Validity period in days (overrides profile default)")
	flags.StringArrayVar(&issueVars, "var", nil, "Variable value (key=value, repeatable)")
	flags.StringVar(&issueVarFile, "var-file", "", "YAML file with variable values")
	flags.StringVar(&issueCAPassphrase, "ca-passphrase", "", "CA private key passphrase (or env:VAR_NAME)")
	flags.StringVar(&issueHybridAlg, "hybrid", "", "PQC algorithm for hybrid extension")
	flags.StringVar(&issueAttestCert, "attest-cert", "", "Attestation certificate for ML-KEM CSR verification (RFC 9883)")
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
	if prof.IsCatalyst() {
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

	// Parse CSR (required)
	var subjectPubKey interface{}
	var template *x509.Certificate

	csrData, err := os.ReadFile(issueCSRFile)
	if err != nil {
		return fmt.Errorf("failed to read CSR file: %w", err)
	}

	block, _ := pem.Decode(csrData)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return fmt.Errorf("invalid CSR file")
	}

	// Try standard Go x509 parsing first (classical algorithms)
	csr, classicalErr := x509.ParseCertificateRequest(block.Bytes)
	if classicalErr == nil {
		// Parsing OK - now check signature algorithm
		if csr.SignatureAlgorithm == x509.UnknownSignatureAlgorithm {
			// Unknown algorithm (likely PQC) - use custom verification
			pqcInfo, pqcErr := x509util.ParsePQCCSR(block.Bytes)
			if pqcErr != nil {
				return fmt.Errorf("failed to parse PQC CSR: %w", pqcErr)
			}

			// Verify PQC CSR signature
			// For ML-KEM CSRs, need attestation certificate
			var attestPubKey gocrypto.PublicKey
			if pqcInfo.HasPossessionStatement() {
				// ML-KEM CSR - need attestation cert for verification
				if issueAttestCert == "" {
					return fmt.Errorf("ML-KEM CSR with RFC 9883 attestation requires --attest-cert for verification")
				}
				attestCert, err := loadCertificate(issueAttestCert)
				if err != nil {
					return fmt.Errorf("failed to load attestation cert: %w", err)
				}
				// Validate RFC 9883 statement
				if err := x509util.ValidateRFC9883Statement(pqcInfo, attestCert); err != nil {
					return fmt.Errorf("RFC 9883 validation failed: %w", err)
				}
				// Extract public key - Go's x509.ParseCertificate returns nil for PQC certs
				attestPubKey, err = extractPQCPublicKeyFromCert(attestCert)
				if err != nil {
					return fmt.Errorf("failed to extract attestation public key: %w", err)
				}
			}

			if err := x509util.VerifyPQCCSRSignature(pqcInfo, attestPubKey); err != nil {
				return fmt.Errorf("invalid PQC CSR signature: %w", err)
			}

			// Use values from Go's parsed CSR (which are correct for subject/SANs)
			subjectPubKey = csr.PublicKey
			template = &x509.Certificate{
				Subject:     csr.Subject,
				DNSNames:    csr.DNSNames,
				IPAddresses: csr.IPAddresses,
			}

			// If Go couldn't parse the public key (PQC), get it from PQC parser
			if subjectPubKey == nil {
				pubKeyAlg := crypto.AlgorithmFromOID(pqcInfo.PublicKeyAlgorithm)
				if pubKeyAlg == crypto.AlgUnknown {
					return fmt.Errorf("unknown public key algorithm OID: %v", pqcInfo.PublicKeyAlgorithm)
				}
				parsedPubKey, err := crypto.ParsePublicKey(pubKeyAlg, pqcInfo.PublicKeyBytes)
				if err != nil {
					return fmt.Errorf("failed to parse PQC public key: %w", err)
				}
				subjectPubKey = parsedPubKey
			}
		} else {
			// Classical algorithm - verify with Go's native verification
			if err := csr.CheckSignature(); err != nil {
				return fmt.Errorf("invalid CSR signature: %w", err)
			}
			subjectPubKey = csr.PublicKey
			template = &x509.Certificate{
				Subject:     csr.Subject,
				DNSNames:    csr.DNSNames,
				IPAddresses: csr.IPAddresses,
			}
		}
	} else {
		// Fallback to PQC CSR parsing (ML-DSA, SLH-DSA, ML-KEM)
		pqcInfo, pqcErr := x509util.ParsePQCCSR(block.Bytes)
		if pqcErr != nil {
			return fmt.Errorf("failed to parse CSR (classical: %v, PQC: %v)", classicalErr, pqcErr)
		}

		// Verify PQC CSR signature
		var attestPubKey gocrypto.PublicKey
		if pqcInfo.HasPossessionStatement() {
			// ML-KEM CSR - need attestation cert for verification
			if issueAttestCert == "" {
				return fmt.Errorf("ML-KEM CSR with RFC 9883 attestation requires --attest-cert for verification")
			}
			attestCert, err := loadCertificate(issueAttestCert)
			if err != nil {
				return fmt.Errorf("failed to load attestation cert: %w", err)
			}
			// Validate RFC 9883 statement
			if err := x509util.ValidateRFC9883Statement(pqcInfo, attestCert); err != nil {
				return fmt.Errorf("RFC 9883 validation failed: %w", err)
			}
			// Extract public key - Go's x509.ParseCertificate returns nil for PQC certs
			attestPubKey, err = extractPQCPublicKeyFromCert(attestCert)
			if err != nil {
				return fmt.Errorf("failed to extract attestation public key: %w", err)
			}
		}

		if err := x509util.VerifyPQCCSRSignature(pqcInfo, attestPubKey); err != nil {
			return fmt.Errorf("invalid PQC CSR signature: %w", err)
		}

		// Reconstruct public key from CSR
		pubKeyAlg := crypto.AlgorithmFromOID(pqcInfo.PublicKeyAlgorithm)
		if pubKeyAlg == crypto.AlgUnknown {
			return fmt.Errorf("unknown public key algorithm OID: %v", pqcInfo.PublicKeyAlgorithm)
		}
		parsedPubKey, err := crypto.ParsePublicKey(pubKeyAlg, pqcInfo.PublicKeyBytes)
		if err != nil {
			return fmt.Errorf("failed to parse public key from CSR: %w", err)
		}
		subjectPubKey = parsedPubKey

		// Build template from PQC CSR info
		template = &x509.Certificate{
			Subject: pkix.Name{
				CommonName:         pqcInfo.Subject.CommonName,
				Organization:       pqcInfo.Subject.Organization,
				OrganizationalUnit: pqcInfo.Subject.OrganizationalUnit,
				Country:            pqcInfo.Subject.Country,
				Province:           pqcInfo.Subject.Province,
				Locality:           pqcInfo.Subject.Locality,
			},
			DNSNames:    pqcInfo.DNSNames,
			IPAddresses: parseIPStrings(pqcInfo.IPAddresses),
		}
	}

	// Apply command-line overrides
	if issueCommonName != "" {
		template.Subject.CommonName = issueCommonName
	}
	// Note: DNSNames and IPAddresses are handled via profile variable substitution
	// If the profile uses {{ dns_names }}/{{ ip_addresses }} variables, they will be substituted below.
	// If no profile SubjectAltName is defined, the values from CSR are used.

	// Load variables from file and/or flags
	varValues, err := profile.LoadVariables(issueVarFile, issueVars)
	if err != nil {
		return fmt.Errorf("failed to load variables: %w", err)
	}

	// Merge legacy CLI flags into variables (backward compatibility)
	// --var takes precedence over legacy flags
	if _, exists := varValues["cn"]; !exists && issueCommonName != "" {
		varValues["cn"] = issueCommonName
	}
	if _, exists := varValues["dns_names"]; !exists && len(issueDNSNames) > 0 {
		varValues["dns_names"] = issueDNSNames
	}
	if _, exists := varValues["ip_addresses"]; !exists && len(issueIPAddrs) > 0 {
		varValues["ip_addresses"] = issueIPAddrs
	}

	// Merge CSR values into variables (if not already set)
	// This allows profiles to use {{ cn }} even when issuing from CSR
	if _, exists := varValues["cn"]; !exists && template.Subject.CommonName != "" {
		varValues["cn"] = template.Subject.CommonName
	}
	if _, exists := varValues["dns_names"]; !exists && len(template.DNSNames) > 0 {
		varValues["dns_names"] = template.DNSNames
	}
	if _, exists := varValues["ip_addresses"]; !exists && len(template.IPAddresses) > 0 {
		ipStrings := make([]string, len(template.IPAddresses))
		for i, ip := range template.IPAddresses {
			ipStrings[i] = ip.String()
		}
		varValues["ip_addresses"] = ipStrings
	}

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

	// Extract SAN variables for extension substitution
	varsForSubstitution := profile.ExtractSANVariables(varValues)

	// Substitute variables in profile extensions
	resolvedExtensions, err := prof.Extensions.SubstituteVariables(varsForSubstitution)
	if err != nil {
		return fmt.Errorf("failed to substitute variables: %w", err)
	}

	// Issue certificate based on profile mode
	var cert *x509.Certificate

	if prof.IsCatalyst() {
		// Catalyst mode: issue certificate with dual signatures
		// Need both classical and PQC keys for the subject

		// Get PQC algorithm from profile
		pqcAlg := prof.GetAlternativeAlgorithm()

		// For Catalyst, we need to generate both key types
		// The subjectPubKey from above is the classical key (or from CSR)
		var classicalPubKey interface{}
		var pqcPubKey interface{}

		// CSR provides classical key, generate PQC key
		classicalPubKey = subjectPubKey

		pqcKP, err := crypto.GenerateKeyPair(pqcAlg)
		if err != nil {
			return fmt.Errorf("failed to generate PQC key for Catalyst: %w", err)
		}
		pqcPubKey = pqcKP.PublicKey

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

	// Show store path
	fmt.Printf("  Stored at:   %s\n", store.CertPath(cert.SerialNumber.Bytes()))

	return nil
}

// parseIPStrings parses a slice of IP address strings into net.IP values.
func parseIPStrings(ipStrs []string) []net.IP {
	var ips []net.IP
	for _, s := range ipStrs {
		if ip := net.ParseIP(s); ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips
}

// spkiForPQC is used to parse SubjectPublicKeyInfo from PQC certificates.
type spkiForPQC struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// extractPQCPublicKeyFromCert extracts the public key from a certificate.
// Go's x509.ParseCertificate returns nil for PublicKey when the algorithm is unknown (PQC).
// This function parses the raw SubjectPublicKeyInfo to extract the PQC public key.
func extractPQCPublicKeyFromCert(cert *x509.Certificate) (gocrypto.PublicKey, error) {
	if cert == nil {
		return nil, fmt.Errorf("certificate is nil")
	}

	// If Go's parser already extracted the public key, use it
	if cert.PublicKey != nil {
		return cert.PublicKey, nil
	}

	// Parse the raw SubjectPublicKeyInfo
	var spki spkiForPQC
	_, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &spki)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SubjectPublicKeyInfo: %w", err)
	}

	// Get the algorithm from the OID
	alg := crypto.AlgorithmFromOID(spki.Algorithm.Algorithm)
	if alg == crypto.AlgUnknown {
		return nil, fmt.Errorf("unknown public key algorithm OID: %v", spki.Algorithm.Algorithm)
	}

	// Parse the public key bytes
	pubKey, err := crypto.ParsePublicKey(alg, spki.PublicKey.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return pubKey, nil
}
