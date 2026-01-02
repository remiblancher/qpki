package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/remiblancher/post-quantum-pki/internal/crypto"
	"github.com/remiblancher/post-quantum-pki/internal/x509util"
)

var csrCmd = &cobra.Command{
	Use:   "csr",
	Short: "Generate a Certificate Signing Request",
	Long: `Generate a Certificate Signing Request (CSR) for submission to a CA.

The CSR can be created in multiple modes:

Mode 1: Classical algorithms (using existing key)
  pki csr --key key.pem --cn example.com -o request.csr

Mode 2: Classical algorithms (generate new key)
  pki csr --algorithm ecdsa-p256 --keyout key.pem --cn example.com -o request.csr

Mode 3: PQC signature algorithms (ML-DSA, SLH-DSA)
  pki csr --algorithm ml-dsa-65 --keyout mldsa.key --cn example.com -o request.csr

Mode 4: PQC KEM algorithms (ML-KEM) with RFC 9883 attestation
  pki csr --algorithm ml-kem-768 --keyout kem.key --cn example.com \
      --attest-cert sign.crt --attest-key sign.key -o request.csr

Mode 5: Hybrid CSR (classical + PQC dual signatures)
  pki csr --algorithm ecdsa-p256 --keyout classical.key \
      --hybrid ml-dsa-65 --hybrid-keyout pqc.key --cn example.com -o request.csr

The --key and --algorithm/--keyout flags are mutually exclusive.

Supported algorithms:
  Classical:
    ecdsa-p256, ecdsa-p384, ecdsa-p521, ed25519
    rsa-2048, rsa-3072, rsa-4096
  PQC Signature (direct signing):
    ml-dsa-44, ml-dsa-65, ml-dsa-87
    slh-dsa-128f, slh-dsa-128s, slh-dsa-192f, slh-dsa-192s, slh-dsa-256f, slh-dsa-256s
  PQC KEM (requires --attest-cert/--attest-key):
    ml-kem-512, ml-kem-768, ml-kem-1024

Examples:
  # Classical ECDSA CSR
  pki csr --algorithm ecdsa-p256 --keyout server.key --cn server.example.com -o server.csr

  # PQC ML-DSA CSR (direct signature)
  pki csr --algorithm ml-dsa-65 --keyout mldsa.key --cn alice@example.com -o mldsa.csr

  # PQC ML-KEM CSR with RFC 9883 attestation
  pki csr --algorithm ml-kem-768 --keyout kem.key --cn alice@example.com \
      --attest-cert sign.crt --attest-key sign.key -o kem.csr

  # Hybrid CSR (ECDSA + ML-DSA)
  pki csr --algorithm ecdsa-p256 --keyout classical.key \
      --hybrid ml-dsa-65 --hybrid-keyout pqc.key --cn example.com -o hybrid.csr`,
	RunE: runCSR,
}

var (
	// Key source flags (mutually exclusive modes)
	csrKey        string
	csrPassphrase string
	csrAlgorithm  string
	csrKeyOut     string
	csrKeyPass    string

	// Output
	csrOutput string

	// Subject fields
	csrCN      string
	csrOrg     string
	csrCountry string

	// SANs
	csrDNS   []string
	csrEmail []string
	csrIP    []string

	// RFC 9883 attestation flags (for ML-KEM)
	csrAttestCert string
	csrAttestKey  string
	csrAttestPass string
	csrIncludeCert bool

	// Hybrid CSR flags
	csrHybridAlg    string
	csrHybridKeyOut string
	csrHybridKeyPass string
)

func init() {
	flags := csrCmd.Flags()

	// Key source flags
	flags.StringVar(&csrKey, "key", "", "Existing private key file (PEM)")
	flags.StringVar(&csrPassphrase, "passphrase", "", "Passphrase for existing key")
	flags.StringVarP(&csrAlgorithm, "algorithm", "a", "", "Algorithm for new key (e.g., ecdsa-p256, ml-dsa-65)")
	flags.StringVar(&csrKeyOut, "keyout", "", "Output file for new private key")
	flags.StringVar(&csrKeyPass, "key-passphrase", "", "Passphrase for new private key")

	// Output
	flags.StringVarP(&csrOutput, "out", "o", "", "Output CSR file (required)")
	_ = csrCmd.MarkFlagRequired("out")

	// Subject fields
	flags.StringVar(&csrCN, "cn", "", "Common Name (required)")
	_ = csrCmd.MarkFlagRequired("cn")
	flags.StringVarP(&csrOrg, "org", "O", "", "Organization")
	flags.StringVarP(&csrCountry, "country", "C", "", "Country (2-letter code)")

	// SANs
	flags.StringSliceVar(&csrDNS, "dns", nil, "DNS Subject Alternative Names")
	flags.StringSliceVar(&csrEmail, "email", nil, "Email Subject Alternative Names")
	flags.StringSliceVar(&csrIP, "ip", nil, "IP Subject Alternative Names")

	// RFC 9883 attestation flags (for ML-KEM CSRs)
	flags.StringVar(&csrAttestCert, "attest-cert", "", "Attestation certificate for ML-KEM (RFC 9883)")
	flags.StringVar(&csrAttestKey, "attest-key", "", "Attestation private key for ML-KEM (RFC 9883)")
	flags.StringVar(&csrAttestPass, "attest-passphrase", "", "Passphrase for attestation key")
	flags.BoolVar(&csrIncludeCert, "include-cert", false, "Include attestation cert in CSR (RFC 9883)")

	// Hybrid CSR flags
	flags.StringVar(&csrHybridAlg, "hybrid", "", "PQC algorithm for hybrid CSR (e.g., ml-dsa-65)")
	flags.StringVar(&csrHybridKeyOut, "hybrid-keyout", "", "Output file for hybrid PQC private key")
	flags.StringVar(&csrHybridKeyPass, "hybrid-passphrase", "", "Passphrase for hybrid PQC private key")
}

func runCSR(cmd *cobra.Command, args []string) error {
	// Validate mutually exclusive modes
	hasKey := csrKey != ""
	hasGen := csrAlgorithm != "" || csrKeyOut != ""
	hasAttest := csrAttestCert != "" || csrAttestKey != ""
	hasHybrid := csrHybridAlg != ""

	if hasKey && hasGen {
		return fmt.Errorf("--key and --algorithm/--keyout are mutually exclusive")
	}

	if !hasKey && !hasGen {
		return fmt.Errorf("must specify either --key (existing key) or --algorithm --keyout (generate new key)")
	}

	// Validate generate mode requires both flags
	if hasGen {
		if csrAlgorithm == "" {
			return fmt.Errorf("--algorithm is required when generating a new key")
		}
		if csrKeyOut == "" {
			return fmt.Errorf("--keyout is required when generating a new key")
		}
	}

	// Validate attestation mode
	if hasAttest {
		if csrAttestCert == "" || csrAttestKey == "" {
			return fmt.Errorf("--attest-cert and --attest-key must both be specified")
		}
	}

	// Validate hybrid mode
	if hasHybrid && csrHybridKeyOut == "" {
		return fmt.Errorf("--hybrid-keyout is required when using --hybrid")
	}

	// Build subject
	subject := pkix.Name{
		CommonName: csrCN,
	}
	if csrOrg != "" {
		subject.Organization = []string{csrOrg}
	}
	if csrCountry != "" {
		subject.Country = []string{csrCountry}
	}

	// Determine mode and create CSR
	var csrDER []byte
	var algDescription string

	if hasGen {
		alg, err := crypto.ParseAlgorithm(csrAlgorithm)
		if err != nil {
			return fmt.Errorf("invalid algorithm: %w", err)
		}
		algDescription = alg.Description()

		// Route based on algorithm type
		if alg.IsKEM() {
			// Mode 4: ML-KEM with RFC 9883 attestation
			csrDER, err = createKEMCSR(alg, subject)
			if err != nil {
				return err
			}
		} else if alg.IsPQC() && hasHybrid {
			// Invalid: can't have PQC primary + hybrid
			return fmt.Errorf("--hybrid is only valid with classical algorithms")
		} else if hasHybrid {
			// Mode 5: Hybrid CSR (classical + PQC)
			csrDER, err = createHybridCSR(alg, subject)
			if err != nil {
				return err
			}
		} else if alg.IsPQC() {
			// Mode 3: PQC signature (ML-DSA, SLH-DSA)
			csrDER, err = createPQCSignatureCSR(alg, subject)
			if err != nil {
				return err
			}
		} else {
			// Mode 2: Classical with new key
			csrDER, err = createClassicalCSR(alg, subject)
			if err != nil {
				return err
			}
		}
	} else {
		// Mode 1: Existing key
		csrDER, algDescription = createCSRWithExistingKey(subject)
		if csrDER == nil {
			loadedSigner, err := crypto.LoadPrivateKey(csrKey, []byte(csrPassphrase))
			if err != nil {
				return fmt.Errorf("failed to load private key: %w", err)
			}

			// Check if we need hybrid mode
			if hasHybrid {
				csrDER, err = createHybridCSRWithExistingKey(loadedSigner, subject)
				if err != nil {
					return err
				}
				algDescription = fmt.Sprintf("Hybrid (%s + %s)", loadedSigner.Algorithm().Description(), csrHybridAlg)
			} else {
				csr, err := x509util.CreateSimpleCSR(x509util.SimpleCSRRequest{
					Subject:        subject,
					DNSNames:       csrDNS,
					EmailAddresses: csrEmail,
					Signer:         loadedSigner,
				})
				if err != nil {
					return fmt.Errorf("failed to create CSR: %w", err)
				}
				csrDER = csr.Raw
				algDescription = loadedSigner.Algorithm().Description()
			}
		}
	}

	// Encode to PEM
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	}

	pemData := pem.EncodeToMemory(pemBlock)
	if err := os.WriteFile(csrOutput, pemData, 0644); err != nil {
		return fmt.Errorf("failed to write CSR: %w", err)
	}

	// Display result
	fmt.Printf("CSR generated successfully!\n")
	fmt.Printf("  Subject:   %s\n", subject.String())
	fmt.Printf("  Algorithm: %s\n", algDescription)
	if len(csrDNS) > 0 {
		fmt.Printf("  DNS SANs:  %v\n", csrDNS)
	}
	if len(csrEmail) > 0 {
		fmt.Printf("  Email SANs: %v\n", csrEmail)
	}
	if len(csrIP) > 0 {
		fmt.Printf("  IP SANs:   %v\n", csrIP)
	}
	fmt.Printf("  Output:    %s\n", csrOutput)

	return nil
}

// createClassicalCSR creates a CSR using Go's standard x509 library.
func createClassicalCSR(alg crypto.AlgorithmID, subject pkix.Name) ([]byte, error) {
	fmt.Printf("Generating %s key pair...\n", alg.Description())

	// Use KeyManager to generate the key
	keyCfg := crypto.KeyStorageConfig{
		Type:       crypto.KeyManagerTypeSoftware,
		KeyPath:    csrKeyOut,
		Passphrase: csrKeyPass,
	}
	km := crypto.NewKeyManager(keyCfg)
	newSigner, err := km.Generate(alg, keyCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}
	fmt.Printf("Private key saved to: %s\n", csrKeyOut)

	csr, err := x509util.CreateSimpleCSR(x509util.SimpleCSRRequest{
		Subject:        subject,
		DNSNames:       csrDNS,
		EmailAddresses: csrEmail,
		Signer:         newSigner,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create CSR: %w", err)
	}

	return csr.Raw, nil
}

// createPQCSignatureCSR creates a CSR signed with ML-DSA or SLH-DSA.
func createPQCSignatureCSR(alg crypto.AlgorithmID, subject pkix.Name) ([]byte, error) {
	fmt.Printf("Generating %s key pair...\n", alg.Description())

	// Use KeyManager to generate the key
	keyCfg := crypto.KeyStorageConfig{
		Type:       crypto.KeyManagerTypeSoftware,
		KeyPath:    csrKeyOut,
		Passphrase: csrKeyPass,
	}
	km := crypto.NewKeyManager(keyCfg)
	newSigner, err := km.Generate(alg, keyCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}
	fmt.Printf("Private key saved to: %s\n", csrKeyOut)

	csrDER, err := x509util.CreatePQCSignatureCSR(x509util.PQCCSRRequest{
		Subject:        subject,
		DNSNames:       csrDNS,
		EmailAddresses: csrEmail,
		IPAddresses:    csrIP,
		Signer:         newSigner,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create PQC CSR: %w", err)
	}

	return csrDER, nil
}

// createKEMCSR creates a CSR for ML-KEM with RFC 9883 attestation.
func createKEMCSR(alg crypto.AlgorithmID, subject pkix.Name) ([]byte, error) {
	if csrAttestCert == "" || csrAttestKey == "" {
		return nil, fmt.Errorf("ML-KEM requires --attest-cert and --attest-key for RFC 9883 attestation\n" +
			"Use a signature certificate to attest possession of the KEM key")
	}

	fmt.Printf("Generating %s key pair...\n", alg.Description())

	// Generate KEM key pair
	kemKP, err := crypto.GenerateKEMKeyPair(alg)
	if err != nil {
		return nil, fmt.Errorf("failed to generate KEM key pair: %w", err)
	}

	// Save KEM private key
	passphrase := []byte(csrKeyPass)
	if err := kemKP.SavePrivateKey(csrKeyOut, passphrase); err != nil {
		return nil, fmt.Errorf("failed to save KEM private key: %w", err)
	}
	fmt.Printf("KEM private key saved to: %s\n", csrKeyOut)

	// Load attestation certificate
	attestCertPEM, err := os.ReadFile(csrAttestCert)
	if err != nil {
		return nil, fmt.Errorf("failed to read attestation certificate: %w", err)
	}
	block, _ := pem.Decode(attestCertPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid attestation certificate PEM")
	}
	attestCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse attestation certificate: %w", err)
	}

	// Load attestation signer using KeyManager
	attestKeyCfg := crypto.KeyStorageConfig{
		Type:       crypto.KeyManagerTypeSoftware,
		KeyPath:    csrAttestKey,
		Passphrase: csrAttestPass,
	}
	attestKM := crypto.NewKeyManager(attestKeyCfg)
	attestSigner, err := attestKM.Load(attestKeyCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to load attestation key: %w", err)
	}

	fmt.Printf("Using attestation certificate: %s\n", attestCert.Subject.String())

	csrDER, err := x509util.CreateKEMCSRWithAttestation(x509util.KEMCSRRequest{
		Subject:        subject,
		DNSNames:       csrDNS,
		EmailAddresses: csrEmail,
		IPAddresses:    csrIP,
		KEMPublicKey:   kemKP.PublicKey,
		KEMAlgorithm:   alg,
		AttestCert:     attestCert,
		AttestSigner:   attestSigner,
		IncludeCert:    csrIncludeCert,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create KEM CSR: %w", err)
	}

	return csrDER, nil
}

// createHybridCSR creates a hybrid CSR with classical + PQC signatures.
func createHybridCSR(classicalAlg crypto.AlgorithmID, subject pkix.Name) ([]byte, error) {
	pqcAlg, err := crypto.ParseAlgorithm(csrHybridAlg)
	if err != nil {
		return nil, fmt.Errorf("invalid hybrid algorithm: %w", err)
	}

	if !pqcAlg.IsPQC() || !pqcAlg.IsSignature() {
		return nil, fmt.Errorf("--hybrid requires a PQC signature algorithm (ml-dsa-*, slh-dsa-*)")
	}

	fmt.Printf("Generating hybrid key pairs: %s + %s...\n", classicalAlg.Description(), pqcAlg.Description())

	// Generate classical key using KeyManager
	classicalKeyCfg := crypto.KeyStorageConfig{
		Type:       crypto.KeyManagerTypeSoftware,
		KeyPath:    csrKeyOut,
		Passphrase: csrKeyPass,
	}
	classicalKM := crypto.NewKeyManager(classicalKeyCfg)
	classicalSigner, err := classicalKM.Generate(classicalAlg, classicalKeyCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to generate classical key pair: %w", err)
	}
	fmt.Printf("Classical private key saved to: %s\n", csrKeyOut)

	// Generate PQC key using KeyManager
	pqcKeyCfg := crypto.KeyStorageConfig{
		Type:       crypto.KeyManagerTypeSoftware,
		KeyPath:    csrHybridKeyOut,
		Passphrase: csrHybridKeyPass,
	}
	pqcKM := crypto.NewKeyManager(pqcKeyCfg)
	pqcSigner, err := pqcKM.Generate(pqcAlg, pqcKeyCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to generate PQC key pair: %w", err)
	}
	fmt.Printf("PQC private key saved to: %s\n", csrHybridKeyOut)

	// Create hybrid CSR
	hybridCSR, err := x509util.CreateHybridCSR(x509util.HybridCSRRequest{
		Subject:         subject,
		DNSNames:        csrDNS,
		EmailAddresses:  csrEmail,
		ClassicalSigner: classicalSigner,
		PQCSigner:       pqcSigner,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create hybrid CSR: %w", err)
	}

	return hybridCSR.DER(), nil
}

// createHybridCSRWithExistingKey creates a hybrid CSR using an existing classical key.
func createHybridCSRWithExistingKey(classicalSigner crypto.Signer, subject pkix.Name) ([]byte, error) {
	pqcAlg, err := crypto.ParseAlgorithm(csrHybridAlg)
	if err != nil {
		return nil, fmt.Errorf("invalid hybrid algorithm: %w", err)
	}

	if !pqcAlg.IsPQC() || !pqcAlg.IsSignature() {
		return nil, fmt.Errorf("--hybrid requires a PQC signature algorithm (ml-dsa-*, slh-dsa-*)")
	}

	fmt.Printf("Using existing classical key + generating %s...\n", pqcAlg.Description())

	// Generate PQC key using KeyManager
	pqcKeyCfg := crypto.KeyStorageConfig{
		Type:       crypto.KeyManagerTypeSoftware,
		KeyPath:    csrHybridKeyOut,
		Passphrase: csrHybridKeyPass,
	}
	pqcKM := crypto.NewKeyManager(pqcKeyCfg)
	pqcSigner, err := pqcKM.Generate(pqcAlg, pqcKeyCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to generate PQC key pair: %w", err)
	}
	fmt.Printf("PQC private key saved to: %s\n", csrHybridKeyOut)

	// Create hybrid CSR
	hybridCSR, err := x509util.CreateHybridCSR(x509util.HybridCSRRequest{
		Subject:         subject,
		DNSNames:        csrDNS,
		EmailAddresses:  csrEmail,
		ClassicalSigner: classicalSigner,
		PQCSigner:       pqcSigner,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create hybrid CSR: %w", err)
	}

	return hybridCSR.DER(), nil
}

// createCSRWithExistingKey is a placeholder that returns nil to indicate
// the caller should handle existing key mode.
func createCSRWithExistingKey(subject pkix.Name) ([]byte, string) {
	return nil, ""
}
