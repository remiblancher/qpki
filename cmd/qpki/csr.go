package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/remiblancher/post-quantum-pki/internal/crypto"
	"github.com/remiblancher/post-quantum-pki/internal/x509util"
)

// csrRootCmd is the parent command for CSR operations.
var csrRootCmd = &cobra.Command{
	Use:   "csr",
	Short: "Certificate Signing Request operations",
	Long: `Manage Certificate Signing Requests (CSRs).

Commands:
  gen     Generate a new CSR
  info    Display CSR information
  verify  Verify CSR signature

Examples:
  # Generate a CSR
  qpki csr gen --algorithm ecdsa-p256 --keyout key.pem --cn example.com --out req.csr

  # Display CSR information
  qpki csr info ./request.csr

  # Verify CSR signature
  qpki csr verify ./request.csr`,
}

var csrGenCmd = &cobra.Command{
	Use:   "gen",
	Short: "Generate a Certificate Signing Request",
	Long: `Generate a Certificate Signing Request (CSR) for submission to a CA.

The CSR can be created in multiple modes:

Mode 1: Classical algorithms (using existing key)
  qpki csr gen --key key.pem --cn example.com --out request.csr

Mode 2: Classical algorithms (generate new key)
  qpki csr gen --algorithm ecdsa-p256 --keyout key.pem --cn example.com --out request.csr

Mode 3: PQC signature algorithms (ML-DSA, SLH-DSA)
  qpki csr gen --algorithm ml-dsa-65 --keyout mldsa.key --cn example.com --out request.csr

Mode 4: PQC KEM algorithms (ML-KEM) with RFC 9883 attestation
  qpki csr gen --algorithm ml-kem-768 --keyout kem.key --cn example.com \
      --attest-cert sign.crt --attest-key sign.key --out request.csr

Mode 5: Catalyst Hybrid CSR (ITU-T X.509 dual signatures)
  qpki csr gen --algorithm ecdsa-p384 --hybrid ml-dsa-87 --keyout classical.key \
      --hybrid-keyout pqc.key --cn example.com --out request.csr

Mode 6: Composite CSR (IETF draft-13 combined signature)
  qpki csr gen --algorithm ecdsa-p384 --composite ml-dsa-87 --keyout classical.key \
      --hybrid-keyout pqc.key --cn example.com --out request.csr

Mode 7: HSM key generation
  qpki csr gen --algorithm ecdsa-p384 --hsm-config hsm.yaml --key-label mykey \
      --cn example.com --out request.csr

Supported algorithms:
  Classical:
    ecdsa-p256, ecdsa-p384, ecdsa-p521, ed25519, ed448
    rsa-2048, rsa-3072, rsa-4096
  PQC Signature (direct signing):
    ml-dsa-44, ml-dsa-65, ml-dsa-87
    slh-dsa-128f, slh-dsa-128s, slh-dsa-192f, slh-dsa-192s, slh-dsa-256f, slh-dsa-256s
  PQC KEM (requires --attest-cert/--attest-key):
    ml-kem-512, ml-kem-768, ml-kem-1024

Catalyst combinations (--algorithm + --hybrid):
  ecdsa-p256 + ml-dsa-44/ml-dsa-65
  ecdsa-p384 + ml-dsa-65/ml-dsa-87
  ecdsa-p521 + ml-dsa-87
  ed25519 + ml-dsa-44/ml-dsa-65
  ed448 + ml-dsa-87

Composite combinations (--algorithm + --composite):
  ecdsa-p256 + ml-dsa-44/ml-dsa-65
  ecdsa-p384 + ml-dsa-87`,
	RunE: runCSRGen,
}

var csrInfoCmd = &cobra.Command{
	Use:   "info <csr-file>",
	Short: "Display CSR information",
	Long: `Display detailed information about a Certificate Signing Request.

Shows subject, public key algorithm, signature algorithm, and requested extensions.

Examples:
  qpki csr info ./request.csr`,
	Args: cobra.ExactArgs(1),
	RunE: runCSRInfo,
}

var csrVerifyCmd = &cobra.Command{
	Use:   "verify <csr-file>",
	Short: "Verify CSR signature",
	Long: `Verify the signature of a Certificate Signing Request.

This proves that the requester possesses the private key corresponding
to the public key in the CSR.

Examples:
  qpki csr verify ./request.csr`,
	Args: cobra.ExactArgs(1),
	RunE: runCSRVerify,
}

// Flags for csr gen
var (
	// Key source flags (mutually exclusive modes)
	csrGenKey        string
	csrGenPassphrase string
	csrGenAlgorithm  string
	csrGenKeyOut     string
	csrGenKeyPass    string

	// HSM flags
	csrGenHSMConfig string
	csrGenKeyLabel  string
	csrGenKeyID     string

	// Output
	csrGenOutput string

	// Subject fields
	csrGenCN      string
	csrGenOrg     string
	csrGenCountry string

	// SANs
	csrGenDNS   []string
	csrGenEmail []string
	csrGenIP    []string

	// RFC 9883 attestation flags (for ML-KEM)
	csrGenAttestCert     string
	csrGenAttestKey      string
	csrGenAttestPass     string
	csrGenAttestKeyLabel string // HSM attestation key label (reuses --hsm-config)
	csrGenIncludeCert    bool

	// Hybrid CSR flags
	csrGenHybridAlg     string
	csrGenHybridKeyOut  string
	csrGenHybridKeyPass string

	// Composite CSR flag (IETF draft-13)
	csrGenComposite string
)

func init() {
	// Add subcommands
	csrRootCmd.AddCommand(csrGenCmd)
	csrRootCmd.AddCommand(csrInfoCmd)
	csrRootCmd.AddCommand(csrVerifyCmd)

	// csr gen flags
	flags := csrGenCmd.Flags()

	// Key source flags
	flags.StringVar(&csrGenKey, "key", "", "Existing private key file (PEM)")
	flags.StringVar(&csrGenPassphrase, "passphrase", "", "Passphrase for existing key")
	flags.StringVarP(&csrGenAlgorithm, "algorithm", "a", "", "Algorithm for new key (e.g., ecdsa-p256, ml-dsa-65)")
	flags.StringVar(&csrGenKeyOut, "keyout", "", "Output file for new private key (software mode)")
	flags.StringVar(&csrGenKeyPass, "key-passphrase", "", "Passphrase for new private key")

	// HSM flags
	flags.StringVar(&csrGenHSMConfig, "hsm-config", "", "HSM configuration file (YAML)")
	flags.StringVar(&csrGenKeyLabel, "key-label", "", "Key label in HSM")
	flags.StringVar(&csrGenKeyID, "key-id", "", "Key ID in HSM (hex)")

	// Output
	flags.StringVarP(&csrGenOutput, "out", "o", "", "Output CSR file (required)")
	_ = csrGenCmd.MarkFlagRequired("out")

	// Subject fields
	flags.StringVar(&csrGenCN, "cn", "", "Common Name (required)")
	_ = csrGenCmd.MarkFlagRequired("cn")
	flags.StringVarP(&csrGenOrg, "org", "O", "", "Organization")
	flags.StringVarP(&csrGenCountry, "country", "C", "", "Country (2-letter code)")

	// SANs
	flags.StringSliceVar(&csrGenDNS, "dns", nil, "DNS Subject Alternative Names")
	flags.StringSliceVar(&csrGenEmail, "email", nil, "Email Subject Alternative Names")
	flags.StringSliceVar(&csrGenIP, "ip", nil, "IP Subject Alternative Names")

	// RFC 9883 attestation flags (for ML-KEM CSRs)
	flags.StringVar(&csrGenAttestCert, "attest-cert", "", "Attestation certificate for ML-KEM (RFC 9883)")
	flags.StringVar(&csrGenAttestKey, "attest-key", "", "Attestation private key for ML-KEM (RFC 9883)")
	flags.StringVar(&csrGenAttestPass, "attest-passphrase", "", "Passphrase for attestation key")
	flags.StringVar(&csrGenAttestKeyLabel, "attest-key-label", "", "Attestation key label in HSM (uses --hsm-config)")
	flags.BoolVar(&csrGenIncludeCert, "include-cert", false, "Include attestation cert in CSR (RFC 9883)")

	// Hybrid CSR flags (Catalyst mode: --algorithm + --hybrid)
	flags.StringVar(&csrGenHybridAlg, "hybrid", "", "PQC algorithm for hybrid/Catalyst CSR (e.g., ml-dsa-65)")
	flags.StringVar(&csrGenHybridKeyOut, "hybrid-keyout", "", "Output file for hybrid PQC private key")
	flags.StringVar(&csrGenHybridKeyPass, "hybrid-passphrase", "", "Passphrase for hybrid PQC private key")

	// Composite CSR flag (IETF draft-13: --algorithm + --composite)
	flags.StringVar(&csrGenComposite, "composite", "", "PQC algorithm for Composite CSR (e.g., ml-dsa-87)")
}

// csrGenMode represents the CSR generation mode determined from flags.
type csrGenMode struct {
	hasKey       bool
	hasGen       bool
	hasHSM       bool
	hasAttest    bool
	hasHybrid    bool
	hasComposite bool
}

func parseCSRGenMode() csrGenMode {
	return csrGenMode{
		hasKey:       csrGenKey != "",
		hasGen:       csrGenAlgorithm != "", // Only algorithm triggers gen mode (keyout is just output path)
		hasHSM:       csrGenHSMConfig != "",
		hasAttest:    csrGenAttestCert != "" || csrGenAttestKey != "",
		hasHybrid:    csrGenHybridAlg != "",
		hasComposite: csrGenComposite != "",
	}
}

func validateCSRGenFlags(mode csrGenMode) error {
	if err := validateCompositeFlags(mode); err != nil {
		return err
	}
	if err := validateMutualExclusivity(mode); err != nil {
		return err
	}
	if err := validateRequiredFlags(mode); err != nil {
		return err
	}
	return nil
}

// validateCompositeFlags validates flags specific to composite CSR mode.
func validateCompositeFlags(mode csrGenMode) error {
	if !mode.hasComposite {
		return nil
	}
	if !mode.hasGen {
		return fmt.Errorf("--composite requires --algorithm (e.g., --algorithm ecdsa-p384 --composite ml-dsa-87)")
	}
	if mode.hasKey || mode.hasHSM {
		return fmt.Errorf("--composite is mutually exclusive with --key and --hsm-config")
	}
	if mode.hasHybrid {
		return fmt.Errorf("--composite is mutually exclusive with --hybrid")
	}
	if csrGenKeyOut == "" {
		return fmt.Errorf("--keyout is required when using --composite (for classical key)")
	}
	if csrGenHybridKeyOut == "" {
		return fmt.Errorf("--hybrid-keyout is required when using --composite (for PQC key)")
	}
	return nil
}

// validateMutualExclusivity checks for mutually exclusive flag combinations.
func validateMutualExclusivity(mode csrGenMode) error {
	if mode.hasKey && mode.hasGen {
		return fmt.Errorf("--key and --algorithm/--keyout are mutually exclusive")
	}
	if mode.hasKey && mode.hasHSM {
		return fmt.Errorf("--key and --hsm-config are mutually exclusive")
	}
	if mode.hasHSM && csrGenKeyOut != "" {
		return fmt.Errorf("--keyout and --hsm-config are mutually exclusive")
	}
	return nil
}

// validateRequiredFlags checks that all required flags are present.
func validateRequiredFlags(mode csrGenMode) error {
	if err := validateCSRKeySourceFlags(mode); err != nil {
		return err
	}
	if err := validateCSRHSMFlags(mode); err != nil {
		return err
	}
	return validateCSROptionalFlags(mode)
}

func validateCSRKeySourceFlags(mode csrGenMode) error {
	if !mode.hasKey && !mode.hasGen && !mode.hasHSM {
		return fmt.Errorf("must specify either --key (existing key), --algorithm --keyout (generate new key), or --hsm-config (HSM key)")
	}
	if mode.hasGen && csrGenAlgorithm == "" {
		return fmt.Errorf("--algorithm is required when generating a new key")
	}
	if mode.hasGen && !mode.hasHSM && csrGenKeyOut == "" {
		return fmt.Errorf("--keyout is required when generating a new key (or use --hsm-config for HSM)")
	}
	return nil
}

func validateCSRHSMFlags(mode csrGenMode) error {
	if !mode.hasHSM {
		return nil
	}
	if csrGenAlgorithm == "" {
		return fmt.Errorf("--algorithm is required when using --hsm-config")
	}
	if csrGenKeyLabel == "" {
		return fmt.Errorf("--key-label is required when using --hsm-config")
	}
	return nil
}

func validateCSROptionalFlags(mode csrGenMode) error {
	if mode.hasAttest {
		if csrGenAttestCert == "" {
			return fmt.Errorf("--attest-cert is required for ML-KEM attestation")
		}
		// Either file-based or HSM-based attestation key
		hasFileKey := csrGenAttestKey != ""
		hasHSMKey := csrGenAttestKeyLabel != ""
		if !hasFileKey && !hasHSMKey {
			return fmt.Errorf("attestation key required: --attest-key (file) or --attest-key-label (HSM)")
		}
		if hasFileKey && hasHSMKey {
			return fmt.Errorf("--attest-key and --attest-key-label are mutually exclusive")
		}
		if hasHSMKey && csrGenHSMConfig == "" {
			return fmt.Errorf("--attest-key-label requires --hsm-config")
		}
	}
	if mode.hasHybrid && csrGenHybridKeyOut == "" {
		return fmt.Errorf("--hybrid-keyout is required when using --hybrid")
	}
	return nil
}

func buildCSRSubject() pkix.Name {
	subject := pkix.Name{CommonName: csrGenCN}
	if csrGenOrg != "" {
		subject.Organization = []string{csrGenOrg}
	}
	if csrGenCountry != "" {
		subject.Country = []string{csrGenCountry}
	}
	return subject
}

func createCSRForMode(mode csrGenMode, subject pkix.Name) ([]byte, string, error) {
	if mode.hasHSM {
		return createCSRWithHSM(subject)
	}
	if mode.hasGen {
		return createCSRWithNewKey(mode, subject)
	}
	return createCSRWithExistingKey(mode, subject)
}

func createCSRWithNewKey(mode csrGenMode, subject pkix.Name) ([]byte, string, error) {
	alg, err := crypto.ParseAlgorithm(csrGenAlgorithm)
	if err != nil {
		return nil, "", fmt.Errorf("invalid algorithm: %w", err)
	}

	if alg.IsKEM() {
		csrDER, err := createKEMCSRGen(alg, subject)
		return csrDER, alg.Description(), err
	}
	if alg.IsPQC() && mode.hasHybrid {
		return nil, "", fmt.Errorf("--hybrid is only valid with classical algorithms")
	}
	if alg.IsPQC() && mode.hasComposite {
		return nil, "", fmt.Errorf("--composite is only valid with classical algorithms")
	}
	if mode.hasComposite {
		csrDER, err := createCompositeCSRGen(alg, subject)
		desc := fmt.Sprintf("Composite (%s + %s)", alg.Description(), csrGenComposite)
		return csrDER, desc, err
	}
	if mode.hasHybrid {
		csrDER, err := createHybridCSRGen(alg, subject)
		desc := fmt.Sprintf("Catalyst (%s + %s)", alg.Description(), csrGenHybridAlg)
		return csrDER, desc, err
	}
	if alg.IsPQC() {
		csrDER, err := createPQCSignatureCSRGen(alg, subject)
		return csrDER, alg.Description(), err
	}
	csrDER, err := createClassicalCSRGen(alg, subject)
	return csrDER, alg.Description(), err
}

func createCSRWithExistingKey(mode csrGenMode, subject pkix.Name) ([]byte, string, error) {
	loadedSigner, err := crypto.LoadPrivateKey(csrGenKey, []byte(csrGenPassphrase))
	if err != nil {
		return nil, "", fmt.Errorf("failed to load private key: %w", err)
	}

	if mode.hasHybrid {
		csrDER, err := createHybridCSRWithExistingKeyGen(loadedSigner, subject)
		desc := fmt.Sprintf("Hybrid (%s + %s)", loadedSigner.Algorithm().Description(), csrGenHybridAlg)
		return csrDER, desc, err
	}

	csr, err := x509util.CreateSimpleCSR(x509util.SimpleCSRRequest{
		Subject:        subject,
		DNSNames:       csrGenDNS,
		EmailAddresses: csrGenEmail,
		Signer:         loadedSigner,
	})
	if err != nil {
		return nil, "", fmt.Errorf("failed to create CSR: %w", err)
	}
	return csr.Raw, loadedSigner.Algorithm().Description(), nil
}

func writeCSRResult(csrDER []byte, subject pkix.Name, algDescription string) error {
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	}
	pemData := pem.EncodeToMemory(pemBlock)
	if err := os.WriteFile(csrGenOutput, pemData, 0644); err != nil {
		return fmt.Errorf("failed to write CSR: %w", err)
	}

	fmt.Printf("CSR generated successfully!\n")
	fmt.Printf("  Subject:   %s\n", subject.String())
	fmt.Printf("  Algorithm: %s\n", algDescription)
	if len(csrGenDNS) > 0 {
		fmt.Printf("  DNS SANs:  %v\n", csrGenDNS)
	}
	if len(csrGenEmail) > 0 {
		fmt.Printf("  Email SANs: %v\n", csrGenEmail)
	}
	if len(csrGenIP) > 0 {
		fmt.Printf("  IP SANs:   %v\n", csrGenIP)
	}
	fmt.Printf("  Output:    %s\n", csrGenOutput)
	return nil
}

func runCSRGen(cmd *cobra.Command, args []string) error {
	mode := parseCSRGenMode()
	if err := validateCSRGenFlags(mode); err != nil {
		return err
	}

	subject := buildCSRSubject()
	csrDER, algDescription, err := createCSRForMode(mode, subject)
	if err != nil {
		return err
	}

	return writeCSRResult(csrDER, subject, algDescription)
}

func createCSRWithHSM(subject pkix.Name) ([]byte, string, error) {
	alg, err := crypto.ParseAlgorithm(csrGenAlgorithm)
	if err != nil {
		return nil, "", fmt.Errorf("invalid algorithm: %w", err)
	}

	// HSM PQC support requires HSM_PQC_ENABLED (e.g., Utimaco QuantumProtect)
	if alg.IsPQC() && os.Getenv("HSM_PQC_ENABLED") == "" {
		return nil, "", fmt.Errorf("HSM does not support PQC algorithms. Set HSM_PQC_ENABLED=1 for PQC-capable HSMs")
	}

	// KEM algorithms (ML-KEM) require attestation - delegate to specialized function
	if alg.IsKEM() {
		csrDER, err := createKEMCSRWithHSM(alg, subject)
		return csrDER, alg.Description() + " (HSM)", err
	}

	// Load HSM configuration
	hsmCfg, err := crypto.LoadHSMConfig(csrGenHSMConfig)
	if err != nil {
		return nil, "", fmt.Errorf("failed to load HSM config: %w", err)
	}

	// Get PIN
	pin, err := hsmCfg.GetPIN()
	if err != nil {
		return nil, "", fmt.Errorf("failed to get HSM PIN: %w", err)
	}

	fmt.Printf("Generating %s key in HSM...\n", alg.Description())

	// Generate key in HSM
	genCfg := crypto.GenerateHSMKeyPairConfig{
		ModulePath: hsmCfg.PKCS11.Lib,
		TokenLabel: hsmCfg.PKCS11.Token,
		PIN:        pin,
		KeyLabel:   csrGenKeyLabel,
		Algorithm:  alg,
	}

	result, err := crypto.GenerateHSMKeyPair(genCfg)
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate key in HSM: %w", err)
	}

	fmt.Printf("Key generated in HSM: label=%s, id=%s\n", result.KeyLabel, result.KeyID)

	// Create PKCS#11 config for signing
	pkcs11Cfg, err := hsmCfg.ToPKCS11Config(csrGenKeyLabel, csrGenKeyID)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create PKCS#11 config: %w", err)
	}

	// Create signer
	signer, err := crypto.NewPKCS11Signer(*pkcs11Cfg)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create HSM signer: %w", err)
	}
	defer func() { _ = signer.Close() }()

	// Create CSR
	csr, err := x509util.CreateSimpleCSR(x509util.SimpleCSRRequest{
		Subject:        subject,
		DNSNames:       csrGenDNS,
		EmailAddresses: csrGenEmail,
		Signer:         signer,
	})
	if err != nil {
		return nil, "", fmt.Errorf("failed to create CSR: %w", err)
	}

	return csr.Raw, alg.Description() + " (HSM)", nil
}

// createClassicalCSRGen creates a CSR using Go's standard x509 library.
func createClassicalCSRGen(alg crypto.AlgorithmID, subject pkix.Name) ([]byte, error) {
	fmt.Printf("Generating %s key pair...\n", alg.Description())

	keyCfg := crypto.KeyStorageConfig{
		Type:       crypto.KeyProviderTypeSoftware,
		KeyPath:    csrGenKeyOut,
		Passphrase: csrGenKeyPass,
	}
	km := crypto.NewKeyProvider(keyCfg)
	newSigner, err := km.Generate(alg, keyCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}
	fmt.Printf("Private key saved to: %s\n", csrGenKeyOut)

	csr, err := x509util.CreateSimpleCSR(x509util.SimpleCSRRequest{
		Subject:        subject,
		DNSNames:       csrGenDNS,
		EmailAddresses: csrGenEmail,
		Signer:         newSigner,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create CSR: %w", err)
	}

	return csr.Raw, nil
}

// createPQCSignatureCSRGen creates a CSR signed with ML-DSA or SLH-DSA.
func createPQCSignatureCSRGen(alg crypto.AlgorithmID, subject pkix.Name) ([]byte, error) {
	fmt.Printf("Generating %s key pair...\n", alg.Description())

	keyCfg := crypto.KeyStorageConfig{
		Type:       crypto.KeyProviderTypeSoftware,
		KeyPath:    csrGenKeyOut,
		Passphrase: csrGenKeyPass,
	}
	km := crypto.NewKeyProvider(keyCfg)
	newSigner, err := km.Generate(alg, keyCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}
	fmt.Printf("Private key saved to: %s\n", csrGenKeyOut)

	csrDER, err := x509util.CreatePQCSignatureCSR(x509util.PQCCSRRequest{
		Subject:        subject,
		DNSNames:       csrGenDNS,
		EmailAddresses: csrGenEmail,
		IPAddresses:    csrGenIP,
		Signer:         newSigner,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create PQC CSR: %w", err)
	}

	return csrDER, nil
}

// createKEMCSRGen creates a CSR for ML-KEM with RFC 9883 attestation.
func createKEMCSRGen(alg crypto.AlgorithmID, subject pkix.Name) ([]byte, error) {
	// Validation is done in validateCSROptionalFlags, but double-check here
	if csrGenAttestCert == "" {
		return nil, fmt.Errorf("ML-KEM requires --attest-cert for RFC 9883 attestation")
	}
	if csrGenAttestKey == "" && csrGenAttestKeyLabel == "" {
		return nil, fmt.Errorf("ML-KEM requires --attest-key or --attest-key-label for RFC 9883 attestation\n" +
			"Use a signature key to attest possession of the KEM key")
	}

	fmt.Printf("Generating %s key pair...\n", alg.Description())

	kemKP, err := crypto.GenerateKEMKeyPair(alg)
	if err != nil {
		return nil, fmt.Errorf("failed to generate KEM key pair: %w", err)
	}

	passphrase := []byte(csrGenKeyPass)
	if err := kemKP.SavePrivateKey(csrGenKeyOut, passphrase); err != nil {
		return nil, fmt.Errorf("failed to save KEM private key: %w", err)
	}
	fmt.Printf("KEM private key saved to: %s\n", csrGenKeyOut)

	attestCertPEM, err := os.ReadFile(csrGenAttestCert)
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

	// Build attestation key config - either HSM or file-based
	var attestKeyCfg crypto.KeyStorageConfig
	if csrGenAttestKeyLabel != "" {
		// HSM mode - reuse --hsm-config
		hsmCfg, err := crypto.LoadHSMConfig(csrGenHSMConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to load HSM config: %w", err)
		}
		pin, err := hsmCfg.GetPIN()
		if err != nil {
			return nil, fmt.Errorf("failed to get HSM PIN: %w", err)
		}
		attestKeyCfg = crypto.KeyStorageConfig{
			Type:           crypto.KeyProviderTypePKCS11,
			PKCS11Lib:      hsmCfg.PKCS11.Lib,
			PKCS11Token:    hsmCfg.PKCS11.Token,
			PKCS11Slot:     hsmCfg.PKCS11.Slot,
			PKCS11Pin:      pin,
			PKCS11KeyLabel: csrGenAttestKeyLabel,
		}
		fmt.Printf("Using HSM attestation key: %s\n", csrGenAttestKeyLabel)
	} else {
		// Software mode
		attestKeyCfg = crypto.KeyStorageConfig{
			Type:       crypto.KeyProviderTypeSoftware,
			KeyPath:    csrGenAttestKey,
			Passphrase: csrGenAttestPass,
		}
	}
	attestKM := crypto.NewKeyProvider(attestKeyCfg)
	attestSigner, err := attestKM.Load(attestKeyCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to load attestation key: %w", err)
	}

	fmt.Printf("Using attestation certificate: %s\n", attestCert.Subject.String())

	csrDER, err := x509util.CreateKEMCSRWithAttestation(x509util.KEMCSRRequest{
		Subject:        subject,
		DNSNames:       csrGenDNS,
		EmailAddresses: csrGenEmail,
		IPAddresses:    csrGenIP,
		KEMPublicKey:   kemKP.PublicKey,
		KEMAlgorithm:   alg,
		AttestCert:     attestCert,
		AttestSigner:   attestSigner,
		IncludeCert:    csrGenIncludeCert,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create KEM CSR: %w", err)
	}

	return csrDER, nil
}

// createKEMCSRWithHSM creates a CSR for ML-KEM with RFC 9883 attestation using HSM.
// Both the KEM key and attestation key are stored in the HSM.
func createKEMCSRWithHSM(alg crypto.AlgorithmID, subject pkix.Name) ([]byte, error) {
	// Validation: attestation is required for KEM
	if csrGenAttestCert == "" {
		return nil, fmt.Errorf("ML-KEM requires --attest-cert for RFC 9883 attestation")
	}
	if csrGenAttestKeyLabel == "" {
		return nil, fmt.Errorf("ML-KEM in HSM mode requires --attest-key-label for RFC 9883 attestation")
	}

	// Load HSM configuration
	hsmCfg, err := crypto.LoadHSMConfig(csrGenHSMConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to load HSM config: %w", err)
	}

	// Get PIN
	pin, err := hsmCfg.GetPIN()
	if err != nil {
		return nil, fmt.Errorf("failed to get HSM PIN: %w", err)
	}

	fmt.Printf("Generating %s key in HSM...\n", alg.Description())

	// Generate ML-KEM key in HSM
	genCfg := crypto.GenerateHSMKeyPairConfig{
		ModulePath: hsmCfg.PKCS11.Lib,
		TokenLabel: hsmCfg.PKCS11.Token,
		PIN:        pin,
		KeyLabel:   csrGenKeyLabel,
		Algorithm:  alg,
	}

	result, err := crypto.GenerateHSMKeyPair(genCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ML-KEM key in HSM: %w", err)
	}

	fmt.Printf("ML-KEM key generated in HSM: label=%s, id=%s\n", result.KeyLabel, result.KeyID)

	// Extract ML-KEM public key from HSM
	pkcs11Cfg, err := hsmCfg.ToPKCS11Config(csrGenKeyLabel, csrGenKeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to create PKCS#11 config: %w", err)
	}

	kemPubKey, err := crypto.GetPublicKeyFromHSM(*pkcs11Cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to extract ML-KEM public key from HSM: %w", err)
	}

	// Load attestation certificate
	attestCertPEM, err := os.ReadFile(csrGenAttestCert)
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

	// Create attestation signer from HSM (reuses same HSM config)
	attestPkcs11Cfg, err := hsmCfg.ToPKCS11Config(csrGenAttestKeyLabel, "")
	if err != nil {
		return nil, fmt.Errorf("failed to create attestation PKCS#11 config: %w", err)
	}

	attestSigner, err := crypto.NewPKCS11Signer(*attestPkcs11Cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create HSM attestation signer: %w", err)
	}
	defer func() { _ = attestSigner.Close() }()

	fmt.Printf("Using HSM attestation key: %s\n", csrGenAttestKeyLabel)
	fmt.Printf("Using attestation certificate: %s\n", attestCert.Subject.String())

	// Create KEM CSR with attestation
	csrDER, err := x509util.CreateKEMCSRWithAttestation(x509util.KEMCSRRequest{
		Subject:        subject,
		DNSNames:       csrGenDNS,
		EmailAddresses: csrGenEmail,
		IPAddresses:    csrGenIP,
		KEMPublicKey:   kemPubKey,
		KEMAlgorithm:   alg,
		AttestCert:     attestCert,
		AttestSigner:   attestSigner,
		IncludeCert:    csrGenIncludeCert,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create KEM CSR: %w", err)
	}

	return csrDER, nil
}

// createHybridCSRGen creates a Catalyst hybrid CSR with classical + PQC signatures.
func createHybridCSRGen(classicalAlg crypto.AlgorithmID, subject pkix.Name) ([]byte, error) {
	// Validate the combination
	if err := validateHybridCombination(string(classicalAlg), csrGenHybridAlg); err != nil {
		return nil, err
	}

	pqcAlg, err := crypto.ParseAlgorithm(csrGenHybridAlg)
	if err != nil {
		return nil, fmt.Errorf("invalid hybrid algorithm: %w", err)
	}

	if !pqcAlg.IsPQC() || !pqcAlg.IsSignature() {
		return nil, fmt.Errorf("--hybrid requires a PQC signature algorithm (ml-dsa-*)")
	}

	fmt.Printf("Generating Catalyst hybrid key pairs: %s + %s...\n", classicalAlg.Description(), pqcAlg.Description())

	classicalKeyCfg := crypto.KeyStorageConfig{
		Type:       crypto.KeyProviderTypeSoftware,
		KeyPath:    csrGenKeyOut,
		Passphrase: csrGenKeyPass,
	}
	classicalKM := crypto.NewKeyProvider(classicalKeyCfg)
	classicalSigner, err := classicalKM.Generate(classicalAlg, classicalKeyCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to generate classical key pair: %w", err)
	}
	fmt.Printf("Classical private key saved to: %s\n", csrGenKeyOut)

	pqcKeyCfg := crypto.KeyStorageConfig{
		Type:       crypto.KeyProviderTypeSoftware,
		KeyPath:    csrGenHybridKeyOut,
		Passphrase: csrGenHybridKeyPass,
	}
	pqcKM := crypto.NewKeyProvider(pqcKeyCfg)
	pqcSigner, err := pqcKM.Generate(pqcAlg, pqcKeyCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to generate PQC key pair: %w", err)
	}
	fmt.Printf("PQC private key saved to: %s\n", csrGenHybridKeyOut)

	hybridCSR, err := x509util.CreateHybridCSR(x509util.HybridCSRRequest{
		Subject:         subject,
		DNSNames:        csrGenDNS,
		EmailAddresses:  csrGenEmail,
		ClassicalSigner: classicalSigner,
		PQCSigner:       pqcSigner,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create hybrid CSR: %w", err)
	}

	return hybridCSR.DER(), nil
}

// createHybridCSRWithExistingKeyGen creates a hybrid CSR using an existing classical key.
func createHybridCSRWithExistingKeyGen(classicalSigner crypto.Signer, subject pkix.Name) ([]byte, error) {
	pqcAlg, err := crypto.ParseAlgorithm(csrGenHybridAlg)
	if err != nil {
		return nil, fmt.Errorf("invalid hybrid algorithm: %w", err)
	}

	if !pqcAlg.IsPQC() || !pqcAlg.IsSignature() {
		return nil, fmt.Errorf("--hybrid requires a PQC signature algorithm (ml-dsa-*, slh-dsa-*)")
	}

	fmt.Printf("Using existing classical key + generating %s...\n", pqcAlg.Description())

	pqcKeyCfg := crypto.KeyStorageConfig{
		Type:       crypto.KeyProviderTypeSoftware,
		KeyPath:    csrGenHybridKeyOut,
		Passphrase: csrGenHybridKeyPass,
	}
	pqcKM := crypto.NewKeyProvider(pqcKeyCfg)
	pqcSigner, err := pqcKM.Generate(pqcAlg, pqcKeyCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to generate PQC key pair: %w", err)
	}
	fmt.Printf("PQC private key saved to: %s\n", csrGenHybridKeyOut)

	hybridCSR, err := x509util.CreateHybridCSR(x509util.HybridCSRRequest{
		Subject:         subject,
		DNSNames:        csrGenDNS,
		EmailAddresses:  csrGenEmail,
		ClassicalSigner: classicalSigner,
		PQCSigner:       pqcSigner,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create hybrid CSR: %w", err)
	}

	return hybridCSR.DER(), nil
}

// validHybridCombinations defines valid Catalyst/Hybrid combinations per ITU-T X.509.
// Maps classical algorithm to list of valid PQC algorithms.
var validHybridCombinations = map[string][]string{
	"ecdsa-p256": {"ml-dsa-44", "ml-dsa-65"},
	"ecdsa-p384": {"ml-dsa-65", "ml-dsa-87"},
	"ecdsa-p521": {"ml-dsa-87"},
	"ed25519":    {"ml-dsa-44", "ml-dsa-65"},
	"ed448":      {"ml-dsa-87"},
}

// validateHybridCombination validates a Catalyst/Hybrid algorithm combination.
func validateHybridCombination(classical, pqc string) error {
	classical = strings.ToLower(strings.TrimSpace(classical))
	pqc = strings.ToLower(strings.TrimSpace(pqc))

	validPQC, ok := validHybridCombinations[classical]
	if !ok {
		var validClassical []string
		for k := range validHybridCombinations {
			validClassical = append(validClassical, k)
		}
		return fmt.Errorf("algorithm %q not supported for hybrid mode\nValid classical algorithms: %s",
			classical, strings.Join(validClassical, ", "))
	}

	for _, v := range validPQC {
		if v == pqc {
			return nil
		}
	}
	return fmt.Errorf("invalid hybrid combination: %s + %s\nValid PQC for %s: %s",
		classical, pqc, classical, strings.Join(validPQC, ", "))
}

// validCompositeCombinations defines valid Composite combinations per IETF draft-13.
// Maps classical algorithm to list of valid PQC algorithms.
// Only IANA-allocated OIDs are supported:
//   - P-256 + ML-DSA-65 (OID .45)
//   - P-384 + ML-DSA-65 (OID .46)
//   - P-521 + ML-DSA-87 (OID .54)
var validCompositeCombinations = map[string][]string{
	"ecdsa-p256": {"ml-dsa-65"},
	"ecdsa-p384": {"ml-dsa-65"},
	"ecdsa-p521": {"ml-dsa-87"},
}

// validateCompositeCombination validates a Composite algorithm combination.
func validateCompositeCombination(classical, pqc string) error {
	classical = strings.ToLower(strings.TrimSpace(classical))
	pqc = strings.ToLower(strings.TrimSpace(pqc))

	validPQC, ok := validCompositeCombinations[classical]
	if !ok {
		var validClassical []string
		for k := range validCompositeCombinations {
			validClassical = append(validClassical, k)
		}
		return fmt.Errorf("algorithm %q not supported for composite mode\nValid classical algorithms: %s",
			classical, strings.Join(validClassical, ", "))
	}

	for _, v := range validPQC {
		if v == pqc {
			return nil
		}
	}
	return fmt.Errorf("invalid composite combination: %s + %s\nValid PQC for %s: %s",
		classical, pqc, classical, strings.Join(validPQC, ", "))
}

// createCompositeCSRGen creates a Composite CSR using --algorithm + --composite flags.
func createCompositeCSRGen(classicalAlg crypto.AlgorithmID, subject pkix.Name) ([]byte, error) {
	// Validate the combination
	if err := validateCompositeCombination(string(classicalAlg), csrGenComposite); err != nil {
		return nil, err
	}

	pqcAlg, err := crypto.ParseAlgorithm(csrGenComposite)
	if err != nil {
		return nil, fmt.Errorf("invalid composite PQC algorithm: %w", err)
	}

	fmt.Printf("Generating Composite key pairs: %s + %s...\n",
		classicalAlg.Description(), pqcAlg.Description())

	// Generate classical key
	classicalKeyCfg := crypto.KeyStorageConfig{
		Type:       crypto.KeyProviderTypeSoftware,
		KeyPath:    csrGenKeyOut,
		Passphrase: csrGenKeyPass,
	}
	classicalKM := crypto.NewKeyProvider(classicalKeyCfg)
	classicalSigner, err := classicalKM.Generate(classicalAlg, classicalKeyCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to generate classical key pair: %w", err)
	}
	fmt.Printf("Classical private key saved to: %s\n", csrGenKeyOut)

	// Generate PQC key
	pqcKeyCfg := crypto.KeyStorageConfig{
		Type:       crypto.KeyProviderTypeSoftware,
		KeyPath:    csrGenHybridKeyOut,
		Passphrase: csrGenHybridKeyPass,
	}
	pqcKM := crypto.NewKeyProvider(pqcKeyCfg)
	pqcSigner, err := pqcKM.Generate(pqcAlg, pqcKeyCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to generate PQC key pair: %w", err)
	}
	fmt.Printf("PQC private key saved to: %s\n", csrGenHybridKeyOut)

	// Create Composite CSR
	csrDER, err := x509util.CreateCompositeCSR(x509util.CompositeCSRRequest{
		Subject:         subject,
		DNSNames:        csrGenDNS,
		EmailAddresses:  csrGenEmail,
		ClassicalSigner: classicalSigner,
		PQCSigner:       pqcSigner,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create Composite CSR: %w", err)
	}

	return csrDER, nil
}

func runCSRInfo(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read CSR file: %w", err)
	}

	// Try PEM first
	var der []byte
	block, _ := pem.Decode(data)
	if block != nil && block.Type == "CERTIFICATE REQUEST" {
		der = block.Bytes
	} else {
		// Try DER
		der = data
	}

	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return fmt.Errorf("failed to parse CSR: %w", err)
	}

	fmt.Println("Certificate Signing Request:")
	fmt.Printf("  Subject:        %s\n", csr.Subject.String())
	fmt.Printf("  Signature Alg:  %s\n", formatCSRSigAlg(csr))
	fmt.Printf("  Public Key Alg: %s\n", formatCSRPubKeyAlg(csr))

	if len(csr.DNSNames) > 0 {
		fmt.Printf("  DNS Names:      %s\n", strings.Join(csr.DNSNames, ", "))
	}
	if len(csr.IPAddresses) > 0 {
		ips := make([]string, len(csr.IPAddresses))
		for i, ip := range csr.IPAddresses {
			ips[i] = ip.String()
		}
		fmt.Printf("  IP Addresses:   %s\n", strings.Join(ips, ", "))
	}
	if len(csr.EmailAddresses) > 0 {
		fmt.Printf("  Email:          %s\n", strings.Join(csr.EmailAddresses, ", "))
	}

	// Verify signature
	if err := csr.CheckSignature(); err != nil {
		fmt.Printf("  Signature:      INVALID (%v)\n", err)
	} else {
		fmt.Printf("  Signature:      valid\n")
	}

	return nil
}

func runCSRVerify(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read CSR file: %w", err)
	}

	// Try PEM first
	var der []byte
	block, _ := pem.Decode(data)
	if block != nil && block.Type == "CERTIFICATE REQUEST" {
		der = block.Bytes
	} else {
		der = data
	}

	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return fmt.Errorf("failed to parse CSR: %w", err)
	}

	fmt.Printf("Verifying CSR: %s\n", filePath)
	fmt.Printf("  Subject: %s\n", csr.Subject.String())

	if err := csr.CheckSignature(); err != nil {
		fmt.Printf("  Signature: INVALID\n")
		fmt.Printf("  Error: %v\n", err)
		return fmt.Errorf("CSR signature verification failed")
	}

	fmt.Printf("  Signature: valid\n")
	fmt.Printf("\nCSR verification successful.\n")
	fmt.Printf("The requester has proven possession of the private key.\n")

	return nil
}

// Helper functions

func formatCSRSigAlg(csr *x509.CertificateRequest) string {
	if csr.SignatureAlgorithm != x509.UnknownSignatureAlgorithm {
		return csr.SignatureAlgorithm.String()
	}
	oid, err := x509util.ExtractCSRSignatureAlgorithmOID(csr.Raw)
	if err != nil {
		return "Unknown"
	}
	return x509util.AlgorithmName(oid)
}

func formatCSRPubKeyAlg(csr *x509.CertificateRequest) string {
	// Handle ECDSA with curve info
	if ecdsaPub, ok := csr.PublicKey.(*ecdsa.PublicKey); ok {
		curveName := ""
		switch ecdsaPub.Curve.Params().BitSize {
		case 256:
			curveName = "P-256"
		case 384:
			curveName = "P-384"
		case 521:
			curveName = "P-521"
		}
		if curveName != "" {
			return fmt.Sprintf("ECDSA %s", curveName)
		}
		return "ECDSA"
	}

	// Handle RSA with key size
	if rsaPub, ok := csr.PublicKey.(*rsa.PublicKey); ok {
		return fmt.Sprintf("RSA %d", rsaPub.N.BitLen())
	}

	// PQC algorithms
	if csr.PublicKeyAlgorithm != x509.UnknownPublicKeyAlgorithm {
		return csr.PublicKeyAlgorithm.String()
	}
	oid, err := x509util.ExtractCSRPublicKeyAlgorithmOID(csr.Raw)
	if err != nil {
		return "Unknown"
	}
	return x509util.AlgorithmName(oid)
}
