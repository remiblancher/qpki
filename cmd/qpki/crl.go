package main

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/remiblancher/post-quantum-pki/internal/ca"
	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
	"github.com/remiblancher/post-quantum-pki/internal/x509util"
)

// crlCmd is the parent command for CRL operations.
var crlCmd = &cobra.Command{
	Use:   "crl",
	Short: "Certificate Revocation List operations",
	Long: `Manage Certificate Revocation Lists (CRLs).

Commands:
  gen     Generate a new CRL
  info    Display CRL information
  verify  Verify CRL signature
  list    List CRLs in a CA directory

Examples:
  # Generate a CRL
  qpki crl gen --ca-dir ./ca

  # Display CRL information
  qpki crl info ./ca/crl/ca.crl

  # Verify CRL signature
  qpki crl verify ./ca/crl/ca.crl --ca ./ca/ca.crt

  # List CRLs in a CA
  qpki crl list --ca-dir ./ca`,
}

var crlGenCmd = &cobra.Command{
	Use:   "gen",
	Short: "Generate a Certificate Revocation List",
	Long: `Generate a new Certificate Revocation List (CRL).

The CRL contains all revoked certificates and is signed by the CA.
It should be distributed to relying parties for certificate validation.

For multi-profile CAs, CRLs can be generated per algorithm family:
  --algo ec       Generate CRL for EC certificates (signed with EC key)
  --algo ml-dsa   Generate CRL for ML-DSA certificates (signed with ML-DSA key)

Without --algo, generates a CRL using the default/primary CA key.

Examples:
  # Generate CRL valid for 7 days
  qpki crl gen --ca-dir ./ca

  # Generate CRL valid for 30 days
  qpki crl gen --ca-dir ./ca --days 30

  # Generate CRL for specific algorithm family
  qpki crl gen --ca-dir ./ca --algo ec
  qpki crl gen --ca-dir ./ca --algo ml-dsa

  # Generate all CRLs for multi-profile CA
  qpki crl gen --ca-dir ./ca --all`,
	RunE: runCRLGen,
}

var crlInfoCmd = &cobra.Command{
	Use:   "info <crl-file>",
	Short: "Display CRL information",
	Long: `Display detailed information about a Certificate Revocation List.

Shows issuer, validity period, signature algorithm, and list of revoked certificates.

Examples:
  qpki crl info ./ca/crl/ca.crl
  qpki crl info /path/to/crl.pem`,
	Args: cobra.ExactArgs(1),
	RunE: runCRLInfo,
}

var crlVerifyCmd = &cobra.Command{
	Use:   "verify <crl-file>",
	Short: "Verify CRL signature",
	Long: `Verify the signature of a Certificate Revocation List.

Checks:
  - CRL signature is valid
  - CRL was signed by the specified CA
  - CRL is not expired (optional)

Examples:
  # Verify CRL signature
  qpki crl verify ./ca/crl/ca.crl --ca ./ca/ca.crt

  # Verify and check expiration
  qpki crl verify ./ca/crl/ca.crl --ca ./ca/ca.crt --check-expiry`,
	Args: cobra.ExactArgs(1),
	RunE: runCRLVerify,
}

var crlListCmd = &cobra.Command{
	Use:   "list",
	Short: "List CRLs in a CA directory",
	Long: `List all CRL files in a CA's crl/ directory.

Scans the CA's crl/ subdirectory for .crl and .pem files.

Examples:
  qpki crl list --ca-dir ./ca`,
	RunE: runCRLList,
}

// Flags
var (
	// crl gen flags
	crlGenCADir      string
	crlGenDays       int
	crlGenPassphrase string
	crlGenAlgo       string // algorithm family (ec, ml-dsa, etc.)
	crlGenAll        bool   // generate all CRLs

	// crl verify flags
	crlVerifyCA          string
	crlVerifyCheckExpiry bool

	// crl list flags
	crlListCADir string
)

func init() {
	// Add subcommands
	crlCmd.AddCommand(crlGenCmd)
	crlCmd.AddCommand(crlInfoCmd)
	crlCmd.AddCommand(crlVerifyCmd)
	crlCmd.AddCommand(crlListCmd)

	// crl gen flags
	crlGenCmd.Flags().StringVarP(&crlGenCADir, "ca-dir", "d", "./ca", "CA directory")
	crlGenCmd.Flags().IntVar(&crlGenDays, "days", 7, "CRL validity in days")
	crlGenCmd.Flags().StringVar(&crlGenPassphrase, "ca-passphrase", "", "CA private key passphrase")
	crlGenCmd.Flags().StringVar(&crlGenAlgo, "algo", "", "Algorithm family (ec, ml-dsa, slh-dsa, etc.)")
	crlGenCmd.Flags().BoolVar(&crlGenAll, "all", false, "Generate CRLs for all algorithm families")

	// crl verify flags
	crlVerifyCmd.Flags().StringVar(&crlVerifyCA, "ca", "", "CA certificate (PEM)")
	crlVerifyCmd.Flags().BoolVar(&crlVerifyCheckExpiry, "check-expiry", false, "Check if CRL is expired")
	_ = crlVerifyCmd.MarkFlagRequired("ca")

	// crl list flags
	crlListCmd.Flags().StringVarP(&crlListCADir, "ca-dir", "d", "./ca", "CA directory")
}

func runCRLGen(cmd *cobra.Command, args []string) error {
	absDir, err := filepath.Abs(crlGenCADir)
	if err != nil {
		return fmt.Errorf("invalid CA directory: %w", err)
	}

	// Check if CA has multiple algorithm families (multi-profile)
	versionStore := ca.NewVersionStore(absDir)
	isMultiProfile := false
	if versionStore.IsVersioned() {
		if activeVer, err := versionStore.GetActiveVersion(); err == nil && activeVer != nil {
			isMultiProfile = len(activeVer.Certificates) > 1
		}
	}

	// Handle --all flag for multi-profile CAs
	if crlGenAll {
		if !isMultiProfile {
			return fmt.Errorf("--all requires a multi-profile CA")
		}
		return runCRLGenAll(absDir, versionStore)
	}

	// Handle --algo flag for multi-profile CAs
	if crlGenAlgo != "" {
		if !isMultiProfile {
			return fmt.Errorf("--algo requires a multi-profile CA")
		}
		return runCRLGenForAlgo(absDir, crlGenAlgo, versionStore)
	}

	// Default: generate CRL from primary store
	store := ca.NewFileStore(absDir)
	if !store.Exists() {
		return fmt.Errorf("CA not found at %s", absDir)
	}

	caInstance, err := ca.NewWithSigner(store, nil)
	if err != nil {
		return fmt.Errorf("failed to load CA: %w", err)
	}

	if err := caInstance.LoadSigner(crlGenPassphrase); err != nil {
		return fmt.Errorf("failed to load CA signer: %w", err)
	}

	// Get revoked certificates count
	revoked, err := store.ListRevoked()
	if err != nil {
		return fmt.Errorf("failed to list revoked certificates: %w", err)
	}

	nextUpdate := time.Now().AddDate(0, 0, crlGenDays)
	crlDER, err := caInstance.GenerateCRL(nextUpdate)
	if err != nil {
		return fmt.Errorf("failed to generate CRL: %w", err)
	}

	fmt.Printf("CRL generated successfully.\n")
	fmt.Printf("  Revoked certificates: %d\n", len(revoked))
	fmt.Printf("  CRL file: %s\n", store.CRLPath())
	fmt.Printf("  Size: %d bytes\n", len(crlDER))
	fmt.Printf("  This update: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Printf("  Next update: %s\n", nextUpdate.Format("2006-01-02 15:04:05"))

	return nil
}

// runCRLGenForAlgo generates a CRL for a specific algorithm family.
func runCRLGenForAlgo(caDir, algoFamily string, versionStore *ca.VersionStore) error {
	activeVersion, err := versionStore.GetActiveVersion()
	if err != nil {
		return fmt.Errorf("failed to get active version: %w", err)
	}

	// Find certificate for this algorithm family and get full algorithm ID
	var algoID string
	for _, cert := range activeVersion.Certificates {
		if cert.AlgorithmFamily == algoFamily {
			algoID = cert.Algorithm
			break
		}
	}

	if algoID == "" {
		return fmt.Errorf("algorithm family %s not found in active version", algoFamily)
	}

	// Load CAInfo to get versioned paths
	info, err := ca.LoadCAInfo(caDir)
	if err != nil {
		return fmt.Errorf("failed to load CA info: %w", err)
	}

	// Load signer from version path using full algorithm ID
	keyPath := info.KeyPath(activeVersion.ID, algoID)
	keyCfg := pkicrypto.KeyStorageConfig{
		Type:       pkicrypto.KeyProviderTypeSoftware,
		KeyPath:    keyPath,
		Passphrase: crlGenPassphrase,
	}
	km := pkicrypto.NewKeyProvider(keyCfg)
	signer, err := km.Load(keyCfg)
	if err != nil {
		return fmt.Errorf("failed to load CA signer for %s: %w", algoFamily, err)
	}

	// Use root store for index operations
	rootStore := ca.NewFileStore(caDir)
	caInstance, err := ca.NewWithSigner(rootStore, signer)
	if err != nil {
		return fmt.Errorf("failed to load CA for %s: %w", algoFamily, err)
	}

	// Get revoked certificates count
	revoked, err := rootStore.ListRevoked()
	if err != nil {
		revoked = nil // Non-fatal: may not have any revocations
	}

	// Generate CRL to crl/ directory with algorithm ID in filename
	crlDir := filepath.Join(caDir, "crl")
	if err := os.MkdirAll(crlDir, 0755); err != nil {
		return fmt.Errorf("failed to create CRL directory: %w", err)
	}

	nextUpdate := time.Now().AddDate(0, 0, crlGenDays)
	crlDER, err := caInstance.GenerateCRL(nextUpdate)
	if err != nil {
		return fmt.Errorf("failed to generate CRL for %s: %w", algoFamily, err)
	}

	// Write CRL with algorithm ID in filename: crl/ca.{algoID}.crl
	crlPath := filepath.Join(crlDir, fmt.Sprintf("ca.%s.crl", algoID))
	crlPEM := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER})
	if err := os.WriteFile(crlPath, crlPEM, 0644); err != nil {
		return fmt.Errorf("failed to write CRL: %w", err)
	}

	// Also write DER version
	crlDERPath := filepath.Join(crlDir, fmt.Sprintf("ca.%s.crl.der", algoID))
	if err := os.WriteFile(crlDERPath, crlDER, 0644); err != nil {
		return fmt.Errorf("failed to write CRL DER: %w", err)
	}

	fmt.Printf("CRL generated for %s (%s):\n", algoFamily, algoID)
	fmt.Printf("  Revoked certificates: %d\n", len(revoked))
	fmt.Printf("  CRL file: %s\n", crlPath)
	fmt.Printf("  Size: %d bytes\n", len(crlDER))
	fmt.Printf("  This update: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Printf("  Next update: %s\n", nextUpdate.Format("2006-01-02 15:04:05"))

	return nil
}

// runCRLGenAll generates CRLs for all algorithm families in a multi-profile CA.
func runCRLGenAll(caDir string, versionStore *ca.VersionStore) error {
	activeVersion, err := versionStore.GetActiveVersion()
	if err != nil {
		return fmt.Errorf("failed to get active version: %w", err)
	}

	if len(activeVersion.Certificates) == 0 {
		return fmt.Errorf("no certificates found in active version")
	}

	fmt.Printf("Generating CRLs for all algorithm families...\n\n")

	var errors []string
	for _, cert := range activeVersion.Certificates {
		err := runCRLGenForAlgo(caDir, cert.AlgorithmFamily, versionStore)
		if err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", cert.AlgorithmFamily, err))
			continue
		}
		fmt.Println()
	}

	if len(errors) > 0 {
		fmt.Printf("\nCompleted with %d error(s):\n", len(errors))
		for _, e := range errors {
			fmt.Printf("  - %s\n", e)
		}
	} else {
		fmt.Printf("All CRLs generated successfully.\n")
	}

	return nil
}

func runCRLInfo(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read CRL file: %w", err)
	}

	// Try PEM first
	var der []byte
	block, _ := pem.Decode(data)
	if block != nil && block.Type == "X509 CRL" {
		der = block.Bytes
	} else {
		// Try DER
		der = data
	}

	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		return fmt.Errorf("failed to parse CRL: %w", err)
	}

	fmt.Println("Certificate Revocation List:")
	fmt.Printf("  Issuer:         %s\n", crl.Issuer.String())
	fmt.Printf("  This Update:    %s\n", crl.ThisUpdate.Format("2006-01-02 15:04:05 UTC"))
	fmt.Printf("  Next Update:    %s\n", crl.NextUpdate.Format("2006-01-02 15:04:05 UTC"))
	fmt.Printf("  Signature Alg:  %s\n", formatCRLSigAlg(crl))

	if crl.Number != nil {
		fmt.Printf("  CRL Number:     %s\n", crl.Number.String())
	}

	if len(crl.AuthorityKeyId) > 0 {
		fmt.Printf("  Auth Key ID:    %s\n", formatCRLHex(crl.AuthorityKeyId))
	}

	fmt.Printf("  Revoked Certs:  %d\n", len(crl.RevokedCertificateEntries))

	// Check expiry status
	now := time.Now()
	if now.After(crl.NextUpdate) {
		fmt.Printf("  Status:         EXPIRED\n")
	} else {
		remaining := crl.NextUpdate.Sub(now)
		fmt.Printf("  Status:         valid (expires in %s)\n", formatDuration(remaining))
	}

	if len(crl.RevokedCertificateEntries) > 0 {
		fmt.Println("\nRevoked Certificates:")
		for _, entry := range crl.RevokedCertificateEntries {
			serial := hex.EncodeToString(entry.SerialNumber.Bytes())
			revTime := entry.RevocationTime.Format("2006-01-02 15:04:05")
			reason := formatCRLRevocationReason(entry.ReasonCode)
			fmt.Printf("  - %s  revoked: %s  reason: %s\n", serial, revTime, reason)
		}
	}

	return nil
}

func runCRLVerify(cmd *cobra.Command, args []string) error {
	crlPath := args[0]

	// Read CRL
	crlData, err := os.ReadFile(crlPath)
	if err != nil {
		return fmt.Errorf("failed to read CRL file: %w", err)
	}

	// Parse CRL
	var crlDER []byte
	block, _ := pem.Decode(crlData)
	if block != nil && block.Type == "X509 CRL" {
		crlDER = block.Bytes
	} else {
		crlDER = crlData
	}

	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		return fmt.Errorf("failed to parse CRL: %w", err)
	}

	// Read CA certificate
	caData, err := os.ReadFile(crlVerifyCA)
	if err != nil {
		return fmt.Errorf("failed to read CA certificate: %w", err)
	}

	caBlock, _ := pem.Decode(caData)
	if caBlock == nil {
		return fmt.Errorf("failed to parse CA certificate PEM")
	}

	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Verify signature
	fmt.Printf("Verifying CRL: %s\n", crlPath)
	fmt.Printf("  Issuer: %s\n", crl.Issuer.String())
	fmt.Printf("  CA:     %s\n", caCert.Subject.String())

	if err := crl.CheckSignatureFrom(caCert); err != nil {
		fmt.Printf("  Signature: INVALID (%v)\n", err)
		return fmt.Errorf("CRL signature verification failed")
	}
	fmt.Printf("  Signature: valid\n")

	// Check expiry if requested
	if crlVerifyCheckExpiry {
		now := time.Now()
		if now.After(crl.NextUpdate) {
			fmt.Printf("  Expiry: EXPIRED (next update was %s)\n", crl.NextUpdate.Format("2006-01-02 15:04:05"))
			return fmt.Errorf("CRL is expired")
		}
		fmt.Printf("  Expiry: valid (until %s)\n", crl.NextUpdate.Format("2006-01-02 15:04:05"))
	}

	fmt.Printf("\nCRL verification successful.\n")
	return nil
}

func runCRLList(cmd *cobra.Command, args []string) error {
	absDir, err := filepath.Abs(crlListCADir)
	if err != nil {
		return fmt.Errorf("invalid CA directory: %w", err)
	}

	crlDir := filepath.Join(absDir, "crl")
	entries, err := os.ReadDir(crlDir)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("No CRL directory found at %s\n", crlDir)
			return nil
		}
		return fmt.Errorf("failed to read CRL directory: %w", err)
	}

	type crlInfo struct {
		Name       string
		Algorithm  string // algorithm family (empty for root CRLs)
		ThisUpdate time.Time
		NextUpdate time.Time
		Revoked    int
		Status     string
	}

	var crls []crlInfo
	now := time.Now()

	// Helper function to parse and add CRL info
	parseCRL := func(path, name, algo string) {
		data, err := os.ReadFile(path)
		if err != nil {
			return
		}

		var der []byte
		block, _ := pem.Decode(data)
		if block != nil && block.Type == "X509 CRL" {
			der = block.Bytes
		} else {
			der = data
		}

		crl, err := x509.ParseRevocationList(der)
		if err != nil {
			return
		}

		status := "valid"
		if now.After(crl.NextUpdate) {
			status = "EXPIRED"
		}

		crls = append(crls, crlInfo{
			Name:       name,
			Algorithm:  algo,
			ThisUpdate: crl.ThisUpdate,
			NextUpdate: crl.NextUpdate,
			Revoked:    len(crl.RevokedCertificateEntries),
			Status:     status,
		})
	}

	// Scan root CRL directory
	for _, entry := range entries {
		name := entry.Name()

		// Check for algorithm subdirectories
		if entry.IsDir() {
			algoDir := filepath.Join(crlDir, name)
			algoEntries, err := os.ReadDir(algoDir)
			if err != nil {
				continue
			}

			for _, algoEntry := range algoEntries {
				algoName := algoEntry.Name()
				if !strings.HasSuffix(algoName, ".crl") {
					continue
				}
				crlPath := filepath.Join(algoDir, algoName)
				parseCRL(crlPath, algoName, name)
			}
			continue
		}

		// Root CRL files
		if !strings.HasSuffix(name, ".crl") && !strings.HasSuffix(name, ".pem") {
			continue
		}

		crlPath := filepath.Join(crlDir, name)
		parseCRL(crlPath, name, "")
	}

	if len(crls) == 0 {
		fmt.Println("No CRLs found.")
		return nil
	}

	// Print table
	fmt.Printf("%-12s %-16s %-18s %-18s %-8s %s\n", "ALGORITHM", "NAME", "THIS UPDATE", "NEXT UPDATE", "REVOKED", "STATUS")
	fmt.Printf("%-12s %-16s %-18s %-18s %-8s %s\n", "---------", "----", "-----------", "-----------", "-------", "------")
	for _, c := range crls {
		algo := c.Algorithm
		if algo == "" {
			algo = "(root)"
		}
		fmt.Printf("%-12s %-16s %-18s %-18s %-8d %s\n",
			algo,
			c.Name,
			c.ThisUpdate.Format("2006-01-02 15:04"),
			c.NextUpdate.Format("2006-01-02 15:04"),
			c.Revoked,
			c.Status,
		)
	}

	fmt.Printf("\nTotal: %d CRL(s)\n", len(crls))
	return nil
}

// Helper functions

func formatCRLSigAlg(crl *x509.RevocationList) string {
	if crl.SignatureAlgorithm != x509.UnknownSignatureAlgorithm {
		return crl.SignatureAlgorithm.String()
	}
	oid, err := x509util.ExtractCRLSignatureAlgorithmOID(crl.Raw)
	if err != nil {
		return "Unknown"
	}
	return x509util.AlgorithmName(oid)
}

func formatCRLHex(data []byte) string {
	parts := make([]string, len(data))
	for i, b := range data {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

func formatCRLRevocationReason(reason int) string {
	reasons := map[int]string{
		0:  "unspecified",
		1:  "keyCompromise",
		2:  "caCompromise",
		3:  "affiliationChanged",
		4:  "superseded",
		5:  "cessationOfOperation",
		6:  "certificateHold",
		8:  "removeFromCRL",
		9:  "privilegeWithdrawn",
		10: "aaCompromise",
	}
	if name, ok := reasons[reason]; ok {
		return name
	}
	return fmt.Sprintf("unknown(%d)", reason)
}

func formatDuration(d time.Duration) string {
	days := int(d.Hours() / 24)
	hours := int(d.Hours()) % 24
	if days > 0 {
		return fmt.Sprintf("%dd %dh", days, hours)
	}
	return fmt.Sprintf("%dh", hours)
}
