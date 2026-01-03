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

Examples:
  # Generate CRL valid for 7 days
  qpki crl gen --ca-dir ./ca

  # Generate CRL valid for 30 days
  qpki crl gen --ca-dir ./ca --days 30`,
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

	store := ca.NewStore(absDir)
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
		ThisUpdate time.Time
		NextUpdate time.Time
		Revoked    int
		Status     string
	}

	var crls []crlInfo
	now := time.Now()

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if !strings.HasSuffix(name, ".crl") && !strings.HasSuffix(name, ".pem") {
			continue
		}

		crlPath := filepath.Join(crlDir, name)
		data, err := os.ReadFile(crlPath)
		if err != nil {
			continue
		}

		// Try to parse
		var der []byte
		block, _ := pem.Decode(data)
		if block != nil && block.Type == "X509 CRL" {
			der = block.Bytes
		} else {
			der = data
		}

		crl, err := x509.ParseRevocationList(der)
		if err != nil {
			continue
		}

		status := "valid"
		if now.After(crl.NextUpdate) {
			status = "EXPIRED"
		}

		crls = append(crls, crlInfo{
			Name:       name,
			ThisUpdate: crl.ThisUpdate,
			NextUpdate: crl.NextUpdate,
			Revoked:    len(crl.RevokedCertificateEntries),
			Status:     status,
		})
	}

	if len(crls) == 0 {
		fmt.Println("No CRLs found.")
		return nil
	}

	// Print table
	fmt.Printf("%-20s %-20s %-20s %-8s %s\n", "NAME", "THIS UPDATE", "NEXT UPDATE", "REVOKED", "STATUS")
	fmt.Printf("%-20s %-20s %-20s %-8s %s\n", "----", "-----------", "-----------", "-------", "------")
	for _, c := range crls {
		fmt.Printf("%-20s %-20s %-20s %-8d %s\n",
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
