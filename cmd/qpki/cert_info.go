package main

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/remiblancher/qpki/pkg/ca"
)

var certInfoCmd = &cobra.Command{
	Use:   "info <serial>",
	Short: "Display certificate information",
	Long: `Display detailed information about an issued certificate.

Shows certificate details including subject, issuer, validity period,
SANs, key usage, and revocation status.

Examples:
  # Show certificate info by serial
  pki cert info 02

  # With specific CA directory
  pki cert info 02 --ca-dir ./myca`,
	Args: cobra.ExactArgs(1),
	RunE: runCertInfo,
}

var certInfoCADir string

func init() {
	certInfoCmd.Flags().StringVarP(&certInfoCADir, "ca-dir", "d", "./ca", "CA directory")
}

func runCertInfo(cmd *cobra.Command, args []string) error {
	serialHex := args[0]
	serial, err := hex.DecodeString(serialHex)
	if err != nil {
		return fmt.Errorf("invalid serial number: %w", err)
	}

	absDir, _ := filepath.Abs(certInfoCADir)
	store := ca.NewFileStore(absDir)

	if !store.Exists() {
		return fmt.Errorf("CA not found at %s", absDir)
	}

	// Load certificate
	cert, err := store.LoadCert(context.Background(), serial)
	if err != nil {
		return fmt.Errorf("certificate not found: %w", err)
	}

	// Get status from index
	status := "Valid"
	entries, err := store.ReadIndex(context.Background())
	if err == nil {
		status = getCertStatus(entries, serialHex)
	}

	// Print certificate information
	printCertDetails(cert, serialHex, status, store, serial)

	return nil
}

// printCertDetails prints the certificate details to stdout.
func printCertDetails(cert *x509.Certificate, serialHex, status string, store *ca.FileStore, serial []byte) {
	fmt.Println("Certificate Information")
	fmt.Println("=======================")
	fmt.Println()
	fmt.Printf("Serial:        %s\n", strings.ToUpper(serialHex))
	fmt.Printf("Subject:       %s\n", cert.Subject.String())
	fmt.Printf("Issuer:        %s\n", cert.Issuer.String())
	fmt.Printf("Status:        %s\n", status)
	fmt.Println()
	fmt.Printf("Not Before:    %s\n", cert.NotBefore.Format("2006-01-02 15:04:05"))
	fmt.Printf("Not After:     %s\n", cert.NotAfter.Format("2006-01-02 15:04:05"))
	fmt.Printf("Algorithm:     %s\n", cert.SignatureAlgorithm.String())

	// SANs
	if sans := formatSANs(cert); len(sans) > 0 {
		fmt.Printf("SANs:          %s\n", strings.Join(sans, ", "))
	}

	// Key Usage
	if keyUsages := getKeyUsageNames(cert.KeyUsage); len(keyUsages) > 0 {
		fmt.Printf("Key Usage:     %s\n", strings.Join(keyUsages, ", "))
	}

	// Extended Key Usage
	if extKeyUsages := getExtKeyUsageNames(cert.ExtKeyUsage); len(extKeyUsages) > 0 {
		fmt.Printf("Ext Key Usage: %s\n", strings.Join(extKeyUsages, ", "))
	}

	// CA
	if cert.IsCA {
		fmt.Printf("CA:            yes (path length: %s)\n", formatPathLen(cert))
	}

	fmt.Println()
	fmt.Printf("File:          %s\n", store.CertPath(serial))
}
