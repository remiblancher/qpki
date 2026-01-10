package main

import (
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/remiblancher/post-quantum-pki/internal/ca"
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
	cert, err := store.LoadCert(serial)
	if err != nil {
		return fmt.Errorf("certificate not found: %w", err)
	}

	// Get status from index
	status := "Valid"
	entries, err := store.ReadIndex()
	if err == nil {
		for _, e := range entries {
			if hex.EncodeToString(e.Serial) == serialHex {
				switch e.Status {
				case "V":
					if !e.Expiry.IsZero() && e.Expiry.Before(time.Now()) {
						status = "Expired"
					} else {
						status = "Valid"
					}
				case "R":
					status = "Revoked"
					if !e.Revocation.IsZero() {
						status = fmt.Sprintf("Revoked (%s)", e.Revocation.Format("2006-01-02"))
					}
				case "E":
					status = "Expired"
				}
				break
			}
		}
	}

	// Print certificate information
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
	var sans []string
	for _, dns := range cert.DNSNames {
		sans = append(sans, "DNS:"+dns)
	}
	for _, ip := range cert.IPAddresses {
		sans = append(sans, "IP:"+ip.String())
	}
	for _, email := range cert.EmailAddresses {
		sans = append(sans, "Email:"+email)
	}
	for _, uri := range cert.URIs {
		sans = append(sans, "URI:"+uri.String())
	}
	if len(sans) > 0 {
		fmt.Printf("SANs:          %s\n", strings.Join(sans, ", "))
	}

	// Key Usage
	var keyUsages []string
	if cert.KeyUsage&1 != 0 {
		keyUsages = append(keyUsages, "digitalSignature")
	}
	if cert.KeyUsage&2 != 0 {
		keyUsages = append(keyUsages, "contentCommitment")
	}
	if cert.KeyUsage&4 != 0 {
		keyUsages = append(keyUsages, "keyEncipherment")
	}
	if cert.KeyUsage&8 != 0 {
		keyUsages = append(keyUsages, "dataEncipherment")
	}
	if cert.KeyUsage&16 != 0 {
		keyUsages = append(keyUsages, "keyAgreement")
	}
	if cert.KeyUsage&32 != 0 {
		keyUsages = append(keyUsages, "keyCertSign")
	}
	if cert.KeyUsage&64 != 0 {
		keyUsages = append(keyUsages, "cRLSign")
	}
	if len(keyUsages) > 0 {
		fmt.Printf("Key Usage:     %s\n", strings.Join(keyUsages, ", "))
	}

	// Extended Key Usage
	var extKeyUsages []string
	for _, eku := range cert.ExtKeyUsage {
		switch eku {
		case 1:
			extKeyUsages = append(extKeyUsages, "serverAuth")
		case 2:
			extKeyUsages = append(extKeyUsages, "clientAuth")
		case 3:
			extKeyUsages = append(extKeyUsages, "codeSigning")
		case 4:
			extKeyUsages = append(extKeyUsages, "emailProtection")
		case 8:
			extKeyUsages = append(extKeyUsages, "timeStamping")
		case 9:
			extKeyUsages = append(extKeyUsages, "OCSPSigning")
		}
	}
	if len(extKeyUsages) > 0 {
		fmt.Printf("Ext Key Usage: %s\n", strings.Join(extKeyUsages, ", "))
	}

	// CA
	if cert.IsCA {
		pathLen := "unlimited"
		if cert.MaxPathLen >= 0 && cert.MaxPathLenZero {
			pathLen = "0"
		} else if cert.MaxPathLen >= 0 {
			pathLen = fmt.Sprintf("%d", cert.MaxPathLen)
		}
		fmt.Printf("CA:            yes (path length: %s)\n", pathLen)
	}

	fmt.Println()
	fmt.Printf("File:          %s\n", store.CertPath(serial))

	return nil
}
