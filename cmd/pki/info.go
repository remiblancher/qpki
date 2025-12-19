package main

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/remiblancher/pki/internal/x509util"
)

var infoCmd = &cobra.Command{
	Use:   "info [file]",
	Short: "Display information about a certificate, key, or CRL",
	Long: `Display detailed information about a certificate, CSR, private key, or CRL.

Examples:
  # Show certificate information
  pki info server.crt

  # Show CSR information
  pki info request.csr

  # Show key information
  pki info key.pem

  # Show CRL information
  pki info ca.crl`,
	Args: cobra.ExactArgs(1),
	RunE: runInfo,
}

func runInfo(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return fmt.Errorf("no PEM data found in %s", filePath)
	}

	switch block.Type {
	case "CERTIFICATE":
		return showCertificate(block.Bytes)
	case "CERTIFICATE REQUEST":
		return showCSR(block.Bytes)
	case "PRIVATE KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY",
		"ML-DSA-44 PRIVATE KEY", "ML-DSA-65 PRIVATE KEY", "ML-DSA-87 PRIVATE KEY":
		return showPrivateKey(block)
	case "X509 CRL":
		return showCRL(block.Bytes)
	default:
		return fmt.Errorf("unknown PEM type: %s", block.Type)
	}
}

func showCertificate(der []byte) error {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	fmt.Println("Certificate:")
	fmt.Printf("  Version:        %d\n", cert.Version)
	fmt.Printf("  Serial Number:  %s\n", formatSerial(cert.SerialNumber.Bytes()))
	fmt.Printf("  Subject:        %s\n", cert.Subject.String())
	fmt.Printf("  Issuer:         %s\n", cert.Issuer.String())
	fmt.Printf("  Not Before:     %s\n", cert.NotBefore.Format("2006-01-02 15:04:05 UTC"))
	fmt.Printf("  Not After:      %s\n", cert.NotAfter.Format("2006-01-02 15:04:05 UTC"))

	fmt.Printf("  Signature Alg:  %s\n", cert.SignatureAlgorithm.String())
	fmt.Printf("  Public Key Alg: %s\n", cert.PublicKeyAlgorithm.String())

	if cert.IsCA {
		fmt.Printf("  CA:             true (path len: %d)\n", cert.MaxPathLen)
	} else {
		fmt.Printf("  CA:             false\n")
	}

	// Key Usage
	if cert.KeyUsage != 0 {
		fmt.Printf("  Key Usage:      %s\n", formatKeyUsage(cert.KeyUsage))
	}

	// Extended Key Usage
	if len(cert.ExtKeyUsage) > 0 {
		fmt.Printf("  Ext Key Usage:  %s\n", formatExtKeyUsage(cert.ExtKeyUsage))
	}

	// Subject Alternative Names
	if len(cert.DNSNames) > 0 {
		fmt.Printf("  DNS Names:      %s\n", strings.Join(cert.DNSNames, ", "))
	}
	if len(cert.IPAddresses) > 0 {
		ips := make([]string, len(cert.IPAddresses))
		for i, ip := range cert.IPAddresses {
			ips[i] = ip.String()
		}
		fmt.Printf("  IP Addresses:   %s\n", strings.Join(ips, ", "))
	}

	// Subject Key ID
	if len(cert.SubjectKeyId) > 0 {
		fmt.Printf("  Subject Key ID: %s\n", formatHex(cert.SubjectKeyId))
	}

	// Authority Key ID
	if len(cert.AuthorityKeyId) > 0 {
		fmt.Printf("  Auth Key ID:    %s\n", formatHex(cert.AuthorityKeyId))
	}

	// Check for hybrid extension
	hybridInfo, err := x509util.ParseHybridExtension(cert.Extensions)
	if err == nil && hybridInfo != nil {
		fmt.Printf("  Hybrid PQC:\n")
		fmt.Printf("    Algorithm:    %s\n", hybridInfo.Algorithm.Description())
		fmt.Printf("    Policy:       %s\n", hybridInfo.Policy.String())
		fmt.Printf("    Public Key:   %d bytes\n", len(hybridInfo.PublicKey))
	}

	return nil
}

func showCSR(der []byte) error {
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return fmt.Errorf("failed to parse CSR: %w", err)
	}

	fmt.Println("Certificate Signing Request:")
	fmt.Printf("  Subject:        %s\n", csr.Subject.String())
	fmt.Printf("  Signature Alg:  %s\n", csr.SignatureAlgorithm.String())
	fmt.Printf("  Public Key Alg: %s\n", csr.PublicKeyAlgorithm.String())

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

	// Verify signature
	if err := csr.CheckSignature(); err != nil {
		fmt.Printf("  Signature:      INVALID (%v)\n", err)
	} else {
		fmt.Printf("  Signature:      valid\n")
	}

	return nil
}

func showPrivateKey(block *pem.Block) error {
	fmt.Println("Private Key:")
	fmt.Printf("  Type:           %s\n", block.Type)

	if x509.IsEncryptedPEMBlock(block) { //nolint:staticcheck
		fmt.Printf("  Encrypted:      yes\n")
	} else {
		fmt.Printf("  Encrypted:      no\n")
	}

	fmt.Printf("  Size:           %d bytes\n", len(block.Bytes))

	return nil
}

func formatSerial(serial []byte) string {
	return hex.EncodeToString(serial)
}

func formatHex(data []byte) string {
	parts := make([]string, len(data))
	for i, b := range data {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

func formatKeyUsage(usage x509.KeyUsage) string {
	var usages []string
	if usage&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "Digital Signature")
	}
	if usage&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "Content Commitment")
	}
	if usage&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "Key Encipherment")
	}
	if usage&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "Data Encipherment")
	}
	if usage&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "Key Agreement")
	}
	if usage&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "Certificate Sign")
	}
	if usage&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRL Sign")
	}
	return strings.Join(usages, ", ")
}

func formatExtKeyUsage(usages []x509.ExtKeyUsage) string {
	var names []string
	for _, u := range usages {
		switch u {
		case x509.ExtKeyUsageServerAuth:
			names = append(names, "Server Auth")
		case x509.ExtKeyUsageClientAuth:
			names = append(names, "Client Auth")
		case x509.ExtKeyUsageCodeSigning:
			names = append(names, "Code Signing")
		case x509.ExtKeyUsageEmailProtection:
			names = append(names, "Email Protection")
		case x509.ExtKeyUsageTimeStamping:
			names = append(names, "Time Stamping")
		case x509.ExtKeyUsageOCSPSigning:
			names = append(names, "OCSP Signing")
		default:
			names = append(names, fmt.Sprintf("OID:%d", u))
		}
	}
	return strings.Join(names, ", ")
}

func showCRL(der []byte) error {
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		return fmt.Errorf("failed to parse CRL: %w", err)
	}

	fmt.Println("Certificate Revocation List:")
	fmt.Printf("  Issuer:         %s\n", crl.Issuer.String())
	fmt.Printf("  This Update:    %s\n", crl.ThisUpdate.Format("2006-01-02 15:04:05 UTC"))
	fmt.Printf("  Next Update:    %s\n", crl.NextUpdate.Format("2006-01-02 15:04:05 UTC"))
	fmt.Printf("  Signature Alg:  %s\n", crl.SignatureAlgorithm.String())

	if crl.Number != nil {
		fmt.Printf("  CRL Number:     %s\n", crl.Number.String())
	}

	if len(crl.AuthorityKeyId) > 0 {
		fmt.Printf("  Auth Key ID:    %s\n", formatHex(crl.AuthorityKeyId))
	}

	fmt.Printf("  Revoked Certs:  %d\n", len(crl.RevokedCertificateEntries))

	if len(crl.RevokedCertificateEntries) > 0 {
		fmt.Println("\n  Revoked Certificates:")
		for _, entry := range crl.RevokedCertificateEntries {
			fmt.Printf("    - Serial: %s\n", formatSerial(entry.SerialNumber.Bytes()))
			fmt.Printf("      Revoked: %s\n", entry.RevocationTime.Format("2006-01-02 15:04:05 UTC"))
			if entry.ReasonCode != 0 {
				fmt.Printf("      Reason: %s\n", formatRevocationReason(entry.ReasonCode))
			}
		}
	}

	return nil
}

func formatRevocationReason(reason int) string {
	reasons := map[int]string{
		0:  "Unspecified",
		1:  "Key Compromise",
		2:  "CA Compromise",
		3:  "Affiliation Changed",
		4:  "Superseded",
		5:  "Cessation Of Operation",
		6:  "Certificate Hold",
		8:  "Remove From CRL",
		9:  "Privilege Withdrawn",
		10: "AA Compromise",
	}
	if name, ok := reasons[reason]; ok {
		return name
	}
	return fmt.Sprintf("Unknown (%d)", reason)
}
