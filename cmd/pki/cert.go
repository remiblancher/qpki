package main

import (
	"github.com/spf13/cobra"
)

// certCmd is the parent command for certificate operations.
var certCmd = &cobra.Command{
	Use:   "cert",
	Short: "Certificate operations",
	Long: `Manage certificates using the traditional CSR workflow.

Commands:
  issue   Issue a certificate from a CSR
  csr     Generate a Certificate Signing Request
  list    List issued certificates
  revoke  Revoke a certificate

For direct enrollment (key + certificate in one step), use 'pki credential enroll'.

Examples:
  # Generate a CSR
  pki cert csr --algorithm ecdsa-p256 --keyout server.key --cn server.example.com -o server.csr

  # Issue certificate from CSR
  pki cert issue --profile ec/tls-server --csr server.csr --out server.crt

  # List all certificates
  pki cert list --ca-dir ./ca

  # Revoke a certificate
  pki cert revoke 02 --reason superseded`,
}

func init() {
	// Add subcommands
	certCmd.AddCommand(issueCmd)
	certCmd.AddCommand(csrCmd)
	certCmd.AddCommand(listCmd)
	certCmd.AddCommand(revokeCmd)
	certCmd.AddCommand(genCRLCmd)
}
