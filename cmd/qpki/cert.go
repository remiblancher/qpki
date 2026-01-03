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
  list    List issued certificates
  info    Display certificate information
  revoke  Revoke a certificate
  verify  Verify a certificate's validity

For CSR generation, use 'qpki csr gen'.
For direct enrollment (key + certificate in one step), use 'qpki credential enroll'.

Examples:
  # Issue certificate from CSR
  qpki cert issue --profile ec/tls-server --csr server.csr --out server.crt

  # List all certificates
  qpki cert list --ca-dir ./ca

  # Verify a certificate
  qpki cert verify --cert server.crt --ca ca.crt

  # Revoke a certificate
  qpki cert revoke 02 --reason superseded`,
}

func init() {
	// Add subcommands
	certCmd.AddCommand(issueCmd)
	certCmd.AddCommand(listCmd)
	certCmd.AddCommand(certInfoCmd)
	certCmd.AddCommand(revokeCmd)
}
