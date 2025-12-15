// Command pki is a CLI tool for managing a post-quantum ready PKI.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var version = "0.1.0"

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "pki",
	Short: "A post-quantum ready PKI toolkit",
	Long: `PKI is a command-line tool for managing a Certificate Authority
with support for classical and post-quantum cryptographic algorithms.

Supported algorithms:
  Classical: ECDSA (P-256, P-384, P-521), Ed25519, RSA (2048, 4096)
  PQC:       ML-DSA-44, ML-DSA-65, ML-DSA-87 (FIPS 204)
  Hybrid:    Classical signature + PQC extension

Examples:
  # Initialize a new root CA
  pki init-ca --name "My Root CA" --algorithm ecdsa-p256

  # Issue a TLS server certificate
  pki issue --profile tls-server --cn server.example.com --dns server.example.com

  # Generate a key pair
  pki genkey --algorithm ml-dsa-65 --out ml-dsa-key.pem`,
	Version: version,
}

func init() {
	rootCmd.AddCommand(initCACmd)
	rootCmd.AddCommand(issueCmd)
	rootCmd.AddCommand(genkeyCmd)
	rootCmd.AddCommand(infoCmd)
	rootCmd.AddCommand(listCmd)
}
