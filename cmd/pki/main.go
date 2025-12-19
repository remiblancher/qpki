// Command pki is a CLI tool for managing a post-quantum ready PKI.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/remiblancher/pki/internal/audit"
)

// Build-time variables (injected by GoReleaser)
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// Global flags
var auditLogPath string

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
  pki issue --profile ecdsa/tls-server --cn server.example.com --dns server.example.com

  # Enroll a bundle with hybrid profile
  pki enroll --subject "CN=Alice,O=Acme" --profile hybrid/catalyst/tls-client

  # Generate a key pair
  pki genkey --algorithm ml-dsa-65 --out ml-dsa-key.pem`,
	Version: fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, date),
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Check for audit log path from environment if not set via flag
		if auditLogPath == "" {
			auditLogPath = os.Getenv("PKI_AUDIT_LOG")
		}

		// Initialize audit logging
		if auditLogPath != "" {
			if err := audit.InitFile(auditLogPath); err != nil {
				return fmt.Errorf("failed to initialize audit log: %w", err)
			}
		}
		return nil
	},
	PersistentPostRunE: func(cmd *cobra.Command, args []string) error {
		// Close audit log
		return audit.Close()
	},
}

func init() {
	// Global persistent flags
	rootCmd.PersistentFlags().StringVar(&auditLogPath, "audit-log", "",
		"Path to audit log file (or set PKI_AUDIT_LOG env var)")

	// Add subcommands
	rootCmd.AddCommand(initCACmd)
	rootCmd.AddCommand(issueCmd)
	rootCmd.AddCommand(genkeyCmd)
	rootCmd.AddCommand(infoCmd)
	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(auditCmd)

	// Profile and bundle management
	rootCmd.AddCommand(profileCmd)
	rootCmd.AddCommand(enrollCmd)
	rootCmd.AddCommand(bundleCmd)

	// Timestamping (RFC 3161)
	rootCmd.AddCommand(tsaCmd)

	// CMS SignedData (RFC 5652)
	rootCmd.AddCommand(cmsCmd)
}
