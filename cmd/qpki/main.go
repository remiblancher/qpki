// Command qpki is the CLI tool for Post-Quantum PKI (QPKI).
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/remiblancher/post-quantum-pki/internal/audit"
	"github.com/remiblancher/post-quantum-pki/internal/crypto"
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
	// Setup signal handler for clean PKCS#11 shutdown
	setupSignalHandler()

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		crypto.CloseAllPools() // Cleanup PKCS#11 before exit
		os.Exit(1)
	}

	// Cleanup PKCS#11 session pools on normal exit
	crypto.CloseAllPools()
}

// setupSignalHandler sets up a signal handler to cleanup PKCS#11 resources on SIGINT/SIGTERM.
// This prevents SIGSEGV crashes during program exit when HSM sessions are active.
func setupSignalHandler() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		crypto.CloseAllPools() // Cleanup PKCS#11 before exit
		os.Exit(0)
	}()
}

var rootCmd = &cobra.Command{
	Use:   "qpki",
	Short: "Post-Quantum PKI (QPKI) - A minimal, modular PKI toolkit",
	Long: `QPKI (Post-Quantum PKI) is a command-line tool for managing a Certificate Authority
supporting both classical and Post-Quantum Cryptography (PQC) algorithms.

QPKI provides quantum-safe migration through hybrid certificates, CSR workflows,
and NIST-standard PQC algorithms (ML-DSA, SLH-DSA, ML-KEM).

Supported algorithms:
  Classical: ECDSA (P-256, P-384, P-521), Ed25519, RSA (2048, 4096)
  PQC:       ML-DSA-44, ML-DSA-65, ML-DSA-87 (FIPS 204)
  Hybrid:    Classical signature + PQC extension

Examples:
  # Initialize a new root CA
  qpki ca init --profile ec/root-ca --var cn="My Root CA"

  # Issue certificate using credential enroll (generates key + certificate)
  qpki credential enroll --profile ec/tls-server --var cn=server.example.com --var dns_names=server.example.com

  # Or using CSR workflow
  qpki cert csr --algorithm ecdsa-p256 --keyout server.key --cn server.example.com --out server.csr
  qpki cert issue --profile ec/tls-server --csr server.csr --out server.crt

  # Generate a key pair
  qpki key gen --algorithm ml-dsa-65 --out ml-dsa-key.pem`,
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

	// Namespace commands
	rootCmd.AddCommand(caCmd)         // qpki ca ...
	rootCmd.AddCommand(certCmd)       // qpki cert ...
	rootCmd.AddCommand(credentialCmd) // qpki credential ...
	rootCmd.AddCommand(profileCmd)    // qpki profile ...

	// Top-level utilities
	rootCmd.AddCommand(inspectCmd)
	rootCmd.AddCommand(keyCmd) // qpki key ...
	rootCmd.AddCommand(auditCmd)

	// Timestamping (RFC 3161)
	rootCmd.AddCommand(tsaCmd)

	// CMS SignedData (RFC 5652)
	rootCmd.AddCommand(cmsCmd)

	// COSE/CWT (RFC 9052, RFC 8392)
	rootCmd.AddCommand(coseCmd)

	// OCSP (RFC 6960)
	rootCmd.AddCommand(ocspCmd)

	// HSM management (PKCS#11)
	rootCmd.AddCommand(hsmCmd)

	// CRL operations
	rootCmd.AddCommand(crlCmd)

	// CSR operations
	rootCmd.AddCommand(csrRootCmd)
}
