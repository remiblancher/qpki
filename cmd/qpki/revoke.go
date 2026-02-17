package main

import (
	"encoding/hex"
	"fmt"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/remiblancher/post-quantum-pki/pkg/ca"
)

var revokeCmd = &cobra.Command{
	Use:   "revoke [serial]",
	Short: "Revoke a certificate",
	Long: `Revoke a certificate by its serial number.

Revocation reasons:
  unspecified         - No specific reason (default)
  keyCompromise       - Private key was compromised
  caCompromise        - CA's private key was compromised
  affiliationChanged  - Subject's name or affiliation changed
  superseded          - Certificate was replaced by a new one
  cessation           - Certificate is no longer needed
  hold                - Certificate is temporarily on hold

Examples:
  # Revoke certificate by serial
  pki revoke 02

  # Revoke with reason
  pki revoke 02 --reason superseded

  # Revoke and generate new CRL
  pki revoke 02 --gen-crl`,
	Args: cobra.ExactArgs(1),
	RunE: runRevoke,
}

var (
	revokeCADir        string
	revokeReason       string
	revokeCAPassphrase string
	revokeGenCRL       bool
	revokeCRLDays      int
)

func init() {
	flags := revokeCmd.Flags()
	flags.StringVarP(&revokeCADir, "ca-dir", "d", "./ca", "CA directory")
	flags.StringVarP(&revokeReason, "reason", "r", "unspecified", "Revocation reason")
	flags.StringVar(&revokeCAPassphrase, "ca-passphrase", "", "CA private key passphrase")
	flags.BoolVar(&revokeGenCRL, "gen-crl", false, "Generate new CRL after revocation")
	flags.IntVar(&revokeCRLDays, "crl-days", 7, "CRL validity in days")
}

func runRevoke(cmd *cobra.Command, args []string) error {
	serialHex := args[0]
	serial, err := hex.DecodeString(serialHex)
	if err != nil {
		return fmt.Errorf("invalid serial number: %w", err)
	}

	reason, err := ca.ParseRevocationReason(revokeReason)
	if err != nil {
		return err
	}

	// Load CA
	absDir, _ := filepath.Abs(revokeCADir)
	store := ca.NewFileStore(absDir)
	if !store.Exists() {
		return fmt.Errorf("CA not found at %s", absDir)
	}

	caInstance, err := ca.NewWithSigner(store, nil)
	if err != nil {
		return fmt.Errorf("failed to load CA: %w", err)
	}
	defer func() { _ = caInstance.Close() }()

	if err := caInstance.LoadSigner(revokeCAPassphrase); err != nil {
		return fmt.Errorf("failed to load CA signer: %w", err)
	}

	// Revoke the certificate
	if err := caInstance.Revoke(serial, reason); err != nil {
		return fmt.Errorf("failed to revoke certificate: %w", err)
	}

	fmt.Printf("Certificate %s revoked successfully.\n", serialHex)
	fmt.Printf("  Reason: %s\n", reason.String())

	// Generate CRL if requested
	if revokeGenCRL {
		nextUpdate := time.Now().AddDate(0, 0, revokeCRLDays)
		crlDER, err := caInstance.GenerateCRL(nextUpdate)
		if err != nil {
			return fmt.Errorf("failed to generate CRL: %w", err)
		}

		fmt.Printf("\nCRL generated successfully.\n")
		fmt.Printf("  CRL file: %s\n", store.CRLPath())
		fmt.Printf("  Size: %d bytes\n", len(crlDER))
		fmt.Printf("  Next update: %s\n", nextUpdate.Format("2006-01-02 15:04:05"))
	} else {
		fmt.Println("\nNote: Run 'pki ca crl gen' to update the CRL.")
	}

	return nil
}
