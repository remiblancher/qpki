package main

import (
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/remiblancher/pki/internal/bundle"
	"github.com/remiblancher/pki/internal/ca"
	"github.com/remiblancher/pki/internal/profile"
)

var bundleCmd = &cobra.Command{
	Use:   "bundle",
	Short: "Manage certificate bundles",
	Long: `Manage certificate bundles with coupled lifecycle.

A bundle groups related certificates created from a profile:
  - All certificates share the same validity period
  - All certificates are renewed together
  - All certificates are revoked together

Examples:
  # List all bundles
  pki bundle list

  # Show bundle details
  pki bundle info alice-20250115-abcd1234

  # Renew a bundle
  pki bundle renew alice-20250115-abcd1234

  # Revoke a bundle
  pki bundle revoke alice-20250115-abcd1234 --reason keyCompromise

  # Export bundle certificates
  pki bundle export alice-20250115-abcd1234 --out alice.pem`,
}

var bundleListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all bundles",
	Long:  `List all bundles in the CA or specified directory.`,
	RunE:  runBundleList,
}

var bundleInfoCmd = &cobra.Command{
	Use:   "info <bundle-id>",
	Short: "Show bundle details",
	Long:  `Show detailed information about a specific bundle.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runBundleInfo,
}

var bundleRenewCmd = &cobra.Command{
	Use:   "renew <bundle-id>",
	Short: "Renew a bundle",
	Long: `Renew all certificates in a bundle.

This creates new certificates with the same subject and profile,
and marks the old bundle as expired.`,
	Args: cobra.ExactArgs(1),
	RunE: runBundleRenew,
}

var bundleRevokeCmd = &cobra.Command{
	Use:   "revoke <bundle-id>",
	Short: "Revoke a bundle",
	Long: `Revoke all certificates in a bundle.

All certificates are added to the CRL and the bundle is marked as revoked.`,
	Args: cobra.ExactArgs(1),
	RunE: runBundleRevoke,
}

var bundleExportCmd = &cobra.Command{
	Use:   "export <bundle-id>",
	Short: "Export bundle certificates",
	Long:  `Export all certificates from a bundle to a PEM file.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runBundleExport,
}

var (
	bundleCADir       string
	bundlePassphrase  string
	bundleRevokeReason string
	bundleExportOut   string
	bundleExportKeys  bool
)

func init() {
	// Add subcommands
	bundleCmd.AddCommand(bundleListCmd)
	bundleCmd.AddCommand(bundleInfoCmd)
	bundleCmd.AddCommand(bundleRenewCmd)
	bundleCmd.AddCommand(bundleRevokeCmd)
	bundleCmd.AddCommand(bundleExportCmd)

	// Global flags
	bundleCmd.PersistentFlags().StringVarP(&bundleCADir, "ca-dir", "c", "./ca", "CA directory")

	// Renew flags
	bundleRenewCmd.Flags().StringVarP(&bundlePassphrase, "passphrase", "p", "", "Passphrase for new private keys")

	// Revoke flags
	bundleRevokeCmd.Flags().StringVarP(&bundleRevokeReason, "reason", "r", "unspecified", "Revocation reason")

	// Export flags
	bundleExportCmd.Flags().StringVarP(&bundleExportOut, "out", "o", "", "Output file (default: stdout)")
	bundleExportCmd.Flags().BoolVar(&bundleExportKeys, "keys", false, "Include private keys (requires passphrase)")
	bundleExportCmd.Flags().StringVarP(&bundlePassphrase, "passphrase", "p", "", "Passphrase for private keys")
}

func runBundleList(cmd *cobra.Command, args []string) error {
	caDir, err := filepath.Abs(bundleCADir)
	if err != nil {
		return fmt.Errorf("invalid CA directory: %w", err)
	}

	bundleStore := bundle.NewFileStore(caDir)
	bundles, err := bundleStore.ListAll()
	if err != nil {
		return fmt.Errorf("failed to list bundles: %w", err)
	}

	if len(bundles) == 0 {
		fmt.Println("No bundles found.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tSUBJECT\tPROFILE\tSTATUS\tCERTS\tVALID UNTIL")
	fmt.Fprintln(w, "--\t-------\t-------\t------\t-----\t-----------")

	for _, b := range bundles {
		status := string(b.Status)
		if b.IsExpired() && b.Status == bundle.StatusValid {
			status = "expired"
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\n",
			b.ID,
			b.Subject.CommonName,
			b.Gamme,
			status,
			len(b.Certificates),
			b.NotAfter.Format("2006-01-02"))
	}

	w.Flush()
	return nil
}

func runBundleInfo(cmd *cobra.Command, args []string) error {
	bundleID := args[0]

	caDir, err := filepath.Abs(bundleCADir)
	if err != nil {
		return fmt.Errorf("invalid CA directory: %w", err)
	}

	bundleStore := bundle.NewFileStore(caDir)
	b, err := bundleStore.Load(bundleID)
	if err != nil {
		return fmt.Errorf("failed to load bundle: %w", err)
	}

	// Print bundle info
	fmt.Printf("Bundle ID:    %s\n", b.ID)
	fmt.Printf("Subject:      %s\n", b.Subject.CommonName)
	if len(b.Subject.Organization) > 0 {
		fmt.Printf("Organization: %s\n", b.Subject.Organization[0])
	}
	fmt.Printf("Profile:      %s\n", b.Gamme) // Legacy field name
	fmt.Printf("Status:       %s\n", b.Status)
	fmt.Printf("Created:      %s\n", b.Created.Format("2006-01-02 15:04:05"))
	fmt.Printf("Valid From:   %s\n", b.NotBefore.Format("2006-01-02 15:04:05"))
	fmt.Printf("Valid Until:  %s\n", b.NotAfter.Format("2006-01-02 15:04:05"))

	if b.RevokedAt != nil {
		fmt.Printf("Revoked At:   %s\n", b.RevokedAt.Format("2006-01-02 15:04:05"))
		fmt.Printf("Revoke Reason: %s\n", b.RevocationReason)
	}

	fmt.Println()
	fmt.Println("Certificates:")
	for i, cert := range b.Certificates {
		fmt.Printf("  [%d] %s\n", i+1, cert.Role)
		fmt.Printf("      Serial:      %s\n", cert.Serial)
		fmt.Printf("      Algorithm:   %s\n", cert.Algorithm)
		if cert.IsCatalyst {
			fmt.Printf("      Catalyst:    yes (alt: %s)\n", cert.AltAlgorithm)
		}
		if cert.RelatedSerial != "" {
			fmt.Printf("      Related to:  %s\n", cert.RelatedSerial)
		}
		fmt.Printf("      Fingerprint: %s\n", cert.Fingerprint)
	}

	if len(b.Metadata) > 0 {
		fmt.Println()
		fmt.Println("Metadata:")
		for k, v := range b.Metadata {
			fmt.Printf("  %s: %s\n", k, v)
		}
	}

	return nil
}

func runBundleRenew(cmd *cobra.Command, args []string) error {
	bundleID := args[0]

	caDir, err := filepath.Abs(bundleCADir)
	if err != nil {
		return fmt.Errorf("invalid CA directory: %w", err)
	}

	// Load CA
	caStore := ca.NewStore(caDir)
	caInstance, err := ca.New(caStore)
	if err != nil {
		return fmt.Errorf("failed to load CA: %w", err)
	}

	// Load profiles
	profileStore := profile.NewProfileStore(caDir)
	if err := profileStore.Load(); err != nil {
		return fmt.Errorf("failed to load profiles: %w", err)
	}

	// Load bundle store
	bundleStore := bundle.NewFileStore(caDir)

	// Renew
	passphrase := []byte(bundlePassphrase)
	result, err := caInstance.RenewBundle(bundleID, bundleStore, profileStore, passphrase)
	if err != nil {
		return fmt.Errorf("failed to renew bundle: %w", err)
	}

	fmt.Println("Bundle renewed successfully!")
	fmt.Println()
	fmt.Printf("Old bundle: %s (now expired)\n", bundleID)
	fmt.Printf("New bundle: %s\n", result.Bundle.ID)
	fmt.Printf("Valid:      %s to %s\n",
		result.Bundle.NotBefore.Format("2006-01-02"),
		result.Bundle.NotAfter.Format("2006-01-02"))
	fmt.Println()

	fmt.Println("New certificates:")
	for i := range result.Certificates {
		ref := result.Bundle.Certificates[i]
		fmt.Printf("  [%d] %s (%s) - Serial: %s\n", i+1, ref.Algorithm, ref.Role, ref.Serial)
	}

	return nil
}

func runBundleRevoke(cmd *cobra.Command, args []string) error {
	bundleID := args[0]

	caDir, err := filepath.Abs(bundleCADir)
	if err != nil {
		return fmt.Errorf("invalid CA directory: %w", err)
	}

	// Load CA
	caStore := ca.NewStore(caDir)
	caInstance, err := ca.New(caStore)
	if err != nil {
		return fmt.Errorf("failed to load CA: %w", err)
	}

	// Load bundle store
	bundleStore := bundle.NewFileStore(caDir)

	// Parse revocation reason
	reason := parseRevocationReason(bundleRevokeReason)

	// Revoke
	if err := caInstance.RevokeBundle(bundleID, reason, bundleStore); err != nil {
		return fmt.Errorf("failed to revoke bundle: %w", err)
	}

	fmt.Printf("Bundle %s revoked successfully.\n", bundleID)
	fmt.Printf("Reason: %s\n", reason)
	fmt.Println("All certificates in the bundle have been added to the CRL.")

	return nil
}

// parseRevocationReason converts a string to RevocationReason.
func parseRevocationReason(s string) ca.RevocationReason {
	switch s {
	case "keyCompromise":
		return ca.ReasonKeyCompromise
	case "caCompromise":
		return ca.ReasonCACompromise
	case "affiliationChanged":
		return ca.ReasonAffiliationChanged
	case "superseded":
		return ca.ReasonSuperseded
	case "cessationOfOperation":
		return ca.ReasonCessationOfOperation
	case "certificateHold":
		return ca.ReasonCertificateHold
	case "removeFromCRL":
		return ca.ReasonRemoveFromCRL
	case "privilegeWithdrawn":
		return ca.ReasonPrivilegeWithdrawn
	case "aaCompromise":
		return ca.ReasonAACompromise
	default:
		return ca.ReasonUnspecified
	}
}

func runBundleExport(cmd *cobra.Command, args []string) error {
	bundleID := args[0]

	caDir, err := filepath.Abs(bundleCADir)
	if err != nil {
		return fmt.Errorf("invalid CA directory: %w", err)
	}

	bundleStore := bundle.NewFileStore(caDir)

	// Load certificates
	certs, err := bundleStore.LoadCertificates(bundleID)
	if err != nil {
		return fmt.Errorf("failed to load certificates: %w", err)
	}

	// Encode to PEM
	pemData, err := bundle.EncodeCertificatesPEM(certs)
	if err != nil {
		return fmt.Errorf("failed to encode certificates: %w", err)
	}

	// If keys requested, load and append them
	if bundleExportKeys {
		if bundlePassphrase == "" {
			return fmt.Errorf("passphrase required for exporting keys")
		}

		signers, err := bundleStore.LoadKeys(bundleID, []byte(bundlePassphrase))
		if err != nil {
			return fmt.Errorf("failed to load keys: %w", err)
		}

		keysPEM, err := bundle.EncodePrivateKeysPEM(signers, []byte(bundlePassphrase))
		if err != nil {
			return fmt.Errorf("failed to encode keys: %w", err)
		}

		pemData = append(pemData, keysPEM...)
	}

	// Output
	if bundleExportOut == "" {
		fmt.Print(string(pemData))
	} else {
		if err := os.WriteFile(bundleExportOut, pemData, 0644); err != nil {
			return fmt.Errorf("failed to write file: %w", err)
		}
		fmt.Printf("Exported to %s\n", bundleExportOut)
	}

	return nil
}
