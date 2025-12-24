package main

import (
	"crypto/x509/pkix"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

A bundle groups related certificates created from one or more profiles:
  - All certificates share the same validity period
  - All certificates are renewed together
  - All certificates are revoked together

Examples:
  # Create a bundle with one profile
  pki bundle enroll --profile ec/tls-client --subject "CN=Alice"

  # Create a bundle with multiple profiles (crypto-agility)
  pki bundle enroll --profile ec/client --profile ml-dsa-kem/client --subject "CN=Alice"

  # Create a bundle with custom ID
  pki bundle enroll --profile ec/tls-client --subject "CN=Alice" --id alice-prod

  # List all bundles
  pki bundle list

  # Show bundle details
  pki bundle info alice-20250115-abcd1234

  # Renew a bundle (same profiles)
  pki bundle renew alice-20250115-abcd1234

  # Renew with crypto migration (add/change profiles)
  pki bundle renew alice-20250115-abcd1234 --profile ec/client --profile ml-dsa-kem/client

  # Revoke a bundle
  pki bundle revoke alice-20250115-abcd1234 --reason keyCompromise

  # Export bundle certificates
  pki bundle export alice-20250115-abcd1234 --out alice.pem`,
}

var bundleEnrollCmd = &cobra.Command{
	Use:   "enroll",
	Short: "Create a new bundle",
	Long: `Create a new certificate bundle from one or more profiles.

Each profile creates one certificate. Use multiple --profile flags for
multi-certificate bundles (e.g., signature + encryption, classical + PQC).

The bundle ID is auto-generated as {cn-slug}-{YYYYMMDD}-{hash}, or you can
provide a custom ID with --id.`,
	RunE: runBundleEnroll,
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

This creates new certificates with the same subject and marks the old
bundle as expired.

By default, uses the same profiles as the original bundle. Use --profile
to change profiles during renewal (crypto-agility):

  # Standard renewal (same profiles)
  pki bundle renew alice-20250115-abc123

  # Add PQC during renewal
  pki bundle renew alice-20250115-abc123 --profile ec/client --profile ml-dsa-kem/client

  # Remove legacy algorithms
  pki bundle renew alice-20250115-abc123 --profile ml-dsa-kem/client`,
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
	bundleCADir        string
	bundlePassphrase   string
	bundleRevokeReason string
	bundleExportOut    string
	bundleExportKeys   bool

	// Enroll flags
	bundleEnrollProfiles []string
	bundleEnrollSubject  string
	bundleEnrollID       string
	bundleEnrollDNS      []string
	bundleEnrollEmail    []string

	// Renew flags (crypto-agility)
	bundleRenewProfiles []string
)

func init() {
	// Add subcommands
	bundleCmd.AddCommand(bundleEnrollCmd)
	bundleCmd.AddCommand(bundleListCmd)
	bundleCmd.AddCommand(bundleInfoCmd)
	bundleCmd.AddCommand(bundleRenewCmd)
	bundleCmd.AddCommand(bundleRevokeCmd)
	bundleCmd.AddCommand(bundleExportCmd)

	// Global flags
	bundleCmd.PersistentFlags().StringVarP(&bundleCADir, "ca-dir", "c", "./ca", "CA directory")

	// Enroll flags
	bundleEnrollCmd.Flags().StringSliceVarP(&bundleEnrollProfiles, "profile", "P", nil, "Profile(s) to use (repeatable)")
	bundleEnrollCmd.Flags().StringVarP(&bundleEnrollSubject, "subject", "s", "", "Subject DN (e.g., 'CN=Alice,O=Acme')")
	bundleEnrollCmd.Flags().StringVar(&bundleEnrollID, "id", "", "Custom bundle ID (auto-generated if not set)")
	bundleEnrollCmd.Flags().StringSliceVar(&bundleEnrollDNS, "dns", nil, "DNS SANs (repeatable)")
	bundleEnrollCmd.Flags().StringSliceVar(&bundleEnrollEmail, "email", nil, "Email SANs (repeatable)")
	bundleEnrollCmd.Flags().StringVarP(&bundlePassphrase, "passphrase", "p", "", "Passphrase for private keys")
	_ = bundleEnrollCmd.MarkFlagRequired("profile")
	_ = bundleEnrollCmd.MarkFlagRequired("subject")

	// Renew flags
	bundleRenewCmd.Flags().StringVarP(&bundlePassphrase, "passphrase", "p", "", "Passphrase for new private keys")
	bundleRenewCmd.Flags().StringSliceVarP(&bundleRenewProfiles, "profile", "P", nil, "New profile(s) for crypto-agility (optional)")

	// Revoke flags
	bundleRevokeCmd.Flags().StringVarP(&bundleRevokeReason, "reason", "r", "unspecified", "Revocation reason")
	bundleRevokeCmd.Flags().StringVarP(&bundlePassphrase, "passphrase", "p", "", "Passphrase for CA key")

	// Export flags
	bundleExportCmd.Flags().StringVarP(&bundleExportOut, "out", "o", "", "Output file (default: stdout)")
	bundleExportCmd.Flags().BoolVar(&bundleExportKeys, "keys", false, "Include private keys (requires passphrase)")
	bundleExportCmd.Flags().StringVarP(&bundlePassphrase, "passphrase", "p", "", "Passphrase for private keys")
}

func runBundleEnroll(cmd *cobra.Command, args []string) error {
	caDir, err := filepath.Abs(bundleCADir)
	if err != nil {
		return fmt.Errorf("invalid CA directory: %w", err)
	}

	// Parse subject DN
	subject, err := parseSubjectDN(bundleEnrollSubject)
	if err != nil {
		return fmt.Errorf("invalid subject: %w", err)
	}

	// Load CA
	caStore := ca.NewStore(caDir)
	caInstance, err := ca.New(caStore)
	if err != nil {
		return fmt.Errorf("failed to load CA: %w", err)
	}

	// Load CA signer (private key)
	if err := caInstance.LoadSigner(bundlePassphrase); err != nil {
		return fmt.Errorf("failed to load CA signer: %w", err)
	}

	// Load profiles
	profileStore := profile.NewProfileStore(caDir)
	if err := profileStore.Load(); err != nil {
		return fmt.Errorf("failed to load profiles: %w", err)
	}

	// Resolve profiles
	profiles := make([]*profile.Profile, 0, len(bundleEnrollProfiles))
	for _, name := range bundleEnrollProfiles {
		prof, ok := profileStore.Get(name)
		if !ok {
			return fmt.Errorf("profile not found: %s", name)
		}
		profiles = append(profiles, prof)
	}

	// Create enrollment request
	req := ca.EnrollmentRequest{
		Subject:        subject,
		DNSNames:       bundleEnrollDNS,
		EmailAddresses: bundleEnrollEmail,
	}

	// Enroll
	var result *ca.EnrollmentResult
	if len(profiles) == 1 {
		result, err = caInstance.EnrollWithProfile(req, profiles[0])
	} else {
		result, err = caInstance.EnrollMulti(req, profiles)
	}
	if err != nil {
		return fmt.Errorf("failed to enroll: %w", err)
	}

	// Override bundle ID if custom one provided
	if bundleEnrollID != "" {
		result.Bundle.ID = bundleEnrollID
	}

	// Save bundle
	bundleStore := bundle.NewFileStore(caDir)
	passphrase := []byte(bundlePassphrase)
	if err := bundleStore.Save(result.Bundle, result.Certificates, result.Signers, passphrase); err != nil {
		return fmt.Errorf("failed to save bundle: %w", err)
	}

	// Output
	fmt.Println("Bundle created successfully!")
	fmt.Println()
	fmt.Printf("Bundle ID: %s\n", result.Bundle.ID)
	fmt.Printf("Subject:   %s\n", result.Bundle.Subject.CommonName)
	fmt.Printf("Profiles:  %s\n", strings.Join(result.Bundle.Profiles, ", "))
	fmt.Printf("Valid:     %s to %s\n",
		result.Bundle.NotBefore.Format("2006-01-02"),
		result.Bundle.NotAfter.Format("2006-01-02"))
	fmt.Println()

	fmt.Println("Certificates:")
	for i := range result.Certificates {
		ref := result.Bundle.Certificates[i]
		fmt.Printf("  [%d] %s (%s) - Serial: %s\n", i+1, ref.Algorithm, ref.Role, ref.Serial)
		if ref.Profile != "" {
			fmt.Printf("      Profile: %s\n", ref.Profile)
		}
	}

	return nil
}

// parseSubjectDN parses a subject DN string like "CN=Alice,O=Acme" into pkix.Name.
func parseSubjectDN(dn string) (pkix.Name, error) {
	result := pkix.Name{}

	if dn == "" {
		return result, fmt.Errorf("subject DN cannot be empty")
	}

	parts := strings.Split(dn, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			return result, fmt.Errorf("invalid DN component: %s", part)
		}

		key := strings.ToUpper(strings.TrimSpace(kv[0]))
		value := strings.TrimSpace(kv[1])

		switch key {
		case "CN":
			result.CommonName = value
		case "O":
			result.Organization = append(result.Organization, value)
		case "OU":
			result.OrganizationalUnit = append(result.OrganizationalUnit, value)
		case "C":
			result.Country = append(result.Country, value)
		case "ST", "S":
			result.Province = append(result.Province, value)
		case "L":
			result.Locality = append(result.Locality, value)
		default:
			return result, fmt.Errorf("unknown DN attribute: %s", key)
		}
	}

	if result.CommonName == "" {
		return result, fmt.Errorf("CN (CommonName) is required")
	}

	return result, nil
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
	fmt.Fprintln(w, "ID\tSUBJECT\tPROFILES\tSTATUS\tCERTS\tVALID UNTIL")
	fmt.Fprintln(w, "--\t-------\t--------\t------\t-----\t-----------")

	for _, b := range bundles {
		status := string(b.Status)
		if b.IsExpired() && b.Status == bundle.StatusValid {
			status = "expired"
		}

		profiles := strings.Join(b.Profiles, ", ")
		if len(profiles) > 40 {
			profiles = profiles[:37] + "..."
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\n",
			b.ID,
			b.Subject.CommonName,
			profiles,
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
	fmt.Printf("Profiles:     %s\n", strings.Join(b.Profiles, ", "))
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

	// Load CA signer (private key)
	if err := caInstance.LoadSigner(bundlePassphrase); err != nil {
		return fmt.Errorf("failed to load CA signer: %w", err)
	}

	// Load profiles
	profileStore := profile.NewProfileStore(caDir)
	if err := profileStore.Load(); err != nil {
		return fmt.Errorf("failed to load profiles: %w", err)
	}

	// Load bundle store
	bundleStore := bundle.NewFileStore(caDir)

	// Renew (pass new profiles for crypto-agility if specified)
	passphrase := []byte(bundlePassphrase)
	result, err := caInstance.RenewBundle(bundleID, bundleStore, profileStore, passphrase, bundleRenewProfiles)
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

	// Load CA signer (private key) - needed for CRL generation
	if err := caInstance.LoadSigner(bundlePassphrase); err != nil {
		return fmt.Errorf("failed to load CA signer: %w", err)
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
