package main

import (
	"crypto/x509/pkix"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/remiblancher/pki/internal/bundle"
	"github.com/remiblancher/pki/internal/ca"
	"github.com/remiblancher/pki/internal/profile"
)

var enrollCmd = &cobra.Command{
	Use:   "enroll",
	Short: "Enroll a new certificate bundle using a profile",
	Long: `Enroll creates a complete certificate bundle based on a profile.

The enrollment process:
  1. Loads the specified profile from the CA
  2. Generates the required key pairs
  3. Issues all certificates defined by the profile
  4. Creates a bundle with coupled lifecycle
  5. Saves the bundle to the output directory

Examples:
  # Basic enrollment with default profile
  pki enroll --subject "CN=Alice,O=Acme" --profile classic

  # Full hybrid enrollment
  pki enroll --subject "CN=Alice,O=Acme" --profile hybrid-full --out ./alice

  # With SANs
  pki enroll --subject "CN=web.example.com" --profile pqc-basic \
      --dns web.example.com --dns www.example.com

  # With passphrase for private keys
  pki enroll --subject "CN=Alice" --profile hybrid-catalyst --passphrase mySecret`,
	RunE: runEnroll,
}

var (
	enrollSubject    string
	enrollProfile    string
	enrollCADir      string
	enrollOutDir     string
	enrollPassphrase string
	enrollDNSNames   []string
	enrollEmails     []string
)

func init() {
	enrollCmd.Flags().StringVarP(&enrollSubject, "subject", "s", "", "Certificate subject (required)")
	enrollCmd.Flags().StringVarP(&enrollProfile, "profile", "P", "classic", "Profile to use")
	enrollCmd.Flags().StringVarP(&enrollCADir, "ca-dir", "c", "./ca", "CA directory")
	enrollCmd.Flags().StringVarP(&enrollOutDir, "out", "o", "", "Output directory (default: current dir)")
	enrollCmd.Flags().StringVarP(&enrollPassphrase, "passphrase", "p", "", "Passphrase for private keys")
	enrollCmd.Flags().StringSliceVar(&enrollDNSNames, "dns", nil, "DNS SANs")
	enrollCmd.Flags().StringSliceVar(&enrollEmails, "email", nil, "Email SANs")

	_ = enrollCmd.MarkFlagRequired("subject")
}

func runEnroll(cmd *cobra.Command, args []string) error {
	// Parse subject
	subject, err := parseSubject(enrollSubject)
	if err != nil {
		return fmt.Errorf("invalid subject: %w", err)
	}

	// Resolve CA directory
	caDir, err := filepath.Abs(enrollCADir)
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

	// Verify profile exists
	prof, ok := profileStore.Get(enrollProfile)
	if !ok {
		return fmt.Errorf("profile not found: %s (available: %v)", enrollProfile, profileStore.List())
	}

	fmt.Printf("Enrolling with profile: %s\n", prof.Name)
	fmt.Printf("  %s\n", prof.Description)
	fmt.Printf("  Certificates: %d\n", prof.CertificateCount())
	fmt.Println()

	// Create enrollment request
	req := ca.EnrollmentRequest{
		Subject:        subject,
		ProfileName:    enrollProfile,
		DNSNames:       enrollDNSNames,
		EmailAddresses: enrollEmails,
	}

	// Enroll
	result, err := caInstance.Enroll(req, profileStore)
	if err != nil {
		return fmt.Errorf("enrollment failed: %w", err)
	}

	// Determine output directory
	outDir := enrollOutDir
	if outDir == "" {
		outDir = "."
	}
	outDir, err = filepath.Abs(outDir)
	if err != nil {
		return fmt.Errorf("invalid output directory: %w", err)
	}

	// Create output directory if needed
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Save bundle using bundle store
	bundleStore := bundle.NewFileStore(outDir)
	passphrase := []byte(enrollPassphrase)
	if err := bundleStore.Save(result.Bundle, result.Certificates, result.Signers, passphrase); err != nil {
		return fmt.Errorf("failed to save bundle: %w", err)
	}

	// Also save to CA's bundle store
	caBundleStore := bundle.NewFileStore(filepath.Join(caDir, "bundles"))
	if err := caBundleStore.Save(result.Bundle, result.Certificates, result.Signers, passphrase); err != nil {
		// Non-fatal, just warn
		fmt.Printf("Warning: failed to save bundle to CA: %v\n", err)
	}

	// Print result
	fmt.Println("Enrollment successful!")
	fmt.Println()
	fmt.Printf("Bundle ID: %s\n", result.Bundle.ID)
	fmt.Printf("Subject:   %s\n", result.Bundle.Subject.CommonName)
	fmt.Printf("Profile:   %s\n", result.Bundle.Gamme) // Legacy field name
	fmt.Printf("Valid:     %s to %s\n",
		result.Bundle.NotBefore.Format("2006-01-02"),
		result.Bundle.NotAfter.Format("2006-01-02"))
	fmt.Println()

	fmt.Println("Certificates issued:")
	for i := range result.Certificates {
		ref := result.Bundle.Certificates[i]
		fmt.Printf("  [%d] %s (%s)\n", i+1, ref.Algorithm, ref.Role)
		fmt.Printf("      Serial: %s\n", ref.Serial)
		if ref.IsCatalyst {
			fmt.Printf("      Catalyst: %s + %s\n", ref.Algorithm, ref.AltAlgorithm)
		}
	}
	fmt.Println()

	fmt.Println("Files created:")
	bundleDir := filepath.Join(outDir, "bundles", result.Bundle.ID)
	fmt.Printf("  %s/bundle.json\n", bundleDir)
	fmt.Printf("  %s/certificates.pem\n", bundleDir)
	fmt.Printf("  %s/private-keys.pem\n", bundleDir)

	return nil
}

// parseSubject parses a subject string like "CN=Alice,O=Acme,C=FR"
func parseSubject(s string) (pkix.Name, error) {
	name := pkix.Name{}

	parts := strings.Split(s, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			return name, fmt.Errorf("invalid subject part: %s", part)
		}

		key := strings.ToUpper(strings.TrimSpace(kv[0]))
		value := strings.TrimSpace(kv[1])

		switch key {
		case "CN":
			name.CommonName = value
		case "O":
			name.Organization = append(name.Organization, value)
		case "OU":
			name.OrganizationalUnit = append(name.OrganizationalUnit, value)
		case "C":
			name.Country = append(name.Country, value)
		case "ST", "S":
			name.Province = append(name.Province, value)
		case "L":
			name.Locality = append(name.Locality, value)
		default:
			return name, fmt.Errorf("unknown subject attribute: %s", key)
		}
	}

	if name.CommonName == "" {
		return name, fmt.Errorf("CN (CommonName) is required")
	}

	return name, nil
}
