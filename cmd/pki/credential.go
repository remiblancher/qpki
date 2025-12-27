package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/remiblancher/pki/internal/ca"
	"github.com/remiblancher/pki/internal/credential"
	pkicrypto "github.com/remiblancher/pki/internal/crypto"
	"github.com/remiblancher/pki/internal/profile"
)

var credentialCmd = &cobra.Command{
	Use:   "credential",
	Short: "Manage certificate credentials",
	Long: `Manage certificate credentials with coupled lifecycle.

A credential groups related certificates created from one or more profiles:
  - All certificates share the same validity period
  - All certificates are renewed together
  - All certificates are revoked together

Examples:
  # Create a credential with one profile
  pki credential enroll --profile ec/tls-client --var cn=alice

  # Create a credential with multiple profiles (crypto-agility)
  pki credential enroll --profile ec/client --profile ml-dsa-kem/client --var cn=alice

  # Create a credential with custom ID
  pki credential enroll --profile ec/tls-client --var cn=alice --id alice-prod

  # List all credentials
  pki credential list

  # Show credential details
  pki credential info alice-20250115-abcd1234

  # Renew a credential (same profiles)
  pki credential renew alice-20250115-abcd1234

  # Renew with crypto migration (add/change profiles)
  pki credential renew alice-20250115-abcd1234 --profile ec/client --profile ml-dsa-kem/client

  # Revoke a credential
  pki credential revoke alice-20250115-abcd1234 --reason keyCompromise

  # Export credential certificates
  pki credential export alice-20250115-abcd1234 --out alice.pem`,
}

var credEnrollCmd = &cobra.Command{
	Use:   "enroll",
	Short: "Create a new credential",
	Long: `Create a new certificate credential from one or more profiles.

Each profile creates one certificate. Use multiple --profile flags for
multi-certificate credentials (e.g., signature + encryption, classical + PQC).

The credential ID is auto-generated as {cn-slug}-{YYYYMMDD}-{hash}, or you can
provide a custom ID with --id.

Variables can be provided via --var flags or --var-file. When a profile
declares variables, they are validated against the profile constraints
(pattern, enum, min/max, allowed_suffixes, etc.).

Examples:
  # Basic usage with variables
  pki credential enroll --profile ec/tls-server \
      --var cn=api.example.com \
      --var dns_names=api.example.com,api2.example.com

  # Using a variables file
  pki credential enroll --profile ec/tls-server --var-file vars.yaml

  # Mix: file + override with --var
  pki credential enroll --profile ec/tls-server \
      --var-file defaults.yaml \
      --var cn=custom.example.com`,
	RunE: runCredEnroll,
}

var credListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all credentials",
	Long:  `List all credentials in the CA or specified directory.`,
	RunE:  runCredList,
}

var credInfoCmd = &cobra.Command{
	Use:   "info <credential-id>",
	Short: "Show credential details",
	Long:  `Show detailed information about a specific credential.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runCredInfo,
}

var credRenewCmd = &cobra.Command{
	Use:   "renew <credential-id>",
	Short: "Renew a credential",
	Long: `Renew all certificates in a credential.

This creates new certificates with the same subject and marks the old
credential as expired.

By default, uses the same profiles as the original credential. Use --profile
to change profiles during renewal (crypto-agility):

  # Standard renewal (same profiles)
  pki credential renew alice-20250115-abc123

  # Add PQC during renewal
  pki credential renew alice-20250115-abc123 --profile ec/client --profile ml-dsa-kem/client

  # Remove legacy algorithms
  pki credential renew alice-20250115-abc123 --profile ml-dsa-kem/client`,
	Args: cobra.ExactArgs(1),
	RunE: runCredRenew,
}

var credRevokeCmd = &cobra.Command{
	Use:   "revoke <credential-id>",
	Short: "Revoke a credential",
	Long: `Revoke all certificates in a credential.

All certificates are added to the CRL and the credential is marked as revoked.`,
	Args: cobra.ExactArgs(1),
	RunE: runCredRevoke,
}

var credExportCmd = &cobra.Command{
	Use:   "export <credential-id>",
	Short: "Export credential certificates",
	Long:  `Export all certificates from a credential to a PEM file.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runCredExport,
}

var credImportCmd = &cobra.Command{
	Use:   "import",
	Short: "Import existing certificate and key as credential",
	Long: `Import an existing certificate and private key as a new credential.

This is useful for migrating certificates issued by external CAs or
bringing legacy certificates under PKI management.

The imported credential will have status "valid" and can be managed
like any other credential (list, info, export).

Note: Imported credentials cannot be renewed or revoked through this CA
since they were not issued by it.

Examples:
  # Import certificate and key
  pki credential import --cert server.crt --key server.key

  # Import with custom ID
  pki credential import --cert server.crt --key server.key --id legacy-server

  # Import encrypted key
  pki credential import --cert server.crt --key server.key --passphrase secret`,
	RunE: runCredImport,
}

var (
	credCADir        string
	credPassphrase   string
	credRevokeReason string
	credExportOut    string
	credExportKeys   bool

	// Enroll flags
	credEnrollProfiles []string
	credEnrollID       string
	credEnrollVars     []string // --var key=value
	credEnrollVarFile  string   // --var-file vars.yaml

	// Renew flags (crypto-agility)
	credRenewProfiles []string

	// Import flags
	credImportCert string
	credImportKey  string
	credImportID   string
)

func init() {
	// Add subcommands
	credentialCmd.AddCommand(credEnrollCmd)
	credentialCmd.AddCommand(credListCmd)
	credentialCmd.AddCommand(credInfoCmd)
	credentialCmd.AddCommand(credRenewCmd)
	credentialCmd.AddCommand(credRevokeCmd)
	credentialCmd.AddCommand(credExportCmd)

	// Global flags
	credentialCmd.PersistentFlags().StringVarP(&credCADir, "ca-dir", "d", "./ca", "CA directory")

	// Enroll flags
	credEnrollCmd.Flags().StringSliceVarP(&credEnrollProfiles, "profile", "P", nil, "Profile(s) to use (repeatable)")
	credEnrollCmd.Flags().StringVar(&credEnrollID, "id", "", "Custom credential ID (auto-generated if not set)")
	credEnrollCmd.Flags().StringArrayVar(&credEnrollVars, "var", nil, "Variable value (key=value, repeatable)")
	credEnrollCmd.Flags().StringVar(&credEnrollVarFile, "var-file", "", "YAML file with variable values")
	credEnrollCmd.Flags().StringVarP(&credPassphrase, "passphrase", "p", "", "Passphrase for private keys")
	_ = credEnrollCmd.MarkFlagRequired("profile")

	// Renew flags
	credRenewCmd.Flags().StringVarP(&credPassphrase, "passphrase", "p", "", "Passphrase for new private keys")
	credRenewCmd.Flags().StringSliceVarP(&credRenewProfiles, "profile", "P", nil, "New profile(s) for crypto-agility (optional)")

	// Revoke flags
	credRevokeCmd.Flags().StringVarP(&credRevokeReason, "reason", "r", "unspecified", "Revocation reason")
	credRevokeCmd.Flags().StringVarP(&credPassphrase, "passphrase", "p", "", "Passphrase for CA key")

	// Export flags
	credExportCmd.Flags().StringVarP(&credExportOut, "out", "o", "", "Output file (default: stdout)")
	credExportCmd.Flags().BoolVar(&credExportKeys, "keys", false, "Include private keys (requires passphrase)")
	credExportCmd.Flags().StringVarP(&credPassphrase, "passphrase", "p", "", "Passphrase for private keys")

	// Import command
	credentialCmd.AddCommand(credImportCmd)
	credImportCmd.Flags().StringVar(&credImportCert, "cert", "", "Certificate file (required)")
	credImportCmd.Flags().StringVar(&credImportKey, "key", "", "Private key file (required)")
	credImportCmd.Flags().StringVar(&credImportID, "id", "", "Credential ID (auto-generated if not set)")
	credImportCmd.Flags().StringVarP(&credPassphrase, "passphrase", "p", "", "Passphrase for private key")
	_ = credImportCmd.MarkFlagRequired("cert")
	_ = credImportCmd.MarkFlagRequired("key")
}

// loadCASigner loads the CA signer, automatically detecting hybrid vs regular CAs.
// For hybrid CAs (with .pqc key file), it loads the HybridSigner.
// For regular CAs, it loads the standard signer.
func loadCASigner(caInstance *ca.CA, caDir, passphrase string) error {
	pqcKeyPath := filepath.Join(caDir, "private", "ca.key.pqc")
	if _, err := os.Stat(pqcKeyPath); err == nil {
		// Hybrid CA - load both keys
		return caInstance.LoadHybridSigner(passphrase, passphrase)
	}
	// Regular CA
	return caInstance.LoadSigner(passphrase)
}

func runCredEnroll(cmd *cobra.Command, args []string) error {
	caDir, err := filepath.Abs(credCADir)
	if err != nil {
		return fmt.Errorf("invalid CA directory: %w", err)
	}

	// Load CA
	caStore := ca.NewStore(caDir)
	caInstance, err := ca.New(caStore)
	if err != nil {
		return fmt.Errorf("failed to load CA: %w", err)
	}

	// Load CA signer (private key) - auto-detects hybrid vs regular
	if err := loadCASigner(caInstance, caDir, credPassphrase); err != nil {
		return fmt.Errorf("failed to load CA signer: %w", err)
	}

	// Load profiles
	profileStore := profile.NewProfileStore(caDir)
	if err := profileStore.Load(); err != nil {
		return fmt.Errorf("failed to load profiles: %w", err)
	}

	// Resolve profiles
	profiles := make([]*profile.Profile, 0, len(credEnrollProfiles))
	for _, name := range credEnrollProfiles {
		prof, ok := profileStore.Get(name)
		if !ok {
			return fmt.Errorf("profile not found: %s", name)
		}
		profiles = append(profiles, prof)
	}

	// Load variables from file and/or flags
	varValues, err := profile.LoadVariables(credEnrollVarFile, credEnrollVars)
	if err != nil {
		return fmt.Errorf("failed to load variables: %w", err)
	}

	// If profile has variables, validate and render them
	// Use first profile for variable resolution (all profiles should use same vars)
	if len(profiles) > 0 && len(profiles[0].Variables) > 0 {
		engine, err := profile.NewTemplateEngine(profiles[0])
		if err != nil {
			return fmt.Errorf("failed to create template engine: %w", err)
		}

		// Render and validate variables
		rendered, err := engine.Render(varValues)
		if err != nil {
			return fmt.Errorf("variable validation failed: %w", err)
		}

		// Extract values from rendered profile
		varValues = rendered.ResolvedValues
	}

	// Build subject from variables
	subject, err := profile.BuildSubject(varValues)
	if err != nil {
		return fmt.Errorf("invalid subject: %w", err)
	}

	// Substitute variables in profile extensions
	// This replaces {{ dns_names }}, {{ ip_addresses }}, etc. with actual values
	varsForSubstitution := make(map[string][]string)
	if dns, ok := varValues.GetStringList("dns_names"); ok {
		varsForSubstitution["dns_names"] = dns
	}
	if ips, ok := varValues.GetStringList("ip_addresses"); ok {
		varsForSubstitution["ip_addresses"] = ips
	}
	if em, ok := varValues.GetStringList("email"); ok {
		varsForSubstitution["email"] = em
	}

	// Apply substitution to each profile's extensions
	for i, prof := range profiles {
		if prof.Extensions != nil {
			substituted, err := prof.Extensions.SubstituteVariables(varsForSubstitution)
			if err != nil {
				return fmt.Errorf("failed to substitute variables in profile %s: %w", prof.Name, err)
			}
			// Create a shallow copy of the profile with substituted extensions
			profileCopy := *prof
			profileCopy.Extensions = substituted
			profiles[i] = &profileCopy
		}
	}

	// Create enrollment request
	// DNS/Email SANs are handled via profile extensions ({{ dns_names }}, {{ email }})
	req := ca.EnrollmentRequest{
		Subject: subject,
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

	// Override credential ID if custom one provided
	if credEnrollID != "" {
		result.Bundle.ID = credEnrollID
	}

	// Save credential
	credStore := credential.NewFileStore(caDir)
	passphrase := []byte(credPassphrase)
	if err := credStore.Save(result.Bundle, result.Certificates, result.Signers, passphrase); err != nil {
		return fmt.Errorf("failed to save credential: %w", err)
	}

	// Output
	fmt.Println("Credential created successfully!")
	fmt.Println()
	fmt.Printf("Credential ID: %s\n", result.Bundle.ID)
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


func runCredList(cmd *cobra.Command, args []string) error {
	caDir, err := filepath.Abs(credCADir)
	if err != nil {
		return fmt.Errorf("invalid CA directory: %w", err)
	}

	credStore := credential.NewFileStore(caDir)
	credentials, err := credStore.ListAll()
	if err != nil {
		return fmt.Errorf("failed to list credentials: %w", err)
	}

	if len(credentials) == 0 {
		fmt.Println("No credentials found.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tSUBJECT\tPROFILES\tSTATUS\tCERTS\tVALID UNTIL")
	fmt.Fprintln(w, "--\t-------\t--------\t------\t-----\t-----------")

	for _, b := range credentials {
		status := string(b.Status)
		if b.IsExpired() && b.Status == credential.StatusValid {
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

func runCredInfo(cmd *cobra.Command, args []string) error {
	credID := args[0]

	caDir, err := filepath.Abs(credCADir)
	if err != nil {
		return fmt.Errorf("invalid CA directory: %w", err)
	}

	credStore := credential.NewFileStore(caDir)
	b, err := credStore.Load(credID)
	if err != nil {
		return fmt.Errorf("failed to load credential: %w", err)
	}

	// Print credential info
	fmt.Printf("Credential ID:    %s\n", b.ID)
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

func runCredRenew(cmd *cobra.Command, args []string) error {
	credID := args[0]

	caDir, err := filepath.Abs(credCADir)
	if err != nil {
		return fmt.Errorf("invalid CA directory: %w", err)
	}

	// Load CA
	caStore := ca.NewStore(caDir)
	caInstance, err := ca.New(caStore)
	if err != nil {
		return fmt.Errorf("failed to load CA: %w", err)
	}

	// Load CA signer (private key) - auto-detects hybrid vs regular
	if err := loadCASigner(caInstance, caDir, credPassphrase); err != nil {
		return fmt.Errorf("failed to load CA signer: %w", err)
	}

	// Load profiles
	profileStore := profile.NewProfileStore(caDir)
	if err := profileStore.Load(); err != nil {
		return fmt.Errorf("failed to load profiles: %w", err)
	}

	// Load credential store
	credStore := credential.NewFileStore(caDir)

	// Renew (pass new profiles for crypto-agility if specified)
	passphrase := []byte(credPassphrase)
	result, err := caInstance.RenewBundle(credID, credStore, profileStore, passphrase, credRenewProfiles)
	if err != nil {
		return fmt.Errorf("failed to renew credential: %w", err)
	}

	fmt.Println("Credential renewed successfully!")
	fmt.Println()
	fmt.Printf("Old credential: %s (now expired)\n", credID)
	fmt.Printf("New credential: %s\n", result.Bundle.ID)
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

func runCredRevoke(cmd *cobra.Command, args []string) error {
	credID := args[0]

	caDir, err := filepath.Abs(credCADir)
	if err != nil {
		return fmt.Errorf("invalid CA directory: %w", err)
	}

	// Load CA
	caStore := ca.NewStore(caDir)
	caInstance, err := ca.New(caStore)
	if err != nil {
		return fmt.Errorf("failed to load CA: %w", err)
	}

	// Load CA signer (private key) - auto-detects hybrid vs regular
	if err := loadCASigner(caInstance, caDir, credPassphrase); err != nil {
		return fmt.Errorf("failed to load CA signer: %w", err)
	}

	// Load credential store
	credStore := credential.NewFileStore(caDir)

	// Parse revocation reason
	reason := parseRevocationReason(credRevokeReason)

	// Revoke
	if err := caInstance.RevokeBundle(credID, reason, credStore); err != nil {
		return fmt.Errorf("failed to revoke credential: %w", err)
	}

	fmt.Printf("Credential %s revoked successfully.\n", credID)
	fmt.Printf("Reason: %s\n", reason)
	fmt.Println("All certificates in the credential have been added to the CRL.")

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

func runCredExport(cmd *cobra.Command, args []string) error {
	credID := args[0]

	caDir, err := filepath.Abs(credCADir)
	if err != nil {
		return fmt.Errorf("invalid CA directory: %w", err)
	}

	credStore := credential.NewFileStore(caDir)

	// Load certificates
	certs, err := credStore.LoadCertificates(credID)
	if err != nil {
		return fmt.Errorf("failed to load certificates: %w", err)
	}

	// Encode to PEM
	pemData, err := credential.EncodeCertificatesPEM(certs)
	if err != nil {
		return fmt.Errorf("failed to encode certificates: %w", err)
	}

	// If keys requested, load and append them
	if credExportKeys {
		if credPassphrase == "" {
			return fmt.Errorf("passphrase required for exporting keys")
		}

		signers, err := credStore.LoadKeys(credID, []byte(credPassphrase))
		if err != nil {
			return fmt.Errorf("failed to load keys: %w", err)
		}

		keysPEM, err := credential.EncodePrivateKeysPEM(signers, []byte(credPassphrase))
		if err != nil {
			return fmt.Errorf("failed to encode keys: %w", err)
		}

		pemData = append(pemData, keysPEM...)
	}

	// Output
	if credExportOut == "" {
		fmt.Print(string(pemData))
	} else {
		if err := os.WriteFile(credExportOut, pemData, 0644); err != nil {
			return fmt.Errorf("failed to write file: %w", err)
		}
		fmt.Printf("Exported to %s\n", credExportOut)
	}

	return nil
}

func runCredImport(cmd *cobra.Command, args []string) error {
	caDir, err := filepath.Abs(credCADir)
	if err != nil {
		return fmt.Errorf("invalid CA directory: %w", err)
	}

	// Load certificate
	certData, err := os.ReadFile(credImportCert)
	if err != nil {
		return fmt.Errorf("failed to read certificate: %w", err)
	}

	certs, err := credential.DecodeCertificatesPEM(certData)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	if len(certs) == 0 {
		return fmt.Errorf("no certificates found in %s", credImportCert)
	}

	cert := certs[0] // Use first certificate

	// Load private key
	passphrase := []byte(credPassphrase)
	signer, err := loadPrivateKeyForImport(credImportKey, passphrase)
	if err != nil {
		return fmt.Errorf("failed to load private key: %w", err)
	}

	// Verify key matches certificate
	certPubBytes, err := marshalPublicKey(cert.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal certificate public key: %w", err)
	}

	keyPubBytes, err := marshalPublicKey(signer.Public())
	if err != nil {
		return fmt.Errorf("failed to marshal key public key: %w", err)
	}

	if string(certPubBytes) != string(keyPubBytes) {
		return fmt.Errorf("private key does not match certificate")
	}

	// Create bundle
	bundleID := credImportID
	if bundleID == "" {
		bundleID = credential.GenerateBundleID(cert.Subject.CommonName)
	}

	subject := credential.SubjectFromCertificate(cert)
	bundle := credential.NewBundle(bundleID, subject, []string{"imported"})
	bundle.SetValidity(cert.NotBefore, cert.NotAfter)
	bundle.Activate()
	bundle.Metadata["source"] = "imported"
	bundle.Metadata["original_issuer"] = cert.Issuer.CommonName

	// Add certificate reference
	certRef := credential.CertificateRefFromCert(cert, credential.RoleSignature, false, "")
	certRef.Profile = "imported"
	bundle.AddCertificate(certRef)

	// Save to store
	credStore := credential.NewFileStore(caDir)
	if err := credStore.Save(bundle, certs, []pkicrypto.Signer{signer}, passphrase); err != nil {
		return fmt.Errorf("failed to save credential: %w", err)
	}

	fmt.Println("Credential imported successfully!")
	fmt.Println()
	fmt.Printf("Credential ID: %s\n", bundle.ID)
	fmt.Printf("Subject:       %s\n", cert.Subject.CommonName)
	fmt.Printf("Issuer:        %s\n", cert.Issuer.CommonName)
	fmt.Printf("Valid:         %s to %s\n",
		cert.NotBefore.Format("2006-01-02"),
		cert.NotAfter.Format("2006-01-02"))
	fmt.Printf("Algorithm:     %s\n", cert.SignatureAlgorithm)
	fmt.Printf("Serial:        %s\n", certRef.Serial)

	return nil
}

// loadPrivateKeyForImport loads a private key from file, supporting multiple formats.
func loadPrivateKeyForImport(path string, passphrase []byte) (pkicrypto.Signer, error) {
	return pkicrypto.LoadPrivateKey(path, passphrase)
}

// marshalPublicKey marshals a public key for comparison.
func marshalPublicKey(pub interface{}) ([]byte, error) {
	switch k := pub.(type) {
	case interface{ Equal(x interface{}) bool }:
		// For types that support Equal, we can't easily marshal
		// Fall back to fmt.Sprintf for comparison
		return []byte(fmt.Sprintf("%v", k)), nil
	default:
		return []byte(fmt.Sprintf("%v", pub)), nil
	}
}
