package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/remiblancher/post-quantum-pki/internal/ca"
	"github.com/remiblancher/post-quantum-pki/internal/credential"
	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
	"github.com/remiblancher/post-quantum-pki/internal/profile"
)

var credentialCmd = &cobra.Command{
	Use:     "credential",
	Aliases: []string{"cred"},
	Short:   "Manage certificate credentials",
	Long: `Manage certificate credentials with coupled lifecycle.

A credential groups related certificates created from one or more profiles:
  - All certificates share the same validity period
  - All certificates are rotated together
  - All certificates are revoked together

Examples:
  # Create a credential with one profile
  pki credential enroll --profile ec/tls-client --var cn=alice

  # Create a credential with multiple profiles (crypto-agility)
  pki credential enroll --profile ec/client --profile ml/client --var cn=alice

  # Create a credential with custom ID
  pki credential enroll --profile ec/tls-client --var cn=alice --id alice-prod

  # List all credentials
  pki credential list

  # Show credential details
  pki credential info alice-20250115-abcd1234

  # Rotate a credential (new keys, same profiles)
  pki credential rotate alice-20250115-abcd1234

  # Rotate keeping existing keys (certificate renewal only)
  pki credential rotate alice-20250115-abcd1234 --keep-keys

  # Rotate with crypto migration (add/change profiles)
  pki credential rotate alice-20250115-abcd1234 --profile ec/client --profile ml/client

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
  pki credential enroll --profile ec/tls-server --var-file vars.yaml`,
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

var credRotateCmd = &cobra.Command{
	Use:   "rotate <credential-id>",
	Short: "Rotate a credential",
	Long: `Rotate all certificates in a credential.

This creates new certificates with new keys (by default) and marks the old
credential as expired. Use --keep-keys to reuse existing keys.

Profile selection (in order of priority):
  1. --profile replaces all profiles entirely
  2. --add-profile / --remove-profile modify current profiles
  3. Neither: uses same profiles as original

Examples:
  # Standard rotation (new keys)
  pki credential rotate alice-20250115-abc123

  # Rotation keeping existing keys (certificate renewal only)
  pki credential rotate alice-20250115-abc123 --keep-keys

  # Replace all profiles (complete migration)
  pki credential rotate alice-20250115-abc123 --profile ml/client

  # Add PQC profile while keeping existing
  pki credential rotate alice-20250115-abc123 --add-profile ml/client

  # Remove classical profile (PQC-only migration)
  pki credential rotate alice-20250115-abc123 --remove-profile ec/client

  # Add and remove in one operation
  pki credential rotate alice-20250115-abc123 \
      --add-profile ml/client \
      --remove-profile ec/client`,
	Args: cobra.ExactArgs(1),
	RunE: runCredRotate,
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
	credEnrollProfiles  []string
	credEnrollID        string
	credEnrollVars      []string // --var key=value
	credEnrollVarFile   string   // --var-file vars.yaml
	credEnrollHSMConfig string   // HSM configuration file
	credEnrollKeyLabel  string   // HSM key label prefix

	// Rotate flags (crypto-agility)
	credRotateProfiles       []string
	credRotateAddProfiles    []string
	credRotateRemoveProfiles []string
	credRotateKeepKeys       bool
	credRotateHSMConfig      string // HSM configuration file
	credRotateKeyLabel       string // HSM key label prefix

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
	credentialCmd.AddCommand(credRotateCmd)
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
	credEnrollCmd.Flags().StringVar(&credEnrollHSMConfig, "hsm-config", "", "HSM configuration file for key generation")
	credEnrollCmd.Flags().StringVar(&credEnrollKeyLabel, "key-label", "", "HSM key label prefix (default: credential ID)")
	_ = credEnrollCmd.MarkFlagRequired("profile")

	// Rotate flags
	credRotateCmd.Flags().StringVarP(&credPassphrase, "passphrase", "p", "", "Passphrase for new private keys")
	credRotateCmd.Flags().StringSliceVarP(&credRotateProfiles, "profile", "P", nil, "Replace all profiles (overrides add/remove)")
	credRotateCmd.Flags().StringSliceVar(&credRotateAddProfiles, "add-profile", nil, "Add profile(s) to current set")
	credRotateCmd.Flags().StringSliceVar(&credRotateRemoveProfiles, "remove-profile", nil, "Remove profile(s) from current set")
	credRotateCmd.Flags().BoolVar(&credRotateKeepKeys, "keep-keys", false, "Reuse existing keys (certificate renewal only)")
	credRotateCmd.Flags().StringVar(&credRotateHSMConfig, "hsm-config", "", "HSM configuration file for key generation")
	credRotateCmd.Flags().StringVar(&credRotateKeyLabel, "key-label", "", "HSM key label prefix (default: credential ID)")

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

// loadCASigner loads the CA signer.
// LoadSigner automatically detects hybrid CAs from metadata and loads both keys.
func loadCASigner(caInstance *ca.CA, caDir, passphrase string) error {
	return caInstance.LoadSigner(passphrase)
}

func runCredEnroll(cmd *cobra.Command, args []string) error {
	// Check mutual exclusivity of --var and --var-file
	if credEnrollVarFile != "" && len(credEnrollVars) > 0 {
		return fmt.Errorf("--var and --var-file are mutually exclusive")
	}

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

	// Configure HSM for key generation if specified
	if credEnrollHSMConfig != "" {
		hsmCfg, err := pkicrypto.LoadHSMConfig(credEnrollHSMConfig)
		if err != nil {
			return fmt.Errorf("failed to load HSM config: %w", err)
		}
		pin, err := hsmCfg.GetPIN()
		if err != nil {
			return fmt.Errorf("failed to get HSM PIN: %w", err)
		}

		keyCfg := pkicrypto.KeyStorageConfig{
			Type:           pkicrypto.KeyProviderTypePKCS11,
			PKCS11Lib:      hsmCfg.PKCS11.Lib,
			PKCS11Token:    hsmCfg.PKCS11.Token,
			PKCS11Pin:      pin,
			PKCS11KeyLabel: credEnrollKeyLabel,
		}
		km := pkicrypto.NewKeyProvider(keyCfg)
		caInstance.SetKeyProvider(km, keyCfg)
	}

	// Load profiles
	profileStore := profile.NewProfileStore(caDir)
	if err := profileStore.Load(); err != nil {
		return fmt.Errorf("failed to load profiles: %w", err)
	}

	// Resolve profiles - support both profile names and file paths
	profiles := make([]*profile.Profile, 0, len(credEnrollProfiles))
	for _, name := range credEnrollProfiles {
		var prof *profile.Profile
		var err error

		// Check if it's a file path (contains path separator or ends with .yaml/.yml)
		if strings.Contains(name, string(os.PathSeparator)) || strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
			// Load as file path
			prof, err = profile.LoadProfile(name)
			if err != nil {
				return fmt.Errorf("failed to load profile from path %s: %w", name, err)
			}
		} else {
			// Look up in profile store
			var ok bool
			prof, ok = profileStore.Get(name)
			if !ok {
				return fmt.Errorf("profile not found: %s", name)
			}
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

	// Resolve profile extensions (substitute SAN template variables)
	// This replaces {{ dns_names }}, {{ ip_addresses }}, {{ email }} with actual values
	for i, prof := range profiles {
		resolvedExtensions, err := profile.ResolveProfileExtensions(prof, varValues)
		if err != nil {
			return fmt.Errorf("failed to resolve extensions in profile %s: %w", prof.Name, err)
		}
		if resolvedExtensions != nil {
			// Create a shallow copy of the profile with resolved extensions
			profileCopy := *prof
			profileCopy.Extensions = resolvedExtensions
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
		result.Credential.ID = credEnrollID
	}

	// Save credential
	credStore := credential.NewFileStore(caDir)
	passphrase := []byte(credPassphrase)
	if err := credStore.Save(result.Credential, result.Certificates, result.Signers, passphrase); err != nil {
		return fmt.Errorf("failed to save credential: %w", err)
	}

	// Output
	fmt.Println("Credential created successfully!")
	fmt.Println()
	fmt.Printf("Credential ID: %s\n", result.Credential.ID)
	fmt.Printf("Subject:   %s\n", result.Credential.Subject.CommonName)
	fmt.Printf("Profiles:  %s\n", strings.Join(result.Credential.Profiles, ", "))
	fmt.Printf("Valid:     %s to %s\n",
		result.Credential.NotBefore.Format("2006-01-02"),
		result.Credential.NotAfter.Format("2006-01-02"))
	if credEnrollHSMConfig != "" {
		fmt.Printf("Storage:   HSM (PKCS#11)\n")
	}
	fmt.Println()

	fmt.Println("Certificates:")
	for i := range result.Certificates {
		ref := result.Credential.Certificates[i]
		fmt.Printf("  [%d] %s (%s) - Serial: %s\n", i+1, ref.Algorithm, ref.Role, ref.Serial)
		if ref.Profile != "" {
			fmt.Printf("      Profile: %s\n", ref.Profile)
		}
		// Show HSM key info if applicable
		if len(result.StorageRefs) > i && result.StorageRefs[i].Type == "pkcs11" {
			fmt.Printf("      Key:     HSM label=%s\n", result.StorageRefs[i].Label)
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
	_, _ = fmt.Fprintln(w, "ID\tSUBJECT\tPROFILES\tSTATUS\tCERTS\tVALID UNTIL")
	_, _ = fmt.Fprintln(w, "--\t-------\t--------\t------\t-----\t-----------")

	for _, b := range credentials {
		status := string(b.Status)
		if b.IsExpired() && b.Status == credential.StatusValid {
			status = "expired"
		}

		profiles := strings.Join(b.Profiles, ", ")
		if len(profiles) > 40 {
			profiles = profiles[:37] + "..."
		}

		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\n",
			b.ID,
			b.Subject.CommonName,
			profiles,
			status,
			len(b.Certificates),
			b.NotAfter.Format("2006-01-02"))
	}

	_ = w.Flush()
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

func runCredRotate(cmd *cobra.Command, args []string) error {
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

	// Configure HSM for key generation if specified
	if credRotateHSMConfig != "" {
		hsmCfg, err := pkicrypto.LoadHSMConfig(credRotateHSMConfig)
		if err != nil {
			return fmt.Errorf("failed to load HSM config: %w", err)
		}
		pin, err := hsmCfg.GetPIN()
		if err != nil {
			return fmt.Errorf("failed to get HSM PIN: %w", err)
		}

		keyCfg := pkicrypto.KeyStorageConfig{
			Type:           pkicrypto.KeyProviderTypePKCS11,
			PKCS11Lib:      hsmCfg.PKCS11.Lib,
			PKCS11Token:    hsmCfg.PKCS11.Token,
			PKCS11Pin:      pin,
			PKCS11KeyLabel: credRotateKeyLabel,
		}
		km := pkicrypto.NewKeyProvider(keyCfg)
		caInstance.SetKeyProvider(km, keyCfg)
	}

	// Load profiles
	profileStore := profile.NewProfileStore(caDir)
	if err := profileStore.Load(); err != nil {
		return fmt.Errorf("failed to load profiles: %w", err)
	}

	// Load credential store
	credStore := credential.NewFileStore(caDir)

	// Determine key rotation mode
	keyMode := ca.KeyRotateNew
	if credRotateKeepKeys {
		keyMode = ca.KeyRotateKeep
	}

	// Determine target profiles:
	// 1. --profile replaces all (priority)
	// 2. --add-profile / --remove-profile modify current
	// 3. Neither: use current (nil)
	var targetProfiles []string

	if len(credRotateProfiles) > 0 {
		// --profile specified: use as-is
		targetProfiles = credRotateProfiles
	} else if len(credRotateAddProfiles) > 0 || len(credRotateRemoveProfiles) > 0 {
		// Compute: current + add - remove
		existingCred, err := credStore.Load(credID)
		if err != nil {
			return fmt.Errorf("failed to load credential: %w", err)
		}

		targetProfiles = computeProfileSet(existingCred.Profiles, credRotateAddProfiles, credRotateRemoveProfiles)

		if len(targetProfiles) == 0 {
			return fmt.Errorf("no profiles remaining after add/remove operations")
		}
	}
	// else: targetProfiles = nil → RotateCredential uses current profiles

	// Rotate credential
	passphrase := []byte(credPassphrase)
	result, err := caInstance.RotateCredential(credID, credStore, profileStore, passphrase, keyMode, targetProfiles)
	if err != nil {
		return fmt.Errorf("failed to rotate credential: %w", err)
	}

	// Output
	action := "rotated"
	keyInfo := "new keys"
	if credRotateKeepKeys {
		keyInfo = "existing keys"
	}
	if credRotateHSMConfig != "" && !credRotateKeepKeys {
		keyInfo = "new keys (HSM)"
	}

	fmt.Printf("Credential %s successfully (%s)!\n", action, keyInfo)
	fmt.Println()
	fmt.Printf("Old credential: %s (now expired)\n", credID)
	fmt.Printf("New credential: %s\n", result.Credential.ID)
	fmt.Printf("Valid:          %s to %s\n",
		result.Credential.NotBefore.Format("2006-01-02"),
		result.Credential.NotAfter.Format("2006-01-02"))
	fmt.Println()

	fmt.Println("New certificates:")
	for i := range result.Certificates {
		ref := result.Credential.Certificates[i]
		fmt.Printf("  [%d] %s (%s) - Serial: %s\n", i+1, ref.Algorithm, ref.Role, ref.Serial)
		// Show HSM key info if applicable
		if len(result.StorageRefs) > i && result.StorageRefs[i].Type == "pkcs11" {
			fmt.Printf("      Key: HSM label=%s\n", result.StorageRefs[i].Label)
		}
	}

	return nil
}

// computeProfileSet computes: current + add - remove
// Maintains order: current profiles first (minus removed), then added.
func computeProfileSet(current, add, remove []string) []string {
	// Build removal set for O(1) lookup
	removeSet := make(map[string]bool)
	for _, p := range remove {
		removeSet[p] = true
	}

	// Build result: current profiles minus removed
	result := make([]string, 0, len(current)+len(add))
	seen := make(map[string]bool)

	for _, p := range current {
		if !removeSet[p] && !seen[p] {
			result = append(result, p)
			seen[p] = true
		}
	}

	// Add new profiles (avoiding duplicates)
	for _, p := range add {
		if !seen[p] {
			result = append(result, p)
			seen[p] = true
		}
	}

	return result
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
	if err := caInstance.RevokeCredential(credID, reason, credStore); err != nil {
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

	// Create credential
	credentialID := credImportID
	if credentialID == "" {
		credentialID = credential.GenerateCredentialID(cert.Subject.CommonName)
	}

	subject := credential.SubjectFromCertificate(cert)
	cred := credential.NewCredential(credentialID, subject, []string{"imported"})
	cred.SetValidity(cert.NotBefore, cert.NotAfter)
	cred.Activate()
	cred.Metadata["source"] = "imported"
	cred.Metadata["original_issuer"] = cert.Issuer.CommonName

	// Add certificate reference
	certRef := credential.CertificateRefFromCert(cert, credential.RoleSignature, false, "")
	certRef.Profile = "imported"
	cred.AddCertificate(certRef)

	// Save to store
	credStore := credential.NewFileStore(caDir)
	if err := credStore.Save(cred, certs, []pkicrypto.Signer{signer}, passphrase); err != nil {
		return fmt.Errorf("failed to save credential: %w", err)
	}

	fmt.Println("Credential imported successfully!")
	fmt.Println()
	fmt.Printf("Credential ID: %s\n", cred.ID)
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
