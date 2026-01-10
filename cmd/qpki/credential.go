package main

import (
	"context"
	"crypto/x509"
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
	Long: `Export certificates from a credential.

Formats:
  pem   PEM format (default)
  der   DER binary format

Bundles:
  cert   Certificate(s) only (default)
  chain  Certificates + issuing CA chain
  all    All certificates from all algorithm families

Version selection:
  --version   Export a specific version
  --all       Export all versions (each to separate file)

Examples:
  # Export active certificates as PEM
  pki credential export alice-xxx

  # Export as DER
  pki credential export alice-xxx --format der

  # Export with full chain
  pki credential export alice-xxx --bundle chain

  # Export a specific version
  pki credential export alice-xxx --version v20260105_abc123

  # Export all versions
  pki credential export alice-xxx --all`,
	Args: cobra.ExactArgs(1),
	RunE: runCredExport,
}


var (
	credCADir        string
	credDir          string
	credPassphrase   string
	credRevokeReason string

	// Export flags
	credExportOut     string
	credExportFormat  string // pem, der
	credExportBundle  string // cert, chain, all
	credExportVersion string // specific version ID
	credExportAll     bool   // export all versions

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
	credentialCmd.PersistentFlags().StringVarP(&credDir, "cred-dir", "c", "./credentials", "Credentials directory")

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
	credExportCmd.Flags().StringVarP(&credExportFormat, "format", "f", "pem", "Output format: pem, der")
	credExportCmd.Flags().StringVarP(&credExportBundle, "bundle", "b", "cert", "Bundle type: cert, chain, all")
	credExportCmd.Flags().StringVarP(&credExportVersion, "version", "v", "", "Export specific version")
	credExportCmd.Flags().BoolVar(&credExportAll, "all", false, "Export all versions")
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

	credentialsDir, err := filepath.Abs(credDir)
	if err != nil {
		return fmt.Errorf("invalid credentials directory: %w", err)
	}

	// Load CA
	caStore := ca.NewFileStore(caDir)
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
	credStore := credential.NewFileStore(credentialsDir)
	passphrase := []byte(credPassphrase)
	if err := credStore.Save(result.Credential, result.Certificates, result.Signers, passphrase); err != nil {
		return fmt.Errorf("failed to save credential: %w", err)
	}

	// Output
	fmt.Println("Credential created successfully!")
	fmt.Println()
	fmt.Printf("Credential ID: %s\n", result.Credential.ID)
	fmt.Printf("Subject:   %s\n", result.Credential.Subject.CommonName)

	activeVer := result.Credential.ActiveVersion()
	if activeVer != nil {
		fmt.Printf("Profiles:  %s\n", strings.Join(activeVer.Profiles, ", "))
		fmt.Printf("Valid:     %s to %s\n",
			activeVer.NotBefore.Format("2006-01-02"),
			activeVer.NotAfter.Format("2006-01-02"))
	}
	if credEnrollHSMConfig != "" {
		fmt.Printf("Storage:   HSM (PKCS#11)\n")
	}
	fmt.Println()

	fmt.Printf("Certificates issued: %d\n", len(result.Certificates))
	for i, cert := range result.Certificates {
		fmt.Printf("  [%d] Serial: %X\n", i+1, cert.SerialNumber.Bytes())
		// Show HSM key info if applicable
		if len(result.StorageRefs) > i && result.StorageRefs[i].Type == "pkcs11" {
			fmt.Printf("      Key:     HSM label=%s\n", result.StorageRefs[i].Label)
		}
	}

	return nil
}


func runCredList(cmd *cobra.Command, args []string) error {
	credentialsDir, err := filepath.Abs(credDir)
	if err != nil {
		return fmt.Errorf("invalid credentials directory: %w", err)
	}

	credStore := credential.NewFileStore(credentialsDir)
	credentials, err := credStore.ListAll()
	if err != nil {
		return fmt.Errorf("failed to list credentials: %w", err)
	}

	if len(credentials) == 0 {
		fmt.Println("No credentials found.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "ID\tSUBJECT\tPROFILES\tSTATUS\tALGOS\tVALID UNTIL")
	_, _ = fmt.Fprintln(w, "--\t-------\t--------\t------\t-----\t-----------")

	for _, b := range credentials {
		ver := b.ActiveVersion()
		var status, profiles, algos, validUntil string

		if b.RevokedAt != nil {
			status = "revoked"
		} else if ver != nil {
			status = ver.Status
			if b.IsExpired() {
				status = "expired"
			}
			profiles = strings.Join(ver.Profiles, ", ")
			algos = strings.Join(ver.Algos, ", ")
			validUntil = ver.NotAfter.Format("2006-01-02")
		} else {
			status = "unknown"
			validUntil = "N/A"
		}

		if len(profiles) > 40 {
			profiles = profiles[:37] + "..."
		}

		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			b.ID,
			b.Subject.CommonName,
			profiles,
			status,
			algos,
			validUntil)
	}

	_ = w.Flush()
	return nil
}

func runCredInfo(cmd *cobra.Command, args []string) error {
	credID := args[0]

	credentialsDir, err := filepath.Abs(credDir)
	if err != nil {
		return fmt.Errorf("invalid credentials directory: %w", err)
	}

	credStore := credential.NewFileStore(credentialsDir)
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
	fmt.Printf("Created:      %s\n", b.Created.Format("2006-01-02 15:04:05"))
	fmt.Printf("Active Ver:   %s\n", b.Active)

	// Show active version details
	ver := b.ActiveVersion()
	if ver != nil {
		fmt.Printf("Profiles:     %s\n", strings.Join(ver.Profiles, ", "))
		fmt.Printf("Algorithms:   %s\n", strings.Join(ver.Algos, ", "))
		fmt.Printf("Status:       %s\n", ver.Status)
		fmt.Printf("Valid From:   %s\n", ver.NotBefore.Format("2006-01-02 15:04:05"))
		fmt.Printf("Valid Until:  %s\n", ver.NotAfter.Format("2006-01-02 15:04:05"))
	}

	if b.RevokedAt != nil {
		fmt.Printf("Revoked At:   %s\n", b.RevokedAt.Format("2006-01-02 15:04:05"))
		fmt.Printf("Revoke Reason: %s\n", b.RevocationReason)
	}

	// Show all versions
	if len(b.Versions) > 1 {
		fmt.Println()
		fmt.Println("Versions:")
		for vID, v := range b.Versions {
			activeMark := ""
			if vID == b.Active {
				activeMark = " (active)"
			}
			fmt.Printf("  %s%s: profiles=%v, algos=%v, status=%s\n",
				vID, activeMark, v.Profiles, v.Algos, v.Status)
		}
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

	credentialsDir, err := filepath.Abs(credDir)
	if err != nil {
		return fmt.Errorf("invalid credentials directory: %w", err)
	}

	// Load CA
	caStore := ca.NewFileStore(caDir)
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
	credStore := credential.NewFileStore(credentialsDir)

	// Determine key rotation mode
	keyMode := ca.KeyRotateNew
	if credRotateKeepKeys {
		keyMode = ca.KeyRotateKeep
	}

	// Determine target profiles:
	// 1. --profile replaces all (priority)
	// 2. --add-profile / --remove-profile modify current
	// 3. Neither: use current profiles from credential
	var profileNames []string

	if len(credRotateProfiles) > 0 {
		// --profile specified: use as-is
		profileNames = credRotateProfiles
	} else if len(credRotateAddProfiles) > 0 || len(credRotateRemoveProfiles) > 0 {
		// Compute: current + add - remove
		existingCred, err := credStore.Load(credID)
		if err != nil {
			return fmt.Errorf("failed to load credential: %w", err)
		}
		ver := existingCred.ActiveVersion()
		if ver == nil {
			return fmt.Errorf("credential has no active version")
		}

		profileNames = computeProfileSet(ver.Profiles, credRotateAddProfiles, credRotateRemoveProfiles)

		if len(profileNames) == 0 {
			return fmt.Errorf("no profiles remaining after add/remove operations")
		}
	} else {
		// Use existing profiles from credential
		existingCred, err := credStore.Load(credID)
		if err != nil {
			return fmt.Errorf("failed to load credential: %w", err)
		}
		ver := existingCred.ActiveVersion()
		if ver == nil {
			return fmt.Errorf("credential has no active version")
		}
		profileNames = ver.Profiles
	}

	// Resolve profile names to profile objects
	profiles := make([]*profile.Profile, 0, len(profileNames))
	for _, pName := range profileNames {
		prof, ok := profileStore.Get(pName)
		if !ok {
			return fmt.Errorf("profile %q not found", pName)
		}
		profiles = append(profiles, prof)
	}

	// Rotate credential (versioned - creates PENDING version)
	passphrase := []byte(credPassphrase)
	req := ca.CredentialRotateRequest{
		CredentialID:    credID,
		CredentialStore: credStore,
		Profiles:        profiles,
		Passphrase:      passphrase,
		KeyMode:         keyMode,
	}
	result, err := caInstance.RotateCredentialVersioned(req)
	if err != nil {
		return fmt.Errorf("failed to rotate credential: %w", err)
	}

	// Output
	keyInfo := "new keys"
	if credRotateKeepKeys {
		keyInfo = "existing keys"
	}
	if credRotateHSMConfig != "" && !credRotateKeepKeys {
		keyInfo = "new keys (HSM)"
	}

	fmt.Printf("Credential rotated successfully (%s)!\n", keyInfo)
	fmt.Println()
	fmt.Printf("Credential: %s\n", credID)
	fmt.Printf("Version:    %s (PENDING)\n", result.NewVersionID)
	fmt.Printf("Profiles:   %s\n", strings.Join(profileNames, ", "))
	fmt.Println()

	fmt.Println("New certificates:")
	for _, cert := range result.Certificates {
		fmt.Printf("  - %s: %s to %s\n",
			cert.SignatureAlgorithm.String(),
			cert.NotBefore.Format("2006-01-02"),
			cert.NotAfter.Format("2006-01-02"))
	}
	fmt.Println()

	fmt.Println("To activate this version:")
	fmt.Printf("  qpki credential activate %s --version %s\n", credID, result.NewVersionID)

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

	credentialsDir, err := filepath.Abs(credDir)
	if err != nil {
		return fmt.Errorf("invalid credentials directory: %w", err)
	}

	// Load CA
	caStore := ca.NewFileStore(caDir)
	caInstance, err := ca.New(caStore)
	if err != nil {
		return fmt.Errorf("failed to load CA: %w", err)
	}

	// Load CA signer (private key) - auto-detects hybrid vs regular
	if err := loadCASigner(caInstance, caDir, credPassphrase); err != nil {
		return fmt.Errorf("failed to load CA signer: %w", err)
	}

	// Load credential store
	credStore := credential.NewFileStore(credentialsDir)

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

	credentialsDir, err := filepath.Abs(credDir)
	if err != nil {
		return fmt.Errorf("invalid credentials directory: %w", err)
	}

	// Validate format
	if credExportFormat != "pem" && credExportFormat != "der" {
		return fmt.Errorf("invalid format: %s (use: pem, der)", credExportFormat)
	}

	// Validate bundle
	if credExportBundle != "cert" && credExportBundle != "chain" && credExportBundle != "all" {
		return fmt.Errorf("invalid bundle: %s (use: cert, chain, all)", credExportBundle)
	}

	credStore := credential.NewFileStore(credentialsDir)
	versionStore := credential.NewVersionStore(credential.CredentialPath(credentialsDir, credID))

	// Handle --all flag (export all versions)
	if credExportAll {
		return exportCredentialAllVersions(credID, credStore, versionStore)
	}

	// Determine which version to export
	var certs []*x509.Certificate

	if credExportVersion != "" {
		// Export specific version
		certs, err = loadCredentialVersionCerts(credID, credExportVersion, versionStore, credStore)
		if err != nil {
			return fmt.Errorf("failed to load version %s: %w", credExportVersion, err)
		}
	} else if versionStore.IsVersioned() {
		// Export active version
		activeVersion, err := versionStore.GetActiveVersion()
		if err != nil {
			return fmt.Errorf("failed to get active version: %w", err)
		}
		certs, err = loadCredentialVersionCerts(credID, activeVersion.ID, versionStore, credStore)
		if err != nil {
			return fmt.Errorf("failed to load active version: %w", err)
		}
	} else {
		// Non-versioned credential: load from root
		certs, err = credStore.LoadCertificates(credID)
		if err != nil {
			return fmt.Errorf("failed to load certificates: %w", err)
		}
	}

	// Load CA chain if bundle=chain
	if credExportBundle == "chain" {
		caStore := ca.NewFileStore(caDir)
		caCerts, err := caStore.LoadAllCACerts(context.Background())
		if err != nil {
			return fmt.Errorf("failed to load CA certificates for chain: %w", err)
		}
		certs = append(certs, caCerts...)
	}

	// Encode output
	var outputData []byte
	if credExportFormat == "der" {
		if len(certs) > 1 {
			return fmt.Errorf("DER format only supports single certificate (use PEM for multiple)")
		}
		if len(certs) > 0 {
			outputData = certs[0].Raw
		}
	} else {
		outputData, err = credential.EncodeCertificatesPEM(certs)
		if err != nil {
			return fmt.Errorf("failed to encode certificates: %w", err)
		}
	}

	// Output
	if credExportOut == "" {
		if credExportFormat == "der" {
			return fmt.Errorf("DER format requires --out file")
		}
		fmt.Print(string(outputData))
	} else {
		if err := os.WriteFile(credExportOut, outputData, 0644); err != nil {
			return fmt.Errorf("failed to write file: %w", err)
		}
		fmt.Printf("Exported to %s\n", credExportOut)
	}

	return nil
}

// loadCredentialVersionCerts loads all certificates from a specific version.
func loadCredentialVersionCerts(credID, versionID string, versionStore *credential.VersionStore, credStore *credential.FileStore) ([]*x509.Certificate, error) {
	version, err := versionStore.GetVersion(versionID)
	if err != nil {
		return nil, err
	}

	var certs []*x509.Certificate
	for _, certRef := range version.Certificates {
		profileDir := versionStore.ProfileDir(versionID, certRef.AlgorithmFamily)
		certPath := filepath.Join(profileDir, "certificates.pem")

		data, err := os.ReadFile(certPath)
		if err != nil {
			continue
		}

		profileCerts, err := credential.DecodeCertificatesPEM(data)
		if err != nil {
			continue
		}

		certs = append(certs, profileCerts...)
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in version %s", versionID)
	}

	return certs, nil
}

// exportCredentialAllVersions exports all versions to separate files.
func exportCredentialAllVersions(credID string, credStore *credential.FileStore, versionStore *credential.VersionStore) error {
	if !versionStore.IsVersioned() {
		return fmt.Errorf("credential %s does not use versioning", credID)
	}

	versions, err := versionStore.ListVersions()
	if err != nil {
		return fmt.Errorf("failed to list versions: %w", err)
	}

	if len(versions) == 0 {
		return fmt.Errorf("no versions found for credential %s", credID)
	}

	baseOut := credExportOut
	if baseOut == "" {
		baseOut = credID
	}

	ext := ".pem"
	if credExportFormat == "der" {
		ext = ".der"
	}

	for _, v := range versions {
		certs, err := loadCredentialVersionCerts(credID, v.ID, versionStore, credStore)
		if err != nil {
			fmt.Printf("  [%s] skipped: %v\n", v.ID, err)
			continue
		}

		// Encode
		var data []byte
		if credExportFormat == "der" {
			if len(certs) > 0 {
				data = certs[0].Raw
			}
		} else {
			data, _ = credential.EncodeCertificatesPEM(certs)
		}

		// Write to file
		outFile := fmt.Sprintf("%s-%s%s", baseOut, v.ID, ext)
		if err := os.WriteFile(outFile, data, 0644); err != nil {
			fmt.Printf("  [%s] failed: %v\n", v.ID, err)
			continue
		}
		fmt.Printf("  [%s] %-10s → %s\n", v.ID, v.Status, outFile)
	}

	return nil
}
