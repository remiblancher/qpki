package main

import (
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/remiblancher/pki/internal/profile"
)

var profileCmd = &cobra.Command{
	Use:   "profile",
	Short: "Manage certificate profiles",
	Long: `Manage certificate profiles.

A profile defines a complete certificate enrollment policy including:
  - Signature requirements (simple, hybrid-combined, hybrid-separate)
  - Encryption requirements (none, simple, hybrid-combined, hybrid-separate)
  - Algorithm choices (classical and/or PQC)
  - Validity period
  - X.509 extensions with criticality

Profiles are stored as YAML files in the CA's profiles/ directory.

Examples:
  # List all available profiles
  pki profile list

  # Show details of a specific profile
  pki profile info hybrid-catalyst

  # Validate a custom profile file
  pki profile validate my-profile.yaml

  # Install default profiles to a CA
  pki profile install --dir ./ca`,
}

var profileListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available profiles",
	Long: `List all available profiles.

Shows both default (built-in) profiles and custom profiles from the CA directory.`,
	RunE: runProfileList,
}

var profileInfoCmd = &cobra.Command{
	Use:   "info <name>",
	Short: "Show details of a profile",
	Long:  `Show detailed information about a specific profile.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runProfileInfo,
}

var profileValidateCmd = &cobra.Command{
	Use:   "validate <file>",
	Short: "Validate a profile YAML file",
	Long:  `Validate a profile YAML file for correctness.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runProfileValidate,
}

var profileInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install default profiles to a CA",
	Long: `Install the default profiles to a CA's profiles directory.

This copies the built-in profile templates to the CA so they can be customized.`,
	RunE: runProfileInstall,
}

var (
	profileCADir    string
	profileOverwrite bool
)

func init() {
	// Add subcommands
	profileCmd.AddCommand(profileListCmd)
	profileCmd.AddCommand(profileInfoCmd)
	profileCmd.AddCommand(profileValidateCmd)
	profileCmd.AddCommand(profileInstallCmd)

	// Flags for list command
	profileListCmd.Flags().StringVarP(&profileCADir, "dir", "d", "./ca", "CA directory")

	// Flags for info command
	profileInfoCmd.Flags().StringVarP(&profileCADir, "dir", "d", "./ca", "CA directory")

	// Flags for install command
	profileInstallCmd.Flags().StringVarP(&profileCADir, "dir", "d", "./ca", "CA directory")
	profileInstallCmd.Flags().BoolVar(&profileOverwrite, "overwrite", false, "Overwrite existing profiles")
}

func runProfileList(cmd *cobra.Command, args []string) error {
	// Get default profiles
	defaultProfiles, err := profile.BuiltinProfiles()
	if err != nil {
		return fmt.Errorf("failed to load default profiles: %w", err)
	}

	// Try to load custom profiles from CA
	var customProfiles map[string]*profile.Profile
	absDir, _ := filepath.Abs(profileCADir)
	profileStore := profile.NewProfileStore(absDir)
	if err := profileStore.Load(); err == nil {
		customProfiles = profileStore.All()
	}

	// Print profiles
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tMODE\tSIGNATURE\tENCRYPTION\tCERTS\tSOURCE")
	fmt.Fprintln(w, "----\t----\t---------\t----------\t-----\t------")

	// Print default profiles
	for name, p := range defaultProfiles {
		source := "default"
		if _, exists := customProfiles[name]; exists {
			source = "custom (overrides default)"
		}
		printProfileRow(w, p, source)
	}

	// Print custom-only profiles
	for name, p := range customProfiles {
		if _, isDefault := defaultProfiles[name]; !isDefault {
			printProfileRow(w, p, "custom")
		}
	}

	w.Flush()
	return nil
}

func printProfileRow(w *tabwriter.Writer, p *profile.Profile, source string) {
	sigAlg := string(p.Signature.Algorithms.Primary)
	if p.Signature.Algorithms.Alternative != "" {
		sigAlg += " + " + string(p.Signature.Algorithms.Alternative)
	}

	encAlg := "none"
	if p.Encryption.Required && p.Encryption.Mode != profile.EncryptionNone {
		encAlg = string(p.Encryption.Algorithms.Primary)
		if p.Encryption.Algorithms.Alternative != "" {
			encAlg += " + " + string(p.Encryption.Algorithms.Alternative)
		}
	}

	fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\n",
		p.Name,
		p.Signature.Mode,
		sigAlg,
		encAlg,
		p.CertificateCount(),
		source)
}

func runProfileInfo(cmd *cobra.Command, args []string) error {
	name := args[0]

	// Try to find profile
	var prof *profile.Profile
	var source string

	// Check custom profiles first
	absDir, _ := filepath.Abs(profileCADir)
	profileStore := profile.NewProfileStore(absDir)
	if err := profileStore.Load(); err == nil {
		if p, ok := profileStore.Get(name); ok {
			prof = p
			source = "custom (" + profileStore.BasePath() + ")"
		}
	}

	// Fall back to default
	if prof == nil {
		p, err := profile.GetBuiltinProfile(name)
		if err != nil {
			return fmt.Errorf("profile not found: %s", name)
		}
		prof = p
		source = "default (built-in)"
	}

	// Print details
	fmt.Printf("Name:        %s\n", prof.Name)
	fmt.Printf("Description: %s\n", prof.Description)
	fmt.Printf("Source:      %s\n", source)
	fmt.Printf("Validity:    %s\n", prof.Validity)
	fmt.Printf("Certificates: %d\n", prof.CertificateCount())
	fmt.Println()

	fmt.Println("Signature:")
	fmt.Printf("  Mode:        %s\n", prof.Signature.Mode)
	fmt.Printf("  Primary:     %s\n", prof.Signature.Algorithms.Primary)
	if prof.Signature.Algorithms.Alternative != "" {
		fmt.Printf("  Alternative: %s\n", prof.Signature.Algorithms.Alternative)
	}
	fmt.Println()

	fmt.Println("Encryption:")
	if !prof.Encryption.Required || prof.Encryption.Mode == profile.EncryptionNone {
		fmt.Println("  Not required")
	} else {
		fmt.Printf("  Mode:        %s\n", prof.Encryption.Mode)
		fmt.Printf("  Primary:     %s\n", prof.Encryption.Algorithms.Primary)
		if prof.Encryption.Algorithms.Alternative != "" {
			fmt.Printf("  Alternative: %s\n", prof.Encryption.Algorithms.Alternative)
		}
	}

	// Print extensions if configured
	if prof.Extensions != nil {
		fmt.Println()
		fmt.Println("Extensions:")
		if prof.Extensions.KeyUsage != nil {
			fmt.Printf("  Key Usage: %v (critical: %v)\n", prof.Extensions.KeyUsage.Values, prof.Extensions.KeyUsage.IsCritical())
		}
		if prof.Extensions.ExtKeyUsage != nil {
			fmt.Printf("  Extended Key Usage: %v (critical: %v)\n", prof.Extensions.ExtKeyUsage.Values, prof.Extensions.ExtKeyUsage.IsCritical())
		}
		if prof.Extensions.BasicConstraints != nil {
			fmt.Printf("  Basic Constraints: CA=%v (critical: %v)\n", prof.Extensions.BasicConstraints.CA, prof.Extensions.BasicConstraints.IsCritical())
		}
	}

	return nil
}

func runProfileValidate(cmd *cobra.Command, args []string) error {
	path := args[0]

	prof, err := profile.LoadProfileFromFile(path)
	if err != nil {
		fmt.Printf("INVALID: %s\n", err)
		return err
	}

	fmt.Printf("VALID: %s\n", prof.Name)
	fmt.Printf("  %s\n", prof.String())
	return nil
}

func runProfileInstall(cmd *cobra.Command, args []string) error {
	absDir, err := filepath.Abs(profileCADir)
	if err != nil {
		return fmt.Errorf("invalid directory: %w", err)
	}

	fmt.Printf("Installing default profiles to %s/profiles/...\n", absDir)

	if err := profile.InstallBuiltinProfiles(absDir, profileOverwrite); err != nil {
		return fmt.Errorf("failed to install profiles: %w", err)
	}

	// List installed profiles
	names, err := profile.ListBuiltinProfileNames()
	if err != nil {
		return err
	}

	fmt.Println("Installed profiles:")
	for _, name := range names {
		fmt.Printf("  - %s\n", name)
	}

	return nil
}
