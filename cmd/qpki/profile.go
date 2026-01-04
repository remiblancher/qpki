package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/remiblancher/post-quantum-pki/internal/profile"
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

  # Lint a custom profile file
  pki profile lint my-profile.yaml

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

var profileLintCmd = &cobra.Command{
	Use:   "lint <file>",
	Short: "Lint a profile YAML file",
	Long:  `Lint a profile YAML file for correctness.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runProfileLint,
}

var profileInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install default profiles to a CA",
	Long: `Install the default profiles to a CA's profiles directory.

This copies the built-in profile templates to the CA so they can be customized.`,
	RunE: runProfileInstall,
}

var profileShowCmd = &cobra.Command{
	Use:   "show <name>",
	Short: "Show profile YAML content",
	Long: `Display the raw YAML content of a profile.

This is useful for exporting profiles via shell redirection:
  pki profile show ec/tls-server > my-tls-server.yaml`,
	Args: cobra.ExactArgs(1),
	RunE: runProfileShow,
}

var profileExportCmd = &cobra.Command{
	Use:   "export <name> <file>",
	Short: "Export a profile to a file",
	Long: `Export a builtin profile to a YAML file for customization.

Examples:
  # Export a single profile
  pki profile export ec/tls-server ./my-tls-server.yaml

  # Export all builtin profiles to a directory
  pki profile export --all ./templates/`,
	RunE: runProfileExport,
}

var profileVarsCmd = &cobra.Command{
	Use:   "vars <name>",
	Short: "List variables for a profile",
	Long: `List all variables defined in a profile.

Shows variable names, types, constraints, and default values.

Examples:
  # List variables for TLS server profile
  pki profile vars ec/tls-server

  # List variables for a custom profile file
  pki profile vars ./my-profile.yaml`,
	Args: cobra.ExactArgs(1),
	RunE: runProfileVars,
}

var (
	profileCADir     string
	profileOverwrite bool
	profileExportAll bool
)

func init() {
	// Add subcommands
	profileCmd.AddCommand(profileListCmd)
	profileCmd.AddCommand(profileInfoCmd)
	profileCmd.AddCommand(profileShowCmd)
	profileCmd.AddCommand(profileExportCmd)
	profileCmd.AddCommand(profileLintCmd)
	profileCmd.AddCommand(profileInstallCmd)
	profileCmd.AddCommand(profileVarsCmd)

	// Flags for list command
	profileListCmd.Flags().StringVarP(&profileCADir, "dir", "d", "./ca", "CA directory")

	// Flags for info command
	profileInfoCmd.Flags().StringVarP(&profileCADir, "dir", "d", "./ca", "CA directory")

	// Flags for install command
	profileInstallCmd.Flags().StringVarP(&profileCADir, "dir", "d", "./ca", "CA directory")
	profileInstallCmd.Flags().BoolVar(&profileOverwrite, "overwrite", false, "Overwrite existing profiles")

	// Flags for export command
	profileExportCmd.Flags().BoolVar(&profileExportAll, "all", false, "Export all builtin profiles to directory")
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
	_, _ = fmt.Fprintln(w, "NAME\tTYPE\tALGORITHM\tCERTS\tSOURCE")
	_, _ = fmt.Fprintln(w, "----\t----\t---------\t-----\t------")

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

	_ = w.Flush()
	return nil
}

func printProfileRow(w *tabwriter.Writer, p *profile.Profile, source string) {
	// Build algorithm description
	var algoDesc string
	if p.IsHybrid() {
		algoDesc = string(p.GetAlgorithm()) + " + " + string(p.GetAlternativeAlgorithm())
	} else {
		algoDesc = string(p.GetAlgorithm())
	}

	// Determine type
	typeDesc := "signature"
	if p.IsKEM() {
		typeDesc = "encryption"
	}
	if p.IsCatalyst() {
		typeDesc = "catalyst"
	}
	if p.IsComposite() {
		typeDesc = "composite"
	}

	_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\n",
		p.Name,
		typeDesc,
		algoDesc,
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

	// Fall back to builtin or file path
	if prof == nil {
		p, err := profile.LoadProfile(name)
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

	fmt.Println("Algorithm:")
	if prof.IsCatalyst() {
		fmt.Printf("  Mode:        catalyst\n")
		fmt.Printf("  Classical:   %s\n", prof.GetAlgorithm())
		fmt.Printf("  PQC:         %s\n", prof.GetAlternativeAlgorithm())
	} else {
		fmt.Printf("  Mode:        simple\n")
		fmt.Printf("  Algorithm:   %s\n", prof.GetAlgorithm())
	}

	fmt.Println()
	fmt.Println("Certificate Type:")
	if prof.IsKEM() {
		fmt.Println("  Encryption (KEM)")
	} else {
		fmt.Println("  Signature")
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

func runProfileLint(cmd *cobra.Command, args []string) error {
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

func runProfileShow(cmd *cobra.Command, args []string) error {
	name := args[0]

	// Get the profile
	prof, err := profile.LoadProfile(name)
	if err != nil {
		return fmt.Errorf("profile not found: %s", name)
	}

	// Convert to YAML and print
	data, err := yaml.Marshal(prof)
	if err != nil {
		return fmt.Errorf("failed to marshal profile: %w", err)
	}

	fmt.Print(string(data))
	return nil
}

func runProfileExport(cmd *cobra.Command, args []string) error {
	if profileExportAll {
		// Export all profiles to a directory
		if len(args) < 1 {
			return fmt.Errorf("destination directory required")
		}
		return exportAllProfiles(args[0])
	}

	// Export single profile
	if len(args) < 2 {
		return fmt.Errorf("usage: pki profile export <name> <file>")
	}

	name := args[0]
	destPath := args[1]

	prof, err := profile.LoadProfile(name)
	if err != nil {
		return fmt.Errorf("profile not found: %s", name)
	}

	data, err := yaml.Marshal(prof)
	if err != nil {
		return fmt.Errorf("failed to marshal profile: %w", err)
	}

	if err := os.WriteFile(destPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	fmt.Printf("Exported '%s' to %s\n", name, destPath)
	return nil
}

func exportAllProfiles(destDir string) error {
	// Create destination directory
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	profiles, err := profile.BuiltinProfiles()
	if err != nil {
		return fmt.Errorf("failed to load builtin profiles: %w", err)
	}

	// Sort names for consistent output
	var names []string
	for name := range profiles {
		names = append(names, name)
	}
	sort.Strings(names)

	fmt.Printf("Exporting %d profiles to %s/\n", len(profiles), destDir)

	for _, name := range names {
		prof := profiles[name]

		// Create subdirectory structure (e.g., ec/, hybrid/catalyst/)
		relDir := filepath.Dir(name)
		if relDir != "." {
			subDir := filepath.Join(destDir, relDir)
			if err := os.MkdirAll(subDir, 0755); err != nil {
				return fmt.Errorf("failed to create subdirectory %s: %w", subDir, err)
			}
		}

		// Generate filename from profile name
		fileName := strings.ReplaceAll(name, "/", "-") + ".yaml"
		if relDir != "." {
			// Use original structure: ec/root-ca.yaml
			fileName = filepath.Base(name) + ".yaml"
		}
		destPath := filepath.Join(destDir, relDir, fileName)

		data, err := yaml.Marshal(prof)
		if err != nil {
			return fmt.Errorf("failed to marshal %s: %w", name, err)
		}

		if err := os.WriteFile(destPath, data, 0644); err != nil {
			return fmt.Errorf("failed to write %s: %w", destPath, err)
		}

		fmt.Printf("  %s\n", destPath)
	}

	return nil
}

func runProfileVars(cmd *cobra.Command, args []string) error {
	name := args[0]

	// Load the profile
	prof, err := profile.LoadProfile(name)
	if err != nil {
		return fmt.Errorf("failed to load profile: %w", err)
	}

	if len(prof.Variables) == 0 {
		fmt.Printf("Profile '%s' has no variables.\n", name)
		return nil
	}

	fmt.Printf("Variables for profile %s:\n\n", prof.Name)

	// Sort variable names for consistent output
	var names []string
	for n := range prof.Variables {
		names = append(names, n)
	}
	sort.Strings(names)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tTYPE\tREQUIRED\tDEFAULT\tDESCRIPTION")
	fmt.Fprintln(w, "----\t----\t--------\t-------\t-----------")

	for _, n := range names {
		v := prof.Variables[n]

		required := "no"
		if v.Required {
			required = "yes"
		}

		defaultVal := "-"
		if v.HasDefault() {
			defaultVal = formatDefaultValue(v.Default)
		}

		desc := v.Description
		if desc == "" {
			desc = "-"
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			n,
			v.Type,
			required,
			defaultVal,
			desc)
	}

	w.Flush()
	return nil
}

// formatDefaultValue formats a default value for display.
func formatDefaultValue(val interface{}) string {
	switch v := val.(type) {
	case string:
		if v == "" {
			return `""`
		}
		return v
	case []interface{}:
		if len(v) == 0 {
			return "[]"
		}
		return fmt.Sprintf("%v", v)
	case []string:
		if len(v) == 0 {
			return "[]"
		}
		return strings.Join(v, ", ")
	default:
		return fmt.Sprintf("%v", v)
	}
}
