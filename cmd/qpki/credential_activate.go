package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/remiblancher/post-quantum-pki/internal/credential"
)

var credentialActivateCmd = &cobra.Command{
	Use:   "activate <credential-id>",
	Short: "Activate a pending credential version",
	Long: `Activate a pending credential version after rotation.

This command:
  1. Marks the specified version as active
  2. Archives the previously active version
  3. Updates the root credential files for backward compatibility

Examples:
  # Activate a specific version
  pki credential activate alice-xxx --version v20260105_abc123

  # List available versions first
  pki credential versions alice-xxx`,
	Args: cobra.ExactArgs(1),
	RunE: runCredentialActivate,
}

var credentialVersionsCmd = &cobra.Command{
	Use:   "versions <credential-id>",
	Short: "List credential versions",
	Long: `List all versions of a credential.

Shows version ID, status, algorithm families, and creation date.

Examples:
  pki credential versions alice-xxx`,
	Args: cobra.ExactArgs(1),
	RunE: runCredentialVersions,
}

var (
	credentialActivateVersion string
	credentialActivateCADir   string
	credentialVersionsCADir   string
)

func init() {
	credentialCmd.AddCommand(credentialActivateCmd)
	credentialCmd.AddCommand(credentialVersionsCmd)

	credentialActivateCmd.Flags().StringVar(&credentialActivateVersion, "version", "", "Version ID to activate (required)")
	credentialActivateCmd.Flags().StringVarP(&credentialActivateCADir, "ca-dir", "d", "./ca", "CA directory (for credentials store)")
	_ = credentialActivateCmd.MarkFlagRequired("version")

	credentialVersionsCmd.Flags().StringVarP(&credentialVersionsCADir, "ca-dir", "d", "./ca", "CA directory (for credentials store)")
}

func runCredentialActivate(cmd *cobra.Command, args []string) error {
	credentialID := args[0]

	absDir, err := filepath.Abs(credentialActivateCADir)
	if err != nil {
		return fmt.Errorf("invalid CA directory: %w", err)
	}

	credentialPath := filepath.Join(absDir, "credentials", credentialID)
	versionStore := credential.NewVersionStore(credentialPath)

	// Check if versioned
	if !versionStore.IsVersioned() {
		return fmt.Errorf("credential %s does not use versioning (no previous rotation)", credentialID)
	}

	// v1 represents the original credential (before versioning) and cannot be activated
	targetVersionID := credentialActivateVersion
	if targetVersionID == "v1" {
		return fmt.Errorf("v1 refers to the original credential, which cannot be activated")
	}

	// Get version info before activation
	version, err := versionStore.GetVersion(targetVersionID)
	if err != nil {
		return err
	}

	if version.Status != credential.VersionStatusPending {
		return fmt.Errorf("version %s is not pending (status: %s)", targetVersionID, version.Status)
	}

	// Activate
	if err := versionStore.Activate(targetVersionID); err != nil {
		return fmt.Errorf("activation failed: %w", err)
	}

	fmt.Printf("Credential version %s activated successfully!\n", targetVersionID)
	fmt.Println()
	fmt.Printf("Credential:  %s\n", credentialID)
	fmt.Printf("Profiles:    %s\n", strings.Join(version.Profiles, ", "))
	if len(version.Certificates) > 0 {
		fmt.Println("Certificates:")
		for _, cert := range version.Certificates {
			fmt.Printf("  - %s (%s): %s to %s\n",
				cert.AlgorithmFamily,
				cert.Algorithm,
				cert.NotBefore.Format("2006-01-02"),
				cert.NotAfter.Format("2006-01-02"))
		}
	}
	fmt.Println()
	fmt.Println("The credential root files have been updated.")
	fmt.Println("Previous version has been archived.")

	return nil
}

func runCredentialVersions(cmd *cobra.Command, args []string) error {
	credentialID := args[0]

	absDir, err := filepath.Abs(credentialVersionsCADir)
	if err != nil {
		return fmt.Errorf("invalid CA directory: %w", err)
	}

	credentialPath := filepath.Join(absDir, "credentials", credentialID)
	versionStore := credential.NewVersionStore(credentialPath)

	// Check if versioned
	if !versionStore.IsVersioned() {
		fmt.Printf("Credential %s does not use versioning (no previous rotation).\n", credentialID)
		fmt.Println()
		fmt.Println("To enable versioning, rotate the credential:")
		fmt.Printf("  pki credential rotate %s\n", credentialID)
		return nil
	}

	versions, err := versionStore.ListVersions()
	if err != nil {
		return fmt.Errorf("failed to list versions: %w", err)
	}

	if len(versions) == 0 {
		fmt.Println("No versions found.")
		return nil
	}

	fmt.Printf("Credential: %s\n\n", credentialID)
	fmt.Printf("%-20s %-10s %-30s %s\n", "VERSION", "STATUS", "PROFILES", "CREATED")
	fmt.Printf("%-20s %-10s %-30s %s\n", "-------", "------", "--------", "-------")

	for _, v := range versions {
		profiles := strings.Join(v.Profiles, ", ")
		if len(profiles) > 30 {
			profiles = profiles[:27] + "..."
		}

		fmt.Printf("%-20s %-10s %-30s %s\n",
			v.ID,
			v.Status,
			profiles,
			v.Created.Format("2006-01-02"),
		)
	}

	return nil
}

func resetCredentialActivateFlags() {
	credentialActivateVersion = ""
	credentialActivateCADir = "./ca"
	credentialVersionsCADir = "./ca"
}
