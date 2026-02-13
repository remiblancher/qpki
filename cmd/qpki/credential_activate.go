package main

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
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

Examples:
  # Activate a specific version
  pki credential activate alice-xxx --version v2

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
	credentialActivateCredDir string
	credentialVersionsCredDir string
)

func init() {
	credentialCmd.AddCommand(credentialActivateCmd)
	credentialCmd.AddCommand(credentialVersionsCmd)

	credentialActivateCmd.Flags().StringVar(&credentialActivateVersion, "version", "", "Version ID to activate (required)")
	credentialActivateCmd.Flags().StringVarP(&credentialActivateCredDir, "cred-dir", "c", "./credentials", "Credentials directory")
	_ = credentialActivateCmd.MarkFlagRequired("version")

	credentialVersionsCmd.Flags().StringVarP(&credentialVersionsCredDir, "cred-dir", "c", "./credentials", "Credentials directory")
}

func runCredentialActivate(cmd *cobra.Command, args []string) error {
	credentialID := args[0]

	credentialsDir, err := filepath.Abs(credentialActivateCredDir)
	if err != nil {
		return fmt.Errorf("invalid credentials directory: %w", err)
	}

	// Load credential from store
	credStore := credential.NewFileStore(credentialsDir)
	cred, err := credStore.Load(context.Background(), credentialID)
	if err != nil {
		return fmt.Errorf("failed to load credential: %w", err)
	}

	targetVersionID := credentialActivateVersion

	// Check if version exists
	_, ok := cred.Versions[targetVersionID]
	if !ok {
		return fmt.Errorf("version %s not found", targetVersionID)
	}

	// Check if version is pending (status is computed, not stored)
	status := cred.GetVersionStatus(targetVersionID)
	if status != "pending" {
		return fmt.Errorf("version %s is not pending (status: %s)", targetVersionID, status)
	}

	// Activate
	if err := cred.ActivateVersion(targetVersionID); err != nil {
		return fmt.Errorf("activation failed: %w", err)
	}

	// Save the updated credential
	if err := cred.Save(); err != nil {
		return fmt.Errorf("failed to save credential: %w", err)
	}

	// Get the now-active version for output
	activeVer := cred.ActiveVersion()

	fmt.Printf("Credential version %s activated successfully!\n", targetVersionID)
	fmt.Println()
	fmt.Printf("Credential:  %s\n", credentialID)
	if activeVer != nil {
		fmt.Printf("Profiles:    %s\n", strings.Join(activeVer.Profiles, ", "))
		fmt.Printf("Valid:       %s to %s\n",
			activeVer.NotBefore.Format("2006-01-02"),
			activeVer.NotAfter.Format("2006-01-02"))
	}
	fmt.Println()
	fmt.Println("Previous version has been archived.")

	return nil
}

func runCredentialVersions(cmd *cobra.Command, args []string) error {
	credentialID := args[0]

	credentialsDir, err := filepath.Abs(credentialVersionsCredDir)
	if err != nil {
		return fmt.Errorf("invalid credentials directory: %w", err)
	}

	// Load credential from store
	credStore := credential.NewFileStore(credentialsDir)
	cred, err := credStore.Load(context.Background(), credentialID)
	if err != nil {
		// Credential not found - just indicate no versioning
		fmt.Printf("Credential %s not found or does not use versioning.\n", credentialID)
		fmt.Println()
		fmt.Println("To create a credential:")
		fmt.Printf("  qpki credential enroll --cn '%s' --profile <profile-name>\n", credentialID)
		return nil
	}

	if len(cred.Versions) == 0 {
		fmt.Println("No versions found.")
		return nil
	}

	fmt.Printf("Credential: %s\n\n", credentialID)
	fmt.Printf("%-10s %-10s %-30s %s\n", "VERSION", "STATUS", "PROFILES", "CREATED")
	fmt.Printf("%-10s %-10s %-30s %s\n", "-------", "------", "--------", "-------")

	// Sort versions by name
	versionIDs := make([]string, 0, len(cred.Versions))
	for id := range cred.Versions {
		versionIDs = append(versionIDs, id)
	}
	sort.Strings(versionIDs)

	for _, id := range versionIDs {
		v := cred.Versions[id]
		profiles := strings.Join(v.Profiles, ", ")
		if len(profiles) > 30 {
			profiles = profiles[:27] + "..."
		}

		status := cred.GetVersionStatus(id)
		if id == cred.Active {
			status += " *"
		}

		fmt.Printf("%-10s %-10s %-30s %s\n",
			id,
			status,
			profiles,
			v.Created.Format("2006-01-02"),
		)
	}

	return nil
}

func resetCredentialActivateFlags() {
	credentialActivateVersion = ""
	credentialActivateCredDir = "./credentials"
	credentialVersionsCredDir = "./credentials"
}
