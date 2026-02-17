package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/remiblancher/post-quantum-pki/pkg/ca"
)

var caActivateCmd = &cobra.Command{
	Use:   "activate",
	Short: "Activate a pending CA version",
	Long: `Activate a pending CA version after rotation.

This command:
  1. Marks the specified version as active
  2. Archives the previously active version
  3. Updates the CA root files (ca.crt, private/ca.key) for backward compatibility

Examples:
  # Activate a specific version
  pki ca activate --ca-dir ./ca --version v2

  # List available versions first
  pki ca versions --ca-dir ./ca`,
	RunE: runCAActivate,
}

var caVersionsCmd = &cobra.Command{
	Use:   "versions",
	Short: "List CA versions",
	Long: `List all versions of a CA.

Shows version ID, status, algorithm, and creation date.

Examples:
  pki ca versions --ca-dir ./ca`,
	RunE: runCAVersions,
}

var (
	caActivateDir     string
	caActivateVersion string
	caVersionsDir     string
)

func init() {
	caCmd.AddCommand(caActivateCmd)
	caCmd.AddCommand(caVersionsCmd)

	caActivateCmd.Flags().StringVarP(&caActivateDir, "ca-dir", "d", "./ca", "CA directory")
	caActivateCmd.Flags().StringVar(&caActivateVersion, "version", "", "Version ID to activate (required)")
	_ = caActivateCmd.MarkFlagRequired("version")

	caVersionsCmd.Flags().StringVarP(&caVersionsDir, "ca-dir", "d", "./ca", "CA directory")
}

func runCAActivate(cmd *cobra.Command, args []string) error {
	absDir, err := filepath.Abs(caActivateDir)
	if err != nil {
		return fmt.Errorf("invalid CA directory: %w", err)
	}

	versionStore := ca.NewVersionStore(absDir)

	// Check if versioned
	if !versionStore.IsVersioned() {
		return fmt.Errorf("CA at %s does not use versioning (no previous rotation)", absDir)
	}

	// v1 represents the original CA (before versioning) and cannot be activated
	targetVersionID := caActivateVersion
	if targetVersionID == "v1" {
		return fmt.Errorf("v1 refers to the original CA, which cannot be activated")
	}

	// Get version info before activation
	version, err := versionStore.GetVersion(targetVersionID)
	if err != nil {
		return err
	}

	// Allow activating both pending versions (after rotation) and archived versions (rollback)
	if version.Status != ca.VersionStatusPending && version.Status != ca.VersionStatusArchived {
		return fmt.Errorf("version %s cannot be activated (status: %s)", targetVersionID, version.Status)
	}

	// Activate
	if err := versionStore.Activate(targetVersionID); err != nil {
		return fmt.Errorf("activation failed: %w", err)
	}

	fmt.Printf("CA version %s activated successfully!\n", targetVersionID)
	fmt.Println()
	fmt.Printf("Profiles:   %s\n", strings.Join(version.Profiles, ", "))
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
	fmt.Println("The CA root files have been updated.")
	fmt.Println("Previous version has been archived.")

	return nil
}

func runCAVersions(cmd *cobra.Command, args []string) error {
	absDir, err := filepath.Abs(caVersionsDir)
	if err != nil {
		return fmt.Errorf("invalid CA directory: %w", err)
	}

	versionStore := ca.NewVersionStore(absDir)

	// Check if versioned
	if !versionStore.IsVersioned() {
		fmt.Println("CA does not use versioning (no previous rotation).")
		fmt.Println()
		fmt.Println("To enable versioning, rotate the CA:")
		fmt.Printf("  pki ca rotate --ca-dir %s\n", caVersionsDir)
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

	fmt.Printf("%-20s %-10s %-30s %-12s %s\n", "VERSION", "STATUS", "PROFILES", "CREATED", "CROSS-SIGNED")
	fmt.Printf("%-20s %-10s %-30s %-12s %s\n", "-------", "------", "--------", "-------", "------------")

	for _, v := range versions {
		crossSigned := "-"
		if len(v.CrossSignedBy) > 0 {
			crossSigned = "yes"
		}

		profiles := strings.Join(v.Profiles, ", ")
		if len(profiles) > 30 {
			profiles = profiles[:27] + "..."
		}

		fmt.Printf("%-20s %-10s %-30s %-12s %s\n",
			v.ID,
			v.Status,
			profiles,
			v.Created.Format("2006-01-02"),
			crossSigned,
		)
	}

	return nil
}
