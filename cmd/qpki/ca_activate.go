package main

import (
	"fmt"
	"path/filepath"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/remiblancher/post-quantum-pki/internal/ca"
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
  pki ca activate --ca-dir ./ca --version v20251228_abc123

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

	// Resolve ordinal version references (v1, v2, v3, etc.) to full version IDs
	targetVersionID := caActivateVersion
	if len(caActivateVersion) >= 2 && caActivateVersion[0] == 'v' {
		if ordinal, err := strconv.Atoi(caActivateVersion[1:]); err == nil && ordinal >= 1 {
			versions, err := versionStore.ListVersions()
			if err != nil {
				return fmt.Errorf("failed to list versions: %w", err)
			}

			// v1 = original CA (cannot be activated)
			// v2 = first versioned version (index 0)
			// v3 = second versioned version (index 1)
			// etc.
			if ordinal == 1 {
				return fmt.Errorf("v1 refers to the original CA, which cannot be activated (it has no version entry)")
			}

			versionIndex := ordinal - 2 // v2 = index 0, v3 = index 1, etc.
			if versionIndex >= len(versions) {
				return fmt.Errorf("version v%d not found (only %d versions exist)", ordinal, len(versions)+1)
			}
			targetVersionID = versions[versionIndex].ID
		}
	}

	// Get version info before activation
	version, err := versionStore.GetVersion(targetVersionID)
	if err != nil {
		return err
	}

	if version.Status != ca.VersionStatusPending {
		return fmt.Errorf("version %s is not pending (status: %s)", targetVersionID, version.Status)
	}

	// Activate
	if err := versionStore.Activate(targetVersionID); err != nil {
		return fmt.Errorf("activation failed: %w", err)
	}

	fmt.Printf("CA version %s activated successfully!\n", targetVersionID)
	fmt.Println()
	fmt.Printf("Profile:    %s\n", version.Profile)
	fmt.Printf("Algorithm:  %s\n", version.Algorithm)
	fmt.Printf("Valid:      %s to %s\n",
		version.NotBefore.Format("2006-01-02"),
		version.NotAfter.Format("2006-01-02"))
	fmt.Println()
	fmt.Println("The CA root files (ca.crt, private/ca.key) have been updated.")
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

	fmt.Printf("%-20s %-10s %-20s %-12s %s\n", "VERSION", "STATUS", "ALGORITHM", "CREATED", "CROSS-SIGNED")
	fmt.Printf("%-20s %-10s %-20s %-12s %s\n", "-------", "------", "---------", "-------", "------------")

	for _, v := range versions {
		crossSigned := "-"
		if len(v.CrossSignedBy) > 0 {
			crossSigned = "yes"
		}

		fmt.Printf("%-20s %-10s %-20s %-12s %s\n",
			v.ID,
			v.Status,
			v.Algorithm,
			v.Created.Format("2006-01-02"),
			crossSigned,
		)
	}

	return nil
}
