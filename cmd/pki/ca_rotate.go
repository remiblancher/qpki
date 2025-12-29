package main

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/remiblancher/post-quantum-pki/internal/ca"
)

var caRotateCmd = &cobra.Command{
	Use:   "rotate",
	Short: "Rotate a CA (new keys/algorithm)",
	Long: `Rotate a Certificate Authority with new keys and optionally a new algorithm.

This creates a new CA version with fresh keys. The old version remains active
until you explicitly activate the new version with 'pki ca activate'.

Cross-signing behavior:
  auto - Cross-sign if algorithm changes (default)
  on   - Always cross-sign
  off  - Never cross-sign

Examples:
  # Preview rotation plan (dry-run)
  pki ca rotate --ca-dir ./ca --dry-run

  # Rotate with same profile (new keys only)
  pki ca rotate --ca-dir ./ca

  # Rotate to a new algorithm (PQC migration)
  pki ca rotate --ca-dir ./ca --profile ml-dsa/root-ca

  # Force cross-signing
  pki ca rotate --ca-dir ./ca --profile ml-dsa/root-ca --cross-sign on

  # After rotation, activate the new version
  pki ca activate --ca-dir ./ca --version v20251228_abc123`,
	RunE: runCARotate,
}

var (
	caRotateDir        string
	caRotateProfile    string
	caRotatePassphrase string
	caRotateCrossSign  string
	caRotateDryRun     bool
)

func init() {
	caCmd.AddCommand(caRotateCmd)

	caRotateCmd.Flags().StringVarP(&caRotateDir, "ca-dir", "d", "./ca", "CA directory")
	caRotateCmd.Flags().StringVarP(&caRotateProfile, "profile", "P", "", "New CA profile (optional, reuses existing if not specified)")
	caRotateCmd.Flags().StringVarP(&caRotatePassphrase, "passphrase", "p", "", "Passphrase for CA private keys")
	caRotateCmd.Flags().StringVar(&caRotateCrossSign, "cross-sign", "auto", "Cross-signing mode: auto, on, off")
	caRotateCmd.Flags().BoolVar(&caRotateDryRun, "dry-run", false, "Preview rotation plan without executing")
}

func runCARotate(cmd *cobra.Command, args []string) error {
	absDir, err := filepath.Abs(caRotateDir)
	if err != nil {
		return fmt.Errorf("invalid CA directory: %w", err)
	}

	// Parse cross-sign mode
	var crossSignMode ca.CrossSignMode
	switch caRotateCrossSign {
	case "auto":
		crossSignMode = ca.CrossSignAuto
	case "on":
		crossSignMode = ca.CrossSignOn
	case "off":
		crossSignMode = ca.CrossSignOff
	default:
		return fmt.Errorf("invalid cross-sign mode: %s (use: auto, on, off)", caRotateCrossSign)
	}

	// Build rotation request
	req := ca.RotateCARequest{
		CADir:      absDir,
		Profile:    caRotateProfile,
		Passphrase: caRotatePassphrase,
		CrossSign:  crossSignMode,
		DryRun:     caRotateDryRun,
	}

	// Execute rotation
	result, err := ca.RotateCA(req)
	if err != nil {
		return fmt.Errorf("rotation failed: %w", err)
	}

	// Display plan
	plan := result.Plan

	if caRotateDryRun {
		fmt.Println("CA Rotation Plan (dry-run)")
		fmt.Println("==========================")
	} else {
		fmt.Println("CA Rotation Complete")
		fmt.Println("====================")
	}
	fmt.Println()

	if plan.CurrentVersion != "" {
		fmt.Printf("Current version: %s\n", plan.CurrentVersion)
	}
	fmt.Printf("New version:     %s\n", plan.NewVersion)
	fmt.Printf("Profile:         %s\n", plan.Profile)
	fmt.Printf("Algorithm:       %s\n", plan.Algorithm)
	fmt.Printf("Subject:         %s\n", plan.Subject)
	fmt.Println()

	if plan.WillCrossSign {
		fmt.Printf("Cross-signing:   yes (%s)\n", plan.CrossSignReason)
	} else {
		fmt.Printf("Cross-signing:   no (%s)\n", plan.CrossSignReason)
	}
	fmt.Println()

	fmt.Println("Steps:")
	for i, step := range plan.Steps {
		if caRotateDryRun {
			fmt.Printf("  %d. [PLANNED] %s\n", i+1, step)
		} else {
			fmt.Printf("  %d. [DONE] %s\n", i+1, step)
		}
	}

	if caRotateDryRun {
		fmt.Println()
		fmt.Println("To execute this plan, run without --dry-run")
	} else {
		fmt.Println()
		fmt.Printf("New version %s created as PENDING.\n", result.Version.ID)
		fmt.Println()
		fmt.Println("To activate the new version:")
		fmt.Printf("  pki ca activate --ca-dir %s --version %s\n", caRotateDir, result.Version.ID)
	}

	return nil
}
