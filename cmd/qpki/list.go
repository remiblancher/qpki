package main

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/remiblancher/qpki/pkg/ca"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List issued certificates",
	Long: `List all certificates issued by the CA.

Shows certificate status, serial number, expiration date, and subject.

Status codes:
  V - Valid
  R - Revoked
  E - Expired

Examples:
  # List all certificates
  pki list --ca-dir ./myca

  # Show only expired certificates
  pki list --status expired`,
	RunE: runList,
}

var (
	listCADir   string
	listStatus  string
	listVerbose bool
)

func init() {
	flags := listCmd.Flags()
	flags.StringVarP(&listCADir, "ca-dir", "d", "./ca", "CA directory")
	flags.StringVar(&listStatus, "status", "", "Filter by status (valid, revoked, expired)")
	flags.BoolVarP(&listVerbose, "verbose", "v", false, "Show detailed information")
}

func runList(cmd *cobra.Command, args []string) error {
	absDir, _ := filepath.Abs(listCADir)
	store := ca.NewFileStore(absDir)

	if !store.Exists() {
		return fmt.Errorf("CA not found at %s", absDir)
	}

	entries, err := store.ReadIndex(context.Background())
	if err != nil {
		return fmt.Errorf("failed to read certificate index: %w", err)
	}

	if len(entries) == 0 {
		fmt.Println("No certificates issued.")
		return nil
	}

	// Filter entries
	now := time.Now()
	filtered, err := filterCertEntries(entries, listStatus, now)
	if err != nil {
		return err
	}

	if len(filtered) == 0 {
		fmt.Println("No certificates match the filter.")
		return nil
	}

	printCertList(filtered, now, listVerbose)
	return nil
}

func formatStatus(status string) string {
	switch status {
	case "V":
		return "[V]"
	case "R":
		return "[R]"
	case "E":
		return "[E]"
	default:
		return "[?]"
	}
}
