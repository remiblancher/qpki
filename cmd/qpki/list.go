package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/remiblancher/post-quantum-pki/internal/ca"
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
	var filtered []ca.IndexEntry
	now := time.Now()

	for _, e := range entries {
		// Update status if expired
		status := e.Status
		if status == "V" && !e.Expiry.IsZero() && e.Expiry.Before(now) {
			status = "E"
		}

		// Apply filter
		switch listStatus {
		case "valid":
			if status != "V" {
				continue
			}
		case "revoked":
			if status != "R" {
				continue
			}
		case "expired":
			if status != "E" {
				continue
			}
		case "":
			// No filter
		default:
			return fmt.Errorf("unknown status filter: %s (use: valid, revoked, expired)", listStatus)
		}

		filtered = append(filtered, e)
	}

	if len(filtered) == 0 {
		fmt.Println("No certificates match the filter.")
		return nil
	}

	// Print header
	fmt.Printf("%-6s %-20s %-20s %s\n", "STATUS", "SERIAL", "EXPIRES", "SUBJECT")
	fmt.Println("------ -------------------- -------------------- -------")

	for _, e := range filtered {
		status := e.Status
		if status == "V" && !e.Expiry.IsZero() && e.Expiry.Before(now) {
			status = "E"
		}

		statusStr := formatStatus(status)
		serial := hex.EncodeToString(e.Serial)
		if len(serial) > 18 {
			serial = serial[:18] + ".."
		}

		expiry := "-"
		if !e.Expiry.IsZero() {
			expiry = e.Expiry.Format("2006-01-02 15:04")
		}

		subject := e.Subject
		if len(subject) > 50 && !listVerbose {
			subject = subject[:47] + "..."
		}

		fmt.Printf("%-6s %-20s %-20s %s\n", statusStr, serial, expiry, subject)
	}

	fmt.Printf("\nTotal: %d certificate(s)\n", len(filtered))

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
