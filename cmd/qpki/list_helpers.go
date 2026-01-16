package main

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/remiblancher/post-quantum-pki/internal/ca"
)

// getEffectiveStatus returns the effective status, checking for expiry.
func getEffectiveStatus(e *ca.IndexEntry, now time.Time) string {
	if e.Status == "V" && !e.Expiry.IsZero() && e.Expiry.Before(now) {
		return "E"
	}
	return e.Status
}

// filterCertEntries filters certificate entries by status.
func filterCertEntries(entries []ca.IndexEntry, statusFilter string, now time.Time) ([]ca.IndexEntry, error) {
	if statusFilter != "" && statusFilter != "valid" && statusFilter != "revoked" && statusFilter != "expired" {
		return nil, fmt.Errorf("unknown status filter: %s (use: valid, revoked, expired)", statusFilter)
	}

	var filtered []ca.IndexEntry
	for _, e := range entries {
		status := getEffectiveStatus(&e, now)

		switch statusFilter {
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
		}
		filtered = append(filtered, e)
	}
	return filtered, nil
}

// formatCertEntry formats a certificate entry for display.
func formatCertEntry(e *ca.IndexEntry, now time.Time, verbose bool) (statusStr, serial, expiry, subject string) {
	status := getEffectiveStatus(e, now)
	statusStr = formatStatus(status)

	serial = hex.EncodeToString(e.Serial)
	if len(serial) > 18 {
		serial = serial[:18] + ".."
	}

	expiry = "-"
	if !e.Expiry.IsZero() {
		expiry = e.Expiry.Format("2006-01-02 15:04")
	}

	subject = e.Subject
	if len(subject) > 50 && !verbose {
		subject = subject[:47] + "..."
	}

	return
}

// printCertList prints the certificate list with header and footer.
func printCertList(entries []ca.IndexEntry, now time.Time, verbose bool) {
	fmt.Printf("%-6s %-20s %-20s %s\n", "STATUS", "SERIAL", "EXPIRES", "SUBJECT")
	fmt.Println("------ -------------------- -------------------- -------")

	for _, e := range entries {
		statusStr, serial, expiry, subject := formatCertEntry(&e, now, verbose)
		fmt.Printf("%-6s %-20s %-20s %s\n", statusStr, serial, expiry, subject)
	}

	fmt.Printf("\nTotal: %d certificate(s)\n", len(entries))
}
