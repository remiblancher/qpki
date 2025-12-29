package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/remiblancher/post-quantum-pki/internal/audit"
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Audit log management",
	Long: `Commands for managing and verifying audit logs.

The audit log provides a tamper-evident record of all CA operations.
Each event is cryptographically chained using SHA-256 hashes.

Examples:
  # Verify audit log integrity
  pki audit verify --log /var/log/pki/audit.jsonl

  # Show last 10 events
  pki audit tail --log /var/log/pki/audit.jsonl -n 10`,
}

var auditVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify audit log integrity",
	Long: `Verify the cryptographic hash chain of an audit log file.

Each event in the log contains:
  - hash_prev: SHA-256 hash of the previous event
  - hash: SHA-256 hash of the current event

The chain starts with hash_prev="sha256:genesis" for the first event.

If the chain is broken (events modified, deleted, or inserted),
this command will report the location and nature of the tampering.`,
	RunE: runAuditVerify,
}

var auditTailCmd = &cobra.Command{
	Use:   "tail",
	Short: "Show recent audit events",
	Long:  `Display the most recent audit events from the log file.`,
	RunE:  runAuditTail,
}

var (
	auditLogFile  string
	auditTailNum  int
	auditShowJSON bool
)

func init() {
	auditVerifyCmd.Flags().StringVar(&auditLogFile, "log", "", "Path to audit log file (required)")
	_ = auditVerifyCmd.MarkFlagRequired("log")

	auditTailCmd.Flags().StringVar(&auditLogFile, "log", "", "Path to audit log file (required)")
	_ = auditTailCmd.MarkFlagRequired("log")
	auditTailCmd.Flags().IntVarP(&auditTailNum, "num", "n", 10, "Number of events to show")
	auditTailCmd.Flags().BoolVar(&auditShowJSON, "json", false, "Output as JSON")

	auditCmd.AddCommand(auditVerifyCmd)
	auditCmd.AddCommand(auditTailCmd)
}

func runAuditVerify(cmd *cobra.Command, args []string) error {
	fmt.Printf("Verifying audit log: %s\n\n", auditLogFile)

	count, err := audit.VerifyChain(auditLogFile)
	if err != nil {
		fmt.Printf("VERIFICATION FAILED\n")
		fmt.Printf("  Valid events: %d\n", count)
		fmt.Printf("  Error: %s\n", err)
		return fmt.Errorf("audit log verification failed: %w", err)
	}

	fmt.Printf("VERIFICATION PASSED\n")
	fmt.Printf("  Total events: %d\n", count)
	fmt.Printf("  Hash chain: VALID\n")

	return nil
}

func runAuditTail(cmd *cobra.Command, args []string) error {
	data, err := os.ReadFile(auditLogFile)
	if err != nil {
		return fmt.Errorf("failed to read audit log: %w", err)
	}

	if len(data) == 0 {
		fmt.Println("Audit log is empty")
		return nil
	}

	// Collect all lines
	var lines []string
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}

	// Get last N lines
	start := 0
	if len(lines) > auditTailNum {
		start = len(lines) - auditTailNum
	}
	lines = lines[start:]

	if auditShowJSON {
		fmt.Println("[")
		for i, line := range lines {
			if i > 0 {
				fmt.Println(",")
			}
			fmt.Print(line)
		}
		fmt.Println("\n]")
		return nil
	}

	// Pretty print
	for _, line := range lines {
		var event audit.Event
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			fmt.Printf("  [ERROR] %s\n", err)
			continue
		}

		printEvent(&event)
	}

	return nil
}

func printEvent(e *audit.Event) {
	resultIcon := "✓"
	if e.Result == "failure" {
		resultIcon = "✗"
	}

	fmt.Printf("[%s] %s %s\n", e.Timestamp, resultIcon, e.EventType)
	fmt.Printf("    Actor:  %s@%s\n", e.Actor.ID, e.Actor.Host)

	if e.Object.Type != "" {
		fmt.Printf("    Object: %s", e.Object.Type)
		if e.Object.Serial != "" {
			fmt.Printf(" serial=%s", e.Object.Serial)
		}
		if e.Object.Subject != "" {
			fmt.Printf(" subject=%s", e.Object.Subject)
		}
		if e.Object.Path != "" {
			fmt.Printf(" path=%s", e.Object.Path)
		}
		fmt.Println()
	}

	if e.Context.Profile != "" || e.Context.Algorithm != "" || e.Context.Reason != "" {
		fmt.Print("    Context:")
		if e.Context.Profile != "" {
			fmt.Printf(" profile=%s", e.Context.Profile)
		}
		if e.Context.Algorithm != "" {
			fmt.Printf(" algorithm=%s", e.Context.Algorithm)
		}
		if e.Context.Reason != "" {
			fmt.Printf(" reason=%s", e.Context.Reason)
		}
		fmt.Println()
	}

	fmt.Println()
}
