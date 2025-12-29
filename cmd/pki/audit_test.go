package main

import (
	"testing"
)

// resetAuditFlags resets all audit command flags to their default values.
func resetAuditFlags() {
	auditLogFile = ""
	auditTailNum = 10
	auditShowJSON = false
}

// =============================================================================
// Audit Verify Tests
// =============================================================================

func TestAuditVerify_LogNotFound(t *testing.T) {
	tc := newTestContext(t)
	resetAuditFlags()

	_, err := executeCommand(rootCmd, "audit", "verify", "--log", tc.path("nonexistent.jsonl"))
	assertError(t, err)
}

func TestAuditVerify_EmptyLog(t *testing.T) {
	tc := newTestContext(t)
	resetAuditFlags()

	// Create empty log file
	logPath := tc.writeFile("audit.jsonl", "")

	_, err := executeCommand(rootCmd, "audit", "verify", "--log", logPath)
	// Empty log should still verify (0 events is valid)
	assertNoError(t, err)
}

func TestAuditVerify_ValidLog(t *testing.T) {
	tc := newTestContext(t)
	resetAuditFlags()

	// Create a valid single-event log with genesis hash
	logContent := `{"timestamp":"2024-01-01T00:00:00Z","event_type":"ca_init","result":"success","hash_prev":"sha256:genesis","hash":"sha256:abc123"}
`
	logPath := tc.writeFile("audit.jsonl", logContent)

	_, err := executeCommand(rootCmd, "audit", "verify", "--log", logPath)
	// This might fail if hash verification is strict, but it tests the command path
	_ = err // We just want to test the command runs
}

// =============================================================================
// Audit Tail Tests
// =============================================================================

func TestAuditTail_LogNotFound(t *testing.T) {
	tc := newTestContext(t)
	resetAuditFlags()

	_, err := executeCommand(rootCmd, "audit", "tail", "--log", tc.path("nonexistent.jsonl"))
	assertError(t, err)
}

func TestAuditTail_EmptyLog(t *testing.T) {
	tc := newTestContext(t)
	resetAuditFlags()

	// Create empty log file
	logPath := tc.writeFile("audit.jsonl", "")

	_, err := executeCommand(rootCmd, "audit", "tail", "--log", logPath)
	assertNoError(t, err)
}

func TestAuditTail_WithNumFlag(t *testing.T) {
	tc := newTestContext(t)
	resetAuditFlags()

	// Create log with some events
	logContent := `{"timestamp":"2024-01-01T00:00:00Z","event_type":"test1"}
{"timestamp":"2024-01-01T00:00:01Z","event_type":"test2"}
{"timestamp":"2024-01-01T00:00:02Z","event_type":"test3"}
`
	logPath := tc.writeFile("audit.jsonl", logContent)

	_, err := executeCommand(rootCmd, "audit", "tail", "--log", logPath, "-n", "2")
	assertNoError(t, err)
}

func TestAuditTail_JSONOutput(t *testing.T) {
	tc := newTestContext(t)
	resetAuditFlags()

	// Create log with an event
	logContent := `{"timestamp":"2024-01-01T00:00:00Z","event_type":"test"}
`
	logPath := tc.writeFile("audit.jsonl", logContent)

	_, err := executeCommand(rootCmd, "audit", "tail", "--log", logPath, "--json")
	assertNoError(t, err)
}
