//go:build acceptance

package acceptance

import (
	"path/filepath"
	"strings"
	"testing"
)

// =============================================================================
// Verb Harmonization Tests (TestA_Key_Verb_*)
// Spec: specs/community/001-verb-harmonization.md
// =============================================================================

// TestA_Key_Verb_Generate_FullVerb tests that "qpki key generate" works as the primary command.
// ATDD Scenario 1: Generate key with full verb
func TestA_Key_Verb_Generate_FullVerb(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "test.key")

	// When I run "qpki key generate --algorithm ecdsa-p256 --out <path>"
	runQPKI(t, "key", "generate", "--algorithm", "ecdsa-p256", "--out", keyPath)

	// Then a key pair is generated
	assertFileExists(t, keyPath)
}

// TestA_Key_Verb_Gen_Alias tests that "qpki key gen" still works as an alias.
// ATDD Scenario 2: Generate key with alias (backward compatibility)
func TestA_Key_Verb_Gen_Alias(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "test.key")

	// When I run "qpki key gen --algorithm ecdsa-p256 --out <path>"
	runQPKI(t, "key", "gen", "--algorithm", "ecdsa-p256", "--out", keyPath)

	// Then a key pair is generated (alias works)
	assertFileExists(t, keyPath)
}

// TestA_Key_Verb_Help_ShowsGenerate tests that help shows "generate" as primary with "gen" alias.
// ATDD Scenario 3: Help shows correct verb
func TestA_Key_Verb_Help_ShowsGenerate(t *testing.T) {
	// When I run "qpki key --help"
	output := runQPKI(t, "key", "--help")

	// Then the output shows "generate" as the command
	if !strings.Contains(output, "generate") {
		t.Errorf("expected help to show 'generate' command, got:\n%s", output)
	}
}

// TestA_Key_Verb_Generate_Help_ShowsAlias tests that "generate --help" shows the alias.
// ATDD Scenario 4: Generate help shows alias
func TestA_Key_Verb_Generate_Help_ShowsAlias(t *testing.T) {
	// When I run "qpki key generate --help"
	output := runQPKI(t, "key", "generate", "--help")

	// Then the output mentions "gen" as an alias (either "Aliases: gen" or similar)
	// Cobra shows aliases in the format "Aliases:"
	if !strings.Contains(strings.ToLower(output), "alias") || !strings.Contains(output, "gen") {
		t.Errorf("expected help to show 'gen' as alias, got:\n%s", output)
	}
}

// TestA_Key_Verb_Generate_MLDSA tests that "generate" works with PQC algorithms.
func TestA_Key_Verb_Generate_MLDSA(t *testing.T) {
	skipIfAlgorithmNotSupported(t, "ml-dsa-65")

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "mldsa.key")

	// When I run "qpki key generate --algorithm ml-dsa-65 --out <path>"
	runQPKI(t, "key", "generate", "--algorithm", "ml-dsa-65", "--out", keyPath)

	// Then a key pair is generated
	assertFileExists(t, keyPath)
}
