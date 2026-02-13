//go:build acceptance

package acceptance

import (
	"strings"
	"testing"
)

// =============================================================================
// Hybrid HSM Tests (TestA_HSM_Hybrid_*)
//
// These tests validate hybrid/catalyst mode with PQC-capable HSMs.
// Hybrid mode uses two keys with the same label but different CKA_KEY_TYPE:
//   - Classical: CKK_EC (ECDSA P-384)
//   - PQC: CKK_UTI_MLDSA (ML-DSA-65)
//
// Requires: HSM_PQC_ENABLED=1
// =============================================================================

// TestA_HSM_Hybrid_SameLabel_DifferentTypes verifies that two keys with
// the same CKA_LABEL but different CKA_KEY_TYPE can coexist in the HSM.
// This is the foundation for hybrid/catalyst mode.
func TestA_HSM_Hybrid_SameLabel_DifferentTypes(t *testing.T) {
	skipIfNoPQCHSM(t)
	configPath := getHSMConfigPath(t)

	// Use same label for both keys
	keyLabel := "hybrid-test-" + randomSuffix()

	// Generate classical key (ECDSA P-384)
	runQPKI(t, "key", "gen",
		"--algorithm", "ecdsa-p384",
		"--hsm-config", configPath,
		"--key-label", keyLabel,
	)

	// Generate PQC key (ML-DSA-65) with SAME label
	runQPKI(t, "key", "gen",
		"--algorithm", "ml-dsa-65",
		"--hsm-config", configPath,
		"--key-label", keyLabel,
	)

	// List keys and verify both exist
	output := runQPKI(t, "key", "list", "--hsm-config", configPath)

	// The label should appear (at least once, possibly twice)
	assertOutputContains(t, output, keyLabel)

	// Verify both key types are present
	// EC keys show as "Type: EC"
	// ML-DSA keys show as "Type: Unknown(0x80000000)" (vendor-defined)
	hasEC := strings.Contains(output, "Type:    EC")
	hasPQC := strings.Contains(output, "Unknown(0x80000000)") || strings.Contains(output, "vendor")

	if !hasEC {
		t.Errorf("Expected EC key type in output, got: %s", output)
	}
	if !hasPQC {
		t.Errorf("Expected PQC key type (vendor-defined) in output, got: %s", output)
	}
}

// TestA_HSM_Hybrid_KeyInfo verifies key info shows both hybrid keys.
func TestA_HSM_Hybrid_KeyInfo(t *testing.T) {
	skipIfNoPQCHSM(t)
	configPath := getHSMConfigPath(t)

	keyLabel := "hybrid-info-test-" + randomSuffix()

	// Generate both keys with same label
	runQPKI(t, "key", "gen",
		"--algorithm", "ecdsa-p384",
		"--hsm-config", configPath,
		"--key-label", keyLabel,
	)
	runQPKI(t, "key", "gen",
		"--algorithm", "ml-dsa-65",
		"--hsm-config", configPath,
		"--key-label", keyLabel,
	)

	// key info should show both keys with same label
	output := runQPKI(t, "key", "info",
		"--hsm-config", configPath,
		"--key-label", keyLabel,
	)

	// Should show 2 keys found
	assertOutputContains(t, output, "Keys found: 2")
	assertOutputContains(t, output, keyLabel)
}

// TestA_HSM_Hybrid_AllVariants tests all ML-DSA variants with EC.
func TestA_HSM_Hybrid_AllVariants(t *testing.T) {
	skipIfNoPQCHSM(t)
	configPath := getHSMConfigPath(t)

	variants := []struct {
		ec    string
		pqc   string
		label string
	}{
		{"ecdsa-p256", "ml-dsa-44", "hybrid-p256-mldsa44-" + randomSuffix()},
		{"ecdsa-p384", "ml-dsa-65", "hybrid-p384-mldsa65-" + randomSuffix()},
		{"ecdsa-p521", "ml-dsa-87", "hybrid-p521-mldsa87-" + randomSuffix()},
	}

	for _, v := range variants {
		t.Run(v.ec+"_"+v.pqc, func(t *testing.T) {
			// Generate EC key
			runQPKI(t, "key", "gen",
				"--algorithm", v.ec,
				"--hsm-config", configPath,
				"--key-label", v.label,
			)

			// Generate ML-DSA key with same label
			runQPKI(t, "key", "gen",
				"--algorithm", v.pqc,
				"--hsm-config", configPath,
				"--key-label", v.label,
			)

			// Verify both keys exist
			output := runQPKI(t, "key", "list", "--hsm-config", configPath)
			assertOutputContains(t, output, v.label)
		})
	}
}
