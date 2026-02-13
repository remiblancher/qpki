//go:build acceptance

package acceptance

import (
	"os"
	"path/filepath"
	"testing"
)

// =============================================================================
// HSM Tests (TestA_HSM_*)
//
// These tests are HSM-specific and cannot be covered by generic tests.
// Skip if HSM_CONFIG is not set.
//
// Note: skipIfNoHSM, getHSMConfigPath, randomSuffix are in helpers_test.go
// =============================================================================

func TestA_HSM_List_Tokens(t *testing.T) {
	skipIfNoHSM(t)
	configPath := getHSMConfigPath(t)

	output := runQPKI(t, "hsm", "list", "--hsm-config", configPath)
	// Should at least run without error
	_ = output
}

func TestA_HSM_Test_Connection(t *testing.T) {
	skipIfNoHSM(t)
	configPath := getHSMConfigPath(t)

	runQPKI(t, "hsm", "test", "--hsm-config", configPath)
}

func TestA_HSM_Info(t *testing.T) {
	skipIfNoHSM(t)
	configPath := getHSMConfigPath(t)

	output := runQPKI(t, "hsm", "info", "--hsm-config", configPath)
	assertOutputContains(t, output, "Token")
}

func TestA_HSM_CA_Init_WithExistingKey(t *testing.T) {
	skipIfNoHSM(t)
	configPath := getHSMConfigPath(t)

	// First generate a key
	keyLabel := "test-ca-key-" + randomSuffix()
	runQPKI(t, "key", "gen",
		"--algorithm", "ecdsa-p384",
		"--hsm-config", configPath,
		"--key-label", keyLabel,
	)

	// Create CA using existing key
	caDir := t.TempDir()
	runQPKI(t, "ca", "init",
		"--hsm-config", configPath,
		"--key-label", keyLabel,
		"--use-existing-key",
		"--profile", "ec/root-ca",
		"--var", "cn=HSM Test CA",
		"--ca-dir", caDir,
	)

	runQPKI(t, "ca", "export", "--ca-dir", caDir, "--out", filepath.Join(caDir, "ca.crt"))
	assertFileExists(t, filepath.Join(caDir, "ca.crt"))

	// Verify CA certificate
	output := runQPKI(t, "inspect", filepath.Join(caDir, "ca.crt"))
	assertOutputContains(t, output, "HSM Test CA")
}

func TestA_HSM_Credential_Enroll_SoftwareKey(t *testing.T) {
	skipIfNoHSM(t)
	configPath := getHSMConfigPath(t)

	keyLabel := "cred-ca-key-" + randomSuffix()
	caDir := t.TempDir()

	// Create HSM-backed CA
	runQPKI(t, "ca", "init",
		"--hsm-config", configPath,
		"--key-label", keyLabel,
		"--profile", "ec/root-ca",
		"--var", "cn=HSM CA for Cred",
		"--ca-dir", caDir,
	)

	runQPKI(t, "ca", "export", "--ca-dir", caDir, "--out", filepath.Join(caDir, "ca.crt"))

	// Enroll credential with software key (no HSM)
	credDir := filepath.Join(caDir, "credentials")
	runQPKI(t, "credential", "enroll",
		"--ca-dir", caDir,
		"--cred-dir", credDir,
		"--profile", "ec/tls-server",
		"--var", "cn=hsm.test.local",
		"--var", "dns_names=hsm.test.local",
	)

	// Verify credential was created
	entries, err := os.ReadDir(credDir)
	if err != nil || len(entries) == 0 {
		t.Fatal("no credential created")
	}
}
