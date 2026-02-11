//go:build acceptance

package acceptance

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// =============================================================================
// HSM Tests (TestA_HSM_*)
//
// These tests require SoftHSM2 to be installed and configured.
// Skip if SOFTHSM2_CONF is not set.
// =============================================================================

func skipIfNoHSM(t *testing.T) {
	t.Helper()
	if os.Getenv("SOFTHSM2_CONF") == "" {
		t.Skip("SOFTHSM2_CONF not set, skipping HSM tests")
	}
	if os.Getenv("HSM_PIN") == "" {
		t.Skip("HSM_PIN not set, skipping HSM tests")
	}
}

func getHSMConfigPath(t *testing.T) string {
	t.Helper()
	configPath := os.Getenv("HSM_CONFIG")
	if configPath == "" {
		t.Skip("HSM_CONFIG not set, skipping HSM tests")
	}
	return configPath
}

func TestA_HSM_List_Tokens(t *testing.T) {
	skipIfNoHSM(t)

	lib := os.Getenv("SOFTHSM2_LIB")
	if lib == "" {
		lib = "/usr/lib/softhsm/libsofthsm2.so"
	}

	output := runQPKI(t, "hsm", "list", "--lib", lib)
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

func TestA_HSM_Key_Gen_EC(t *testing.T) {
	skipIfNoHSM(t)
	configPath := getHSMConfigPath(t)

	keyLabel := "test-ec-key-" + randomSuffix()

	runQPKI(t, "key", "gen",
		"--algorithm", "ecdsa-p384",
		"--hsm-config", configPath,
		"--key-label", keyLabel,
	)

	// Verify key is listed
	output := runQPKI(t, "key", "list", "--hsm-config", configPath)
	assertOutputContains(t, output, keyLabel)
}

func TestA_HSM_Key_Gen_RSA(t *testing.T) {
	skipIfNoHSM(t)
	configPath := getHSMConfigPath(t)

	keyLabel := "test-rsa-key-" + randomSuffix()

	runQPKI(t, "key", "gen",
		"--algorithm", "rsa-4096",
		"--hsm-config", configPath,
		"--key-label", keyLabel,
	)

	output := runQPKI(t, "key", "list", "--hsm-config", configPath)
	assertOutputContains(t, output, keyLabel)
}

func TestA_HSM_Key_List(t *testing.T) {
	skipIfNoHSM(t)
	configPath := getHSMConfigPath(t)

	runQPKI(t, "key", "list", "--hsm-config", configPath)
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

func TestA_HSM_CA_Init_GenerateKey(t *testing.T) {
	skipIfNoHSM(t)
	configPath := getHSMConfigPath(t)

	keyLabel := "auto-gen-ca-key-" + randomSuffix()
	caDir := t.TempDir()

	runQPKI(t, "ca", "init",
		"--hsm-config", configPath,
		"--key-label", keyLabel,
		"--generate-key",
		"--profile", "ec/root-ca",
		"--var", "cn=Auto-Gen HSM CA",
		"--ca-dir", caDir,
	)

	runQPKI(t, "ca", "export", "--ca-dir", caDir, "--out", filepath.Join(caDir, "ca.crt"))
	assertFileExists(t, filepath.Join(caDir, "ca.crt"))

	// Verify the CA was created
	output := runQPKI(t, "inspect", filepath.Join(caDir, "ca.crt"))
	assertOutputContains(t, output, "Auto-Gen HSM CA")

	// Verify key was created in HSM
	keysOutput := runQPKI(t, "key", "list", "--hsm-config", configPath)
	assertOutputContains(t, keysOutput, keyLabel)
}

func TestA_HSM_CA_Init_RSA(t *testing.T) {
	skipIfNoHSM(t)
	configPath := getHSMConfigPath(t)

	keyLabel := "rsa-ca-key-" + randomSuffix()
	runQPKI(t, "key", "gen",
		"--algorithm", "rsa-4096",
		"--hsm-config", configPath,
		"--key-label", keyLabel,
	)

	caDir := t.TempDir()
	runQPKI(t, "ca", "init",
		"--hsm-config", configPath,
		"--key-label", keyLabel,
		"--profile", "rsa/root-ca",
		"--var", "cn=RSA HSM Test CA",
		"--ca-dir", caDir,
	)

	runQPKI(t, "ca", "export", "--ca-dir", caDir, "--out", filepath.Join(caDir, "ca.crt"))

	output := runQPKI(t, "inspect", filepath.Join(caDir, "ca.crt"))
	assertOutputContains(t, output, "RSA")
}

func TestA_HSM_CA_Info(t *testing.T) {
	skipIfNoHSM(t)
	configPath := getHSMConfigPath(t)

	keyLabel := "info-ca-key-" + randomSuffix()
	caDir := t.TempDir()

	runQPKI(t, "ca", "init",
		"--hsm-config", configPath,
		"--key-label", keyLabel,
		"--generate-key",
		"--profile", "ec/root-ca",
		"--var", "cn=HSM CA Info Test",
		"--ca-dir", caDir,
	)

	runQPKI(t, "ca", "export", "--ca-dir", caDir, "--out", filepath.Join(caDir, "ca.crt"))

	output := runQPKI(t, "ca", "info", "--ca-dir", caDir)
	assertOutputContains(t, output, "HSM CA Info Test")
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
		"--generate-key",
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

func TestA_HSM_Credential_Enroll_HSMKey(t *testing.T) {
	skipIfNoHSM(t)
	configPath := getHSMConfigPath(t)

	caKeyLabel := "cred-ca-hsm-key-" + randomSuffix()
	caDir := t.TempDir()

	// Create HSM-backed CA
	runQPKI(t, "ca", "init",
		"--hsm-config", configPath,
		"--key-label", caKeyLabel,
		"--generate-key",
		"--profile", "ec/root-ca",
		"--var", "cn=HSM CA for HSM Cred",
		"--ca-dir", caDir,
	)

	runQPKI(t, "ca", "export", "--ca-dir", caDir, "--out", filepath.Join(caDir, "ca.crt"))

	// Enroll credential with HSM-backed key
	credKeyLabel := "cred-hsm-key-" + randomSuffix()
	credDir := filepath.Join(caDir, "credentials")
	runQPKI(t, "credential", "enroll",
		"--ca-dir", caDir,
		"--cred-dir", credDir,
		"--profile", "ec/tls-server",
		"--hsm-config", configPath,
		"--key-label", credKeyLabel,
		"--var", "cn=hsm-cred.test.local",
		"--var", "dns_names=hsm-cred.test.local",
	)

	// Verify key was created in HSM
	output := runQPKI(t, "key", "list", "--hsm-config", configPath)
	assertOutputContains(t, output, credKeyLabel)
}

func TestA_HSM_Credential_List(t *testing.T) {
	skipIfNoHSM(t)
	configPath := getHSMConfigPath(t)

	keyLabel := "list-ca-key-" + randomSuffix()
	caDir := t.TempDir()

	runQPKI(t, "ca", "init",
		"--hsm-config", configPath,
		"--key-label", keyLabel,
		"--generate-key",
		"--profile", "ec/root-ca",
		"--var", "cn=HSM CA for List",
		"--ca-dir", caDir,
	)

	runQPKI(t, "ca", "export", "--ca-dir", caDir, "--out", filepath.Join(caDir, "ca.crt"))

	credDir := filepath.Join(caDir, "credentials")
	runQPKI(t, "credential", "enroll",
		"--ca-dir", caDir,
		"--cred-dir", credDir,
		"--profile", "ec/tls-server",
		"--var", "cn=list.test.local",
		"--var", "dns_names=list.test.local",
	)

	output := runQPKI(t, "credential", "list", "--cred-dir", credDir)
	assertOutputContains(t, output, "list.test.local")
}

// =============================================================================
// Helper Functions
// =============================================================================

// randomSuffix generates a simple random suffix for unique key labels.
func randomSuffix() string {
	// Use current time nanoseconds for uniqueness
	return fmt.Sprintf("%08x", time.Now().UnixNano()&0xFFFFFFFF)
}
