//go:build cgo

package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// =============================================================================
// PKCS#11 Test Helpers
// =============================================================================

const (
	testTokenLabel = "pki-test-token"
	testTokenPIN   = "1234"
	testSOPIN      = "12345678"
)

// testSoftHSM holds SoftHSM test environment info
type testSoftHSM struct {
	modulePath string
	tokenDir   string
	configFile string
}

// setupSoftHSM creates a temporary SoftHSM token for testing.
// Returns nil and skips the test if SoftHSM is not available.
func setupSoftHSM(t *testing.T) *testSoftHSM {
	t.Helper()

	// Check if softhsm2-util is available
	if _, err := exec.LookPath("softhsm2-util"); err != nil {
		t.Skip("softhsm2-util not found, skipping PKCS#11 tests")
	}

	// Find SoftHSM library
	modulePath := findSoftHSMLib()
	if modulePath == "" {
		t.Skip("SoftHSM library not found, skipping PKCS#11 tests")
	}

	// Create temporary directory for token storage
	tokenDir := t.TempDir()
	tokensDir := filepath.Join(tokenDir, "tokens")
	if err := os.MkdirAll(tokensDir, 0700); err != nil {
		t.Fatalf("Failed to create token directory: %v", err)
	}

	// Create SoftHSM config file
	configFile := filepath.Join(tokenDir, "softhsm2.conf")
	configContent := "directories.tokendir = " + tokensDir + "\nobjectstore.backend = file\nlog.level = ERROR\n"
	if err := os.WriteFile(configFile, []byte(configContent), 0600); err != nil {
		t.Fatalf("Failed to write SoftHSM config: %v", err)
	}

	// Set SOFTHSM2_CONF environment variable
	t.Setenv("SOFTHSM2_CONF", configFile)

	// Initialize the token
	cmd := exec.Command("softhsm2-util", "--init-token", "--free",
		"--label", testTokenLabel,
		"--pin", testTokenPIN,
		"--so-pin", testSOPIN)
	cmd.Env = append(os.Environ(), "SOFTHSM2_CONF="+configFile)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to initialize SoftHSM token: %v\nOutput: %s", err, output)
	}

	return &testSoftHSM{
		modulePath: modulePath,
		tokenDir:   tokenDir,
		configFile: configFile,
	}
}

// findSoftHSMLib finds the SoftHSM library path
func findSoftHSMLib() string {
	// Common paths for SoftHSM library
	paths := []string{
		"/usr/local/Cellar/softhsm/2.6.1/lib/softhsm/libsofthsm2.so", // macOS Homebrew
		"/usr/local/lib/softhsm/libsofthsm2.so",
		"/usr/lib/softhsm/libsofthsm2.so",
		"/usr/lib64/softhsm/libsofthsm2.so",
		"/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so", // Debian/Ubuntu
		"/opt/homebrew/lib/softhsm/libsofthsm2.so",         // macOS ARM Homebrew
	}

	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	return ""
}

// =============================================================================
// ListHSMSlots Unit Tests
// =============================================================================

func TestU_ListHSMSlots_Valid(t *testing.T) {
	hsm := setupSoftHSM(t)

	info, err := ListHSMSlots(hsm.modulePath)
	if err != nil {
		t.Fatalf("ListHSMSlots() error = %v", err)
	}

	if info == nil {
		t.Fatal("ListHSMSlots() returned nil")
	}

	if len(info.Slots) == 0 {
		t.Error("ListHSMSlots() returned no slots")
	}

	// Find our test token
	found := false
	for _, slot := range info.Slots {
		if slot.TokenLabel == testTokenLabel {
			found = true
			if !slot.HasToken {
				t.Error("Slot should have token present")
			}
			break
		}
	}
	if !found {
		t.Errorf("Test token '%s' not found in slot list", testTokenLabel)
	}
}

func TestU_ListHSMSlots_InvalidModule(t *testing.T) {
	_, err := ListHSMSlots("/nonexistent/path/to/module.so")
	if err == nil {
		t.Error("ListHSMSlots() should fail for invalid module path")
	}
}

// =============================================================================
// GenerateHSMKeyPair Unit Tests
// =============================================================================

func TestU_GenerateHSMKeyPair_ECDSA_P256(t *testing.T) {
	hsm := setupSoftHSM(t)

	cfg := GenerateHSMKeyPairConfig{
		ModulePath: hsm.modulePath,
		TokenLabel: testTokenLabel,
		PIN:        testTokenPIN,
		KeyLabel:   "test-ecdsa-p256",
		Algorithm:  AlgECDSAP256,
	}

	result, err := GenerateHSMKeyPair(cfg)
	if err != nil {
		t.Fatalf("GenerateHSMKeyPair() error = %v", err)
	}

	if result.KeyLabel != cfg.KeyLabel {
		t.Errorf("KeyLabel = %s, want %s", result.KeyLabel, cfg.KeyLabel)
	}
	if result.Type != "EC" {
		t.Errorf("Type = %s, want EC", result.Type)
	}
	if result.Size != 256 {
		t.Errorf("Size = %d, want 256", result.Size)
	}
}

func TestU_GenerateHSMKeyPair_ECDSA_P384(t *testing.T) {
	hsm := setupSoftHSM(t)

	cfg := GenerateHSMKeyPairConfig{
		ModulePath: hsm.modulePath,
		TokenLabel: testTokenLabel,
		PIN:        testTokenPIN,
		KeyLabel:   "test-ecdsa-p384",
		Algorithm:  AlgECDSAP384,
	}

	result, err := GenerateHSMKeyPair(cfg)
	if err != nil {
		t.Fatalf("GenerateHSMKeyPair() error = %v", err)
	}

	if result.Type != "EC" {
		t.Errorf("Type = %s, want EC", result.Type)
	}
	if result.Size != 384 {
		t.Errorf("Size = %d, want 384", result.Size)
	}
}

func TestU_GenerateHSMKeyPair_RSA_2048(t *testing.T) {
	hsm := setupSoftHSM(t)

	cfg := GenerateHSMKeyPairConfig{
		ModulePath: hsm.modulePath,
		TokenLabel: testTokenLabel,
		PIN:        testTokenPIN,
		KeyLabel:   "test-rsa-2048",
		Algorithm:  AlgRSA2048,
	}

	result, err := GenerateHSMKeyPair(cfg)
	if err != nil {
		t.Fatalf("GenerateHSMKeyPair() error = %v", err)
	}

	if result.Type != "RSA" {
		t.Errorf("Type = %s, want RSA", result.Type)
	}
	if result.Size != 2048 {
		t.Errorf("Size = %d, want 2048", result.Size)
	}
}

func TestU_GenerateHSMKeyPair_UnsupportedAlgorithm(t *testing.T) {
	hsm := setupSoftHSM(t)

	cfg := GenerateHSMKeyPairConfig{
		ModulePath: hsm.modulePath,
		TokenLabel: testTokenLabel,
		PIN:        testTokenPIN,
		KeyLabel:   "test-unsupported",
		Algorithm:  AlgMLDSA65, // PQC not supported by HSM
	}

	_, err := GenerateHSMKeyPair(cfg)
	if err == nil {
		t.Error("GenerateHSMKeyPair() should fail for unsupported algorithm")
	}
}

func TestU_GenerateHSMKeyPair_MissingConfig(t *testing.T) {
	// Missing module path
	_, err := GenerateHSMKeyPair(GenerateHSMKeyPairConfig{
		TokenLabel: testTokenLabel,
		PIN:        testTokenPIN,
		KeyLabel:   "test-key",
		Algorithm:  AlgECDSAP256,
	})
	if err == nil {
		t.Error("GenerateHSMKeyPair() should fail for missing module path")
	}

	// Missing key label
	hsm := setupSoftHSM(t)
	_, err = GenerateHSMKeyPair(GenerateHSMKeyPairConfig{
		ModulePath: hsm.modulePath,
		TokenLabel: testTokenLabel,
		PIN:        testTokenPIN,
		Algorithm:  AlgECDSAP256,
	})
	if err == nil {
		t.Error("GenerateHSMKeyPair() should fail for missing key label")
	}
}

// =============================================================================
// NewPKCS11Signer Unit Tests
// =============================================================================

func TestU_NewPKCS11Signer_ECDSA(t *testing.T) {
	hsm := setupSoftHSM(t)

	// First generate a key
	keyLabel := "test-signer-ecdsa"
	genCfg := GenerateHSMKeyPairConfig{
		ModulePath: hsm.modulePath,
		TokenLabel: testTokenLabel,
		PIN:        testTokenPIN,
		KeyLabel:   keyLabel,
		Algorithm:  AlgECDSAP256,
	}
	_, err := GenerateHSMKeyPair(genCfg)
	if err != nil {
		t.Fatalf("GenerateHSMKeyPair() error = %v", err)
	}

	// Create signer
	signerCfg := PKCS11Config{
		ModulePath: hsm.modulePath,
		TokenLabel: testTokenLabel,
		PIN:        testTokenPIN,
		KeyLabel:   keyLabel,
	}

	signer, err := NewPKCS11Signer(signerCfg)
	if err != nil {
		t.Fatalf("NewPKCS11Signer() error = %v", err)
	}
	defer func() { _ = signer.Close() }()

	if signer.Algorithm() != AlgECDSAP256 {
		t.Errorf("Algorithm() = %s, want %s", signer.Algorithm(), AlgECDSAP256)
	}

	if signer.Public() == nil {
		t.Error("Public() returned nil")
	}
}

func TestU_NewPKCS11Signer_MissingConfig(t *testing.T) {
	// Missing module path
	_, err := NewPKCS11Signer(PKCS11Config{
		TokenLabel: testTokenLabel,
		PIN:        testTokenPIN,
		KeyLabel:   "test-key",
	})
	if err == nil {
		t.Error("NewPKCS11Signer() should fail for missing module path")
	}

	// Missing key identification
	_, err = NewPKCS11Signer(PKCS11Config{
		ModulePath: "/some/path/libsofthsm2.so",
		TokenLabel: testTokenLabel,
		PIN:        testTokenPIN,
	})
	if err == nil {
		t.Error("NewPKCS11Signer() should fail for missing key label/id")
	}
}

// =============================================================================
// PKCS11Signer Sign Unit Tests
// =============================================================================

func TestU_PKCS11Signer_Sign_ECDSA(t *testing.T) {
	hsm := setupSoftHSM(t)

	// Generate key
	keyLabel := "test-sign-ecdsa"
	genCfg := GenerateHSMKeyPairConfig{
		ModulePath: hsm.modulePath,
		TokenLabel: testTokenLabel,
		PIN:        testTokenPIN,
		KeyLabel:   keyLabel,
		Algorithm:  AlgECDSAP256,
	}
	_, err := GenerateHSMKeyPair(genCfg)
	if err != nil {
		t.Fatalf("GenerateHSMKeyPair() error = %v", err)
	}

	// Create signer
	signerCfg := PKCS11Config{
		ModulePath: hsm.modulePath,
		TokenLabel: testTokenLabel,
		PIN:        testTokenPIN,
		KeyLabel:   keyLabel,
	}

	signer, err := NewPKCS11Signer(signerCfg)
	if err != nil {
		t.Fatalf("NewPKCS11Signer() error = %v", err)
	}
	defer func() { _ = signer.Close() }()

	// Sign some data
	message := []byte("test message for signing")
	digest := sha256.Sum256(message)

	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	if len(signature) == 0 {
		t.Error("Sign() returned empty signature")
	}
}

func TestU_PKCS11Signer_Sign_RSA(t *testing.T) {
	hsm := setupSoftHSM(t)

	// Generate RSA key
	keyLabel := "test-sign-rsa"
	genCfg := GenerateHSMKeyPairConfig{
		ModulePath: hsm.modulePath,
		TokenLabel: testTokenLabel,
		PIN:        testTokenPIN,
		KeyLabel:   keyLabel,
		Algorithm:  AlgRSA2048,
	}
	_, err := GenerateHSMKeyPair(genCfg)
	if err != nil {
		t.Fatalf("GenerateHSMKeyPair() error = %v", err)
	}

	// Create signer
	signerCfg := PKCS11Config{
		ModulePath: hsm.modulePath,
		TokenLabel: testTokenLabel,
		PIN:        testTokenPIN,
		KeyLabel:   keyLabel,
	}

	signer, err := NewPKCS11Signer(signerCfg)
	if err != nil {
		t.Fatalf("NewPKCS11Signer() error = %v", err)
	}
	defer func() { _ = signer.Close() }()

	// Sign some data
	message := []byte("test message for RSA signing")
	digest := sha256.Sum256(message)

	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	if len(signature) == 0 {
		t.Error("Sign() returned empty signature")
	}
}

// =============================================================================
// PKCS11Signer Close Unit Tests
// =============================================================================

func TestU_PKCS11Signer_Close(t *testing.T) {
	hsm := setupSoftHSM(t)

	// Generate key
	keyLabel := "test-close"
	genCfg := GenerateHSMKeyPairConfig{
		ModulePath: hsm.modulePath,
		TokenLabel: testTokenLabel,
		PIN:        testTokenPIN,
		KeyLabel:   keyLabel,
		Algorithm:  AlgECDSAP256,
	}
	_, err := GenerateHSMKeyPair(genCfg)
	if err != nil {
		t.Fatalf("GenerateHSMKeyPair() error = %v", err)
	}

	// Create signer
	signerCfg := PKCS11Config{
		ModulePath: hsm.modulePath,
		TokenLabel: testTokenLabel,
		PIN:        testTokenPIN,
		KeyLabel:   keyLabel,
	}

	signer, err := NewPKCS11Signer(signerCfg)
	if err != nil {
		t.Fatalf("NewPKCS11Signer() error = %v", err)
	}

	// Close should succeed
	err = signer.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}

	// Second close should be safe (idempotent)
	err = signer.Close()
	if err != nil {
		t.Errorf("Second Close() error = %v", err)
	}
}

// =============================================================================
// ListHSMKeys Unit Tests
// =============================================================================

func TestU_ListHSMKeys_Valid(t *testing.T) {
	hsm := setupSoftHSM(t)

	// Generate a key first
	keyLabel := "test-list-key"
	genCfg := GenerateHSMKeyPairConfig{
		ModulePath: hsm.modulePath,
		TokenLabel: testTokenLabel,
		PIN:        testTokenPIN,
		KeyLabel:   keyLabel,
		Algorithm:  AlgECDSAP256,
	}
	_, err := GenerateHSMKeyPair(genCfg)
	if err != nil {
		t.Fatalf("GenerateHSMKeyPair() error = %v", err)
	}

	// List keys
	keys, err := ListHSMKeys(hsm.modulePath, testTokenLabel, testTokenPIN)
	if err != nil {
		t.Fatalf("ListHSMKeys() error = %v", err)
	}

	// Should find our key
	found := false
	for _, key := range keys {
		if key.Label == keyLabel {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Key '%s' not found in key list", keyLabel)
	}
}
