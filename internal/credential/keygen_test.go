package credential

import (
	"fmt"
	"testing"

	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
)

// =============================================================================
// GenerateKey Tests
// =============================================================================

func TestU_GenerateKey_Software_ECDSA(t *testing.T) {
	kp := pkicrypto.NewSoftwareKeyProvider()
	cfg := pkicrypto.KeyStorageConfig{
		Type: pkicrypto.KeyProviderTypeSoftware,
	}

	signer, storageRef, err := GenerateKey(kp, cfg, pkicrypto.AlgECDSAP256, "test-cred", 0)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	if signer == nil {
		t.Error("GenerateKey() returned nil signer")
	}

	if signer.Algorithm() != pkicrypto.AlgECDSAP256 {
		t.Errorf("Signer algorithm = %s, want %s", signer.Algorithm(), pkicrypto.AlgECDSAP256)
	}

	if storageRef.Type != "software" {
		t.Errorf("StorageRef.Type = %s, want software", storageRef.Type)
	}
}

func TestU_GenerateKey_Software_ECDSA_P384(t *testing.T) {
	kp := pkicrypto.NewSoftwareKeyProvider()
	cfg := pkicrypto.KeyStorageConfig{
		Type: pkicrypto.KeyProviderTypeSoftware,
	}

	signer, storageRef, err := GenerateKey(kp, cfg, pkicrypto.AlgECDSAP384, "test-cred", 1)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	if signer == nil {
		t.Error("GenerateKey() returned nil signer")
	}

	if signer.Algorithm() != pkicrypto.AlgECDSAP384 {
		t.Errorf("Signer algorithm = %s, want %s", signer.Algorithm(), pkicrypto.AlgECDSAP384)
	}

	if storageRef.Type != "software" {
		t.Errorf("StorageRef.Type = %s, want software", storageRef.Type)
	}
}

func TestU_GenerateKey_Software_MLDSA44(t *testing.T) {
	kp := pkicrypto.NewSoftwareKeyProvider()
	cfg := pkicrypto.KeyStorageConfig{
		Type: pkicrypto.KeyProviderTypeSoftware,
	}

	signer, storageRef, err := GenerateKey(kp, cfg, pkicrypto.AlgMLDSA44, "test-cred", 0)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	if signer == nil {
		t.Error("GenerateKey() returned nil signer")
	}

	if signer.Algorithm() != pkicrypto.AlgMLDSA44 {
		t.Errorf("Signer algorithm = %s, want %s", signer.Algorithm(), pkicrypto.AlgMLDSA44)
	}

	if storageRef.Type != "software" {
		t.Errorf("StorageRef.Type = %s, want software", storageRef.Type)
	}
}

func TestU_GenerateKey_Software_MLDSA65(t *testing.T) {
	kp := pkicrypto.NewSoftwareKeyProvider()
	cfg := pkicrypto.KeyStorageConfig{
		Type: pkicrypto.KeyProviderTypeSoftware,
	}

	signer, storageRef, err := GenerateKey(kp, cfg, pkicrypto.AlgMLDSA65, "test-cred", 0)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	if signer == nil {
		t.Error("GenerateKey() returned nil signer")
	}

	if signer.Algorithm() != pkicrypto.AlgMLDSA65 {
		t.Errorf("Signer algorithm = %s, want %s", signer.Algorithm(), pkicrypto.AlgMLDSA65)
	}

	if storageRef.Type != "software" {
		t.Errorf("StorageRef.Type = %s, want software", storageRef.Type)
	}
}

func TestU_GenerateKey_Software_MLDSA87(t *testing.T) {
	kp := pkicrypto.NewSoftwareKeyProvider()
	cfg := pkicrypto.KeyStorageConfig{
		Type: pkicrypto.KeyProviderTypeSoftware,
	}

	signer, storageRef, err := GenerateKey(kp, cfg, pkicrypto.AlgMLDSA87, "test-cred", 0)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	if signer == nil {
		t.Error("GenerateKey() returned nil signer")
	}

	if signer.Algorithm() != pkicrypto.AlgMLDSA87 {
		t.Errorf("Signer algorithm = %s, want %s", signer.Algorithm(), pkicrypto.AlgMLDSA87)
	}

	if storageRef.Type != "software" {
		t.Errorf("StorageRef.Type = %s, want software", storageRef.Type)
	}
}

func TestU_GenerateKey_Software_KEM_512(t *testing.T) {
	kp := pkicrypto.NewSoftwareKeyProvider()
	cfg := pkicrypto.KeyStorageConfig{
		Type: pkicrypto.KeyProviderTypeSoftware,
	}

	signer, storageRef, err := GenerateKey(kp, cfg, pkicrypto.AlgMLKEM512, "test-cred", 0)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	if signer == nil {
		t.Error("GenerateKey() returned nil signer")
	}

	if signer.Algorithm() != pkicrypto.AlgMLKEM512 {
		t.Errorf("Signer algorithm = %s, want %s", signer.Algorithm(), pkicrypto.AlgMLKEM512)
	}

	if storageRef.Type != "software" {
		t.Errorf("StorageRef.Type = %s, want software", storageRef.Type)
	}
}

func TestU_GenerateKey_Software_KEM_768(t *testing.T) {
	kp := pkicrypto.NewSoftwareKeyProvider()
	cfg := pkicrypto.KeyStorageConfig{
		Type: pkicrypto.KeyProviderTypeSoftware,
	}

	signer, storageRef, err := GenerateKey(kp, cfg, pkicrypto.AlgMLKEM768, "test-cred", 0)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	if signer == nil {
		t.Error("GenerateKey() returned nil signer")
	}

	if signer.Algorithm() != pkicrypto.AlgMLKEM768 {
		t.Errorf("Signer algorithm = %s, want %s", signer.Algorithm(), pkicrypto.AlgMLKEM768)
	}

	if storageRef.Type != "software" {
		t.Errorf("StorageRef.Type = %s, want software", storageRef.Type)
	}
}

func TestU_GenerateKey_Software_KEM_1024(t *testing.T) {
	kp := pkicrypto.NewSoftwareKeyProvider()
	cfg := pkicrypto.KeyStorageConfig{
		Type: pkicrypto.KeyProviderTypeSoftware,
	}

	signer, storageRef, err := GenerateKey(kp, cfg, pkicrypto.AlgMLKEM1024, "test-cred", 0)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	if signer == nil {
		t.Error("GenerateKey() returned nil signer")
	}

	if signer.Algorithm() != pkicrypto.AlgMLKEM1024 {
		t.Errorf("Signer algorithm = %s, want %s", signer.Algorithm(), pkicrypto.AlgMLKEM1024)
	}

	if storageRef.Type != "software" {
		t.Errorf("StorageRef.Type = %s, want software", storageRef.Type)
	}
}

func TestU_GenerateKey_Software_SLHDSA(t *testing.T) {
	kp := pkicrypto.NewSoftwareKeyProvider()
	cfg := pkicrypto.KeyStorageConfig{
		Type: pkicrypto.KeyProviderTypeSoftware,
	}

	signer, storageRef, err := GenerateKey(kp, cfg, pkicrypto.AlgSLHDSA128s, "test-cred", 0)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	if signer == nil {
		t.Error("GenerateKey() returned nil signer")
	}

	if signer.Algorithm() != pkicrypto.AlgSLHDSA128s {
		t.Errorf("Signer algorithm = %s, want %s", signer.Algorithm(), pkicrypto.AlgSLHDSA128s)
	}

	if storageRef.Type != "software" {
		t.Errorf("StorageRef.Type = %s, want software", storageRef.Type)
	}
}

func TestU_GenerateKey_MultipleKeys_SameCredential(t *testing.T) {
	kp := pkicrypto.NewSoftwareKeyProvider()
	cfg := pkicrypto.KeyStorageConfig{
		Type: pkicrypto.KeyProviderTypeSoftware,
	}

	credentialID := "multi-key-cred"

	// Generate multiple keys for the same credential
	algorithms := []pkicrypto.AlgorithmID{
		pkicrypto.AlgECDSAP256,
		pkicrypto.AlgMLDSA65,
		pkicrypto.AlgMLKEM768,
	}

	for i, alg := range algorithms {
		signer, storageRef, err := GenerateKey(kp, cfg, alg, credentialID, i)
		if err != nil {
			t.Fatalf("GenerateKey(%s) error = %v", alg, err)
		}

		if signer == nil {
			t.Errorf("GenerateKey(%s) returned nil signer", alg)
		}

		if signer.Algorithm() != alg {
			t.Errorf("GenerateKey(%s) signer algorithm = %s", alg, signer.Algorithm())
		}

		if storageRef.Type != "software" {
			t.Errorf("GenerateKey(%s) StorageRef.Type = %s, want software", alg, storageRef.Type)
		}
	}
}

func TestU_GenerateKey_InvalidAlgorithm(t *testing.T) {
	kp := pkicrypto.NewSoftwareKeyProvider()
	cfg := pkicrypto.KeyStorageConfig{
		Type: pkicrypto.KeyProviderTypeSoftware,
	}

	// Try with an invalid/unknown algorithm
	_, _, err := GenerateKey(kp, cfg, pkicrypto.AlgorithmID("invalid-algo"), "test-cred", 0)
	if err == nil {
		t.Error("GenerateKey() should fail for invalid algorithm")
	}
}

func TestU_GenerateKey_Ed25519(t *testing.T) {
	kp := pkicrypto.NewSoftwareKeyProvider()
	cfg := pkicrypto.KeyStorageConfig{
		Type: pkicrypto.KeyProviderTypeSoftware,
	}

	signer, storageRef, err := GenerateKey(kp, cfg, pkicrypto.AlgEd25519, "test-cred", 0)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	if signer == nil {
		t.Error("GenerateKey() returned nil signer")
	}

	if signer.Algorithm() != pkicrypto.AlgEd25519 {
		t.Errorf("Signer algorithm = %s, want %s", signer.Algorithm(), pkicrypto.AlgEd25519)
	}

	if storageRef.Type != "software" {
		t.Errorf("StorageRef.Type = %s, want software", storageRef.Type)
	}
}

// =============================================================================
// PKCS#11 Path Tests (with mock provider)
// =============================================================================

// mockPKCS11KeyProvider simulates a PKCS#11 key provider for testing
type mockPKCS11KeyProvider struct {
	generateErr error
}

func (m *mockPKCS11KeyProvider) Generate(alg pkicrypto.AlgorithmID, cfg pkicrypto.KeyStorageConfig) (pkicrypto.Signer, error) {
	if m.generateErr != nil {
		return nil, m.generateErr
	}
	// Return a software signer for testing (simulates HSM behavior)
	return pkicrypto.GenerateSoftwareSigner(alg)
}

func (m *mockPKCS11KeyProvider) Load(cfg pkicrypto.KeyStorageConfig) (pkicrypto.Signer, error) {
	return nil, nil
}

func TestU_GenerateKey_PKCS11_Success(t *testing.T) {
	mockKP := &mockPKCS11KeyProvider{}
	cfg := pkicrypto.KeyStorageConfig{
		Type:             pkicrypto.KeyProviderTypePKCS11,
		PKCS11ConfigPath: "/path/to/softhsm.conf",
		PKCS11KeyLabel:   "test-label",
		PKCS11KeyID:      "test-id",
	}

	signer, storageRef, err := GenerateKey(mockKP, cfg, pkicrypto.AlgECDSAP256, "cred-123", 0)
	if err != nil {
		t.Fatalf("GenerateKey(PKCS11) error = %v", err)
	}

	if signer == nil {
		t.Error("GenerateKey(PKCS11) returned nil signer")
	}

	if storageRef.Type != "pkcs11" {
		t.Errorf("StorageRef.Type = %s, want pkcs11", storageRef.Type)
	}

	if storageRef.Config != "/path/to/softhsm.conf" {
		t.Errorf("StorageRef.Config = %s, want /path/to/softhsm.conf", storageRef.Config)
	}

	// Label should be "test-label-0" (prefix + keyIndex)
	expectedLabel := "test-label-0"
	if storageRef.Label != expectedLabel {
		t.Errorf("StorageRef.Label = %s, want %s", storageRef.Label, expectedLabel)
	}

	if storageRef.KeyID != "test-id" {
		t.Errorf("StorageRef.KeyID = %s, want test-id", storageRef.KeyID)
	}
}

func TestU_GenerateKey_PKCS11_NoLabelPrefix(t *testing.T) {
	mockKP := &mockPKCS11KeyProvider{}
	cfg := pkicrypto.KeyStorageConfig{
		Type:             pkicrypto.KeyProviderTypePKCS11,
		PKCS11ConfigPath: "/path/to/softhsm.conf",
		PKCS11KeyLabel:   "", // Empty label prefix - should use credentialID
	}

	signer, storageRef, err := GenerateKey(mockKP, cfg, pkicrypto.AlgECDSAP256, "my-credential", 2)
	if err != nil {
		t.Fatalf("GenerateKey(PKCS11) error = %v", err)
	}

	if signer == nil {
		t.Error("GenerateKey(PKCS11) returned nil signer")
	}

	// Label should be "my-credential-2" (credentialID + keyIndex)
	expectedLabel := "my-credential-2"
	if storageRef.Label != expectedLabel {
		t.Errorf("StorageRef.Label = %s, want %s", storageRef.Label, expectedLabel)
	}
}

func TestU_GenerateKey_PKCS11_MultipleKeyIndices(t *testing.T) {
	mockKP := &mockPKCS11KeyProvider{}
	cfg := pkicrypto.KeyStorageConfig{
		Type:             pkicrypto.KeyProviderTypePKCS11,
		PKCS11ConfigPath: "/path/to/softhsm.conf",
		PKCS11KeyLabel:   "hybrid-key",
	}

	credentialID := "hybrid-cred"

	// Test multiple key indices (for Catalyst/Composite with 2 keys)
	for i := 0; i < 3; i++ {
		signer, storageRef, err := GenerateKey(mockKP, cfg, pkicrypto.AlgECDSAP256, credentialID, i)
		if err != nil {
			t.Fatalf("GenerateKey(keyIndex=%d) error = %v", i, err)
		}

		if signer == nil {
			t.Errorf("GenerateKey(keyIndex=%d) returned nil signer", i)
		}

		expectedLabel := "hybrid-key-" + string(rune('0'+i))
		if storageRef.Label != expectedLabel {
			t.Errorf("StorageRef.Label = %s, want %s", storageRef.Label, expectedLabel)
		}
	}
}

// mockFailingKeyProvider simulates a KeyProvider that fails
type mockFailingKeyProvider struct{}

func (m *mockFailingKeyProvider) Generate(alg pkicrypto.AlgorithmID, cfg pkicrypto.KeyStorageConfig) (pkicrypto.Signer, error) {
	return nil, fmt.Errorf("HSM key generation failed: connection error")
}

func (m *mockFailingKeyProvider) Load(cfg pkicrypto.KeyStorageConfig) (pkicrypto.Signer, error) {
	return nil, fmt.Errorf("HSM key loading failed")
}

func TestU_GenerateKey_PKCS11_GenerationFails(t *testing.T) {
	mockKP := &mockFailingKeyProvider{}
	cfg := pkicrypto.KeyStorageConfig{
		Type:             pkicrypto.KeyProviderTypePKCS11,
		PKCS11ConfigPath: "/path/to/softhsm.conf",
	}

	_, _, err := GenerateKey(mockKP, cfg, pkicrypto.AlgECDSAP256, "test-cred", 0)
	if err == nil {
		t.Error("GenerateKey(PKCS11) should fail when HSM generation fails")
	}
}

// =============================================================================
// Additional Software Path Tests
// =============================================================================

func TestU_GenerateKey_Software_RSA(t *testing.T) {
	kp := pkicrypto.NewSoftwareKeyProvider()
	cfg := pkicrypto.KeyStorageConfig{
		Type: pkicrypto.KeyProviderTypeSoftware,
	}

	signer, storageRef, err := GenerateKey(kp, cfg, pkicrypto.AlgRSA2048, "rsa-test", 0)
	if err != nil {
		t.Fatalf("GenerateKey(RSA2048) error = %v", err)
	}

	if signer == nil {
		t.Error("GenerateKey() returned nil signer")
	}

	if signer.Algorithm() != pkicrypto.AlgRSA2048 {
		t.Errorf("Signer algorithm = %s, want %s", signer.Algorithm(), pkicrypto.AlgRSA2048)
	}

	if storageRef.Type != "software" {
		t.Errorf("StorageRef.Type = %s, want software", storageRef.Type)
	}
}

func TestU_GenerateKey_Software_ECDSA_P521(t *testing.T) {
	kp := pkicrypto.NewSoftwareKeyProvider()
	cfg := pkicrypto.KeyStorageConfig{
		Type: pkicrypto.KeyProviderTypeSoftware,
	}

	signer, storageRef, err := GenerateKey(kp, cfg, pkicrypto.AlgECDSAP521, "test-cred", 0)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	if signer == nil {
		t.Error("GenerateKey() returned nil signer")
	}

	if signer.Algorithm() != pkicrypto.AlgECDSAP521 {
		t.Errorf("Signer algorithm = %s, want %s", signer.Algorithm(), pkicrypto.AlgECDSAP521)
	}

	if storageRef.Type != "software" {
		t.Errorf("StorageRef.Type = %s, want software", storageRef.Type)
	}
}
