package credential

import (
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

// Note: PKCS#11 tests would require a mock HSM or SoftHSM,
// which is beyond the scope of unit tests.
// Integration tests with real HSMs should be done separately.
