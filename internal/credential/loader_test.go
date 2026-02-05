package credential

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
)

// =============================================================================
// LoadSigner Tests
// =============================================================================

func TestU_LoadSigner_Classical(t *testing.T) {
	// Setup: Create mock store with ECDSA credential
	store := NewMockStore()
	credID := "test-ecdsa"

	// Create credential
	cred := NewCredential(credID, Subject{CommonName: "ECDSA Test"})
	cred.CreateInitialVersion([]string{"ec/signing"}, []string{"ec"})
	ver := cred.Versions["v1"]
	ver.NotBefore = time.Now().Add(-time.Hour)
	ver.NotAfter = time.Now().Add(time.Hour * 24 * 365)
	cred.Versions["v1"] = ver

	// Generate ECDSA signer
	signer, err := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgECDSAP256)
	if err != nil {
		t.Fatalf("failed to generate signer: %v", err)
	}

	// Create certificate matching the signer
	cert := generateCertForSigner(t, signer)

	// Add to mock store
	store.AddCredential(cred)
	store.AddCertificates(credID, []*x509.Certificate{cert})
	store.AddKeys(credID, []pkicrypto.Signer{signer})

	// Test LoadSigner
	loadedCert, loadedSigner, err := LoadSigner(context.Background(), store, credID, nil)
	if err != nil {
		t.Fatalf("LoadSigner failed: %v", err)
	}

	if loadedCert == nil {
		t.Fatal("expected certificate, got nil")
	}
	if loadedSigner == nil {
		t.Fatal("expected signer, got nil")
	}

	// Verify algorithm
	if loadedSigner.Algorithm() != pkicrypto.AlgECDSAP256 {
		t.Errorf("expected algorithm %s, got %s", pkicrypto.AlgECDSAP256, loadedSigner.Algorithm())
	}
}

func TestU_LoadSigner_PQC(t *testing.T) {
	// Setup: Create mock store with ML-DSA credential
	store := NewMockStore()
	credID := "test-mldsa"

	// Create credential
	cred := NewCredential(credID, Subject{CommonName: "ML-DSA Test"})
	cred.CreateInitialVersion([]string{"ml-dsa/signing"}, []string{"ml-dsa"})
	ver := cred.Versions["v1"]
	ver.NotBefore = time.Now().Add(-time.Hour)
	ver.NotAfter = time.Now().Add(time.Hour * 24 * 365)
	cred.Versions["v1"] = ver

	// Generate ML-DSA signer
	signer, err := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgMLDSA65)
	if err != nil {
		t.Fatalf("failed to generate signer: %v", err)
	}

	// Create certificate matching the signer (using a fake cert with matching public key)
	// For PQC, we can't create a real x509 cert easily, so we use a classical cert
	// and manually match in the test
	ecdsaSigner, _ := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgECDSAP256)
	cert := generateCertForSigner(t, ecdsaSigner)

	// For this test, we'll use a workaround: put the ML-DSA signer in the store
	// but use a classical cert (since x509 doesn't support ML-DSA directly)
	// In real scenarios, the credential store handles this properly
	store.AddCredential(cred)
	store.AddCertificates(credID, []*x509.Certificate{cert})
	store.AddKeys(credID, []pkicrypto.Signer{signer})

	// Test LoadSigner - it should return the signer even if cert doesn't match
	// because the matcher will find the first available
	_, loadedSigner, err := LoadSigner(context.Background(), store, credID, nil)
	if err != nil {
		t.Fatalf("LoadSigner failed: %v", err)
	}

	if loadedSigner == nil {
		t.Fatal("expected signer, got nil")
	}

	// Verify algorithm is ML-DSA
	if loadedSigner.Algorithm() != pkicrypto.AlgMLDSA65 {
		t.Errorf("expected algorithm %s, got %s", pkicrypto.AlgMLDSA65, loadedSigner.Algorithm())
	}
}

func TestU_LoadSigner_Hybrid(t *testing.T) {
	// Setup: Create mock store with hybrid credential (classical + PQC)
	store := NewMockStore()
	credID := "test-hybrid"

	// Create credential
	cred := NewCredential(credID, Subject{CommonName: "Hybrid Test"})
	cred.CreateInitialVersion([]string{"hybrid/signing"}, []string{"ec", "ml-dsa"})
	ver := cred.Versions["v1"]
	ver.NotBefore = time.Now().Add(-time.Hour)
	ver.NotAfter = time.Now().Add(time.Hour * 24 * 365)
	cred.Versions["v1"] = ver

	// Generate classical (ECDSA) and PQC (ML-DSA) signers
	classicalSigner, err := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgECDSAP256)
	if err != nil {
		t.Fatalf("failed to generate classical signer: %v", err)
	}

	pqcSigner, err := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgMLDSA65)
	if err != nil {
		t.Fatalf("failed to generate PQC signer: %v", err)
	}

	// Create certificate matching the classical signer
	cert := generateCertForSigner(t, classicalSigner)

	// Add to mock store with both signers
	store.AddCredential(cred)
	store.AddCertificates(credID, []*x509.Certificate{cert})
	store.AddKeys(credID, []pkicrypto.Signer{classicalSigner, pqcSigner})

	// Test LoadSigner
	loadedCert, loadedSigner, err := LoadSigner(context.Background(), store, credID, nil)
	if err != nil {
		t.Fatalf("LoadSigner failed: %v", err)
	}

	if loadedCert == nil {
		t.Fatal("expected certificate, got nil")
	}
	if loadedSigner == nil {
		t.Fatal("expected signer, got nil")
	}

	// Verify it's a HybridSigner
	hybridSigner, ok := loadedSigner.(pkicrypto.HybridSigner)
	if !ok {
		t.Fatalf("expected HybridSigner, got %T", loadedSigner)
	}

	// Verify both signers are present
	if hybridSigner.ClassicalSigner() == nil {
		t.Error("expected classical signer in hybrid")
	}
	if hybridSigner.PQCSigner() == nil {
		t.Error("expected PQC signer in hybrid")
	}
}

func TestU_LoadSigner_NotFound(t *testing.T) {
	store := NewMockStore()

	// Test LoadSigner with non-existent credential
	_, _, err := LoadSigner(context.Background(), store, "non-existent", nil)
	if err == nil {
		t.Fatal("expected error for non-existent credential")
	}
}

func TestU_LoadSigner_Revoked(t *testing.T) {
	store := NewMockStore()
	credID := "test-revoked"

	// Create revoked credential
	cred := NewCredential(credID, Subject{CommonName: "Revoked Test"})
	cred.CreateInitialVersion([]string{"ec/signing"}, []string{"ec"})
	cred.Revoke("keyCompromise")

	// Generate signer and cert
	signer, _ := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgECDSAP256)
	cert := generateCertForSigner(t, signer)

	store.AddCredential(cred)
	store.AddCertificates(credID, []*x509.Certificate{cert})
	store.AddKeys(credID, []pkicrypto.Signer{signer})

	// Test LoadSigner - should fail for revoked credential
	_, _, err := LoadSigner(context.Background(), store, credID, nil)
	if err == nil {
		t.Fatal("expected error for revoked credential")
	}
	// Verify error message mentions revocation
	if !strings.Contains(err.Error(), "revoked") {
		t.Errorf("expected error to mention 'revoked', got: %v", err)
	}
}

func TestU_LoadSigner_NoCertificates(t *testing.T) {
	store := NewMockStore()
	credID := "test-no-certs"

	// Create credential without certificates
	cred := NewCredential(credID, Subject{CommonName: "No Certs Test"})
	cred.CreateInitialVersion([]string{"ec/signing"}, []string{"ec"})
	ver := cred.Versions["v1"]
	ver.NotBefore = time.Now().Add(-time.Hour)
	ver.NotAfter = time.Now().Add(time.Hour * 24 * 365)
	cred.Versions["v1"] = ver

	store.AddCredential(cred)
	// No certificates added

	// Test LoadSigner - should fail
	_, _, err := LoadSigner(context.Background(), store, credID, nil)
	if err == nil {
		t.Fatal("expected error for credential with no certificates")
	}
}

func TestU_LoadSigner_NoKeys(t *testing.T) {
	store := NewMockStore()
	credID := "test-no-keys"

	// Create credential without keys
	cred := NewCredential(credID, Subject{CommonName: "No Keys Test"})
	cred.CreateInitialVersion([]string{"ec/signing"}, []string{"ec"})
	ver := cred.Versions["v1"]
	ver.NotBefore = time.Now().Add(-time.Hour)
	ver.NotAfter = time.Now().Add(time.Hour * 24 * 365)
	cred.Versions["v1"] = ver

	// Generate a cert
	signer, _ := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgECDSAP256)
	cert := generateCertForSigner(t, signer)

	store.AddCredential(cred)
	store.AddCertificates(credID, []*x509.Certificate{cert})
	// No keys added

	// Test LoadSigner - should fail
	_, _, err := LoadSigner(context.Background(), store, credID, nil)
	if err == nil {
		t.Fatal("expected error for credential with no keys")
	}
}

func TestU_LoadSigner_AfterRotateAndActivate(t *testing.T) {
	// This test verifies that after a credential rotation and activation,
	// LoadSigner returns the new version's certificate and signer.
	store := NewMockStore()
	credID := "test-rotate"

	// Step 1: Create credential with v1
	cred := NewCredential(credID, Subject{CommonName: "Rotate Test"})
	cred.CreateInitialVersion([]string{"ec/signing"}, []string{"ec"})
	ver1 := cred.Versions["v1"]
	ver1.NotBefore = time.Now().Add(-time.Hour)
	ver1.NotAfter = time.Now().Add(time.Hour * 24 * 365)
	ver1.Status = string(VersionStatusActive)
	cred.Versions["v1"] = ver1

	// Generate v1 signer and cert
	signerV1, err := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgECDSAP256)
	if err != nil {
		t.Fatalf("failed to generate v1 signer: %v", err)
	}
	certV1 := generateCertForSigner(t, signerV1)

	store.AddCredential(cred)
	store.AddCertificates(credID, []*x509.Certificate{certV1})
	store.AddKeys(credID, []pkicrypto.Signer{signerV1})

	// Verify v1 is loaded
	var loadedSigner pkicrypto.Signer
	loadedCert, loadedSigner, err := LoadSigner(context.Background(), store, credID, nil)
	_ = loadedSigner // not checked for v1, will be verified for v2
	if err != nil {
		t.Fatalf("LoadSigner v1 failed: %v", err)
	}
	if loadedCert.SerialNumber.Cmp(certV1.SerialNumber) != 0 {
		t.Error("expected v1 certificate before rotation")
	}

	// Step 2: Simulate rotation - create v2
	signerV2, err := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgECDSAP256)
	if err != nil {
		t.Fatalf("failed to generate v2 signer: %v", err)
	}
	certV2 := generateCertForSigner(t, signerV2)

	// Add v2 to credential versions
	ver2 := CredVersion{
		Created:   time.Now(),
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 365),
		Status:    string(VersionStatusPending),
		Profiles:  []string{"ec/signing"},
		Algos:     []string{"ec"},
	}
	cred.Versions["v2"] = ver2

	// Step 3: Activate v2
	// In real FileStore, this updates the Active field and the stored certs/keys
	cred.Active = "v2"
	ver2.Status = string(VersionStatusActive)
	cred.Versions["v2"] = ver2

	// Update the stored certs/keys to v2 (simulates what FileStore.Save does on activation)
	store.AddCertificates(credID, []*x509.Certificate{certV2})
	store.AddKeys(credID, []pkicrypto.Signer{signerV2})

	// Step 4: Verify LoadSigner now returns v2
	loadedCert, loadedSigner, err = LoadSigner(context.Background(), store, credID, nil)
	if err != nil {
		t.Fatalf("LoadSigner v2 failed: %v", err)
	}

	// Verify we got v2 certificate (different serial number)
	if loadedCert.SerialNumber.Cmp(certV2.SerialNumber) != 0 {
		t.Error("expected v2 certificate after activation")
	}
	if loadedCert.SerialNumber.Cmp(certV1.SerialNumber) == 0 {
		t.Error("got v1 certificate instead of v2 after activation")
	}

	// Verify the signer public key matches v2
	if !publicKeysMatch(loadedSigner.Public(), signerV2.Public()) {
		t.Error("loaded signer does not match v2 signer")
	}
	if publicKeysMatch(loadedSigner.Public(), signerV1.Public()) {
		t.Error("loaded signer still matches v1 signer after rotation")
	}

	_ = loadedSigner // used in verification above
}

func TestU_LoadSigner_RotateClassicalToPQC(t *testing.T) {
	// Test rotating from a classical (ECDSA) credential to a PQC (ML-DSA) credential
	store := NewMockStore()
	credID := "test-rotate-pqc"

	// Step 1: Create credential with v1 (classical)
	cred := NewCredential(credID, Subject{CommonName: "Classical to PQC"})
	cred.CreateInitialVersion([]string{"ec/signing"}, []string{"ec"})
	ver1 := cred.Versions["v1"]
	ver1.NotBefore = time.Now().Add(-time.Hour)
	ver1.NotAfter = time.Now().Add(time.Hour * 24 * 365)
	ver1.Status = string(VersionStatusActive)
	cred.Versions["v1"] = ver1

	// Generate classical v1
	signerV1, err := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgECDSAP256)
	if err != nil {
		t.Fatalf("failed to generate v1 signer: %v", err)
	}
	certV1 := generateCertForSigner(t, signerV1)

	store.AddCredential(cred)
	store.AddCertificates(credID, []*x509.Certificate{certV1})
	store.AddKeys(credID, []pkicrypto.Signer{signerV1})

	// Verify v1 is classical
	_, loadedSigner, err := LoadSigner(context.Background(), store, credID, nil)
	if err != nil {
		t.Fatalf("LoadSigner v1 failed: %v", err)
	}
	if loadedSigner.Algorithm().IsPQC() {
		t.Error("v1 should be classical, not PQC")
	}

	// Step 2: Rotate to v2 (PQC)
	signerV2, err := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgMLDSA65)
	if err != nil {
		t.Fatalf("failed to generate v2 PQC signer: %v", err)
	}

	// For PQC, we use a placeholder cert (x509 doesn't support ML-DSA natively)
	ecdsaForCert, _ := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgECDSAP256)
	certV2 := generateCertForSigner(t, ecdsaForCert)

	// Update versions
	ver2 := CredVersion{
		Created:   time.Now(),
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 365),
		Status:    string(VersionStatusActive),
		Profiles:  []string{"ml-dsa/signing"},
		Algos:     []string{"ml-dsa"},
	}
	cred.Versions["v2"] = ver2
	cred.Active = "v2"

	// Update store with v2
	store.AddCertificates(credID, []*x509.Certificate{certV2})
	store.AddKeys(credID, []pkicrypto.Signer{signerV2})

	// Verify v2 is PQC
	_, loadedSigner, err = LoadSigner(context.Background(), store, credID, nil)
	if err != nil {
		t.Fatalf("LoadSigner v2 failed: %v", err)
	}
	if !loadedSigner.Algorithm().IsPQC() {
		t.Errorf("v2 should be PQC, got algorithm %s", loadedSigner.Algorithm())
	}
	if loadedSigner.Algorithm() != pkicrypto.AlgMLDSA65 {
		t.Errorf("expected ML-DSA-65, got %s", loadedSigner.Algorithm())
	}
}

func TestU_LoadSigner_RotateToHybrid(t *testing.T) {
	// Test rotating from a single-key credential to a hybrid credential
	store := NewMockStore()
	credID := "test-rotate-hybrid"

	// Step 1: Create credential with v1 (single classical key)
	cred := NewCredential(credID, Subject{CommonName: "To Hybrid"})
	cred.CreateInitialVersion([]string{"ec/signing"}, []string{"ec"})
	ver1 := cred.Versions["v1"]
	ver1.NotBefore = time.Now().Add(-time.Hour)
	ver1.NotAfter = time.Now().Add(time.Hour * 24 * 365)
	ver1.Status = string(VersionStatusActive)
	cred.Versions["v1"] = ver1

	signerV1, _ := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgECDSAP256)
	certV1 := generateCertForSigner(t, signerV1)

	store.AddCredential(cred)
	store.AddCertificates(credID, []*x509.Certificate{certV1})
	store.AddKeys(credID, []pkicrypto.Signer{signerV1})

	// Verify v1 is NOT hybrid
	_, loadedSigner, err := LoadSigner(context.Background(), store, credID, nil)
	if err != nil {
		t.Fatalf("LoadSigner v1 failed: %v", err)
	}
	if _, isHybrid := loadedSigner.(pkicrypto.HybridSigner); isHybrid {
		t.Error("v1 should not be hybrid")
	}

	// Step 2: Rotate to v2 (hybrid: classical + PQC)
	classicalV2, _ := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgECDSAP256)
	pqcV2, _ := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgMLDSA65)
	certV2 := generateCertForSigner(t, classicalV2)

	ver2 := CredVersion{
		Created:   time.Now(),
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 365),
		Status:    string(VersionStatusActive),
		Profiles:  []string{"hybrid/signing"},
		Algos:     []string{"ec", "ml-dsa"},
	}
	cred.Versions["v2"] = ver2
	cred.Active = "v2"

	store.AddCertificates(credID, []*x509.Certificate{certV2})
	store.AddKeys(credID, []pkicrypto.Signer{classicalV2, pqcV2})

	// Verify v2 is hybrid
	_, loadedSigner, err = LoadSigner(context.Background(), store, credID, nil)
	if err != nil {
		t.Fatalf("LoadSigner v2 failed: %v", err)
	}

	hybridSigner, isHybrid := loadedSigner.(pkicrypto.HybridSigner)
	if !isHybrid {
		t.Fatalf("v2 should be hybrid, got %T", loadedSigner)
	}

	if hybridSigner.ClassicalSigner() == nil {
		t.Error("hybrid v2 should have classical signer")
	}
	if hybridSigner.PQCSigner() == nil {
		t.Error("hybrid v2 should have PQC signer")
	}
}

func TestU_LoadSigner_RotateP256ToP384(t *testing.T) {
	// Test rotating from ECDSA P-256 to ECDSA P-384
	store := NewMockStore()
	credID := "test-rotate-curve"

	// v1: P-256
	cred := NewCredential(credID, Subject{CommonName: "P256 to P384"})
	cred.CreateInitialVersion([]string{"ec/signing"}, []string{"ec"})
	ver1 := cred.Versions["v1"]
	ver1.NotBefore = time.Now().Add(-time.Hour)
	ver1.NotAfter = time.Now().Add(time.Hour * 24 * 365)
	ver1.Status = string(VersionStatusActive)
	cred.Versions["v1"] = ver1

	signerV1, err := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgECDSAP256)
	if err != nil {
		t.Fatalf("failed to generate P-256 signer: %v", err)
	}
	certV1 := generateCertForSigner(t, signerV1)

	store.AddCredential(cred)
	store.AddCertificates(credID, []*x509.Certificate{certV1})
	store.AddKeys(credID, []pkicrypto.Signer{signerV1})

	// Verify v1 is P-256
	_, loadedSigner, err := LoadSigner(context.Background(), store, credID, nil)
	if err != nil {
		t.Fatalf("LoadSigner v1 failed: %v", err)
	}
	if loadedSigner.Algorithm() != pkicrypto.AlgECDSAP256 {
		t.Errorf("v1 should be P-256, got %s", loadedSigner.Algorithm())
	}

	// Rotate to v2: P-384
	signerV2, err := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgECDSAP384)
	if err != nil {
		t.Fatalf("failed to generate P-384 signer: %v", err)
	}
	certV2 := generateCertForSigner(t, signerV2)

	ver2 := CredVersion{
		Created:   time.Now(),
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 365),
		Status:    string(VersionStatusActive),
		Profiles:  []string{"ec/signing"},
		Algos:     []string{"ec"},
	}
	cred.Versions["v2"] = ver2
	cred.Active = "v2"

	store.AddCertificates(credID, []*x509.Certificate{certV2})
	store.AddKeys(credID, []pkicrypto.Signer{signerV2})

	// Verify v2 is P-384
	_, loadedSigner, err = LoadSigner(context.Background(), store, credID, nil)
	if err != nil {
		t.Fatalf("LoadSigner v2 failed: %v", err)
	}
	if loadedSigner.Algorithm() != pkicrypto.AlgECDSAP384 {
		t.Errorf("v2 should be P-384, got %s", loadedSigner.Algorithm())
	}
}

func TestU_LoadSigner_RotateHybridToClassical(t *testing.T) {
	// Test downgrading from hybrid to classical (e.g., PQC deprecation scenario)
	store := NewMockStore()
	credID := "test-hybrid-to-classical"

	// v1: Hybrid (ECDSA + ML-DSA)
	cred := NewCredential(credID, Subject{CommonName: "Hybrid to Classical"})
	cred.CreateInitialVersion([]string{"hybrid/signing"}, []string{"ec", "ml-dsa"})
	ver1 := cred.Versions["v1"]
	ver1.NotBefore = time.Now().Add(-time.Hour)
	ver1.NotAfter = time.Now().Add(time.Hour * 24 * 365)
	ver1.Status = string(VersionStatusActive)
	cred.Versions["v1"] = ver1

	classicalV1, _ := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgECDSAP256)
	pqcV1, _ := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgMLDSA65)
	certV1 := generateCertForSigner(t, classicalV1)

	store.AddCredential(cred)
	store.AddCertificates(credID, []*x509.Certificate{certV1})
	store.AddKeys(credID, []pkicrypto.Signer{classicalV1, pqcV1})

	// Verify v1 is hybrid
	_, loadedSigner, err := LoadSigner(context.Background(), store, credID, nil)
	if err != nil {
		t.Fatalf("LoadSigner v1 failed: %v", err)
	}
	if _, isHybrid := loadedSigner.(pkicrypto.HybridSigner); !isHybrid {
		t.Error("v1 should be hybrid")
	}

	// Rotate to v2: Classical only (downgrade)
	signerV2, _ := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgECDSAP256)
	certV2 := generateCertForSigner(t, signerV2)

	ver2 := CredVersion{
		Created:   time.Now(),
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 365),
		Status:    string(VersionStatusActive),
		Profiles:  []string{"ec/signing"},
		Algos:     []string{"ec"},
	}
	cred.Versions["v2"] = ver2
	cred.Active = "v2"

	store.AddCertificates(credID, []*x509.Certificate{certV2})
	store.AddKeys(credID, []pkicrypto.Signer{signerV2}) // Only classical

	// Verify v2 is NOT hybrid
	_, loadedSigner, err = LoadSigner(context.Background(), store, credID, nil)
	if err != nil {
		t.Fatalf("LoadSigner v2 failed: %v", err)
	}
	if _, isHybrid := loadedSigner.(pkicrypto.HybridSigner); isHybrid {
		t.Error("v2 should not be hybrid after downgrade")
	}
	if loadedSigner.Algorithm() != pkicrypto.AlgECDSAP256 {
		t.Errorf("v2 should be ECDSA P-256, got %s", loadedSigner.Algorithm())
	}
}

func TestU_LoadSigner_RotatePQCToClassical(t *testing.T) {
	// Test rotating from PQC back to classical
	store := NewMockStore()
	credID := "test-pqc-to-classical"

	// v1: PQC (ML-DSA)
	cred := NewCredential(credID, Subject{CommonName: "PQC to Classical"})
	cred.CreateInitialVersion([]string{"ml-dsa/signing"}, []string{"ml-dsa"})
	ver1 := cred.Versions["v1"]
	ver1.NotBefore = time.Now().Add(-time.Hour)
	ver1.NotAfter = time.Now().Add(time.Hour * 24 * 365)
	ver1.Status = string(VersionStatusActive)
	cred.Versions["v1"] = ver1

	signerV1, err := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgMLDSA65)
	if err != nil {
		t.Fatalf("failed to generate ML-DSA signer: %v", err)
	}
	// Placeholder cert for PQC
	ecdsaForCert, _ := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgECDSAP256)
	certV1 := generateCertForSigner(t, ecdsaForCert)

	store.AddCredential(cred)
	store.AddCertificates(credID, []*x509.Certificate{certV1})
	store.AddKeys(credID, []pkicrypto.Signer{signerV1})

	// Verify v1 is PQC
	_, loadedSigner, err := LoadSigner(context.Background(), store, credID, nil)
	if err != nil {
		t.Fatalf("LoadSigner v1 failed: %v", err)
	}
	if !loadedSigner.Algorithm().IsPQC() {
		t.Errorf("v1 should be PQC, got %s", loadedSigner.Algorithm())
	}

	// Rotate to v2: Classical
	signerV2, _ := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgECDSAP256)
	certV2 := generateCertForSigner(t, signerV2)

	ver2 := CredVersion{
		Created:   time.Now(),
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 365),
		Status:    string(VersionStatusActive),
		Profiles:  []string{"ec/signing"},
		Algos:     []string{"ec"},
	}
	cred.Versions["v2"] = ver2
	cred.Active = "v2"

	store.AddCertificates(credID, []*x509.Certificate{certV2})
	store.AddKeys(credID, []pkicrypto.Signer{signerV2})

	// Verify v2 is classical
	_, loadedSigner, err = LoadSigner(context.Background(), store, credID, nil)
	if err != nil {
		t.Fatalf("LoadSigner v2 failed: %v", err)
	}
	if loadedSigner.Algorithm().IsPQC() {
		t.Errorf("v2 should be classical, got PQC algorithm %s", loadedSigner.Algorithm())
	}
	if loadedSigner.Algorithm() != pkicrypto.AlgECDSAP256 {
		t.Errorf("v2 should be ECDSA P-256, got %s", loadedSigner.Algorithm())
	}
}

func TestU_LoadSigner_PendingVersionNotUsed(t *testing.T) {
	// Test that a pending (not yet activated) version is not used
	store := NewMockStore()
	credID := "test-pending"

	// Create credential with v1 active
	cred := NewCredential(credID, Subject{CommonName: "Pending Test"})
	cred.CreateInitialVersion([]string{"ec/signing"}, []string{"ec"})
	ver1 := cred.Versions["v1"]
	ver1.NotBefore = time.Now().Add(-time.Hour)
	ver1.NotAfter = time.Now().Add(time.Hour * 24 * 365)
	ver1.Status = string(VersionStatusActive)
	cred.Versions["v1"] = ver1

	signerV1, _ := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgECDSAP256)
	certV1 := generateCertForSigner(t, signerV1)

	// Add v2 as PENDING (not activated)
	ver2 := CredVersion{
		Created:   time.Now(),
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 365),
		Status:    string(VersionStatusPending), // Not active!
		Profiles:  []string{"ec/signing"},
		Algos:     []string{"ec"},
	}
	cred.Versions["v2"] = ver2
	// Active is still v1
	cred.Active = "v1"

	store.AddCredential(cred)
	store.AddCertificates(credID, []*x509.Certificate{certV1})
	store.AddKeys(credID, []pkicrypto.Signer{signerV1})

	// LoadSigner should return v1 (the active version)
	loadedCert, _, err := LoadSigner(context.Background(), store, credID, nil)
	if err != nil {
		t.Fatalf("LoadSigner failed: %v", err)
	}

	// Verify we got v1
	if loadedCert.SerialNumber.Cmp(certV1.SerialNumber) != 0 {
		t.Error("expected v1 certificate (active), not v2 (pending)")
	}
}

// =============================================================================
// ValidateForUsage Tests
// =============================================================================

func TestU_ValidateForUsage_TSA_OK(t *testing.T) {
	// Create certificate with timestamping EKU
	cert := generateCertWithEKU(t, x509.ExtKeyUsageTimeStamping)

	err := ValidateForTimestamping(cert)
	if err != nil {
		t.Errorf("expected no error for cert with timestamping EKU, got: %v", err)
	}
}

func TestU_ValidateForUsage_TSA_Missing(t *testing.T) {
	// Create certificate without timestamping EKU (only serverAuth)
	cert := generateCertWithEKU(t, x509.ExtKeyUsageServerAuth)

	err := ValidateForTimestamping(cert)
	if err == nil {
		t.Error("expected error for cert without timestamping EKU")
	}
}

func TestU_ValidateForUsage_AnyEKU(t *testing.T) {
	// Create certificate with ExtKeyUsageAny
	cert := generateCertWithEKU(t, x509.ExtKeyUsageAny)

	// Should pass for any usage
	if err := ValidateForTimestamping(cert); err != nil {
		t.Errorf("ExtKeyUsageAny should allow timestamping: %v", err)
	}
	if err := ValidateForCodeSigning(cert); err != nil {
		t.Errorf("ExtKeyUsageAny should allow code signing: %v", err)
	}
	if err := ValidateForOCSP(cert); err != nil {
		t.Errorf("ExtKeyUsageAny should allow OCSP signing: %v", err)
	}
	if err := ValidateForEmailProtection(cert); err != nil {
		t.Errorf("ExtKeyUsageAny should allow email protection: %v", err)
	}
}

func TestU_ValidateForUsage_OCSP_OK(t *testing.T) {
	// Create certificate with OCSP signing EKU
	cert := generateCertWithEKU(t, x509.ExtKeyUsageOCSPSigning)

	err := ValidateForOCSP(cert)
	if err != nil {
		t.Errorf("expected no error for cert with OCSP signing EKU, got: %v", err)
	}
}

func TestU_ValidateForUsage_OCSP_Missing(t *testing.T) {
	// Create certificate without OCSP signing EKU (only serverAuth)
	cert := generateCertWithEKU(t, x509.ExtKeyUsageServerAuth)

	err := ValidateForOCSP(cert)
	if err == nil {
		t.Error("expected error for cert without OCSP signing EKU")
	}
	if !strings.Contains(err.Error(), "ocspSigning") {
		t.Errorf("error should mention ocspSigning EKU, got: %v", err)
	}
}

func TestU_ValidateForUsage_EmailProtection_OK(t *testing.T) {
	// Create certificate with email protection EKU
	cert := generateCertWithEKU(t, x509.ExtKeyUsageEmailProtection)

	err := ValidateForEmailProtection(cert)
	if err != nil {
		t.Errorf("expected no error for cert with email protection EKU, got: %v", err)
	}
}

func TestU_ValidateForUsage_EmailProtection_Missing(t *testing.T) {
	// Create certificate without email protection EKU
	cert := generateCertWithEKU(t, x509.ExtKeyUsageServerAuth)

	err := ValidateForEmailProtection(cert)
	if err == nil {
		t.Error("expected error for cert without email protection EKU")
	}
}

func TestU_ValidateForUsage_NoEKU(t *testing.T) {
	// Create certificate without any EKU (should be valid for any use)
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: "No EKU Test"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	cert, _ := x509.ParseCertificate(certDER)

	// Should pass for any usage since no EKU constraints
	if err := ValidateForTimestamping(cert); err != nil {
		t.Errorf("cert without EKU should allow timestamping: %v", err)
	}
}

func TestU_ValidateForUsage_NilCert(t *testing.T) {
	err := ValidateForUsage(nil, x509.ExtKeyUsageTimeStamping)
	if err == nil {
		t.Error("expected error for nil certificate")
	}
}

// =============================================================================
// LoadDecryptionKey Tests
// =============================================================================

func TestU_LoadDecryptionKey_Classical(t *testing.T) {
	store := NewMockStore()
	credID := "test-decrypt"

	// Create credential
	cred := NewCredential(credID, Subject{CommonName: "Decrypt Test"})
	cred.CreateInitialVersion([]string{"ec/encryption"}, []string{"ec"})
	ver := cred.Versions["v1"]
	ver.NotBefore = time.Now().Add(-time.Hour)
	ver.NotAfter = time.Now().Add(time.Hour * 24 * 365)
	cred.Versions["v1"] = ver

	// Generate signer
	signer, err := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgECDSAP256)
	if err != nil {
		t.Fatalf("failed to generate signer: %v", err)
	}

	// Create certificate with keyEncipherment usage
	cert := generateEncryptionCertForSigner(t, signer)

	store.AddCredential(cred)
	store.AddCertificates(credID, []*x509.Certificate{cert})
	store.AddKeys(credID, []pkicrypto.Signer{signer})

	// Test LoadDecryptionKey
	loadedCert, privKey, err := LoadDecryptionKey(context.Background(), store, credID, nil)
	if err != nil {
		t.Fatalf("LoadDecryptionKey failed: %v", err)
	}

	if loadedCert == nil {
		t.Fatal("expected certificate, got nil")
	}
	if privKey == nil {
		t.Fatal("expected private key, got nil")
	}
}

func TestU_LoadDecryptionKey_Revoked(t *testing.T) {
	store := NewMockStore()
	credID := "test-decrypt-revoked"

	// Create revoked credential
	cred := NewCredential(credID, Subject{CommonName: "Revoked Decrypt Test"})
	cred.CreateInitialVersion([]string{"ec/encryption"}, []string{"ec"})
	cred.Revoke("keyCompromise")

	signer, _ := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgECDSAP256)
	cert := generateEncryptionCertForSigner(t, signer)

	store.AddCredential(cred)
	store.AddCertificates(credID, []*x509.Certificate{cert})
	store.AddKeys(credID, []pkicrypto.Signer{signer})

	// Test LoadDecryptionKey - should fail for revoked credential
	_, _, err := LoadDecryptionKey(context.Background(), store, credID, nil)
	if err == nil {
		t.Fatal("expected error for revoked credential")
	}
}

// =============================================================================
// Error Injection Tests (Store errors)
// =============================================================================

func TestU_LoadSigner_StoreLoadError(t *testing.T) {
	store := NewMockStore()
	store.LoadErr = errors.New("simulated store error")

	_, _, err := LoadSigner(context.Background(), store, "any-id", nil)
	if err == nil {
		t.Fatal("expected error when store.Load fails")
	}
	if !strings.Contains(err.Error(), "failed to load credential") {
		t.Errorf("error should mention credential load failure, got: %v", err)
	}
}

func TestU_LoadSigner_StoreLoadCertsError(t *testing.T) {
	store := NewMockStore()
	credID := "test-certs-error"

	cred := NewCredential(credID, Subject{CommonName: "Certs Error Test"})
	cred.CreateInitialVersion([]string{"ec/signing"}, []string{"ec"})
	ver := cred.Versions["v1"]
	ver.NotBefore = time.Now().Add(-time.Hour)
	ver.NotAfter = time.Now().Add(time.Hour * 24 * 365)
	cred.Versions["v1"] = ver

	store.AddCredential(cred)
	store.LoadCertsErr = errors.New("simulated certificate load error")

	_, _, err := LoadSigner(context.Background(), store, credID, nil)
	if err == nil {
		t.Fatal("expected error when store.LoadCertificates fails")
	}
	if !strings.Contains(err.Error(), "failed to load certificates") {
		t.Errorf("error should mention certificate load failure, got: %v", err)
	}
}

func TestU_LoadSigner_StoreLoadKeysError(t *testing.T) {
	store := NewMockStore()
	credID := "test-keys-error"

	cred := NewCredential(credID, Subject{CommonName: "Keys Error Test"})
	cred.CreateInitialVersion([]string{"ec/signing"}, []string{"ec"})
	ver := cred.Versions["v1"]
	ver.NotBefore = time.Now().Add(-time.Hour)
	ver.NotAfter = time.Now().Add(time.Hour * 24 * 365)
	cred.Versions["v1"] = ver

	signer, _ := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgECDSAP256)
	cert := generateCertForSigner(t, signer)

	store.AddCredential(cred)
	store.AddCertificates(credID, []*x509.Certificate{cert})
	store.LoadKeysErr = errors.New("simulated key load error")

	_, _, err := LoadSigner(context.Background(), store, credID, nil)
	if err == nil {
		t.Fatal("expected error when store.LoadKeys fails")
	}
	if !strings.Contains(err.Error(), "failed to load keys") {
		t.Errorf("error should mention key load failure, got: %v", err)
	}
}

func TestU_LoadDecryptionKey_StoreErrors(t *testing.T) {
	tests := []struct {
		name      string
		setupErr  func(*MockStore)
		expectMsg string
	}{
		{
			name:      "LoadError",
			setupErr:  func(m *MockStore) { m.LoadErr = errors.New("load error") },
			expectMsg: "failed to load credential",
		},
		{
			name:      "LoadCertsError",
			setupErr:  func(m *MockStore) { m.LoadCertsErr = errors.New("certs error") },
			expectMsg: "failed to load certificates",
		},
		{
			name:      "LoadKeysError",
			setupErr:  func(m *MockStore) { m.LoadKeysErr = errors.New("keys error") },
			expectMsg: "failed to load keys",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := NewMockStore()
			credID := "test-decrypt-" + tt.name

			cred := NewCredential(credID, Subject{CommonName: tt.name})
			cred.CreateInitialVersion([]string{"ec/encryption"}, []string{"ec"})
			ver := cred.Versions["v1"]
			ver.NotBefore = time.Now().Add(-time.Hour)
			ver.NotAfter = time.Now().Add(time.Hour * 24 * 365)
			cred.Versions["v1"] = ver

			signer, _ := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgECDSAP256)
			cert := generateEncryptionCertForSigner(t, signer)

			store.AddCredential(cred)
			store.AddCertificates(credID, []*x509.Certificate{cert})
			store.AddKeys(credID, []pkicrypto.Signer{signer})

			tt.setupErr(store)

			_, _, err := LoadDecryptionKey(context.Background(), store, credID, nil)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.expectMsg) {
				t.Errorf("expected error containing %q, got: %v", tt.expectMsg, err)
			}
		})
	}
}

// =============================================================================
// Context Cancellation Tests
// =============================================================================

func TestU_LoadSigner_ContextCancelled(t *testing.T) {
	store := NewMockStore()
	credID := "test-ctx"

	cred := NewCredential(credID, Subject{CommonName: "Context Test"})
	cred.CreateInitialVersion([]string{"ec/signing"}, []string{"ec"})
	store.AddCredential(cred)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, _, err := LoadSigner(ctx, store, credID, nil)
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
	if !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "context canceled") {
		t.Errorf("expected context.Canceled error, got: %v", err)
	}
}

func TestU_LoadDecryptionKey_ContextCancelled(t *testing.T) {
	store := NewMockStore()
	credID := "test-decrypt-ctx"

	cred := NewCredential(credID, Subject{CommonName: "Context Test"})
	cred.CreateInitialVersion([]string{"ec/encryption"}, []string{"ec"})
	store.AddCredential(cred)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, err := LoadDecryptionKey(ctx, store, credID, nil)
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

// =============================================================================
// Edge Cases Tests
// =============================================================================

func TestU_LoadSigner_MultipleCertsNoMatch(t *testing.T) {
	// Test case where we have multiple certs but none match any signer
	store := NewMockStore()
	credID := "test-no-match"

	cred := NewCredential(credID, Subject{CommonName: "No Match Test"})
	cred.CreateInitialVersion([]string{"ec/signing"}, []string{"ec"})
	ver := cred.Versions["v1"]
	ver.NotBefore = time.Now().Add(-time.Hour)
	ver.NotAfter = time.Now().Add(time.Hour * 24 * 365)
	cred.Versions["v1"] = ver

	// Generate signer but use different key for certificate
	signer, _ := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgECDSAP256)
	differentSigner, _ := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgECDSAP256)
	cert := generateCertForSigner(t, differentSigner) // Cert doesn't match signer

	store.AddCredential(cred)
	store.AddCertificates(credID, []*x509.Certificate{cert})
	store.AddKeys(credID, []pkicrypto.Signer{signer})

	_, _, err := LoadSigner(context.Background(), store, credID, nil)
	if err == nil {
		t.Fatal("expected error when no cert matches signer")
	}
	if !strings.Contains(err.Error(), "no certificate found matching signer") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestU_LoadSigner_TwoClassicalSigners(t *testing.T) {
	// Test with 2 classical signers (not hybrid case)
	store := NewMockStore()
	credID := "test-two-classical"

	cred := NewCredential(credID, Subject{CommonName: "Two Classical"})
	cred.CreateInitialVersion([]string{"ec/signing"}, []string{"ec"})
	ver := cred.Versions["v1"]
	ver.NotBefore = time.Now().Add(-time.Hour)
	ver.NotAfter = time.Now().Add(time.Hour * 24 * 365)
	cred.Versions["v1"] = ver

	signer1, _ := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgECDSAP256)
	signer2, _ := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgECDSAP384)
	cert1 := generateCertForSigner(t, signer1)
	cert2 := generateCertForSigner(t, signer2)

	store.AddCredential(cred)
	store.AddCertificates(credID, []*x509.Certificate{cert1, cert2})
	store.AddKeys(credID, []pkicrypto.Signer{signer1, signer2})

	// Should NOT create hybrid (both are classical)
	_, loadedSigner, err := LoadSigner(context.Background(), store, credID, nil)
	if err != nil {
		t.Fatalf("LoadSigner failed: %v", err)
	}

	// Should not be hybrid
	if _, isHybrid := loadedSigner.(pkicrypto.HybridSigner); isHybrid {
		t.Error("two classical signers should not create hybrid")
	}
}

func TestU_LoadSigner_TwoPQCSigners(t *testing.T) {
	// Test with 2 PQC signers (not hybrid case)
	store := NewMockStore()
	credID := "test-two-pqc"

	cred := NewCredential(credID, Subject{CommonName: "Two PQC"})
	cred.CreateInitialVersion([]string{"ml-dsa/signing"}, []string{"ml-dsa"})
	ver := cred.Versions["v1"]
	ver.NotBefore = time.Now().Add(-time.Hour)
	ver.NotAfter = time.Now().Add(time.Hour * 24 * 365)
	cred.Versions["v1"] = ver

	signer1, _ := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgMLDSA65)
	signer2, _ := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgMLDSA87)

	// Placeholder certs
	ecdsaForCert, _ := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgECDSAP256)
	cert := generateCertForSigner(t, ecdsaForCert)

	store.AddCredential(cred)
	store.AddCertificates(credID, []*x509.Certificate{cert})
	store.AddKeys(credID, []pkicrypto.Signer{signer1, signer2})

	// Should NOT create hybrid (both are PQC)
	_, loadedSigner, err := LoadSigner(context.Background(), store, credID, nil)
	if err != nil {
		t.Fatalf("LoadSigner failed: %v", err)
	}

	// Should not be hybrid
	if _, isHybrid := loadedSigner.(pkicrypto.HybridSigner); isHybrid {
		t.Error("two PQC signers should not create hybrid")
	}
}

func TestU_LoadDecryptionKey_NoEncryptionKey(t *testing.T) {
	// Test when credential has no encryption-capable key
	store := NewMockStore()
	credID := "test-no-encrypt-key"

	cred := NewCredential(credID, Subject{CommonName: "No Encrypt Key"})
	cred.CreateInitialVersion([]string{"ec/signing"}, []string{"ec"})
	ver := cred.Versions["v1"]
	ver.NotBefore = time.Now().Add(-time.Hour)
	ver.NotAfter = time.Now().Add(time.Hour * 24 * 365)
	cred.Versions["v1"] = ver

	// Certificate with signing key usage only (no encryption)
	signer, _ := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgECDSAP256)
	cert := generateCertForSigner(t, signer) // Has KeyUsageDigitalSignature only

	store.AddCredential(cred)
	store.AddCertificates(credID, []*x509.Certificate{cert})
	store.AddKeys(credID, []pkicrypto.Signer{signer})

	// Should still work (fallback to any matching key)
	_, privKey, err := LoadDecryptionKey(context.Background(), store, credID, nil)
	if err != nil {
		t.Fatalf("LoadDecryptionKey failed: %v", err)
	}
	if privKey == nil {
		t.Error("expected private key")
	}
}

// =============================================================================
// FindDecryptionKeyByRecipient Tests (Multi-Version Decryption)
// =============================================================================

func TestU_FindDecryptionKeyByRecipient_IssuerAndSerial(t *testing.T) {
	// Test matching by Issuer and Serial Number
	store := NewMockStore()
	credID := "test-find-issuer-serial"

	cred := NewCredential(credID, Subject{CommonName: "Find Test"})
	cred.CreateInitialVersion([]string{"ec/encryption"}, []string{"ec"})
	ver := cred.Versions["v1"]
	ver.NotBefore = time.Now().Add(-time.Hour)
	ver.NotAfter = time.Now().Add(time.Hour * 24 * 365)
	ver.Status = string(VersionStatusActive)
	cred.Versions["v1"] = ver

	signer, _ := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgECDSAP256)
	cert := generateEncryptionCertForSigner(t, signer)

	store.AddCredential(cred)
	store.AddCertificates(credID, []*x509.Certificate{cert})
	store.AddKeys(credID, []pkicrypto.Signer{signer})
	store.AddVersionedCertificates(credID, "v1", []*x509.Certificate{cert})
	store.AddVersionedKeys(credID, "v1", []pkicrypto.Signer{signer})

	// Create matcher from certificate's issuer and serial
	var issuer pkix.RDNSequence
	_, _ = asn1.Unmarshal(cert.RawIssuer, &issuer)
	matcher := &RecipientMatcher{
		IssuerAndSerialNumber: &IssuerAndSerial{
			Issuer:       issuer,
			SerialNumber: cert.SerialNumber,
		},
	}

	// Find decryption key
	loadedCert, privKey, err := FindDecryptionKeyByRecipient(context.Background(), store, credID, matcher, nil)
	if err != nil {
		t.Fatalf("FindDecryptionKeyByRecipient failed: %v", err)
	}

	if loadedCert == nil {
		t.Fatal("expected certificate")
	}
	if privKey == nil {
		t.Fatal("expected private key")
	}

	// Verify it's the correct certificate
	if loadedCert.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Error("returned certificate doesn't match expected")
	}
}

func TestU_FindDecryptionKeyByRecipient_SKI(t *testing.T) {
	// Test matching by Subject Key Identifier
	store := NewMockStore()
	credID := "test-find-ski"

	cred := NewCredential(credID, Subject{CommonName: "Find SKI Test"})
	cred.CreateInitialVersion([]string{"ec/encryption"}, []string{"ec"})
	ver := cred.Versions["v1"]
	ver.NotBefore = time.Now().Add(-time.Hour)
	ver.NotAfter = time.Now().Add(time.Hour * 24 * 365)
	ver.Status = string(VersionStatusActive)
	cred.Versions["v1"] = ver

	signer, _ := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgECDSAP256)
	cert := generateEncryptionCertForSigner(t, signer)

	store.AddCredential(cred)
	store.AddCertificates(credID, []*x509.Certificate{cert})
	store.AddKeys(credID, []pkicrypto.Signer{signer})
	store.AddVersionedCertificates(credID, "v1", []*x509.Certificate{cert})
	store.AddVersionedKeys(credID, "v1", []pkicrypto.Signer{signer})

	// Create matcher with SKI
	matcher := &RecipientMatcher{
		SubjectKeyIdentifier: cert.SubjectKeyId,
	}

	// Find decryption key
	loadedCert, privKey, err := FindDecryptionKeyByRecipient(context.Background(), store, credID, matcher, nil)
	if err != nil {
		t.Fatalf("FindDecryptionKeyByRecipient failed: %v", err)
	}

	if loadedCert == nil {
		t.Fatal("expected certificate")
	}
	if privKey == nil {
		t.Fatal("expected private key")
	}
}

func TestU_FindDecryptionKeyByRecipient_OldVersion(t *testing.T) {
	// Test finding a key from an old version after rotation
	// This is the critical use case: data encrypted with v1 key should still be decryptable
	// after v2 is activated
	store := NewMockStore()
	credID := "test-find-old-version"

	// Create credential with v1
	cred := NewCredential(credID, Subject{CommonName: "Old Version Test"})
	cred.CreateInitialVersion([]string{"ec/encryption"}, []string{"ec"})
	ver1 := cred.Versions["v1"]
	ver1.NotBefore = time.Now().Add(-time.Hour * 24 * 30) // 30 days ago
	ver1.NotAfter = time.Now().Add(time.Hour * 24 * 335)  // expires in 335 days
	ver1.Status = string(VersionStatusArchived)           // v1 is now archived
	cred.Versions["v1"] = ver1

	// v1 signer and cert
	signerV1, _ := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgECDSAP256)
	certV1 := generateEncryptionCertForSigner(t, signerV1)

	// Add v2 as the active version
	ver2 := CredVersion{
		Created:   time.Now(),
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 365),
		Status:    string(VersionStatusActive),
		Profiles:  []string{"ec/encryption"},
		Algos:     []string{"ec"},
	}
	cred.Versions["v2"] = ver2
	cred.Active = "v2"

	signerV2, _ := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgECDSAP256)
	certV2 := generateEncryptionCertForSigner(t, signerV2)

	store.AddCredential(cred)
	// Active certs/keys are v2
	store.AddCertificates(credID, []*x509.Certificate{certV2})
	store.AddKeys(credID, []pkicrypto.Signer{signerV2})
	// Versioned storage has both
	store.AddVersionedCertificates(credID, "v1", []*x509.Certificate{certV1})
	store.AddVersionedKeys(credID, "v1", []pkicrypto.Signer{signerV1})
	store.AddVersionedCertificates(credID, "v2", []*x509.Certificate{certV2})
	store.AddVersionedKeys(credID, "v2", []pkicrypto.Signer{signerV2})

	// Create matcher for v1 certificate (simulating data encrypted with old key)
	var issuer pkix.RDNSequence
	_, _ = asn1.Unmarshal(certV1.RawIssuer, &issuer)
	matcher := &RecipientMatcher{
		IssuerAndSerialNumber: &IssuerAndSerial{
			Issuer:       issuer,
			SerialNumber: certV1.SerialNumber,
		},
	}

	// Find decryption key - should find v1 even though v2 is active
	loadedCert, privKey, err := FindDecryptionKeyByRecipient(context.Background(), store, credID, matcher, nil)
	if err != nil {
		t.Fatalf("FindDecryptionKeyByRecipient failed: %v", err)
	}

	if loadedCert == nil {
		t.Fatal("expected certificate")
	}
	if privKey == nil {
		t.Fatal("expected private key")
	}

	// Verify it's v1 certificate, not v2
	if loadedCert.SerialNumber.Cmp(certV1.SerialNumber) != 0 {
		t.Error("expected v1 certificate")
	}
	if loadedCert.SerialNumber.Cmp(certV2.SerialNumber) == 0 {
		t.Error("got v2 certificate instead of v1")
	}
}

func TestU_FindDecryptionKeyByRecipient_NotFound(t *testing.T) {
	// Test when no matching key is found
	store := NewMockStore()
	credID := "test-find-not-found"

	cred := NewCredential(credID, Subject{CommonName: "Not Found Test"})
	cred.CreateInitialVersion([]string{"ec/encryption"}, []string{"ec"})
	ver := cred.Versions["v1"]
	ver.NotBefore = time.Now().Add(-time.Hour)
	ver.NotAfter = time.Now().Add(time.Hour * 24 * 365)
	ver.Status = string(VersionStatusActive)
	cred.Versions["v1"] = ver

	signer, _ := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgECDSAP256)
	cert := generateEncryptionCertForSigner(t, signer)

	store.AddCredential(cred)
	store.AddCertificates(credID, []*x509.Certificate{cert})
	store.AddKeys(credID, []pkicrypto.Signer{signer})
	store.AddVersionedCertificates(credID, "v1", []*x509.Certificate{cert})
	store.AddVersionedKeys(credID, "v1", []pkicrypto.Signer{signer})

	// Create matcher with wrong serial number
	var issuer pkix.RDNSequence
	_, _ = asn1.Unmarshal(cert.RawIssuer, &issuer)
	wrongSerial := big.NewInt(999999999) // Different serial
	matcher := &RecipientMatcher{
		IssuerAndSerialNumber: &IssuerAndSerial{
			Issuer:       issuer,
			SerialNumber: wrongSerial,
		},
	}

	// Should fail to find
	_, _, err := FindDecryptionKeyByRecipient(context.Background(), store, credID, matcher, nil)
	if err == nil {
		t.Fatal("expected error when no matching key found")
	}
	if !strings.Contains(err.Error(), "no matching decryption key found") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestU_FindDecryptionKeyByRecipient_CredentialNotFound(t *testing.T) {
	store := NewMockStore()

	matcher := &RecipientMatcher{
		SubjectKeyIdentifier: []byte{1, 2, 3, 4},
	}

	_, _, err := FindDecryptionKeyByRecipient(context.Background(), store, "non-existent", matcher, nil)
	if err == nil {
		t.Fatal("expected error for non-existent credential")
	}
	if !strings.Contains(err.Error(), "failed to load credential") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestU_FindAllDecryptionKeys(t *testing.T) {
	// Test loading all decryption keys from all versions
	store := NewMockStore()
	credID := "test-find-all"

	cred := NewCredential(credID, Subject{CommonName: "Find All Test"})
	cred.CreateInitialVersion([]string{"ec/encryption"}, []string{"ec"})

	// Set up v1
	ver1 := cred.Versions["v1"]
	ver1.NotBefore = time.Now().Add(-time.Hour * 24 * 30)
	ver1.NotAfter = time.Now().Add(time.Hour * 24 * 335)
	ver1.Status = string(VersionStatusArchived)
	cred.Versions["v1"] = ver1

	signerV1, _ := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgECDSAP256)
	certV1 := generateEncryptionCertForSigner(t, signerV1)

	// Set up v2 as active
	ver2 := CredVersion{
		Created:   time.Now(),
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 365),
		Status:    string(VersionStatusActive),
		Profiles:  []string{"ec/encryption"},
		Algos:     []string{"ec"},
	}
	cred.Versions["v2"] = ver2
	cred.Active = "v2"

	signerV2, _ := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgECDSAP256)
	certV2 := generateEncryptionCertForSigner(t, signerV2)

	store.AddCredential(cred)
	store.AddCertificates(credID, []*x509.Certificate{certV2})
	store.AddKeys(credID, []pkicrypto.Signer{signerV2})
	store.AddVersionedCertificates(credID, "v1", []*x509.Certificate{certV1})
	store.AddVersionedKeys(credID, "v1", []pkicrypto.Signer{signerV1})
	store.AddVersionedCertificates(credID, "v2", []*x509.Certificate{certV2})
	store.AddVersionedKeys(credID, "v2", []pkicrypto.Signer{signerV2})

	// Find all decryption keys
	entries, err := FindAllDecryptionKeys(context.Background(), store, credID, nil)
	if err != nil {
		t.Fatalf("FindAllDecryptionKeys failed: %v", err)
	}

	// Should have entries from both versions
	if len(entries) < 2 {
		t.Errorf("expected at least 2 entries, got %d", len(entries))
	}

	// Check that we have both active and non-active entries
	var hasActive, hasInactive bool
	for _, entry := range entries {
		if entry.IsActive {
			hasActive = true
		} else {
			hasInactive = true
		}
		if entry.Certificate == nil {
			t.Error("entry has nil certificate")
		}
		if entry.PrivateKey == nil {
			t.Error("entry has nil private key")
		}
	}

	if !hasActive {
		t.Error("expected at least one active entry")
	}
	if !hasInactive {
		t.Error("expected at least one inactive entry")
	}
}

func TestU_FindAllDecryptionKeys_CredentialNotFound(t *testing.T) {
	store := NewMockStore()

	_, err := FindAllDecryptionKeys(context.Background(), store, "non-existent", nil)
	if err == nil {
		t.Fatal("expected error for non-existent credential")
	}
}

func TestU_RecipientMatcher_MatchesCertificate(t *testing.T) {
	// Test the MatchesCertificate helper
	signer, _ := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgECDSAP256)
	cert := generateEncryptionCertForSigner(t, signer)

	// Test with nil certificate
	matcher := &RecipientMatcher{
		SubjectKeyIdentifier: cert.SubjectKeyId,
	}
	if matcher.MatchesCertificate(nil) {
		t.Error("should not match nil certificate")
	}

	// Test SKI match
	if !matcher.MatchesCertificate(cert) {
		t.Error("should match by SKI")
	}

	// Test wrong SKI
	wrongSKIMatcher := &RecipientMatcher{
		SubjectKeyIdentifier: []byte{9, 9, 9, 9},
	}
	if wrongSKIMatcher.MatchesCertificate(cert) {
		t.Error("should not match wrong SKI")
	}

	// Test IssuerAndSerial match
	var issuer pkix.RDNSequence
	_, _ = asn1.Unmarshal(cert.RawIssuer, &issuer)
	iasMatcher := &RecipientMatcher{
		IssuerAndSerialNumber: &IssuerAndSerial{
			Issuer:       issuer,
			SerialNumber: cert.SerialNumber,
		},
	}
	if !iasMatcher.MatchesCertificate(cert) {
		t.Error("should match by IssuerAndSerial")
	}
}

// =============================================================================
// Validator Edge Cases
// =============================================================================

func TestU_ValidateForUsage_MultipleEKUs(t *testing.T) {
	// Certificate with multiple EKUs
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: "Multi EKU"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageTimeStamping,
			x509.ExtKeyUsageCodeSigning,
			x509.ExtKeyUsageOCSPSigning,
		},
		BasicConstraintsValid: true,
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	cert, _ := x509.ParseCertificate(certDER)

	// Should pass for all included EKUs
	if err := ValidateForTimestamping(cert); err != nil {
		t.Errorf("should allow timestamping: %v", err)
	}
	if err := ValidateForCodeSigning(cert); err != nil {
		t.Errorf("should allow code signing: %v", err)
	}
	if err := ValidateForOCSP(cert); err != nil {
		t.Errorf("should allow OCSP signing: %v", err)
	}
	if err := ValidateForUsage(cert, x509.ExtKeyUsageServerAuth); err != nil {
		t.Errorf("should allow server auth: %v", err)
	}
	if err := ValidateForUsage(cert, x509.ExtKeyUsageClientAuth); err != nil {
		t.Errorf("should allow client auth: %v", err)
	}

	// Should fail for non-included EKU
	if err := ValidateForUsage(cert, x509.ExtKeyUsageEmailProtection); err == nil {
		t.Error("should reject email protection (not in EKU list)")
	}
}

func TestU_ValidateForUsage_AllEKUTypes(t *testing.T) {
	// Test ekuToString coverage
	ekus := []x509.ExtKeyUsage{
		x509.ExtKeyUsageServerAuth,
		x509.ExtKeyUsageClientAuth,
		x509.ExtKeyUsageCodeSigning,
		x509.ExtKeyUsageEmailProtection,
		x509.ExtKeyUsageTimeStamping,
		x509.ExtKeyUsageOCSPSigning,
	}

	for _, eku := range ekus {
		cert := generateCertWithEKU(t, x509.ExtKeyUsageServerAuth) // Wrong EKU
		err := ValidateForUsage(cert, eku)
		if err == nil && eku != x509.ExtKeyUsageServerAuth {
			t.Errorf("expected error for EKU %v", eku)
		}
		// Just verify the error message is formatted properly
		if err != nil && !strings.Contains(err.Error(), "does not have required EKU") {
			t.Errorf("unexpected error format: %v", err)
		}
	}
}

// =============================================================================
// issuerEqual Tests (DER comparison)
// =============================================================================

func TestU_issuerEqual_SameIssuer(t *testing.T) {
	issuer := pkix.RDNSequence{
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{
				Type:  asn1.ObjectIdentifier{2, 5, 4, 3}, // CN
				Value: "Test Issuer",
			},
		},
	}

	if !issuerEqual(issuer, issuer) {
		t.Error("same issuer should be equal")
	}
}

func TestU_issuerEqual_DifferentIssuer(t *testing.T) {
	issuer1 := pkix.RDNSequence{
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{
				Type:  asn1.ObjectIdentifier{2, 5, 4, 3},
				Value: "Issuer One",
			},
		},
	}
	issuer2 := pkix.RDNSequence{
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{
				Type:  asn1.ObjectIdentifier{2, 5, 4, 3},
				Value: "Issuer Two",
			},
		},
	}

	if issuerEqual(issuer1, issuer2) {
		t.Error("different issuers should not be equal")
	}
}

func TestU_issuerEqual_DifferentLength(t *testing.T) {
	issuer1 := pkix.RDNSequence{
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "CN"},
		},
	}
	issuer2 := pkix.RDNSequence{
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "CN"},
		},
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "O"},
		},
	}

	if issuerEqual(issuer1, issuer2) {
		t.Error("issuers with different lengths should not be equal")
	}
}

func TestU_issuerEqual_EmptyIssuers(t *testing.T) {
	var empty1, empty2 pkix.RDNSequence

	if !issuerEqual(empty1, empty2) {
		t.Error("two empty issuers should be equal")
	}
}

// =============================================================================
// Additional Error Cases
// =============================================================================

func TestU_FindDecryptionKeyByRecipient_ListVersionsError(t *testing.T) {
	store := NewMockStore()
	credID := "test-list-versions-error"

	cred := NewCredential(credID, Subject{CommonName: "Test"})
	cred.CreateInitialVersion([]string{"ec/encryption"}, []string{"ec"})
	store.AddCredential(cred)

	// Configure mock to return error on ListVersions
	store.SetListVersionsError(credID, errors.New("storage error"))

	matcher := &RecipientMatcher{
		SubjectKeyIdentifier: []byte{1, 2, 3, 4},
	}

	_, _, err := FindDecryptionKeyByRecipient(context.Background(), store, credID, matcher, nil)
	if err == nil {
		t.Fatal("expected error when ListVersions fails")
	}
	if !strings.Contains(err.Error(), "failed to list versions") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestU_FindDecryptionKeyByRecipient_LoadKeysError(t *testing.T) {
	store := NewMockStore()
	credID := "test-load-keys-error"

	cred := NewCredential(credID, Subject{CommonName: "Test"})
	cred.CreateInitialVersion([]string{"ec/encryption"}, []string{"ec"})
	ver := cred.Versions["v1"]
	ver.Status = string(VersionStatusActive)
	cred.Versions["v1"] = ver

	signer, _ := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgECDSAP256)
	cert := generateEncryptionCertForSigner(t, signer)

	store.AddCredential(cred)
	store.AddVersionedCertificates(credID, "v1", []*x509.Certificate{cert})
	// Don't add keys - this will cause LoadKeysForVersion to fail when cert matches

	// Configure mock to return error on LoadKeysForVersion
	store.SetLoadKeysForVersionError(credID, "v1", errors.New("key load error"))

	var issuer pkix.RDNSequence
	_, _ = asn1.Unmarshal(cert.RawIssuer, &issuer)
	matcher := &RecipientMatcher{
		IssuerAndSerialNumber: &IssuerAndSerial{
			Issuer:       issuer,
			SerialNumber: cert.SerialNumber,
		},
	}

	_, _, err := FindDecryptionKeyByRecipient(context.Background(), store, credID, matcher, nil)
	if err == nil {
		t.Fatal("expected error when LoadKeysForVersion fails")
	}
	if !strings.Contains(err.Error(), "failed to load keys") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestU_RecipientMatcher_EmptyMatcher(t *testing.T) {
	// Matcher with no criteria should not match anything
	matcher := &RecipientMatcher{}

	signer, _ := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgECDSAP256)
	cert := generateEncryptionCertForSigner(t, signer)

	if matcher.MatchesCertificate(cert) {
		t.Error("empty matcher should not match any certificate")
	}
}

func TestU_RecipientMatcher_CertWithoutSKI(t *testing.T) {
	// Test matching SKI when certificate has no SKI
	matcher := &RecipientMatcher{
		SubjectKeyIdentifier: []byte{1, 2, 3, 4},
	}

	// Create cert without SKI
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: "No SKI"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		// No SubjectKeyId
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	cert, _ := x509.ParseCertificate(certDER)

	if matcher.MatchesCertificate(cert) {
		t.Error("SKI matcher should not match cert without SKI")
	}
}

func TestU_FindAllDecryptionKeys_ListVersionsError(t *testing.T) {
	store := NewMockStore()
	credID := "test-find-all-versions-error"

	cred := NewCredential(credID, Subject{CommonName: "Test"})
	cred.CreateInitialVersion([]string{"ec/encryption"}, []string{"ec"})
	store.AddCredential(cred)

	store.SetListVersionsError(credID, errors.New("storage error"))

	_, err := FindAllDecryptionKeys(context.Background(), store, credID, nil)
	if err == nil {
		t.Fatal("expected error when ListVersions fails")
	}
	if !strings.Contains(err.Error(), "failed to list versions") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestU_FindAllDecryptionKeys_EmptyVersions(t *testing.T) {
	store := NewMockStore()
	credID := "test-find-all-empty"

	cred := NewCredential(credID, Subject{CommonName: "Test"})
	// Don't create any versions
	cred.Versions = make(map[string]CredVersion)
	store.AddCredential(cred)

	entries, err := FindAllDecryptionKeys(context.Background(), store, credID, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries for credential with no versions, got %d", len(entries))
	}
}

// =============================================================================
// Helper Functions
// =============================================================================

func generateCertForSigner(t *testing.T, signer pkicrypto.Signer) *x509.Certificate {
	t.Helper()

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "Test Certificate",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		SubjectKeyId:          []byte{1, 2, 3, 4},
	}

	// Self-sign using the signer
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert
}

func generateEncryptionCertForSigner(t *testing.T, signer pkicrypto.Signer) *x509.Certificate {
	t.Helper()

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "Test Encryption Certificate",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement,
		BasicConstraintsValid: true,
		SubjectKeyId:          []byte{1, 2, 3, 4},
	}

	// Self-sign using the signer
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert
}

func generateCertWithEKU(t *testing.T, eku x509.ExtKeyUsage) *x509.Certificate {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "EKU Test Certificate",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{eku},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert
}
