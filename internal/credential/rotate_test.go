package credential

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509/pkix"
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/remiblancher/post-quantum-pki/internal/ca"
	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
	"github.com/remiblancher/post-quantum-pki/internal/profile"
)

// =============================================================================
// Key Rotation Mode Tests
// =============================================================================

func TestKeyRotationMode_Constants(t *testing.T) {
	// Verify constants have expected values
	if KeyRotateNew != 0 {
		t.Errorf("KeyRotateNew = %d, want 0", KeyRotateNew)
	}
	if KeyRotateKeep != 1 {
		t.Errorf("KeyRotateKeep = %d, want 1", KeyRotateKeep)
	}
}

// =============================================================================
// RotateCredential Tests
// =============================================================================

func TestCA_RotateCredential_Success(t *testing.T) {
	tmpDir := t.TempDir()
	store := ca.NewFileStore(tmpDir)

	cfg := ca.Config{
		CommonName:    "Test Root CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	caInstance, err := ca.Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Create a profile
	prof := &profile.Profile{
		Name:      "test-profile",
		Algorithm: pkicrypto.AlgECDSAP256,
		Validity:  365 * 24 * time.Hour,
	}

	// Create profile store
	profileStore := profile.NewProfileStore(tmpDir)
	if err := profileStore.Save(prof); err != nil {
		t.Fatalf("Save profile error = %v", err)
	}

	// Create initial credential
	req := EnrollmentRequest{
		Subject:  pkix.Name{CommonName: "Test Subject"},
		DNSNames: []string{"test.example.com"},
	}

	result, err := EnrollWithProfile(caInstance, req, prof)
	if err != nil {
		t.Fatalf("EnrollWithProfile() error = %v", err)
	}

	// Save credential to store
	credStore := NewFileStore(filepath.Join(tmpDir, "credentials"))
	if err := credStore.Init(); err != nil {
		t.Fatalf("credStore.Init() error = %v", err)
	}

	passphrase := []byte("testpass")
	if err := credStore.Save(context.Background(), result.Credential, result.Certificates, result.Signers, passphrase); err != nil {
		t.Fatalf("credStore.Save() error = %v", err)
	}

	credentialID := result.Credential.ID

	// Rotate credential with new keys
	rotatedResult, err := RotateCredential(caInstance, context.Background(), credentialID, credStore, profileStore, passphrase, KeyRotateNew, nil)
	if err != nil {
		t.Fatalf("RotateCredential() error = %v", err)
	}

	if rotatedResult == nil {
		t.Fatal("RotateCredential() returned nil result")
	}

	if rotatedResult.Credential == nil {
		t.Error("RotateCredential() result has nil Credential")
	}

	if len(rotatedResult.Certificates) != 1 {
		t.Errorf("RotateCredential() returned %d certificates, want 1", len(rotatedResult.Certificates))
	}

	// Verify new credential has different ID
	if rotatedResult.Credential.ID == credentialID {
		t.Error("Rotated credential should have new ID")
	}
}

func TestCA_RotateCredential_KeepKeys(t *testing.T) {
	tmpDir := t.TempDir()
	store := ca.NewFileStore(tmpDir)

	cfg := ca.Config{
		CommonName:    "Test Root CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	caInstance, err := ca.Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Create a profile
	prof := &profile.Profile{
		Name:      "test-profile",
		Algorithm: pkicrypto.AlgECDSAP256,
		Validity:  365 * 24 * time.Hour,
	}

	// Create profile store
	profileStore := profile.NewProfileStore(tmpDir)
	if err := profileStore.Save(prof); err != nil {
		t.Fatalf("Save profile error = %v", err)
	}

	// Create initial credential
	req := EnrollmentRequest{
		Subject:  pkix.Name{CommonName: "Test Subject"},
		DNSNames: []string{"test.example.com"},
	}

	result, err := EnrollWithProfile(caInstance, req, prof)
	if err != nil {
		t.Fatalf("EnrollWithProfile() error = %v", err)
	}

	// Save credential to store
	credStore := NewFileStore(filepath.Join(tmpDir, "credentials"))
	if err := credStore.Init(); err != nil {
		t.Fatalf("credStore.Init() error = %v", err)
	}

	passphrase := []byte("testpass")
	if err := credStore.Save(context.Background(), result.Credential, result.Certificates, result.Signers, passphrase); err != nil {
		t.Fatalf("credStore.Save() error = %v", err)
	}

	credentialID := result.Credential.ID

	// Rotate credential keeping existing keys
	rotatedResult, err := RotateCredential(caInstance, context.Background(), credentialID, credStore, profileStore, passphrase, KeyRotateKeep, nil)
	if err != nil {
		t.Fatalf("RotateCredential(KeyRotateKeep) error = %v", err)
	}

	if rotatedResult == nil {
		t.Fatal("RotateCredential() returned nil result")
	}

	if len(rotatedResult.Certificates) != 1 {
		t.Errorf("RotateCredential() returned %d certificates, want 1", len(rotatedResult.Certificates))
	}
}

func TestCA_RotateCredential_CredentialNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	store := ca.NewFileStore(tmpDir)

	cfg := ca.Config{
		CommonName:    "Test Root CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	caInstance, err := ca.Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	profileStore := profile.NewProfileStore(tmpDir)
	credStore := NewFileStore(filepath.Join(tmpDir, "credentials"))
	if err := credStore.Init(); err != nil {
		t.Fatalf("credStore.Init() error = %v", err)
	}

	// Try to rotate non-existent credential
	_, err = RotateCredential(caInstance, context.Background(), "nonexistent", credStore, profileStore, nil, KeyRotateNew, nil)
	if err == nil {
		t.Error("RotateCredential() should fail for non-existent credential")
	}
}

func TestCA_RotateCredential_ProfileNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	store := ca.NewFileStore(tmpDir)

	cfg := ca.Config{
		CommonName:    "Test Root CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	caInstance, err := ca.Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Create a profile
	prof := &profile.Profile{
		Name:      "test-profile",
		Algorithm: pkicrypto.AlgECDSAP256,
		Validity:  365 * 24 * time.Hour,
	}

	// Create profile store WITHOUT saving the profile
	profileStore := profile.NewProfileStore(tmpDir)

	// Create initial credential
	req := EnrollmentRequest{
		Subject: pkix.Name{CommonName: "Test Subject"},
	}

	result, err := EnrollWithProfile(caInstance, req, prof)
	if err != nil {
		t.Fatalf("EnrollWithProfile() error = %v", err)
	}

	// Save credential to store
	credStore := NewFileStore(filepath.Join(tmpDir, "credentials"))
	if err := credStore.Init(); err != nil {
		t.Fatalf("credStore.Init() error = %v", err)
	}

	passphrase := []byte("testpass")
	if err := credStore.Save(context.Background(), result.Credential, result.Certificates, result.Signers, passphrase); err != nil {
		t.Fatalf("credStore.Save() error = %v", err)
	}

	credentialID := result.Credential.ID

	// Try to rotate - should fail because profile not found
	_, err = RotateCredential(caInstance, context.Background(), credentialID, credStore, profileStore, passphrase, KeyRotateNew, nil)
	if err == nil {
		t.Error("RotateCredential() should fail when profile not found")
	}
}

func TestCA_RotateCredential_WithNewProfiles(t *testing.T) {
	tmpDir := t.TempDir()
	store := ca.NewFileStore(tmpDir)

	cfg := ca.Config{
		CommonName:    "Test Root CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	caInstance, err := ca.Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Create original profile
	origProf := &profile.Profile{
		Name:      "original-profile",
		Algorithm: pkicrypto.AlgECDSAP256,
		Validity:  365 * 24 * time.Hour,
	}

	// Create new profile for rotation
	newProf := &profile.Profile{
		Name:      "new-profile",
		Algorithm: pkicrypto.AlgECDSAP256,
		Validity:  730 * 24 * time.Hour, // 2 years
	}

	// Create profile store and save both
	profileStore := profile.NewProfileStore(tmpDir)
	if err := profileStore.Save(origProf); err != nil {
		t.Fatalf("Save origProf error = %v", err)
	}
	if err := profileStore.Save(newProf); err != nil {
		t.Fatalf("Save newProf error = %v", err)
	}

	// Create initial credential
	req := EnrollmentRequest{
		Subject: pkix.Name{CommonName: "Test Subject"},
	}

	result, err := EnrollWithProfile(caInstance, req, origProf)
	if err != nil {
		t.Fatalf("EnrollWithProfile() error = %v", err)
	}

	// Save credential to store
	credStore := NewFileStore(filepath.Join(tmpDir, "credentials"))
	if err := credStore.Init(); err != nil {
		t.Fatalf("credStore.Init() error = %v", err)
	}

	passphrase := []byte("testpass")
	if err := credStore.Save(context.Background(), result.Credential, result.Certificates, result.Signers, passphrase); err != nil {
		t.Fatalf("credStore.Save() error = %v", err)
	}

	credentialID := result.Credential.ID

	// Rotate credential with new profile (crypto-agility)
	rotatedResult, err := RotateCredential(caInstance, context.Background(), credentialID, credStore, profileStore, passphrase, KeyRotateNew, []string{"new-profile"})
	if err != nil {
		t.Fatalf("RotateCredential() error = %v", err)
	}

	if rotatedResult == nil {
		t.Fatal("RotateCredential() returned nil result")
	}

	// Verify the new credential uses the new profile
	ver := rotatedResult.Credential.ActiveVersion()
	if ver == nil || len(ver.Profiles) != 1 || ver.Profiles[0] != "new-profile" {
		t.Errorf("Rotated credential profiles = %v, want [new-profile]", ver)
	}
}

// =============================================================================
// RevokeCredential Tests
// =============================================================================

func TestCA_RevokeCredential_Success(t *testing.T) {
	tmpDir := t.TempDir()
	store := ca.NewFileStore(tmpDir)

	cfg := ca.Config{
		CommonName:    "Test Root CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	caInstance, err := ca.Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Create a profile
	prof := &profile.Profile{
		Name:      "test-profile",
		Algorithm: pkicrypto.AlgECDSAP256,
		Validity:  365 * 24 * time.Hour,
	}

	// Create initial credential
	req := EnrollmentRequest{
		Subject: pkix.Name{CommonName: "Test Subject"},
	}

	result, err := EnrollWithProfile(caInstance, req, prof)
	if err != nil {
		t.Fatalf("EnrollWithProfile() error = %v", err)
	}

	// Save credential to store
	credStore := NewFileStore(filepath.Join(tmpDir, "credentials"))
	if err := credStore.Init(); err != nil {
		t.Fatalf("credStore.Init() error = %v", err)
	}

	passphrase := []byte("testpass")
	if err := credStore.Save(context.Background(), result.Credential, result.Certificates, result.Signers, passphrase); err != nil {
		t.Fatalf("credStore.Save() error = %v", err)
	}

	credentialID := result.Credential.ID

	// Revoke credential
	err = RevokeCredential(caInstance, context.Background(), credentialID, ca.ReasonKeyCompromise, credStore)
	if err != nil {
		t.Fatalf("RevokeCredential() error = %v", err)
	}

	// Verify credential status is revoked
	revokedCred, err := credStore.Load(context.Background(), credentialID)
	if err != nil {
		t.Fatalf("Load revoked credential error = %v", err)
	}

	if revokedCred.RevokedAt == nil {
		t.Errorf("Credential RevokedAt is nil, expected to be set")
	}
}

func TestCA_RevokeCredential_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	store := ca.NewFileStore(tmpDir)

	cfg := ca.Config{
		CommonName:    "Test Root CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	caInstance, err := ca.Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	credStore := NewFileStore(filepath.Join(tmpDir, "credentials"))
	if err := credStore.Init(); err != nil {
		t.Fatalf("credStore.Init() error = %v", err)
	}

	// Try to revoke non-existent credential
	err = RevokeCredential(caInstance, context.Background(), "nonexistent", ca.ReasonKeyCompromise, credStore)
	if err == nil {
		t.Error("RevokeCredential() should fail for non-existent credential")
	}
}

func TestCA_RevokeCredential_WithReason(t *testing.T) {
	tmpDir := t.TempDir()
	store := ca.NewFileStore(tmpDir)

	cfg := ca.Config{
		CommonName:    "Test Root CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	caInstance, err := ca.Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	prof := &profile.Profile{
		Name:      "test-profile",
		Algorithm: pkicrypto.AlgECDSAP256,
		Validity:  365 * 24 * time.Hour,
	}

	req := EnrollmentRequest{
		Subject: pkix.Name{CommonName: "Test Subject"},
	}

	result, err := EnrollWithProfile(caInstance, req, prof)
	if err != nil {
		t.Fatalf("EnrollWithProfile() error = %v", err)
	}

	credStore := NewFileStore(filepath.Join(tmpDir, "credentials"))
	if err := credStore.Init(); err != nil {
		t.Fatalf("credStore.Init() error = %v", err)
	}

	passphrase := []byte("testpass")
	if err := credStore.Save(context.Background(), result.Credential, result.Certificates, result.Signers, passphrase); err != nil {
		t.Fatalf("credStore.Save() error = %v", err)
	}

	credentialID := result.Credential.ID

	// Test different revocation reasons
	reasons := []ca.RevocationReason{
		ca.ReasonUnspecified,
		ca.ReasonKeyCompromise,
		ca.ReasonCACompromise,
		ca.ReasonAffiliationChanged,
		ca.ReasonSuperseded,
		ca.ReasonCessationOfOperation,
	}

	for i, reason := range reasons {
		// Create a new credential for each test
		result, err := EnrollWithProfile(caInstance, req, prof)
		if err != nil {
			t.Fatalf("EnrollWithProfile() error = %v", err)
		}

		if err := credStore.Save(context.Background(), result.Credential, result.Certificates, result.Signers, passphrase); err != nil {
			t.Fatalf("credStore.Save() error = %v", err)
		}

		err = RevokeCredential(caInstance, context.Background(), result.Credential.ID, reason, credStore)
		if err != nil {
			t.Errorf("RevokeCredential(reason=%d) error = %v", reason, err)
		}

		if i == 0 {
			// Also verify the original credential
			err = RevokeCredential(caInstance, context.Background(), credentialID, ca.ReasonSuperseded, credStore)
			if err != nil {
				t.Fatalf("RevokeCredential(original) error = %v", err)
			}
		}
	}
}

// =============================================================================
// rotateWithExistingKeys Tests
// =============================================================================

func TestCA_rotateWithExistingKeys_NoProfiles(t *testing.T) {
	tmpDir := t.TempDir()
	store := ca.NewFileStore(tmpDir)

	cfg := ca.Config{
		CommonName:    "Test Root CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	caInstance, err := ca.Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	req := EnrollmentRequest{
		Subject: pkix.Name{CommonName: "Test Subject"},
	}

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer := &rotateTestSigner{key: key, alg: pkicrypto.AlgECDSAP256}

	_, err = rotateWithExistingKeys(caInstance, req, []*profile.Profile{}, []pkicrypto.Signer{signer})
	if err == nil {
		t.Error("rotateWithExistingKeys() should fail with no profiles")
	}
}

// rotateTestSigner is a minimal signer for testing rotateWithExistingKeys
type rotateTestSigner struct {
	key *ecdsa.PrivateKey
	alg pkicrypto.AlgorithmID
}

func (s *rotateTestSigner) Public() crypto.PublicKey {
	return &s.key.PublicKey
}

func (s *rotateTestSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return ecdsa.SignASN1(rand, s.key, digest)
}

func (s *rotateTestSigner) Algorithm() pkicrypto.AlgorithmID {
	return s.alg
}

// =============================================================================
// RotateCredentialVersioned Tests
// =============================================================================

func TestCA_RotateCredentialVersioned_NoSignerLoaded(t *testing.T) {
	tmpDir := t.TempDir()
	store := ca.NewFileStore(tmpDir)

	cfg := ca.Config{
		CommonName:    "Test Root CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	caInstance, err := ca.Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Create a CA without signer (simulating unloaded state)
	mockCA := &ca.CA{}

	credStore := NewFileStore(filepath.Join(tmpDir, "credentials"))
	if err := credStore.Init(); err != nil {
		t.Fatalf("credStore.Init() error = %v", err)
	}

	_ = caInstance // Just to use it

	req := CredentialRotateRequest{
		CredentialID:    "test-cred",
		CredentialStore: credStore,
	}

	_, err = RotateCredentialVersioned(mockCA, req)
	if err == nil {
		t.Error("RotateCredentialVersioned() should fail when CA signer not loaded")
	}
}

func TestCA_RotateCredentialVersioned_NoStore(t *testing.T) {
	tmpDir := t.TempDir()
	store := ca.NewFileStore(tmpDir)

	cfg := ca.Config{
		CommonName:    "Test Root CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	caInstance, err := ca.Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	req := CredentialRotateRequest{
		CredentialID:    "test-cred",
		CredentialStore: nil, // No store
	}

	_, err = RotateCredentialVersioned(caInstance, req)
	if err == nil {
		t.Error("RotateCredentialVersioned() should fail when no credential store provided")
	}
}

func TestCA_RotateCredentialVersioned_CredentialNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	store := ca.NewFileStore(tmpDir)

	cfg := ca.Config{
		CommonName:    "Test Root CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	caInstance, err := ca.Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	credStore := NewFileStore(filepath.Join(tmpDir, "credentials"))
	if err := credStore.Init(); err != nil {
		t.Fatalf("credStore.Init() error = %v", err)
	}

	prof := &profile.Profile{
		Name:      "test-profile",
		Algorithm: pkicrypto.AlgECDSAP256,
		Validity:  365 * 24 * time.Hour,
	}

	req := CredentialRotateRequest{
		CredentialID:    "nonexistent",
		CredentialStore: credStore,
		Profiles:        []*profile.Profile{prof},
	}

	_, err = RotateCredentialVersioned(caInstance, req)
	if err == nil {
		t.Error("RotateCredentialVersioned() should fail for non-existent credential")
	}
}

func TestCA_RotateCredentialVersioned_NoProfiles(t *testing.T) {
	tmpDir := t.TempDir()
	store := ca.NewFileStore(tmpDir)

	cfg := ca.Config{
		CommonName:    "Test Root CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	caInstance, err := ca.Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Create initial credential
	prof := &profile.Profile{
		Name:      "test-profile",
		Algorithm: pkicrypto.AlgECDSAP256,
		Validity:  365 * 24 * time.Hour,
	}

	credStore := NewFileStore(filepath.Join(tmpDir, "credentials"))
	if err := credStore.Init(); err != nil {
		t.Fatalf("credStore.Init() error = %v", err)
	}

	enrollReq := EnrollmentRequest{
		Subject: pkix.Name{CommonName: "Test Subject"},
	}

	result, err := EnrollWithProfile(caInstance, enrollReq, prof)
	if err != nil {
		t.Fatalf("EnrollWithProfile() error = %v", err)
	}

	passphrase := []byte("testpass")
	if err := credStore.Save(context.Background(), result.Credential, result.Certificates, result.Signers, passphrase); err != nil {
		t.Fatalf("credStore.Save() error = %v", err)
	}

	req := CredentialRotateRequest{
		CredentialID:    result.Credential.ID,
		CredentialStore: credStore,
		Profiles:        []*profile.Profile{}, // No profiles
	}

	_, err = RotateCredentialVersioned(caInstance, req)
	if err == nil {
		t.Error("RotateCredentialVersioned() should fail with no profiles")
	}
}

func TestCA_RotateCredentialVersioned_Success(t *testing.T) {
	tmpDir := t.TempDir()
	store := ca.NewFileStore(tmpDir)

	cfg := ca.Config{
		CommonName:    "Test Root CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	caInstance, err := ca.Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Create initial credential
	prof := &profile.Profile{
		Name:      "test-profile",
		Algorithm: pkicrypto.AlgECDSAP256,
		Validity:  365 * 24 * time.Hour,
	}

	credStore := NewFileStore(filepath.Join(tmpDir, "credentials"))
	if err := credStore.Init(); err != nil {
		t.Fatalf("credStore.Init() error = %v", err)
	}

	enrollReq := EnrollmentRequest{
		Subject: pkix.Name{CommonName: "Test Subject"},
	}

	result, err := EnrollWithProfile(caInstance, enrollReq, prof)
	if err != nil {
		t.Fatalf("EnrollWithProfile() error = %v", err)
	}

	passphrase := []byte("testpass")
	if err := credStore.Save(context.Background(), result.Credential, result.Certificates, result.Signers, passphrase); err != nil {
		t.Fatalf("credStore.Save() error = %v", err)
	}

	// Rotate with new profile
	newProf := &profile.Profile{
		Name:      "new-profile",
		Algorithm: pkicrypto.AlgECDSAP256,
		Validity:  730 * 24 * time.Hour,
	}

	req := CredentialRotateRequest{
		Context:         context.Background(),
		CredentialID:    result.Credential.ID,
		Profiles:        []*profile.Profile{newProf},
		Passphrase:      passphrase,
		CredentialStore: credStore,
		KeyMode:         KeyRotateNew,
	}

	rotateResult, err := RotateCredentialVersioned(caInstance, req)
	if err != nil {
		t.Fatalf("RotateCredentialVersioned() error = %v", err)
	}

	if rotateResult == nil {
		t.Fatal("RotateCredentialVersioned() returned nil result")
	}

	if rotateResult.NewVersionID == "" {
		t.Error("NewVersionID should not be empty")
	}

	if len(rotateResult.Certificates) != 1 {
		t.Errorf("Expected 1 certificate, got %d", len(rotateResult.Certificates))
	}
}

// =============================================================================
// issueCatalystCertWithExistingKeys Tests
// =============================================================================

func TestCA_issueCatalystCertWithExistingKeys_InvalidProfile(t *testing.T) {
	tmpDir := t.TempDir()
	store := ca.NewFileStore(tmpDir)

	cfg := ca.Config{
		CommonName:    "Test Root CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	caInstance, err := ca.Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Profile without catalyst mode
	prof := &profile.Profile{
		Name:      "simple-profile",
		Algorithm: pkicrypto.AlgECDSAP256,
		Validity:  365 * 24 * time.Hour,
	}

	req := EnrollmentRequest{
		Subject: pkix.Name{CommonName: "Test Subject"},
	}

	signersByAlg := make(map[pkicrypto.AlgorithmID][]pkicrypto.Signer)
	usedIndex := make(map[pkicrypto.AlgorithmID]int)

	_, _, err = issueCatalystCertWithExistingKeys(caInstance, req, prof, time.Now(), time.Now().AddDate(1, 0, 0), signersByAlg, usedIndex)
	if err == nil {
		t.Error("issueCatalystCertWithExistingKeys() should fail with non-catalyst profile")
	}
}

// =============================================================================
// issueCompositeCertWithExistingKeys Tests
// =============================================================================

func TestCA_issueCompositeCertWithExistingKeys_InvalidProfile(t *testing.T) {
	tmpDir := t.TempDir()
	store := ca.NewFileStore(tmpDir)

	cfg := ca.Config{
		CommonName:    "Test Root CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	caInstance, err := ca.Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Profile without composite mode
	prof := &profile.Profile{
		Name:      "simple-profile",
		Algorithm: pkicrypto.AlgECDSAP256,
		Validity:  365 * 24 * time.Hour,
	}

	req := EnrollmentRequest{
		Subject: pkix.Name{CommonName: "Test Subject"},
	}

	signersByAlg := make(map[pkicrypto.AlgorithmID][]pkicrypto.Signer)
	usedIndex := make(map[pkicrypto.AlgorithmID]int)

	_, _, err = issueCompositeCertWithExistingKeys(caInstance, req, prof, time.Now(), time.Now().AddDate(1, 0, 0), signersByAlg, usedIndex)
	if err == nil {
		t.Error("issueCompositeCertWithExistingKeys() should fail with non-composite profile")
	}
}

// =============================================================================
// ParseSerialHex Tests
// =============================================================================

func TestU_ParseSerialHex_Valid(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"01", "1"},
		{"0x01", "1"},
		{"0X01", "1"},
		{"ff", "255"},
		{"0xff", "255"},
		{"0123", "291"},
		{"deadbeef", "3735928559"},
		{"0xdeadbeef", "3735928559"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			n, ok := ParseSerialHex(tc.input)
			if !ok {
				t.Errorf("ParseSerialHex(%q) returned false, want true", tc.input)
				return
			}
			if n.String() != tc.expected {
				t.Errorf("ParseSerialHex(%q) = %s, want %s", tc.input, n.String(), tc.expected)
			}
		})
	}
}

func TestU_ParseSerialHex_Invalid(t *testing.T) {
	tests := []string{
		"xyz",
		"0xghi",
		"not-hex",
		"",
	}

	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			_, ok := ParseSerialHex(input)
			if ok && input != "" {
				t.Errorf("ParseSerialHex(%q) returned true, want false", input)
			}
		})
	}
}
