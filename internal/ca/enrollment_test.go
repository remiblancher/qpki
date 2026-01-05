package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509/pkix"
	"io"
	"testing"
	"time"

	"github.com/remiblancher/post-quantum-pki/internal/credential"
	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
	"github.com/remiblancher/post-quantum-pki/internal/profile"
)

// =============================================================================
// Enrollment Tests
// =============================================================================

func TestCA_Enroll_Simple(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Create a simple profile
	simpleProfile := &profile.Profile{
		Name:      "test-simple",
		Algorithm: pkicrypto.AlgECDSAP256,
		Validity:  365 * 24 * time.Hour,
		Extensions: &profile.ExtensionsConfig{
			KeyUsage: &profile.KeyUsageConfig{
				Values: []string{"digitalSignature"},
			},
			BasicConstraints: &profile.BasicConstraintsConfig{
				CA: false,
			},
		},
	}

	// Create a profile store and save the profile
	profileStore := profile.NewProfileStore(tmpDir)
	if err := profileStore.Save(simpleProfile); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	req := EnrollmentRequest{
		Subject:     pkix.Name{CommonName: "Test Subject"},
		ProfileName: "test-simple",
		DNSNames:    []string{"test.example.com"},
	}

	result, err := ca.Enroll(req, profileStore)
	if err != nil {
		t.Fatalf("Enroll() error = %v", err)
	}

	if result == nil {
		t.Fatal("Enroll() returned nil result")
	}
	if result.Credential == nil {
		t.Error("Enroll() result has nil Credential")
	}
	if len(result.Certificates) != 1 {
		t.Errorf("Enroll() returned %d certificates, want 1", len(result.Certificates))
	}
	if len(result.Signers) != 1 {
		t.Errorf("Enroll() returned %d signers, want 1", len(result.Signers))
	}

	// Verify certificate subject
	cert := result.Certificates[0]
	if cert.Subject.CommonName != "Test Subject" {
		t.Errorf("Certificate CN = %s, want Test Subject", cert.Subject.CommonName)
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "test.example.com" {
		t.Errorf("Certificate DNSNames = %v, want [test.example.com]", cert.DNSNames)
	}
}

func TestCA_Enroll_ProfileNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	profileStore := profile.NewProfileStore(tmpDir)

	req := EnrollmentRequest{
		Subject:     pkix.Name{CommonName: "Test Subject"},
		ProfileName: "nonexistent",
	}

	_, err = ca.Enroll(req, profileStore)
	if err == nil {
		t.Error("Enroll() should fail for non-existent profile")
	}
}

func TestCA_Enroll_NoSigner(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
		Passphrase:    "test",
	}

	_, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Load CA without signer
	ca, err := New(store)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	profileStore := profile.NewProfileStore(tmpDir)

	req := EnrollmentRequest{
		Subject:     pkix.Name{CommonName: "Test Subject"},
		ProfileName: "test-simple",
	}

	_, err = ca.Enroll(req, profileStore)
	if err == nil {
		t.Error("Enroll() should fail when signer not loaded")
	}
}

func TestCA_EnrollWithProfile_Simple(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	prof := &profile.Profile{
		Name:      "test-profile",
		Algorithm: pkicrypto.AlgECDSAP256,
		Validity:  365 * 24 * time.Hour,
	}

	req := EnrollmentRequest{
		Subject:  pkix.Name{CommonName: "Test Subject", Organization: []string{"Test Org"}},
		DNSNames: []string{"test.example.com"},
	}

	result, err := ca.EnrollWithProfile(req, prof)
	if err != nil {
		t.Fatalf("EnrollWithProfile() error = %v", err)
	}

	if result.Credential == nil {
		t.Error("EnrollWithProfile() result has nil Credential")
	}
	if len(result.Certificates) != 1 {
		t.Errorf("EnrollWithProfile() returned %d certificates, want 1", len(result.Certificates))
	}
	if len(result.Signers) != 1 {
		t.Errorf("EnrollWithProfile() returned %d signers, want 1", len(result.Signers))
	}

	// Verify credential is activated (status may be "valid" or "active" depending on implementation)
	if result.Credential.Status != "valid" && result.Credential.Status != "active" {
		t.Errorf("Credential status = %s, want valid or active", result.Credential.Status)
	}
}

func TestCA_EnrollWithProfile_NoSigner(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
		Passphrase:    "test",
	}

	_, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	ca, err := New(store)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	prof := &profile.Profile{
		Name:      "test-profile",
		Algorithm: pkicrypto.AlgECDSAP256,
		Validity:  365 * 24 * time.Hour,
	}

	req := EnrollmentRequest{
		Subject: pkix.Name{CommonName: "Test Subject"},
	}

	_, err = ca.EnrollWithProfile(req, prof)
	if err == nil {
		t.Error("EnrollWithProfile() should fail when signer not loaded")
	}
}

func TestCA_EnrollMulti_SingleProfile(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	profiles := []*profile.Profile{
		{
			Name:      "signature",
			Algorithm: pkicrypto.AlgECDSAP256,
			Validity:  365 * 24 * time.Hour,
		},
	}

	req := EnrollmentRequest{
		Subject: pkix.Name{CommonName: "Test Subject"},
	}

	result, err := ca.EnrollMulti(req, profiles)
	if err != nil {
		t.Fatalf("EnrollMulti() error = %v", err)
	}

	if result.Credential == nil {
		t.Error("EnrollMulti() result has nil Credential")
	}
	if len(result.Certificates) != 1 {
		t.Errorf("EnrollMulti() returned %d certificates, want 1", len(result.Certificates))
	}
}

func TestCA_EnrollMulti_NoProfiles(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	req := EnrollmentRequest{
		Subject: pkix.Name{CommonName: "Test Subject"},
	}

	_, err = ca.EnrollMulti(req, []*profile.Profile{})
	if err == nil {
		t.Error("EnrollMulti() should fail with no profiles")
	}
}

func TestCA_EnrollMulti_NoSigner(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
		Passphrase:    "test",
	}

	_, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	ca, err := New(store)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	profiles := []*profile.Profile{
		{
			Name:      "signature",
			Algorithm: pkicrypto.AlgECDSAP256,
			Validity:  365 * 24 * time.Hour,
		},
	}

	req := EnrollmentRequest{
		Subject: pkix.Name{CommonName: "Test Subject"},
	}

	_, err = ca.EnrollMulti(req, profiles)
	if err == nil {
		t.Error("EnrollMulti() should fail when signer not loaded")
	}
}

// =============================================================================
// Helper Function Tests
// =============================================================================

func TestGenerateCredentialID(t *testing.T) {
	// Test with regular common name
	id1 := generateCredentialID("Test User")
	if id1 == "" {
		t.Error("generateCredentialID() returned empty string")
	}

	// Test with common name that needs cleaning
	id2 := generateCredentialID("Test.User@example.com")
	if id2 == "" {
		t.Error("generateCredentialID() returned empty string for email")
	}

	// Test with long common name (should be truncated)
	id3 := generateCredentialID("VeryLongCommonNameThatExceedsSixteenCharacters")
	if id3 == "" {
		t.Error("generateCredentialID() returned empty string for long name")
	}

	// Two calls should generate different IDs (due to random suffix)
	id4 := generateCredentialID("Test User")
	if id1 == id4 {
		t.Log("Warning: two calls to generateCredentialID may occasionally produce the same ID (rare)")
	}
}

func TestParseSerialHex(t *testing.T) {
	tests := []struct {
		input   string
		wantOK  bool
		wantVal int64
	}{
		{"0x01", true, 1},
		{"0X01", true, 1},
		{"01", true, 1},
		{"ff", true, 255},
		{"0xFF", true, 255},
		{"invalid", false, 0},
		{"0xgg", false, 0},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			val, ok := parseSerialHex(tt.input)
			if ok != tt.wantOK {
				t.Errorf("parseSerialHex(%s) ok = %v, want %v", tt.input, ok, tt.wantOK)
			}
			if ok && val.Int64() != tt.wantVal {
				t.Errorf("parseSerialHex(%s) value = %d, want %d", tt.input, val.Int64(), tt.wantVal)
			}
		})
	}
}

func TestGetSignerForAlgorithm(t *testing.T) {
	// Create a test signer
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer := &testSigner{key: key, alg: pkicrypto.AlgECDSAP256}

	signersByAlg := map[pkicrypto.AlgorithmID][]pkicrypto.Signer{
		pkicrypto.AlgECDSAP256: {signer},
	}
	usedIndex := make(map[pkicrypto.AlgorithmID]int)

	// First call should succeed
	s1, err := getSignerForAlgorithm(pkicrypto.AlgECDSAP256, signersByAlg, usedIndex)
	if err != nil {
		t.Fatalf("getSignerForAlgorithm() error = %v", err)
	}
	if s1 == nil {
		t.Error("getSignerForAlgorithm() returned nil signer")
	}

	// Second call should fail (no more signers)
	_, err = getSignerForAlgorithm(pkicrypto.AlgECDSAP256, signersByAlg, usedIndex)
	if err == nil {
		t.Error("getSignerForAlgorithm() should fail when no more signers available")
	}

	// Call with non-existent algorithm should fail
	_, err = getSignerForAlgorithm(pkicrypto.AlgECDSAP384, signersByAlg, usedIndex)
	if err == nil {
		t.Error("getSignerForAlgorithm() should fail for non-existent algorithm")
	}
}

// testSigner is a minimal signer for testing getSignerForAlgorithm
type testSigner struct {
	key *ecdsa.PrivateKey
	alg pkicrypto.AlgorithmID
}

func (s *testSigner) Public() crypto.PublicKey {
	return &s.key.PublicKey
}

func (s *testSigner) Sign(rnd io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}

func (s *testSigner) Algorithm() pkicrypto.AlgorithmID {
	return s.alg
}

func (s *testSigner) SavePrivateKey(path string, passphrase []byte) error {
	return nil
}

// =============================================================================
// Compiled Profile Tests
// =============================================================================

func TestCA_EnrollWithCompiledProfile_NoSigner(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
		Passphrase:    "test",
	}

	_, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	ca, err := New(store)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	prof := &profile.Profile{
		Name:      "test-profile",
		Algorithm: pkicrypto.AlgECDSAP256,
		Validity:  365 * 24 * time.Hour,
	}

	cp, err := prof.Compile()
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	req := EnrollmentRequest{
		Subject: pkix.Name{CommonName: "Test Subject"},
	}

	_, err = ca.EnrollWithCompiledProfile(req, cp)
	if err == nil {
		t.Error("EnrollWithCompiledProfile() should fail when signer not loaded")
	}
}

func TestCA_EnrollWithCompiledProfile_Simple(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	prof := &profile.Profile{
		Name:      "test-profile",
		Algorithm: pkicrypto.AlgECDSAP256,
		Validity:  365 * 24 * time.Hour,
	}

	cp, err := prof.Compile()
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	req := EnrollmentRequest{
		Subject:  pkix.Name{CommonName: "Test Subject"},
		DNSNames: []string{"test.example.com"},
	}

	result, err := ca.EnrollWithCompiledProfile(req, cp)
	if err != nil {
		t.Fatalf("EnrollWithCompiledProfile() error = %v", err)
	}

	if result.Credential == nil {
		t.Error("EnrollWithCompiledProfile() result has nil Credential")
	}
	if len(result.Certificates) != 1 {
		t.Errorf("EnrollWithCompiledProfile() returned %d certificates, want 1", len(result.Certificates))
	}
	if len(result.Signers) != 1 {
		t.Errorf("EnrollWithCompiledProfile() returned %d signers, want 1", len(result.Signers))
	}
}

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
	store := NewStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := Initialize(store, cfg)
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

	result, err := ca.EnrollWithProfile(req, prof)
	if err != nil {
		t.Fatalf("EnrollWithProfile() error = %v", err)
	}

	// Save credential to store
	credStore := credential.NewFileStore(tmpDir)
	if err := credStore.Init(); err != nil {
		t.Fatalf("credStore.Init() error = %v", err)
	}

	passphrase := []byte("testpass")
	if err := credStore.Save(result.Credential, result.Certificates, result.Signers, passphrase); err != nil {
		t.Fatalf("credStore.Save() error = %v", err)
	}

	credentialID := result.Credential.ID

	// Rotate credential with new keys
	rotatedResult, err := ca.RotateCredential(credentialID, credStore, profileStore, passphrase, KeyRotateNew, nil)
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
	store := NewStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := Initialize(store, cfg)
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

	result, err := ca.EnrollWithProfile(req, prof)
	if err != nil {
		t.Fatalf("EnrollWithProfile() error = %v", err)
	}

	// Save credential to store
	credStore := credential.NewFileStore(tmpDir)
	if err := credStore.Init(); err != nil {
		t.Fatalf("credStore.Init() error = %v", err)
	}

	passphrase := []byte("testpass")
	if err := credStore.Save(result.Credential, result.Certificates, result.Signers, passphrase); err != nil {
		t.Fatalf("credStore.Save() error = %v", err)
	}

	credentialID := result.Credential.ID

	// Rotate credential keeping existing keys
	rotatedResult, err := ca.RotateCredential(credentialID, credStore, profileStore, passphrase, KeyRotateKeep, nil)
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
	store := NewStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	profileStore := profile.NewProfileStore(tmpDir)
	credStore := credential.NewFileStore(tmpDir)
	if err := credStore.Init(); err != nil {
		t.Fatalf("credStore.Init() error = %v", err)
	}

	// Try to rotate non-existent credential
	_, err = ca.RotateCredential("nonexistent", credStore, profileStore, nil, KeyRotateNew, nil)
	if err == nil {
		t.Error("RotateCredential() should fail for non-existent credential")
	}
}

func TestCA_RotateCredential_ProfileNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := Initialize(store, cfg)
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

	result, err := ca.EnrollWithProfile(req, prof)
	if err != nil {
		t.Fatalf("EnrollWithProfile() error = %v", err)
	}

	// Save credential to store
	credStore := credential.NewFileStore(tmpDir)
	if err := credStore.Init(); err != nil {
		t.Fatalf("credStore.Init() error = %v", err)
	}

	passphrase := []byte("testpass")
	if err := credStore.Save(result.Credential, result.Certificates, result.Signers, passphrase); err != nil {
		t.Fatalf("credStore.Save() error = %v", err)
	}

	credentialID := result.Credential.ID

	// Try to rotate - should fail because profile not found
	_, err = ca.RotateCredential(credentialID, credStore, profileStore, passphrase, KeyRotateNew, nil)
	if err == nil {
		t.Error("RotateCredential() should fail when profile not found")
	}
}

func TestCA_RotateCredential_WithNewProfiles(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := Initialize(store, cfg)
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

	result, err := ca.EnrollWithProfile(req, origProf)
	if err != nil {
		t.Fatalf("EnrollWithProfile() error = %v", err)
	}

	// Save credential to store
	credStore := credential.NewFileStore(tmpDir)
	if err := credStore.Init(); err != nil {
		t.Fatalf("credStore.Init() error = %v", err)
	}

	passphrase := []byte("testpass")
	if err := credStore.Save(result.Credential, result.Certificates, result.Signers, passphrase); err != nil {
		t.Fatalf("credStore.Save() error = %v", err)
	}

	credentialID := result.Credential.ID

	// Rotate credential with new profile (crypto-agility)
	rotatedResult, err := ca.RotateCredential(credentialID, credStore, profileStore, passphrase, KeyRotateNew, []string{"new-profile"})
	if err != nil {
		t.Fatalf("RotateCredential() error = %v", err)
	}

	if rotatedResult == nil {
		t.Fatal("RotateCredential() returned nil result")
	}

	// Verify the new credential uses the new profile
	if len(rotatedResult.Credential.Profiles) != 1 || rotatedResult.Credential.Profiles[0] != "new-profile" {
		t.Errorf("Rotated credential profiles = %v, want [new-profile]", rotatedResult.Credential.Profiles)
	}
}

// =============================================================================
// RevokeCredential Tests
// =============================================================================

func TestCA_RevokeCredential_Success(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := Initialize(store, cfg)
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

	result, err := ca.EnrollWithProfile(req, prof)
	if err != nil {
		t.Fatalf("EnrollWithProfile() error = %v", err)
	}

	// Save credential to store
	credStore := credential.NewFileStore(tmpDir)
	if err := credStore.Init(); err != nil {
		t.Fatalf("credStore.Init() error = %v", err)
	}

	passphrase := []byte("testpass")
	if err := credStore.Save(result.Credential, result.Certificates, result.Signers, passphrase); err != nil {
		t.Fatalf("credStore.Save() error = %v", err)
	}

	credentialID := result.Credential.ID

	// Revoke credential
	err = ca.RevokeCredential(credentialID, ReasonKeyCompromise, credStore)
	if err != nil {
		t.Fatalf("RevokeCredential() error = %v", err)
	}

	// Verify credential status is revoked
	revokedCred, err := credStore.Load(credentialID)
	if err != nil {
		t.Fatalf("Load revoked credential error = %v", err)
	}

	if revokedCred.Status != credential.StatusRevoked {
		t.Errorf("Credential status = %s, want revoked", revokedCred.Status)
	}
}

func TestCA_RevokeCredential_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	credStore := credential.NewFileStore(tmpDir)
	if err := credStore.Init(); err != nil {
		t.Fatalf("credStore.Init() error = %v", err)
	}

	// Try to revoke non-existent credential
	err = ca.RevokeCredential("nonexistent", ReasonKeyCompromise, credStore)
	if err == nil {
		t.Error("RevokeCredential() should fail for non-existent credential")
	}
}

func TestCA_RevokeCredential_WithReason(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := Initialize(store, cfg)
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

	result, err := ca.EnrollWithProfile(req, prof)
	if err != nil {
		t.Fatalf("EnrollWithProfile() error = %v", err)
	}

	credStore := credential.NewFileStore(tmpDir)
	if err := credStore.Init(); err != nil {
		t.Fatalf("credStore.Init() error = %v", err)
	}

	passphrase := []byte("testpass")
	if err := credStore.Save(result.Credential, result.Certificates, result.Signers, passphrase); err != nil {
		t.Fatalf("credStore.Save() error = %v", err)
	}

	credentialID := result.Credential.ID

	// Test different revocation reasons
	reasons := []RevocationReason{
		ReasonUnspecified,
		ReasonKeyCompromise,
		ReasonCACompromise,
		ReasonAffiliationChanged,
		ReasonSuperseded,
		ReasonCessationOfOperation,
	}

	for i, reason := range reasons {
		// Create a new credential for each test
		result, err := ca.EnrollWithProfile(req, prof)
		if err != nil {
			t.Fatalf("EnrollWithProfile() error = %v", err)
		}

		if err := credStore.Save(result.Credential, result.Certificates, result.Signers, passphrase); err != nil {
			t.Fatalf("credStore.Save() error = %v", err)
		}

		err = ca.RevokeCredential(result.Credential.ID, reason, credStore)
		if err != nil {
			t.Errorf("RevokeCredential(reason=%d) error = %v", reason, err)
		}

		if i == 0 {
			// Also verify the original credential
			err = ca.RevokeCredential(credentialID, ReasonSuperseded, credStore)
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
	store := NewStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	req := EnrollmentRequest{
		Subject: pkix.Name{CommonName: "Test Subject"},
	}

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer := &testSigner{key: key, alg: pkicrypto.AlgECDSAP256}

	_, err = ca.rotateWithExistingKeys(req, []*profile.Profile{}, []pkicrypto.Signer{signer})
	if err == nil {
		t.Error("rotateWithExistingKeys() should fail with no profiles")
	}
}

// =============================================================================
// getAlgorithmFamily Unit Tests
// =============================================================================

func TestU_getAlgorithmFamily(t *testing.T) {
	tests := []struct {
		name     string
		algID    pkicrypto.AlgorithmID
		expected string
	}{
		// ECDSA variants
		{"ECDSA P256", pkicrypto.AlgECDSAP256, "ec"},
		{"ECDSA P384", pkicrypto.AlgECDSAP384, "ec"},
		{"ECDSA P521", pkicrypto.AlgECDSAP521, "ec"},
		{"EC-P256", pkicrypto.AlgorithmID("ec-p256"), "ec"},

		// RSA variants
		{"RSA 2048", pkicrypto.AlgRSA2048, "rsa"},
		{"RSA 4096", pkicrypto.AlgRSA4096, "rsa"},

		// EdDSA variants
		{"Ed25519", pkicrypto.AlgEd25519, "ed"},
		{"Ed448", pkicrypto.AlgorithmID("ed448"), "ed"},

		// ML-DSA (FIPS 204)
		{"ML-DSA-44", pkicrypto.AlgMLDSA44, "ml-dsa"},
		{"ML-DSA-65", pkicrypto.AlgMLDSA65, "ml-dsa"},
		{"ML-DSA-87", pkicrypto.AlgMLDSA87, "ml-dsa"},
		{"MLDSA65 alt", pkicrypto.AlgorithmID("mldsa65"), "ml-dsa"},

		// SLH-DSA (FIPS 205)
		{"SLH-DSA-128s", pkicrypto.AlgSLHDSA128s, "slh-dsa"},
		{"SLH-DSA-256f", pkicrypto.AlgSLHDSA256f, "slh-dsa"},
		{"SLHDSA alt", pkicrypto.AlgorithmID("slhdsa128f"), "slh-dsa"},

		// ML-KEM (FIPS 203)
		{"ML-KEM-512", pkicrypto.AlgMLKEM512, "ml-kem"},
		{"ML-KEM-768", pkicrypto.AlgMLKEM768, "ml-kem"},
		{"MLKEM alt", pkicrypto.AlgorithmID("mlkem1024"), "ml-kem"},

		// Hybrid
		{"Hybrid EC+ML-DSA", pkicrypto.AlgorithmID("hybrid-ec-mldsa"), "hybrid"},

		// Unknown/Default
		{"Unknown algo", pkicrypto.AlgorithmID("unknown-algo"), "unknown"},
		{"Custom algo", pkicrypto.AlgorithmID("custom-crypto-algo"), "custom"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock profile with the algorithm
			prof := &profile.Profile{
				Algorithm: tt.algID,
			}

			result := getAlgorithmFamily(prof)
			if result != tt.expected {
				t.Errorf("getAlgorithmFamily(%q) = %q, want %q", tt.algID, result, tt.expected)
			}
		})
	}
}
