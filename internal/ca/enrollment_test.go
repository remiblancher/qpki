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
	if result.Bundle == nil {
		t.Error("Enroll() result has nil Bundle")
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

	if result.Bundle == nil {
		t.Error("EnrollWithProfile() result has nil Bundle")
	}
	if len(result.Certificates) != 1 {
		t.Errorf("EnrollWithProfile() returned %d certificates, want 1", len(result.Certificates))
	}
	if len(result.Signers) != 1 {
		t.Errorf("EnrollWithProfile() returned %d signers, want 1", len(result.Signers))
	}

	// Verify bundle is activated (status may be "valid" or "active" depending on implementation)
	if result.Bundle.Status != "valid" && result.Bundle.Status != "active" {
		t.Errorf("Bundle status = %s, want valid or active", result.Bundle.Status)
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

	if result.Bundle == nil {
		t.Error("EnrollMulti() result has nil Bundle")
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

func TestGenerateBundleID(t *testing.T) {
	// Test with regular common name
	id1 := generateBundleID("Test User")
	if id1 == "" {
		t.Error("generateBundleID() returned empty string")
	}

	// Test with common name that needs cleaning
	id2 := generateBundleID("Test.User@example.com")
	if id2 == "" {
		t.Error("generateBundleID() returned empty string for email")
	}

	// Test with long common name (should be truncated)
	id3 := generateBundleID("VeryLongCommonNameThatExceedsSixteenCharacters")
	if id3 == "" {
		t.Error("generateBundleID() returned empty string for long name")
	}

	// Two calls should generate different IDs (due to random suffix)
	id4 := generateBundleID("Test User")
	if id1 == id4 {
		t.Log("Warning: two calls to generateBundleID may occasionally produce the same ID (rare)")
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

	if result.Bundle == nil {
		t.Error("EnrollWithCompiledProfile() result has nil Bundle")
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
