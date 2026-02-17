package credential

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509/pkix"
	"io"
	"testing"
	"time"

	"github.com/remiblancher/post-quantum-pki/pkg/ca"
	pkicrypto "github.com/remiblancher/post-quantum-pki/pkg/crypto"
	"github.com/remiblancher/post-quantum-pki/pkg/profile"
)

// =============================================================================
// Enrollment Tests
// =============================================================================

func TestCA_Enroll_Simple(t *testing.T) {
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

	result, err := Enroll(caInstance, req, profileStore)
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

	req := EnrollmentRequest{
		Subject:     pkix.Name{CommonName: "Test Subject"},
		ProfileName: "nonexistent",
	}

	_, err = Enroll(caInstance, req, profileStore)
	if err == nil {
		t.Error("Enroll() should fail for non-existent profile")
	}
}

func TestCA_Enroll_NoSigner(t *testing.T) {
	tmpDir := t.TempDir()
	store := ca.NewFileStore(tmpDir)

	cfg := ca.Config{
		CommonName:    "Test Root CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
		Passphrase:    "test",
	}

	_, err := ca.Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Load CA without signer
	caInstance, err := ca.New(store)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	profileStore := profile.NewProfileStore(tmpDir)

	req := EnrollmentRequest{
		Subject:     pkix.Name{CommonName: "Test Subject"},
		ProfileName: "test-simple",
	}

	_, err = Enroll(caInstance, req, profileStore)
	if err == nil {
		t.Error("Enroll() should fail when signer not loaded")
	}
}

func TestCA_EnrollWithProfile_Simple(t *testing.T) {
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
		Subject:  pkix.Name{CommonName: "Test Subject", Organization: []string{"Test Org"}},
		DNSNames: []string{"test.example.com"},
	}

	result, err := EnrollWithProfile(caInstance, req, prof)
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

	// Verify credential is activated (version status should be "active")
	ver := result.Credential.ActiveVersion()
	if ver == nil {
		t.Error("Credential has no active version")
	}
	if result.Credential.GetVersionStatus(result.Credential.Active) != "active" {
		t.Errorf("Credential version status = %s, want active", result.Credential.GetVersionStatus(result.Credential.Active))
	}
}

func TestCA_EnrollWithProfile_NoSigner(t *testing.T) {
	tmpDir := t.TempDir()
	store := ca.NewFileStore(tmpDir)

	cfg := ca.Config{
		CommonName:    "Test Root CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
		Passphrase:    "test",
	}

	_, err := ca.Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	caInstance, err := ca.New(store)
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

	_, err = EnrollWithProfile(caInstance, req, prof)
	if err == nil {
		t.Error("EnrollWithProfile() should fail when signer not loaded")
	}
}

func TestCA_EnrollMulti_SingleProfile(t *testing.T) {
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

	result, err := EnrollMulti(caInstance, req, profiles)
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

	_, err = EnrollMulti(caInstance, req, []*profile.Profile{})
	if err == nil {
		t.Error("EnrollMulti() should fail with no profiles")
	}
}

func TestCA_EnrollMulti_NoSigner(t *testing.T) {
	tmpDir := t.TempDir()
	store := ca.NewFileStore(tmpDir)

	cfg := ca.Config{
		CommonName:    "Test Root CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
		Passphrase:    "test",
	}

	_, err := ca.Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	caInstance, err := ca.New(store)
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

	_, err = EnrollMulti(caInstance, req, profiles)
	if err == nil {
		t.Error("EnrollMulti() should fail when signer not loaded")
	}
}

// =============================================================================
// Helper Function Tests
// =============================================================================

func TestU_Credential_GenerateCredentialID(t *testing.T) {
	// Test with regular common name
	id1 := GenerateCredentialID("Test User")
	if id1 == "" {
		t.Error("GenerateCredentialID() returned empty string")
	}

	// Test with common name that needs cleaning
	id2 := GenerateCredentialID("Test.User@example.com")
	if id2 == "" {
		t.Error("GenerateCredentialID() returned empty string for email")
	}

	// Test with long common name (should be truncated)
	id3 := GenerateCredentialID("VeryLongCommonNameThatExceedsSixteenCharacters")
	if id3 == "" {
		t.Error("GenerateCredentialID() returned empty string for long name")
	}

	// Two calls should generate different IDs (due to random suffix)
	id4 := GenerateCredentialID("Test User")
	if id1 == id4 {
		t.Log("Warning: two calls to generateCredentialID may occasionally produce the same ID (rare)")
	}
}

func TestU_Credential_ParseSerialHex(t *testing.T) {
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
			val, ok := ParseSerialHex(tt.input)
			if ok != tt.wantOK {
				t.Errorf("ParseSerialHex(%s) ok = %v, want %v", tt.input, ok, tt.wantOK)
			}
			if ok && val.Int64() != tt.wantVal {
				t.Errorf("ParseSerialHex(%s) value = %d, want %d", tt.input, val.Int64(), tt.wantVal)
			}
		})
	}
}

func TestU_Credential_GetSignerForAlgorithm(t *testing.T) {
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
	store := ca.NewFileStore(tmpDir)

	cfg := ca.Config{
		CommonName:    "Test Root CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
		Passphrase:    "test",
	}

	_, err := ca.Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	caInstance, err := ca.New(store)
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

	_, err = EnrollWithCompiledProfile(caInstance, req, cp)
	if err == nil {
		t.Error("EnrollWithCompiledProfile() should fail when signer not loaded")
	}
}

func TestCA_EnrollWithCompiledProfile_Simple(t *testing.T) {
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

	cp, err := prof.Compile()
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	req := EnrollmentRequest{
		Subject:  pkix.Name{CommonName: "Test Subject"},
		DNSNames: []string{"test.example.com"},
	}

	result, err := EnrollWithCompiledProfile(caInstance, req, cp)
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

			result := GetProfileAlgoFamily(prof)
			if result != tt.expected {
				t.Errorf("getAlgorithmFamily(%q) = %q, want %q", tt.algID, result, tt.expected)
			}
		})
	}
}

// =============================================================================
// Catalyst Enrollment Tests
// =============================================================================

func TestCA_EnrollWithProfile_Catalyst(t *testing.T) {
	tmpDir := t.TempDir()
	store := ca.NewFileStore(tmpDir)

	// Initialize Hybrid CA (required for Catalyst issuance)
	cfg := ca.HybridCAConfig{
		CommonName:         "Catalyst Test CA",
		Organization:       "Test Org",
		Country:            "US",
		ClassicalAlgorithm: pkicrypto.AlgECDSAP384,
		PQCAlgorithm:       pkicrypto.AlgMLDSA87,
		ValidityYears:      10,
		PathLen:            1,
	}

	caInstance, err := ca.InitializeHybridCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeHybridCA() error = %v", err)
	}

	// Create a Catalyst profile (mode=catalyst, 2 algorithms)
	catalystProfile := &profile.Profile{
		Name:       "catalyst-test",
		Mode:       profile.ModeCatalyst,
		Algorithms: []pkicrypto.AlgorithmID{pkicrypto.AlgECDSAP256, pkicrypto.AlgMLDSA65},
		Validity:   365 * 24 * time.Hour,
		Extensions: &profile.ExtensionsConfig{
			KeyUsage: &profile.KeyUsageConfig{
				Values: []string{"digitalSignature"},
			},
			BasicConstraints: &profile.BasicConstraintsConfig{
				CA: false,
			},
		},
	}

	req := EnrollmentRequest{
		Subject:  pkix.Name{CommonName: "Catalyst Test Subject"},
		DNSNames: []string{"catalyst.example.com"},
	}

	result, err := EnrollWithProfile(caInstance, req, catalystProfile)
	if err != nil {
		t.Fatalf("EnrollWithProfile(Catalyst) error = %v", err)
	}

	if result.Credential == nil {
		t.Error("EnrollWithProfile(Catalyst) result has nil Credential")
	}
	if len(result.Certificates) != 1 {
		t.Errorf("EnrollWithProfile(Catalyst) returned %d certificates, want 1", len(result.Certificates))
	}
	// Catalyst uses 2 keys (classical + PQC)
	if len(result.Signers) != 2 {
		t.Errorf("EnrollWithProfile(Catalyst) returned %d signers, want 2", len(result.Signers))
	}
	if len(result.StorageRefs) != 2 {
		t.Errorf("EnrollWithProfile(Catalyst) returned %d storage refs, want 2", len(result.StorageRefs))
	}
}

func TestCA_EnrollWithProfile_Catalyst_FallsBackToSimple(t *testing.T) {
	// When mode=catalyst but only 1 algorithm, IsCatalyst() returns false
	// and the code falls back to simple issuance
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

	// Profile with mode=catalyst but only 1 algorithm
	// IsCatalyst() will return false, so it falls back to simple issuance
	profileWithOnlyOneAlgo := &profile.Profile{
		Name:       "not-really-catalyst",
		Mode:       profile.ModeCatalyst,
		Algorithms: []pkicrypto.AlgorithmID{pkicrypto.AlgECDSAP256}, // Only 1 algo
		Validity:   365 * 24 * time.Hour,
	}

	req := EnrollmentRequest{
		Subject: pkix.Name{CommonName: "Test Subject"},
	}

	// Should succeed with simple issuance (1 certificate, 1 key)
	result, err := EnrollWithProfile(caInstance, req, profileWithOnlyOneAlgo)
	if err != nil {
		t.Fatalf("EnrollWithProfile() error = %v", err)
	}
	if len(result.Signers) != 1 {
		t.Errorf("Expected 1 signer (simple fallback), got %d", len(result.Signers))
	}
}

func TestCA_EnrollWithCompiledProfile_Catalyst(t *testing.T) {
	tmpDir := t.TempDir()
	store := ca.NewFileStore(tmpDir)

	cfg := ca.HybridCAConfig{
		CommonName:         "Catalyst Test CA",
		ClassicalAlgorithm: pkicrypto.AlgECDSAP384,
		PQCAlgorithm:       pkicrypto.AlgMLDSA87,
		ValidityYears:      10,
		PathLen:            1,
	}

	caInstance, err := ca.InitializeHybridCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeHybridCA() error = %v", err)
	}

	catalystProfile := &profile.Profile{
		Name:       "catalyst-test",
		Mode:       profile.ModeCatalyst,
		Algorithms: []pkicrypto.AlgorithmID{pkicrypto.AlgECDSAP256, pkicrypto.AlgMLDSA65},
		Validity:   365 * 24 * time.Hour,
	}

	cp, err := catalystProfile.Compile()
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	req := EnrollmentRequest{
		Subject:  pkix.Name{CommonName: "Compiled Catalyst Subject"},
		DNSNames: []string{"compiled-catalyst.example.com"},
	}

	result, err := EnrollWithCompiledProfile(caInstance, req, cp)
	if err != nil {
		t.Fatalf("EnrollWithCompiledProfile(Catalyst) error = %v", err)
	}

	if result.Credential == nil {
		t.Error("EnrollWithCompiledProfile(Catalyst) result has nil Credential")
	}
	if len(result.Certificates) != 1 {
		t.Errorf("EnrollWithCompiledProfile(Catalyst) returned %d certificates, want 1", len(result.Certificates))
	}
	if len(result.Signers) != 2 {
		t.Errorf("EnrollWithCompiledProfile(Catalyst) returned %d signers, want 2", len(result.Signers))
	}
}

func TestCA_EnrollWithCompiledProfile_Catalyst_FallsBackToSimple(t *testing.T) {
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

	// Profile with mode=catalyst but only 1 algorithm
	profileWithOnlyOneAlgo := &profile.Profile{
		Name:       "not-really-catalyst",
		Mode:       profile.ModeCatalyst,
		Algorithms: []pkicrypto.AlgorithmID{pkicrypto.AlgECDSAP256},
		Validity:   365 * 24 * time.Hour,
	}

	cp, err := profileWithOnlyOneAlgo.Compile()
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	req := EnrollmentRequest{
		Subject: pkix.Name{CommonName: "Test Subject"},
	}

	// Should succeed with simple issuance
	result, err := EnrollWithCompiledProfile(caInstance, req, cp)
	if err != nil {
		t.Fatalf("EnrollWithCompiledProfile() error = %v", err)
	}
	if len(result.Signers) != 1 {
		t.Errorf("Expected 1 signer (simple fallback), got %d", len(result.Signers))
	}
}

// =============================================================================
// Composite Enrollment Tests
// =============================================================================

func TestCA_EnrollWithProfile_Composite(t *testing.T) {
	tmpDir := t.TempDir()
	store := ca.NewFileStore(tmpDir)

	// Initialize Composite CA (required for Composite issuance)
	cfg := ca.CompositeCAConfig{
		CommonName:         "Composite Test CA",
		Organization:       "Test Org",
		Country:            "US",
		ClassicalAlgorithm: pkicrypto.AlgECDSAP256,
		PQCAlgorithm:       pkicrypto.AlgMLDSA65,
		ValidityYears:      10,
		PathLen:            1,
	}

	caInstance, err := ca.InitializeCompositeCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeCompositeCA() error = %v", err)
	}

	// Create a Composite profile (mode=composite, 2 algorithms)
	compositeProfile := &profile.Profile{
		Name:       "composite-test",
		Mode:       profile.ModeComposite,
		Algorithms: []pkicrypto.AlgorithmID{pkicrypto.AlgECDSAP256, pkicrypto.AlgMLDSA65},
		Validity:   365 * 24 * time.Hour,
		Extensions: &profile.ExtensionsConfig{
			KeyUsage: &profile.KeyUsageConfig{
				Values: []string{"digitalSignature"},
			},
			BasicConstraints: &profile.BasicConstraintsConfig{
				CA: false,
			},
		},
	}

	req := EnrollmentRequest{
		Subject:  pkix.Name{CommonName: "Composite Test Subject"},
		DNSNames: []string{"composite.example.com"},
	}

	result, err := EnrollWithProfile(caInstance, req, compositeProfile)
	if err != nil {
		t.Fatalf("EnrollWithProfile(Composite) error = %v", err)
	}

	if result.Credential == nil {
		t.Error("EnrollWithProfile(Composite) result has nil Credential")
	}
	if len(result.Certificates) != 1 {
		t.Errorf("EnrollWithProfile(Composite) returned %d certificates, want 1", len(result.Certificates))
	}
	// Composite uses 2 keys (classical + PQC)
	if len(result.Signers) != 2 {
		t.Errorf("EnrollWithProfile(Composite) returned %d signers, want 2", len(result.Signers))
	}
	if len(result.StorageRefs) != 2 {
		t.Errorf("EnrollWithProfile(Composite) returned %d storage refs, want 2", len(result.StorageRefs))
	}
}

func TestCA_EnrollWithProfile_Composite_FallsBackToSimple(t *testing.T) {
	// When mode=composite but only 1 algorithm, IsComposite() returns false
	// and the code falls back to simple issuance
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

	// Profile with mode=composite but only 1 algorithm
	profileWithOnlyOneAlgo := &profile.Profile{
		Name:       "not-really-composite",
		Mode:       profile.ModeComposite,
		Algorithms: []pkicrypto.AlgorithmID{pkicrypto.AlgECDSAP256},
		Validity:   365 * 24 * time.Hour,
	}

	req := EnrollmentRequest{
		Subject: pkix.Name{CommonName: "Test Subject"},
	}

	// Should succeed with simple issuance
	result, err := EnrollWithProfile(caInstance, req, profileWithOnlyOneAlgo)
	if err != nil {
		t.Fatalf("EnrollWithProfile() error = %v", err)
	}
	if len(result.Signers) != 1 {
		t.Errorf("Expected 1 signer (simple fallback), got %d", len(result.Signers))
	}
}

func TestCA_EnrollWithCompiledProfile_Composite(t *testing.T) {
	tmpDir := t.TempDir()
	store := ca.NewFileStore(tmpDir)

	cfg := ca.CompositeCAConfig{
		CommonName:         "Composite Test CA",
		ClassicalAlgorithm: pkicrypto.AlgECDSAP256,
		PQCAlgorithm:       pkicrypto.AlgMLDSA65,
		ValidityYears:      10,
		PathLen:            1,
	}

	caInstance, err := ca.InitializeCompositeCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeCompositeCA() error = %v", err)
	}

	compositeProfile := &profile.Profile{
		Name:       "composite-test",
		Mode:       profile.ModeComposite,
		Algorithms: []pkicrypto.AlgorithmID{pkicrypto.AlgECDSAP256, pkicrypto.AlgMLDSA65},
		Validity:   365 * 24 * time.Hour,
	}

	cp, err := compositeProfile.Compile()
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	req := EnrollmentRequest{
		Subject:  pkix.Name{CommonName: "Compiled Composite Subject"},
		DNSNames: []string{"compiled-composite.example.com"},
	}

	result, err := EnrollWithCompiledProfile(caInstance, req, cp)
	if err != nil {
		t.Fatalf("EnrollWithCompiledProfile(Composite) error = %v", err)
	}

	if result.Credential == nil {
		t.Error("EnrollWithCompiledProfile(Composite) result has nil Credential")
	}
	if len(result.Certificates) != 1 {
		t.Errorf("EnrollWithCompiledProfile(Composite) returned %d certificates, want 1", len(result.Certificates))
	}
	if len(result.Signers) != 2 {
		t.Errorf("EnrollWithCompiledProfile(Composite) returned %d signers, want 2", len(result.Signers))
	}
}

func TestCA_EnrollWithCompiledProfile_Composite_FallsBackToSimple(t *testing.T) {
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

	profileWithOnlyOneAlgo := &profile.Profile{
		Name:       "not-really-composite",
		Mode:       profile.ModeComposite,
		Algorithms: []pkicrypto.AlgorithmID{pkicrypto.AlgECDSAP256},
		Validity:   365 * 24 * time.Hour,
	}

	cp, err := profileWithOnlyOneAlgo.Compile()
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	req := EnrollmentRequest{
		Subject: pkix.Name{CommonName: "Test Subject"},
	}

	// Should succeed with simple issuance
	result, err := EnrollWithCompiledProfile(caInstance, req, cp)
	if err != nil {
		t.Fatalf("EnrollWithCompiledProfile() error = %v", err)
	}
	if len(result.Signers) != 1 {
		t.Errorf("Expected 1 signer (simple fallback), got %d", len(result.Signers))
	}
}

// =============================================================================
// EnrollMultiProfileVersioned Tests
// =============================================================================

func TestCA_EnrollMultiProfileVersioned_Simple(t *testing.T) {
	tmpDir := t.TempDir()
	caStore := ca.NewFileStore(tmpDir + "/ca")

	cfg := ca.Config{
		CommonName:    "Test Root CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	caInstance, err := ca.Initialize(caStore, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	credStore := NewFileStore(tmpDir + "/credentials")

	profiles := []*profile.Profile{
		{
			Name:      "signature",
			Algorithm: pkicrypto.AlgECDSAP256,
			Validity:  365 * 24 * time.Hour,
		},
	}

	req := MultiProfileEnrollRequest{
		Subject:         pkix.Name{CommonName: "Test Subject"},
		Profiles:        profiles,
		DNSNames:        []string{"test.example.com"},
		CredentialStore: credStore,
	}

	result, err := EnrollMultiProfileVersioned(caInstance, req)
	if err != nil {
		t.Fatalf("EnrollMultiProfileVersioned() error = %v", err)
	}

	if result.Credential == nil {
		t.Error("EnrollMultiProfileVersioned() result has nil Credential")
	}
	if len(result.Certificates) != 1 {
		t.Errorf("EnrollMultiProfileVersioned() returned %d certificates, want 1", len(result.Certificates))
	}
	if len(result.Signers) != 1 {
		t.Errorf("EnrollMultiProfileVersioned() returned %d signers, want 1", len(result.Signers))
	}
}

func TestCA_EnrollMultiProfileVersioned_NoSigner(t *testing.T) {
	tmpDir := t.TempDir()
	caStore := ca.NewFileStore(tmpDir + "/ca")

	cfg := ca.Config{
		CommonName:    "Test Root CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
		Passphrase:    "test",
	}

	_, err := ca.Initialize(caStore, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	caInstance, err := ca.New(caStore)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	credStore := NewFileStore(tmpDir + "/credentials")

	profiles := []*profile.Profile{
		{
			Name:      "signature",
			Algorithm: pkicrypto.AlgECDSAP256,
			Validity:  365 * 24 * time.Hour,
		},
	}

	req := MultiProfileEnrollRequest{
		Subject:         pkix.Name{CommonName: "Test Subject"},
		Profiles:        profiles,
		CredentialStore: credStore,
	}

	_, err = EnrollMultiProfileVersioned(caInstance, req)
	if err == nil {
		t.Error("EnrollMultiProfileVersioned() should fail when signer not loaded")
	}
}

func TestCA_EnrollMultiProfileVersioned_NoProfiles(t *testing.T) {
	tmpDir := t.TempDir()
	caStore := ca.NewFileStore(tmpDir + "/ca")

	cfg := ca.Config{
		CommonName:    "Test Root CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	caInstance, err := ca.Initialize(caStore, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	credStore := NewFileStore(tmpDir + "/credentials")

	req := MultiProfileEnrollRequest{
		Subject:         pkix.Name{CommonName: "Test Subject"},
		Profiles:        []*profile.Profile{},
		CredentialStore: credStore,
	}

	_, err = EnrollMultiProfileVersioned(caInstance, req)
	if err == nil {
		t.Error("EnrollMultiProfileVersioned() should fail with no profiles")
	}
}

func TestCA_EnrollMultiProfileVersioned_NoStore(t *testing.T) {
	tmpDir := t.TempDir()
	caStore := ca.NewFileStore(tmpDir + "/ca")

	cfg := ca.Config{
		CommonName:    "Test Root CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	caInstance, err := ca.Initialize(caStore, cfg)
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

	req := MultiProfileEnrollRequest{
		Subject:         pkix.Name{CommonName: "Test Subject"},
		Profiles:        profiles,
		CredentialStore: nil, // No store
	}

	_, err = EnrollMultiProfileVersioned(caInstance, req)
	if err == nil {
		t.Error("EnrollMultiProfileVersioned() should fail when no credential store provided")
	}
}

func TestCA_EnrollMultiProfileVersioned_Catalyst(t *testing.T) {
	tmpDir := t.TempDir()
	caStore := ca.NewFileStore(tmpDir + "/ca")

	cfg := ca.HybridCAConfig{
		CommonName:         "Catalyst Test CA",
		ClassicalAlgorithm: pkicrypto.AlgECDSAP384,
		PQCAlgorithm:       pkicrypto.AlgMLDSA87,
		ValidityYears:      10,
		PathLen:            1,
	}

	caInstance, err := ca.InitializeHybridCA(caStore, cfg)
	if err != nil {
		t.Fatalf("InitializeHybridCA() error = %v", err)
	}

	credStore := NewFileStore(tmpDir + "/credentials")

	profiles := []*profile.Profile{
		{
			Name:       "catalyst-signature",
			Mode:       profile.ModeCatalyst,
			Algorithms: []pkicrypto.AlgorithmID{pkicrypto.AlgECDSAP256, pkicrypto.AlgMLDSA65},
			Validity:   365 * 24 * time.Hour,
		},
	}

	req := MultiProfileEnrollRequest{
		Subject:         pkix.Name{CommonName: "Catalyst Subject"},
		Profiles:        profiles,
		DNSNames:        []string{"catalyst.example.com"},
		CredentialStore: credStore,
	}

	result, err := EnrollMultiProfileVersioned(caInstance, req)
	if err != nil {
		t.Fatalf("EnrollMultiProfileVersioned(Catalyst) error = %v", err)
	}

	if result.Credential == nil {
		t.Error("EnrollMultiProfileVersioned(Catalyst) result has nil Credential")
	}
	if len(result.Certificates) != 1 {
		t.Errorf("EnrollMultiProfileVersioned(Catalyst) returned %d certificates, want 1", len(result.Certificates))
	}
	// Catalyst uses 2 keys
	if len(result.Signers) != 2 {
		t.Errorf("EnrollMultiProfileVersioned(Catalyst) returned %d signers, want 2", len(result.Signers))
	}
}

func TestCA_EnrollMultiProfileVersioned_Composite(t *testing.T) {
	tmpDir := t.TempDir()
	caStore := ca.NewFileStore(tmpDir + "/ca")

	cfg := ca.CompositeCAConfig{
		CommonName:         "Composite Test CA",
		ClassicalAlgorithm: pkicrypto.AlgECDSAP256,
		PQCAlgorithm:       pkicrypto.AlgMLDSA65,
		ValidityYears:      10,
		PathLen:            1,
	}

	caInstance, err := ca.InitializeCompositeCA(caStore, cfg)
	if err != nil {
		t.Fatalf("InitializeCompositeCA() error = %v", err)
	}

	credStore := NewFileStore(tmpDir + "/credentials")

	profiles := []*profile.Profile{
		{
			Name:       "composite-signature",
			Mode:       profile.ModeComposite,
			Algorithms: []pkicrypto.AlgorithmID{pkicrypto.AlgECDSAP256, pkicrypto.AlgMLDSA65},
			Validity:   365 * 24 * time.Hour,
		},
	}

	req := MultiProfileEnrollRequest{
		Subject:         pkix.Name{CommonName: "Composite Subject"},
		Profiles:        profiles,
		DNSNames:        []string{"composite.example.com"},
		CredentialStore: credStore,
	}

	result, err := EnrollMultiProfileVersioned(caInstance, req)
	if err != nil {
		t.Fatalf("EnrollMultiProfileVersioned(Composite) error = %v", err)
	}

	if result.Credential == nil {
		t.Error("EnrollMultiProfileVersioned(Composite) result has nil Credential")
	}
	if len(result.Certificates) != 1 {
		t.Errorf("EnrollMultiProfileVersioned(Composite) returned %d certificates, want 1", len(result.Certificates))
	}
	// Composite uses 2 keys
	if len(result.Signers) != 2 {
		t.Errorf("EnrollMultiProfileVersioned(Composite) returned %d signers, want 2", len(result.Signers))
	}
}

// =============================================================================
// EnrollMulti with Catalyst and Composite Tests
// =============================================================================

func TestCA_EnrollMulti_Catalyst(t *testing.T) {
	tmpDir := t.TempDir()
	store := ca.NewFileStore(tmpDir)

	cfg := ca.HybridCAConfig{
		CommonName:         "Catalyst Test CA",
		ClassicalAlgorithm: pkicrypto.AlgECDSAP384,
		PQCAlgorithm:       pkicrypto.AlgMLDSA87,
		ValidityYears:      10,
		PathLen:            1,
	}

	caInstance, err := ca.InitializeHybridCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeHybridCA() error = %v", err)
	}

	profiles := []*profile.Profile{
		{
			Name:       "catalyst-signature",
			Mode:       profile.ModeCatalyst,
			Algorithms: []pkicrypto.AlgorithmID{pkicrypto.AlgECDSAP256, pkicrypto.AlgMLDSA65},
			Validity:   365 * 24 * time.Hour,
		},
	}

	req := EnrollmentRequest{
		Subject:  pkix.Name{CommonName: "Catalyst Subject"},
		DNSNames: []string{"catalyst.example.com"},
	}

	result, err := EnrollMulti(caInstance, req, profiles)
	if err != nil {
		t.Fatalf("EnrollMulti(Catalyst) error = %v", err)
	}

	if result.Credential == nil {
		t.Error("EnrollMulti(Catalyst) result has nil Credential")
	}
	if len(result.Certificates) != 1 {
		t.Errorf("EnrollMulti(Catalyst) returned %d certificates, want 1", len(result.Certificates))
	}
	if len(result.Signers) != 2 {
		t.Errorf("EnrollMulti(Catalyst) returned %d signers, want 2 (classical + PQC)", len(result.Signers))
	}
}

func TestCA_EnrollMulti_Composite(t *testing.T) {
	tmpDir := t.TempDir()
	store := ca.NewFileStore(tmpDir)

	cfg := ca.CompositeCAConfig{
		CommonName:         "Composite Test CA",
		ClassicalAlgorithm: pkicrypto.AlgECDSAP256,
		PQCAlgorithm:       pkicrypto.AlgMLDSA65,
		ValidityYears:      10,
		PathLen:            1,
	}

	caInstance, err := ca.InitializeCompositeCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeCompositeCA() error = %v", err)
	}

	profiles := []*profile.Profile{
		{
			Name:       "composite-signature",
			Mode:       profile.ModeComposite,
			Algorithms: []pkicrypto.AlgorithmID{pkicrypto.AlgECDSAP256, pkicrypto.AlgMLDSA65},
			Validity:   365 * 24 * time.Hour,
		},
	}

	req := EnrollmentRequest{
		Subject:  pkix.Name{CommonName: "Composite Subject"},
		DNSNames: []string{"composite.example.com"},
	}

	result, err := EnrollMulti(caInstance, req, profiles)
	if err != nil {
		t.Fatalf("EnrollMulti(Composite) error = %v", err)
	}

	if result.Credential == nil {
		t.Error("EnrollMulti(Composite) result has nil Credential")
	}
	if len(result.Certificates) != 1 {
		t.Errorf("EnrollMulti(Composite) returned %d certificates, want 1", len(result.Certificates))
	}
	if len(result.Signers) != 2 {
		t.Errorf("EnrollMulti(Composite) returned %d signers, want 2 (classical + PQC)", len(result.Signers))
	}
}
