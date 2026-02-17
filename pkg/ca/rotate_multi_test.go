package ca

import (
	"context"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	pkicrypto "github.com/remiblancher/post-quantum-pki/pkg/crypto"
	"github.com/remiblancher/post-quantum-pki/pkg/profile"
)

// =============================================================================
// MultiProfileRotateRequest Tests
// =============================================================================

func TestU_CA_MultiProfileRotateRequest_Fields(t *testing.T) {
	profiles := []*profile.Profile{
		{Name: "profile1", Algorithm: pkicrypto.AlgECDSAP256},
	}

	req := MultiProfileRotateRequest{
		CADir:      "/test/ca",
		Profiles:   profiles,
		Passphrase: "testpass",
		CrossSign:  true,
		DryRun:     true,
	}

	if req.CADir != "/test/ca" {
		t.Errorf("CADir = %s, want /test/ca", req.CADir)
	}
	if len(req.Profiles) != 1 {
		t.Errorf("Profiles length = %d, want 1", len(req.Profiles))
	}
	if req.Passphrase != "testpass" {
		t.Errorf("Passphrase = %s, want testpass", req.Passphrase)
	}
	if !req.CrossSign {
		t.Error("CrossSign should be true")
	}
	if !req.DryRun {
		t.Error("DryRun should be true")
	}
}

// =============================================================================
// MultiProfileRotatePlan Tests
// =============================================================================

func TestU_CA_MultiProfileRotatePlan_Fields(t *testing.T) {
	plan := &MultiProfileRotatePlan{
		CurrentVersion: "v1",
		NewVersion:     "v2",
		Profiles: []ProfileRotatePlan{
			{
				ProfileName:     "ecdsa-profile",
				Algorithm:       "ecdsa-p256",
				AlgorithmFamily: "ec",
				WillCrossSign:   true,
				CrossSignReason: "enabled",
			},
		},
		Steps: []string{"step1", "step2"},
	}

	if plan.CurrentVersion != "v1" {
		t.Errorf("CurrentVersion = %s, want v1", plan.CurrentVersion)
	}
	if plan.NewVersion != "v2" {
		t.Errorf("NewVersion = %s, want v2", plan.NewVersion)
	}
	if len(plan.Profiles) != 1 {
		t.Errorf("Profiles length = %d, want 1", len(plan.Profiles))
	}
	if plan.Profiles[0].ProfileName != "ecdsa-profile" {
		t.Errorf("ProfileName = %s, want ecdsa-profile", plan.Profiles[0].ProfileName)
	}
	if len(plan.Steps) != 2 {
		t.Errorf("Steps length = %d, want 2", len(plan.Steps))
	}
}

// =============================================================================
// ProfileRotatePlan Tests
// =============================================================================

func TestU_CA_ProfileRotatePlan_Fields(t *testing.T) {
	plan := ProfileRotatePlan{
		ProfileName:     "test-profile",
		Algorithm:       "ml-dsa-65",
		AlgorithmFamily: "ml-dsa",
		WillCrossSign:   true,
		CrossSignReason: "enabled",
	}

	if plan.ProfileName != "test-profile" {
		t.Errorf("ProfileName = %s, want test-profile", plan.ProfileName)
	}
	if plan.Algorithm != "ml-dsa-65" {
		t.Errorf("Algorithm = %s, want ml-dsa-65", plan.Algorithm)
	}
	if plan.AlgorithmFamily != "ml-dsa" {
		t.Errorf("AlgorithmFamily = %s, want ml-dsa", plan.AlgorithmFamily)
	}
	if !plan.WillCrossSign {
		t.Error("WillCrossSign should be true")
	}
	if plan.CrossSignReason != "enabled" {
		t.Errorf("CrossSignReason = %s, want enabled", plan.CrossSignReason)
	}
}

// =============================================================================
// MultiProfileRotateResult Tests
// =============================================================================

func TestU_CA_MultiProfileRotateResult_Fields(t *testing.T) {
	plan := &MultiProfileRotatePlan{
		NewVersion: "v2",
	}

	result := &MultiProfileRotateResult{
		Plan:             plan,
		Version:          nil,
		Certificates:     nil,
		CrossSignedCerts: nil,
	}

	if result.Plan != plan {
		t.Error("Plan should match")
	}
	if result.Version != nil {
		t.Error("Version should be nil")
	}
}

// =============================================================================
// RotateCAMultiProfile Tests
// =============================================================================

func TestU_CA_RotateCAMultiProfile_NoProfiles_Error(t *testing.T) {
	tmpDir := t.TempDir()

	req := MultiProfileRotateRequest{
		CADir:    tmpDir,
		Profiles: nil,
	}

	_, err := RotateCAMultiProfile(req)
	if err == nil {
		t.Error("RotateCAMultiProfile() should fail with no profiles")
	}
}

func TestU_CA_RotateCAMultiProfile_EmptyProfiles_Error(t *testing.T) {
	tmpDir := t.TempDir()

	req := MultiProfileRotateRequest{
		CADir:    tmpDir,
		Profiles: []*profile.Profile{},
	}

	_, err := RotateCAMultiProfile(req)
	if err == nil {
		t.Error("RotateCAMultiProfile() should fail with empty profiles")
	}
}

func TestU_CA_RotateCAMultiProfile_CANotFound_Error(t *testing.T) {
	tmpDir := t.TempDir()

	req := MultiProfileRotateRequest{
		CADir: tmpDir,
		Profiles: []*profile.Profile{
			{Name: "test-profile", Algorithm: pkicrypto.AlgECDSAP256},
		},
	}

	_, err := RotateCAMultiProfile(req)
	if err == nil {
		t.Error("RotateCAMultiProfile() should fail when CA not found")
	}
}

// setupVersionedCA creates a versioned CA for testing.
func setupVersionedCA(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize CA
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

	// Create CAInfo to make it versioned
	info := NewCAInfo(Subject{CommonName: "Test Root CA"})
	info.SetBasePath(tmpDir)
	info.CreateInitialVersion([]string{"default"}, []string{"ecdsa-p256"})

	if err := info.Save(); err != nil {
		t.Fatalf("SaveCAInfo() error = %v", err)
	}

	// Verify certificate was created
	if ca.Certificate() == nil {
		t.Fatal("CA certificate should not be nil")
	}

	return tmpDir
}

func TestU_CA_RotateCAMultiProfile_DryRun_SingleProfile(t *testing.T) {
	tmpDir := setupVersionedCA(t)

	// Create profiles
	ecProfile := &profile.Profile{
		Name:      "ec-profile",
		Algorithm: pkicrypto.AlgECDSAP384,
		Validity:  10 * 365 * 24 * time.Hour,
	}

	req := MultiProfileRotateRequest{
		CADir:    tmpDir,
		Profiles: []*profile.Profile{ecProfile},
		DryRun:   true,
	}

	result, err := RotateCAMultiProfile(req)
	if err != nil {
		t.Fatalf("RotateCAMultiProfile(DryRun) error = %v", err)
	}

	if result == nil {
		t.Fatal("RotateCAMultiProfile(DryRun) returned nil result")
	}

	if result.Plan == nil {
		t.Fatal("RotateCAMultiProfile(DryRun) result has nil Plan")
	}

	// DryRun should not create new version
	if result.Version != nil {
		t.Error("RotateCAMultiProfile(DryRun) should not create version")
	}

	// Plan should have one profile
	if len(result.Plan.Profiles) != 1 {
		t.Errorf("Plan.Profiles length = %d, want 1", len(result.Plan.Profiles))
	}

	// Plan should have steps
	if len(result.Plan.Steps) == 0 {
		t.Error("RotateCAMultiProfile(DryRun) plan should have steps")
	}
}

func TestU_CA_RotateCAMultiProfile_DryRun_MultipleProfiles(t *testing.T) {
	tmpDir := setupVersionedCA(t)

	// Create multiple profiles
	profiles := []*profile.Profile{
		{
			Name:      "ec-profile",
			Algorithm: pkicrypto.AlgECDSAP384,
			Validity:  10 * 365 * 24 * time.Hour,
		},
		{
			Name:      "pqc-profile",
			Algorithm: pkicrypto.AlgMLDSA65,
			Validity:  10 * 365 * 24 * time.Hour,
		},
	}

	req := MultiProfileRotateRequest{
		CADir:    tmpDir,
		Profiles: profiles,
		DryRun:   true,
	}

	result, err := RotateCAMultiProfile(req)
	if err != nil {
		t.Fatalf("RotateCAMultiProfile(DryRun) error = %v", err)
	}

	if result == nil {
		t.Fatal("RotateCAMultiProfile(DryRun) returned nil result")
	}

	// Plan should have two profiles
	if len(result.Plan.Profiles) != 2 {
		t.Errorf("Plan.Profiles length = %d, want 2", len(result.Plan.Profiles))
	}

	// Verify profile details
	foundEC := false
	foundPQC := false
	for _, p := range result.Plan.Profiles {
		if p.ProfileName == "ec-profile" {
			foundEC = true
			if p.AlgorithmFamily != "ec" {
				t.Errorf("ec-profile AlgorithmFamily = %s, want ec", p.AlgorithmFamily)
			}
		}
		if p.ProfileName == "pqc-profile" {
			foundPQC = true
			if p.AlgorithmFamily != "ml-dsa" {
				t.Errorf("pqc-profile AlgorithmFamily = %s, want ml-dsa", p.AlgorithmFamily)
			}
		}
	}

	if !foundEC {
		t.Error("ec-profile not found in plan")
	}
	if !foundPQC {
		t.Error("pqc-profile not found in plan")
	}
}

func TestU_CA_RotateCAMultiProfile_DryRun_WithCrossSign(t *testing.T) {
	tmpDir := setupVersionedCA(t)

	// Create profile with same algorithm family
	ecProfile := &profile.Profile{
		Name:      "ec-profile",
		Algorithm: pkicrypto.AlgECDSAP384,
		Validity:  10 * 365 * 24 * time.Hour,
	}

	req := MultiProfileRotateRequest{
		CADir:     tmpDir,
		Profiles:  []*profile.Profile{ecProfile},
		CrossSign: true,
		DryRun:    true,
	}

	result, err := RotateCAMultiProfile(req)
	if err != nil {
		t.Fatalf("RotateCAMultiProfile(DryRun, CrossSign) error = %v", err)
	}

	if result == nil || result.Plan == nil {
		t.Fatal("RotateCAMultiProfile(DryRun, CrossSign) returned nil result or plan")
	}

	// Plan should indicate cross-signing
	if len(result.Plan.Profiles) > 0 {
		// CrossSign reason should be set
		if result.Plan.Profiles[0].CrossSignReason == "" {
			t.Error("CrossSignReason should not be empty")
		}
	}
}

// =============================================================================
// buildMultiProfileRotationSteps Tests
// =============================================================================

func TestU_CA_BuildMultiProfileRotationSteps_SingleProfile(t *testing.T) {
	profiles := []ProfileRotatePlan{
		{
			ProfileName:     "ec-profile",
			AlgorithmFamily: "ec",
			WillCrossSign:   false,
		},
	}

	steps := buildMultiProfileRotationSteps("v2", profiles)

	if len(steps) < 3 {
		t.Errorf("buildMultiProfileRotationSteps() returned %d steps, want at least 3", len(steps))
	}

	// Should contain version directory creation
	foundVersionDir := false
	for _, step := range steps {
		if step == "Create new version directory: versions/v2" {
			foundVersionDir = true
			break
		}
	}
	if !foundVersionDir {
		t.Error("Steps should contain version directory creation")
	}
}

func TestU_CA_BuildMultiProfileRotationSteps_MultipleProfiles(t *testing.T) {
	profiles := []ProfileRotatePlan{
		{
			ProfileName:     "ec-profile",
			AlgorithmFamily: "ec",
			WillCrossSign:   false,
		},
		{
			ProfileName:     "pqc-profile",
			AlgorithmFamily: "ml-dsa",
			WillCrossSign:   true,
		},
	}

	steps := buildMultiProfileRotationSteps("v2", profiles)

	// Should have more steps with multiple profiles
	if len(steps) < 5 {
		t.Errorf("buildMultiProfileRotationSteps() returned %d steps, want at least 5", len(steps))
	}

	// Should contain cross-sign step for pqc-profile
	foundCrossSign := false
	for _, step := range steps {
		if step == "  - Cross-sign ml-dsa certificate with current CA" {
			foundCrossSign = true
			break
		}
	}
	if !foundCrossSign {
		t.Error("Steps should contain cross-sign step for ml-dsa")
	}
}

func TestU_CA_BuildMultiProfileRotationSteps_AllCrossSign(t *testing.T) {
	profiles := []ProfileRotatePlan{
		{
			ProfileName:     "ec-profile",
			AlgorithmFamily: "ec",
			WillCrossSign:   true,
		},
		{
			ProfileName:     "pqc-profile",
			AlgorithmFamily: "ml-dsa",
			WillCrossSign:   true,
		},
	}

	steps := buildMultiProfileRotationSteps("v3", profiles)

	// Count cross-sign steps
	crossSignCount := 0
	for _, step := range steps {
		if step == "  - Cross-sign ec certificate with current CA" ||
			step == "  - Cross-sign ml-dsa certificate with current CA" {
			crossSignCount++
		}
	}

	if crossSignCount != 2 {
		t.Errorf("Expected 2 cross-sign steps, got %d", crossSignCount)
	}
}

// =============================================================================
// RotateCAMultiProfile Execute Tests (non-DryRun)
// =============================================================================

func TestU_CA_RotateCAMultiProfile_Execute_SingleProfile(t *testing.T) {
	tmpDir := setupVersionedCA(t)

	// Create profile
	ecProfile := &profile.Profile{
		Name:      "ec-profile",
		Algorithm: pkicrypto.AlgECDSAP384,
		Validity:  10 * 365 * 24 * time.Hour,
	}

	req := MultiProfileRotateRequest{
		CADir:    tmpDir,
		Profiles: []*profile.Profile{ecProfile},
		DryRun:   false, // Execute
	}

	result, err := RotateCAMultiProfile(req)
	if err != nil {
		t.Fatalf("RotateCAMultiProfile(Execute) error = %v", err)
	}

	if result == nil {
		t.Fatal("RotateCAMultiProfile(Execute) returned nil result")
	}

	// Should have created version
	if result.Version == nil {
		t.Error("RotateCAMultiProfile(Execute) should create version")
	}

	// Should have certificate
	if len(result.Certificates) == 0 {
		t.Error("RotateCAMultiProfile(Execute) should create certificates")
	}
}

func TestU_CA_RotateCAMultiProfile_Execute_PQCProfile(t *testing.T) {
	tmpDir := setupVersionedCA(t)

	// Create PQC profile
	pqcProfile := &profile.Profile{
		Name:      "pqc-profile",
		Algorithm: pkicrypto.AlgMLDSA65,
		Validity:  10 * 365 * 24 * time.Hour,
	}

	req := MultiProfileRotateRequest{
		CADir:    tmpDir,
		Profiles: []*profile.Profile{pqcProfile},
		DryRun:   false,
	}

	result, err := RotateCAMultiProfile(req)
	if err != nil {
		t.Fatalf("RotateCAMultiProfile(Execute, PQC) error = %v", err)
	}

	if result == nil {
		t.Fatal("RotateCAMultiProfile(Execute, PQC) returned nil result")
	}

	// Should have created version
	if result.Version == nil {
		t.Error("RotateCAMultiProfile(Execute, PQC) should create version")
	}

	// Should have PQC certificate
	if _, ok := result.Certificates["ml-dsa"]; !ok {
		t.Error("RotateCAMultiProfile(Execute, PQC) should create ml-dsa certificate")
	}
}

// =============================================================================
// initializeCatalystCA Tests
// =============================================================================

func TestU_CA_InitializeCatalystCA(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a Catalyst profile (classical + PQC)
	prof := &profile.Profile{
		Name: "catalyst-profile",
		Algorithms: []pkicrypto.AlgorithmID{
			pkicrypto.AlgECDSAP256, // Classical
			pkicrypto.AlgMLDSA65,   // PQC
		},
		Validity: 10 * 365 * 24 * time.Hour,
	}

	profileDir := filepath.Join(tmpDir, "profile")
	rootDir := filepath.Join(tmpDir, "root")
	profileStore := NewFileStore(profileDir)
	rootStore := NewFileStore(rootDir)

	// Initialize stores
	if err := profileStore.Init(context.Background()); err != nil {
		t.Fatalf("profileStore.Init() error = %v", err)
	}
	if err := rootStore.Init(context.Background()); err != nil {
		t.Fatalf("rootStore.Init() error = %v", err)
	}

	ca, err := initializeCatalystCA(prof, "Test Catalyst CA", 10, "", profileStore, rootStore)
	if err != nil {
		t.Fatalf("initializeCatalystCA() error = %v", err)
	}

	if ca == nil {
		t.Fatal("initializeCatalystCA() returned nil CA")
	}

	cert := ca.Certificate()
	if cert == nil {
		t.Fatal("CA certificate should not be nil")
	}
	if cert.Subject.CommonName != "Test Catalyst CA" {
		t.Errorf("CommonName = %q, want %q", cert.Subject.CommonName, "Test Catalyst CA")
	}
	if !cert.IsCA {
		t.Error("certificate should be CA")
	}
}

func TestU_CA_InitializeCatalystCA_WithPassphrase(t *testing.T) {
	tmpDir := t.TempDir()

	prof := &profile.Profile{
		Name: "catalyst-profile",
		Algorithms: []pkicrypto.AlgorithmID{
			pkicrypto.AlgECDSAP384, // Classical
			pkicrypto.AlgMLDSA44,   // PQC
		},
		Validity: 5 * 365 * 24 * time.Hour,
	}

	profileDir := filepath.Join(tmpDir, "profile")
	rootDir := filepath.Join(tmpDir, "root")
	profileStore := NewFileStore(profileDir)
	rootStore := NewFileStore(rootDir)

	// Initialize stores
	if err := profileStore.Init(context.Background()); err != nil {
		t.Fatalf("profileStore.Init() error = %v", err)
	}
	if err := rootStore.Init(context.Background()); err != nil {
		t.Fatalf("rootStore.Init() error = %v", err)
	}

	ca, err := initializeCatalystCA(prof, "Test Catalyst CA With Passphrase", 5, "test-passphrase", profileStore, rootStore)
	if err != nil {
		t.Fatalf("initializeCatalystCA() error = %v", err)
	}

	if ca == nil {
		t.Fatal("initializeCatalystCA() returned nil CA")
	}

	cert := ca.Certificate()
	if cert.Subject.CommonName != "Test Catalyst CA With Passphrase" {
		t.Errorf("CommonName = %q, want %q", cert.Subject.CommonName, "Test Catalyst CA With Passphrase")
	}
}

// =============================================================================
// initializeCompositeCA (rotate_multi.go) Tests
// =============================================================================

func TestU_CA_RotateMulti_InitializeCompositeCA(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a Composite profile using supported combination: ECDSA-P256 + ML-DSA-65
	prof := &profile.Profile{
		Name: "composite-profile",
		Algorithms: []pkicrypto.AlgorithmID{
			pkicrypto.AlgECDSAP256, // Classical
			pkicrypto.AlgMLDSA65,   // PQC (MLDSA65-ECDSA-P256-SHA512 is supported)
		},
		Validity: 10 * 365 * 24 * time.Hour,
	}

	profileDir := filepath.Join(tmpDir, "profile")
	rootDir := filepath.Join(tmpDir, "root")
	profileStore := NewFileStore(profileDir)
	rootStore := NewFileStore(rootDir)

	// Initialize stores
	if err := profileStore.Init(context.Background()); err != nil {
		t.Fatalf("profileStore.Init() error = %v", err)
	}
	if err := rootStore.Init(context.Background()); err != nil {
		t.Fatalf("rootStore.Init() error = %v", err)
	}

	ca, err := initializeCompositeCA(prof, "Test Composite CA", 10, "", profileStore, rootStore)
	if err != nil {
		t.Fatalf("initializeCompositeCA() error = %v", err)
	}

	if ca == nil {
		t.Fatal("initializeCompositeCA() returned nil CA")
	}

	cert := ca.Certificate()
	if cert == nil {
		t.Fatal("CA certificate should not be nil")
	}
	if cert.Subject.CommonName != "Test Composite CA" {
		t.Errorf("CommonName = %q, want %q", cert.Subject.CommonName, "Test Composite CA")
	}
	if !cert.IsCA {
		t.Error("certificate should be CA")
	}
}

func TestU_CA_RotateMulti_InitializeCompositeCA_WithPassphrase(t *testing.T) {
	tmpDir := t.TempDir()

	// Use supported combination: ECDSA-P384 + ML-DSA-65 (MLDSA65-ECDSA-P384-SHA512)
	prof := &profile.Profile{
		Name: "composite-profile",
		Algorithms: []pkicrypto.AlgorithmID{
			pkicrypto.AlgECDSAP384, // Classical
			pkicrypto.AlgMLDSA65,   // PQC
		},
		Validity: 5 * 365 * 24 * time.Hour,
	}

	profileDir := filepath.Join(tmpDir, "profile")
	rootDir := filepath.Join(tmpDir, "root")
	profileStore := NewFileStore(profileDir)
	rootStore := NewFileStore(rootDir)

	// Initialize stores
	if err := profileStore.Init(context.Background()); err != nil {
		t.Fatalf("profileStore.Init() error = %v", err)
	}
	if err := rootStore.Init(context.Background()); err != nil {
		t.Fatalf("rootStore.Init() error = %v", err)
	}

	ca, err := initializeCompositeCA(prof, "Test Composite CA With Passphrase", 5, "test-passphrase", profileStore, rootStore)
	if err != nil {
		t.Fatalf("initializeCompositeCA() error = %v", err)
	}

	if ca == nil {
		t.Fatal("initializeCompositeCA() returned nil CA")
	}

	cert := ca.Certificate()
	if cert.Subject.CommonName != "Test Composite CA With Passphrase" {
		t.Errorf("CommonName = %q, want %q", cert.Subject.CommonName, "Test Composite CA With Passphrase")
	}
}

func TestU_CA_RotateMulti_InitializeCompositeCA_UnsupportedAlgorithm(t *testing.T) {
	tmpDir := t.TempDir()

	// Use an unsupported algorithm combination (Ed25519 is not supported for composite)
	prof := &profile.Profile{
		Name: "invalid-composite-profile",
		Algorithms: []pkicrypto.AlgorithmID{
			pkicrypto.AlgEd25519, // Not supported for composite
			pkicrypto.AlgMLDSA87, // PQC
		},
		Validity: 10 * 365 * 24 * time.Hour,
	}

	profileDir := filepath.Join(tmpDir, "profile")
	rootDir := filepath.Join(tmpDir, "root")
	profileStore := NewFileStore(profileDir)
	rootStore := NewFileStore(rootDir)

	// Initialize stores
	if err := profileStore.Init(context.Background()); err != nil {
		t.Fatalf("profileStore.Init() error = %v", err)
	}
	if err := rootStore.Init(context.Background()); err != nil {
		t.Fatalf("rootStore.Init() error = %v", err)
	}

	_, err := initializeCompositeCA(prof, "Test Invalid Composite CA", 10, "", profileStore, rootStore)
	if err == nil {
		t.Error("initializeCompositeCA() should fail with unsupported algorithm combination")
	}
}

// =============================================================================
// loadCurrentCAsForCrossSigning Tests
// =============================================================================

func TestU_CA_LoadCurrentCAsForCrossSigning_NoCrossSign(t *testing.T) {
	tmpDir := t.TempDir()
	versionStore := NewVersionStore(tmpDir)

	currentCerts := map[string]*CertRef{
		"ec": {AlgorithmFamily: "ec", Subject: "CN=Test EC CA"},
	}

	req := MultiProfileRotateRequest{
		CADir:     tmpDir,
		CrossSign: false, // No cross-signing
	}

	result := loadCurrentCAsForCrossSigning(versionStore, currentCerts, req)
	if result != nil {
		t.Error("loadCurrentCAsForCrossSigning() should return nil when CrossSign is false")
	}
}

func TestU_CA_LoadCurrentCAsForCrossSigning_NoCerts(t *testing.T) {
	tmpDir := t.TempDir()
	versionStore := NewVersionStore(tmpDir)

	req := MultiProfileRotateRequest{
		CADir:     tmpDir,
		CrossSign: true,
	}

	result := loadCurrentCAsForCrossSigning(versionStore, nil, req)
	if result != nil {
		t.Error("loadCurrentCAsForCrossSigning() should return nil when currentCerts is nil")
	}
}

func TestU_CA_LoadCurrentCAsForCrossSigning_EmptyCerts(t *testing.T) {
	tmpDir := t.TempDir()
	versionStore := NewVersionStore(tmpDir)

	req := MultiProfileRotateRequest{
		CADir:     tmpDir,
		CrossSign: true,
	}

	result := loadCurrentCAsForCrossSigning(versionStore, map[string]*CertRef{}, req)
	if result != nil {
		t.Error("loadCurrentCAsForCrossSigning() should return nil when currentCerts is empty")
	}
}

func TestU_CA_LoadCurrentCAsForCrossSigning_WithCrossSign(t *testing.T) {
	tmpDir := setupVersionedCA(t)
	versionStore := NewVersionStore(tmpDir)

	// setupVersionedCA already creates and activates v1 via CreateInitialVersion
	// No need to create/activate again

	currentCerts := map[string]*CertRef{
		"ec": {AlgorithmFamily: "ec", Subject: "CN=Test EC CA"},
	}

	req := MultiProfileRotateRequest{
		CADir:     tmpDir,
		CrossSign: true,
	}

	// This will try to load CAs but may fail due to missing cert files
	// The function should still return a map (possibly empty) without panicking
	result := loadCurrentCAsForCrossSigning(versionStore, currentCerts, req)
	// Result may be empty or nil due to missing actual CA files, but function should not panic
	_ = result // We're testing that the function doesn't panic
}

// =============================================================================
// crossSignIfRequested Tests
// =============================================================================

func TestU_CA_CrossSignIfRequested_NoCrossSign(t *testing.T) {
	currentCAs := map[string]*CA{
		"ec": nil, // Won't be accessed
	}

	cert, err := crossSignIfRequested(currentCAs, nil, "ec", t.TempDir(), false)
	if err != nil {
		t.Fatalf("crossSignIfRequested() error = %v", err)
	}
	if cert != nil {
		t.Error("crossSignIfRequested() should return nil when doCrossSign is false")
	}
}

func TestU_CA_CrossSignIfRequested_NilCurrentCAs(t *testing.T) {
	cert, err := crossSignIfRequested(nil, nil, "ec", t.TempDir(), true)
	if err != nil {
		t.Fatalf("crossSignIfRequested() error = %v", err)
	}
	if cert != nil {
		t.Error("crossSignIfRequested() should return nil when currentCAs is nil")
	}
}

func TestU_CA_CrossSignIfRequested_AlgoNotFound(t *testing.T) {
	currentCAs := map[string]*CA{
		"rsa": nil, // Different algorithm family
	}

	cert, err := crossSignIfRequested(currentCAs, nil, "ec", t.TempDir(), true)
	if err != nil {
		t.Fatalf("crossSignIfRequested() error = %v", err)
	}
	if cert != nil {
		t.Error("crossSignIfRequested() should return nil when algorithm family not found")
	}
}

func TestU_CA_CrossSignIfRequested_WithCrossSign(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create old CA
	oldCfg := Config{
		CommonName:    "Old CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	oldCA, err := Initialize(store, oldCfg)
	if err != nil {
		t.Fatalf("Initialize(oldCA) error = %v", err)
	}

	// Create new CA
	newDir := t.TempDir()
	newStore := NewFileStore(newDir)

	newCfg := Config{
		CommonName:    "New CA",
		Algorithm:     pkicrypto.AlgECDSAP384,
		ValidityYears: 10,
		PathLen:       1,
	}

	newCA, err := Initialize(newStore, newCfg)
	if err != nil {
		t.Fatalf("Initialize(newCA) error = %v", err)
	}

	currentCAs := map[string]*CA{
		"ec": oldCA,
	}

	versionDir := t.TempDir()
	cert, err := crossSignIfRequested(currentCAs, newCA, "ec", versionDir, true)
	if err != nil {
		t.Fatalf("crossSignIfRequested() error = %v", err)
	}

	if cert == nil {
		t.Fatal("crossSignIfRequested() should return cross-signed certificate")
	}

	// Verify cross-signed cert properties
	if cert.Subject.CommonName != "New CA" {
		t.Errorf("Subject CN = %s, want New CA", cert.Subject.CommonName)
	}
	if cert.Issuer.CommonName != "Old CA" {
		t.Errorf("Issuer CN = %s, want Old CA", cert.Issuer.CommonName)
	}
}

// =============================================================================
// finalizeRotation Tests
// =============================================================================

func TestU_CA_FinalizeRotation_NoCrossSignedCerts(t *testing.T) {
	tmpDir := t.TempDir()
	versionStore := NewVersionStore(tmpDir)

	// Create a version
	_, err := versionStore.CreateVersionWithID("v1", []string{"test-profile"})
	if err != nil {
		t.Fatalf("CreateVersionWithID() error = %v", err)
	}

	crossSignedCerts := map[string]*x509.Certificate{} // Empty

	err = finalizeRotation(versionStore, "v1", tmpDir, []string{"test-profile"}, crossSignedCerts)
	if err != nil {
		t.Fatalf("finalizeRotation() error = %v", err)
	}
}

func TestU_CA_FinalizeRotation_WithCrossSignedCerts(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)
	versionStore := NewVersionStore(tmpDir)

	// Initialize a CA to have valid audit directory
	cfg := Config{
		CommonName:    "Test CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}
	_, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Create a version
	_, err = versionStore.CreateVersionWithID("v1", []string{"test-profile"})
	if err != nil {
		t.Fatalf("CreateVersionWithID() error = %v", err)
	}

	// Create a dummy cross-signed cert
	crossSignedCerts := map[string]*x509.Certificate{
		"ec": {}, // Dummy cert, not used directly
	}

	err = finalizeRotation(versionStore, "v1", tmpDir, []string{"test-profile"}, crossSignedCerts)
	if err != nil {
		t.Fatalf("finalizeRotation() error = %v", err)
	}
}

// =============================================================================
// extractProfileNames Tests
// =============================================================================

func TestU_CA_ExtractProfileNames_Empty(t *testing.T) {
	profiles := []*profile.Profile{}
	names := extractProfileNames(profiles)
	if len(names) != 0 {
		t.Errorf("extractProfileNames() returned %d names, want 0", len(names))
	}
}

func TestU_CA_ExtractProfileNames_Single(t *testing.T) {
	profiles := []*profile.Profile{
		{Name: "profile1"},
	}
	names := extractProfileNames(profiles)
	if len(names) != 1 || names[0] != "profile1" {
		t.Errorf("extractProfileNames() = %v, want [profile1]", names)
	}
}

func TestU_CA_ExtractProfileNames_Multiple(t *testing.T) {
	profiles := []*profile.Profile{
		{Name: "profile1"},
		{Name: "profile2"},
		{Name: "profile3"},
	}
	names := extractProfileNames(profiles)
	if len(names) != 3 {
		t.Errorf("extractProfileNames() returned %d names, want 3", len(names))
	}
	for i, expected := range []string{"profile1", "profile2", "profile3"} {
		if names[i] != expected {
			t.Errorf("names[%d] = %s, want %s", i, names[i], expected)
		}
	}
}

// =============================================================================
// getSubjectCN Tests
// =============================================================================

func TestU_CA_GetSubjectCN_FromCertRef(t *testing.T) {
	currentCerts := map[string]*CertRef{
		"ec": {AlgorithmFamily: "ec", Subject: "CN=Test EC CA"},
	}

	cn := getSubjectCN(currentCerts, "ec")
	if cn != "CN=Test EC CA" {
		t.Errorf("getSubjectCN() = %s, want CN=Test EC CA", cn)
	}
}

func TestU_CA_GetSubjectCN_NotFound(t *testing.T) {
	currentCerts := map[string]*CertRef{
		"rsa": {AlgorithmFamily: "rsa", Subject: "CN=Test RSA CA"},
	}

	cn := getSubjectCN(currentCerts, "ec")
	if cn != "CA ec" {
		t.Errorf("getSubjectCN() = %s, want CA ec", cn)
	}
}

func TestU_CA_GetSubjectCN_EmptySubject(t *testing.T) {
	currentCerts := map[string]*CertRef{
		"ec": {AlgorithmFamily: "ec", Subject: ""},
	}

	cn := getSubjectCN(currentCerts, "ec")
	if cn != "CA ec" {
		t.Errorf("getSubjectCN() = %s, want CA ec", cn)
	}
}

func TestU_CA_GetSubjectCN_NilMap(t *testing.T) {
	cn := getSubjectCN(nil, "ec")
	if cn != "CA ec" {
		t.Errorf("getSubjectCN() = %s, want CA ec", cn)
	}
}

// =============================================================================
// createVersionDirectories Tests
// =============================================================================

func TestU_CA_CreateVersionDirectories(t *testing.T) {
	tmpDir := t.TempDir()
	versionStore := NewVersionStore(tmpDir)

	err := createVersionDirectories(versionStore, "v1")
	if err != nil {
		t.Fatalf("createVersionDirectories() error = %v", err)
	}

	// Verify directories exist
	keysDir := versionStore.KeysDir("v1")
	certsDir := versionStore.CertsDir("v1")

	if _, err := os.Stat(keysDir); os.IsNotExist(err) {
		t.Errorf("keys directory %s does not exist", keysDir)
	}
	if _, err := os.Stat(certsDir); os.IsNotExist(err) {
		t.Errorf("certs directory %s does not exist", certsDir)
	}
}

// =============================================================================
// initializeCAForProfile Tests
// =============================================================================

func TestU_CA_InitializeCAForProfile_Classical(t *testing.T) {
	tmpDir := t.TempDir()

	prof := &profile.Profile{
		Name:      "ec-profile",
		Algorithm: pkicrypto.AlgECDSAP256,
		Validity:  10 * 365 * 24 * time.Hour,
	}

	currentCerts := map[string]*CertRef{
		"ec": {AlgorithmFamily: "ec", Subject: "CN=Test EC CA"},
	}

	profileDir := filepath.Join(tmpDir, "profile")
	rootDir := filepath.Join(tmpDir, "root")
	profileStore := NewFileStore(profileDir)
	rootStore := NewFileStore(rootDir)

	// Initialize stores
	if err := profileStore.Init(context.Background()); err != nil {
		t.Fatalf("profileStore.Init() error = %v", err)
	}
	if err := rootStore.Init(context.Background()); err != nil {
		t.Fatalf("rootStore.Init() error = %v", err)
	}

	ca, err := initializeCAForProfile(prof, currentCerts, profileStore, rootStore, "")
	if err != nil {
		t.Fatalf("initializeCAForProfile() error = %v", err)
	}

	if ca == nil {
		t.Fatal("initializeCAForProfile() returned nil CA")
	}

	if ca.Certificate().Subject.CommonName != "CN=Test EC CA" {
		t.Errorf("CommonName = %s, want CN=Test EC CA", ca.Certificate().Subject.CommonName)
	}
}

func TestU_CA_InitializeCAForProfile_PQC(t *testing.T) {
	tmpDir := t.TempDir()

	prof := &profile.Profile{
		Name:      "pqc-profile",
		Algorithm: pkicrypto.AlgMLDSA65,
		Validity:  10 * 365 * 24 * time.Hour,
	}

	currentCerts := map[string]*CertRef{
		"ml-dsa": {AlgorithmFamily: "ml-dsa", Subject: "CN=Test PQC CA"},
	}

	profileDir := filepath.Join(tmpDir, "profile")
	rootDir := filepath.Join(tmpDir, "root")
	profileStore := NewFileStore(profileDir)
	rootStore := NewFileStore(rootDir)

	// Initialize stores
	if err := profileStore.Init(context.Background()); err != nil {
		t.Fatalf("profileStore.Init() error = %v", err)
	}
	if err := rootStore.Init(context.Background()); err != nil {
		t.Fatalf("rootStore.Init() error = %v", err)
	}

	ca, err := initializeCAForProfile(prof, currentCerts, profileStore, rootStore, "")
	if err != nil {
		t.Fatalf("initializeCAForProfile() error = %v", err)
	}

	if ca == nil {
		t.Fatal("initializeCAForProfile() returned nil CA")
	}
}
