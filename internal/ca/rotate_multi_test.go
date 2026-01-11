package ca

import (
	"testing"
	"time"

	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
	"github.com/remiblancher/post-quantum-pki/internal/profile"
)

// =============================================================================
// MultiProfileRotateRequest Tests
// =============================================================================

func TestMultiProfileRotateRequest_Fields(t *testing.T) {
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

func TestMultiProfileRotatePlan_Fields(t *testing.T) {
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

func TestProfileRotatePlan_Fields(t *testing.T) {
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

func TestMultiProfileRotateResult_Fields(t *testing.T) {
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

func TestRotateCAMultiProfile_NoProfiles_Error(t *testing.T) {
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

func TestRotateCAMultiProfile_EmptyProfiles_Error(t *testing.T) {
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

func TestRotateCAMultiProfile_CANotFound_Error(t *testing.T) {
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

func TestRotateCAMultiProfile_DryRun_SingleProfile(t *testing.T) {
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

func TestRotateCAMultiProfile_DryRun_MultipleProfiles(t *testing.T) {
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

func TestRotateCAMultiProfile_DryRun_WithCrossSign(t *testing.T) {
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

func TestBuildMultiProfileRotationSteps_SingleProfile(t *testing.T) {
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

func TestBuildMultiProfileRotationSteps_MultipleProfiles(t *testing.T) {
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

func TestBuildMultiProfileRotationSteps_AllCrossSign(t *testing.T) {
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

func TestRotateCAMultiProfile_Execute_SingleProfile(t *testing.T) {
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

func TestRotateCAMultiProfile_Execute_PQCProfile(t *testing.T) {
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
