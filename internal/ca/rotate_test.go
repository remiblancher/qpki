package ca

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
	"github.com/remiblancher/post-quantum-pki/internal/profile"
)

// =============================================================================
// CA Rotation Tests
// =============================================================================

func TestRotateCA_DryRun(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	_, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Create a profile
	prof := &profile.Profile{
		Name:      "test-profile",
		Algorithm: pkicrypto.AlgECDSAP256,
		Validity:  10 * 365 * 24 * time.Hour,
	}

	profileStore := profile.NewProfileStore(tmpDir)
	if err := profileStore.Save(prof); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	req := RotateCARequest{
		CADir:     tmpDir,
		Profile:   "test-profile",
		CrossSign: CrossSignOff,
		DryRun:    true,
	}

	result, err := RotateCA(req)
	if err != nil {
		t.Fatalf("RotateCA() error = %v", err)
	}

	// Dry run should return a plan but not actually execute
	if result.Plan == nil {
		t.Error("RotateCA() dry run should return a plan")
	}
	if result.NewCA != nil {
		t.Error("RotateCA() dry run should not create new CA")
	}
	if result.Plan.NewVersion == "" {
		t.Error("RotateCA() dry run plan should have new version ID")
	}
	if result.Plan.Profile != "test-profile" {
		t.Errorf("RotateCA() plan profile = %s, want test-profile", result.Plan.Profile)
	}
}

func TestRotateCA_CANotFound(t *testing.T) {
	tmpDir := t.TempDir()

	req := RotateCARequest{
		CADir:   tmpDir,
		Profile: "test-profile",
	}

	_, err := RotateCA(req)
	if err == nil {
		t.Error("RotateCA() should fail when CA not found")
	}
}

func TestRotateCA_ProfileNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	_, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	req := RotateCARequest{
		CADir:   tmpDir,
		Profile: "nonexistent",
	}

	_, err = RotateCA(req)
	if err == nil {
		t.Error("RotateCA() should fail when profile not found")
	}
}

// =============================================================================
// Cross-Sign Mode Tests
// =============================================================================

func TestShouldCrossSign(t *testing.T) {
	tests := []struct {
		name        string
		mode        CrossSignMode
		currentAlgo string
		newAlgo     string
		want        bool
	}{
		{"auto same algo", CrossSignAuto, "ECDSA", "ECDSA", false},
		{"auto different algo", CrossSignAuto, "ECDSA", "ML-DSA-65", true},
		{"on same algo", CrossSignOn, "ECDSA", "ECDSA", true},
		{"on different algo", CrossSignOn, "ECDSA", "ML-DSA-65", true},
		{"off same algo", CrossSignOff, "ECDSA", "ECDSA", false},
		{"off different algo", CrossSignOff, "ECDSA", "ML-DSA-65", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldCrossSign(tt.mode, tt.currentAlgo, tt.newAlgo)
			if got != tt.want {
				t.Errorf("shouldCrossSign(%v, %s, %s) = %v, want %v", tt.mode, tt.currentAlgo, tt.newAlgo, got, tt.want)
			}
		})
	}
}

func TestCrossSignMode_Constants(t *testing.T) {
	// Verify constants have expected values
	if CrossSignAuto != 0 {
		t.Errorf("CrossSignAuto = %d, want 0", CrossSignAuto)
	}
	if CrossSignOn != 1 {
		t.Errorf("CrossSignOn = %d, want 1", CrossSignOn)
	}
	if CrossSignOff != 2 {
		t.Errorf("CrossSignOff = %d, want 2", CrossSignOff)
	}
}

// =============================================================================
// Helper Function Tests
// =============================================================================

func TestDetermineCurrentProfile(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

	// No metadata file - should return empty
	result := determineCurrentProfile(store)
	if result != "" {
		t.Errorf("determineCurrentProfile() = %s, want empty for no metadata", result)
	}

	// Create a metadata file
	if err := store.Init(); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	metaPath := filepath.Join(tmpDir, "ca.meta.json")
	if err := os.WriteFile(metaPath, []byte(`{"profile":"test-profile"}`), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	result = determineCurrentProfile(store)
	if result != "test-profile" {
		t.Errorf("determineCurrentProfile() = %s, want test-profile", result)
	}
}

func TestDetermineCurrentProfile_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

	if err := store.Init(); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	// Write invalid JSON
	metaPath := filepath.Join(tmpDir, "ca.meta.json")
	if err := os.WriteFile(metaPath, []byte(`not valid json`), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	result := determineCurrentProfile(store)
	if result != "" {
		t.Errorf("determineCurrentProfile() = %s, want empty for invalid JSON", result)
	}
}

func TestBuildRotationSteps(t *testing.T) {
	// Test without cross-signing
	steps := buildRotationSteps("v1", "test-profile", false)
	if len(steps) == 0 {
		t.Error("buildRotationSteps() returned empty steps")
	}

	// Should contain version ID and profile
	found := false
	for _, s := range steps {
		if s == "Create new version directory: versions/v1" {
			found = true
			break
		}
	}
	if !found {
		t.Error("buildRotationSteps() should contain version directory step")
	}

	// Test with cross-signing
	stepsWithCross := buildRotationSteps("v2", "test-profile", true)
	if len(stepsWithCross) <= len(steps) {
		t.Error("buildRotationSteps() with cross-signing should have more steps")
	}

	// Should contain cross-signing step
	foundCrossSign := false
	for _, s := range stepsWithCross {
		if s == "Cross-sign new CA certificate with current CA" {
			foundCrossSign = true
			break
		}
	}
	if !foundCrossSign {
		t.Error("buildRotationSteps() should contain cross-sign step")
	}
}

func TestFirstOrEmpty(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  string
	}{
		{"empty slice", []string{}, ""},
		{"single element", []string{"first"}, "first"},
		{"multiple elements", []string{"first", "second", "third"}, "first"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := firstOrEmpty(tt.input)
			if got != tt.want {
				t.Errorf("firstOrEmpty(%v) = %s, want %s", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseJSON(t *testing.T) {
	// Valid JSON
	var result struct {
		Name string `json:"name"`
	}
	err := parseJSON([]byte(`{"name":"test"}`), &result)
	if err != nil {
		t.Errorf("parseJSON() error = %v", err)
	}
	if result.Name != "test" {
		t.Errorf("parseJSON() result.Name = %s, want test", result.Name)
	}

	// Invalid JSON
	err = parseJSON([]byte(`not valid`), &result)
	if err == nil {
		t.Error("parseJSON() should fail for invalid JSON")
	}
}

// =============================================================================
// Rotation Plan Tests
// =============================================================================

func TestRotateCAPlan_Fields(t *testing.T) {
	plan := &RotateCAPlan{
		CurrentVersion:  "v1",
		NewVersion:      "v2",
		Profile:         "test-profile",
		Algorithm:       "ECDSA-P256",
		Subject:         "CN=Test CA",
		WillCrossSign:   true,
		CrossSignReason: "algorithm changed",
		Steps:           []string{"step1", "step2"},
	}

	if plan.CurrentVersion != "v1" {
		t.Errorf("plan.CurrentVersion = %s, want v1", plan.CurrentVersion)
	}
	if plan.NewVersion != "v2" {
		t.Errorf("plan.NewVersion = %s, want v2", plan.NewVersion)
	}
	if plan.Profile != "test-profile" {
		t.Errorf("plan.Profile = %s, want test-profile", plan.Profile)
	}
	if !plan.WillCrossSign {
		t.Error("plan.WillCrossSign should be true")
	}
	if len(plan.Steps) != 2 {
		t.Errorf("plan.Steps length = %d, want 2", len(plan.Steps))
	}
}

func TestRotateCAResult_Fields(t *testing.T) {
	plan := &RotateCAPlan{NewVersion: "v1"}
	result := &RotateCAResult{
		Plan: plan,
	}

	if result.Plan != plan {
		t.Error("result.Plan should match")
	}
	if result.NewCA != nil {
		t.Error("result.NewCA should be nil when not executed")
	}
	if result.Version != nil {
		t.Error("result.Version should be nil when not executed")
	}
}

// =============================================================================
// Profile Path Tests
// =============================================================================

func TestRotateCA_ProfileFromPath(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	_, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Create a profile file
	prof := &profile.Profile{
		Name:      "file-profile",
		Algorithm: pkicrypto.AlgECDSAP256,
		Validity:  10 * 365 * 24 * time.Hour,
	}

	profilePath := filepath.Join(tmpDir, "custom-profile.yaml")
	if err := profile.SaveProfileToFile(prof, profilePath); err != nil {
		t.Fatalf("SaveProfileToFile() error = %v", err)
	}

	req := RotateCARequest{
		CADir:     tmpDir,
		Profile:   profilePath,
		CrossSign: CrossSignOff,
		DryRun:    true,
	}

	result, err := RotateCA(req)
	if err != nil {
		t.Fatalf("RotateCA() error = %v", err)
	}

	if result.Plan == nil {
		t.Error("RotateCA() should return plan")
	}
}

func TestRotateCA_NoProfile(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	_, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// No profile specified and no metadata file
	req := RotateCARequest{
		CADir:     tmpDir,
		CrossSign: CrossSignOff,
	}

	_, err = RotateCA(req)
	if err == nil {
		t.Error("RotateCA() should fail when no profile and no metadata")
	}
}
