package profile

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/remiblancher/post-quantum-pki/internal/crypto"
)

// =============================================================================
// Profile Validation Tests
// =============================================================================

func TestProfile_Validate_ValidSimple(t *testing.T) {
	p := &Profile{
		Name:        "test-simple",
		Description: "Test simple profile",
		Algorithm:   crypto.AlgECDSAP256,
		Mode:        ModeSimple,
		Validity:    365 * 24 * time.Hour,
	}

	if err := p.Validate(); err != nil {
		t.Errorf("expected valid profile, got error: %v", err)
	}
}

func TestProfile_Validate_ValidCatalyst(t *testing.T) {
	p := &Profile{
		Name:        "test-catalyst",
		Description: "Test catalyst profile",
		Algorithms:  []crypto.AlgorithmID{crypto.AlgECDSAP256, crypto.AlgMLDSA65},
		Mode:        ModeCatalyst,
		Validity:    365 * 24 * time.Hour,
	}

	if err := p.Validate(); err != nil {
		t.Errorf("expected valid profile, got error: %v", err)
	}
}

func TestProfile_Validate_ValidKEM(t *testing.T) {
	p := &Profile{
		Name:        "test-kem",
		Description: "Test KEM profile",
		Algorithm:   crypto.AlgMLKEM768,
		Mode:        ModeSimple,
		Validity:    365 * 24 * time.Hour,
	}

	if err := p.Validate(); err != nil {
		t.Errorf("expected valid profile, got error: %v", err)
	}
}

func TestProfile_Validate_EmptyName(t *testing.T) {
	p := &Profile{
		Name:      "",
		Algorithm: crypto.AlgECDSAP256,
		Mode:      ModeSimple,
		Validity:  365 * 24 * time.Hour,
	}

	err := p.Validate()
	if err == nil {
		t.Error("expected error for empty name")
	}
}

func TestProfile_Validate_MissingAlgorithm(t *testing.T) {
	p := &Profile{
		Name:     "test",
		Mode:     ModeSimple,
		Validity: 365 * 24 * time.Hour,
	}

	err := p.Validate()
	if err == nil {
		t.Error("expected error for missing algorithm")
	}
}

func TestProfile_Validate_InvalidAlgorithm(t *testing.T) {
	p := &Profile{
		Name:      "test",
		Algorithm: crypto.AlgorithmID("unknown-algo"),
		Mode:      ModeSimple,
		Validity:  365 * 24 * time.Hour,
	}

	err := p.Validate()
	if err == nil {
		t.Error("expected error for invalid algorithm")
	}
}

func TestProfile_Validate_CatalystMissingSecondAlgorithm(t *testing.T) {
	p := &Profile{
		Name:       "test",
		Algorithms: []crypto.AlgorithmID{crypto.AlgECDSAP256},
		Mode:       ModeCatalyst,
		Validity:   365 * 24 * time.Hour,
	}

	err := p.Validate()
	if err == nil {
		t.Error("expected error for catalyst mode with only one algorithm")
	}
}

func TestProfile_Validate_CatalystFirstNotClassical(t *testing.T) {
	p := &Profile{
		Name:       "test",
		Algorithms: []crypto.AlgorithmID{crypto.AlgMLDSA65, crypto.AlgECDSAP256},
		Mode:       ModeCatalyst,
		Validity:   365 * 24 * time.Hour,
	}

	err := p.Validate()
	if err == nil {
		t.Error("expected error when catalyst first algorithm is PQC")
	}
}

func TestProfile_Validate_CatalystSecondNotPQC(t *testing.T) {
	p := &Profile{
		Name:       "test",
		Algorithms: []crypto.AlgorithmID{crypto.AlgECDSAP256, crypto.AlgECDSAP384},
		Mode:       ModeCatalyst,
		Validity:   365 * 24 * time.Hour,
	}

	err := p.Validate()
	if err == nil {
		t.Error("expected error when catalyst second algorithm is not PQC")
	}
}

func TestProfile_Validate_ZeroValidity(t *testing.T) {
	p := &Profile{
		Name:      "test",
		Algorithm: crypto.AlgECDSAP256,
		Mode:      ModeSimple,
		Validity:  0,
	}

	err := p.Validate()
	if err == nil {
		t.Error("expected error for zero validity")
	}
}

func TestProfile_Validate_NegativeValidity(t *testing.T) {
	p := &Profile{
		Name:      "test",
		Algorithm: crypto.AlgECDSAP256,
		Mode:      ModeSimple,
		Validity:  -24 * time.Hour,
	}

	err := p.Validate()
	if err == nil {
		t.Error("expected error for negative validity")
	}
}

// =============================================================================
// CertificateCount Tests (always 1 now: 1 profile = 1 certificate)
// =============================================================================

func TestProfile_CertificateCount_Simple(t *testing.T) {
	p := &Profile{
		Algorithm: crypto.AlgECDSAP256,
		Mode:      ModeSimple,
	}

	if count := p.CertificateCount(); count != 1 {
		t.Errorf("expected 1 certificate, got %d", count)
	}
}

func TestProfile_CertificateCount_Catalyst(t *testing.T) {
	p := &Profile{
		Algorithms: []crypto.AlgorithmID{crypto.AlgECDSAP256, crypto.AlgMLDSA65},
		Mode:       ModeCatalyst,
	}

	// Catalyst still produces 1 certificate (dual-key)
	if count := p.CertificateCount(); count != 1 {
		t.Errorf("expected 1 certificate for Catalyst, got %d", count)
	}
}

func TestProfile_CertificateCount_KEM(t *testing.T) {
	p := &Profile{
		Algorithm: crypto.AlgMLKEM768,
		Mode:      ModeSimple,
	}

	if count := p.CertificateCount(); count != 1 {
		t.Errorf("expected 1 certificate for KEM, got %d", count)
	}
}

// =============================================================================
// Helper Method Tests
// =============================================================================

func TestProfile_IsCatalyst(t *testing.T) {
	tests := []struct {
		name       string
		mode       Mode
		algorithms []crypto.AlgorithmID
		expected   bool
	}{
		{"simple", ModeSimple, nil, false},
		{"catalyst-with-2-algos", ModeCatalyst, []crypto.AlgorithmID{crypto.AlgECDSAP256, crypto.AlgMLDSA65}, true},
		{"catalyst-with-1-algo", ModeCatalyst, []crypto.AlgorithmID{crypto.AlgECDSAP256}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Profile{Mode: tt.mode, Algorithms: tt.algorithms}
			if got := p.IsCatalyst(); got != tt.expected {
				t.Errorf("IsCatalyst() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestProfile_IsKEM(t *testing.T) {
	tests := []struct {
		name      string
		algorithm crypto.AlgorithmID
		expected  bool
	}{
		{"ecdsa", crypto.AlgECDSAP256, false},
		{"ml-dsa", crypto.AlgMLDSA65, false},
		{"ml-kem", crypto.AlgMLKEM768, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Profile{Algorithm: tt.algorithm, Mode: ModeSimple}
			if got := p.IsKEM(); got != tt.expected {
				t.Errorf("IsKEM() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestProfile_IsSignature(t *testing.T) {
	tests := []struct {
		name      string
		algorithm crypto.AlgorithmID
		expected  bool
	}{
		{"ecdsa", crypto.AlgECDSAP256, true},
		{"ml-dsa", crypto.AlgMLDSA65, true},
		{"ml-kem", crypto.AlgMLKEM768, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Profile{Algorithm: tt.algorithm, Mode: ModeSimple}
			if got := p.IsSignature(); got != tt.expected {
				t.Errorf("IsSignature() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestProfile_GetAlgorithm(t *testing.T) {
	// Simple profile with Algorithm field
	p1 := &Profile{Algorithm: crypto.AlgECDSAP256}
	if got := p1.GetAlgorithm(); got != crypto.AlgECDSAP256 {
		t.Errorf("GetAlgorithm() = %v, want %v", got, crypto.AlgECDSAP256)
	}

	// Catalyst profile with Algorithms slice
	p2 := &Profile{Algorithms: []crypto.AlgorithmID{crypto.AlgECDSAP384, crypto.AlgMLDSA87}}
	if got := p2.GetAlgorithm(); got != crypto.AlgECDSAP384 {
		t.Errorf("GetAlgorithm() = %v, want %v", got, crypto.AlgECDSAP384)
	}
}

func TestProfile_GetAlternativeAlgorithm(t *testing.T) {
	// Simple profile - no alternative
	p1 := &Profile{Algorithm: crypto.AlgECDSAP256}
	if got := p1.GetAlternativeAlgorithm(); got != "" {
		t.Errorf("GetAlternativeAlgorithm() = %v, want empty", got)
	}

	// Catalyst profile
	p2 := &Profile{Algorithms: []crypto.AlgorithmID{crypto.AlgECDSAP384, crypto.AlgMLDSA87}}
	if got := p2.GetAlternativeAlgorithm(); got != crypto.AlgMLDSA87 {
		t.Errorf("GetAlternativeAlgorithm() = %v, want %v", got, crypto.AlgMLDSA87)
	}
}

func TestProfile_String(t *testing.T) {
	p := &Profile{
		Name:       "test-profile",
		Algorithms: []crypto.AlgorithmID{crypto.AlgECDSAP256, crypto.AlgMLDSA65},
		Mode:       ModeCatalyst,
		Validity:   365 * 24 * time.Hour,
	}

	s := p.String()

	// Check that the string contains expected information
	if s == "" {
		t.Error("String() returned empty string")
	}
}

// =============================================================================
// YAML Loading Tests (loader.go)
// =============================================================================

func TestLoadProfileFromBytes_ValidSimple(t *testing.T) {
	yaml := `
name: test-profile
description: Test profile
algorithm: ecdsa-p256
validity: 365d
`
	p, err := LoadProfileFromBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("LoadProfileFromBytes failed: %v", err)
	}

	if p.Name != "test-profile" {
		t.Errorf("expected name 'test-profile', got '%s'", p.Name)
	}
	if p.Mode != ModeSimple {
		t.Errorf("expected mode ModeSimple, got '%s'", p.Mode)
	}
	if p.GetAlgorithm() != crypto.AlgECDSAP256 {
		t.Errorf("expected algorithm ecdsa-p256, got '%s'", p.GetAlgorithm())
	}
	if p.Validity != 365*24*time.Hour {
		t.Errorf("expected validity 365 days, got %v", p.Validity)
	}
}

func TestLoadProfileFromBytes_ValidCatalyst(t *testing.T) {
	yaml := `
name: hybrid-test
description: Hybrid test
algorithms:
  - ecdsa-p384
  - ml-dsa-65
mode: catalyst
validity: 8760h
`
	p, err := LoadProfileFromBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("LoadProfileFromBytes failed: %v", err)
	}

	if p.Mode != ModeCatalyst {
		t.Errorf("expected mode ModeCatalyst, got '%s'", p.Mode)
	}
	if p.GetAlgorithm() != crypto.AlgECDSAP384 {
		t.Errorf("expected primary ecdsa-p384, got '%s'", p.GetAlgorithm())
	}
	if p.GetAlternativeAlgorithm() != crypto.AlgMLDSA65 {
		t.Errorf("expected alternative ml-dsa-65, got '%s'", p.GetAlternativeAlgorithm())
	}
}

func TestLoadProfileFromBytes_InvalidYAML(t *testing.T) {
	yaml := `invalid: yaml: content`

	_, err := LoadProfileFromBytes([]byte(yaml))
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestParseDuration_Hours(t *testing.T) {
	d, err := parseDuration("24h")
	if err != nil {
		t.Fatalf("parseDuration failed: %v", err)
	}
	if d != 24*time.Hour {
		t.Errorf("expected 24h, got %v", d)
	}
}

func TestParseDuration_Days(t *testing.T) {
	d, err := parseDuration("30d")
	if err != nil {
		t.Fatalf("parseDuration failed: %v", err)
	}
	if d != 30*24*time.Hour {
		t.Errorf("expected 30 days, got %v", d)
	}
}

func TestParseDuration_Years(t *testing.T) {
	d, err := parseDuration("1y")
	if err != nil {
		t.Fatalf("parseDuration failed: %v", err)
	}
	if d != 365*24*time.Hour {
		t.Errorf("expected 1 year (365 days), got %v", d)
	}
}

func TestParseDuration_Combined(t *testing.T) {
	d, err := parseDuration("1y30d12h")
	if err != nil {
		t.Fatalf("parseDuration failed: %v", err)
	}
	expected := 365*24*time.Hour + 30*24*time.Hour + 12*time.Hour
	if d != expected {
		t.Errorf("expected %v, got %v", expected, d)
	}
}

func TestParseDuration_Empty(t *testing.T) {
	_, err := parseDuration("")
	if err == nil {
		t.Error("expected error for empty duration")
	}
}

func TestLoadProfileFromFile(t *testing.T) {
	// Create a temp file
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "test.yaml")

	content := `
name: file-test
description: Test from file
algorithm: ecdsa-p256
validity: 30d
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	p, err := LoadProfileFromFile(path)
	if err != nil {
		t.Fatalf("LoadProfileFromFile failed: %v", err)
	}

	if p.Name != "file-test" {
		t.Errorf("expected name 'file-test', got '%s'", p.Name)
	}
}

func TestLoadProfileFromFile_NotFound(t *testing.T) {
	_, err := LoadProfileFromFile("/nonexistent/path/profile.yaml")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestLoadProfilesFromDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	// Create two profile files
	profile1 := `
name: profile-one
algorithm: ecdsa-p256
validity: 365d
`
	profile2 := `
name: profile-two
algorithm: ecdsa-p384
validity: 365d
`
	if err := os.WriteFile(filepath.Join(tmpDir, "one.yaml"), []byte(profile1), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "two.yaml"), []byte(profile2), 0644); err != nil {
		t.Fatal(err)
	}

	profiles, err := LoadProfilesFromDirectory(tmpDir)
	if err != nil {
		t.Fatalf("LoadProfilesFromDirectory failed: %v", err)
	}

	if len(profiles) != 2 {
		t.Errorf("expected 2 profiles, got %d", len(profiles))
	}
	if _, ok := profiles["profile-one"]; !ok {
		t.Error("expected profile-one to be loaded")
	}
	if _, ok := profiles["profile-two"]; !ok {
		t.Error("expected profile-two to be loaded")
	}
}

func TestLoadProfilesFromDirectory_DuplicateName(t *testing.T) {
	tmpDir := t.TempDir()

	// Two files with same profile name
	profile := `
name: duplicate-name
algorithm: ecdsa-p256
validity: 365d
`
	if err := os.WriteFile(filepath.Join(tmpDir, "one.yaml"), []byte(profile), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "two.yaml"), []byte(profile), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadProfilesFromDirectory(tmpDir)
	if err == nil {
		t.Error("expected error for duplicate profile names")
	}
}

// =============================================================================
// ProfileStore Tests
// =============================================================================

func TestProfileStore_SaveAndLoad(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewProfileStore(tmpDir)

	p := &Profile{
		Name:        "store-test",
		Description: "Test profile for store",
		Algorithm:   crypto.AlgECDSAP256,
		Mode:        ModeSimple,
		Validity:    365 * 24 * time.Hour,
	}

	// Save
	if err := store.Save(p); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Create new store and load
	store2 := NewProfileStore(tmpDir)
	if err := store2.Load(); err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Get
	loaded, ok := store2.Get("store-test")
	if !ok {
		t.Fatal("profile not found after load")
	}

	if loaded.Name != p.Name {
		t.Errorf("expected name '%s', got '%s'", p.Name, loaded.Name)
	}
	if loaded.Mode != p.Mode {
		t.Errorf("expected mode '%s', got '%s'", p.Mode, loaded.Mode)
	}
}

func TestProfileStore_List(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewProfileStore(tmpDir)

	profiles := []*Profile{
		{
			Name:      "profile-a",
			Algorithm: crypto.AlgECDSAP256,
			Mode:      ModeSimple,
			Validity:  365 * 24 * time.Hour,
		},
		{
			Name:      "profile-b",
			Algorithm: crypto.AlgECDSAP256,
			Mode:      ModeSimple,
			Validity:  365 * 24 * time.Hour,
		},
	}

	for _, p := range profiles {
		if err := store.Save(p); err != nil {
			t.Fatalf("Save failed: %v", err)
		}
	}

	names := store.List()
	if len(names) != 2 {
		t.Errorf("expected 2 names, got %d", len(names))
	}
}

func TestProfileStore_All(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewProfileStore(tmpDir)

	p := &Profile{
		Name:      "all-test",
		Algorithm: crypto.AlgECDSAP256,
		Mode:      ModeSimple,
		Validity:  365 * 24 * time.Hour,
	}

	if err := store.Save(p); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	all := store.All()
	if len(all) != 1 {
		t.Errorf("expected 1 profile, got %d", len(all))
	}
}

func TestProfileStore_BasePath(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewProfileStore(tmpDir)

	expected := filepath.Join(tmpDir, "profiles")
	if store.BasePath() != expected {
		t.Errorf("expected basePath '%s', got '%s'", expected, store.BasePath())
	}
}

// =============================================================================
// Defaults Tests (defaults.go)
// =============================================================================

func TestBuiltinProfiles(t *testing.T) {
	profiles, err := BuiltinProfiles()
	if err != nil {
		t.Fatalf("BuiltinProfiles failed: %v", err)
	}

	if len(profiles) == 0 {
		t.Error("expected at least one builtin profile")
	}

	// Check that known profiles exist (new hierarchical naming)
	expectedNames := []string{"ec/root-ca", "hybrid/catalyst/root-ca"}
	for _, name := range expectedNames {
		if _, ok := profiles[name]; !ok {
			t.Errorf("expected builtin profile '%s' not found", name)
		}
	}

	// Verify all builtin profiles are valid
	for name, p := range profiles {
		if err := p.Validate(); err != nil {
			t.Errorf("builtin profile '%s' is invalid: %v", name, err)
		}
	}
}

func TestListBuiltinProfileNames(t *testing.T) {
	names, err := ListBuiltinProfileNames()
	if err != nil {
		t.Fatalf("ListBuiltinProfileNames failed: %v", err)
	}

	if len(names) == 0 {
		t.Error("expected at least one builtin profile name")
	}
}

func TestGetBuiltinProfile(t *testing.T) {
	p, err := GetBuiltinProfile("ec/root-ca")
	if err != nil {
		t.Fatalf("GetBuiltinProfile failed: %v", err)
	}

	if p.Name != "ec/root-ca" {
		t.Errorf("expected name 'ec/root-ca', got '%s'", p.Name)
	}
}

func TestGetBuiltinProfile_NotFound(t *testing.T) {
	_, err := GetBuiltinProfile("nonexistent-profile")
	if err == nil {
		t.Error("expected error for nonexistent profile")
	}
}

func TestInstallBuiltinProfiles(t *testing.T) {
	tmpDir := t.TempDir()

	if err := InstallBuiltinProfiles(tmpDir, false); err != nil {
		t.Fatalf("InstallBuiltinProfiles failed: %v", err)
	}

	// Check that files were created in subdirectories
	profilesDir := filepath.Join(tmpDir, "profiles")

	// Check ec subdirectory exists
	ecDir := filepath.Join(profilesDir, "ec")
	entries, err := os.ReadDir(ecDir)
	if err != nil {
		t.Fatalf("failed to read ec profiles directory: %v", err)
	}

	if len(entries) == 0 {
		t.Error("expected at least one profile file in ec/")
	}

	// Verify a specific profile file exists
	rootCAPath := filepath.Join(ecDir, "root-ca.yaml")
	if _, err := os.Stat(rootCAPath); os.IsNotExist(err) {
		t.Error("expected 'ec/root-ca.yaml' profile to be installed")
	}
}

func TestInstallBuiltinProfiles_NoOverwrite(t *testing.T) {
	tmpDir := t.TempDir()
	profilesDir := filepath.Join(tmpDir, "profiles")

	// First install
	if err := InstallBuiltinProfiles(tmpDir, false); err != nil {
		t.Fatalf("InstallBuiltinProfiles failed: %v", err)
	}

	// Modify a file
	rootCAPath := filepath.Join(profilesDir, "ec", "root-ca.yaml")
	customContent := []byte("# Custom content\n")
	if err := os.WriteFile(rootCAPath, customContent, 0644); err != nil {
		t.Fatalf("failed to modify file: %v", err)
	}

	// Second install without overwrite
	if err := InstallBuiltinProfiles(tmpDir, false); err != nil {
		t.Fatalf("InstallBuiltinProfiles failed: %v", err)
	}

	// Check that file was not overwritten
	content, err := os.ReadFile(rootCAPath)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}

	if string(content) != string(customContent) {
		t.Error("file should not have been overwritten")
	}
}

func TestInstallBuiltinProfiles_Overwrite(t *testing.T) {
	tmpDir := t.TempDir()
	profilesDir := filepath.Join(tmpDir, "profiles")

	// First install
	if err := InstallBuiltinProfiles(tmpDir, false); err != nil {
		t.Fatalf("InstallBuiltinProfiles failed: %v", err)
	}

	// Modify a file
	rootCAPath := filepath.Join(profilesDir, "ec", "root-ca.yaml")
	customContent := []byte("# Custom content\n")
	if err := os.WriteFile(rootCAPath, customContent, 0644); err != nil {
		t.Fatalf("failed to modify file: %v", err)
	}

	// Second install with overwrite
	if err := InstallBuiltinProfiles(tmpDir, true); err != nil {
		t.Fatalf("InstallBuiltinProfiles failed: %v", err)
	}

	// Check that file was overwritten
	content, err := os.ReadFile(rootCAPath)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}

	if string(content) == string(customContent) {
		t.Error("file should have been overwritten")
	}
}

// =============================================================================
// SaveProfileToFile Tests
// =============================================================================

func TestSaveProfileToFile(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "saved.yaml")

	p := &Profile{
		Name:        "saved-profile",
		Description: "A saved profile",
		Algorithms:  []crypto.AlgorithmID{crypto.AlgECDSAP256, crypto.AlgMLDSA65},
		Mode:        ModeCatalyst,
		Validity:    30 * 24 * time.Hour,
	}

	if err := SaveProfileToFile(p, path); err != nil {
		t.Fatalf("SaveProfileToFile failed: %v", err)
	}

	// Load it back
	loaded, err := LoadProfileFromFile(path)
	if err != nil {
		t.Fatalf("LoadProfileFromFile failed: %v", err)
	}

	if loaded.Name != p.Name {
		t.Errorf("expected name '%s', got '%s'", p.Name, loaded.Name)
	}
	if loaded.Mode != p.Mode {
		t.Errorf("expected mode '%s', got '%s'", p.Mode, loaded.Mode)
	}
	if loaded.Validity != p.Validity {
		t.Errorf("expected validity %v, got %v", p.Validity, loaded.Validity)
	}
}
