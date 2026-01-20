package profile

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/remiblancher/post-quantum-pki/internal/crypto"
)

// =============================================================================
// Unit Tests: Profile Validation
// =============================================================================

func TestU_Validate_ValidSimple(t *testing.T) {
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

func TestU_Validate_ValidCatalyst(t *testing.T) {
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

func TestU_Validate_ValidKEM(t *testing.T) {
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

func TestU_Validate_NameMissing(t *testing.T) {
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

func TestU_Validate_AlgorithmMissing(t *testing.T) {
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

func TestU_Validate_AlgorithmInvalid(t *testing.T) {
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

func TestU_Validate_CatalystSecondAlgorithmMissing(t *testing.T) {
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

func TestU_Validate_CatalystFirstNotClassicalInvalid(t *testing.T) {
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

func TestU_Validate_CatalystSecondNotPQCInvalid(t *testing.T) {
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

func TestU_Validate_ValidityZeroInvalid(t *testing.T) {
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

func TestU_Validate_ValidityNegativeInvalid(t *testing.T) {
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
// Unit Tests: CertificateCount (always 1 now: 1 profile = 1 certificate)
// =============================================================================

func TestU_CertificateCount_Simple(t *testing.T) {
	p := &Profile{
		Algorithm: crypto.AlgECDSAP256,
		Mode:      ModeSimple,
	}

	if count := p.CertificateCount(); count != 1 {
		t.Errorf("expected 1 certificate, got %d", count)
	}
}

func TestU_CertificateCount_Catalyst(t *testing.T) {
	p := &Profile{
		Algorithms: []crypto.AlgorithmID{crypto.AlgECDSAP256, crypto.AlgMLDSA65},
		Mode:       ModeCatalyst,
	}

	// Catalyst still produces 1 certificate (dual-key)
	if count := p.CertificateCount(); count != 1 {
		t.Errorf("expected 1 certificate for Catalyst, got %d", count)
	}
}

func TestU_CertificateCount_KEM(t *testing.T) {
	p := &Profile{
		Algorithm: crypto.AlgMLKEM768,
		Mode:      ModeSimple,
	}

	if count := p.CertificateCount(); count != 1 {
		t.Errorf("expected 1 certificate for KEM, got %d", count)
	}
}

// =============================================================================
// Unit Tests: Helper Methods
// =============================================================================

func TestU_IsCatalyst_Modes(t *testing.T) {
	tests := []struct {
		name       string
		mode       Mode
		algorithms []crypto.AlgorithmID
		expected   bool
	}{
		{"[Unit] IsCatalyst: Simple Mode", ModeSimple, nil, false},
		{"[Unit] IsCatalyst: Catalyst With Two Algorithms", ModeCatalyst, []crypto.AlgorithmID{crypto.AlgECDSAP256, crypto.AlgMLDSA65}, true},
		{"[Unit] IsCatalyst: Catalyst With One Algorithm", ModeCatalyst, []crypto.AlgorithmID{crypto.AlgECDSAP256}, false},
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

func TestU_IsKEM_Algorithms(t *testing.T) {
	tests := []struct {
		name      string
		algorithm crypto.AlgorithmID
		expected  bool
	}{
		{"[Unit] IsKEM: ECDSA Algorithm", crypto.AlgECDSAP256, false},
		{"[Unit] IsKEM: ML-DSA Algorithm", crypto.AlgMLDSA65, false},
		{"[Unit] IsKEM: ML-KEM Algorithm", crypto.AlgMLKEM768, true},
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

func TestU_IsSignature_Algorithms(t *testing.T) {
	tests := []struct {
		name      string
		algorithm crypto.AlgorithmID
		expected  bool
	}{
		{"[Unit] IsSignature: ECDSA Algorithm", crypto.AlgECDSAP256, true},
		{"[Unit] IsSignature: ML-DSA Algorithm", crypto.AlgMLDSA65, true},
		{"[Unit] IsSignature: ML-KEM Algorithm", crypto.AlgMLKEM768, false},
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

func TestU_GetAlgorithm_ProfileTypes(t *testing.T) {
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

func TestU_GetAlternativeAlgorithm_ProfileTypes(t *testing.T) {
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

func TestU_String_ProfileRepresentation(t *testing.T) {
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
// Unit Tests: YAML Loading (loader.go)
// =============================================================================

func TestU_LoadProfileFromBytes_ValidSimple(t *testing.T) {
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

func TestU_LoadProfileFromBytes_ValidCatalyst(t *testing.T) {
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

func TestU_LoadProfileFromBytes_YAMLInvalid(t *testing.T) {
	yaml := `invalid: yaml: content`

	_, err := LoadProfileFromBytes([]byte(yaml))
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestU_ParseDuration_Hours(t *testing.T) {
	d, err := parseDuration("24h")
	if err != nil {
		t.Fatalf("parseDuration failed: %v", err)
	}
	if d != 24*time.Hour {
		t.Errorf("expected 24h, got %v", d)
	}
}

func TestU_ParseDuration_Days(t *testing.T) {
	d, err := parseDuration("30d")
	if err != nil {
		t.Fatalf("parseDuration failed: %v", err)
	}
	if d != 30*24*time.Hour {
		t.Errorf("expected 30 days, got %v", d)
	}
}

func TestU_ParseDuration_Years(t *testing.T) {
	d, err := parseDuration("1y")
	if err != nil {
		t.Fatalf("parseDuration failed: %v", err)
	}
	if d != 365*24*time.Hour {
		t.Errorf("expected 1 year (365 days), got %v", d)
	}
}

func TestU_ParseDuration_Combined(t *testing.T) {
	d, err := parseDuration("1y30d12h")
	if err != nil {
		t.Fatalf("parseDuration failed: %v", err)
	}
	expected := 365*24*time.Hour + 30*24*time.Hour + 12*time.Hour
	if d != expected {
		t.Errorf("expected %v, got %v", expected, d)
	}
}

func TestU_ParseDuration_EmptyInvalid(t *testing.T) {
	_, err := parseDuration("")
	if err == nil {
		t.Error("expected error for empty duration")
	}
}

func TestU_LoadProfileFromFile_ValidFile(t *testing.T) {
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

func TestU_LoadProfileFromFile_FileNotFound(t *testing.T) {
	_, err := LoadProfileFromFile("/nonexistent/path/profile.yaml")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestU_LoadProfilesFromDirectory_MultipleProfiles(t *testing.T) {
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

func TestU_LoadProfilesFromDirectory_DuplicateNameInvalid(t *testing.T) {
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
// Unit Tests: ProfileStore
// =============================================================================

func TestU_ProfileStore_SaveAndLoad(t *testing.T) {
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

func TestU_ProfileStore_List(t *testing.T) {
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

func TestU_ProfileStore_All(t *testing.T) {
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

func TestU_ProfileStore_BasePath(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewProfileStore(tmpDir)

	expected := filepath.Join(tmpDir, "profiles")
	if store.BasePath() != expected {
		t.Errorf("expected basePath '%s', got '%s'", expected, store.BasePath())
	}
}

// =============================================================================
// Unit Tests: Defaults (defaults.go)
// =============================================================================

func TestU_BuiltinProfiles_LoadAll(t *testing.T) {
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

func TestU_ListBuiltinProfileNames_ReturnsNames(t *testing.T) {
	names, err := ListBuiltinProfileNames()
	if err != nil {
		t.Fatalf("ListBuiltinProfileNames failed: %v", err)
	}

	if len(names) == 0 {
		t.Error("expected at least one builtin profile name")
	}
}

func TestU_GetBuiltinProfile_ValidName(t *testing.T) {
	p, err := GetBuiltinProfile("ec/root-ca")
	if err != nil {
		t.Fatalf("GetBuiltinProfile failed: %v", err)
	}

	if p.Name != "ec/root-ca" {
		t.Errorf("expected name 'ec/root-ca', got '%s'", p.Name)
	}
}

func TestU_GetBuiltinProfile_NameNotFound(t *testing.T) {
	_, err := GetBuiltinProfile("nonexistent-profile")
	if err == nil {
		t.Error("expected error for nonexistent profile")
	}
}

func TestU_InstallBuiltinProfiles_CreatesFiles(t *testing.T) {
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

func TestU_InstallBuiltinProfiles_NoOverwrite(t *testing.T) {
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

func TestU_InstallBuiltinProfiles_Overwrite(t *testing.T) {
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
// Unit Tests: SaveProfileToFile
// =============================================================================

func TestU_SaveProfileToFile_RoundTrip(t *testing.T) {
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

// =============================================================================
// Unit Tests: LoadProfile
// =============================================================================

func TestU_LoadProfile_AbsolutePath(t *testing.T) {
	tmpDir := t.TempDir()
	profilePath := filepath.Join(tmpDir, "test-profile.yaml")

	// Create a valid profile file
	profileYAML := `name: test-abs-profile
description: Test profile with absolute path
algorithm: ecdsa-p256
validity: 720h
`
	if err := os.WriteFile(profilePath, []byte(profileYAML), 0644); err != nil {
		t.Fatalf("failed to write profile: %v", err)
	}

	// Load using absolute path (starts with "/")
	p, err := LoadProfile(profilePath)
	if err != nil {
		t.Fatalf("LoadProfile() error = %v", err)
	}

	if p.Name != "test-abs-profile" {
		t.Errorf("Name = %s, want test-abs-profile", p.Name)
	}
}

func TestU_LoadProfile_RelativePath(t *testing.T) {
	// Create temp file in current directory
	tmpFile, err := os.CreateTemp(".", "test-profile-*.yaml")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	profileYAML := `name: test-rel-profile
description: Test profile with relative path
algorithm: ecdsa-p384
validity: 720h
`
	if _, err := tmpFile.WriteString(profileYAML); err != nil {
		t.Fatalf("failed to write profile: %v", err)
	}
	_ = tmpFile.Close()

	// Load using relative path (starts with ".")
	p, err := LoadProfile("./" + filepath.Base(tmpFile.Name()))
	if err != nil {
		t.Fatalf("LoadProfile() error = %v", err)
	}

	if p.Name != "test-rel-profile" {
		t.Errorf("Name = %s, want test-rel-profile", p.Name)
	}
}

func TestU_LoadProfile_YAMLSuffix(t *testing.T) {
	tmpDir := t.TempDir()
	profilePath := filepath.Join(tmpDir, "profile.yaml")

	profileYAML := `name: yaml-suffix-test
algorithm: ecdsa-p256
validity: 720h
`
	if err := os.WriteFile(profilePath, []byte(profileYAML), 0644); err != nil {
		t.Fatalf("failed to write profile: %v", err)
	}

	// Load using filename with .yaml suffix (detected as file path)
	p, err := LoadProfile(profilePath)
	if err != nil {
		t.Fatalf("LoadProfile() error = %v", err)
	}

	if p.Name != "yaml-suffix-test" {
		t.Errorf("Name = %s, want yaml-suffix-test", p.Name)
	}
}

func TestU_LoadProfile_YMLSuffix(t *testing.T) {
	tmpDir := t.TempDir()
	profilePath := filepath.Join(tmpDir, "profile.yml")

	profileYAML := `name: yml-suffix-test
algorithm: ecdsa-p384
validity: 720h
`
	if err := os.WriteFile(profilePath, []byte(profileYAML), 0644); err != nil {
		t.Fatalf("failed to write profile: %v", err)
	}

	// Load using filename with .yml suffix (detected as file path)
	p, err := LoadProfile(profilePath)
	if err != nil {
		t.Fatalf("LoadProfile() error = %v", err)
	}

	if p.Name != "yml-suffix-test" {
		t.Errorf("Name = %s, want yml-suffix-test", p.Name)
	}
}

func TestU_LoadProfile_BuiltinName(t *testing.T) {
	// Load using builtin profile name (no special prefix/suffix)
	p, err := LoadProfile("ec/root-ca")
	if err != nil {
		t.Fatalf("LoadProfile() error = %v", err)
	}

	if p.Name != "ec/root-ca" {
		t.Errorf("Name = %s, want ec/root-ca", p.Name)
	}
}

func TestU_LoadProfile_BuiltinNotFound(t *testing.T) {
	_, err := LoadProfile("nonexistent/profile")
	if err == nil {
		t.Error("LoadProfile() should fail for nonexistent builtin")
	}
}

func TestU_LoadProfile_FileNotFound(t *testing.T) {
	_, err := LoadProfile("/nonexistent/path/profile.yaml")
	if err == nil {
		t.Error("LoadProfile() should fail for nonexistent file")
	}
}

// =============================================================================
// Unit Tests: InstallBuiltinProfiles Error Paths
// =============================================================================

func TestU_InstallBuiltinProfiles_CannotCreateDir(t *testing.T) {
	// Try to create profiles directory in a non-existent parent
	err := InstallBuiltinProfiles("/nonexistent/parent/path", false)
	if err == nil {
		t.Error("InstallBuiltinProfiles() should fail when cannot create directory")
	}
}

func TestU_InstallBuiltinProfiles_WriteToReadOnlyDir(t *testing.T) {
	// Skip on non-Unix or when running as root
	if os.Getuid() == 0 {
		t.Skip("skipping test when running as root")
	}

	tmpDir := t.TempDir()
	profilesDir := filepath.Join(tmpDir, "profiles")

	// Create the profiles directory
	if err := os.MkdirAll(profilesDir, 0755); err != nil {
		t.Fatalf("failed to create profiles dir: %v", err)
	}

	// Create ec subdirectory and make it read-only
	ecDir := filepath.Join(profilesDir, "ec")
	if err := os.MkdirAll(ecDir, 0555); err != nil {
		t.Fatalf("failed to create ec dir: %v", err)
	}
	defer func() { _ = os.Chmod(ecDir, 0755) }() // Restore permissions for cleanup

	// Try to install - should fail when writing files
	err := InstallBuiltinProfiles(tmpDir, true)
	if err == nil {
		t.Error("InstallBuiltinProfiles() should fail when writing to read-only directory")
	}
}
