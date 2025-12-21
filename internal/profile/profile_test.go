package profile

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/remiblancher/pki/internal/crypto"
)

// =============================================================================
// Profile Validation Tests
// =============================================================================

func TestProfile_Validate_ValidClassic(t *testing.T) {
	p := &Profile{
		Name:        "test-classic",
		Description: "Test classic profile",
		Signature: SignatureConfig{
			Required: true,
			Mode:     SignatureSimple,
			Algorithms: AlgorithmPair{
				Primary: crypto.AlgECDSAP256,
			},
		},
		Encryption: EncryptionConfig{
			Required: false,
			Mode:     EncryptionNone,
		},
		Validity: 365 * 24 * time.Hour,
	}

	if err := p.Validate(); err != nil {
		t.Errorf("expected valid profile, got error: %v", err)
	}
}

func TestProfile_Validate_ValidHybridCombined(t *testing.T) {
	p := &Profile{
		Name:        "test-hybrid-combined",
		Description: "Test hybrid combined profile",
		Signature: SignatureConfig{
			Required: true,
			Mode:     SignatureHybridCombined,
			Algorithms: AlgorithmPair{
				Primary:     crypto.AlgECDSAP256,
				Alternative: crypto.AlgMLDSA65,
			},
		},
		Encryption: EncryptionConfig{
			Required: false,
			Mode:     EncryptionNone,
		},
		Validity: 365 * 24 * time.Hour,
	}

	if err := p.Validate(); err != nil {
		t.Errorf("expected valid profile, got error: %v", err)
	}
}

func TestProfile_Validate_ValidHybridSeparate(t *testing.T) {
	p := &Profile{
		Name:        "test-hybrid-separate",
		Description: "Test hybrid separate profile",
		Signature: SignatureConfig{
			Required: true,
			Mode:     SignatureHybridSeparate,
			Algorithms: AlgorithmPair{
				Primary:     crypto.AlgECDSAP384,
				Alternative: crypto.AlgMLDSA87,
			},
		},
		Encryption: EncryptionConfig{
			Required: false,
			Mode:     EncryptionNone,
		},
		Validity: 30 * 24 * time.Hour,
	}

	if err := p.Validate(); err != nil {
		t.Errorf("expected valid profile, got error: %v", err)
	}
}

func TestProfile_Validate_ValidWithEncryption(t *testing.T) {
	p := &Profile{
		Name:        "test-with-encryption",
		Description: "Test profile with encryption",
		Signature: SignatureConfig{
			Required: true,
			Mode:     SignatureSimple,
			Algorithms: AlgorithmPair{
				Primary: crypto.AlgECDSAP256,
			},
		},
		Encryption: EncryptionConfig{
			Required: true,
			Mode:     EncryptionSimple,
			Algorithms: AlgorithmPair{
				Primary: crypto.AlgMLKEM768,
			},
		},
		Validity: 365 * 24 * time.Hour,
	}

	if err := p.Validate(); err != nil {
		t.Errorf("expected valid profile, got error: %v", err)
	}
}

func TestProfile_Validate_EmptyName(t *testing.T) {
	p := &Profile{
		Name: "",
		Signature: SignatureConfig{
			Required: true,
			Mode:     SignatureSimple,
			Algorithms: AlgorithmPair{
				Primary: crypto.AlgECDSAP256,
			},
		},
		Validity: 365 * 24 * time.Hour,
	}

	err := p.Validate()
	if err == nil {
		t.Error("expected error for empty name")
	}
}

func TestProfile_Validate_SignatureNotRequired(t *testing.T) {
	p := &Profile{
		Name: "test",
		Signature: SignatureConfig{
			Required: false, // Signature should always be required
			Mode:     SignatureSimple,
			Algorithms: AlgorithmPair{
				Primary: crypto.AlgECDSAP256,
			},
		},
		Validity: 365 * 24 * time.Hour,
	}

	err := p.Validate()
	if err == nil {
		t.Error("expected error when signature is not required")
	}
}

func TestProfile_Validate_InvalidSignatureMode(t *testing.T) {
	p := &Profile{
		Name: "test",
		Signature: SignatureConfig{
			Required: true,
			Mode:     SignatureMode("invalid-mode"),
			Algorithms: AlgorithmPair{
				Primary: crypto.AlgECDSAP256,
			},
		},
		Validity: 365 * 24 * time.Hour,
	}

	err := p.Validate()
	if err == nil {
		t.Error("expected error for invalid signature mode")
	}
}

func TestProfile_Validate_MissingPrimaryAlgorithm(t *testing.T) {
	p := &Profile{
		Name: "test",
		Signature: SignatureConfig{
			Required:   true,
			Mode:       SignatureSimple,
			Algorithms: AlgorithmPair{},
		},
		Validity: 365 * 24 * time.Hour,
	}

	err := p.Validate()
	if err == nil {
		t.Error("expected error for missing primary algorithm")
	}
}

func TestProfile_Validate_InvalidPrimaryAlgorithm(t *testing.T) {
	p := &Profile{
		Name: "test",
		Signature: SignatureConfig{
			Required: true,
			Mode:     SignatureSimple,
			Algorithms: AlgorithmPair{
				Primary: crypto.AlgorithmID("unknown-algo"),
			},
		},
		Validity: 365 * 24 * time.Hour,
	}

	err := p.Validate()
	if err == nil {
		t.Error("expected error for invalid primary algorithm")
	}
}

func TestProfile_Validate_HybridMissingAlternative(t *testing.T) {
	p := &Profile{
		Name: "test",
		Signature: SignatureConfig{
			Required: true,
			Mode:     SignatureHybridCombined,
			Algorithms: AlgorithmPair{
				Primary: crypto.AlgECDSAP256,
				// Missing Alternative
			},
		},
		Validity: 365 * 24 * time.Hour,
	}

	err := p.Validate()
	if err == nil {
		t.Error("expected error for hybrid mode without alternative algorithm")
	}
}

func TestProfile_Validate_HybridPrimaryNotClassical(t *testing.T) {
	p := &Profile{
		Name: "test",
		Signature: SignatureConfig{
			Required: true,
			Mode:     SignatureHybridCombined,
			Algorithms: AlgorithmPair{
				Primary:     crypto.AlgMLDSA65, // PQC as primary - wrong
				Alternative: crypto.AlgECDSAP256,
			},
		},
		Validity: 365 * 24 * time.Hour,
	}

	err := p.Validate()
	if err == nil {
		t.Error("expected error when hybrid primary is PQC")
	}
}

func TestProfile_Validate_HybridAlternativeNotPQC(t *testing.T) {
	p := &Profile{
		Name: "test",
		Signature: SignatureConfig{
			Required: true,
			Mode:     SignatureHybridSeparate,
			Algorithms: AlgorithmPair{
				Primary:     crypto.AlgECDSAP256,
				Alternative: crypto.AlgECDSAP384, // Classical as alternative - wrong
			},
		},
		Validity: 365 * 24 * time.Hour,
	}

	err := p.Validate()
	if err == nil {
		t.Error("expected error when hybrid alternative is not PQC")
	}
}

func TestProfile_Validate_ZeroValidity(t *testing.T) {
	p := &Profile{
		Name: "test",
		Signature: SignatureConfig{
			Required: true,
			Mode:     SignatureSimple,
			Algorithms: AlgorithmPair{
				Primary: crypto.AlgECDSAP256,
			},
		},
		Validity: 0,
	}

	err := p.Validate()
	if err == nil {
		t.Error("expected error for zero validity")
	}
}

func TestProfile_Validate_NegativeValidity(t *testing.T) {
	p := &Profile{
		Name: "test",
		Signature: SignatureConfig{
			Required: true,
			Mode:     SignatureSimple,
			Algorithms: AlgorithmPair{
				Primary: crypto.AlgECDSAP256,
			},
		},
		Validity: -24 * time.Hour,
	}

	err := p.Validate()
	if err == nil {
		t.Error("expected error for negative validity")
	}
}

// =============================================================================
// CertificateCount Tests
// =============================================================================

func TestProfile_CertificateCount_Simple(t *testing.T) {
	p := &Profile{
		Signature: SignatureConfig{
			Mode: SignatureSimple,
		},
		Encryption: EncryptionConfig{
			Required: false,
		},
	}

	if count := p.CertificateCount(); count != 1 {
		t.Errorf("expected 1 certificate, got %d", count)
	}
}

func TestProfile_CertificateCount_HybridCombined(t *testing.T) {
	p := &Profile{
		Signature: SignatureConfig{
			Mode: SignatureHybridCombined,
		},
		Encryption: EncryptionConfig{
			Required: false,
		},
	}

	if count := p.CertificateCount(); count != 1 {
		t.Errorf("expected 1 certificate for Catalyst, got %d", count)
	}
}

func TestProfile_CertificateCount_HybridSeparate(t *testing.T) {
	p := &Profile{
		Signature: SignatureConfig{
			Mode: SignatureHybridSeparate,
		},
		Encryption: EncryptionConfig{
			Required: false,
		},
	}

	if count := p.CertificateCount(); count != 2 {
		t.Errorf("expected 2 certificates for separate hybrid, got %d", count)
	}
}

func TestProfile_CertificateCount_WithSimpleEncryption(t *testing.T) {
	p := &Profile{
		Signature: SignatureConfig{
			Mode: SignatureSimple,
		},
		Encryption: EncryptionConfig{
			Required: true,
			Mode:     EncryptionSimple,
		},
	}

	if count := p.CertificateCount(); count != 2 {
		t.Errorf("expected 2 certificates (sig + enc), got %d", count)
	}
}

func TestProfile_CertificateCount_HybridBoth(t *testing.T) {
	p := &Profile{
		Signature: SignatureConfig{
			Mode: SignatureHybridSeparate, // 2 certs
		},
		Encryption: EncryptionConfig{
			Required: true,
			Mode:     EncryptionHybridSeparate, // 2 certs
		},
	}

	if count := p.CertificateCount(); count != 4 {
		t.Errorf("expected 4 certificates, got %d", count)
	}
}

// =============================================================================
// Helper Method Tests
// =============================================================================

func TestProfile_IsHybridSignature(t *testing.T) {
	tests := []struct {
		name     string
		mode     SignatureMode
		expected bool
	}{
		{"simple", SignatureSimple, false},
		{"hybrid-combined", SignatureHybridCombined, true},
		{"hybrid-separate", SignatureHybridSeparate, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Profile{Signature: SignatureConfig{Mode: tt.mode}}
			if got := p.IsHybridSignature(); got != tt.expected {
				t.Errorf("IsHybridSignature() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestProfile_IsCatalystSignature(t *testing.T) {
	tests := []struct {
		name     string
		mode     SignatureMode
		expected bool
	}{
		{"simple", SignatureSimple, false},
		{"hybrid-combined", SignatureHybridCombined, true},
		{"hybrid-separate", SignatureHybridSeparate, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Profile{Signature: SignatureConfig{Mode: tt.mode}}
			if got := p.IsCatalystSignature(); got != tt.expected {
				t.Errorf("IsCatalystSignature() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestProfile_RequiresEncryption(t *testing.T) {
	tests := []struct {
		name     string
		required bool
		mode     EncryptionMode
		expected bool
	}{
		{"not required", false, EncryptionNone, false},
		{"required none", true, EncryptionNone, false},
		{"required simple", true, EncryptionSimple, true},
		{"required hybrid", true, EncryptionHybridCombined, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Profile{Encryption: EncryptionConfig{Required: tt.required, Mode: tt.mode}}
			if got := p.RequiresEncryption(); got != tt.expected {
				t.Errorf("RequiresEncryption() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestProfile_String(t *testing.T) {
	p := &Profile{
		Name: "test-profile",
		Signature: SignatureConfig{
			Mode: SignatureHybridCombined,
			Algorithms: AlgorithmPair{
				Primary:     crypto.AlgECDSAP256,
				Alternative: crypto.AlgMLDSA65,
			},
		},
		Encryption: EncryptionConfig{
			Required: true,
			Mode:     EncryptionSimple,
			Algorithms: AlgorithmPair{
				Primary: crypto.AlgMLKEM768,
			},
		},
		Validity: 365 * 24 * time.Hour,
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

func TestLoadProfileFromBytes_Valid(t *testing.T) {
	yaml := `
name: test-profile
description: Test profile
signature:
  algorithms:
    - ec-p256
validity: 365d
`
	p, err := LoadProfileFromBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("LoadProfileFromBytes failed: %v", err)
	}

	if p.Name != "test-profile" {
		t.Errorf("expected name 'test-profile', got '%s'", p.Name)
	}
	if p.Signature.Mode != SignatureSimple {
		t.Errorf("expected mode SignatureSimple, got '%s'", p.Signature.Mode)
	}
	if p.Validity != 365*24*time.Hour {
		t.Errorf("expected validity 365 days, got %v", p.Validity)
	}
}

func TestLoadProfileFromBytes_HybridCombined(t *testing.T) {
	yaml := `
name: hybrid-test
description: Hybrid test
signature:
  mode: catalyst
  algorithms:
    - ec-p384
    - ml-dsa-65
validity: 8760h
`
	p, err := LoadProfileFromBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("LoadProfileFromBytes failed: %v", err)
	}

	if p.Signature.Mode != SignatureHybridCombined {
		t.Errorf("expected mode SignatureHybridCombined, got '%s'", p.Signature.Mode)
	}
	if p.Signature.Algorithms.Primary != crypto.AlgECP384 {
		t.Errorf("expected primary ec-p384, got '%s'", p.Signature.Algorithms.Primary)
	}
	if p.Signature.Algorithms.Alternative != crypto.AlgMLDSA65 {
		t.Errorf("expected alternative ml-dsa-65, got '%s'", p.Signature.Algorithms.Alternative)
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
signature:
  algorithms:
    - ec-p256
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
signature:
  algorithms:
    - ec-p256
validity: 365d
`
	profile2 := `
name: profile-two
signature:
  algorithms:
    - ec-p384
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
signature:
  algorithms:
    - ec-p256
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
		Signature: SignatureConfig{
			Required: true,
			Mode:     SignatureSimple,
			Algorithms: AlgorithmPair{
				Primary: crypto.AlgECDSAP256,
			},
		},
		Encryption: EncryptionConfig{
			Required: false,
			Mode:     EncryptionNone,
		},
		Validity: 365 * 24 * time.Hour,
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
	if loaded.Signature.Mode != p.Signature.Mode {
		t.Errorf("expected mode '%s', got '%s'", p.Signature.Mode, loaded.Signature.Mode)
	}
}

func TestProfileStore_List(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewProfileStore(tmpDir)

	profiles := []*Profile{
		{
			Name: "profile-a",
			Signature: SignatureConfig{
				Required:   true,
				Mode:       SignatureSimple,
				Algorithms: AlgorithmPair{Primary: crypto.AlgECDSAP256},
			},
			Validity: 365 * 24 * time.Hour,
		},
		{
			Name: "profile-b",
			Signature: SignatureConfig{
				Required:   true,
				Mode:       SignatureSimple,
				Algorithms: AlgorithmPair{Primary: crypto.AlgECDSAP256},
			},
			Validity: 365 * 24 * time.Hour,
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
		Name: "all-test",
		Signature: SignatureConfig{
			Required:   true,
			Mode:       SignatureSimple,
			Algorithms: AlgorithmPair{Primary: crypto.AlgECDSAP256},
		},
		Validity: 365 * 24 * time.Hour,
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
	expectedNames := []string{"ec/root-ca", "hybrid/catalyst/root-ca", "ml-dsa-kem/root-ca"}
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
		Signature: SignatureConfig{
			Required: true,
			Mode:     SignatureHybridCombined,
			Algorithms: AlgorithmPair{
				Primary:     crypto.AlgECDSAP256,
				Alternative: crypto.AlgMLDSA65,
			},
		},
		Encryption: EncryptionConfig{
			Required: false,
			Mode:     EncryptionNone,
		},
		Validity: 30 * 24 * time.Hour,
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
	if loaded.Signature.Mode != p.Signature.Mode {
		t.Errorf("expected mode '%s', got '%s'", p.Signature.Mode, loaded.Signature.Mode)
	}
	if loaded.Validity != p.Validity {
		t.Errorf("expected validity %v, got %v", p.Validity, loaded.Validity)
	}
}
