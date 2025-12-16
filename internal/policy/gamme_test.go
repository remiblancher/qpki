package policy

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/remiblancher/pki/internal/crypto"
)

// =============================================================================
// Gamme Validation Tests
// =============================================================================

func TestGamme_Validate_ValidClassic(t *testing.T) {
	g := &Gamme{
		Name:        "test-classic",
		Description: "Test classic gamme",
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

	if err := g.Validate(); err != nil {
		t.Errorf("expected valid gamme, got error: %v", err)
	}
}

func TestGamme_Validate_ValidHybridCombined(t *testing.T) {
	g := &Gamme{
		Name:        "test-hybrid-combined",
		Description: "Test hybrid combined gamme",
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

	if err := g.Validate(); err != nil {
		t.Errorf("expected valid gamme, got error: %v", err)
	}
}

func TestGamme_Validate_ValidHybridSeparate(t *testing.T) {
	g := &Gamme{
		Name:        "test-hybrid-separate",
		Description: "Test hybrid separate gamme",
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

	if err := g.Validate(); err != nil {
		t.Errorf("expected valid gamme, got error: %v", err)
	}
}

func TestGamme_Validate_ValidWithEncryption(t *testing.T) {
	g := &Gamme{
		Name:        "test-with-encryption",
		Description: "Test gamme with encryption",
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

	if err := g.Validate(); err != nil {
		t.Errorf("expected valid gamme, got error: %v", err)
	}
}

func TestGamme_Validate_EmptyName(t *testing.T) {
	g := &Gamme{
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

	err := g.Validate()
	if err == nil {
		t.Error("expected error for empty name")
	}
}

func TestGamme_Validate_SignatureNotRequired(t *testing.T) {
	g := &Gamme{
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

	err := g.Validate()
	if err == nil {
		t.Error("expected error when signature is not required")
	}
}

func TestGamme_Validate_InvalidSignatureMode(t *testing.T) {
	g := &Gamme{
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

	err := g.Validate()
	if err == nil {
		t.Error("expected error for invalid signature mode")
	}
}

func TestGamme_Validate_MissingPrimaryAlgorithm(t *testing.T) {
	g := &Gamme{
		Name: "test",
		Signature: SignatureConfig{
			Required:   true,
			Mode:       SignatureSimple,
			Algorithms: AlgorithmPair{},
		},
		Validity: 365 * 24 * time.Hour,
	}

	err := g.Validate()
	if err == nil {
		t.Error("expected error for missing primary algorithm")
	}
}

func TestGamme_Validate_InvalidPrimaryAlgorithm(t *testing.T) {
	g := &Gamme{
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

	err := g.Validate()
	if err == nil {
		t.Error("expected error for invalid primary algorithm")
	}
}

func TestGamme_Validate_HybridMissingAlternative(t *testing.T) {
	g := &Gamme{
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

	err := g.Validate()
	if err == nil {
		t.Error("expected error for hybrid mode without alternative algorithm")
	}
}

func TestGamme_Validate_HybridPrimaryNotClassical(t *testing.T) {
	g := &Gamme{
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

	err := g.Validate()
	if err == nil {
		t.Error("expected error when hybrid primary is PQC")
	}
}

func TestGamme_Validate_HybridAlternativeNotPQC(t *testing.T) {
	g := &Gamme{
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

	err := g.Validate()
	if err == nil {
		t.Error("expected error when hybrid alternative is not PQC")
	}
}

func TestGamme_Validate_ZeroValidity(t *testing.T) {
	g := &Gamme{
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

	err := g.Validate()
	if err == nil {
		t.Error("expected error for zero validity")
	}
}

func TestGamme_Validate_NegativeValidity(t *testing.T) {
	g := &Gamme{
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

	err := g.Validate()
	if err == nil {
		t.Error("expected error for negative validity")
	}
}

func TestGamme_Validate_EncryptionModeWithoutRequired(t *testing.T) {
	g := &Gamme{
		Name: "test",
		Signature: SignatureConfig{
			Required: true,
			Mode:     SignatureSimple,
			Algorithms: AlgorithmPair{
				Primary: crypto.AlgECDSAP256,
			},
		},
		Encryption: EncryptionConfig{
			Required: false,
			Mode:     EncryptionSimple, // Mode set but not required
			Algorithms: AlgorithmPair{
				Primary: crypto.AlgMLKEM768,
			},
		},
		Validity: 365 * 24 * time.Hour,
	}

	err := g.Validate()
	if err == nil {
		t.Error("expected error when encryption mode is set but not required")
	}
}

func TestGamme_Validate_InvalidEncryptionMode(t *testing.T) {
	g := &Gamme{
		Name: "test",
		Signature: SignatureConfig{
			Required: true,
			Mode:     SignatureSimple,
			Algorithms: AlgorithmPair{
				Primary: crypto.AlgECDSAP256,
			},
		},
		Encryption: EncryptionConfig{
			Required: true,
			Mode:     EncryptionMode("invalid"),
			Algorithms: AlgorithmPair{
				Primary: crypto.AlgMLKEM768,
			},
		},
		Validity: 365 * 24 * time.Hour,
	}

	err := g.Validate()
	if err == nil {
		t.Error("expected error for invalid encryption mode")
	}
}

func TestGamme_Validate_EncryptionMissingAlgorithm(t *testing.T) {
	g := &Gamme{
		Name: "test",
		Signature: SignatureConfig{
			Required: true,
			Mode:     SignatureSimple,
			Algorithms: AlgorithmPair{
				Primary: crypto.AlgECDSAP256,
			},
		},
		Encryption: EncryptionConfig{
			Required:   true,
			Mode:       EncryptionSimple,
			Algorithms: AlgorithmPair{}, // Missing algorithm
		},
		Validity: 365 * 24 * time.Hour,
	}

	err := g.Validate()
	if err == nil {
		t.Error("expected error for encryption without algorithm")
	}
}

// =============================================================================
// CertificateCount Tests
// =============================================================================

func TestGamme_CertificateCount_Simple(t *testing.T) {
	g := &Gamme{
		Signature: SignatureConfig{
			Mode: SignatureSimple,
		},
		Encryption: EncryptionConfig{
			Required: false,
		},
	}

	if count := g.CertificateCount(); count != 1 {
		t.Errorf("expected 1 certificate, got %d", count)
	}
}

func TestGamme_CertificateCount_HybridCombined(t *testing.T) {
	g := &Gamme{
		Signature: SignatureConfig{
			Mode: SignatureHybridCombined,
		},
		Encryption: EncryptionConfig{
			Required: false,
		},
	}

	if count := g.CertificateCount(); count != 1 {
		t.Errorf("expected 1 certificate for Catalyst, got %d", count)
	}
}

func TestGamme_CertificateCount_HybridSeparate(t *testing.T) {
	g := &Gamme{
		Signature: SignatureConfig{
			Mode: SignatureHybridSeparate,
		},
		Encryption: EncryptionConfig{
			Required: false,
		},
	}

	if count := g.CertificateCount(); count != 2 {
		t.Errorf("expected 2 certificates for separate hybrid, got %d", count)
	}
}

func TestGamme_CertificateCount_WithSimpleEncryption(t *testing.T) {
	g := &Gamme{
		Signature: SignatureConfig{
			Mode: SignatureSimple,
		},
		Encryption: EncryptionConfig{
			Required: true,
			Mode:     EncryptionSimple,
		},
	}

	if count := g.CertificateCount(); count != 2 {
		t.Errorf("expected 2 certificates (sig + enc), got %d", count)
	}
}

func TestGamme_CertificateCount_HybridBoth(t *testing.T) {
	g := &Gamme{
		Signature: SignatureConfig{
			Mode: SignatureHybridSeparate, // 2 certs
		},
		Encryption: EncryptionConfig{
			Required: true,
			Mode:     EncryptionHybridSeparate, // 2 certs
		},
	}

	if count := g.CertificateCount(); count != 4 {
		t.Errorf("expected 4 certificates, got %d", count)
	}
}

func TestGamme_CertificateCount_CatalystWithCatalystEnc(t *testing.T) {
	g := &Gamme{
		Signature: SignatureConfig{
			Mode: SignatureHybridCombined, // 1 cert (Catalyst)
		},
		Encryption: EncryptionConfig{
			Required: true,
			Mode:     EncryptionHybridCombined, // 1 cert (Catalyst)
		},
	}

	if count := g.CertificateCount(); count != 2 {
		t.Errorf("expected 2 certificates, got %d", count)
	}
}

// =============================================================================
// Helper Method Tests
// =============================================================================

func TestGamme_IsHybridSignature(t *testing.T) {
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
			g := &Gamme{Signature: SignatureConfig{Mode: tt.mode}}
			if got := g.IsHybridSignature(); got != tt.expected {
				t.Errorf("IsHybridSignature() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGamme_IsCatalystSignature(t *testing.T) {
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
			g := &Gamme{Signature: SignatureConfig{Mode: tt.mode}}
			if got := g.IsCatalystSignature(); got != tt.expected {
				t.Errorf("IsCatalystSignature() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGamme_IsHybridEncryption(t *testing.T) {
	tests := []struct {
		name     string
		mode     EncryptionMode
		expected bool
	}{
		{"none", EncryptionNone, false},
		{"simple", EncryptionSimple, false},
		{"hybrid-combined", EncryptionHybridCombined, true},
		{"hybrid-separate", EncryptionHybridSeparate, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := &Gamme{Encryption: EncryptionConfig{Mode: tt.mode}}
			if got := g.IsHybridEncryption(); got != tt.expected {
				t.Errorf("IsHybridEncryption() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGamme_IsCatalystEncryption(t *testing.T) {
	tests := []struct {
		name     string
		mode     EncryptionMode
		expected bool
	}{
		{"none", EncryptionNone, false},
		{"simple", EncryptionSimple, false},
		{"hybrid-combined", EncryptionHybridCombined, true},
		{"hybrid-separate", EncryptionHybridSeparate, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := &Gamme{Encryption: EncryptionConfig{Mode: tt.mode}}
			if got := g.IsCatalystEncryption(); got != tt.expected {
				t.Errorf("IsCatalystEncryption() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGamme_RequiresEncryption(t *testing.T) {
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
			g := &Gamme{Encryption: EncryptionConfig{Required: tt.required, Mode: tt.mode}}
			if got := g.RequiresEncryption(); got != tt.expected {
				t.Errorf("RequiresEncryption() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGamme_String(t *testing.T) {
	g := &Gamme{
		Name: "test-gamme",
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

	s := g.String()

	// Check that the string contains expected information
	if s == "" {
		t.Error("String() returned empty string")
	}
	if !contains(s, "test-gamme") {
		t.Error("String() should contain gamme name")
	}
}

// =============================================================================
// YAML Loading Tests (loader.go)
// =============================================================================

func TestLoadGammeFromBytes_Valid(t *testing.T) {
	yaml := `
name: test-gamme
description: Test gamme
signature:
  required: true
  mode: simple
  algorithms:
    primary: ecdsa-p256
encryption:
  required: false
  mode: none
validity: 365d
`
	g, err := LoadGammeFromBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("LoadGammeFromBytes failed: %v", err)
	}

	if g.Name != "test-gamme" {
		t.Errorf("expected name 'test-gamme', got '%s'", g.Name)
	}
	if g.Signature.Mode != SignatureSimple {
		t.Errorf("expected mode SignatureSimple, got '%s'", g.Signature.Mode)
	}
	if g.Validity != 365*24*time.Hour {
		t.Errorf("expected validity 365 days, got %v", g.Validity)
	}
}

func TestLoadGammeFromBytes_HybridCombined(t *testing.T) {
	yaml := `
name: hybrid-test
description: Hybrid test
signature:
  required: true
  mode: hybrid-combined
  algorithms:
    primary: ecdsa-p384
    alternative: ml-dsa-65
encryption:
  required: false
  mode: none
validity: 8760h
`
	g, err := LoadGammeFromBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("LoadGammeFromBytes failed: %v", err)
	}

	if g.Signature.Mode != SignatureHybridCombined {
		t.Errorf("expected mode SignatureHybridCombined, got '%s'", g.Signature.Mode)
	}
	if g.Signature.Algorithms.Primary != crypto.AlgECDSAP384 {
		t.Errorf("expected primary ecdsa-p384, got '%s'", g.Signature.Algorithms.Primary)
	}
	if g.Signature.Algorithms.Alternative != crypto.AlgMLDSA65 {
		t.Errorf("expected alternative ml-dsa-65, got '%s'", g.Signature.Algorithms.Alternative)
	}
}

func TestLoadGammeFromBytes_InvalidYAML(t *testing.T) {
	yaml := `invalid: yaml: content`

	_, err := LoadGammeFromBytes([]byte(yaml))
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestLoadGammeFromBytes_ValidationFails(t *testing.T) {
	yaml := `
name: ""
signature:
  required: true
  mode: simple
  algorithms:
    primary: ecdsa-p256
validity: 365d
`
	_, err := LoadGammeFromBytes([]byte(yaml))
	if err == nil {
		t.Error("expected validation error for empty name")
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

func TestLoadGammeFromFile(t *testing.T) {
	// Create a temp file
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "test.yaml")

	content := `
name: file-test
description: Test from file
signature:
  required: true
  mode: simple
  algorithms:
    primary: ecdsa-p256
encryption:
  required: false
  mode: none
validity: 30d
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	g, err := LoadGammeFromFile(path)
	if err != nil {
		t.Fatalf("LoadGammeFromFile failed: %v", err)
	}

	if g.Name != "file-test" {
		t.Errorf("expected name 'file-test', got '%s'", g.Name)
	}
}

func TestLoadGammeFromFile_NotFound(t *testing.T) {
	_, err := LoadGammeFromFile("/nonexistent/path/gamme.yaml")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestLoadGammesFromDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	// Create two gamme files
	gamme1 := `
name: gamme-one
signature:
  required: true
  mode: simple
  algorithms:
    primary: ecdsa-p256
encryption:
  required: false
  mode: none
validity: 365d
`
	gamme2 := `
name: gamme-two
signature:
  required: true
  mode: simple
  algorithms:
    primary: ecdsa-p384
encryption:
  required: false
  mode: none
validity: 365d
`
	if err := os.WriteFile(filepath.Join(tmpDir, "one.yaml"), []byte(gamme1), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "two.yaml"), []byte(gamme2), 0644); err != nil {
		t.Fatal(err)
	}

	gammes, err := LoadGammesFromDirectory(tmpDir)
	if err != nil {
		t.Fatalf("LoadGammesFromDirectory failed: %v", err)
	}

	if len(gammes) != 2 {
		t.Errorf("expected 2 gammes, got %d", len(gammes))
	}
	if _, ok := gammes["gamme-one"]; !ok {
		t.Error("expected gamme-one to be loaded")
	}
	if _, ok := gammes["gamme-two"]; !ok {
		t.Error("expected gamme-two to be loaded")
	}
}

func TestLoadGammesFromDirectory_SkipsNonYAML(t *testing.T) {
	tmpDir := t.TempDir()

	gamme := `
name: valid-gamme
signature:
  required: true
  mode: simple
  algorithms:
    primary: ecdsa-p256
encryption:
  required: false
  mode: none
validity: 365d
`
	if err := os.WriteFile(filepath.Join(tmpDir, "valid.yaml"), []byte(gamme), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "readme.txt"), []byte("not a gamme"), 0644); err != nil {
		t.Fatal(err)
	}

	gammes, err := LoadGammesFromDirectory(tmpDir)
	if err != nil {
		t.Fatalf("LoadGammesFromDirectory failed: %v", err)
	}

	if len(gammes) != 1 {
		t.Errorf("expected 1 gamme (skipping .txt), got %d", len(gammes))
	}
}

func TestLoadGammesFromDirectory_DuplicateName(t *testing.T) {
	tmpDir := t.TempDir()

	// Two files with same gamme name
	gamme := `
name: duplicate-name
signature:
  required: true
  mode: simple
  algorithms:
    primary: ecdsa-p256
encryption:
  required: false
  mode: none
validity: 365d
`
	if err := os.WriteFile(filepath.Join(tmpDir, "one.yaml"), []byte(gamme), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "two.yaml"), []byte(gamme), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadGammesFromDirectory(tmpDir)
	if err == nil {
		t.Error("expected error for duplicate gamme names")
	}
}

func TestLoadGammesFromDirectory_Empty(t *testing.T) {
	tmpDir := t.TempDir()

	gammes, err := LoadGammesFromDirectory(tmpDir)
	if err != nil {
		t.Fatalf("LoadGammesFromDirectory failed: %v", err)
	}

	if len(gammes) != 0 {
		t.Errorf("expected 0 gammes for empty directory, got %d", len(gammes))
	}
}

func TestLoadGammesFromDirectory_NonexistentDir(t *testing.T) {
	gammes, err := LoadGammesFromDirectory("/nonexistent/directory")
	if err != nil {
		t.Fatalf("expected no error for nonexistent directory, got: %v", err)
	}
	if len(gammes) != 0 {
		t.Errorf("expected empty map, got %d gammes", len(gammes))
	}
}

// =============================================================================
// GammeStore Tests
// =============================================================================

func TestGammeStore_SaveAndLoad(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewGammeStore(tmpDir)

	g := &Gamme{
		Name:        "store-test",
		Description: "Test gamme for store",
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
	if err := store.Save(g); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Create new store and load
	store2 := NewGammeStore(tmpDir)
	if err := store2.Load(); err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Get
	loaded, ok := store2.Get("store-test")
	if !ok {
		t.Fatal("gamme not found after load")
	}

	if loaded.Name != g.Name {
		t.Errorf("expected name '%s', got '%s'", g.Name, loaded.Name)
	}
	if loaded.Signature.Mode != g.Signature.Mode {
		t.Errorf("expected mode '%s', got '%s'", g.Signature.Mode, loaded.Signature.Mode)
	}
}

func TestGammeStore_List(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewGammeStore(tmpDir)

	gammes := []*Gamme{
		{
			Name: "gamme-a",
			Signature: SignatureConfig{
				Required:   true,
				Mode:       SignatureSimple,
				Algorithms: AlgorithmPair{Primary: crypto.AlgECDSAP256},
			},
			Validity: 365 * 24 * time.Hour,
		},
		{
			Name: "gamme-b",
			Signature: SignatureConfig{
				Required:   true,
				Mode:       SignatureSimple,
				Algorithms: AlgorithmPair{Primary: crypto.AlgECDSAP256},
			},
			Validity: 365 * 24 * time.Hour,
		},
	}

	for _, g := range gammes {
		if err := store.Save(g); err != nil {
			t.Fatalf("Save failed: %v", err)
		}
	}

	names := store.List()
	if len(names) != 2 {
		t.Errorf("expected 2 names, got %d", len(names))
	}
}

func TestGammeStore_All(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewGammeStore(tmpDir)

	g := &Gamme{
		Name: "all-test",
		Signature: SignatureConfig{
			Required:   true,
			Mode:       SignatureSimple,
			Algorithms: AlgorithmPair{Primary: crypto.AlgECDSAP256},
		},
		Validity: 365 * 24 * time.Hour,
	}

	if err := store.Save(g); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	all := store.All()
	if len(all) != 1 {
		t.Errorf("expected 1 gamme, got %d", len(all))
	}
}

func TestGammeStore_BasePath(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewGammeStore(tmpDir)

	expected := filepath.Join(tmpDir, "gammes")
	if store.BasePath() != expected {
		t.Errorf("expected basePath '%s', got '%s'", expected, store.BasePath())
	}
}

// =============================================================================
// Defaults Tests (defaults.go)
// =============================================================================

func TestDefaultGammes(t *testing.T) {
	gammes, err := DefaultGammes()
	if err != nil {
		t.Fatalf("DefaultGammes failed: %v", err)
	}

	if len(gammes) == 0 {
		t.Error("expected at least one default gamme")
	}

	// Check that known gammes exist
	expectedNames := []string{"classic", "hybrid-catalyst", "pqc-basic"}
	for _, name := range expectedNames {
		if _, ok := gammes[name]; !ok {
			t.Errorf("expected default gamme '%s' not found", name)
		}
	}

	// Verify all default gammes are valid
	for name, g := range gammes {
		if err := g.Validate(); err != nil {
			t.Errorf("default gamme '%s' is invalid: %v", name, err)
		}
	}
}

func TestListDefaultGammeNames(t *testing.T) {
	names, err := ListDefaultGammeNames()
	if err != nil {
		t.Fatalf("ListDefaultGammeNames failed: %v", err)
	}

	if len(names) == 0 {
		t.Error("expected at least one default gamme name")
	}
}

func TestGetDefaultGamme(t *testing.T) {
	g, err := GetDefaultGamme("classic")
	if err != nil {
		t.Fatalf("GetDefaultGamme failed: %v", err)
	}

	if g.Name != "classic" {
		t.Errorf("expected name 'classic', got '%s'", g.Name)
	}
}

func TestGetDefaultGamme_NotFound(t *testing.T) {
	_, err := GetDefaultGamme("nonexistent-gamme")
	if err == nil {
		t.Error("expected error for nonexistent gamme")
	}
}

func TestInstallDefaultGammes(t *testing.T) {
	tmpDir := t.TempDir()

	if err := InstallDefaultGammes(tmpDir, false); err != nil {
		t.Fatalf("InstallDefaultGammes failed: %v", err)
	}

	// Check that files were created
	gammesDir := filepath.Join(tmpDir, "gammes")
	entries, err := os.ReadDir(gammesDir)
	if err != nil {
		t.Fatalf("failed to read gammes directory: %v", err)
	}

	if len(entries) == 0 {
		t.Error("expected at least one gamme file to be installed")
	}

	// Verify the installed gammes can be loaded
	gammes, err := LoadGammesFromDirectory(gammesDir)
	if err != nil {
		t.Fatalf("failed to load installed gammes: %v", err)
	}

	if _, ok := gammes["classic"]; !ok {
		t.Error("expected 'classic' gamme to be installed")
	}
}

func TestInstallDefaultGammes_NoOverwrite(t *testing.T) {
	tmpDir := t.TempDir()
	gammesDir := filepath.Join(tmpDir, "gammes")

	// First install
	if err := InstallDefaultGammes(tmpDir, false); err != nil {
		t.Fatalf("InstallDefaultGammes failed: %v", err)
	}

	// Modify a file
	classicPath := filepath.Join(gammesDir, "classic.yaml")
	customContent := []byte("# Custom content\n")
	if err := os.WriteFile(classicPath, customContent, 0644); err != nil {
		t.Fatalf("failed to modify file: %v", err)
	}

	// Second install without overwrite
	if err := InstallDefaultGammes(tmpDir, false); err != nil {
		t.Fatalf("InstallDefaultGammes failed: %v", err)
	}

	// Check that file was not overwritten
	content, err := os.ReadFile(classicPath)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}

	if string(content) != string(customContent) {
		t.Error("file should not have been overwritten")
	}
}

func TestInstallDefaultGammes_Overwrite(t *testing.T) {
	tmpDir := t.TempDir()
	gammesDir := filepath.Join(tmpDir, "gammes")

	// First install
	if err := InstallDefaultGammes(tmpDir, false); err != nil {
		t.Fatalf("InstallDefaultGammes failed: %v", err)
	}

	// Modify a file
	classicPath := filepath.Join(gammesDir, "classic.yaml")
	customContent := []byte("# Custom content\n")
	if err := os.WriteFile(classicPath, customContent, 0644); err != nil {
		t.Fatalf("failed to modify file: %v", err)
	}

	// Second install with overwrite
	if err := InstallDefaultGammes(tmpDir, true); err != nil {
		t.Fatalf("InstallDefaultGammes failed: %v", err)
	}

	// Check that file was overwritten
	content, err := os.ReadFile(classicPath)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}

	if string(content) == string(customContent) {
		t.Error("file should have been overwritten")
	}
}

// =============================================================================
// SaveGammeToFile Tests
// =============================================================================

func TestSaveGammeToFile(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "saved.yaml")

	g := &Gamme{
		Name:        "saved-gamme",
		Description: "A saved gamme",
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

	if err := SaveGammeToFile(g, path); err != nil {
		t.Fatalf("SaveGammeToFile failed: %v", err)
	}

	// Load it back
	loaded, err := LoadGammeFromFile(path)
	if err != nil {
		t.Fatalf("LoadGammeFromFile failed: %v", err)
	}

	if loaded.Name != g.Name {
		t.Errorf("expected name '%s', got '%s'", g.Name, loaded.Name)
	}
	if loaded.Signature.Mode != g.Signature.Mode {
		t.Errorf("expected mode '%s', got '%s'", g.Signature.Mode, loaded.Signature.Mode)
	}
	if loaded.Validity != g.Validity {
		t.Errorf("expected validity %v, got %v", g.Validity, loaded.Validity)
	}
}

// =============================================================================
// Helper Functions
// =============================================================================

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsImpl(s, substr))
}

func containsImpl(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
