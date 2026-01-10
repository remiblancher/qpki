package ca

import (
	"context"
	"strings"
	"testing"
	"time"

	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
	"github.com/remiblancher/post-quantum-pki/internal/profile"
)

// =============================================================================
// RotateCARequest Tests
// =============================================================================

func TestRotateCARequest_Fields(t *testing.T) {
	req := RotateCARequest{
		CADir:      "/test/ca",
		Profile:    "test-profile",
		Passphrase: "testpass",
		CrossSign:  true,
		DryRun:     true,
	}

	if req.CADir != "/test/ca" {
		t.Errorf("CADir = %s, want /test/ca", req.CADir)
	}
	if req.Profile != "test-profile" {
		t.Errorf("Profile = %s, want test-profile", req.Profile)
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
// RotateCAPlan Tests
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
		Steps: []string{
			"Create new version",
			"Generate keys",
			"Cross-sign",
		},
	}

	if plan.CurrentVersion != "v1" {
		t.Errorf("CurrentVersion = %s, want v1", plan.CurrentVersion)
	}
	if plan.NewVersion != "v2" {
		t.Errorf("NewVersion = %s, want v2", plan.NewVersion)
	}
	if plan.Profile != "test-profile" {
		t.Errorf("Profile = %s, want test-profile", plan.Profile)
	}
	if plan.Algorithm != "ECDSA-P256" {
		t.Errorf("Algorithm = %s, want ECDSA-P256", plan.Algorithm)
	}
	if plan.Subject != "CN=Test CA" {
		t.Errorf("Subject = %s, want CN=Test CA", plan.Subject)
	}
	if !plan.WillCrossSign {
		t.Error("WillCrossSign should be true")
	}
	if plan.CrossSignReason != "algorithm changed" {
		t.Errorf("CrossSignReason = %s, want 'algorithm changed'", plan.CrossSignReason)
	}
	if len(plan.Steps) != 3 {
		t.Errorf("Steps length = %d, want 3", len(plan.Steps))
	}
}

// =============================================================================
// RotateCAResult Tests
// =============================================================================

func TestRotateCAResult_Fields(t *testing.T) {
	plan := &RotateCAPlan{
		NewVersion: "v2",
	}

	result := &RotateCAResult{
		Plan:            plan,
		NewCA:           nil,
		Version:         nil,
		CrossSignedCert: nil,
	}

	if result.Plan != plan {
		t.Error("Plan should match")
	}
	if result.NewCA != nil {
		t.Error("NewCA should be nil")
	}
	if result.Version != nil {
		t.Error("Version should be nil")
	}
	if result.CrossSignedCert != nil {
		t.Error("CrossSignedCert should be nil")
	}
}

// =============================================================================
// RotateCA Tests
// =============================================================================

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

func TestRotateCA_DryRun(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

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
		t.Fatalf("Save profile error = %v", err)
	}

	req := RotateCARequest{
		CADir:   tmpDir,
		Profile: "test-profile",
		DryRun:  true,
	}

	result, err := RotateCA(req)
	if err != nil {
		t.Fatalf("RotateCA(DryRun) error = %v", err)
	}

	if result == nil {
		t.Fatal("RotateCA(DryRun) returned nil result")
	}

	if result.Plan == nil {
		t.Fatal("RotateCA(DryRun) result has nil Plan")
	}

	// DryRun should not create new CA
	if result.NewCA != nil {
		t.Error("RotateCA(DryRun) should not create new CA")
	}

	// DryRun should not create version
	if result.Version != nil {
		t.Error("RotateCA(DryRun) should not create version")
	}

	// Plan should have steps
	if len(result.Plan.Steps) == 0 {
		t.Error("RotateCA(DryRun) plan should have steps")
	}
}

func TestRotateCA_ProfileNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

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

	// Don't create profile store
	req := RotateCARequest{
		CADir:   tmpDir,
		Profile: "nonexistent-profile",
		DryRun:  true,
	}

	_, err = RotateCA(req)
	if err == nil {
		t.Error("RotateCA() should fail when profile not found")
	}
}

func TestRotateCA_HybridProfileShowsBothAlgorithms(t *testing.T) {
	tests := []struct {
		name           string
		mode           profile.Mode
		algorithms     []pkicrypto.AlgorithmID
		wantContains   string
		wantAlgorithms []string
	}{
		{
			name:           "Catalyst shows both algorithms",
			mode:           profile.ModeCatalyst,
			algorithms:     []pkicrypto.AlgorithmID{pkicrypto.AlgECDSAP384, pkicrypto.AlgMLDSA87},
			wantContains:   "+",
			wantAlgorithms: []string{"ecdsa-p384", "ml-dsa-87"},
		},
		{
			name:           "Composite shows both algorithms",
			mode:           profile.ModeComposite,
			algorithms:     []pkicrypto.AlgorithmID{pkicrypto.AlgECDSAP256, pkicrypto.AlgMLDSA65},
			wantContains:   "+",
			wantAlgorithms: []string{"ecdsa-p256", "ml-dsa-65"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			store := NewFileStore(tmpDir)

			// Initialize classical CA
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

			// Create hybrid profile
			prof := &profile.Profile{
				Name:       "hybrid-profile",
				Mode:       tt.mode,
				Algorithms: tt.algorithms,
				Validity:   10 * 365 * 24 * time.Hour,
			}

			profileStore := profile.NewProfileStore(tmpDir)
			if err := profileStore.Save(prof); err != nil {
				t.Fatalf("Save profile error = %v", err)
			}

			// DryRun rotation to hybrid profile
			req := RotateCARequest{
				CADir:   tmpDir,
				Profile: "hybrid-profile",
				DryRun:  true,
			}

			result, err := RotateCA(req)
			if err != nil {
				t.Fatalf("RotateCA(DryRun) error = %v", err)
			}

			if result == nil || result.Plan == nil {
				t.Fatal("RotateCA(DryRun) returned nil result or plan")
			}

			// Verify plan.Algorithm contains "+" separator (both algorithms)
			if !strings.Contains(result.Plan.Algorithm, tt.wantContains) {
				t.Errorf("Plan.Algorithm = %q, want to contain %q", result.Plan.Algorithm, tt.wantContains)
			}

			// Verify both algorithm names are present
			for _, alg := range tt.wantAlgorithms {
				if !strings.Contains(result.Plan.Algorithm, alg) {
					t.Errorf("Plan.Algorithm = %q, want to contain %q", result.Plan.Algorithm, alg)
				}
			}
		})
	}
}

// =============================================================================
// buildRotationSteps Tests
// =============================================================================

func TestBuildRotationSteps(t *testing.T) {
	tests := []struct {
		name          string
		versionID     string
		profile       string
		willCrossSign bool
		wantMinSteps  int
	}{
		{"without cross-sign", "v1", "test-profile", false, 5},
		{"with cross-sign", "v2", "test-profile", true, 7},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			steps := buildRotationSteps(tt.versionID, tt.profile, tt.willCrossSign)
			if len(steps) < tt.wantMinSteps {
				t.Errorf("buildRotationSteps() returned %d steps, want at least %d",
					len(steps), tt.wantMinSteps)
			}
		})
	}
}

// =============================================================================
// firstOrEmpty Tests
// =============================================================================

func TestFirstOrEmpty(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  string
	}{
		{"empty slice", []string{}, ""},
		{"nil slice", nil, ""},
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

// =============================================================================
// determineCurrentProfile Tests
// =============================================================================

func TestDetermineCurrentProfile_NoMetadata(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize store without metadata
	if err := store.Init(context.Background()); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	profile := determineCurrentProfile(store)
	if profile != "" {
		t.Errorf("determineCurrentProfile() = %s, want empty string", profile)
	}
}

// =============================================================================
// parseJSON Tests
// =============================================================================

func TestParseJSON(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{"valid JSON", []byte(`{"key": "value"}`), false},
		{"invalid JSON", []byte(`{invalid}`), true},
		{"empty JSON", []byte(`{}`), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var v map[string]interface{}
			err := parseJSON(tt.data, &v)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// =============================================================================
// initializeCAInDir Tests
// =============================================================================

func TestInitializeCAInDir_Classical(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test CA",
		Organization:  "Test Org",
		Country:       "US",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := initializeCAInDir(store, cfg)
	if err != nil {
		t.Fatalf("initializeCAInDir() error = %v", err)
	}

	if ca == nil {
		t.Fatal("initializeCAInDir() returned nil CA")
	}

	cert := ca.Certificate()
	if cert == nil {
		t.Fatal("CA certificate is nil")
	}

	if cert.Subject.CommonName != "Test CA" {
		t.Errorf("CN = %s, want Test CA", cert.Subject.CommonName)
	}
}

func TestInitializeCAInDir_RSA(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test RSA CA",
		Algorithm:     pkicrypto.AlgRSA2048,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := initializeCAInDir(store, cfg)
	if err != nil {
		t.Fatalf("initializeCAInDir(RSA) error = %v", err)
	}

	if ca == nil {
		t.Fatal("initializeCAInDir(RSA) returned nil CA")
	}

	cert := ca.Certificate()
	if cert == nil {
		t.Fatal("CA certificate is nil")
	}

	if cert.Subject.CommonName != "Test RSA CA" {
		t.Errorf("CN = %s, want Test RSA CA", cert.Subject.CommonName)
	}
}

func TestInitializeCAInDir_Ed25519(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Ed25519 CA",
		Algorithm:     pkicrypto.AlgEd25519,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := initializeCAInDir(store, cfg)
	if err != nil {
		t.Fatalf("initializeCAInDir(Ed25519) error = %v", err)
	}

	if ca == nil {
		t.Fatal("initializeCAInDir(Ed25519) returned nil CA")
	}

	cert := ca.Certificate()
	if cert == nil {
		t.Fatal("CA certificate is nil")
	}

	if cert.Subject.CommonName != "Test Ed25519 CA" {
		t.Errorf("CN = %s, want Test Ed25519 CA", cert.Subject.CommonName)
	}
}

func TestInitializeCAInDir_WithPassphrase(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test CA",
		Algorithm:     pkicrypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
		Passphrase:    "testpass",
	}

	ca, err := initializeCAInDir(store, cfg)
	if err != nil {
		t.Fatalf("initializeCAInDir() error = %v", err)
	}

	if ca == nil {
		t.Fatal("initializeCAInDir() returned nil CA")
	}
}

// =============================================================================
// initializePQCCAInDir Tests
// =============================================================================

func TestInitializePQCCAInDir_MLDSA65(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test PQC CA",
		Algorithm:     pkicrypto.AlgMLDSA65,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := initializePQCCAInDir(store, cfg)
	if err != nil {
		t.Fatalf("initializePQCCAInDir(ML-DSA-65) error = %v", err)
	}

	if ca == nil {
		t.Fatal("initializePQCCAInDir(ML-DSA-65) returned nil CA")
	}

	cert := ca.Certificate()
	if cert == nil {
		t.Fatal("CA certificate is nil")
	}

	if cert.Subject.CommonName != "Test PQC CA" {
		t.Errorf("CN = %s, want Test PQC CA", cert.Subject.CommonName)
	}
}

func TestInitializePQCCAInDir_MLDSA87(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test PQC CA 87",
		Algorithm:     pkicrypto.AlgMLDSA87,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := initializePQCCAInDir(store, cfg)
	if err != nil {
		t.Fatalf("initializePQCCAInDir(ML-DSA-87) error = %v", err)
	}

	if ca == nil {
		t.Fatal("initializePQCCAInDir(ML-DSA-87) returned nil CA")
	}
}

// =============================================================================
// initializeHybridCAInDir Tests
// =============================================================================

func TestInitializeHybridCAInDir(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := HybridCAConfig{
		CommonName:         "Test Hybrid CA",
		Organization:       "Test Org",
		Country:            "US",
		ClassicalAlgorithm: pkicrypto.AlgECDSAP384,
		PQCAlgorithm:       pkicrypto.AlgMLDSA87,
		ValidityYears:      10,
		PathLen:            1,
	}

	ca, err := initializeHybridCAInDir(store, cfg)
	if err != nil {
		t.Fatalf("initializeHybridCAInDir() error = %v", err)
	}

	if ca == nil {
		t.Fatal("initializeHybridCAInDir() returned nil CA")
	}

	cert := ca.Certificate()
	if cert == nil {
		t.Fatal("CA certificate is nil")
	}

	if cert.Subject.CommonName != "Test Hybrid CA" {
		t.Errorf("CN = %s, want Test Hybrid CA", cert.Subject.CommonName)
	}
}

func TestInitializeHybridCAInDir_WithPassphrase(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := HybridCAConfig{
		CommonName:         "Test Hybrid CA",
		ClassicalAlgorithm: pkicrypto.AlgECDSAP256,
		PQCAlgorithm:       pkicrypto.AlgMLDSA65,
		ValidityYears:      10,
		PathLen:            1,
		Passphrase:         "testpass",
	}

	ca, err := initializeHybridCAInDir(store, cfg)
	if err != nil {
		t.Fatalf("initializeHybridCAInDir() error = %v", err)
	}

	if ca == nil {
		t.Fatal("initializeHybridCAInDir() returned nil CA")
	}
}

// =============================================================================
// crossSign Tests
// =============================================================================

func TestCrossSign_Classical(t *testing.T) {
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

	// Cross-sign new CA with old CA
	crossSignedCert, err := crossSign(oldCA, newCA)
	if err != nil {
		t.Fatalf("crossSign() error = %v", err)
	}

	if crossSignedCert == nil {
		t.Fatal("crossSign() returned nil certificate")
	}

	// Verify cross-signed cert has new CA's subject
	if crossSignedCert.Subject.CommonName != "New CA" {
		t.Errorf("Subject CN = %s, want New CA", crossSignedCert.Subject.CommonName)
	}

	// Verify cross-signed cert is signed by old CA
	if crossSignedCert.Issuer.CommonName != "Old CA" {
		t.Errorf("Issuer CN = %s, want Old CA", crossSignedCert.Issuer.CommonName)
	}
}
