package cli

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/remiblancher/qpki/internal/ca"
	"github.com/remiblancher/qpki/internal/crypto"
	"github.com/remiblancher/qpki/internal/profile"
)

// =============================================================================
// ValidateHSMFlags Tests
// =============================================================================

func TestU_ValidateHSMFlags(t *testing.T) {
	tests := []struct {
		name           string
		useExistingKey bool
		keyLabel       string
		keyID          string
		wantErr        bool
	}{
		{
			name:           "[Unit] ValidateHSMFlags: new key with label",
			useExistingKey: false,
			keyLabel:       "my-key",
			keyID:          "",
			wantErr:        false,
		},
		{
			name:           "[Unit] ValidateHSMFlags: new key without label",
			useExistingKey: false,
			keyLabel:       "",
			keyID:          "",
			wantErr:        true,
		},
		{
			name:           "[Unit] ValidateHSMFlags: existing key with label",
			useExistingKey: true,
			keyLabel:       "existing-key",
			keyID:          "",
			wantErr:        false,
		},
		{
			name:           "[Unit] ValidateHSMFlags: existing key with id",
			useExistingKey: true,
			keyLabel:       "",
			keyID:          "key-id-123",
			wantErr:        false,
		},
		{
			name:           "[Unit] ValidateHSMFlags: existing key without label or id",
			useExistingKey: true,
			keyLabel:       "",
			keyID:          "",
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateHSMFlags(tt.useExistingKey, tt.keyLabel, tt.keyID)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateHSMFlags() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// =============================================================================
// ValidateCAHSMInitFlags Tests
// =============================================================================

func TestU_ValidateCAHSMInitFlags(t *testing.T) {
	tests := []struct {
		name           string
		varFile        string
		vars           []string
		profiles       []string
		useExistingKey bool
		keyLabel       string
		keyID          string
		wantErr        bool
	}{
		{
			name:           "[Unit] ValidateCAHSMInitFlags: valid config",
			varFile:        "",
			vars:           nil,
			profiles:       []string{"ec/root-ca"},
			useExistingKey: false,
			keyLabel:       "ca-key",
			wantErr:        false,
		},
		{
			name:           "[Unit] ValidateCAHSMInitFlags: var and var-file conflict",
			varFile:        "vars.yaml",
			vars:           []string{"cn=Test"},
			profiles:       []string{"ec/root-ca"},
			useExistingKey: false,
			keyLabel:       "ca-key",
			wantErr:        true,
		},
		{
			name:           "[Unit] ValidateCAHSMInitFlags: multiple profiles",
			varFile:        "",
			vars:           nil,
			profiles:       []string{"ec/root-ca", "rsa/root-ca"},
			useExistingKey: false,
			keyLabel:       "ca-key",
			wantErr:        true,
		},
		{
			name:           "[Unit] ValidateCAHSMInitFlags: no profiles",
			varFile:        "",
			vars:           nil,
			profiles:       []string{},
			useExistingKey: false,
			keyLabel:       "ca-key",
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCAHSMInitFlags(tt.varFile, tt.vars, tt.profiles, tt.useExistingKey, tt.keyLabel, tt.keyID)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCAHSMInitFlags() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// =============================================================================
// ValidateCAInitSoftwareFlags Tests
// =============================================================================

func TestU_ValidateCAInitSoftwareFlags(t *testing.T) {
	tests := []struct {
		name     string
		varFile  string
		vars     []string
		profiles []string
		wantErr  bool
	}{
		{
			name:     "[Unit] ValidateCAInitSoftwareFlags: valid config",
			varFile:  "",
			vars:     nil,
			profiles: []string{"ec/root-ca"},
			wantErr:  false,
		},
		{
			name:     "[Unit] ValidateCAInitSoftwareFlags: var and var-file conflict",
			varFile:  "vars.yaml",
			vars:     []string{"cn=Test"},
			profiles: []string{"ec/root-ca"},
			wantErr:  true,
		},
		{
			name:     "[Unit] ValidateCAInitSoftwareFlags: no profiles",
			varFile:  "",
			vars:     nil,
			profiles: []string{},
			wantErr:  true,
		},
		{
			name:     "[Unit] ValidateCAInitSoftwareFlags: multiple profiles",
			varFile:  "",
			vars:     nil,
			profiles: []string{"ec/root-ca", "rsa/root-ca"},
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCAInitSoftwareFlags(tt.varFile, tt.vars, tt.profiles)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCAInitSoftwareFlags() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// =============================================================================
// ValidateSubordinateCAFlags Tests
// =============================================================================

func TestU_ValidateSubordinateCAFlags(t *testing.T) {
	tests := []struct {
		name     string
		varFile  string
		vars     []string
		profiles []string
		wantErr  bool
	}{
		{
			name:     "[Unit] ValidateSubordinateCAFlags: valid config",
			varFile:  "",
			vars:     nil,
			profiles: []string{"ec/issuing-ca"},
			wantErr:  false,
		},
		{
			name:     "[Unit] ValidateSubordinateCAFlags: var and var-file conflict",
			varFile:  "vars.yaml",
			vars:     []string{"cn=Test"},
			profiles: []string{"ec/issuing-ca"},
			wantErr:  true,
		},
		{
			name:     "[Unit] ValidateSubordinateCAFlags: multiple profiles",
			varFile:  "",
			vars:     nil,
			profiles: []string{"ec/issuing-ca", "rsa/issuing-ca"},
			wantErr:  true,
		},
		{
			name:     "[Unit] ValidateSubordinateCAFlags: no profiles",
			varFile:  "",
			vars:     nil,
			profiles: []string{},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSubordinateCAFlags(tt.varFile, tt.vars, tt.profiles)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateSubordinateCAFlags() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// =============================================================================
// EncodeCertificates Tests
// =============================================================================

func TestU_EncodeCertificates(t *testing.T) {
	cert := generateTestCert(t)

	t.Run("[Unit] EncodeCertificates: PEM format", func(t *testing.T) {
		data, err := EncodeCertificates([]*x509.Certificate{cert}, "pem")
		if err != nil {
			t.Fatalf("EncodeCertificates() error = %v", err)
		}

		if len(data) == 0 {
			t.Error("EncodeCertificates() returned empty data")
		}

		// Verify it's valid PEM
		if string(data[:27]) != "-----BEGIN CERTIFICATE-----" {
			t.Error("EncodeCertificates() did not return valid PEM")
		}
	})

	t.Run("[Unit] EncodeCertificates: DER format", func(t *testing.T) {
		data, err := EncodeCertificates([]*x509.Certificate{cert}, "der")
		if err != nil {
			t.Fatalf("EncodeCertificates() error = %v", err)
		}

		if len(data) == 0 {
			t.Error("EncodeCertificates() returned empty data")
		}

		// DER should equal raw certificate
		if len(data) != len(cert.Raw) {
			t.Errorf("EncodeCertificates() DER length = %d, want %d", len(data), len(cert.Raw))
		}
	})

	t.Run("[Unit] EncodeCertificates: DER with multiple certs", func(t *testing.T) {
		cert2 := generateTestCert(t)
		_, err := EncodeCertificates([]*x509.Certificate{cert, cert2}, "der")
		if err == nil {
			t.Error("EncodeCertificates() should fail for multiple certs in DER format")
		}
	})

	t.Run("[Unit] EncodeCertificates: PEM with multiple certs", func(t *testing.T) {
		cert2 := generateTestCert(t)
		data, err := EncodeCertificates([]*x509.Certificate{cert, cert2}, "pem")
		if err != nil {
			t.Fatalf("EncodeCertificates() error = %v", err)
		}

		if len(data) == 0 {
			t.Error("EncodeCertificates() returned empty data")
		}
	})
}

// =============================================================================
// WriteExportOutput Tests
// =============================================================================

func TestU_WriteExportOutput(t *testing.T) {
	t.Run("[Unit] WriteExportOutput: write to file", func(t *testing.T) {
		tmpDir := t.TempDir()
		outPath := filepath.Join(tmpDir, "output.pem")

		data := []byte("test certificate data")
		err := WriteExportOutput(data, outPath, 1)
		if err != nil {
			t.Fatalf("WriteExportOutput() error = %v", err)
		}

		// Verify file was created
		written, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatalf("failed to read output file: %v", err)
		}

		if string(written) != string(data) {
			t.Errorf("WriteExportOutput() wrote %q, want %q", written, data)
		}
	})

	t.Run("[Unit] WriteExportOutput: invalid path", func(t *testing.T) {
		data := []byte("test certificate data")
		err := WriteExportOutput(data, "/nonexistent/directory/output.pem", 1)
		if err == nil {
			t.Error("WriteExportOutput() should fail for invalid path")
		}
	})
}

// =============================================================================
// ProfileAlgorithmInfo Tests
// =============================================================================

func TestU_ProfileAlgorithmInfo_Structure(t *testing.T) {
	info := &ProfileAlgorithmInfo{
		Algorithm:     crypto.AlgECDSAP256,
		HybridAlg:     crypto.AlgMLDSA65,
		IsComposite:   false,
		IsCatalyst:    true,
		ValidityYears: 10,
		PathLen:       1,
	}

	if info.Algorithm != crypto.AlgECDSAP256 {
		t.Errorf("ProfileAlgorithmInfo.Algorithm = %s, want %s", info.Algorithm, crypto.AlgECDSAP256)
	}

	if !info.IsCatalyst {
		t.Error("ProfileAlgorithmInfo.IsCatalyst should be true")
	}

	if info.ValidityYears != 10 {
		t.Errorf("ProfileAlgorithmInfo.ValidityYears = %d, want 10", info.ValidityYears)
	}
}

// =============================================================================
// ExtractProfileAlgorithmInfo Tests
// =============================================================================

func TestU_ExtractProfileAlgorithmInfo(t *testing.T) {
	t.Run("[Unit] ExtractProfileAlgorithmInfo: basic profile", func(t *testing.T) {
		prof := &profile.Profile{
			Algorithm: "ecdsa-p256",
			Validity:  365 * 24 * time.Hour,
		}

		info, err := ExtractProfileAlgorithmInfo(prof)
		if err != nil {
			t.Fatalf("ExtractProfileAlgorithmInfo() error = %v", err)
		}

		if info.ValidityYears != 1 {
			t.Errorf("ExtractProfileAlgorithmInfo() ValidityYears = %d, want 1", info.ValidityYears)
		}
	})
}

// =============================================================================
// BuildCAConfigFromProfile Tests
// =============================================================================

func TestU_BuildCAConfigFromProfile(t *testing.T) {
	prof := &profile.Profile{
		Algorithm: "ecdsa-p256",
		Validity:  10 * 365 * 24 * time.Hour,
	}

	subject := pkix.Name{
		CommonName:   "Test CA",
		Organization: []string{"Test Org"},
		Country:      []string{"FR"},
	}

	algInfo := &ProfileAlgorithmInfo{
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	cfg, err := BuildCAConfigFromProfile(prof, subject, algInfo, "secret")
	if err != nil {
		t.Fatalf("BuildCAConfigFromProfile() error = %v", err)
	}

	if cfg.CommonName != "Test CA" {
		t.Errorf("BuildCAConfigFromProfile() CommonName = %s, want Test CA", cfg.CommonName)
	}

	if cfg.ValidityYears != 10 {
		t.Errorf("BuildCAConfigFromProfile() ValidityYears = %d, want 10", cfg.ValidityYears)
	}
}

func TestU_BuildCAConfigFromProfile_HybridError(t *testing.T) {
	prof := &profile.Profile{
		Algorithm: "ecdsa-p256",
		Validity:  10 * 365 * 24 * time.Hour,
	}

	subject := pkix.Name{
		CommonName: "Test CA",
	}

	// Non-PQC hybrid algorithm should fail
	algInfo := &ProfileAlgorithmInfo{
		Algorithm:     crypto.AlgECDSAP256,
		HybridAlg:     crypto.AlgECDSAP384, // Not a PQC algorithm
		ValidityYears: 10,
		PathLen:       1,
	}

	_, err := BuildCAConfigFromProfile(prof, subject, algInfo, "secret")
	if err == nil {
		t.Error("BuildCAConfigFromProfile() should fail for non-PQC hybrid algorithm")
	}
}

// =============================================================================
// ExtractProfileAlgorithmInfo Extended Tests
// =============================================================================

func TestU_ExtractProfileAlgorithmInfo_ShortValidity(t *testing.T) {
	prof := &profile.Profile{
		Algorithm: "ecdsa-p256",
		Validity:  30 * 24 * time.Hour, // 30 days, less than 1 year
	}

	info, err := ExtractProfileAlgorithmInfo(prof)
	if err != nil {
		t.Fatalf("ExtractProfileAlgorithmInfo() error = %v", err)
	}

	if info.ValidityYears != 1 {
		t.Errorf("ExtractProfileAlgorithmInfo() ValidityYears = %d, want 1 (minimum)", info.ValidityYears)
	}
}

func TestU_ExtractProfileAlgorithmInfo_WithPathLen(t *testing.T) {
	pathLen := 3
	prof := &profile.Profile{
		Algorithm: "ecdsa-p256",
		Validity:  10 * 365 * 24 * time.Hour,
		Extensions: &profile.ExtensionsConfig{
			BasicConstraints: &profile.BasicConstraintsConfig{
				CA:      true,
				PathLen: &pathLen,
			},
		},
	}

	info, err := ExtractProfileAlgorithmInfo(prof)
	if err != nil {
		t.Fatalf("ExtractProfileAlgorithmInfo() error = %v", err)
	}

	if info.PathLen != 3 {
		t.Errorf("ExtractProfileAlgorithmInfo() PathLen = %d, want 3", info.PathLen)
	}
}

func TestU_ExtractProfileAlgorithmInfo_InvalidAlgorithm(t *testing.T) {
	prof := &profile.Profile{
		Algorithm: "invalid-algorithm",
		Validity:  365 * 24 * time.Hour,
	}

	_, err := ExtractProfileAlgorithmInfo(prof)
	if err == nil {
		t.Error("ExtractProfileAlgorithmInfo() should fail for invalid algorithm")
	}
}

// =============================================================================
// CreateChainFile Tests
// =============================================================================

func TestU_CreateChainFile(t *testing.T) {
	caCert, caKey := generateTestCAAndKey(t)
	subCert, _ := createIssuedCert(t, caCert, caKey, "Sub CA")

	tmpDir := t.TempDir()
	chainPath := filepath.Join(tmpDir, "chain.pem")

	err := CreateChainFile(chainPath, subCert, caCert)
	if err != nil {
		t.Fatalf("CreateChainFile() error = %v", err)
	}

	// Verify file exists and contains 2 certificates
	data, err := os.ReadFile(chainPath)
	if err != nil {
		t.Fatalf("failed to read chain file: %v", err)
	}

	certCount := 0
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			certCount++
		}
	}

	if certCount != 2 {
		t.Errorf("CreateChainFile() wrote %d certificates, want 2", certCount)
	}
}

func TestU_CreateChainFile_InvalidPath(t *testing.T) {
	caCert, caKey := generateTestCAAndKey(t)
	subCert, _ := createIssuedCert(t, caCert, caKey, "Sub CA")

	err := CreateChainFile("/nonexistent/directory/chain.pem", subCert, caCert)
	if err == nil {
		t.Error("CreateChainFile() should fail for invalid path")
	}
}

// =============================================================================
// ApplyValidityOverrides Tests
// =============================================================================

func TestU_ApplyValidityOverrides(t *testing.T) {
	t.Run("[Unit] ApplyValidityOverrides: no changes", func(t *testing.T) {
		cmd := &mockCmd{changedFields: map[string]bool{}}
		algInfo := &ProfileAlgorithmInfo{ValidityYears: 10, PathLen: 1}

		ApplyValidityOverrides(cmd, algInfo, 5, 3)

		if algInfo.ValidityYears != 10 {
			t.Errorf("ValidityYears = %d, want 10 (unchanged)", algInfo.ValidityYears)
		}
		if algInfo.PathLen != 1 {
			t.Errorf("PathLen = %d, want 1 (unchanged)", algInfo.PathLen)
		}
	})

	t.Run("[Unit] ApplyValidityOverrides: validity changed", func(t *testing.T) {
		cmd := &mockCmd{changedFields: map[string]bool{"validity": true}}
		algInfo := &ProfileAlgorithmInfo{ValidityYears: 10, PathLen: 1}

		ApplyValidityOverrides(cmd, algInfo, 5, 3)

		if algInfo.ValidityYears != 5 {
			t.Errorf("ValidityYears = %d, want 5", algInfo.ValidityYears)
		}
		if algInfo.PathLen != 1 {
			t.Errorf("PathLen = %d, want 1 (unchanged)", algInfo.PathLen)
		}
	})

	t.Run("[Unit] ApplyValidityOverrides: path-len changed", func(t *testing.T) {
		cmd := &mockCmd{changedFields: map[string]bool{"path-len": true}}
		algInfo := &ProfileAlgorithmInfo{ValidityYears: 10, PathLen: 1}

		ApplyValidityOverrides(cmd, algInfo, 5, 3)

		if algInfo.ValidityYears != 10 {
			t.Errorf("ValidityYears = %d, want 10 (unchanged)", algInfo.ValidityYears)
		}
		if algInfo.PathLen != 3 {
			t.Errorf("PathLen = %d, want 3", algInfo.PathLen)
		}
	})

	t.Run("[Unit] ApplyValidityOverrides: both changed", func(t *testing.T) {
		cmd := &mockCmd{changedFields: map[string]bool{"validity": true, "path-len": true}}
		algInfo := &ProfileAlgorithmInfo{ValidityYears: 10, PathLen: 1}

		ApplyValidityOverrides(cmd, algInfo, 5, 3)

		if algInfo.ValidityYears != 5 {
			t.Errorf("ValidityYears = %d, want 5", algInfo.ValidityYears)
		}
		if algInfo.PathLen != 3 {
			t.Errorf("PathLen = %d, want 3", algInfo.PathLen)
		}
	})
}

// =============================================================================
// BuildProfileConfigs Tests
// =============================================================================

func TestU_BuildProfileConfigs_SingleProfile(t *testing.T) {
	prof := &profile.Profile{
		Algorithm: "ecdsa-p256",
		Validity:  10 * 365 * 24 * time.Hour,
	}
	cmd := &mockCmd{changedFields: map[string]bool{}}

	configs := BuildProfileConfigs([]*profile.Profile{prof}, cmd, 0, 0)

	if len(configs) != 1 {
		t.Fatalf("BuildProfileConfigs() returned %d configs, want 1", len(configs))
	}

	if configs[0].ValidityYears != 10 {
		t.Errorf("BuildProfileConfigs() ValidityYears = %d, want 10", configs[0].ValidityYears)
	}
	if configs[0].PathLen != 1 {
		t.Errorf("BuildProfileConfigs() PathLen = %d, want 1 (default)", configs[0].PathLen)
	}
}

func TestU_BuildProfileConfigs_WithOverrides(t *testing.T) {
	prof := &profile.Profile{
		Algorithm: "ecdsa-p256",
		Validity:  10 * 365 * 24 * time.Hour,
	}
	cmd := &mockCmd{changedFields: map[string]bool{"validity": true, "path-len": true}}

	configs := BuildProfileConfigs([]*profile.Profile{prof}, cmd, 5, 2)

	if len(configs) != 1 {
		t.Fatalf("BuildProfileConfigs() returned %d configs, want 1", len(configs))
	}

	if configs[0].ValidityYears != 5 {
		t.Errorf("BuildProfileConfigs() ValidityYears = %d, want 5 (overridden)", configs[0].ValidityYears)
	}
	if configs[0].PathLen != 2 {
		t.Errorf("BuildProfileConfigs() PathLen = %d, want 2 (overridden)", configs[0].PathLen)
	}
}

func TestU_BuildProfileConfigs_MultipleProfiles(t *testing.T) {
	prof1 := &profile.Profile{
		Algorithm: "ecdsa-p256",
		Validity:  10 * 365 * 24 * time.Hour,
	}
	prof2 := &profile.Profile{
		Algorithm: "ecdsa-p384",
		Validity:  5 * 365 * 24 * time.Hour,
	}
	cmd := &mockCmd{changedFields: map[string]bool{}}

	configs := BuildProfileConfigs([]*profile.Profile{prof1, prof2}, cmd, 0, 0)

	if len(configs) != 2 {
		t.Fatalf("BuildProfileConfigs() returned %d configs, want 2", len(configs))
	}

	if configs[0].ValidityYears != 10 {
		t.Errorf("configs[0].ValidityYears = %d, want 10", configs[0].ValidityYears)
	}
	if configs[1].ValidityYears != 5 {
		t.Errorf("configs[1].ValidityYears = %d, want 5", configs[1].ValidityYears)
	}
}

// =============================================================================
// ValidateHSMProfile Tests
// =============================================================================

func TestU_ValidateHSMProfile_ClassicalAlwaysOK(t *testing.T) {
	prof := &profile.Profile{
		Algorithm: "ecdsa-p256",
	}

	err := ValidateHSMProfile(prof, crypto.AlgECDSAP256, "ec/root-ca")
	if err != nil {
		t.Errorf("ValidateHSMProfile() should succeed for classical algorithm, got %v", err)
	}
}

func TestU_ValidateHSMProfile_PQCWithoutEnv(t *testing.T) {
	prof := &profile.Profile{
		Algorithm: "ml-dsa-65",
	}

	// Ensure env var is not set
	_ = os.Unsetenv("HSM_PQC_ENABLED")

	err := ValidateHSMProfile(prof, crypto.AlgMLDSA65, "pqc/root-ca")
	if err == nil {
		t.Error("ValidateHSMProfile() should fail for PQC algorithm without HSM_PQC_ENABLED")
	}
}

func TestU_ValidateHSMProfile_PQCWithEnv(t *testing.T) {
	prof := &profile.Profile{
		Algorithm: "ml-dsa-65",
	}

	t.Setenv("HSM_PQC_ENABLED", "1")

	err := ValidateHSMProfile(prof, crypto.AlgMLDSA65, "pqc/root-ca")
	if err != nil {
		t.Errorf("ValidateHSMProfile() should succeed for PQC with HSM_PQC_ENABLED, got %v", err)
	}
}

// =============================================================================
// LoadVersionCerts Tests
// =============================================================================

func TestU_LoadVersionCerts_NotVersioned(t *testing.T) {
	tmpDir := t.TempDir()

	_, err := LoadVersionCerts(tmpDir, "v1", nil)
	if err == nil {
		t.Error("LoadVersionCerts() should fail when CAInfo is nil")
	}
}

func TestU_LoadVersionCerts_VersionNotFound(t *testing.T) {
	tmpDir := t.TempDir()

	info := &ca.CAInfo{
		Versions: map[string]ca.CAVersion{
			"v1": {Algos: []string{"ecdsa-p256"}},
		},
	}

	_, err := LoadVersionCerts(tmpDir, "v99", info)
	if err == nil {
		t.Error("LoadVersionCerts() should fail for non-existent version")
	}
}

// =============================================================================
// LoadAllVersionCerts Tests
// =============================================================================

func TestU_LoadAllVersionCerts_NilInfo(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a CA store with a certificate
	caCert, _ := generateTestCAAndKey(t)
	store := ca.NewFileStore(tmpDir)
	if err := store.Init(ctx); err != nil {
		t.Fatalf("failed to init store: %v", err)
	}
	saveCertPEM(t, store.CACertPath(), caCert)

	certs, err := LoadAllVersionCerts(tmpDir, nil)
	if err != nil {
		t.Fatalf("LoadAllVersionCerts() error = %v", err)
	}
	if len(certs) != 1 {
		t.Errorf("LoadAllVersionCerts() returned %d certs, want 1", len(certs))
	}
}

// =============================================================================
// LoadAndValidateProfileVariables Tests
// =============================================================================

func TestU_LoadAndValidateProfileVariables_NoVars(t *testing.T) {
	prof := &profile.Profile{
		Name:      "test-profile",
		Variables: nil,
	}

	result, err := LoadAndValidateProfileVariables(prof, "", nil)
	if err != nil {
		t.Fatalf("LoadAndValidateProfileVariables() error = %v", err)
	}

	if result == nil {
		t.Error("LoadAndValidateProfileVariables() should return non-nil result")
	}
}

func TestU_LoadAndValidateProfileVariables_InvalidVarFile(t *testing.T) {
	prof := &profile.Profile{
		Name: "test-profile",
	}

	_, err := LoadAndValidateProfileVariables(prof, "/non/existent/vars.yaml", nil)
	if err == nil {
		t.Error("LoadAndValidateProfileVariables() should fail for non-existent var file")
	}
}
