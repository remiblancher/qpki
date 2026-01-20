package ca

import (
	"testing"
	"time"

	"github.com/remiblancher/post-quantum-pki/internal/crypto"
	"github.com/remiblancher/post-quantum-pki/internal/profile"
)

// =============================================================================
// Multi-Profile CA Initialization Tests
// =============================================================================

func TestF_InitializeMultiProfile_SingleProfile(t *testing.T) {
	tmpDir := t.TempDir()

	prof := &profile.Profile{
		Name:      "test-ec",
		Algorithm: crypto.AlgECDSAP256,
		Validity:  10 * 365 * 24 * time.Hour,
	}

	cfg := MultiProfileInitConfig{
		Profiles: []ProfileInitConfig{
			{
				Profile:       prof,
				ValidityYears: 10,
				PathLen:       1,
			},
		},
		Variables: map[string]string{
			"cn": "Test Multi-Profile CA",
			"o":  "Test Org",
			"c":  "US",
		},
	}

	result, err := InitializeMultiProfile(tmpDir, cfg)
	if err != nil {
		t.Fatalf("InitializeMultiProfile() error = %v", err)
	}

	if result == nil {
		t.Fatal("InitializeMultiProfile() returned nil result")
	}
	if result.Info == nil {
		t.Fatal("InitializeMultiProfile() returned nil Info")
	}
	if len(result.Certificates) != 1 {
		t.Errorf("InitializeMultiProfile() created %d certificates, want 1", len(result.Certificates))
	}

	cert, ok := result.Certificates["ec"]
	if !ok {
		t.Fatal("InitializeMultiProfile() did not create EC certificate")
	}
	if cert.Subject.CommonName != "Test Multi-Profile CA" {
		t.Errorf("CommonName = %q, want %q", cert.Subject.CommonName, "Test Multi-Profile CA")
	}
	if !cert.IsCA {
		t.Error("certificate should be CA")
	}
}

func TestF_InitializeMultiProfile_MultipleProfiles(t *testing.T) {
	tmpDir := t.TempDir()

	profEC := &profile.Profile{
		Name:      "test-ec",
		Algorithm: crypto.AlgECDSAP256,
		Validity:  10 * 365 * 24 * time.Hour,
	}

	profMLDSA := &profile.Profile{
		Name:      "test-mldsa",
		Algorithm: crypto.AlgMLDSA65,
		Validity:  10 * 365 * 24 * time.Hour,
	}

	cfg := MultiProfileInitConfig{
		Profiles: []ProfileInitConfig{
			{
				Profile:       profEC,
				ValidityYears: 10,
				PathLen:       1,
			},
			{
				Profile:       profMLDSA,
				ValidityYears: 10,
				PathLen:       1,
			},
		},
		Variables: map[string]string{
			"cn": "Test Multi-Profile CA",
			"o":  "Test Org",
			"c":  "US",
		},
	}

	result, err := InitializeMultiProfile(tmpDir, cfg)
	if err != nil {
		t.Fatalf("InitializeMultiProfile() error = %v", err)
	}

	if len(result.Certificates) != 2 {
		t.Errorf("InitializeMultiProfile() created %d certificates, want 2", len(result.Certificates))
	}

	if _, ok := result.Certificates["ec"]; !ok {
		t.Error("InitializeMultiProfile() did not create EC certificate")
	}
	if _, ok := result.Certificates["ml-dsa"]; !ok {
		t.Error("InitializeMultiProfile() did not create ML-DSA certificate")
	}
}

func TestF_InitializeMultiProfile_NoProfiles(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := MultiProfileInitConfig{
		Profiles: []ProfileInitConfig{},
		Variables: map[string]string{
			"cn": "Test CA",
		},
	}

	_, err := InitializeMultiProfile(tmpDir, cfg)
	if err == nil {
		t.Error("InitializeMultiProfile() should fail with no profiles")
	}
}

func TestF_InitializeMultiProfile_AlreadyExists(t *testing.T) {
	tmpDir := t.TempDir()

	prof := &profile.Profile{
		Name:      "test-ec",
		Algorithm: crypto.AlgECDSAP256,
		Validity:  10 * 365 * 24 * time.Hour,
	}

	cfg := MultiProfileInitConfig{
		Profiles: []ProfileInitConfig{
			{
				Profile:       prof,
				ValidityYears: 10,
				PathLen:       1,
			},
		},
		Variables: map[string]string{
			"cn": "Test CA",
		},
	}

	// First initialization should succeed
	_, err := InitializeMultiProfile(tmpDir, cfg)
	if err != nil {
		t.Fatalf("First InitializeMultiProfile() error = %v", err)
	}

	// Second initialization should fail
	_, err = InitializeMultiProfile(tmpDir, cfg)
	if err == nil {
		t.Error("InitializeMultiProfile() should fail when CA already exists")
	}
}

// =============================================================================
// Unit Tests for helper functions
// =============================================================================

func TestU_validateMultiProfileInitConfig(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		tmpDir := t.TempDir()
		prof := &profile.Profile{
			Name:      "test",
			Algorithm: crypto.AlgECDSAP256,
			Validity:  10 * 365 * 24 * time.Hour,
		}
		cfg := MultiProfileInitConfig{
			Profiles: []ProfileInitConfig{{Profile: prof}},
		}
		err := validateMultiProfileInitConfig(tmpDir, cfg)
		if err != nil {
			t.Errorf("validateMultiProfileInitConfig() error = %v", err)
		}
	})

	t.Run("no profiles", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfg := MultiProfileInitConfig{
			Profiles: []ProfileInitConfig{},
		}
		err := validateMultiProfileInitConfig(tmpDir, cfg)
		if err == nil {
			t.Error("validateMultiProfileInitConfig() should fail with no profiles")
		}
	})
}

func TestU_resolveSubjectFromConfig(t *testing.T) {
	t.Run("all variables set", func(t *testing.T) {
		cfg := MultiProfileInitConfig{
			Variables: map[string]string{
				"cn": "Test CN",
				"o":  "Test Org",
				"c":  "US",
			},
		}
		subj := resolveSubjectFromConfig(cfg)
		if subj.cn != "Test CN" {
			t.Errorf("cn = %q, want %q", subj.cn, "Test CN")
		}
		if subj.org != "Test Org" {
			t.Errorf("org = %q, want %q", subj.org, "Test Org")
		}
		if subj.country != "US" {
			t.Errorf("country = %q, want %q", subj.country, "US")
		}
	})

	t.Run("default common name", func(t *testing.T) {
		cfg := MultiProfileInitConfig{
			Variables: map[string]string{},
		}
		subj := resolveSubjectFromConfig(cfg)
		if subj.cn != "Multi-Profile CA" {
			t.Errorf("cn = %q, want %q", subj.cn, "Multi-Profile CA")
		}
	})

	t.Run("empty cn uses default", func(t *testing.T) {
		cfg := MultiProfileInitConfig{
			Variables: map[string]string{
				"cn": "",
			},
		}
		subj := resolveSubjectFromConfig(cfg)
		if subj.cn != "Multi-Profile CA" {
			t.Errorf("cn = %q, want %q", subj.cn, "Multi-Profile CA")
		}
	})
}

func TestU_determineValidityYears(t *testing.T) {
	t.Run("explicit validity years", func(t *testing.T) {
		profCfg := ProfileInitConfig{
			Profile: &profile.Profile{
				Validity: 5 * 365 * 24 * time.Hour,
			},
			ValidityYears: 20,
		}
		years := determineValidityYears(profCfg)
		if years != 20 {
			t.Errorf("determineValidityYears() = %d, want 20", years)
		}
	})

	t.Run("from profile validity", func(t *testing.T) {
		profCfg := ProfileInitConfig{
			Profile: &profile.Profile{
				Validity: 5 * 365 * 24 * time.Hour,
			},
		}
		years := determineValidityYears(profCfg)
		if years != 5 {
			t.Errorf("determineValidityYears() = %d, want 5", years)
		}
	})

	t.Run("default to 10 years", func(t *testing.T) {
		profCfg := ProfileInitConfig{
			Profile: &profile.Profile{
				Validity: 0,
			},
		}
		years := determineValidityYears(profCfg)
		if years != 10 {
			t.Errorf("determineValidityYears() = %d, want 10", years)
		}
	})
}

func TestU_buildKeyStorageConfig(t *testing.T) {
	t.Run("with existing config", func(t *testing.T) {
		info := NewCAInfo(Subject{CommonName: "Test"})
		info.SetBasePath(t.TempDir())

		cfg := MultiProfileInitConfig{
			KeyStorageConfig: crypto.KeyStorageConfig{
				Type:    crypto.KeyProviderTypeSoftware,
				KeyPath: "/custom/path",
			},
		}
		result := buildKeyStorageConfig(cfg, info, crypto.AlgECDSAP256)
		if result.KeyPath != "/custom/path" {
			t.Errorf("KeyPath = %q, want %q", result.KeyPath, "/custom/path")
		}
	})

	t.Run("default config", func(t *testing.T) {
		tmpDir := t.TempDir()
		info := NewCAInfo(Subject{CommonName: "Test"})
		info.SetBasePath(tmpDir)

		cfg := MultiProfileInitConfig{
			Passphrase: "test-passphrase",
		}
		result := buildKeyStorageConfig(cfg, info, crypto.AlgECDSAP256)
		if result.Type != crypto.KeyProviderTypeSoftware {
			t.Errorf("Type = %v, want %v", result.Type, crypto.KeyProviderTypeSoftware)
		}
		if result.Passphrase != "test-passphrase" {
			t.Errorf("Passphrase = %q, want %q", result.Passphrase, "test-passphrase")
		}
	})
}

func TestU_createMultiProfileCAInfo(t *testing.T) {
	tmpDir := t.TempDir()

	prof := &profile.Profile{
		Name:      "test-ec",
		Algorithm: crypto.AlgECDSAP256,
		Validity:  10 * 365 * 24 * time.Hour,
	}

	cfg := MultiProfileInitConfig{
		Profiles: []ProfileInitConfig{
			{Profile: prof},
		},
		Variables: map[string]string{
			"cn": "Test CA",
			"o":  "Test Org",
			"c":  "US",
		},
	}

	info := createMultiProfileCAInfo(tmpDir, cfg)
	if info == nil {
		t.Fatal("createMultiProfileCAInfo() returned nil")
	}
	if info.Subject.CommonName != "Test CA" {
		t.Errorf("CommonName = %q, want %q", info.Subject.CommonName, "Test CA")
	}
}

func TestF_InitializeMultiProfile_WithPassphrase(t *testing.T) {
	tmpDir := t.TempDir()

	prof := &profile.Profile{
		Name:      "test-ec",
		Algorithm: crypto.AlgECDSAP256,
		Validity:  10 * 365 * 24 * time.Hour,
	}

	cfg := MultiProfileInitConfig{
		Profiles: []ProfileInitConfig{
			{
				Profile:       prof,
				ValidityYears: 10,
				PathLen:       1,
			},
		},
		Variables: map[string]string{
			"cn": "Test CA with Passphrase",
		},
		Passphrase: "test-passphrase-123",
	}

	result, err := InitializeMultiProfile(tmpDir, cfg)
	if err != nil {
		t.Fatalf("InitializeMultiProfile() error = %v", err)
	}

	if len(result.Certificates) != 1 {
		t.Errorf("InitializeMultiProfile() created %d certificates, want 1", len(result.Certificates))
	}
}

func TestF_InitializeMultiProfile_RSA(t *testing.T) {
	tmpDir := t.TempDir()

	prof := &profile.Profile{
		Name:      "test-rsa",
		Algorithm: crypto.AlgRSA4096,
		Validity:  10 * 365 * 24 * time.Hour,
	}

	cfg := MultiProfileInitConfig{
		Profiles: []ProfileInitConfig{
			{
				Profile:       prof,
				ValidityYears: 10,
				PathLen:       1,
			},
		},
		Variables: map[string]string{
			"cn": "Test RSA CA",
		},
	}

	result, err := InitializeMultiProfile(tmpDir, cfg)
	if err != nil {
		t.Fatalf("InitializeMultiProfile() error = %v", err)
	}

	cert, ok := result.Certificates["rsa"]
	if !ok {
		t.Fatal("InitializeMultiProfile() did not create RSA certificate")
	}
	if !cert.IsCA {
		t.Error("certificate should be CA")
	}
}

func TestF_InitializeMultiProfile_Ed25519(t *testing.T) {
	tmpDir := t.TempDir()

	prof := &profile.Profile{
		Name:      "test-ed25519",
		Algorithm: crypto.AlgEd25519,
		Validity:  10 * 365 * 24 * time.Hour,
	}

	cfg := MultiProfileInitConfig{
		Profiles: []ProfileInitConfig{
			{
				Profile:       prof,
				ValidityYears: 10,
				PathLen:       0,
			},
		},
		Variables: map[string]string{
			"cn": "Test Ed25519 CA",
		},
	}

	result, err := InitializeMultiProfile(tmpDir, cfg)
	if err != nil {
		t.Fatalf("InitializeMultiProfile() error = %v", err)
	}

	cert, ok := result.Certificates["ed25519"]
	if !ok {
		t.Fatal("InitializeMultiProfile() did not create Ed25519 certificate")
	}
	if !cert.IsCA {
		t.Error("certificate should be CA")
	}
}

func TestF_InitializeMultiProfile_PQC(t *testing.T) {
	tmpDir := t.TempDir()

	prof := &profile.Profile{
		Name:      "test-mldsa44",
		Algorithm: crypto.AlgMLDSA44,
		Validity:  10 * 365 * 24 * time.Hour,
	}

	cfg := MultiProfileInitConfig{
		Profiles: []ProfileInitConfig{
			{
				Profile:       prof,
				ValidityYears: 10,
				PathLen:       1,
			},
		},
		Variables: map[string]string{
			"cn": "Test ML-DSA CA",
		},
	}

	result, err := InitializeMultiProfile(tmpDir, cfg)
	if err != nil {
		t.Fatalf("InitializeMultiProfile() error = %v", err)
	}

	cert, ok := result.Certificates["ml-dsa"]
	if !ok {
		t.Fatal("InitializeMultiProfile() did not create ML-DSA certificate")
	}
	if !cert.IsCA {
		t.Error("certificate should be CA")
	}
}
