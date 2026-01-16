package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"testing"
	"time"

	"github.com/remiblancher/post-quantum-pki/internal/ca"
	"github.com/remiblancher/post-quantum-pki/internal/crypto"
	"github.com/remiblancher/post-quantum-pki/internal/profile"
)

// =============================================================================
// validateHSMFlags Tests
// =============================================================================

func TestValidateHSMFlags(t *testing.T) {
	tests := []struct {
		name        string
		generateKey bool
		keyLabel    string
		keyID       string
		wantErr     bool
	}{
		{
			name:        "generate key with label",
			generateKey: true,
			keyLabel:    "my-key",
			keyID:       "",
			wantErr:     false,
		},
		{
			name:        "generate key without label",
			generateKey: true,
			keyLabel:    "",
			keyID:       "",
			wantErr:     true,
		},
		{
			name:        "existing key with label",
			generateKey: false,
			keyLabel:    "existing-key",
			keyID:       "",
			wantErr:     false,
		},
		{
			name:        "existing key with ID",
			generateKey: false,
			keyLabel:    "",
			keyID:       "key-id-123",
			wantErr:     false,
		},
		{
			name:        "existing key with both label and ID",
			generateKey: false,
			keyLabel:    "my-key",
			keyID:       "key-id-123",
			wantErr:     false,
		},
		{
			name:        "no generate and no key identifier",
			generateKey: false,
			keyLabel:    "",
			keyID:       "",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateHSMFlags(tt.generateKey, tt.keyLabel, tt.keyID)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateHSMFlags() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// =============================================================================
// validateHSMProfile Tests
// =============================================================================

func TestValidateHSMProfile(t *testing.T) {
	tests := []struct {
		name    string
		alg     crypto.AlgorithmID
		mode    profile.Mode
		algos   []crypto.AlgorithmID
		wantErr bool
	}{
		{
			name:    "ECDSA P-256 algorithm",
			alg:     crypto.AlgECDSAP256,
			mode:    profile.ModeSimple,
			wantErr: false,
		},
		{
			name:    "ECDSA P-384 algorithm",
			alg:     crypto.AlgECDSAP384,
			mode:    profile.ModeSimple,
			wantErr: false,
		},
		{
			name:    "RSA 2048 algorithm",
			alg:     crypto.AlgRSA2048,
			mode:    profile.ModeSimple,
			wantErr: false,
		},
		{
			name:    "ML-DSA-65 PQC algorithm",
			alg:     crypto.AlgMLDSA65,
			mode:    profile.ModeSimple,
			wantErr: true,
		},
		{
			name:    "ML-DSA-87 PQC algorithm",
			alg:     crypto.AlgMLDSA87,
			mode:    profile.ModeSimple,
			wantErr: true,
		},
		{
			name:    "Catalyst profile",
			alg:     crypto.AlgECDSAP256,
			mode:    profile.ModeCatalyst,
			algos:   []crypto.AlgorithmID{crypto.AlgECDSAP256, crypto.AlgMLDSA87},
			wantErr: true,
		},
		{
			name:    "Composite profile",
			alg:     crypto.AlgECDSAP256,
			mode:    profile.ModeComposite,
			algos:   []crypto.AlgorithmID{crypto.AlgECDSAP256, crypto.AlgMLDSA87},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prof := &profile.Profile{
				Name: "test-profile",
				Mode: tt.mode,
			}
			if len(tt.algos) > 0 {
				prof.Algorithms = tt.algos
			}

			err := validateHSMProfile(prof, tt.alg, "test-profile")
			if (err != nil) != tt.wantErr {
				t.Errorf("validateHSMProfile() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// =============================================================================
// encodeCertificates Tests
// =============================================================================

func TestEncodeCertificates(t *testing.T) {
	// Generate test certificates
	tc := newTestContext(t)
	priv, pub := generateECDSAKeyPair(t)
	cert := generateSelfSignedCert(t, priv, pub)
	_ = tc // Keep tc reference for cleanup

	tests := []struct {
		name    string
		certs   []*x509.Certificate
		format  string
		wantErr bool
	}{
		{
			name:    "single cert PEM format",
			certs:   []*x509.Certificate{cert},
			format:  "pem",
			wantErr: false,
		},
		{
			name:    "single cert DER format",
			certs:   []*x509.Certificate{cert},
			format:  "der",
			wantErr: false,
		},
		{
			name:    "multiple certs PEM format",
			certs:   []*x509.Certificate{cert, cert},
			format:  "pem",
			wantErr: false,
		},
		{
			name:    "multiple certs DER format (should fail)",
			certs:   []*x509.Certificate{cert, cert},
			format:  "der",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := encodeCertificates(tt.certs, tt.format)
			if (err != nil) != tt.wantErr {
				t.Errorf("encodeCertificates() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && len(data) == 0 {
				t.Error("encodeCertificates() returned empty data")
			}

			// Verify PEM format has proper structure
			if !tt.wantErr && tt.format == "pem" {
				block, _ := pem.Decode(data)
				if block == nil {
					t.Error("encodeCertificates() PEM output is not valid PEM")
				}
				if block != nil && block.Type != "CERTIFICATE" {
					t.Errorf("encodeCertificates() PEM type = %s, want CERTIFICATE", block.Type)
				}
			}
		})
	}
}

// =============================================================================
// extractProfileAlgorithmInfo Tests
// =============================================================================

func TestExtractProfileAlgorithmInfo(t *testing.T) {
	tests := []struct {
		name          string
		profile       *profile.Profile
		wantAlgorithm crypto.AlgorithmID
		wantHybrid    crypto.AlgorithmID
		wantComposite bool
		wantCatalyst  bool
		wantErr       bool
	}{
		{
			name: "ECDSA P-384 profile",
			profile: &profile.Profile{
				Name:      "ec-root",
				Algorithm: crypto.AlgECDSAP384,
				Mode:      profile.ModeSimple,
				Validity:  365 * 24 * time.Hour * 10, // 10 years
			},
			wantAlgorithm: crypto.AlgECDSAP384,
			wantHybrid:    "",
			wantComposite: false,
			wantCatalyst:  false,
			wantErr:       false,
		},
		{
			name: "ML-DSA-87 PQC profile",
			profile: &profile.Profile{
				Name:      "ml-root",
				Algorithm: crypto.AlgMLDSA87,
				Mode:      profile.ModeSimple,
				Validity:  365 * 24 * time.Hour * 5, // 5 years
			},
			wantAlgorithm: crypto.AlgMLDSA87,
			wantHybrid:    "",
			wantComposite: false,
			wantCatalyst:  false,
			wantErr:       false,
		},
		{
			name: "Catalyst profile",
			profile: &profile.Profile{
				Name:       "catalyst-root",
				Mode:       profile.ModeCatalyst,
				Algorithms: []crypto.AlgorithmID{crypto.AlgECDSAP384, crypto.AlgMLDSA87},
				Validity:   365 * 24 * time.Hour * 10,
			},
			wantAlgorithm: crypto.AlgECDSAP384,
			wantHybrid:    crypto.AlgMLDSA87,
			wantComposite: false,
			wantCatalyst:  true,
			wantErr:       false,
		},
		{
			name: "Composite profile",
			profile: &profile.Profile{
				Name:       "composite-root",
				Mode:       profile.ModeComposite,
				Algorithms: []crypto.AlgorithmID{crypto.AlgECDSAP384, crypto.AlgMLDSA87},
				Validity:   365 * 24 * time.Hour * 10,
			},
			wantAlgorithm: crypto.AlgECDSAP384,
			wantHybrid:    crypto.AlgMLDSA87,
			wantComposite: true,
			wantCatalyst:  false,
			wantErr:       false,
		},
		{
			name: "Invalid algorithm",
			profile: &profile.Profile{
				Name:      "invalid",
				Algorithm: crypto.AlgorithmID("invalid-algo"),
				Mode:      profile.ModeSimple,
				Validity:  365 * 24 * time.Hour,
			},
			wantErr: true,
		},
		{
			name: "Short validity (less than 1 year)",
			profile: &profile.Profile{
				Name:      "short-validity",
				Algorithm: crypto.AlgECDSAP256,
				Mode:      profile.ModeSimple,
				Validity:  30 * 24 * time.Hour, // 30 days
			},
			wantAlgorithm: crypto.AlgECDSAP256,
			wantErr:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := extractProfileAlgorithmInfo(tt.profile)
			if (err != nil) != tt.wantErr {
				t.Errorf("extractProfileAlgorithmInfo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			if info.Algorithm != tt.wantAlgorithm {
				t.Errorf("Algorithm = %v, want %v", info.Algorithm, tt.wantAlgorithm)
			}
			if info.HybridAlg != tt.wantHybrid {
				t.Errorf("HybridAlg = %v, want %v", info.HybridAlg, tt.wantHybrid)
			}
			if info.IsComposite != tt.wantComposite {
				t.Errorf("IsComposite = %v, want %v", info.IsComposite, tt.wantComposite)
			}
			if info.IsCatalyst != tt.wantCatalyst {
				t.Errorf("IsCatalyst = %v, want %v", info.IsCatalyst, tt.wantCatalyst)
			}

			// Validity should be at least 1 year
			if info.ValidityYears < 1 {
				t.Errorf("ValidityYears = %d, want >= 1", info.ValidityYears)
			}
		})
	}
}

// =============================================================================
// buildCAConfigFromProfile Tests
// =============================================================================

func TestBuildCAConfigFromProfile(t *testing.T) {
	tests := []struct {
		name       string
		profile    *profile.Profile
		algInfo    *profileAlgorithmInfo
		passphrase string
		wantErr    bool
	}{
		{
			name: "simple ECDSA profile",
			profile: &profile.Profile{
				Name: "test",
			},
			algInfo: &profileAlgorithmInfo{
				Algorithm:     crypto.AlgECDSAP384,
				ValidityYears: 10,
				PathLen:       1,
			},
			passphrase: "secret",
			wantErr:    false,
		},
		{
			name: "profile with PQC hybrid",
			profile: &profile.Profile{
				Name: "hybrid",
			},
			algInfo: &profileAlgorithmInfo{
				Algorithm:     crypto.AlgECDSAP384,
				HybridAlg:     crypto.AlgMLDSA87,
				ValidityYears: 10,
				PathLen:       1,
			},
			passphrase: "",
			wantErr:    false,
		},
		{
			name: "profile with classical hybrid (should fail)",
			profile: &profile.Profile{
				Name: "invalid-hybrid",
			},
			algInfo: &profileAlgorithmInfo{
				Algorithm:     crypto.AlgECDSAP384,
				HybridAlg:     crypto.AlgECDSAP256, // Classical, not PQC
				ValidityYears: 10,
				PathLen:       1,
			},
			passphrase: "",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := buildCAConfigFromProfile(
				tt.profile,
				testSubject(),
				tt.algInfo,
				tt.passphrase,
			)

			if (err != nil) != tt.wantErr {
				t.Errorf("buildCAConfigFromProfile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			if cfg.CommonName != "Test CA" {
				t.Errorf("CommonName = %s, want Test CA", cfg.CommonName)
			}
			if cfg.Algorithm != tt.algInfo.Algorithm {
				t.Errorf("Algorithm = %v, want %v", cfg.Algorithm, tt.algInfo.Algorithm)
			}
			if cfg.ValidityYears != tt.algInfo.ValidityYears {
				t.Errorf("ValidityYears = %d, want %d", cfg.ValidityYears, tt.algInfo.ValidityYears)
			}
			if cfg.Passphrase != tt.passphrase {
				t.Errorf("Passphrase = %s, want %s", cfg.Passphrase, tt.passphrase)
			}

			if tt.algInfo.HybridAlg != "" {
				if cfg.HybridConfig == nil {
					t.Error("HybridConfig is nil, expected non-nil")
				} else if cfg.HybridConfig.Algorithm != tt.algInfo.HybridAlg {
					t.Errorf("HybridConfig.Algorithm = %v, want %v", cfg.HybridConfig.Algorithm, tt.algInfo.HybridAlg)
				}
			}
		})
	}
}

// =============================================================================
// Test Helpers
// =============================================================================

func testSubject() pkix.Name {
	return pkix.Name{
		CommonName:   "Test CA",
		Organization: []string{"Test Org"},
		Country:      []string{"US"},
	}
}

// =============================================================================
// validateCAInitSoftwareFlags Tests
// =============================================================================

func TestValidateCAInitSoftwareFlags(t *testing.T) {
	tests := []struct {
		name     string
		varFile  string
		vars     []string
		profiles []string
		wantErr  bool
	}{
		{
			name:     "valid single profile",
			varFile:  "",
			vars:     nil,
			profiles: []string{"profile1"},
			wantErr:  false,
		},
		{
			name:     "valid with var file",
			varFile:  "vars.yaml",
			vars:     nil,
			profiles: []string{"profile1"},
			wantErr:  false,
		},
		{
			name:     "valid with vars",
			varFile:  "",
			vars:     []string{"key=value"},
			profiles: []string{"profile1"},
			wantErr:  false,
		},
		{
			name:     "error: both var file and vars",
			varFile:  "vars.yaml",
			vars:     []string{"key=value"},
			profiles: []string{"profile1"},
			wantErr:  true,
		},
		{
			name:     "error: no profiles",
			varFile:  "",
			vars:     nil,
			profiles: []string{},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCAInitSoftwareFlags(tt.varFile, tt.vars, tt.profiles)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateCAInitSoftwareFlags() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// =============================================================================
// validateSubordinateCAFlags Tests
// =============================================================================

func TestValidateSubordinateCAFlags(t *testing.T) {
	tests := []struct {
		name     string
		varFile  string
		vars     []string
		profiles []string
		wantErr  bool
	}{
		{
			name:     "valid single profile",
			varFile:  "",
			vars:     nil,
			profiles: []string{"profile1"},
			wantErr:  false,
		},
		{
			name:     "error: both var file and vars",
			varFile:  "vars.yaml",
			vars:     []string{"key=value"},
			profiles: []string{"profile1"},
			wantErr:  true,
		},
		{
			name:     "error: no profiles",
			varFile:  "",
			vars:     nil,
			profiles: []string{},
			wantErr:  true,
		},
		{
			name:     "error: multiple profiles",
			varFile:  "",
			vars:     nil,
			profiles: []string{"profile1", "profile2"},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSubordinateCAFlags(tt.varFile, tt.vars, tt.profiles)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateSubordinateCAFlags() error = %v, wantErr %v", err, tt.wantErr)
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
		{
			name:  "non-empty slice",
			input: []string{"first", "second"},
			want:  "first",
		},
		{
			name:  "single element",
			input: []string{"only"},
			want:  "only",
		},
		{
			name:  "empty slice",
			input: []string{},
			want:  "",
		},
		{
			name:  "nil slice",
			input: nil,
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := firstOrEmpty(tt.input); got != tt.want {
				t.Errorf("firstOrEmpty() = %v, want %v", got, tt.want)
			}
		})
	}
}

// =============================================================================
// getSignatureAlgorithmName Tests
// =============================================================================

func TestGetSignatureAlgorithmName(t *testing.T) {
	// Create a test certificate with a known algorithm
	tc := newTestContext(t)
	priv, pub := generateECDSAKeyPair(tc.t)
	cert := generateSelfSignedCert(tc.t, priv, pub)

	// Test with a standard ECDSA certificate
	name := getSignatureAlgorithmName(cert)
	if name == "" || name == "Unknown" {
		t.Errorf("getSignatureAlgorithmName() for ECDSA cert = %q, want non-empty and not Unknown", name)
	}

	// Test with nil certificate (should not panic)
	// We can't actually test nil because it would panic, but we can verify the function works with valid certs
}

// =============================================================================
// parseCertificatesPEM Tests
// =============================================================================

func TestParseCertificatesPEM(t *testing.T) {
	tc := newTestContext(t)
	priv, pub := generateECDSAKeyPair(tc.t)
	cert := generateSelfSignedCert(tc.t, priv, pub)

	// Create PEM data for single certificate
	singlePEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	// Create PEM data for multiple certificates
	multiplePEM := append(singlePEM, singlePEM...)

	tests := []struct {
		name      string
		data      []byte
		wantCount int
		wantErr   bool
	}{
		{
			name:      "single certificate",
			data:      singlePEM,
			wantCount: 1,
			wantErr:   false,
		},
		{
			name:      "multiple certificates",
			data:      multiplePEM,
			wantCount: 2,
			wantErr:   false,
		},
		{
			name:      "empty data",
			data:      []byte{},
			wantCount: 0,
			wantErr:   false,
		},
		{
			name:      "non-PEM data",
			data:      []byte("not a PEM block"),
			wantCount: 0,
			wantErr:   false,
		},
		{
			name: "mixed PEM types",
			data: append(singlePEM, pem.EncodeToMemory(&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: []byte("fake key"),
			})...),
			wantCount: 1,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certs, err := parseCertificatesPEM(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseCertificatesPEM() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(certs) != tt.wantCount {
				t.Errorf("parseCertificatesPEM() got %d certs, want %d", len(certs), tt.wantCount)
			}
		})
	}
}

// =============================================================================
// parseIPStrings Tests (from issue_helpers.go)
// =============================================================================

func TestParseIPStrings(t *testing.T) {
	tests := []struct {
		name    string
		input   []string
		wantLen int
	}{
		{
			name:    "valid IPv4",
			input:   []string{"192.168.1.1", "10.0.0.1"},
			wantLen: 2,
		},
		{
			name:    "valid IPv6",
			input:   []string{"::1", "fe80::1"},
			wantLen: 2,
		},
		{
			name:    "mixed valid and invalid",
			input:   []string{"192.168.1.1", "invalid", "10.0.0.1"},
			wantLen: 2,
		},
		{
			name:    "empty input",
			input:   []string{},
			wantLen: 0,
		},
		{
			name:    "all invalid",
			input:   []string{"not-an-ip", "also-not-an-ip"},
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseIPStrings(tt.input)
			if len(got) != tt.wantLen {
				t.Errorf("parseIPStrings() returned %d IPs, want %d", len(got), tt.wantLen)
			}
		})
	}
}

// =============================================================================
// list_helpers Tests
// =============================================================================

func TestGetEffectiveStatus(t *testing.T) {
	now := time.Now()
	futureTime := now.Add(24 * time.Hour)
	pastTime := now.Add(-24 * time.Hour)

	tests := []struct {
		name  string
		entry *ca.IndexEntry
		want  string
	}{
		{
			name: "valid not expired",
			entry: &ca.IndexEntry{
				Status: "V",
				Expiry: futureTime,
			},
			want: "V",
		},
		{
			name: "valid but expired",
			entry: &ca.IndexEntry{
				Status: "V",
				Expiry: pastTime,
			},
			want: "E",
		},
		{
			name: "revoked",
			entry: &ca.IndexEntry{
				Status: "R",
				Expiry: futureTime,
			},
			want: "R",
		},
		{
			name: "valid with zero expiry",
			entry: &ca.IndexEntry{
				Status: "V",
				Expiry: time.Time{},
			},
			want: "V",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getEffectiveStatus(tt.entry, now)
			if got != tt.want {
				t.Errorf("getEffectiveStatus() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFilterCertEntries(t *testing.T) {
	now := time.Now()
	futureTime := now.Add(24 * time.Hour)
	pastTime := now.Add(-24 * time.Hour)

	entries := []ca.IndexEntry{
		{Status: "V", Expiry: futureTime, Subject: "valid"},
		{Status: "R", Expiry: futureTime, Subject: "revoked"},
		{Status: "V", Expiry: pastTime, Subject: "expired"},
	}

	tests := []struct {
		name      string
		filter    string
		wantCount int
		wantErr   bool
	}{
		{
			name:      "no filter",
			filter:    "",
			wantCount: 3,
			wantErr:   false,
		},
		{
			name:      "filter valid",
			filter:    "valid",
			wantCount: 1,
			wantErr:   false,
		},
		{
			name:      "filter revoked",
			filter:    "revoked",
			wantCount: 1,
			wantErr:   false,
		},
		{
			name:      "filter expired",
			filter:    "expired",
			wantCount: 1,
			wantErr:   false,
		},
		{
			name:      "invalid filter",
			filter:    "unknown",
			wantCount: 0,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := filterCertEntries(entries, tt.filter, now)
			if (err != nil) != tt.wantErr {
				t.Errorf("filterCertEntries() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(got) != tt.wantCount {
				t.Errorf("filterCertEntries() returned %d entries, want %d", len(got), tt.wantCount)
			}
		})
	}
}

// =============================================================================
// isCompatibleAlgorithm Tests
// =============================================================================

func TestIsCompatibleAlgorithm(t *testing.T) {
	tests := []struct {
		name    string
		profile crypto.AlgorithmID
		hsm     crypto.AlgorithmID
		want    bool
	}{
		{
			name:    "same algorithm",
			profile: crypto.AlgECDSAP384,
			hsm:     crypto.AlgECDSAP384,
			want:    true,
		},
		{
			name:    "different algorithms",
			profile: crypto.AlgECDSAP384,
			hsm:     crypto.AlgECDSAP256,
			want:    false,
		},
		{
			name:    "RSA algorithms match",
			profile: crypto.AlgRSA2048,
			hsm:     crypto.AlgRSA2048,
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isCompatibleAlgorithm(tt.profile, tt.hsm)
			if got != tt.want {
				t.Errorf("isCompatibleAlgorithm() = %v, want %v", got, tt.want)
			}
		})
	}
}

// =============================================================================
// copyHSMConfig Tests
// =============================================================================

func TestCopyHSMConfig(t *testing.T) {
	tc := newTestContext(t)

	// Create source file
	srcContent := "pkcs11:\n  lib: /path/to/lib.so\n  token: test-token\n"
	srcPath := tc.writeFile("hsm-src.yaml", srcContent)
	dstPath := tc.path("hsm-dst.yaml")

	// Test successful copy
	err := copyHSMConfig(srcPath, dstPath)
	if err != nil {
		t.Fatalf("copyHSMConfig() error = %v", err)
	}

	// Verify content
	data, err := os.ReadFile(dstPath)
	if err != nil {
		t.Fatalf("failed to read destination: %v", err)
	}
	if string(data) != srcContent {
		t.Errorf("copyHSMConfig() content mismatch: got %q, want %q", string(data), srcContent)
	}

	// Test non-existent source
	err = copyHSMConfig("/nonexistent/path.yaml", tc.path("dst.yaml"))
	if err == nil {
		t.Error("copyHSMConfig() expected error for non-existent source")
	}
}
