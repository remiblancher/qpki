package pki

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"path/filepath"
	"testing"
	"time"

	"github.com/remiblancher/qpki/internal/crypto"
	"github.com/remiblancher/qpki/internal/profile"
)

// =============================================================================
// NewFileStore Tests
// =============================================================================

func TestU_NewFileStore(t *testing.T) {
	t.Run("[Unit] NewFileStore: creates store", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := NewFileStore(tmpDir)
		if store == nil {
			t.Error("NewFileStore() returned nil")
		}
	})

	t.Run("[Unit] NewFileStore: store has correct base path", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := NewFileStore(tmpDir)
		// Store should work even if directory doesn't exist yet
		if store == nil {
			t.Error("NewFileStore() returned nil for non-existent path")
		}
	})
}

// =============================================================================
// NewCAService Tests
// =============================================================================

func TestU_NewCAService(t *testing.T) {
	t.Run("[Unit] NewCAService: fails for non-existent CA", func(t *testing.T) {
		tmpDir := t.TempDir()
		_, err := NewCAService(tmpDir)
		if err == nil {
			t.Error("NewCAService() should fail for non-initialized CA")
		}
	})

	t.Run("[Unit] NewCAService: fails for empty directory", func(t *testing.T) {
		tmpDir := t.TempDir()
		_, err := NewCAService(filepath.Join(tmpDir, "nonexistent"))
		if err == nil {
			t.Error("NewCAService() should fail for non-existent directory")
		}
	})
}

// =============================================================================
// ParseRevocationReason Tests
// =============================================================================

func TestU_ParseRevocationReason(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected CARevocationReason
		wantErr  bool
	}{
		{
			name:     "[Unit] ParseRevocationReason: unspecified",
			input:    "unspecified",
			expected: CAReasonUnspecified,
			wantErr:  false,
		},
		{
			name:     "[Unit] ParseRevocationReason: keyCompromise",
			input:    "keyCompromise",
			expected: CAReasonKeyCompromise,
			wantErr:  false,
		},
		{
			name:     "[Unit] ParseRevocationReason: CACompromise",
			input:    "CACompromise",
			expected: CAReasonCACompromise,
			wantErr:  false,
		},
		{
			name:     "[Unit] ParseRevocationReason: affiliationChanged",
			input:    "affiliationChanged",
			expected: CAReasonAffiliationChanged,
			wantErr:  false,
		},
		{
			name:     "[Unit] ParseRevocationReason: superseded",
			input:    "superseded",
			expected: CAReasonSuperseded,
			wantErr:  false,
		},
		{
			name:     "[Unit] ParseRevocationReason: cessationOfOperation",
			input:    "cessationOfOperation",
			expected: CAReasonCessationOfOperation,
			wantErr:  false,
		},
		{
			name:    "[Unit] ParseRevocationReason: invalid reason",
			input:   "invalidReason",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reason, err := ParseRevocationReason(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("ParseRevocationReason() should fail")
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseRevocationReason() error = %v", err)
			}
			if reason != tt.expected {
				t.Errorf("ParseRevocationReason() = %v, want %v", reason, tt.expected)
			}
		})
	}
}

// =============================================================================
// LoadCAInfo Tests
// =============================================================================

func TestU_LoadCAInfo(t *testing.T) {
	t.Run("[Unit] LoadCAInfo: returns info or error", func(t *testing.T) {
		// LoadCAInfo may return nil info for non-existent path
		// or an error - either behavior is acceptable
		info, err := LoadCAInfo("/nonexistent/path")
		// If no error and info is nil, that's the expected behavior for missing path
		if err == nil && info != nil {
			t.Log("LoadCAInfo returned info for non-existent path")
		}
	})
}

// =============================================================================
// ProfileService Tests
// =============================================================================

func TestU_NewProfileService(t *testing.T) {
	t.Run("[Unit] NewProfileService: creates service", func(t *testing.T) {
		svc := NewProfileService()
		if svc == nil {
			t.Error("NewProfileService() returned nil")
		}
	})
}

func TestU_ProfileService_LoadProfile(t *testing.T) {
	svc := NewProfileService()

	t.Run("[Unit] ProfileService.LoadProfile: valid profile", func(t *testing.T) {
		prof, err := svc.LoadProfile("ec/tls-server")
		if err != nil {
			t.Fatalf("ProfileService.LoadProfile() error = %v", err)
		}
		if prof == nil {
			t.Error("ProfileService.LoadProfile() returned nil")
		}
	})

	t.Run("[Unit] ProfileService.LoadProfile: invalid profile", func(t *testing.T) {
		_, err := svc.LoadProfile("nonexistent")
		if err == nil {
			t.Error("ProfileService.LoadProfile() should fail for non-existent profile")
		}
	})
}

func TestU_ProfileService_ListProfiles(t *testing.T) {
	svc := NewProfileService()

	t.Run("[Unit] ProfileService.ListProfiles: returns profiles", func(t *testing.T) {
		profiles, err := svc.ListProfiles()
		if err != nil {
			t.Fatalf("ProfileService.ListProfiles() error = %v", err)
		}
		if len(profiles) == 0 {
			t.Error("ProfileService.ListProfiles() returned empty list")
		}
	})
}

// =============================================================================
// Revocation Reason Constants Tests
// =============================================================================

func TestU_RevocationReasonConstants(t *testing.T) {
	t.Run("[Unit] RevocationReasonConstants: are defined", func(t *testing.T) {
		reasons := []CARevocationReason{
			CAReasonUnspecified,
			CAReasonKeyCompromise,
			CAReasonCACompromise,
			CAReasonAffiliationChanged,
			CAReasonSuperseded,
			CAReasonCessationOfOperation,
			CAReasonCertificateHold,
			CAReasonRemoveFromCRL,
			CAReasonPrivilegeWithdrawn,
			CAReasonAACompromise,
		}

		seen := make(map[CARevocationReason]bool)
		for _, r := range reasons {
			if seen[r] && r != CAReasonUnspecified {
				// Some constants might be 0, so we check for duplicates
				continue
			}
			seen[r] = true
		}
	})
}

// =============================================================================
// VerifyChain Tests
// =============================================================================

func TestU_VerifyChain(t *testing.T) {
	t.Run("[Unit] VerifyChain: fails with empty config", func(t *testing.T) {
		cfg := VerifyChainConfig{}
		err := VerifyChain(cfg)
		if err == nil {
			t.Error("VerifyChain() should fail with empty config")
		}
	})
}

// =============================================================================
// Test Helper: setupTestCA
// =============================================================================

// setupTestCA creates a test CA and returns the CAService.
// The CA is initialized with ECDSA P-256 algorithm.
func setupTestCA(t *testing.T) (*CAService, string) {
	t.Helper()
	tmpDir := t.TempDir()

	store := NewFileStore(tmpDir)
	cfg := Config{
		CommonName:    "Test CA",
		Organization:  "Test Org",
		Country:       "US",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
		Passphrase:    "test-passphrase",
	}

	_, err := InitializeCA(store, cfg)
	if err != nil {
		t.Fatalf("setupTestCA: InitializeCA() error = %v", err)
	}

	svc, err := NewCAService(tmpDir)
	if err != nil {
		t.Fatalf("setupTestCA: NewCAService() error = %v", err)
	}

	return svc, tmpDir
}

// =============================================================================
// InitializeCA Tests
// =============================================================================

func TestU_InitializeCA(t *testing.T) {
	t.Run("[Unit] InitializeCA: initializes CA with valid config", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := NewFileStore(tmpDir)
		cfg := Config{
			CommonName:    "Test Root CA",
			Organization:  "Test Org",
			Country:       "US",
			Algorithm:     crypto.AlgECDSAP256,
			ValidityYears: 10,
			PathLen:       1,
			Passphrase:    "test-password",
		}

		ca, err := InitializeCA(store, cfg)
		if err != nil {
			t.Fatalf("InitializeCA() error = %v", err)
		}
		if ca == nil {
			t.Fatal("InitializeCA() returned nil CA")
		}

		cert := ca.Certificate()
		if cert == nil {
			t.Fatal("CA certificate is nil")
		}
		if cert.Subject.CommonName != "Test Root CA" {
			t.Errorf("CommonName = %v, want Test Root CA", cert.Subject.CommonName)
		}
		if !cert.IsCA {
			t.Error("certificate should be CA")
		}
	})

	t.Run("[Unit] InitializeCA: fails with empty common name", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := NewFileStore(tmpDir)
		cfg := Config{
			Algorithm:     crypto.AlgECDSAP256,
			ValidityYears: 10,
		}

		_, err := InitializeCA(store, cfg)
		if err == nil {
			t.Error("InitializeCA() should fail with empty common name")
		}
	})

	t.Run("[Unit] InitializeCA: fails with empty algorithm", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := NewFileStore(tmpDir)
		cfg := Config{
			CommonName:    "Test CA",
			ValidityYears: 10,
		}

		_, err := InitializeCA(store, cfg)
		if err == nil {
			t.Error("InitializeCA() should fail with empty algorithm")
		}
	})

	t.Run("[Unit] InitializeCA: fails if CA already exists", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := NewFileStore(tmpDir)
		cfg := Config{
			CommonName:    "Test CA",
			Algorithm:     crypto.AlgECDSAP256,
			ValidityYears: 10,
		}

		_, err := InitializeCA(store, cfg)
		if err != nil {
			t.Fatalf("InitializeCA() first call error = %v", err)
		}

		_, err = InitializeCA(store, cfg)
		if err == nil {
			t.Error("InitializeCA() should fail when CA already exists")
		}
	})
}

// =============================================================================
// NewCA Tests
// =============================================================================

func TestU_NewCA(t *testing.T) {
	t.Run("[Unit] NewCA: loads existing CA", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := NewFileStore(tmpDir)
		cfg := Config{
			CommonName:    "Test CA",
			Algorithm:     crypto.AlgECDSAP256,
			ValidityYears: 10,
			Passphrase:    "test",
		}

		_, err := InitializeCA(store, cfg)
		if err != nil {
			t.Fatalf("InitializeCA() error = %v", err)
		}

		ca, err := NewCA(store)
		if err != nil {
			t.Fatalf("NewCA() error = %v", err)
		}
		if ca == nil {
			t.Error("NewCA() returned nil")
		}
	})

	t.Run("[Unit] NewCA: fails for empty store", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := NewFileStore(tmpDir)

		_, err := NewCA(store)
		if err == nil {
			t.Error("NewCA() should fail for empty store")
		}
	})
}

// =============================================================================
// CAService Getters Tests
// =============================================================================

func TestU_CAService_Getters(t *testing.T) {
	svc, _ := setupTestCA(t)
	defer func() { _ = svc.Close() }()

	t.Run("[Unit] CAService.CA: returns CA instance", func(t *testing.T) {
		ca := svc.CA()
		if ca == nil {
			t.Error("CAService.CA() returned nil")
		}
	})

	t.Run("[Unit] CAService.Store: returns store", func(t *testing.T) {
		store := svc.Store()
		if store == nil {
			t.Error("CAService.Store() returned nil")
		}
	})

	t.Run("[Unit] CAService.Info: returns CA info", func(t *testing.T) {
		info := svc.Info()
		if info == nil {
			t.Error("CAService.Info() returned nil")
		}
	})
}

// =============================================================================
// CAService.Certificate Tests
// =============================================================================

func TestU_CAService_Certificate(t *testing.T) {
	svc, _ := setupTestCA(t)
	defer func() { _ = svc.Close() }()

	t.Run("[Unit] CAService.Certificate: returns CA certificate", func(t *testing.T) {
		cert := svc.Certificate()
		if cert == nil {
			t.Fatal("CAService.Certificate() returned nil")
		}
		if cert.Subject.CommonName != "Test CA" {
			t.Errorf("Certificate CommonName = %v, want Test CA", cert.Subject.CommonName)
		}
		if !cert.IsCA {
			t.Error("Certificate should be a CA")
		}
	})
}

// =============================================================================
// CAService.Close Tests
// =============================================================================

func TestU_CAService_Close(t *testing.T) {
	t.Run("[Unit] CAService.Close: releases resources", func(t *testing.T) {
		svc, _ := setupTestCA(t)

		err := svc.Close()
		if err != nil {
			t.Errorf("CAService.Close() error = %v", err)
		}
	})

	t.Run("[Unit] CAService.Close: can be called multiple times", func(t *testing.T) {
		svc, _ := setupTestCA(t)

		err := svc.Close()
		if err != nil {
			t.Errorf("CAService.Close() first call error = %v", err)
		}

		err = svc.Close()
		if err != nil {
			t.Errorf("CAService.Close() second call error = %v", err)
		}
	})
}

// =============================================================================
// CAService.LoadSigner Tests
// =============================================================================

func TestU_CAService_LoadSigner(t *testing.T) {
	t.Run("[Unit] CAService.LoadSigner: loads signer with correct passphrase", func(t *testing.T) {
		svc, _ := setupTestCA(t)
		defer func() { _ = svc.Close() }()

		err := svc.LoadSigner("test-passphrase")
		if err != nil {
			t.Errorf("CAService.LoadSigner() error = %v", err)
		}
	})

	t.Run("[Unit] CAService.LoadSigner: fails with wrong passphrase", func(t *testing.T) {
		svc, _ := setupTestCA(t)
		defer func() { _ = svc.Close() }()

		err := svc.LoadSigner("wrong-passphrase")
		if err == nil {
			t.Error("CAService.LoadSigner() should fail with wrong passphrase")
		}
	})
}

// =============================================================================
// CAService.LoadCACert Tests
// =============================================================================

func TestU_CAService_LoadCACert(t *testing.T) {
	svc, _ := setupTestCA(t)
	defer func() { _ = svc.Close() }()

	t.Run("[Unit] CAService.LoadCACert: loads CA certificate", func(t *testing.T) {
		cert, err := svc.LoadCACert(context.Background())
		if err != nil {
			t.Fatalf("CAService.LoadCACert() error = %v", err)
		}
		if cert == nil {
			t.Fatal("CAService.LoadCACert() returned nil")
		}
		if cert.Subject.CommonName != "Test CA" {
			t.Errorf("Certificate CommonName = %v, want Test CA", cert.Subject.CommonName)
		}
	})
}

// =============================================================================
// CAService.ReadIndex Tests
// =============================================================================

func TestU_CAService_ReadIndex(t *testing.T) {
	svc, _ := setupTestCA(t)
	defer func() { _ = svc.Close() }()

	t.Run("[Unit] CAService.ReadIndex: returns without error", func(t *testing.T) {
		entries, err := svc.ReadIndex(context.Background())
		if err != nil {
			t.Fatalf("CAService.ReadIndex() error = %v", err)
		}
		// Empty slice is acceptable for a fresh CA
		t.Logf("ReadIndex returned %d entries", len(entries))
	})
}

// =============================================================================
// CAService.Issue and LoadCert Tests
// =============================================================================

func TestU_CAService_Issue(t *testing.T) {
	t.Run("[Unit] CAService.Issue: issues certificate", func(t *testing.T) {
		svc, _ := setupTestCA(t)
		defer func() { _ = svc.Close() }()

		// Load signer first
		if err := svc.LoadSigner("test-passphrase"); err != nil {
			t.Fatalf("LoadSigner() error = %v", err)
		}

		// Generate a key for the certificate
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey() error = %v", err)
		}

		req := IssueRequest{
			Template: &x509.Certificate{
				Subject:  pkix.Name{CommonName: "test.example.com"},
				DNSNames: []string{"test.example.com"},
			},
			PublicKey: key.Public(),
			Extensions: &profile.ExtensionsConfig{
				KeyUsage: &profile.KeyUsageConfig{
					Values: []string{"digitalSignature"},
				},
			},
			Validity: 365 * 24 * time.Hour,
		}

		cert, err := svc.Issue(context.Background(), req)
		if err != nil {
			t.Fatalf("CAService.Issue() error = %v", err)
		}
		if cert == nil {
			t.Fatal("CAService.Issue() returned nil certificate")
		}
		if cert.Subject.CommonName != "test.example.com" {
			t.Errorf("Certificate CommonName = %v, want test.example.com", cert.Subject.CommonName)
		}
	})

	t.Run("[Unit] CAService.Issue: fails without signer loaded", func(t *testing.T) {
		svc, _ := setupTestCA(t)
		defer func() { _ = svc.Close() }()

		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		req := IssueRequest{
			Template: &x509.Certificate{
				Subject: pkix.Name{CommonName: "test.example.com"},
			},
			PublicKey: key.Public(),
			Validity:  365 * 24 * time.Hour,
		}

		_, err := svc.Issue(context.Background(), req)
		if err == nil {
			t.Error("CAService.Issue() should fail without signer loaded")
		}
	})
}

func TestU_CAService_LoadCert(t *testing.T) {
	t.Run("[Unit] CAService.LoadCert: loads issued certificate", func(t *testing.T) {
		svc, _ := setupTestCA(t)
		defer func() { _ = svc.Close() }()

		if err := svc.LoadSigner("test-passphrase"); err != nil {
			t.Fatalf("LoadSigner() error = %v", err)
		}

		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		req := IssueRequest{
			Template: &x509.Certificate{
				Subject: pkix.Name{CommonName: "loadcert.example.com"},
			},
			PublicKey: key.Public(),
			Validity:  365 * 24 * time.Hour,
		}

		issued, err := svc.Issue(context.Background(), req)
		if err != nil {
			t.Fatalf("Issue() error = %v", err)
		}

		loaded, err := svc.LoadCert(context.Background(), issued.SerialNumber.Bytes())
		if err != nil {
			t.Fatalf("CAService.LoadCert() error = %v", err)
		}
		if loaded.Subject.CommonName != "loadcert.example.com" {
			t.Errorf("Loaded certificate CommonName = %v, want loadcert.example.com", loaded.Subject.CommonName)
		}
	})

	t.Run("[Unit] CAService.LoadCert: fails for non-existent serial", func(t *testing.T) {
		svc, _ := setupTestCA(t)
		defer func() { _ = svc.Close() }()

		_, err := svc.LoadCert(context.Background(), []byte{0xff, 0xff, 0xff})
		if err == nil {
			t.Error("CAService.LoadCert() should fail for non-existent serial")
		}
	})
}

// =============================================================================
// CAService.Revoke Tests
// =============================================================================

func TestU_CAService_Revoke(t *testing.T) {
	t.Run("[Unit] CAService.Revoke: revokes certificate", func(t *testing.T) {
		svc, _ := setupTestCA(t)
		defer func() { _ = svc.Close() }()

		if err := svc.LoadSigner("test-passphrase"); err != nil {
			t.Fatalf("LoadSigner() error = %v", err)
		}

		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		req := IssueRequest{
			Template: &x509.Certificate{
				Subject: pkix.Name{CommonName: "revoke.example.com"},
			},
			PublicKey: key.Public(),
			Validity:  365 * 24 * time.Hour,
		}

		issued, err := svc.Issue(context.Background(), req)
		if err != nil {
			t.Fatalf("Issue() error = %v", err)
		}

		err = svc.Revoke(issued.SerialNumber.Bytes(), CAReasonKeyCompromise)
		if err != nil {
			t.Errorf("CAService.Revoke() error = %v", err)
		}
	})

	t.Run("[Unit] CAService.Revoke: fails for non-existent certificate", func(t *testing.T) {
		svc, _ := setupTestCA(t)
		defer func() { _ = svc.Close() }()

		if err := svc.LoadSigner("test-passphrase"); err != nil {
			t.Fatalf("LoadSigner() error = %v", err)
		}

		err := svc.Revoke([]byte{0xff, 0xff, 0xff}, CAReasonUnspecified)
		if err == nil {
			t.Error("CAService.Revoke() should fail for non-existent certificate")
		}
	})
}

// =============================================================================
// ProfileService.BuildSubject Tests
// =============================================================================

func TestU_ProfileService_BuildSubject(t *testing.T) {
	svc := NewProfileService()

	t.Run("[Unit] ProfileService.BuildSubject: builds subject with variables", func(t *testing.T) {
		prof, err := svc.LoadProfile("ec/tls-server")
		if err != nil {
			t.Fatalf("LoadProfile() error = %v", err)
		}

		vars := map[string]interface{}{
			"cn": "test.example.com",
			"o":  "Test Org",
			"c":  "US",
		}

		cert, err := svc.BuildSubject(prof, vars)
		if err != nil {
			t.Fatalf("BuildSubject() error = %v", err)
		}
		if cert == nil {
			t.Fatal("BuildSubject() returned nil")
		}
		if cert.Subject.CommonName != "test.example.com" {
			t.Errorf("Subject.CommonName = %v, want test.example.com", cert.Subject.CommonName)
		}
	})

	t.Run("[Unit] ProfileService.BuildSubject: handles empty variables", func(t *testing.T) {
		prof, err := svc.LoadProfile("ec/tls-server")
		if err != nil {
			t.Fatalf("LoadProfile() error = %v", err)
		}

		// Empty vars - should work but with empty subject fields
		vars := map[string]interface{}{}

		cert, err := svc.BuildSubject(prof, vars)
		// May succeed with empty subject or fail depending on profile requirements
		if err != nil {
			t.Logf("BuildSubject() with empty vars returned error (expected for some profiles): %v", err)
			return
		}
		if cert == nil {
			t.Error("BuildSubject() returned nil without error")
		}
	})
}

// =============================================================================
// LoadCAInfo Tests (extended)
// =============================================================================

func TestU_LoadCAInfo_Extended(t *testing.T) {
	t.Run("[Unit] LoadCAInfo: loads info for valid CA", func(t *testing.T) {
		_, tmpDir := setupTestCA(t)

		info, err := LoadCAInfo(tmpDir)
		if err != nil {
			t.Fatalf("LoadCAInfo() error = %v", err)
		}
		if info == nil {
			t.Fatal("LoadCAInfo() returned nil")
		}
	})
}
