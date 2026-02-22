package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/remiblancher/qpki/internal/cli"
)

func TestF_TSA_LoadTSACAConfig(t *testing.T) {
	// Create a temp directory for test certs
	tmpDir := t.TempDir()

	// Create a test certificate
	priv, pub := generateECDSAKeyPair(t)
	cert := generateSelfSignedCert(t, priv, pub)
	certPath := filepath.Join(tmpDir, "ca.crt")
	saveCertPEM(t, cert, certPath)

	tests := []struct {
		name        string
		caPath      string
		wantRoots   bool
		wantRawCert bool
		wantErr     bool
	}{
		{
			name:        "empty path",
			caPath:      "",
			wantRoots:   false,
			wantRawCert: false,
			wantErr:     false,
		},
		{
			name:        "valid certificate",
			caPath:      certPath,
			wantRoots:   true,
			wantRawCert: true,
			wantErr:     false,
		},
		{
			name:        "non-existent file",
			caPath:      "/nonexistent/path/ca.crt",
			wantRoots:   false,
			wantRawCert: false,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := cli.LoadTSACAConfig(tt.caPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("cli.LoadTSACAConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			if cfg == nil {
				t.Fatal("cli.LoadTSACAConfig() returned nil config")
			}

			if tt.wantRoots && cfg.Roots == nil {
				t.Error("cli.LoadTSACAConfig() Roots is nil, expected non-nil")
			}
			if !tt.wantRoots && cfg.Roots != nil {
				t.Error("cli.LoadTSACAConfig() Roots is non-nil, expected nil")
			}

			if tt.wantRawCert && len(cfg.RootCertRaw) == 0 {
				t.Error("cli.LoadTSACAConfig() RootCertRaw is empty, expected non-empty")
			}
			if !tt.wantRawCert && len(cfg.RootCertRaw) > 0 {
				t.Error("cli.LoadTSACAConfig() RootCertRaw is non-empty, expected empty")
			}
		})
	}
}

// saveCertPEM saves a certificate in PEM format.
func saveCertPEM(t *testing.T, cert *x509.Certificate, path string) {
	t.Helper()
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	if err := os.WriteFile(path, pemData, 0644); err != nil {
		t.Fatalf("Failed to save cert: %v", err)
	}
}
