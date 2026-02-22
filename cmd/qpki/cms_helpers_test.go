package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/remiblancher/qpki/internal/cli"
)

func TestF_CMS_LoadSigningCert(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a test certificate
	priv, pub := generateECDSAKeyPair(t)
	cert := generateSelfSignedCert(t, priv, pub)
	certPath := filepath.Join(tmpDir, "signer.crt")
	saveCertPEMFile(t, cert, certPath)

	// Create invalid PEM file
	invalidPath := filepath.Join(tmpDir, "invalid.crt")
	if err := os.WriteFile(invalidPath, []byte("not a pem file"), 0644); err != nil {
		t.Fatalf("Failed to write invalid file: %v", err)
	}

	tests := []struct {
		name     string
		certPath string
		wantErr  bool
	}{
		{
			name:     "valid certificate",
			certPath: certPath,
			wantErr:  false,
		},
		{
			name:     "non-existent file",
			certPath: "/nonexistent/cert.crt",
			wantErr:  true,
		},
		{
			name:     "invalid PEM",
			certPath: invalidPath,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := cli.LoadSigningCert(tt.certPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("cli.LoadSigningCert() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && cert == nil {
				t.Error("cli.LoadSigningCert() returned nil cert")
			}
		})
	}
}

func TestF_CMS_LoadDecryptionCert(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a test certificate
	priv, pub := generateECDSAKeyPair(t)
	cert := generateSelfSignedCert(t, priv, pub)
	certPath := filepath.Join(tmpDir, "decrypt.crt")
	saveCertPEMFile(t, cert, certPath)

	tests := []struct {
		name     string
		certPath string
		wantErr  bool
	}{
		{
			name:     "valid certificate",
			certPath: certPath,
			wantErr:  false,
		},
		{
			name:     "non-existent file",
			certPath: "/nonexistent/cert.crt",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := cli.LoadDecryptionCert(tt.certPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("cli.LoadDecryptionCert() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && cert == nil {
				t.Error("cli.LoadDecryptionCert() returned nil cert")
			}
		})
	}
}

func TestF_CMS_LoadSigningKey(t *testing.T) {
	// Test with software key
	tmpDir := t.TempDir()
	priv, _ := generateECDSAKeyPair(t)
	keyPath := filepath.Join(tmpDir, "key.pem")
	saveECKeyPEM(t, priv, keyPath)

	tests := []struct {
		name       string
		hsmConfig  string
		keyPath    string
		passphrase string
		keyLabel   string
		keyID      string
		wantErr    bool
	}{
		{
			name:       "software key",
			hsmConfig:  "",
			keyPath:    keyPath,
			passphrase: "",
			keyLabel:   "",
			keyID:      "",
			wantErr:    false,
		},
		{
			name:       "missing software key path",
			hsmConfig:  "",
			keyPath:    "",
			passphrase: "",
			keyLabel:   "",
			keyID:      "",
			wantErr:    true,
		},
		{
			name:       "non-existent key file",
			hsmConfig:  "",
			keyPath:    "/nonexistent/key.pem",
			passphrase: "",
			keyLabel:   "",
			keyID:      "",
			wantErr:    true,
		},
		{
			name:       "hsm config without label or id",
			hsmConfig:  "some-config.yaml", // Will fail because file doesn't exist
			keyPath:    "",
			passphrase: "",
			keyLabel:   "",
			keyID:      "",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer, err := cli.LoadSigningKey(tt.hsmConfig, tt.keyPath, tt.passphrase, tt.keyLabel, tt.keyID, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("cli.LoadSigningKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && signer == nil {
				t.Error("cli.LoadSigningKey() returned nil signer")
			}
		})
	}
}

// saveCertPEMFile saves a certificate in PEM format.
func saveCertPEMFile(t *testing.T, cert *x509.Certificate, path string) {
	t.Helper()
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	if err := os.WriteFile(path, pemData, 0644); err != nil {
		t.Fatalf("Failed to save cert: %v", err)
	}
}

// saveECKeyPEM saves an ECDSA private key in PEM format.
func saveECKeyPEM(t *testing.T, key *ecdsa.PrivateKey, path string) {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("Failed to marshal key: %v", err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	})
	if err := os.WriteFile(path, pemData, 0600); err != nil {
		t.Fatalf("Failed to save key: %v", err)
	}
}

// =============================================================================
// cli.LoadDecryptionKey Tests
// =============================================================================

func TestF_CMS_LoadDecryptionKey(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a test EC key
	priv, _ := generateECDSAKeyPair(t)
	keyPath := filepath.Join(tmpDir, "key.pem")
	saveECKeyPEM(t, priv, keyPath)

	// Create an invalid PEM file
	invalidPath := filepath.Join(tmpDir, "invalid.pem")
	if err := os.WriteFile(invalidPath, []byte("not a pem file"), 0644); err != nil {
		t.Fatalf("Failed to write invalid file: %v", err)
	}

	// Create PKCS8 key
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("Failed to marshal PKCS8: %v", err)
	}
	pkcs8Path := filepath.Join(tmpDir, "pkcs8.pem")
	pkcs8PEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8DER,
	})
	if err := os.WriteFile(pkcs8Path, pkcs8PEM, 0600); err != nil {
		t.Fatalf("Failed to write PKCS8 key: %v", err)
	}

	tests := []struct {
		name       string
		keyPath    string
		passphrase string
		wantErr    bool
	}{
		{
			name:       "valid EC key",
			keyPath:    keyPath,
			passphrase: "",
			wantErr:    false,
		},
		{
			name:       "PKCS8 key",
			keyPath:    pkcs8Path,
			passphrase: "",
			wantErr:    false,
		},
		{
			name:       "non-existent file",
			keyPath:    "/nonexistent/key.pem",
			passphrase: "",
			wantErr:    true,
		},
		{
			name:       "invalid PEM",
			keyPath:    invalidPath,
			passphrase: "",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := cli.LoadDecryptionKey(tt.keyPath, tt.passphrase)
			if (err != nil) != tt.wantErr {
				t.Errorf("cli.LoadDecryptionKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && key == nil {
				t.Error("cli.LoadDecryptionKey() returned nil key")
			}
		})
	}
}

// =============================================================================
// cli.LoadStandardKey Tests
// =============================================================================

func TestF_CMS_LoadStandardKey(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a test EC key
	priv, _ := generateECDSAKeyPair(t)
	keyPath := filepath.Join(tmpDir, "key.pem")
	saveECKeyPEM(t, priv, keyPath)

	tests := []struct {
		name       string
		keyPath    string
		passphrase string
		wantErr    bool
	}{
		{
			name:       "valid EC key",
			keyPath:    keyPath,
			passphrase: "",
			wantErr:    false,
		},
		{
			name:       "non-existent file",
			keyPath:    "/nonexistent/key.pem",
			passphrase: "",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := cli.LoadStandardKey(tt.keyPath, tt.passphrase)
			if (err != nil) != tt.wantErr {
				t.Errorf("cli.LoadStandardKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && key == nil {
				t.Error("cli.LoadStandardKey() returned nil key")
			}
		})
	}
}

// =============================================================================
// cli.LoadPKCS8Key Tests
// =============================================================================

func TestF_CMS_LoadPKCS8Key(t *testing.T) {
	tmpDir := t.TempDir()

	// Create PKCS8 key
	priv, _ := generateECDSAKeyPair(t)
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("Failed to marshal PKCS8: %v", err)
	}
	pkcs8Path := filepath.Join(tmpDir, "pkcs8.pem")
	pkcs8PEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8DER,
	})
	if err := os.WriteFile(pkcs8Path, pkcs8PEM, 0600); err != nil {
		t.Fatalf("Failed to write PKCS8 key: %v", err)
	}

	tests := []struct {
		name       string
		keyPath    string
		passphrase string
		wantErr    bool
	}{
		{
			name:       "valid PKCS8 key",
			keyPath:    pkcs8Path,
			passphrase: "",
			wantErr:    false,
		},
		{
			name:       "non-existent file",
			keyPath:    "/nonexistent/key.pem",
			passphrase: "",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := cli.LoadPKCS8Key(tt.keyPath, tt.passphrase)
			if (err != nil) != tt.wantErr {
				t.Errorf("cli.LoadPKCS8Key() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && key == nil {
				t.Error("cli.LoadPKCS8Key() returned nil key")
			}
		})
	}
}
