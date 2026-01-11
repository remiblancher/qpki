package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/remiblancher/post-quantum-pki/internal/crypto"
	"github.com/remiblancher/post-quantum-pki/internal/profile"
)

// =============================================================================
// Store Unit Tests
// =============================================================================

func TestU_Store_Init(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	if err := store.Init(context.Background()); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	// Check directories exist
	dirs := []string{
		tmpDir,
		filepath.Join(tmpDir, "certs"),
		filepath.Join(tmpDir, "crl"),
		filepath.Join(tmpDir, "private"),
	}
	for _, dir := range dirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			t.Errorf("directory %s does not exist", dir)
		}
	}

	// Check files exist
	files := []string{
		filepath.Join(tmpDir, "serial"),
		filepath.Join(tmpDir, "index.txt"),
	}
	for _, f := range files {
		if _, err := os.Stat(f); os.IsNotExist(err) {
			t.Errorf("file %s does not exist", f)
		}
	}
}

func TestU_Store_NextSerial(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	if err := store.Init(context.Background()); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	// Get first serial
	serial1, err := store.NextSerial(context.Background())
	if err != nil {
		t.Fatalf("NextSerial() error = %v", err)
	}
	if len(serial1) != 1 || serial1[0] != 0x01 {
		t.Errorf("first serial = %x, want 01", serial1)
	}

	// Get second serial
	serial2, err := store.NextSerial(context.Background())
	if err != nil {
		t.Fatalf("NextSerial() error = %v", err)
	}
	if len(serial2) != 1 || serial2[0] != 0x02 {
		t.Errorf("second serial = %x, want 02", serial2)
	}
}

func TestU_IncrementSerial(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		output []byte
	}{
		{"[Unit] Serial Increment: Simple", []byte{0x01}, []byte{0x02}},
		{"[Unit] Serial Increment: Carry", []byte{0xFF}, []byte{0x01, 0x00}},
		{"[Unit] Serial Increment: MultiByte", []byte{0x01, 0xFF}, []byte{0x02, 0x00}},
		{"[Unit] Serial Increment: MultiCarry", []byte{0xFF, 0xFF}, []byte{0x01, 0x00, 0x00}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := incrementSerial(tt.input)
			if len(result) != len(tt.output) {
				t.Errorf("length = %d, want %d", len(result), len(tt.output))
				return
			}
			for i := range result {
				if result[i] != tt.output[i] {
					t.Errorf("result[%d] = %x, want %x", i, result[i], tt.output[i])
				}
			}
		})
	}
}

// =============================================================================
// Store Index Functional Tests
// =============================================================================

func TestF_Store_ReadIndex(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
		Passphrase:    "test-password",
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Build extensions for TLS server
	criticalTrue := true
	criticalFalse := false
	extensions := &profile.ExtensionsConfig{
		KeyUsage: &profile.KeyUsageConfig{
			Critical: &criticalTrue,
			Values:   []string{"digitalSignature", "keyEncipherment"},
		},
		ExtKeyUsage: &profile.ExtKeyUsageConfig{
			Critical: &criticalFalse,
			Values:   []string{"serverAuth"},
		},
		BasicConstraints: &profile.BasicConstraintsConfig{
			Critical: &criticalTrue,
			CA:       false,
		},
	}

	// Issue a few certificates
	for i := 0; i < 3; i++ {
		subjectKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		template := &x509.Certificate{
			Subject:  pkix.Name{CommonName: "server.example.com"},
			DNSNames: []string{"server.example.com"},
		}
		_, err = ca.Issue(context.Background(), IssueRequest{
			Template:   template,
			PublicKey:  &subjectKey.PublicKey,
			Extensions: extensions,
			Validity:   365 * 24 * time.Hour,
		})
		if err != nil {
			t.Fatalf("Issue() error = %v", err)
		}
	}

	// Read index
	entries, err := store.ReadIndex(context.Background())
	if err != nil {
		t.Fatalf("ReadIndex() error = %v", err)
	}

	if len(entries) != 3 {
		t.Errorf("entries count = %d, want 3", len(entries))
	}

	for _, entry := range entries {
		if entry.Status != "V" {
			t.Errorf("entry status = %v, want V", entry.Status)
		}
	}
}
