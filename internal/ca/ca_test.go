package ca

import (
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

	if err := store.Init(); err != nil {
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

	if err := store.Init(); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	// Get first serial
	serial1, err := store.NextSerial()
	if err != nil {
		t.Fatalf("NextSerial() error = %v", err)
	}
	if len(serial1) != 1 || serial1[0] != 0x01 {
		t.Errorf("first serial = %x, want 01", serial1)
	}

	// Get second serial
	serial2, err := store.NextSerial()
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
// CA Initialization Functional Tests
// =============================================================================

func TestF_CA_Initialize(t *testing.T) {
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

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	cert := ca.Certificate()
	if cert.Subject.CommonName != "Test Root CA" {
		t.Errorf("CommonName = %v, want Test Root CA", cert.Subject.CommonName)
	}
	if !cert.IsCA {
		t.Error("certificate should be CA")
	}
	if cert.MaxPathLen != 1 {
		t.Errorf("MaxPathLen = %d, want 1", cert.MaxPathLen)
	}

	// Verify store has certificate
	if !store.Exists() {
		t.Error("store should show CA exists")
	}

	// Verify we can reload
	loadedCert, err := store.LoadCACert()
	if err != nil {
		t.Fatalf("LoadCACert() error = %v", err)
	}
	if loadedCert.Subject.CommonName != cert.Subject.CommonName {
		t.Error("loaded certificate doesn't match")
	}
}

func TestF_CA_Initialize_AlreadyExists(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	// Initialize first time
	_, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Try to initialize again
	_, err = Initialize(store, cfg)
	if err == nil {
		t.Error("Initialize() should fail when CA already exists")
	}
}

// =============================================================================
// CA Issue Certificate Functional Tests
// =============================================================================

func TestF_CA_IssueTLSServer(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize CA
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

	// Generate subject key
	subjectKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	// Issue TLS server certificate using Issue with explicit extensions
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

	template := &x509.Certificate{
		Subject:  pkix.Name{CommonName: "server.example.com"},
		DNSNames: []string{"server.example.com", "www.example.com"},
	}

	cert, err := ca.Issue(IssueRequest{
		Template:   template,
		PublicKey:  &subjectKey.PublicKey,
		Extensions: extensions,
		Validity:   365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	if cert.Subject.CommonName != "server.example.com" {
		t.Errorf("CommonName = %v, want server.example.com", cert.Subject.CommonName)
	}
	if len(cert.DNSNames) != 2 {
		t.Errorf("DNSNames count = %d, want 2", len(cert.DNSNames))
	}
	if cert.IsCA {
		t.Error("TLS server certificate should not be CA")
	}

	// Verify certificate is signed by CA
	if err := cert.CheckSignatureFrom(ca.Certificate()); err != nil {
		t.Errorf("certificate signature verification failed: %v", err)
	}

	// Verify certificate is stored
	loadedCert, err := store.LoadCert(cert.SerialNumber.Bytes())
	if err != nil {
		t.Fatalf("LoadCert() error = %v", err)
	}
	if loadedCert.Subject.CommonName != cert.Subject.CommonName {
		t.Error("loaded certificate doesn't match")
	}
}

func TestF_CA_IssueTLSClient(t *testing.T) {
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

	subjectKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Issue TLS client certificate using Issue with explicit extensions
	criticalTrue := true
	criticalFalse := false
	extensions := &profile.ExtensionsConfig{
		KeyUsage: &profile.KeyUsageConfig{
			Critical: &criticalTrue,
			Values:   []string{"digitalSignature"},
		},
		ExtKeyUsage: &profile.ExtKeyUsageConfig{
			Critical: &criticalFalse,
			Values:   []string{"clientAuth"},
		},
		BasicConstraints: &profile.BasicConstraintsConfig{
			Critical: &criticalTrue,
			CA:       false,
		},
	}

	template := &x509.Certificate{
		Subject: pkix.Name{CommonName: "client@example.com"},
	}

	cert, err := ca.Issue(IssueRequest{
		Template:   template,
		PublicKey:  &subjectKey.PublicKey,
		Extensions: extensions,
		Validity:   365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	if cert.Subject.CommonName != "client@example.com" {
		t.Errorf("CommonName = %v, want client@example.com", cert.Subject.CommonName)
	}

	if err := cert.CheckSignatureFrom(ca.Certificate()); err != nil {
		t.Errorf("certificate signature verification failed: %v", err)
	}
}

func TestF_CA_IssueSubordinateCA(t *testing.T) {
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

	subCAKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Issue subordinate CA certificate using Issue with explicit extensions
	criticalTrue := true
	pathLen := 0
	extensions := &profile.ExtensionsConfig{
		KeyUsage: &profile.KeyUsageConfig{
			Critical: &criticalTrue,
			Values:   []string{"keyCertSign", "cRLSign"},
		},
		BasicConstraints: &profile.BasicConstraintsConfig{
			Critical: &criticalTrue,
			CA:       true,
			PathLen:  &pathLen,
		},
	}

	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:   "Test Issuing CA",
			Organization: []string{"Test Org"},
		},
	}

	cert, err := ca.Issue(IssueRequest{
		Template:   template,
		PublicKey:  &subCAKey.PublicKey,
		Extensions: extensions,
		Validity:   5 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	if cert.Subject.CommonName != "Test Issuing CA" {
		t.Errorf("CommonName = %v, want Test Issuing CA", cert.Subject.CommonName)
	}
	if !cert.IsCA {
		t.Error("subordinate CA certificate should be CA")
	}
	if cert.MaxPathLen != 0 {
		t.Errorf("MaxPathLen = %d, want 0", cert.MaxPathLen)
	}

	if err := cert.CheckSignatureFrom(ca.Certificate()); err != nil {
		t.Errorf("certificate signature verification failed: %v", err)
	}
}

// =============================================================================
// CA Signer Loading Functional Tests
// =============================================================================

func TestF_CA_LoadSigner(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
		Passphrase:    "test-password",
	}

	_, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Load CA without signer
	ca, err := New(store)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Try to issue without loading signer (should fail)
	subjectKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

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

	template := &x509.Certificate{
		Subject:  pkix.Name{CommonName: "server.example.com"},
		DNSNames: []string{"server.example.com"},
	}

	_, err = ca.Issue(IssueRequest{
		Template:   template,
		PublicKey:  &subjectKey.PublicKey,
		Extensions: extensions,
		Validity:   365 * 24 * time.Hour,
	})
	if err == nil {
		t.Error("Issue should fail without signer loaded")
	}

	// Load signer
	if err := ca.LoadSigner("test-password"); err != nil {
		t.Fatalf("LoadSigner() error = %v", err)
	}

	// Now issue should work
	cert, err := ca.Issue(IssueRequest{
		Template:   template,
		PublicKey:  &subjectKey.PublicKey,
		Extensions: extensions,
		Validity:   365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if cert == nil {
		t.Error("certificate should not be nil")
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
		_, err = ca.Issue(IssueRequest{
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
	entries, err := store.ReadIndex()
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

// =============================================================================
// PQC CA Functional Tests
// =============================================================================

func TestF_InitializePQCCA(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := PQCCAConfig{
		CommonName:    "Test PQC Root CA",
		Organization:  "Test Org",
		Country:       "US",
		Algorithm:     crypto.AlgMLDSA87,
		ValidityYears: 10,
		PathLen:       1,
		Passphrase:    "test-password",
	}

	ca, err := InitializePQCCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializePQCCA() error = %v", err)
	}

	cert := ca.Certificate()
	if cert.Subject.CommonName != "Test PQC Root CA" {
		t.Errorf("CommonName = %v, want Test PQC Root CA", cert.Subject.CommonName)
	}
	if !cert.IsCA {
		t.Error("certificate should be CA")
	}
	if cert.MaxPathLen != 1 {
		t.Errorf("MaxPathLen = %d, want 1", cert.MaxPathLen)
	}

	// Verify store has certificate
	if !store.Exists() {
		t.Error("store should show CA exists")
	}

	// Verify we can reload
	loadedCert, err := store.LoadCACert()
	if err != nil {
		t.Fatalf("LoadCACert() error = %v", err)
	}
	if loadedCert.Subject.CommonName != cert.Subject.CommonName {
		t.Error("loaded certificate doesn't match")
	}

	// Verify the certificate using our PQC verification
	certDER := cert.Raw
	valid, err := VerifyPQCCertificateRaw(certDER, cert)
	if err != nil {
		t.Fatalf("VerifyPQCCertificateRaw() error = %v", err)
	}
	if !valid {
		t.Error("PQC certificate signature should be valid")
	}
}

func TestF_InitializePQCCA_AllAlgorithms(t *testing.T) {
	algorithms := []crypto.AlgorithmID{
		// ML-DSA (FIPS 204)
		crypto.AlgMLDSA44,
		crypto.AlgMLDSA65,
		crypto.AlgMLDSA87,
		// SLH-DSA (FIPS 205) - note: these are slower
		crypto.AlgSLHDSA128s,
		crypto.AlgSLHDSA128f,
		crypto.AlgSLHDSA256f, // Also test 256f variant
	}

	for _, alg := range algorithms {
		t.Run("[Functional] PQC CA Init: "+string(alg), func(t *testing.T) {
			tmpDir := t.TempDir()
			store := NewFileStore(tmpDir)

			cfg := PQCCAConfig{
				CommonName:    "Test " + string(alg) + " CA",
				Algorithm:     alg,
				ValidityYears: 10,
				PathLen:       1,
			}

			ca, err := InitializePQCCA(store, cfg)
			if err != nil {
				t.Fatalf("InitializePQCCA(%s) error = %v", alg, err)
			}

			cert := ca.Certificate()
			if !cert.IsCA {
				t.Errorf("%s: certificate should be CA", alg)
			}

			// Verify signature
			valid, err := VerifyPQCCertificateRaw(cert.Raw, cert)
			if err != nil {
				t.Fatalf("%s: VerifyPQCCertificateRaw() error = %v", alg, err)
			}
			if !valid {
				t.Errorf("%s: signature should be valid", alg)
			}
		})
	}
}

func TestF_InitializePQCCA_RejectsClassicalAlgorithm(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := PQCCAConfig{
		CommonName:    "Test Classical CA",
		Algorithm:     crypto.AlgECDSAP256, // Classical algorithm
		ValidityYears: 10,
		PathLen:       1,
	}

	_, err := InitializePQCCA(store, cfg)
	if err == nil {
		t.Error("InitializePQCCA should reject classical algorithms")
	}
}

// =============================================================================
// PQC CA Issue Functional Tests
// =============================================================================

func TestF_PQCCA_IssueClassicalCertificate(t *testing.T) {
	// Create PQC CA
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := PQCCAConfig{
		CommonName:    "Test PQC Root CA",
		Organization:  "Test Org",
		Country:       "US",
		Algorithm:     crypto.AlgMLDSA65,
		ValidityYears: 10,
		PathLen:       1,
		Passphrase:    "test-password",
	}

	ca, err := InitializePQCCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializePQCCA() error = %v", err)
	}

	// Generate classical key for subject
	subjectKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	// Issue certificate (should route to IssuePQC automatically)
	template := &x509.Certificate{
		Subject:  pkix.Name{CommonName: "server.example.com"},
		DNSNames: []string{"server.example.com"},
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}

	cert, err := ca.Issue(IssueRequest{
		Template:  template,
		PublicKey: &subjectKey.PublicKey,
		Validity:  365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	// Verify certificate properties
	if cert.Subject.CommonName != "server.example.com" {
		t.Errorf("Subject.CommonName = %v, want server.example.com", cert.Subject.CommonName)
	}
	if cert.Issuer.CommonName != "Test PQC Root CA" {
		t.Errorf("Issuer.CommonName = %v, want Test PQC Root CA", cert.Issuer.CommonName)
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "server.example.com" {
		t.Errorf("DNSNames = %v, want [server.example.com]", cert.DNSNames)
	}

	// Verify signature using PQC verification
	valid, err := VerifyPQCCertificateRaw(cert.Raw, ca.Certificate())
	if err != nil {
		t.Fatalf("VerifyPQCCertificateRaw() error = %v", err)
	}
	if !valid {
		t.Error("PQC signature should be valid")
	}
}

func TestF_PQCCA_IssuePQCCertificate(t *testing.T) {
	// Create PQC CA
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := PQCCAConfig{
		CommonName:    "Test PQC Root CA",
		Algorithm:     crypto.AlgMLDSA87,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := InitializePQCCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializePQCCA() error = %v", err)
	}

	// Generate PQC key for subject
	subjectKP, err := crypto.GenerateKeyPair(crypto.AlgMLDSA65)
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	// Issue certificate
	template := &x509.Certificate{
		Subject:  pkix.Name{CommonName: "pqc-service.example.com"},
		KeyUsage: x509.KeyUsageDigitalSignature,
	}

	cert, err := ca.Issue(IssueRequest{
		Template:  template,
		PublicKey: subjectKP.PublicKey,
		Validity:  365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	// Verify certificate properties
	if cert.Subject.CommonName != "pqc-service.example.com" {
		t.Errorf("Subject.CommonName = %v, want pqc-service.example.com", cert.Subject.CommonName)
	}

	// Verify signature using PQC verification
	valid, err := VerifyPQCCertificateRaw(cert.Raw, ca.Certificate())
	if err != nil {
		t.Fatalf("VerifyPQCCertificateRaw() error = %v", err)
	}
	if !valid {
		t.Error("PQC signature should be valid")
	}
}

func TestF_PQCCA_IssueSubordinateCA(t *testing.T) {
	// Create PQC Root CA
	tmpDir := t.TempDir()
	rootStore := NewFileStore(filepath.Join(tmpDir, "root"))

	rootCfg := PQCCAConfig{
		CommonName:    "PQC Root CA",
		Algorithm:     crypto.AlgMLDSA87,
		ValidityYears: 20,
		PathLen:       1,
	}

	rootCA, err := InitializePQCCA(rootStore, rootCfg)
	if err != nil {
		t.Fatalf("InitializePQCCA() error = %v", err)
	}

	// Generate key for subordinate CA
	subKP, err := crypto.GenerateKeyPair(crypto.AlgMLDSA65)
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	// Issue subordinate CA certificate
	template := &x509.Certificate{
		Subject:        pkix.Name{CommonName: "PQC Issuing CA"},
		IsCA:           true,
		MaxPathLen:     0,
		MaxPathLenZero: true, // Explicitly set path length to 0
		KeyUsage:       x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	subCACert, err := rootCA.Issue(IssueRequest{
		Template:  template,
		PublicKey: subKP.PublicKey,
		Validity:  10 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue subordinate CA error = %v", err)
	}

	// Verify certificate properties
	if !subCACert.IsCA {
		t.Error("subordinate CA certificate should be CA")
	}
	if subCACert.MaxPathLen != 0 {
		t.Errorf("MaxPathLen = %d, want 0", subCACert.MaxPathLen)
	}
	if subCACert.Subject.CommonName != "PQC Issuing CA" {
		t.Errorf("Subject.CommonName = %v, want PQC Issuing CA", subCACert.Subject.CommonName)
	}

	// Verify signature
	valid, err := VerifyPQCCertificateRaw(subCACert.Raw, rootCA.Certificate())
	if err != nil {
		t.Fatalf("VerifyPQCCertificateRaw() error = %v", err)
	}
	if !valid {
		t.Error("subordinate CA signature should be valid")
	}
}

// =============================================================================
// CA Store Method Unit Tests
// =============================================================================

func TestU_CA_Store(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Test Store() method returns the same store
	if ca.Store() != store {
		t.Error("Store() should return the same store instance")
	}
	if ca.Store().BasePath() != tmpDir {
		t.Errorf("Store().BasePath() = %v, want %v", ca.Store().BasePath(), tmpDir)
	}
}

func TestF_NewWithSigner(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	// Initialize the CA first
	initCA, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Get the signer from the initialized CA (it's loaded during init with no passphrase)
	// For this test, we just verify NewWithSigner works correctly
	signer, err := crypto.GenerateSoftwareSigner(crypto.AlgECDSAP256)
	if err != nil {
		t.Fatalf("GenerateSoftwareSigner() error = %v", err)
	}

	// Create CA with pre-loaded signer (different signer, just testing the path)
	ca, err := NewWithSigner(store, signer)
	if err != nil {
		t.Fatalf("NewWithSigner() error = %v", err)
	}

	// Verify CA was loaded correctly
	if ca.Certificate().Subject.CommonName != "Test Root CA" {
		t.Errorf("CommonName = %v, want Test Root CA", ca.Certificate().Subject.CommonName)
	}

	// The signer should be set (even if it's a different key)
	// We just verify the function path, not that we can issue
	_ = initCA // Suppress unused warning
}

func TestF_NewWithSigner_CANotExists(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	signer, _ := crypto.GenerateSoftwareSigner(crypto.AlgECDSAP256)

	// Should fail because CA doesn't exist
	_, err := NewWithSigner(store, signer)
	if err == nil {
		t.Error("NewWithSigner() should fail when CA doesn't exist")
	}
}

// =============================================================================
// Catalyst Hybrid Certificate Functional Tests
// =============================================================================

// =============================================================================
// CA Accessor Unit Tests
// =============================================================================

func TestU_CA_Metadata(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
		Profile:       "root-ca",
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Test Metadata() accessor
	metadata := ca.Metadata()
	if metadata == nil {
		t.Fatal("Metadata() should not return nil for newly initialized CA")
	}
	// Verify CAInfo has Subject info
	if metadata.Subject.CommonName == "" {
		t.Error("Metadata().Subject.CommonName should not be empty")
	}
}

func TestU_CA_Metadata_LegacyCA(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
		// No Profile set - simulates legacy CA
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Metadata should still exist
	metadata := ca.Metadata()
	if metadata == nil {
		t.Error("Metadata() should not return nil")
	}
}

func TestU_CA_KeyPaths(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	paths := ca.KeyPaths()
	if len(paths) == 0 {
		t.Error("KeyPaths() should return at least one path")
	}

	// Should have the full algorithm ID key for ECDSA algorithm
	ecPath, ok := paths["ecdsa-p256"]
	if !ok {
		t.Errorf("KeyPaths() should include 'ecdsa-p256' key, got keys: %v", paths)
	}
	if ecPath == "" {
		t.Error("KeyPaths()['ecdsa-p256'] should not be empty")
	}
}

func TestU_CA_DefaultKeyPath(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	keyPath := ca.DefaultKeyPath()
	if keyPath == "" {
		t.Error("DefaultKeyPath() should not return empty string")
	}

	// Should be an absolute path containing the temp dir
	if !filepath.IsAbs(keyPath) {
		t.Errorf("DefaultKeyPath() should return absolute path, got %v", keyPath)
	}
}

func TestU_CA_SetKeyProvider(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	_, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Load CA
	ca, err := New(store)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Default should return software provider
	initialKP := ca.KeyProvider()
	if initialKP == nil {
		t.Error("KeyProvider() should not return nil")
	}

	// Set custom key provider
	customKP := crypto.NewSoftwareKeyProvider()
	customCfg := crypto.KeyStorageConfig{
		Type:    crypto.KeyProviderTypeSoftware,
		KeyPath: "/custom/path/key.pem",
	}

	ca.SetKeyProvider(customKP, customCfg)

	// KeyProvider should return our custom provider
	kp := ca.KeyProvider()
	if kp == nil {
		t.Error("KeyProvider() should not return nil after SetKeyProvider")
	}

	// KeyStorageConfig should return our custom config
	retrievedCfg := ca.KeyStorageConfig()
	if retrievedCfg.KeyPath != "/custom/path/key.pem" {
		t.Errorf("KeyStorageConfig().KeyPath = %v, want /custom/path/key.pem", retrievedCfg.KeyPath)
	}
}

func TestU_CA_KeyProvider_Default(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	_, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Load CA fresh (no key provider set)
	ca, err := New(store)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Default KeyProvider should return a SoftwareKeyProvider
	kp := ca.KeyProvider()
	if kp == nil {
		t.Error("KeyProvider() should return default provider when none set")
	}
}

func TestU_CA_KeyStorageConfig_Empty(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	_, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Load CA fresh (no config set)
	ca, err := New(store)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Should return empty config
	config := ca.KeyStorageConfig()
	if config.Type != "" && config.Type != crypto.KeyProviderTypeSoftware {
		t.Errorf("KeyStorageConfig().Type = %v, want empty or software", config.Type)
	}
}

func TestU_CA_KeyPaths_HybridCA(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize Hybrid CA
	cfg := HybridCAConfig{
		CommonName:         "Hybrid Test CA",
		ClassicalAlgorithm: crypto.AlgECDSAP384,
		PQCAlgorithm:       crypto.AlgMLDSA87,
		ValidityYears:      10,
		PathLen:            1,
	}

	ca, err := InitializeHybridCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeHybridCA() error = %v", err)
	}

	paths := ca.KeyPaths()
	if len(paths) < 2 {
		t.Errorf("KeyPaths() for hybrid CA should return at least 2 paths, got %d: %v", len(paths), paths)
	}

	// Should have full algorithm ID keys (ecdsa-p384 for classical, ml-dsa-87 for PQC)
	if _, ok := paths["ecdsa-p384"]; !ok {
		t.Errorf("KeyPaths() for hybrid CA should include 'ecdsa-p384' key, got: %v", paths)
	}
	if _, ok := paths["ml-dsa-87"]; !ok {
		t.Errorf("KeyPaths() for hybrid CA should include 'ml-dsa-87' key, got: %v", paths)
	}
}

func TestU_CA_IsHybridCA(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(t *testing.T) *CA
		expected bool
	}{
		{
			name: "Classical CA is not hybrid",
			setup: func(t *testing.T) *CA {
				tmpDir := t.TempDir()
				store := NewFileStore(tmpDir)
				cfg := Config{
					CommonName:    "Test CA",
					Algorithm:     crypto.AlgECDSAP256,
					ValidityYears: 10,
					PathLen:       1,
				}
				ca, err := Initialize(store, cfg)
				if err != nil {
					t.Fatalf("Initialize() error = %v", err)
				}
				return ca
			},
			expected: false,
		},
		{
			name: "Hybrid CA is hybrid",
			setup: func(t *testing.T) *CA {
				tmpDir := t.TempDir()
				store := NewFileStore(tmpDir)
				cfg := HybridCAConfig{
					CommonName:         "Hybrid CA",
					ClassicalAlgorithm: crypto.AlgECDSAP384,
					PQCAlgorithm:       crypto.AlgMLDSA87,
					ValidityYears:      10,
					PathLen:            1,
				}
				ca, err := InitializeHybridCA(store, cfg)
				if err != nil {
					t.Fatalf("InitializeHybridCA() error = %v", err)
				}
				return ca
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ca := tt.setup(t)
			if ca.IsHybridCA() != tt.expected {
				t.Errorf("IsHybridCA() = %v, want %v", ca.IsHybridCA(), tt.expected)
			}
		})
	}
}

func TestU_CA_GenerateCredentialKey_Software(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Generate credential key
	signer, storageRef, err := ca.GenerateCredentialKey(crypto.AlgECDSAP256, "test-cred", 0)
	if err != nil {
		t.Fatalf("GenerateCredentialKey() error = %v", err)
	}

	if signer == nil {
		t.Error("GenerateCredentialKey() signer should not be nil")
	}
	if storageRef.Type != "software" {
		t.Errorf("GenerateCredentialKey() storageRef.Type = %v, want software", storageRef.Type)
	}
}

// =============================================================================
// Catalyst Hybrid Certificate Functional Tests
// =============================================================================

func TestF_CatalystCertificateIssuanceAndVerification(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize Hybrid CA (ECDSA + ML-DSA)
	cfg := HybridCAConfig{
		CommonName:         "Catalyst Test CA",
		Organization:       "Test Org",
		Country:            "US",
		ClassicalAlgorithm: crypto.AlgECDSAP384,
		PQCAlgorithm:       crypto.AlgMLDSA87,
		ValidityYears:      10,
		PathLen:            1,
	}

	ca, err := InitializeHybridCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeHybridCA() error = %v", err)
	}

	// Generate keys for end-entity certificate
	classicalKP, err := crypto.GenerateKeyPair(crypto.AlgECDSAP256)
	if err != nil {
		t.Fatalf("GenerateKeyPair (classical) error = %v", err)
	}
	pqcKP, err := crypto.GenerateKeyPair(crypto.AlgMLDSA65)
	if err != nil {
		t.Fatalf("GenerateKeyPair (PQC) error = %v", err)
	}

	// Issue Catalyst certificate
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

	template := &x509.Certificate{
		Subject:  pkix.Name{CommonName: "catalyst.example.com"},
		DNSNames: []string{"catalyst.example.com"},
	}

	cert, err := ca.IssueCatalyst(CatalystRequest{
		Template:           template,
		ClassicalPublicKey: classicalKP.PublicKey,
		PQCPublicKey:       pqcKP.PublicKey,
		PQCAlgorithm:       crypto.AlgMLDSA65,
		Extensions:         extensions,
		Validity:           365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("IssueCatalyst() error = %v", err)
	}

	// Verify certificate has Catalyst extensions
	if cert == nil {
		t.Fatal("certificate should not be nil")
	}
	if cert.Subject.CommonName != "catalyst.example.com" {
		t.Errorf("Subject.CommonName = %v, want catalyst.example.com", cert.Subject.CommonName)
	}

	// Verify both signatures
	valid, err := VerifyCatalystSignatures(cert, ca.Certificate())
	if err != nil {
		t.Fatalf("VerifyCatalystSignatures() error = %v", err)
	}
	if !valid {
		t.Error("Catalyst certificate signatures should be valid")
	}

	// Verify classical signature also works with standard Go verification
	roots := x509.NewCertPool()
	roots.AddCert(ca.Certificate())
	opts := x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: time.Now(),
	}
	if _, err := cert.Verify(opts); err != nil {
		t.Errorf("Standard X.509 verification failed: %v", err)
	}
}

// =============================================================================
// Crypto-Agility Tests: LoadAllCACerts and LoadCrossSignedCerts
// =============================================================================

func TestA_LoadAllCACerts_SingleAlgo(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize single-algo CA
	cfg := Config{
		CommonName:    "Single Algo CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	_, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// LoadAllCACerts should return exactly 1 certificate
	certs, err := store.LoadAllCACerts()
	if err != nil {
		t.Fatalf("LoadAllCACerts() error = %v", err)
	}
	if len(certs) != 1 {
		t.Errorf("LoadAllCACerts() returned %d certs, want 1", len(certs))
	}
	if certs[0].Subject.CommonName != "Single Algo CA" {
		t.Errorf("Subject.CommonName = %v, want Single Algo CA", certs[0].Subject.CommonName)
	}
}

func TestA_LoadAllCACerts_Versioned(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize CA
	cfg := Config{
		CommonName:    "Versioned CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
		Passphrase:    "test",
	}

	_, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// LoadAllCACerts should work with versioned CAs
	certs, err := store.LoadAllCACerts()
	if err != nil {
		t.Fatalf("LoadAllCACerts() error = %v", err)
	}
	if len(certs) != 1 {
		t.Errorf("LoadAllCACerts() returned %d certs, want 1", len(certs))
	}
	if certs[0].Subject.CommonName != "Versioned CA" {
		t.Errorf("Subject.CommonName = %v, want Versioned CA", certs[0].Subject.CommonName)
	}
}

// Note: TestA_LoadAllCACerts_HybridCA is tested via CLI integration tests
// in cmd/qpki/credential_test.go:TestA_Credential_Export_Chain_HybridCA

func TestA_LoadCrossSignedCerts_NoCrossSign(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize CA without rotation/cross-signing
	cfg := Config{
		CommonName:    "No CrossSign CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	_, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// LoadCrossSignedCerts should return empty slice (not error)
	certs, err := store.LoadCrossSignedCerts()
	if err != nil {
		t.Fatalf("LoadCrossSignedCerts() error = %v", err)
	}
	if len(certs) != 0 {
		t.Errorf("LoadCrossSignedCerts() returned %d certs, want 0", len(certs))
	}
}

// Note: TestA_LoadCrossSignedCerts_WithCrossSign is tested via CLI integration tests
// in cmd/qpki/ca_test.go:TestA_CA_Export_Chain_WithCrossSign
// because it requires profile loading which is complex at the unit level.
