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

func TestStore_Init(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

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

func TestStore_NextSerial(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

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

func TestIncrementSerial(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		output []byte
	}{
		{"simple", []byte{0x01}, []byte{0x02}},
		{"carry", []byte{0xFF}, []byte{0x01, 0x00}},
		{"multi-byte", []byte{0x01, 0xFF}, []byte{0x02, 0x00}},
		{"multi-carry", []byte{0xFF, 0xFF}, []byte{0x01, 0x00, 0x00}},
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

func TestCA_Initialize(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

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

func TestCA_Initialize_AlreadyExists(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

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

func TestCA_IssueTLSServer(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

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

func TestCA_IssueTLSClient(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

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

func TestCA_IssueSubordinateCA(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

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

func TestCA_LoadSigner(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

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

func TestStore_ReadIndex(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

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

func TestInitializePQCCA(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

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

func TestInitializePQCCA_AllAlgorithms(t *testing.T) {
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
		t.Run(string(alg), func(t *testing.T) {
			tmpDir := t.TempDir()
			store := NewStore(tmpDir)

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

func TestInitializePQCCA_RejectsClassicalAlgorithm(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

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

func TestPQCCA_IssueClassicalCertificate(t *testing.T) {
	// Create PQC CA
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

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

func TestPQCCA_IssuePQCCertificate(t *testing.T) {
	// Create PQC CA
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

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

func TestPQCCA_IssueSubordinateCA(t *testing.T) {
	// Create PQC Root CA
	tmpDir := t.TempDir()
	rootStore := NewStore(filepath.Join(tmpDir, "root"))

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

func TestCatalystCertificateIssuanceAndVerification(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

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
