package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/slhdsa"
	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
	"github.com/remiblancher/post-quantum-pki/internal/x509util"
)

// =============================================================================
// PQCCAConfig Tests
// =============================================================================

func TestPQCCAConfig_Fields(t *testing.T) {
	cfg := PQCCAConfig{
		CommonName:    "Test PQC CA",
		Organization:  "Test Org",
		Country:       "US",
		Algorithm:     pkicrypto.AlgMLDSA65,
		ValidityYears: 10,
		PathLen:       1,
		Passphrase:    "testpass",
	}

	if cfg.CommonName != "Test PQC CA" {
		t.Errorf("CommonName = %s, want Test PQC CA", cfg.CommonName)
	}
	if cfg.Organization != "Test Org" {
		t.Errorf("Organization = %s, want Test Org", cfg.Organization)
	}
	if cfg.Country != "US" {
		t.Errorf("Country = %s, want US", cfg.Country)
	}
	if cfg.Algorithm != pkicrypto.AlgMLDSA65 {
		t.Errorf("Algorithm = %s, want ML-DSA-65", cfg.Algorithm)
	}
	if cfg.ValidityYears != 10 {
		t.Errorf("ValidityYears = %d, want 10", cfg.ValidityYears)
	}
	if cfg.PathLen != 1 {
		t.Errorf("PathLen = %d, want 1", cfg.PathLen)
	}
}

// =============================================================================
// InitializePQCCA Tests
// =============================================================================

func TestInitializePQCCA_MLDSA65(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

	cfg := PQCCAConfig{
		CommonName:    "Test ML-DSA-65 CA",
		Organization:  "Test Org",
		Country:       "US",
		Algorithm:     pkicrypto.AlgMLDSA65,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := InitializePQCCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializePQCCA() error = %v", err)
	}

	if ca == nil {
		t.Fatal("InitializePQCCA() returned nil CA")
	}

	cert := ca.Certificate()
	if cert == nil {
		t.Fatal("CA certificate is nil")
	}

	if cert.Subject.CommonName != "Test ML-DSA-65 CA" {
		t.Errorf("CN = %s, want Test ML-DSA-65 CA", cert.Subject.CommonName)
	}

	if !cert.IsCA {
		t.Error("certificate should be a CA")
	}
}

func TestInitializePQCCA_MLDSA87(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

	cfg := PQCCAConfig{
		CommonName:    "Test ML-DSA-87 CA",
		Algorithm:     pkicrypto.AlgMLDSA87,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := InitializePQCCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializePQCCA() error = %v", err)
	}

	if ca == nil {
		t.Fatal("InitializePQCCA() returned nil CA")
	}
}

func TestInitializePQCCA_AlreadyExists(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

	cfg := PQCCAConfig{
		CommonName:    "Test PQC CA",
		Algorithm:     pkicrypto.AlgMLDSA65,
		ValidityYears: 10,
		PathLen:       1,
	}

	// Initialize first time
	_, err := InitializePQCCA(store, cfg)
	if err != nil {
		t.Fatalf("First InitializePQCCA() error = %v", err)
	}

	// Try to initialize again - should fail
	_, err = InitializePQCCA(store, cfg)
	if err == nil {
		t.Error("Second InitializePQCCA() should fail")
	}
}

func TestInitializePQCCA_NonPQCAlgorithm(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

	cfg := PQCCAConfig{
		CommonName:    "Test CA",
		Algorithm:     pkicrypto.AlgECDSAP256, // Classical algorithm
		ValidityYears: 10,
		PathLen:       1,
	}

	_, err := InitializePQCCA(store, cfg)
	if err == nil {
		t.Error("InitializePQCCA() should fail for non-PQC algorithm")
	}
}

func TestInitializePQCCA_WithPassphrase(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

	cfg := PQCCAConfig{
		CommonName:    "Test PQC CA",
		Algorithm:     pkicrypto.AlgMLDSA65,
		ValidityYears: 10,
		PathLen:       1,
		Passphrase:    "testpass",
	}

	ca, err := InitializePQCCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializePQCCA() error = %v", err)
	}

	if ca == nil {
		t.Fatal("InitializePQCCA() returned nil CA")
	}
}

// =============================================================================
// algorithmToOID Tests
// =============================================================================

func TestAlgorithmToOID(t *testing.T) {
	tests := []struct {
		alg     pkicrypto.AlgorithmID
		wantErr bool
	}{
		{pkicrypto.AlgMLDSA44, false},
		{pkicrypto.AlgMLDSA65, false},
		{pkicrypto.AlgMLDSA87, false},
		{pkicrypto.AlgSLHDSA128s, false},
		{pkicrypto.AlgSLHDSA128f, false},
		{pkicrypto.AlgSLHDSA192s, false},
		{pkicrypto.AlgSLHDSA192f, false},
		{pkicrypto.AlgSLHDSA256s, false},
		{pkicrypto.AlgSLHDSA256f, false},
		{pkicrypto.AlgECDSAP256, true}, // Not a PQC algorithm
		{"invalid", true},
	}

	for _, tt := range tests {
		t.Run(string(tt.alg), func(t *testing.T) {
			oid, err := algorithmToOID(tt.alg)
			if (err != nil) != tt.wantErr {
				t.Errorf("algorithmToOID(%s) error = %v, wantErr %v", tt.alg, err, tt.wantErr)
			}
			if !tt.wantErr && oid == nil {
				t.Errorf("algorithmToOID(%s) returned nil OID", tt.alg)
			}
		})
	}
}

// =============================================================================
// slhdsaIDToOID Tests
// =============================================================================

func TestSlhdsaIDToOID(t *testing.T) {
	tests := []struct {
		name    string
		id      slhdsa.ID
		wantNil bool
	}{
		{"SHA2_128s", slhdsa.SHA2_128s, false},
		{"SHA2_128f", slhdsa.SHA2_128f, false},
		{"SHA2_192s", slhdsa.SHA2_192s, false},
		{"SHA2_192f", slhdsa.SHA2_192f, false},
		{"SHA2_256s", slhdsa.SHA2_256s, false},
		{"SHA2_256f", slhdsa.SHA2_256f, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oid := slhdsaIDToOID(tt.id)
			if (oid == nil) != tt.wantNil {
				t.Errorf("slhdsaIDToOID(%v) returned nil = %v, wantNil %v", tt.id, oid == nil, tt.wantNil)
			}
		})
	}
}

// =============================================================================
// oidToAlgorithm Tests
// =============================================================================

func TestOidToAlgorithm(t *testing.T) {
	tests := []struct {
		name    string
		sigAlg  x509.SignatureAlgorithm
		wantErr bool
	}{
		{"ECDSA-SHA256", x509.ECDSAWithSHA256, false},
		{"ECDSA-SHA384", x509.ECDSAWithSHA384, false},
		{"ECDSA-SHA512", x509.ECDSAWithSHA512, false},
		{"Ed25519", x509.PureEd25519, false},
		{"SHA256-RSA", x509.SHA256WithRSA, false},
		{"Unknown", x509.UnknownSignatureAlgorithm, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := oidToAlgorithm(tt.sigAlg)
			if (err != nil) != tt.wantErr {
				t.Errorf("oidToAlgorithm(%v) error = %v, wantErr %v", tt.sigAlg, err, tt.wantErr)
			}
		})
	}
}

// =============================================================================
// buildName Tests
// =============================================================================

func TestBuildName(t *testing.T) {
	tests := []struct {
		name    string
		cn      string
		org     string
		country string
		wantLen int
	}{
		{"all fields", "Test CN", "Test Org", "US", 3},
		{"CN only", "Test CN", "", "", 1},
		{"no fields", "", "", "", 0},
		{"CN and org", "Test CN", "Test Org", "", 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rdns := buildName(tt.cn, tt.org, tt.country)
			if len(rdns) != tt.wantLen {
				t.Errorf("buildName() returned %d RDNs, want %d", len(rdns), tt.wantLen)
			}
		})
	}
}

// =============================================================================
// buildCAExtensions Tests
// =============================================================================

func TestBuildCAExtensions(t *testing.T) {
	skid := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}

	exts, err := buildCAExtensions(1, skid)
	if err != nil {
		t.Fatalf("buildCAExtensions() error = %v", err)
	}

	// Should have: BasicConstraints, KeyUsage, SubjectKeyIdentifier
	if len(exts) < 3 {
		t.Errorf("buildCAExtensions() returned %d extensions, want at least 3", len(exts))
	}

	// Check for BasicConstraints
	hasBC := false
	for _, ext := range exts {
		if ext.Id.Equal(x509util.OIDExtBasicConstraints) {
			hasBC = true
			if !ext.Critical {
				t.Error("BasicConstraints should be critical")
			}
		}
	}
	if !hasBC {
		t.Error("buildCAExtensions() should include BasicConstraints")
	}
}

// =============================================================================
// IsPQCSigner Tests
// =============================================================================

func TestCA_IsPQCSigner(t *testing.T) {
	t.Run("PQC signer", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := NewStore(tmpDir)

		cfg := PQCCAConfig{
			CommonName:    "Test PQC CA",
			Algorithm:     pkicrypto.AlgMLDSA65,
			ValidityYears: 10,
			PathLen:       1,
		}

		ca, err := InitializePQCCA(store, cfg)
		if err != nil {
			t.Fatalf("InitializePQCCA() error = %v", err)
		}

		if !ca.IsPQCSigner() {
			t.Error("IsPQCSigner() should return true for PQC CA")
		}
	})

	t.Run("Classical signer", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := NewStore(tmpDir)

		cfg := Config{
			CommonName:    "Test ECDSA CA",
			Algorithm:     pkicrypto.AlgECDSAP256,
			ValidityYears: 10,
			PathLen:       1,
		}

		ca, err := Initialize(store, cfg)
		if err != nil {
			t.Fatalf("Initialize() error = %v", err)
		}

		if ca.IsPQCSigner() {
			t.Error("IsPQCSigner() should return false for classical CA")
		}
	})

	t.Run("No signer", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := NewStore(tmpDir)

		cfg := Config{
			CommonName:    "Test CA",
			Algorithm:     pkicrypto.AlgECDSAP256,
			ValidityYears: 10,
			PathLen:       1,
			Passphrase:    "test",
		}

		_, err := Initialize(store, cfg)
		if err != nil {
			t.Fatalf("Initialize() error = %v", err)
		}

		ca, err := New(store)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}

		if ca.IsPQCSigner() {
			t.Error("IsPQCSigner() should return false when no signer loaded")
		}
	})
}

// =============================================================================
// IsPQCPublicKey Tests
// =============================================================================

func TestIsPQCPublicKey(t *testing.T) {
	t.Run("Classical ECDSA key", func(t *testing.T) {
		privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if IsPQCPublicKey(&privKey.PublicKey) {
			t.Error("IsPQCPublicKey() should return false for ECDSA public key")
		}
	})

	t.Run("ML-DSA key", func(t *testing.T) {
		signer, err := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgMLDSA65)
		if err != nil {
			t.Fatalf("GenerateSoftwareSigner() error = %v", err)
		}

		if !IsPQCPublicKey(signer.Public()) {
			t.Error("IsPQCPublicKey() should return true for ML-DSA public key")
		}
	})
}

// =============================================================================
// VerifyPQCCertificateRaw Tests
// =============================================================================

func TestVerifyPQCCertificateRaw_SelfSigned(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

	cfg := PQCCAConfig{
		CommonName:    "Test PQC CA",
		Algorithm:     pkicrypto.AlgMLDSA65,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := InitializePQCCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializePQCCA() error = %v", err)
	}

	cert := ca.Certificate()

	// Verify self-signed PQC certificate
	valid, err := VerifyPQCCertificateRaw(cert.Raw, cert)
	if err != nil {
		t.Fatalf("VerifyPQCCertificateRaw() error = %v", err)
	}

	if !valid {
		t.Error("VerifyPQCCertificateRaw() should return true for valid self-signed certificate")
	}
}

func TestVerifyPQCCertificateRaw_MLDSA87(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

	cfg := PQCCAConfig{
		CommonName:    "Test ML-DSA-87 CA",
		Algorithm:     pkicrypto.AlgMLDSA87,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := InitializePQCCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializePQCCA() error = %v", err)
	}

	cert := ca.Certificate()

	// Verify self-signed PQC certificate
	valid, err := VerifyPQCCertificateRaw(cert.Raw, cert)
	if err != nil {
		t.Fatalf("VerifyPQCCertificateRaw() error = %v", err)
	}

	if !valid {
		t.Error("VerifyPQCCertificateRaw() should return true for valid ML-DSA-87 certificate")
	}
}

func TestVerifyPQCCertificateRaw_InvalidDER(t *testing.T) {
	// Create a valid CA for issuer
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

	cfg := PQCCAConfig{
		CommonName:    "Test PQC CA",
		Algorithm:     pkicrypto.AlgMLDSA65,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := InitializePQCCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializePQCCA() error = %v", err)
	}

	// Try to verify invalid DER
	_, err = VerifyPQCCertificateRaw([]byte("invalid"), ca.Certificate())
	if err == nil {
		t.Error("VerifyPQCCertificateRaw() should fail for invalid DER")
	}
}

// =============================================================================
// IssuePQC Tests
// =============================================================================

func TestCA_IssuePQC_MLDSA(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

	cfg := PQCCAConfig{
		CommonName:    "Test PQC CA",
		Algorithm:     pkicrypto.AlgMLDSA65,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := InitializePQCCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializePQCCA() error = %v", err)
	}

	// Generate subject key
	subjectSigner, err := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgMLDSA65)
	if err != nil {
		t.Fatalf("GenerateSoftwareSigner() error = %v", err)
	}

	cert, err := ca.IssuePQC(IssueRequest{
		Template: &x509.Certificate{
			DNSNames: []string{"test.example.com"},
		},
		PublicKey: subjectSigner.Public(),
		Validity:  365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("IssuePQC() error = %v", err)
	}

	if cert == nil {
		t.Fatal("IssuePQC() returned nil certificate")
	}
}

func TestCA_IssuePQC_NoSigner(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

	cfg := PQCCAConfig{
		CommonName:    "Test PQC CA",
		Algorithm:     pkicrypto.AlgMLDSA65,
		ValidityYears: 10,
		PathLen:       1,
		Passphrase:    "test",
	}

	_, err := InitializePQCCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializePQCCA() error = %v", err)
	}

	// Load CA without signer
	ca, err := New(store)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	subjectSigner, _ := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgMLDSA65)

	_, err = ca.IssuePQC(IssueRequest{
		PublicKey: subjectSigner.Public(),
	})
	if err == nil {
		t.Error("IssuePQC() should fail when signer not loaded")
	}
}

// =============================================================================
// encodeKeyUsage Tests
// =============================================================================

func TestEncodeKeyUsage(t *testing.T) {
	tests := []struct {
		name string
		ku   x509.KeyUsage
	}{
		{"digital signature", x509.KeyUsageDigitalSignature},
		{"key encipherment", x509.KeyUsageKeyEncipherment},
		{"cert sign", x509.KeyUsageCertSign},
		{"crl sign", x509.KeyUsageCRLSign},
		{"multiple", x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bs := encodeKeyUsage(tt.ku)
			if len(bs.Bytes) == 0 {
				t.Error("encodeKeyUsage() returned empty bytes")
			}
		})
	}
}

// =============================================================================
// encodeExtKeyUsage Tests
// =============================================================================

func TestEncodeExtKeyUsage(t *testing.T) {
	tests := []struct {
		name string
		ekus []x509.ExtKeyUsage
	}{
		{"server auth", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}},
		{"client auth", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}},
		{"code signing", []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}},
		{"multiple", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			der, err := encodeExtKeyUsage(tt.ekus)
			if err != nil {
				t.Errorf("encodeExtKeyUsage() error = %v", err)
			}
			if len(der) == 0 {
				t.Error("encodeExtKeyUsage() returned empty DER")
			}
		})
	}
}

// =============================================================================
// encodeSAN Tests
// =============================================================================

func TestEncodeSAN(t *testing.T) {
	template := &x509.Certificate{
		DNSNames:       []string{"example.com", "www.example.com"},
		EmailAddresses: []string{"test@example.com"},
	}

	der, err := encodeSAN(template)
	if err != nil {
		t.Fatalf("encodeSAN() error = %v", err)
	}

	if len(der) == 0 {
		t.Error("encodeSAN() returned empty DER")
	}
}

// =============================================================================
// getPublicKeyBytes Tests
// =============================================================================

func TestGetPublicKeyBytes(t *testing.T) {
	t.Run("ECDSA key", func(t *testing.T) {
		privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		bytes, err := getPublicKeyBytes(&privKey.PublicKey)
		if err != nil {
			t.Fatalf("getPublicKeyBytes(ECDSA) error = %v", err)
		}
		if len(bytes) == 0 {
			t.Error("getPublicKeyBytes(ECDSA) returned empty bytes")
		}
	})

	t.Run("ML-DSA key", func(t *testing.T) {
		signer, err := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgMLDSA65)
		if err != nil {
			t.Fatalf("GenerateSoftwareSigner() error = %v", err)
		}

		bytes, err := getPublicKeyBytes(signer.Public())
		if err != nil {
			t.Fatalf("getPublicKeyBytes(ML-DSA) error = %v", err)
		}
		if len(bytes) == 0 {
			t.Error("getPublicKeyBytes(ML-DSA) returned empty bytes")
		}
	})
}

// =============================================================================
// encodeSubjectPublicKeyInfo Tests
// =============================================================================

func TestEncodeSubjectPublicKeyInfo(t *testing.T) {
	t.Run("ECDSA key", func(t *testing.T) {
		privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		spki, err := encodeSubjectPublicKeyInfo(&privKey.PublicKey)
		if err != nil {
			t.Fatalf("encodeSubjectPublicKeyInfo(ECDSA) error = %v", err)
		}
		if len(spki.PublicKey.Bytes) == 0 {
			t.Error("encodeSubjectPublicKeyInfo(ECDSA) returned empty public key")
		}
	})

	t.Run("ML-DSA-65 key", func(t *testing.T) {
		signer, err := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgMLDSA65)
		if err != nil {
			t.Fatalf("GenerateSoftwareSigner() error = %v", err)
		}

		spki, err := encodeSubjectPublicKeyInfo(signer.Public())
		if err != nil {
			t.Fatalf("encodeSubjectPublicKeyInfo(ML-DSA-65) error = %v", err)
		}
		if len(spki.PublicKey.Bytes) == 0 {
			t.Error("encodeSubjectPublicKeyInfo(ML-DSA-65) returned empty public key")
		}
	})

	t.Run("ML-DSA-87 key", func(t *testing.T) {
		signer, err := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgMLDSA87)
		if err != nil {
			t.Fatalf("GenerateSoftwareSigner() error = %v", err)
		}

		spki, err := encodeSubjectPublicKeyInfo(signer.Public())
		if err != nil {
			t.Fatalf("encodeSubjectPublicKeyInfo(ML-DSA-87) error = %v", err)
		}
		if len(spki.PublicKey.Bytes) == 0 {
			t.Error("encodeSubjectPublicKeyInfo(ML-DSA-87) returned empty public key")
		}
	})

	t.Run("ML-DSA-44 key", func(t *testing.T) {
		signer, err := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgMLDSA44)
		if err != nil {
			t.Fatalf("GenerateSoftwareSigner() error = %v", err)
		}

		spki, err := encodeSubjectPublicKeyInfo(signer.Public())
		if err != nil {
			t.Fatalf("encodeSubjectPublicKeyInfo(ML-DSA-44) error = %v", err)
		}
		if len(spki.PublicKey.Bytes) == 0 {
			t.Error("encodeSubjectPublicKeyInfo(ML-DSA-44) returned empty public key")
		}
	})
}

// =============================================================================
// buildEndEntityExtensions Tests
// =============================================================================

func TestBuildEndEntityExtensions(t *testing.T) {
	template := &x509.Certificate{
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"example.com"},
	}

	skid := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
	akid := []byte{20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}

	exts, err := buildEndEntityExtensions(template, skid, akid)
	if err != nil {
		t.Fatalf("buildEndEntityExtensions() error = %v", err)
	}

	// Should have: KeyUsage, ExtKeyUsage, SubjectKeyId, AuthorityKeyId, SAN
	if len(exts) < 4 {
		t.Errorf("buildEndEntityExtensions() returned %d extensions, want at least 4", len(exts))
	}
}

func TestBuildEndEntityExtensions_CATemplate(t *testing.T) {
	template := &x509.Certificate{
		IsCA:       true,
		MaxPathLen: 0,
		KeyUsage:   x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	skid := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}

	exts, err := buildEndEntityExtensions(template, skid, nil)
	if err != nil {
		t.Fatalf("buildEndEntityExtensions() error = %v", err)
	}

	// Check for BasicConstraints
	hasBC := false
	for _, ext := range exts {
		if ext.Id.Equal(x509util.OIDExtBasicConstraints) {
			hasBC = true
		}
	}
	if !hasBC {
		t.Error("buildEndEntityExtensions() should include BasicConstraints for CA template")
	}
}
