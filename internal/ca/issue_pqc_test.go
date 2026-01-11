package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/slhdsa"
	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
	"github.com/remiblancher/post-quantum-pki/internal/x509util"
)

// =============================================================================
// algorithmToOID Unit Tests
// =============================================================================

func TestU_AlgorithmToOID(t *testing.T) {
	tests := []struct {
		name    string
		alg     pkicrypto.AlgorithmID
		wantErr bool
	}{
		{"[Unit] AlgToOID: ML-DSA-44", pkicrypto.AlgMLDSA44, false},
		{"[Unit] AlgToOID: ML-DSA-65", pkicrypto.AlgMLDSA65, false},
		{"[Unit] AlgToOID: ML-DSA-87", pkicrypto.AlgMLDSA87, false},
		{"[Unit] AlgToOID: SLH-DSA-128s", pkicrypto.AlgSLHDSA128s, false},
		{"[Unit] AlgToOID: SLH-DSA-128f", pkicrypto.AlgSLHDSA128f, false},
		{"[Unit] AlgToOID: SLH-DSA-192s", pkicrypto.AlgSLHDSA192s, false},
		{"[Unit] AlgToOID: SLH-DSA-192f", pkicrypto.AlgSLHDSA192f, false},
		{"[Unit] AlgToOID: SLH-DSA-256s", pkicrypto.AlgSLHDSA256s, false},
		{"[Unit] AlgToOID: SLH-DSA-256f", pkicrypto.AlgSLHDSA256f, false},
		{"[Unit] AlgToOID: ECDSA-P256 Invalid", pkicrypto.AlgECDSAP256, true},
		{"[Unit] AlgToOID: Invalid", "invalid", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
// slhdsaIDToOID Unit Tests
// =============================================================================

func TestU_SlhdsaIDToOID(t *testing.T) {
	tests := []struct {
		name    string
		id      slhdsa.ID
		wantNil bool
	}{
		{"[Unit] SLHDSA OID: SHA2_128s", slhdsa.SHA2_128s, false},
		{"[Unit] SLHDSA OID: SHA2_128f", slhdsa.SHA2_128f, false},
		{"[Unit] SLHDSA OID: SHA2_192s", slhdsa.SHA2_192s, false},
		{"[Unit] SLHDSA OID: SHA2_192f", slhdsa.SHA2_192f, false},
		{"[Unit] SLHDSA OID: SHA2_256s", slhdsa.SHA2_256s, false},
		{"[Unit] SLHDSA OID: SHA2_256f", slhdsa.SHA2_256f, false},
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
// oidToAlgorithm Unit Tests
// =============================================================================

func TestU_OidToAlgorithm(t *testing.T) {
	tests := []struct {
		name    string
		sigAlg  x509.SignatureAlgorithm
		wantErr bool
	}{
		{"[Unit] OIDToAlg: ECDSA-SHA256", x509.ECDSAWithSHA256, false},
		{"[Unit] OIDToAlg: ECDSA-SHA384", x509.ECDSAWithSHA384, false},
		{"[Unit] OIDToAlg: ECDSA-SHA512", x509.ECDSAWithSHA512, false},
		{"[Unit] OIDToAlg: Ed25519", x509.PureEd25519, false},
		{"[Unit] OIDToAlg: SHA256-RSA", x509.SHA256WithRSA, false},
		{"[Unit] OIDToAlg: Unknown Invalid", x509.UnknownSignatureAlgorithm, true},
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
// buildName Unit Tests
// =============================================================================

func TestU_BuildName(t *testing.T) {
	tests := []struct {
		name    string
		cn      string
		org     string
		country string
		wantLen int
	}{
		{"[Unit] BuildName: All Fields", "Test CN", "Test Org", "US", 3},
		{"[Unit] BuildName: CN Only", "Test CN", "", "", 1},
		{"[Unit] BuildName: No Fields", "", "", "", 0},
		{"[Unit] BuildName: CN and Org", "Test CN", "Test Org", "", 2},
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
// buildCAExtensions Unit Tests
// =============================================================================

func TestU_BuildCAExtensions(t *testing.T) {
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
// IsPQCSigner Functional Tests
// =============================================================================

func TestF_CA_IsPQCSigner(t *testing.T) {
	t.Run("[Functional] IsPQCSigner: PQC Signer", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := NewFileStore(tmpDir)

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

	t.Run("[Functional] IsPQCSigner: Classical Signer", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := NewFileStore(tmpDir)

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

	t.Run("[Functional] IsPQCSigner: No Signer", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := NewFileStore(tmpDir)

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
// IsPQCPublicKey Unit Tests
// =============================================================================

func TestU_IsPQCPublicKey(t *testing.T) {
	t.Run("[Unit] IsPQCKey: Classical ECDSA", func(t *testing.T) {
		privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if IsPQCPublicKey(&privKey.PublicKey) {
			t.Error("IsPQCPublicKey() should return false for ECDSA public key")
		}
	})

	t.Run("[Unit] IsPQCKey: ML-DSA", func(t *testing.T) {
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
// VerifyPQCCertificateRaw Functional Tests
// =============================================================================

func TestF_VerifyPQCCertificateRaw_SelfSigned(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

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

func TestF_VerifyPQCCertificateRaw_MLDSA87(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

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

func TestF_VerifyPQCCertificateRaw_InvalidDER(t *testing.T) {
	// Create a valid CA for issuer
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

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
// IssuePQC Functional Tests
// =============================================================================

func TestF_CA_IssuePQC_MLDSA(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

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

	cert, err := ca.IssuePQC(context.Background(), IssueRequest{
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

func TestF_CA_IssuePQC_SignerMissing(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

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

	_, err = ca.IssuePQC(context.Background(), IssueRequest{
		PublicKey: subjectSigner.Public(),
	})
	if err == nil {
		t.Error("IssuePQC() should fail when signer not loaded")
	}
}

// =============================================================================
// buildEndEntityExtensions Unit Tests
// =============================================================================

func TestU_BuildEndEntityExtensions_AllExtensions(t *testing.T) {
	// Create a template with all extension types
	template := &x509.Certificate{
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  false,
		BasicConstraintsValid: true,
		DNSNames:              []string{"example.com", "www.example.com"},
		EmailAddresses:        []string{"admin@example.com"},
		IPAddresses:           []net.IP{net.ParseIP("192.168.1.1")},
		CRLDistributionPoints: []string{"http://crl.example.com/crl.pem"},
		OCSPServer:            []string{"http://ocsp.example.com"},
		IssuingCertificateURL: []string{"http://ca.example.com/ca.pem"},
		ExtraExtensions: []pkix.Extension{
			{
				Id:       asn1.ObjectIdentifier{2, 5, 29, 32}, // Certificate Policies
				Critical: false,
				Value:    []byte{0x30, 0x00}, // Empty SEQUENCE (simplified)
			},
		},
	}

	subjectKeyId := []byte{1, 2, 3, 4, 5}
	authorityKeyId := []byte{6, 7, 8, 9, 10}

	exts, err := buildEndEntityExtensions(template, subjectKeyId, authorityKeyId, false)
	if err != nil {
		t.Fatalf("buildEndEntityExtensions() error = %v", err)
	}

	// Check that all expected extensions are present
	expectedOIDs := map[string]bool{
		"2.5.29.15":         false, // Key Usage
		"2.5.29.37":         false, // Extended Key Usage
		"2.5.29.14":         false, // Subject Key Identifier
		"2.5.29.35":         false, // Authority Key Identifier
		"2.5.29.17":         false, // Subject Alternative Name
		"2.5.29.31":         false, // CRL Distribution Points
		"1.3.6.1.5.5.7.1.1": false, // Authority Information Access
		"2.5.29.32":         false, // Certificate Policies (from ExtraExtensions)
	}

	for _, ext := range exts {
		oidStr := ext.Id.String()
		if _, ok := expectedOIDs[oidStr]; ok {
			expectedOIDs[oidStr] = true
		}
	}

	for oid, found := range expectedOIDs {
		if !found {
			t.Errorf("Extension with OID %s not found in result", oid)
		}
	}
}

func TestU_BuildEndEntityExtensions_CRLDistributionPoints(t *testing.T) {
	template := &x509.Certificate{
		CRLDistributionPoints: []string{
			"http://crl.example.com/crl.pem",
			"http://crl2.example.com/crl.pem",
		},
	}

	exts, err := buildEndEntityExtensions(template, []byte{1, 2, 3}, nil, false)
	if err != nil {
		t.Fatalf("buildEndEntityExtensions() error = %v", err)
	}

	// Find CRL DP extension
	var cdpExt *pkix.Extension
	for i := range exts {
		if exts[i].Id.Equal(x509util.OIDExtCRLDistributionPoints) {
			cdpExt = &exts[i]
			break
		}
	}

	if cdpExt == nil {
		t.Fatal("CRL Distribution Points extension not found")
	}

	if cdpExt.Critical {
		t.Error("CRL Distribution Points should not be critical")
	}
}

func TestU_BuildEndEntityExtensions_AuthorityInfoAccess(t *testing.T) {
	template := &x509.Certificate{
		OCSPServer:            []string{"http://ocsp.example.com"},
		IssuingCertificateURL: []string{"http://ca.example.com/ca.pem"},
	}

	exts, err := buildEndEntityExtensions(template, []byte{1, 2, 3}, nil, false)
	if err != nil {
		t.Fatalf("buildEndEntityExtensions() error = %v", err)
	}

	// Find AIA extension
	var aiaExt *pkix.Extension
	for i := range exts {
		if exts[i].Id.Equal(x509util.OIDExtAuthorityInfoAccess) {
			aiaExt = &exts[i]
			break
		}
	}

	if aiaExt == nil {
		t.Fatal("Authority Information Access extension not found")
	}

	if aiaExt.Critical {
		t.Error("Authority Information Access should not be critical")
	}
}

func TestU_BuildEndEntityExtensions_ExtraExtensions(t *testing.T) {
	// Custom extension (simulating OCSPNoCheck)
	customOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}
	nullValue, _ := asn1.Marshal(asn1.NullRawValue)

	template := &x509.Certificate{
		ExtraExtensions: []pkix.Extension{
			{
				Id:       customOID,
				Critical: false,
				Value:    nullValue,
			},
		},
	}

	exts, err := buildEndEntityExtensions(template, []byte{1, 2, 3}, nil, false)
	if err != nil {
		t.Fatalf("buildEndEntityExtensions() error = %v", err)
	}

	// Find custom extension
	found := false
	for _, ext := range exts {
		if ext.Id.Equal(customOID) {
			found = true
			break
		}
	}

	if !found {
		t.Error("ExtraExtensions not transferred to output")
	}
}

// =============================================================================
// encodeKeyUsage Unit Tests
// =============================================================================

func TestU_EncodeKeyUsage(t *testing.T) {
	tests := []struct {
		name string
		ku   x509.KeyUsage
	}{
		{"[Unit] EncodeKU: Digital Signature", x509.KeyUsageDigitalSignature},
		{"[Unit] EncodeKU: Key Encipherment", x509.KeyUsageKeyEncipherment},
		{"[Unit] EncodeKU: Cert Sign", x509.KeyUsageCertSign},
		{"[Unit] EncodeKU: CRL Sign", x509.KeyUsageCRLSign},
		{"[Unit] EncodeKU: Multiple", x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment},
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
// encodeExtKeyUsage Unit Tests
// =============================================================================

func TestU_EncodeExtKeyUsage(t *testing.T) {
	tests := []struct {
		name string
		ekus []x509.ExtKeyUsage
	}{
		{"[Unit] EncodeEKU: Server Auth", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}},
		{"[Unit] EncodeEKU: Client Auth", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}},
		{"[Unit] EncodeEKU: Code Signing", []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}},
		{"[Unit] EncodeEKU: Multiple", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}},
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
// encodeSAN Unit Tests
// =============================================================================

func TestU_EncodeSAN(t *testing.T) {
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
// getPublicKeyBytes Unit Tests
// =============================================================================

func TestU_GetPublicKeyBytes(t *testing.T) {
	t.Run("[Unit] GetPubKeyBytes: ECDSA", func(t *testing.T) {
		privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		bytes, err := getPublicKeyBytes(&privKey.PublicKey)
		if err != nil {
			t.Fatalf("getPublicKeyBytes(ECDSA) error = %v", err)
		}
		if len(bytes) == 0 {
			t.Error("getPublicKeyBytes(ECDSA) returned empty bytes")
		}
	})

	t.Run("[Unit] GetPubKeyBytes: ML-DSA", func(t *testing.T) {
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
// encodeSubjectPublicKeyInfo Unit Tests
// =============================================================================

func TestU_EncodeSubjectPublicKeyInfo(t *testing.T) {
	t.Run("[Unit] EncodeSPKI: ECDSA", func(t *testing.T) {
		privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		spki, err := encodeSubjectPublicKeyInfo(&privKey.PublicKey)
		if err != nil {
			t.Fatalf("encodeSubjectPublicKeyInfo(ECDSA) error = %v", err)
		}
		if len(spki.PublicKey.Bytes) == 0 {
			t.Error("encodeSubjectPublicKeyInfo(ECDSA) returned empty public key")
		}
	})

	t.Run("[Unit] EncodeSPKI: ML-DSA-65", func(t *testing.T) {
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

	t.Run("[Unit] EncodeSPKI: ML-DSA-87", func(t *testing.T) {
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

	t.Run("[Unit] EncodeSPKI: ML-DSA-44", func(t *testing.T) {
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
// buildEndEntityExtensions Unit Tests
// =============================================================================

func TestU_BuildEndEntityExtensions(t *testing.T) {
	template := &x509.Certificate{
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"example.com"},
	}

	skid := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
	akid := []byte{20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}

	exts, err := buildEndEntityExtensions(template, skid, akid, false)
	if err != nil {
		t.Fatalf("buildEndEntityExtensions() error = %v", err)
	}

	// Should have: KeyUsage, ExtKeyUsage, SubjectKeyId, AuthorityKeyId, SAN
	if len(exts) < 4 {
		t.Errorf("buildEndEntityExtensions() returned %d extensions, want at least 4", len(exts))
	}
}

func TestU_BuildEndEntityExtensions_CATemplate(t *testing.T) {
	template := &x509.Certificate{
		IsCA:       true,
		MaxPathLen: 0,
		KeyUsage:   x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	skid := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}

	exts, err := buildEndEntityExtensions(template, skid, nil, false)
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

// =============================================================================
// VerifyPQCCertificate Unit Tests
// =============================================================================

// Note: VerifyPQCCertificate uses pkicrypto.ParsePublicKey which only supports
// PQC algorithms (ML-DSA, SLH-DSA, ML-KEM). Classical algorithms like ECDSA
// will fail at the key parsing stage even though oidToAlgorithm maps them.

func TestU_VerifyPQCCertificate_ECDSANotSupported(t *testing.T) {
	// Create a self-signed ECDSA certificate
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}

	// VerifyPQCCertificate with ECDSA - pkicrypto.ParsePublicKey doesn't support
	// ECDSA keys, so verification will return false or error
	valid, err := VerifyPQCCertificate(cert, cert)
	// Either returns an error OR returns valid=false is acceptable
	if err == nil && valid {
		t.Error("VerifyPQCCertificate() should fail or return false for ECDSA")
	}
}

// =============================================================================
// VerifyPQCCertificateRaw Unit Tests
// =============================================================================

func TestU_VerifyPQCCertificateRaw_MLDSA65(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create an ML-DSA-65 CA
	caCfg := PQCCAConfig{
		CommonName:    "Test ML-DSA-65 CA",
		Organization:  "Test Org",
		Algorithm:     pkicrypto.AlgMLDSA65,
		ValidityYears: 1,
		PathLen:       0,
	}

	ca, err := InitializePQCCA(store, caCfg)
	if err != nil {
		t.Fatalf("InitializePQCCA() error = %v", err)
	}

	caCert := ca.Certificate()

	// The CA certificate should verify against itself (self-signed)
	valid, err := VerifyPQCCertificateRaw(caCert.Raw, caCert)
	if err != nil {
		t.Fatalf("VerifyPQCCertificateRaw() error = %v", err)
	}
	if !valid {
		t.Error("VerifyPQCCertificateRaw() = false, want true for valid self-signed ML-DSA cert")
	}
}

func TestU_VerifyPQCCertificateRaw_InvalidDER(t *testing.T) {
	// Create a simple ECDSA CA just for the issuer parameter
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	cert, _ := x509.ParseCertificate(certDER)

	// Try to verify invalid DER data
	_, err := VerifyPQCCertificateRaw([]byte("invalid DER"), cert)
	if err == nil {
		t.Error("VerifyPQCCertificateRaw() should fail for invalid DER")
	}
}

func TestU_VerifyPQCCertificateRaw_UnsupportedAlgorithm(t *testing.T) {
	// Create an ECDSA certificate (not PQC)
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test Cert"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	cert, _ := x509.ParseCertificate(certDER)

	// ECDSA signature algorithm is not supported by VerifyPQCCertificateRaw
	_, err := VerifyPQCCertificateRaw(certDER, cert)
	if err == nil {
		t.Error("VerifyPQCCertificateRaw() should fail for ECDSA (non-PQC) algorithm")
	}
}

// =============================================================================
// oidToAlgorithm Unit Tests
// =============================================================================

func TestU_oidToAlgorithm_Valid(t *testing.T) {
	tests := []struct {
		name     string
		sigAlg   x509.SignatureAlgorithm
		expected pkicrypto.AlgorithmID
	}{
		{"ECDSA P256", x509.ECDSAWithSHA256, pkicrypto.AlgECDSAP256},
		{"ECDSA P384", x509.ECDSAWithSHA384, pkicrypto.AlgECDSAP384},
		{"ECDSA P521", x509.ECDSAWithSHA512, pkicrypto.AlgECDSAP521},
		{"Ed25519", x509.PureEd25519, pkicrypto.AlgEd25519},
		{"RSA", x509.SHA256WithRSA, pkicrypto.AlgRSA2048},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := oidToAlgorithm(tt.sigAlg)
			if err != nil {
				t.Fatalf("oidToAlgorithm() error = %v", err)
			}
			if result != tt.expected {
				t.Errorf("oidToAlgorithm() = %s, want %s", result, tt.expected)
			}
		})
	}
}

func TestU_oidToAlgorithm_Unknown(t *testing.T) {
	// Unknown signature algorithm should return error
	_, err := oidToAlgorithm(x509.UnknownSignatureAlgorithm)
	if err == nil {
		t.Error("oidToAlgorithm() should fail for UnknownSignatureAlgorithm")
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
		Algorithm:     pkicrypto.AlgMLDSA65,
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

	cert, err := ca.Issue(context.Background(), IssueRequest{
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
		Algorithm:     pkicrypto.AlgMLDSA87,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := InitializePQCCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializePQCCA() error = %v", err)
	}

	// Generate PQC key for subject
	subjectKP, err := pkicrypto.GenerateKeyPair(pkicrypto.AlgMLDSA65)
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	// Issue certificate
	template := &x509.Certificate{
		Subject:  pkix.Name{CommonName: "pqc-service.example.com"},
		KeyUsage: x509.KeyUsageDigitalSignature,
	}

	cert, err := ca.Issue(context.Background(), IssueRequest{
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
		Algorithm:     pkicrypto.AlgMLDSA87,
		ValidityYears: 20,
		PathLen:       1,
	}

	rootCA, err := InitializePQCCA(rootStore, rootCfg)
	if err != nil {
		t.Fatalf("InitializePQCCA() error = %v", err)
	}

	// Generate key for subordinate CA
	subKP, err := pkicrypto.GenerateKeyPair(pkicrypto.AlgMLDSA65)
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

	subCACert, err := rootCA.Issue(context.Background(), IssueRequest{
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
