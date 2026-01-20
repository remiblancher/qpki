package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"testing"
	"time"

	"github.com/remiblancher/post-quantum-pki/internal/crypto"
	"github.com/remiblancher/post-quantum-pki/internal/x509util"
)

// =============================================================================
// Catalyst CRL Functional Tests
// =============================================================================

func TestF_CA_GenerateCatalystCRL(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize Hybrid CA (ECDSA + ML-DSA)
	cfg := HybridCAConfig{
		CommonName:         "Catalyst CRL Test CA",
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

	// Generate CRL without any revoked certificates
	nextUpdate := time.Now().AddDate(0, 0, 7)
	crlDER, err := ca.GenerateCatalystCRL(nextUpdate)
	if err != nil {
		t.Fatalf("GenerateCatalystCRL() error = %v", err)
	}

	if len(crlDER) == 0 {
		t.Error("Catalyst CRL should not be empty")
	}

	// Verify both signatures on the CRL
	valid, err := VerifyCatalystCRL(crlDER, ca.Certificate())
	if err != nil {
		t.Fatalf("VerifyCatalystCRL() error = %v", err)
	}
	if !valid {
		t.Error("Catalyst CRL signatures should be valid")
	}
}

func TestF_CA_GenerateCatalystCRL_WithRevokedCerts(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize Hybrid CA
	cfg := HybridCAConfig{
		CommonName:         "Catalyst CRL Test CA",
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

	// Issue and revoke a certificate
	subjectKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	cert, err := issueTLSServerCert(ca, "server.example.com", []string{"server.example.com"}, &subjectKey.PublicKey)
	if err != nil {
		t.Fatalf("issueTLSServerCert() error = %v", err)
	}

	// Revoke the certificate
	if err := ca.Revoke(cert.SerialNumber.Bytes(), ReasonKeyCompromise); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}

	// Generate CRL with revoked certificate
	nextUpdate := time.Now().AddDate(0, 0, 7)
	crlDER, err := ca.GenerateCatalystCRL(nextUpdate)
	if err != nil {
		t.Fatalf("GenerateCatalystCRL() error = %v", err)
	}

	// Verify CRL
	valid, err := VerifyCatalystCRL(crlDER, ca.Certificate())
	if err != nil {
		t.Fatalf("VerifyCatalystCRL() error = %v", err)
	}
	if !valid {
		t.Error("Catalyst CRL signatures should be valid")
	}
}

func TestF_CA_GenerateCatalystCRL_NoSigner(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize Hybrid CA with passphrase
	cfg := HybridCAConfig{
		CommonName:         "Catalyst CRL Test CA",
		Organization:       "Test Org",
		Country:            "US",
		ClassicalAlgorithm: crypto.AlgECDSAP384,
		PQCAlgorithm:       crypto.AlgMLDSA87,
		ValidityYears:      10,
		PathLen:            1,
		Passphrase:         "testpass",
	}

	_, err := InitializeHybridCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeHybridCA() error = %v", err)
	}

	// Load CA without signer
	ca, err := New(store)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Try to generate CRL without signer loaded
	_, err = ca.GenerateCatalystCRL(time.Now().AddDate(0, 0, 7))
	if err == nil {
		t.Error("GenerateCatalystCRL() should fail when signer not loaded")
	}
}

func TestF_CA_GenerateCatalystCRL_NonHybridCA(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize non-hybrid CA
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

	// Try to generate Catalyst CRL with non-hybrid CA
	_, err = ca.GenerateCatalystCRL(time.Now().AddDate(0, 0, 7))
	if err == nil {
		t.Error("GenerateCatalystCRL() should fail with non-hybrid CA")
	}
}

// =============================================================================
// Helper Function Unit Tests
// =============================================================================

func TestU_isAltSignatureValueExtension(t *testing.T) {
	tests := []struct {
		name     string
		extBytes []byte
		want     bool
	}{
		{
			name:     "AltSignatureValue extension",
			extBytes: mustMarshalExtension(t, x509util.OIDAltSignatureValue, false, []byte{0x01, 0x02, 0x03}),
			want:     true,
		},
		{
			name:     "AltSignatureAlgorithm extension",
			extBytes: mustMarshalExtension(t, x509util.OIDAltSignatureAlgorithm, false, []byte{0x01, 0x02, 0x03}),
			want:     false,
		},
		{
			name:     "BasicConstraints extension",
			extBytes: mustMarshalExtension(t, asn1.ObjectIdentifier{2, 5, 29, 19}, false, []byte{0x01}),
			want:     false,
		},
		{
			name:     "invalid ASN.1",
			extBytes: []byte{0xff, 0xff, 0xff},
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isAltSignatureValueExtension(tt.extBytes); got != tt.want {
				t.Errorf("isAltSignatureValueExtension() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestU_buildPreTBSCertList(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize a regular CA to get a CRL
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

	// Generate a standard CRL
	nextUpdate := time.Now().AddDate(0, 0, 7)
	crlDER, err := ca.GenerateCRL(nextUpdate)
	if err != nil {
		t.Fatalf("GenerateCRL() error = %v", err)
	}

	// Test buildPreTBSCertList
	preTBS, err := buildPreTBSCertList(crlDER)
	if err != nil {
		t.Fatalf("buildPreTBSCertList() error = %v", err)
	}

	if len(preTBS) == 0 {
		t.Error("PreTBS should not be empty")
	}

	// The PreTBS should be smaller than the original CRL
	// (since signature algorithm is removed)
	if len(preTBS) >= len(crlDER) {
		t.Error("PreTBS should be smaller than original CRL")
	}
}

func TestU_buildPreTBSCertList_InvalidDER(t *testing.T) {
	_, err := buildPreTBSCertList([]byte{0xff, 0xff, 0xff})
	if err == nil {
		t.Error("buildPreTBSCertList() should fail with invalid DER")
	}
}

func TestU_filterAltSignatureValueFromExtensions(t *testing.T) {
	// Create a sequence of extensions including AltSignatureValue
	altSigValueOID := x509util.OIDAltSignatureValue
	basicConstraintsOID := asn1.ObjectIdentifier{2, 5, 29, 19}

	ext1 := mustMarshalExtension(t, basicConstraintsOID, true, []byte{0x30, 0x00})
	ext2 := mustMarshalExtension(t, altSigValueOID, false, []byte{0x03, 0x03, 0x00, 0x01, 0x02})

	// Build extension sequence
	extSeqBytes := append(ext1, ext2...)
	extSeq, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      extSeqBytes,
	})
	if err != nil {
		t.Fatalf("Failed to marshal extension sequence: %v", err)
	}

	// Filter out AltSignatureValue
	filtered, err := filterAltSignatureValueFromExtensions(extSeq)
	if err != nil {
		t.Fatalf("filterAltSignatureValueFromExtensions() error = %v", err)
	}

	// Parse filtered extensions to verify AltSignatureValue is removed
	var filteredSeq asn1.RawValue
	_, err = asn1.Unmarshal(filtered, &filteredSeq)
	if err != nil {
		t.Fatalf("Failed to unmarshal filtered extensions: %v", err)
	}

	// Count extensions
	remaining := filteredSeq.Bytes
	count := 0
	for len(remaining) > 0 {
		var ext asn1.RawValue
		rest, err := asn1.Unmarshal(remaining, &ext)
		if err != nil {
			break
		}
		count++
		remaining = rest
	}

	if count != 1 {
		t.Errorf("Expected 1 extension after filtering, got %d", count)
	}
}

func TestF_VerifyCatalystCRL_InvalidCRL(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize Hybrid CA
	cfg := HybridCAConfig{
		CommonName:         "Catalyst CRL Test CA",
		ClassicalAlgorithm: crypto.AlgECDSAP384,
		PQCAlgorithm:       crypto.AlgMLDSA87,
		ValidityYears:      10,
		PathLen:            1,
	}

	ca, err := InitializeHybridCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeHybridCA() error = %v", err)
	}

	// Try to verify invalid CRL data
	_, err = VerifyCatalystCRL([]byte{0xff, 0xff, 0xff}, ca.Certificate())
	if err == nil {
		t.Error("VerifyCatalystCRL() should fail with invalid CRL data")
	}
}

func TestF_VerifyCatalystCRL_NonCatalystCRL(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize regular CA
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

	// Generate a standard CRL (without Catalyst extensions)
	crlDER, err := ca.GenerateCRL(time.Now().AddDate(0, 0, 7))
	if err != nil {
		t.Fatalf("GenerateCRL() error = %v", err)
	}

	// Try to verify as Catalyst CRL - should fail because no Catalyst extensions
	_, err = VerifyCatalystCRL(crlDER, ca.Certificate())
	if err == nil {
		t.Error("VerifyCatalystCRL() should fail with non-Catalyst CRL")
	}
}

func TestF_VerifyCatalystCRL_InvalidClassicalSignature(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize Hybrid CA
	cfg := HybridCAConfig{
		CommonName:         "Catalyst CRL Test CA",
		ClassicalAlgorithm: crypto.AlgECDSAP384,
		PQCAlgorithm:       crypto.AlgMLDSA87,
		ValidityYears:      10,
		PathLen:            1,
	}

	ca, err := InitializeHybridCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeHybridCA() error = %v", err)
	}

	// Generate a Catalyst CRL
	crlDER, err := ca.GenerateCatalystCRL(time.Now().AddDate(0, 0, 7))
	if err != nil {
		t.Fatalf("GenerateCatalystCRL() error = %v", err)
	}

	// Create a different CA to use as "wrong" issuer
	tmpDir2 := t.TempDir()
	store2 := NewFileStore(tmpDir2)
	cfg2 := HybridCAConfig{
		CommonName:         "Different CA",
		ClassicalAlgorithm: crypto.AlgECDSAP384,
		PQCAlgorithm:       crypto.AlgMLDSA87,
		ValidityYears:      10,
		PathLen:            1,
	}

	ca2, err := InitializeHybridCA(store2, cfg2)
	if err != nil {
		t.Fatalf("InitializeHybridCA() error = %v", err)
	}

	// Try to verify CRL with wrong issuer certificate - classical signature should fail
	valid, err := VerifyCatalystCRL(crlDER, ca2.Certificate())
	if err != nil {
		t.Fatalf("VerifyCatalystCRL() unexpected error = %v", err)
	}
	if valid {
		t.Error("VerifyCatalystCRL() should return false for wrong issuer (invalid classical signature)")
	}
}

func TestU_buildPreTBSCertList_WithVersion(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize Hybrid CA (creates v2 CRL with version field)
	cfg := HybridCAConfig{
		CommonName:         "Catalyst CRL Test CA",
		ClassicalAlgorithm: crypto.AlgECDSAP384,
		PQCAlgorithm:       crypto.AlgMLDSA87,
		ValidityYears:      10,
		PathLen:            1,
	}

	ca, err := InitializeHybridCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeHybridCA() error = %v", err)
	}

	// Issue and revoke a certificate to get a v2 CRL with revokedCerts
	subjectKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	cert, _ := issueTLSServerCert(ca, "server.example.com", []string{"server.example.com"}, &subjectKey.PublicKey)
	_ = ca.Revoke(cert.SerialNumber.Bytes(), ReasonKeyCompromise)

	// Generate a Catalyst CRL
	crlDER, err := ca.GenerateCatalystCRL(time.Now().AddDate(0, 0, 7))
	if err != nil {
		t.Fatalf("GenerateCatalystCRL() error = %v", err)
	}

	// Test buildPreTBSCertList with a real Catalyst CRL
	preTBS, err := buildPreTBSCertList(crlDER)
	if err != nil {
		t.Fatalf("buildPreTBSCertList() error = %v", err)
	}

	if len(preTBS) == 0 {
		t.Error("PreTBS should not be empty")
	}
}

func TestU_filterAltSignatureValueFromExtensions_InvalidASN1(t *testing.T) {
	// Test with invalid ASN.1 data
	_, err := filterAltSignatureValueFromExtensions([]byte{0xff, 0xff, 0xff})
	if err == nil {
		t.Error("filterAltSignatureValueFromExtensions() should fail with invalid ASN.1")
	}
}

func TestU_filterAltSignatureValueFromExtensions_NoExtensions(t *testing.T) {
	// Create an empty extension sequence
	emptySeq, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      []byte{},
	})
	if err != nil {
		t.Fatalf("Failed to marshal empty sequence: %v", err)
	}

	// Filter empty extensions
	filtered, err := filterAltSignatureValueFromExtensions(emptySeq)
	if err != nil {
		t.Fatalf("filterAltSignatureValueFromExtensions() error = %v", err)
	}

	// Should return a valid (empty) sequence
	if len(filtered) == 0 {
		t.Error("Should return a valid (empty) sequence")
	}
}

func TestF_VerifyCatalystCRL_WithNonCatalystIssuer(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize Hybrid CA
	cfg := HybridCAConfig{
		CommonName:         "Catalyst CRL Test CA",
		ClassicalAlgorithm: crypto.AlgECDSAP384,
		PQCAlgorithm:       crypto.AlgMLDSA87,
		ValidityYears:      10,
		PathLen:            1,
	}

	ca, err := InitializeHybridCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializeHybridCA() error = %v", err)
	}

	// Generate a Catalyst CRL
	crlDER, err := ca.GenerateCatalystCRL(time.Now().AddDate(0, 0, 7))
	if err != nil {
		t.Fatalf("GenerateCatalystCRL() error = %v", err)
	}

	// Create a non-Catalyst CA certificate
	tmpDir2 := t.TempDir()
	store2 := NewFileStore(tmpDir2)
	cfgRegular := Config{
		CommonName:    "Non-Catalyst CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	regularCA, err := Initialize(store2, cfgRegular)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Try to verify Catalyst CRL with non-Catalyst issuer certificate
	// First, the classical signature fails (returns false, nil)
	// Then if it passed, it would fail because issuer has no Catalyst extensions (returns error)
	valid, err := VerifyCatalystCRL(crlDER, regularCA.Certificate())
	// Classical signature should fail first (wrong issuer key), returning false with no error
	if err != nil {
		t.Fatalf("VerifyCatalystCRL() unexpected error = %v", err)
	}
	if valid {
		t.Error("VerifyCatalystCRL() should return false for wrong issuer certificate")
	}
}

// =============================================================================
// Helper functions for tests
// =============================================================================

// mustMarshalExtension creates a DER-encoded extension.
func mustMarshalExtension(t *testing.T, oid asn1.ObjectIdentifier, critical bool, value []byte) []byte {
	t.Helper()

	ext := struct {
		ExtnID    asn1.ObjectIdentifier
		Critical  bool `asn1:"optional,default:false"`
		ExtnValue []byte
	}{
		ExtnID:    oid,
		Critical:  critical,
		ExtnValue: value,
	}

	der, err := asn1.Marshal(ext)
	if err != nil {
		t.Fatalf("Failed to marshal extension: %v", err)
	}
	return der
}
