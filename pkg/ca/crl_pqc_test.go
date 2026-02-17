package ca

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
	"time"

	"github.com/remiblancher/post-quantum-pki/pkg/crypto"
	"github.com/remiblancher/post-quantum-pki/pkg/x509util"
)

func TestU_CA_GeneratePQCCRL_MLDSA65(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize PQC CA
	cfg := PQCCAConfig{
		CommonName:    "Test PQC Root CA",
		Organization:  "Test Org",
		Country:       "US",
		Algorithm:     crypto.AlgMLDSA65,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := InitializePQCCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializePQCCA() error = %v", err)
	}

	if err := ca.LoadSigner(""); err != nil {
		t.Fatalf("LoadSigner() error = %v", err)
	}

	// Issue a certificate
	subjectKP, err := crypto.GenerateKeyPair(crypto.AlgMLDSA65)
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	template := &x509.Certificate{
		Subject: pkix.Name{CommonName: "test.example.com"},
	}

	cert, err := ca.Issue(context.Background(), IssueRequest{
		Template:  template,
		PublicKey: subjectKP.PublicKey,
		Validity:  365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	// Revoke the certificate
	if err := ca.Revoke(cert.SerialNumber.Bytes(), ReasonKeyCompromise); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}

	// Generate CRL (should delegate to GeneratePQCCRL)
	nextUpdate := time.Now().AddDate(0, 0, 7)
	crlDER, err := ca.GenerateCRL(nextUpdate)
	if err != nil {
		t.Fatalf("GenerateCRL() error = %v", err)
	}

	if len(crlDER) == 0 {
		t.Fatal("Generated CRL is empty")
	}

	// Verify the CRL signature
	valid, err := VerifyPQCCRL(crlDER, ca.cert)
	if err != nil {
		t.Fatalf("VerifyPQCCRL() error = %v", err)
	}
	if !valid {
		t.Error("CRL signature verification failed")
	}

	// Verify the signature algorithm OID is correct
	sigAlgOID, err := ExtractCRLSignatureAlgorithmOID(crlDER)
	if err != nil {
		t.Fatalf("ExtractCRLSignatureAlgorithmOID() error = %v", err)
	}
	if !sigAlgOID.Equal(x509util.OIDMLDSA65) {
		t.Errorf("Signature algorithm OID = %v, want %v", sigAlgOID, x509util.OIDMLDSA65)
	}

	// Parse the CRL to verify structure
	var crl certificateList
	_, err = asn1.Unmarshal(crlDER, &crl)
	if err != nil {
		t.Fatalf("Failed to parse CRL: %v", err)
	}

	// Check that the revoked certificate is in the CRL
	found := false
	for _, entry := range crl.TBSCertList.RevokedCertificates {
		if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			found = true
			break
		}
	}
	if !found {
		t.Error("Revoked certificate not found in CRL")
	}

	// Check extensions
	if len(crl.TBSCertList.Extensions) == 0 {
		t.Error("CRL should have extensions")
	}

	t.Logf("CRL generated successfully with %d revoked certificates", len(crl.TBSCertList.RevokedCertificates))
	t.Logf("CRL size: %d bytes", len(crlDER))
}

func TestU_CA_GeneratePQCCRL_MLDSA44(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := PQCCAConfig{
		CommonName:    "Test PQC CA ML-DSA-44",
		Algorithm:     crypto.AlgMLDSA44,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := InitializePQCCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializePQCCA() error = %v", err)
	}

	if err := ca.LoadSigner(""); err != nil {
		t.Fatalf("LoadSigner() error = %v", err)
	}

	// Generate CRL with no revoked certs
	nextUpdate := time.Now().AddDate(0, 0, 7)
	crlDER, err := ca.GenerateCRL(nextUpdate)
	if err != nil {
		t.Fatalf("GenerateCRL() error = %v", err)
	}

	// Verify
	valid, err := VerifyPQCCRL(crlDER, ca.cert)
	if err != nil {
		t.Fatalf("VerifyPQCCRL() error = %v", err)
	}
	if !valid {
		t.Error("CRL signature verification failed")
	}

	// Check OID
	sigAlgOID, _ := ExtractCRLSignatureAlgorithmOID(crlDER)
	if !sigAlgOID.Equal(x509util.OIDMLDSA44) {
		t.Errorf("Signature algorithm OID = %v, want %v", sigAlgOID, x509util.OIDMLDSA44)
	}
}

func TestU_CA_GeneratePQCCRL_MLDSA87(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := PQCCAConfig{
		CommonName:    "Test PQC CA ML-DSA-87",
		Algorithm:     crypto.AlgMLDSA87,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := InitializePQCCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializePQCCA() error = %v", err)
	}

	if err := ca.LoadSigner(""); err != nil {
		t.Fatalf("LoadSigner() error = %v", err)
	}

	nextUpdate := time.Now().AddDate(0, 0, 7)
	crlDER, err := ca.GenerateCRL(nextUpdate)
	if err != nil {
		t.Fatalf("GenerateCRL() error = %v", err)
	}

	valid, err := VerifyPQCCRL(crlDER, ca.cert)
	if err != nil {
		t.Fatalf("VerifyPQCCRL() error = %v", err)
	}
	if !valid {
		t.Error("CRL signature verification failed")
	}

	sigAlgOID, _ := ExtractCRLSignatureAlgorithmOID(crlDER)
	if !sigAlgOID.Equal(x509util.OIDMLDSA87) {
		t.Errorf("Signature algorithm OID = %v, want %v", sigAlgOID, x509util.OIDMLDSA87)
	}
}

func TestU_CA_VerifyPQCCRL_WrongIssuer(t *testing.T) {
	// Create two different CAs
	store1 := NewFileStore(t.TempDir())
	store2 := NewFileStore(t.TempDir())

	cfg := PQCCAConfig{
		CommonName:    "CA 1",
		Algorithm:     crypto.AlgMLDSA65,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca1, err := InitializePQCCA(store1, cfg)
	if err != nil {
		t.Fatalf("InitializePQCCA(CA1) error = %v", err)
	}
	if err := ca1.LoadSigner(""); err != nil {
		t.Fatalf("LoadSigner(CA1) error = %v", err)
	}

	cfg.CommonName = "CA 2"
	ca2, err := InitializePQCCA(store2, cfg)
	if err != nil {
		t.Fatalf("InitializePQCCA(CA2) error = %v", err)
	}
	if err := ca2.LoadSigner(""); err != nil {
		t.Fatalf("LoadSigner(CA2) error = %v", err)
	}

	// Generate CRL from CA1
	crlDER, err := ca1.GenerateCRL(time.Now().AddDate(0, 0, 7))
	if err != nil {
		t.Fatalf("GenerateCRL() error = %v", err)
	}

	// Try to verify with CA2's certificate - should fail
	valid, err := VerifyPQCCRL(crlDER, ca2.cert)
	if err != nil {
		// Error is acceptable - means verification properly rejected
		t.Logf("VerifyPQCCRL with wrong issuer returned error: %v", err)
		return
	}
	if valid {
		t.Error("CRL verification should fail with wrong issuer")
	}
}

func TestU_CA_VerifyPQCCRL_TamperedCRL(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := PQCCAConfig{
		CommonName:    "Test CA",
		Algorithm:     crypto.AlgMLDSA65,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := InitializePQCCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializePQCCA() error = %v", err)
	}
	if err := ca.LoadSigner(""); err != nil {
		t.Fatalf("LoadSigner() error = %v", err)
	}

	crlDER, err := ca.GenerateCRL(time.Now().AddDate(0, 0, 7))
	if err != nil {
		t.Fatalf("GenerateCRL() error = %v", err)
	}

	// Tamper with the CRL
	if len(crlDER) > 100 {
		crlDER[50] ^= 0xFF
	}

	// Verification should fail
	valid, _ := VerifyPQCCRL(crlDER, ca.cert)
	if valid {
		t.Error("CRL verification should fail for tampered CRL")
	}
}

func TestU_CA_GenerateCRL_FallbackToStandard(t *testing.T) {
	// Test that classical algorithms still use the standard Go implementation
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Classical CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	if err := ca.LoadSigner(""); err != nil {
		t.Fatalf("LoadSigner() error = %v", err)
	}

	// Generate CRL - should use standard Go
	crlDER, err := ca.GenerateCRL(time.Now().AddDate(0, 0, 7))
	if err != nil {
		t.Fatalf("GenerateCRL() error = %v", err)
	}

	// Should be parseable by Go's standard library
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatalf("ParseRevocationList() error = %v", err)
	}

	// Verify with standard Go
	if err := crl.CheckSignatureFrom(ca.cert); err != nil {
		t.Errorf("CheckSignatureFrom() error = %v", err)
	}

	// IsPQCSignatureOID should return false for ECDSA
	sigAlgOID, _ := ExtractCRLSignatureAlgorithmOID(crlDER)
	if IsPQCSignatureOID(sigAlgOID) {
		t.Error("ECDSA CRL should not be detected as PQC")
	}
}

func TestU_CA_IsPQCSignatureOID(t *testing.T) {
	tests := []struct {
		name     string
		oid      asn1.ObjectIdentifier
		expected bool
	}{
		{"ML-DSA-44", x509util.OIDMLDSA44, true},
		{"ML-DSA-65", x509util.OIDMLDSA65, true},
		{"ML-DSA-87", x509util.OIDMLDSA87, true},
		{"SLH-DSA-128s", x509util.OIDSLHDSA128s, true},
		{"SLH-DSA-128f", x509util.OIDSLHDSA128f, true},
		{"ECDSA-SHA256", asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}, false},
		{"RSA-SHA256", asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsPQCSignatureOID(tt.oid)
			if result != tt.expected {
				t.Errorf("IsPQCSignatureOID(%v) = %v, want %v", tt.oid, result, tt.expected)
			}
		})
	}
}

func TestU_CA_OidToAlgorithmID(t *testing.T) {
	tests := []struct {
		name        string
		oid         asn1.ObjectIdentifier
		expectedAlg crypto.AlgorithmID
		expectError bool
	}{
		{"ML-DSA-44", x509util.OIDMLDSA44, crypto.AlgMLDSA44, false},
		{"ML-DSA-65", x509util.OIDMLDSA65, crypto.AlgMLDSA65, false},
		{"ML-DSA-87", x509util.OIDMLDSA87, crypto.AlgMLDSA87, false},
		{"SLH-DSA-128s", x509util.OIDSLHDSA128s, crypto.AlgSLHDSA128s, false},
		{"SLH-DSA-128f", x509util.OIDSLHDSA128f, crypto.AlgSLHDSA128f, false},
		{"SLH-DSA-192s", x509util.OIDSLHDSA192s, crypto.AlgSLHDSA192s, false},
		{"SLH-DSA-192f", x509util.OIDSLHDSA192f, crypto.AlgSLHDSA192f, false},
		{"SLH-DSA-256s", x509util.OIDSLHDSA256s, crypto.AlgSLHDSA256s, false},
		{"SLH-DSA-256f", x509util.OIDSLHDSA256f, crypto.AlgSLHDSA256f, false},
		{"Unknown OID", asn1.ObjectIdentifier{1, 2, 3, 4, 5}, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alg, err := oidToAlgorithmID(tt.oid)
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if alg != tt.expectedAlg {
					t.Errorf("oidToAlgorithmID(%v) = %v, want %v", tt.oid, alg, tt.expectedAlg)
				}
			}
		})
	}
}

func TestU_CA_GeneratePQCCRL_NonPQCSigner(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Initialize a classical CA
	cfg := Config{
		CommonName:    "Classical CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Try to call GeneratePQCCRL directly - should fail
	_, err = ca.GeneratePQCCRL(time.Now().AddDate(0, 0, 7))
	if err == nil {
		t.Error("GeneratePQCCRL() should fail with non-PQC signer")
	}
}

func TestU_CA_GeneratePQCCRL_NoSigner(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := PQCCAConfig{
		CommonName:    "Test PQC CA",
		Algorithm:     crypto.AlgMLDSA65,
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

	// Try to generate PQC CRL without signer
	_, err = ca.GeneratePQCCRL(time.Now().AddDate(0, 0, 7))
	if err == nil {
		t.Error("GeneratePQCCRL() should fail when signer not loaded")
	}
}

func TestU_CA_GeneratePQCCRLWithEntries_NonPQCSigner(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := Config{
		CommonName:    "Classical CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := Initialize(store, cfg)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Try to call GeneratePQCCRLWithEntries directly - should fail
	_, err = ca.GeneratePQCCRLWithEntries(nil, []byte{0x01}, time.Now().AddDate(0, 0, 7))
	if err == nil {
		t.Error("GeneratePQCCRLWithEntries() should fail with non-PQC signer")
	}
}

func TestU_CA_GeneratePQCCRLWithEntries_NoSigner(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := PQCCAConfig{
		CommonName:    "Test PQC CA",
		Algorithm:     crypto.AlgMLDSA65,
		ValidityYears: 10,
		PathLen:       1,
		Passphrase:    "test",
	}

	_, err := InitializePQCCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializePQCCA() error = %v", err)
	}

	ca, err := New(store)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_, err = ca.GeneratePQCCRLWithEntries(nil, []byte{0x01}, time.Now().AddDate(0, 0, 7))
	if err == nil {
		t.Error("GeneratePQCCRLWithEntries() should fail when signer not loaded")
	}
}

func TestU_CA_VerifyPQCCRL_InvalidDER(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cfg := PQCCAConfig{
		CommonName:    "Test CA",
		Algorithm:     crypto.AlgMLDSA65,
		ValidityYears: 10,
		PathLen:       1,
	}

	ca, err := InitializePQCCA(store, cfg)
	if err != nil {
		t.Fatalf("InitializePQCCA() error = %v", err)
	}

	// Try to verify invalid DER
	_, err = VerifyPQCCRL([]byte{0xff, 0xff, 0xff}, ca.cert)
	if err == nil {
		t.Error("VerifyPQCCRL() should fail with invalid DER")
	}
}

func TestU_CA_ExtractCRLSignatureAlgorithmOID_InvalidDER(t *testing.T) {
	_, err := ExtractCRLSignatureAlgorithmOID([]byte{0xff, 0xff, 0xff})
	if err == nil {
		t.Error("ExtractCRLSignatureAlgorithmOID() should fail with invalid DER")
	}
}

func TestU_CA_BuildCRLExtensions_NoAuthorityKeyId(t *testing.T) {
	// Test buildCRLExtensions with empty authority key ID
	exts, err := buildCRLExtensions([]byte{0x01}, nil)
	if err != nil {
		t.Fatalf("buildCRLExtensions() error = %v", err)
	}

	// Should only have CRL Number extension
	if len(exts) != 1 {
		t.Errorf("Expected 1 extension (CRL Number only), got %d", len(exts))
	}
}

func TestU_CA_BuildCRLExtensions_WithAuthorityKeyId(t *testing.T) {
	// Test buildCRLExtensions with authority key ID
	akid := []byte{0x01, 0x02, 0x03, 0x04}
	exts, err := buildCRLExtensions([]byte{0x01}, akid)
	if err != nil {
		t.Fatalf("buildCRLExtensions() error = %v", err)
	}

	// Should have both CRL Number and Authority Key Identifier
	if len(exts) != 2 {
		t.Errorf("Expected 2 extensions, got %d", len(exts))
	}
}
