package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"testing"
	"time"

	"github.com/remiblancher/post-quantum-pki/internal/crypto"
	"github.com/remiblancher/post-quantum-pki/internal/profile"
)

// tlsServerExtensions returns common TLS server extensions for testing
func tlsServerExtensions() *profile.ExtensionsConfig {
	criticalTrue := true
	criticalFalse := false
	return &profile.ExtensionsConfig{
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
}

// issueTLSServerCert is a helper for tests to issue TLS server certificates
func issueTLSServerCert(ca *CA, cn string, dnsNames []string, pubKey interface{}) (*x509.Certificate, error) {
	template := &x509.Certificate{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: dnsNames,
	}
	return ca.Issue(IssueRequest{
		Template:   template,
		PublicKey:  pubKey,
		Extensions: tlsServerExtensions(),
		Validity:   365 * 24 * time.Hour,
	})
}

func TestCA_Revoke(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

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

	// Issue a certificate
	subjectKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert, err := issueTLSServerCert(ca, "server.example.com", []string{"server.example.com"}, &subjectKey.PublicKey)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	// Revoke it
	if err := ca.Revoke(cert.SerialNumber.Bytes(), ReasonSuperseded); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}

	// Check it's marked as revoked
	isRevoked, err := store.IsRevoked(cert.SerialNumber.Bytes())
	if err != nil {
		t.Fatalf("IsRevoked() error = %v", err)
	}
	if !isRevoked {
		t.Error("certificate should be revoked")
	}
}

func TestCA_GenerateCRL(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

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

	// Issue and revoke a certificate
	subjectKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert, _ := issueTLSServerCert(ca, "server.example.com", []string{"server.example.com"}, &subjectKey.PublicKey)
	_ = ca.Revoke(cert.SerialNumber.Bytes(), ReasonKeyCompromise)

	// Generate CRL
	nextUpdate := time.Now().AddDate(0, 0, 7)
	crlDER, err := ca.GenerateCRL(nextUpdate)
	if err != nil {
		t.Fatalf("GenerateCRL() error = %v", err)
	}

	if len(crlDER) == 0 {
		t.Error("CRL should not be empty")
	}

	// Parse and verify CRL
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatalf("ParseRevocationList() error = %v", err)
	}

	if len(crl.RevokedCertificateEntries) != 1 {
		t.Errorf("CRL should have 1 revoked cert, got %d", len(crl.RevokedCertificateEntries))
	}

	// Verify CRL signature
	if err := crl.CheckSignatureFrom(ca.Certificate()); err != nil {
		t.Errorf("CRL signature verification failed: %v", err)
	}
}

func TestStore_ListRevoked(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

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

	// Issue 3 certificates, revoke 2
	for i := 0; i < 3; i++ {
		subjectKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		cert, _ := issueTLSServerCert(ca, "server.example.com", []string{"server.example.com"}, &subjectKey.PublicKey)
		if i < 2 {
			_ = ca.Revoke(cert.SerialNumber.Bytes(), ReasonUnspecified)
		}
	}

	revoked, err := store.ListRevoked()
	if err != nil {
		t.Fatalf("ListRevoked() error = %v", err)
	}

	if len(revoked) != 2 {
		t.Errorf("ListRevoked() returned %d, want 2", len(revoked))
	}
}

func TestParseRevocationReason(t *testing.T) {
	tests := []struct {
		input    string
		expected RevocationReason
		wantErr  bool
	}{
		{"unspecified", ReasonUnspecified, false},
		{"keyCompromise", ReasonKeyCompromise, false},
		{"key-compromise", ReasonKeyCompromise, false},
		{"superseded", ReasonSuperseded, false},
		{"cessation", ReasonCessationOfOperation, false},
		{"hold", ReasonCertificateHold, false},
		{"", ReasonUnspecified, false},
		{"invalid", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			reason, err := ParseRevocationReason(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if reason != tt.expected {
				t.Errorf("reason = %v, want %v", reason, tt.expected)
			}
		})
	}
}

func TestRevocationReason_String(t *testing.T) {
	tests := []struct {
		reason RevocationReason
		want   string
	}{
		{ReasonUnspecified, "unspecified"},
		{ReasonKeyCompromise, "keyCompromise"},
		{ReasonCACompromise, "caCompromise"},
		{ReasonAffiliationChanged, "affiliationChanged"},
		{ReasonSuperseded, "superseded"},
		{ReasonCessationOfOperation, "cessationOfOperation"},
		{ReasonCertificateHold, "certificateHold"},
		{ReasonRemoveFromCRL, "removeFromCRL"},
		{ReasonPrivilegeWithdrawn, "privilegeWithdrawn"},
		{ReasonAACompromise, "aaCompromise"},
		{RevocationReason(99), "unknown(99)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.reason.String(); got != tt.want {
				t.Errorf("String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStore_CRLPath(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

	path := store.CRLPath()
	expected := tmpDir + "/crl/ca.crl"

	if path != expected {
		t.Errorf("CRLPath() = %v, want %v", path, expected)
	}
}

func TestStore_LoadCRL(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

	// No CRL yet - should return nil, nil
	crl, err := store.LoadCRL()
	if err != nil {
		t.Fatalf("LoadCRL() error = %v (expected nil for non-existent)", err)
	}
	if crl != nil {
		t.Error("LoadCRL() should return nil when no CRL exists")
	}

	// Initialize CA and generate CRL
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

	// Generate CRL
	nextUpdate := time.Now().AddDate(0, 0, 7)
	_, err = ca.GenerateCRL(nextUpdate)
	if err != nil {
		t.Fatalf("GenerateCRL() error = %v", err)
	}

	// Now LoadCRL should work
	crl, err = store.LoadCRL()
	if err != nil {
		t.Fatalf("LoadCRL() error = %v", err)
	}
	if crl == nil {
		t.Error("LoadCRL() should return CRL after generation")
	}
	if crl.Issuer.CommonName != "Test Root CA" {
		t.Errorf("CRL issuer = %v, want Test Root CA", crl.Issuer.CommonName)
	}
}

func TestStore_LoadCRL_InvalidPEM(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)
	store.Init()

	// Create crl directory and write invalid PEM
	crlDir := tmpDir + "/crl"
	if err := os.MkdirAll(crlDir, 0755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(store.CRLPath(), []byte("not a valid PEM"), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, err := store.LoadCRL()
	if err == nil {
		t.Error("LoadCRL() should fail for invalid PEM")
	}
}

func TestParseRevocationReason_AllVariants(t *testing.T) {
	tests := []struct {
		input    string
		expected RevocationReason
		wantErr  bool
	}{
		// Standard names
		{"unspecified", ReasonUnspecified, false},
		{"keyCompromise", ReasonKeyCompromise, false},
		{"caCompromise", ReasonCACompromise, false},
		{"affiliationChanged", ReasonAffiliationChanged, false},
		{"superseded", ReasonSuperseded, false},
		{"cessationOfOperation", ReasonCessationOfOperation, false},
		{"certificateHold", ReasonCertificateHold, false},
		{"privilegeWithdrawn", ReasonPrivilegeWithdrawn, false},

		// Alternative names (hyphenated)
		{"key-compromise", ReasonKeyCompromise, false},
		{"ca-compromise", ReasonCACompromise, false},
		{"affiliation-changed", ReasonAffiliationChanged, false},

		// Short names
		{"cessation", ReasonCessationOfOperation, false},
		{"hold", ReasonCertificateHold, false},

		// Empty defaults to unspecified
		{"", ReasonUnspecified, false},

		// Invalid
		{"invalid-reason", 0, true},
		{"removeFromCRL", 0, true}, // Not directly parseable
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			reason, err := ParseRevocationReason(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && reason != tt.expected {
				t.Errorf("reason = %v, want %v", reason, tt.expected)
			}
		})
	}
}

func TestCA_Revoke_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

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

	// Try to revoke a non-existent certificate
	err = ca.Revoke([]byte{0x99, 0x99}, ReasonUnspecified)
	if err == nil {
		t.Error("Revoke() should fail for non-existent certificate")
	}
}

func TestCA_Revoke_NoSigner(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
		Passphrase:    "test",
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

	// Try to revoke without signer loaded
	err = ca.Revoke([]byte{0x01}, ReasonUnspecified)
	if err == nil {
		t.Error("Revoke() should fail when signer not loaded")
	}
}

func TestCA_GenerateCRL_NoSigner(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

	cfg := Config{
		CommonName:    "Test Root CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
		Passphrase:    "test",
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

	// Try to generate CRL without signer loaded
	_, err = ca.GenerateCRL(time.Now().AddDate(0, 0, 7))
	if err == nil {
		t.Error("GenerateCRL() should fail when signer not loaded")
	}
}
