package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"

	"github.com/remiblancher/pki/internal/crypto"
)

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
	cert, err := ca.IssueTLSServer("server.example.com", []string{"server.example.com"}, &subjectKey.PublicKey)
	if err != nil {
		t.Fatalf("IssueTLSServer() error = %v", err)
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
	cert, _ := ca.IssueTLSServer("server.example.com", []string{"server.example.com"}, &subjectKey.PublicKey)
	ca.Revoke(cert.SerialNumber.Bytes(), ReasonKeyCompromise)

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

	if len(crl.RevokedCertificates) != 1 {
		t.Errorf("CRL should have 1 revoked cert, got %d", len(crl.RevokedCertificates))
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
		cert, _ := ca.IssueTLSServer("server.example.com", []string{"server.example.com"}, &subjectKey.PublicKey)
		if i < 2 {
			ca.Revoke(cert.SerialNumber.Bytes(), ReasonUnspecified)
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
		{ReasonSuperseded, "superseded"},
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
