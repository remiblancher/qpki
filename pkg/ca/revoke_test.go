package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/remiblancher/post-quantum-pki/pkg/crypto"
)

// =============================================================================
// CA Revoke Functional Tests
// =============================================================================

func TestF_CA_Revoke(t *testing.T) {
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
	isRevoked, err := store.IsRevoked(context.Background(), cert.SerialNumber.Bytes())
	if err != nil {
		t.Fatalf("IsRevoked() error = %v", err)
	}
	if !isRevoked {
		t.Error("certificate should be revoked")
	}
}

func TestF_CA_Revoke_NotFound(t *testing.T) {
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

	// Try to revoke a non-existent certificate
	err = ca.Revoke([]byte{0x99, 0x99}, ReasonUnspecified)
	if err == nil {
		t.Error("Revoke() should fail for non-existent certificate")
	}
}

func TestF_CA_Revoke_SignerMissing(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

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

// =============================================================================
// RevocationReason Unit Tests
// =============================================================================

func TestU_ParseRevocationReason(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected RevocationReason
		wantErr  bool
	}{
		{"[Unit] Parse Reason: Unspecified", "unspecified", ReasonUnspecified, false},
		{"[Unit] Parse Reason: KeyCompromise", "keyCompromise", ReasonKeyCompromise, false},
		{"[Unit] Parse Reason: KeyCompromise Hyphen", "key-compromise", ReasonKeyCompromise, false},
		{"[Unit] Parse Reason: Superseded", "superseded", ReasonSuperseded, false},
		{"[Unit] Parse Reason: Cessation", "cessation", ReasonCessationOfOperation, false},
		{"[Unit] Parse Reason: Hold", "hold", ReasonCertificateHold, false},
		{"[Unit] Parse Reason: Empty", "", ReasonUnspecified, false},
		{"[Unit] Parse Reason: Invalid", "invalid", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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

func TestU_RevocationReason_String(t *testing.T) {
	tests := []struct {
		name   string
		reason RevocationReason
		want   string
	}{
		{"[Unit] Reason String: Unspecified", ReasonUnspecified, "unspecified"},
		{"[Unit] Reason String: KeyCompromise", ReasonKeyCompromise, "keyCompromise"},
		{"[Unit] Reason String: CACompromise", ReasonCACompromise, "caCompromise"},
		{"[Unit] Reason String: AffiliationChanged", ReasonAffiliationChanged, "affiliationChanged"},
		{"[Unit] Reason String: Superseded", ReasonSuperseded, "superseded"},
		{"[Unit] Reason String: CessationOfOperation", ReasonCessationOfOperation, "cessationOfOperation"},
		{"[Unit] Reason String: CertificateHold", ReasonCertificateHold, "certificateHold"},
		{"[Unit] Reason String: RemoveFromCRL", ReasonRemoveFromCRL, "removeFromCRL"},
		{"[Unit] Reason String: PrivilegeWithdrawn", ReasonPrivilegeWithdrawn, "privilegeWithdrawn"},
		{"[Unit] Reason String: AACompromise", ReasonAACompromise, "aaCompromise"},
		{"[Unit] Reason String: Unknown", RevocationReason(99), "unknown(99)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.reason.String(); got != tt.want {
				t.Errorf("String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestU_ParseRevocationReason_AllVariants(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected RevocationReason
		wantErr  bool
	}{
		// Standard names
		{"[Unit] Parse Reason: unspecified", "unspecified", ReasonUnspecified, false},
		{"[Unit] Parse Reason: keyCompromise", "keyCompromise", ReasonKeyCompromise, false},
		{"[Unit] Parse Reason: caCompromise", "caCompromise", ReasonCACompromise, false},
		{"[Unit] Parse Reason: affiliationChanged", "affiliationChanged", ReasonAffiliationChanged, false},
		{"[Unit] Parse Reason: superseded", "superseded", ReasonSuperseded, false},
		{"[Unit] Parse Reason: cessationOfOperation", "cessationOfOperation", ReasonCessationOfOperation, false},
		{"[Unit] Parse Reason: certificateHold", "certificateHold", ReasonCertificateHold, false},
		{"[Unit] Parse Reason: privilegeWithdrawn", "privilegeWithdrawn", ReasonPrivilegeWithdrawn, false},

		// Alternative names (hyphenated)
		{"[Unit] Parse Reason: key-compromise", "key-compromise", ReasonKeyCompromise, false},
		{"[Unit] Parse Reason: ca-compromise", "ca-compromise", ReasonCACompromise, false},
		{"[Unit] Parse Reason: affiliation-changed", "affiliation-changed", ReasonAffiliationChanged, false},

		// Short names
		{"[Unit] Parse Reason: cessation short", "cessation", ReasonCessationOfOperation, false},
		{"[Unit] Parse Reason: hold short", "hold", ReasonCertificateHold, false},

		// Empty defaults to unspecified
		{"[Unit] Parse Reason: empty", "", ReasonUnspecified, false},

		// Invalid
		{"[Unit] Parse Reason: invalid-reason", "invalid-reason", 0, true},
		{"[Unit] Parse Reason: removeFromCRL", "removeFromCRL", 0, true}, // Not directly parseable
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
