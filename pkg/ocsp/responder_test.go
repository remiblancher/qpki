package ocsp

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/remiblancher/qpki/pkg/ca"
)

// =============================================================================
// Mock Store for OCSP Responder Tests
// =============================================================================

// mockCAStore implements ca.Store interface for testing.
type mockCAStore struct {
	index    []ca.IndexEntry
	indexErr error
	caCert   *x509.Certificate
}

func (m *mockCAStore) Init(ctx context.Context) error                               { return nil }
func (m *mockCAStore) Exists() bool                                                 { return true }
func (m *mockCAStore) BasePath() string                                             { return "/mock" }
func (m *mockCAStore) SaveCACert(ctx context.Context, cert *x509.Certificate) error { return nil }
func (m *mockCAStore) LoadCACert(ctx context.Context) (*x509.Certificate, error) {
	return m.caCert, nil
}
func (m *mockCAStore) LoadAllCACerts(ctx context.Context) ([]*x509.Certificate, error) {
	return []*x509.Certificate{m.caCert}, nil
}
func (m *mockCAStore) LoadCrossSignedCerts(ctx context.Context) ([]*x509.Certificate, error) {
	return nil, nil
}
func (m *mockCAStore) SaveCert(ctx context.Context, cert *x509.Certificate) error { return nil }
func (m *mockCAStore) SaveCertAt(ctx context.Context, path string, cert *x509.Certificate) error {
	return nil
}
func (m *mockCAStore) LoadCert(ctx context.Context, serial []byte) (*x509.Certificate, error) {
	return nil, nil
}
func (m *mockCAStore) CACertPath() string { return "/mock/ca.crt" }
func (m *mockCAStore) CAKeyPath() string  { return "/mock/ca.key" }
func (m *mockCAStore) CertPath(serial []byte) string {
	return "/mock/certs/" + hex.EncodeToString(serial) + ".crt"
}
func (m *mockCAStore) NextSerial(ctx context.Context) ([]byte, error) { return []byte{1}, nil }
func (m *mockCAStore) ReadIndex(ctx context.Context) ([]ca.IndexEntry, error) {
	if m.indexErr != nil {
		return nil, m.indexErr
	}
	return m.index, nil
}
func (m *mockCAStore) MarkRevoked(ctx context.Context, serial []byte, reason ca.RevocationReason) error {
	return nil
}
func (m *mockCAStore) NextCRLNumber(ctx context.Context) ([]byte, error) { return []byte{1}, nil }
func (m *mockCAStore) SaveCRL(ctx context.Context, crlDER []byte) error  { return nil }
func (m *mockCAStore) SaveCRLForAlgorithm(ctx context.Context, crlDER []byte, algorithm string) error {
	return nil
}

// =============================================================================
// NewResponder Tests
// =============================================================================

func TestU_NewResponder_Valid(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	store := &mockCAStore{caCert: caCert}

	responder, err := NewResponder(&ResponderConfig{
		Signer:  caKey,
		CACert:  caCert,
		CAStore: store,
	})

	if err != nil {
		t.Fatalf("NewResponder() error = %v, want nil", err)
	}
	if responder == nil {
		t.Fatal("NewResponder() returned nil responder")
	}
}

func TestU_NewResponder_MissingSigner(t *testing.T) {
	caCert, _ := generateTestCA(t)
	store := &mockCAStore{caCert: caCert}

	_, err := NewResponder(&ResponderConfig{
		Signer:  nil,
		CACert:  caCert,
		CAStore: store,
	})

	if err == nil {
		t.Error("NewResponder() expected error for missing signer")
	}
}

func TestU_NewResponder_MissingCACert(t *testing.T) {
	_, caKey := generateTestCA(t)
	store := &mockCAStore{}

	_, err := NewResponder(&ResponderConfig{
		Signer:  caKey,
		CACert:  nil,
		CAStore: store,
	})

	if err == nil {
		t.Error("NewResponder() expected error for missing CA cert")
	}
}

func TestU_NewResponder_MissingStore(t *testing.T) {
	caCert, caKey := generateTestCA(t)

	_, err := NewResponder(&ResponderConfig{
		Signer:  caKey,
		CACert:  caCert,
		CAStore: nil,
	})

	if err == nil {
		t.Error("NewResponder() expected error for missing store")
	}
}

func TestU_NewResponder_DefaultResponderCert(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	store := &mockCAStore{caCert: caCert}

	responder, err := NewResponder(&ResponderConfig{
		Signer:        caKey,
		CACert:        caCert,
		CAStore:       store,
		ResponderCert: nil, // Should default to CA cert
	})

	if err != nil {
		t.Fatalf("NewResponder() error = %v", err)
	}
	if responder.config.ResponderCert != caCert {
		t.Error("NewResponder() did not default ResponderCert to CACert")
	}
}

func TestU_NewResponder_DefaultValidity(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	store := &mockCAStore{caCert: caCert}

	responder, err := NewResponder(&ResponderConfig{
		Signer:   caKey,
		CACert:   caCert,
		CAStore:  store,
		Validity: 0, // Should default to 1 hour
	})

	if err != nil {
		t.Fatalf("NewResponder() error = %v", err)
	}
	if responder.config.Validity != time.Hour {
		t.Errorf("NewResponder() Validity = %v, want %v", responder.config.Validity, time.Hour)
	}
}

// =============================================================================
// Respond Tests
// =============================================================================

func TestU_Respond_NilRequest(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	store := &mockCAStore{caCert: caCert}

	responder, _ := NewResponder(&ResponderConfig{
		Signer:  caKey,
		CACert:  caCert,
		CAStore: store,
	})

	responseBytes, err := responder.Respond(context.Background(), nil)
	if err != nil {
		t.Fatalf("Respond() error = %v", err)
	}

	// Should return malformed response
	if responseBytes == nil {
		t.Fatal("Respond() returned nil response")
	}
}

func TestU_Respond_EmptyRequestList(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	store := &mockCAStore{caCert: caCert}

	responder, _ := NewResponder(&ResponderConfig{
		Signer:  caKey,
		CACert:  caCert,
		CAStore: store,
	})

	req := &OCSPRequest{
		TBSRequest: TBSRequest{
			RequestList: []Request{}, // Empty list
		},
	}

	responseBytes, err := responder.Respond(context.Background(), req)
	if err != nil {
		t.Fatalf("Respond() error = %v", err)
	}

	// Should return malformed response
	if responseBytes == nil {
		t.Fatal("Respond() returned nil response")
	}
}

func TestU_Respond_ValidRequest_Good(t *testing.T) {
	caCert, caKey := generateTestCA(t)

	// Create a certificate serial
	serial := big.NewInt(12345)

	store := &mockCAStore{
		caCert: caCert,
		index: []ca.IndexEntry{
			{
				Status: "V", // Valid
				Serial: serial.Bytes(),
				Expiry: time.Now().Add(24 * time.Hour),
			},
		},
	}

	responder, _ := NewResponder(&ResponderConfig{
		Signer:  caKey,
		CACert:  caCert,
		CAStore: store,
	})

	// Create a CertID for the request
	certID, err := NewCertIDFromSerial(crypto.SHA256, caCert, serial)
	if err != nil {
		t.Fatalf("NewCertIDFromSerial() error = %v", err)
	}

	req := &OCSPRequest{
		TBSRequest: TBSRequest{
			RequestList: []Request{
				{ReqCert: *certID},
			},
		},
	}

	responseBytes, err := responder.Respond(context.Background(), req)
	if err != nil {
		t.Fatalf("Respond() error = %v", err)
	}

	if responseBytes == nil {
		t.Fatal("Respond() returned nil response")
	}
}

func TestU_Respond_ValidRequest_Revoked(t *testing.T) {
	caCert, caKey := generateTestCA(t)

	serial := big.NewInt(12345)
	revocationTime := time.Now().Add(-1 * time.Hour)

	store := &mockCAStore{
		caCert: caCert,
		index: []ca.IndexEntry{
			{
				Status:     "R", // Revoked
				Serial:     serial.Bytes(),
				Expiry:     time.Now().Add(24 * time.Hour),
				Revocation: revocationTime,
			},
		},
	}

	responder, _ := NewResponder(&ResponderConfig{
		Signer:  caKey,
		CACert:  caCert,
		CAStore: store,
	})

	certID, _ := NewCertIDFromSerial(crypto.SHA256, caCert, serial)
	req := &OCSPRequest{
		TBSRequest: TBSRequest{
			RequestList: []Request{
				{ReqCert: *certID},
			},
		},
	}

	responseBytes, err := responder.Respond(context.Background(), req)
	if err != nil {
		t.Fatalf("Respond() error = %v", err)
	}

	if responseBytes == nil {
		t.Fatal("Respond() returned nil response")
	}
}

func TestU_Respond_WithNonce(t *testing.T) {
	caCert, caKey := generateTestCA(t)

	serial := big.NewInt(12345)
	store := &mockCAStore{
		caCert: caCert,
		index: []ca.IndexEntry{
			{
				Status: "V",
				Serial: serial.Bytes(),
			},
		},
	}

	responder, _ := NewResponder(&ResponderConfig{
		Signer:    caKey,
		CACert:    caCert,
		CAStore:   store,
		CopyNonce: true,
	})

	certID, _ := NewCertIDFromSerial(crypto.SHA256, caCert, serial)

	// Create request with nonce manually
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("Failed to generate nonce: %v", err)
	}
	nonceValue, _ := asn1.Marshal(nonce)

	req := &OCSPRequest{
		TBSRequest: TBSRequest{
			RequestList: []Request{
				{ReqCert: *certID},
			},
			RequestExtensions: []pkix.Extension{
				{
					Id:       OIDOcspNonce,
					Critical: false,
					Value:    nonceValue,
				},
			},
		},
	}

	responseBytes, err := responder.Respond(context.Background(), req)
	if err != nil {
		t.Fatalf("Respond() error = %v", err)
	}

	if responseBytes == nil {
		t.Fatal("Respond() returned nil response")
	}
}

// =============================================================================
// CheckStatus Tests
// =============================================================================

func TestU_CheckStatus_Good(t *testing.T) {
	caCert, caKey := generateTestCA(t)

	serial := big.NewInt(12345)
	store := &mockCAStore{
		caCert: caCert,
		index: []ca.IndexEntry{
			{
				Status: "V",
				Serial: serial.Bytes(),
			},
		},
	}

	responder, _ := NewResponder(&ResponderConfig{
		Signer:  caKey,
		CACert:  caCert,
		CAStore: store,
	})

	certID, _ := NewCertIDFromSerial(crypto.SHA256, caCert, serial)

	status, err := responder.CheckStatus(context.Background(), certID)
	if err != nil {
		t.Fatalf("CheckStatus() error = %v", err)
	}
	if status.Status != CertStatusGood {
		t.Errorf("CheckStatus() status = %v, want %v", status.Status, CertStatusGood)
	}
}

func TestU_CheckStatus_Revoked(t *testing.T) {
	caCert, caKey := generateTestCA(t)

	serial := big.NewInt(12345)
	revTime := time.Now().Add(-1 * time.Hour)

	store := &mockCAStore{
		caCert: caCert,
		index: []ca.IndexEntry{
			{
				Status:     "R",
				Serial:     serial.Bytes(),
				Revocation: revTime,
			},
		},
	}

	responder, _ := NewResponder(&ResponderConfig{
		Signer:  caKey,
		CACert:  caCert,
		CAStore: store,
	})

	certID, _ := NewCertIDFromSerial(crypto.SHA256, caCert, serial)

	status, err := responder.CheckStatus(context.Background(), certID)
	if err != nil {
		t.Fatalf("CheckStatus() error = %v", err)
	}
	if status.Status != CertStatusRevoked {
		t.Errorf("CheckStatus() status = %v, want %v", status.Status, CertStatusRevoked)
	}
}

func TestU_CheckStatus_Unknown(t *testing.T) {
	caCert, caKey := generateTestCA(t)

	store := &mockCAStore{
		caCert: caCert,
		index:  []ca.IndexEntry{}, // Empty index - cert not found
	}

	responder, _ := NewResponder(&ResponderConfig{
		Signer:  caKey,
		CACert:  caCert,
		CAStore: store,
	})

	serial := big.NewInt(99999) // Non-existent serial
	certID, _ := NewCertIDFromSerial(crypto.SHA256, caCert, serial)

	status, err := responder.CheckStatus(context.Background(), certID)
	if err != nil {
		t.Fatalf("CheckStatus() error = %v", err)
	}
	if status.Status != CertStatusUnknown {
		t.Errorf("CheckStatus() status = %v, want %v", status.Status, CertStatusUnknown)
	}
}

func TestU_CheckStatus_IssuerMismatch(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	otherCA, _ := generateTestCA(t) // Different CA

	store := &mockCAStore{
		caCert: caCert,
		index: []ca.IndexEntry{
			{
				Status: "V",
				Serial: big.NewInt(12345).Bytes(),
			},
		},
	}

	responder, _ := NewResponder(&ResponderConfig{
		Signer:  caKey,
		CACert:  caCert,
		CAStore: store,
	})

	// Create CertID for a different CA
	certID, _ := NewCertIDFromSerial(crypto.SHA256, otherCA, big.NewInt(12345))

	status, err := responder.CheckStatus(context.Background(), certID)
	if err != nil {
		t.Fatalf("CheckStatus() error = %v", err)
	}
	// Should return unknown since issuer doesn't match
	if status.Status != CertStatusUnknown {
		t.Errorf("CheckStatus() status = %v, want %v", status.Status, CertStatusUnknown)
	}
}

func TestU_CheckStatus_IndexError(t *testing.T) {
	caCert, caKey := generateTestCA(t)

	store := &mockCAStore{
		caCert:   caCert,
		indexErr: errors.New("index read error"),
	}

	responder, _ := NewResponder(&ResponderConfig{
		Signer:  caKey,
		CACert:  caCert,
		CAStore: store,
	})

	certID, _ := NewCertIDFromSerial(crypto.SHA256, caCert, big.NewInt(12345))

	_, err := responder.CheckStatus(context.Background(), certID)
	if err == nil {
		t.Error("CheckStatus() expected error for index read failure")
	}
}

// =============================================================================
// statusFromEntry Tests
// =============================================================================

func TestU_statusFromEntry_Valid(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	store := &mockCAStore{caCert: caCert}

	responder, _ := NewResponder(&ResponderConfig{
		Signer:  caKey,
		CACert:  caCert,
		CAStore: store,
	})

	entry := &ca.IndexEntry{Status: "V"}
	status := responder.statusFromEntry(entry)

	if status.Status != CertStatusGood {
		t.Errorf("statusFromEntry(V) = %v, want %v", status.Status, CertStatusGood)
	}
}

func TestU_statusFromEntry_Revoked(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	store := &mockCAStore{caCert: caCert}

	responder, _ := NewResponder(&ResponderConfig{
		Signer:  caKey,
		CACert:  caCert,
		CAStore: store,
	})

	revTime := time.Now().Add(-1 * time.Hour)
	entry := &ca.IndexEntry{Status: "R", Revocation: revTime}
	status := responder.statusFromEntry(entry)

	if status.Status != CertStatusRevoked {
		t.Errorf("statusFromEntry(R) = %v, want %v", status.Status, CertStatusRevoked)
	}
	if !status.RevocationTime.Equal(revTime) {
		t.Errorf("statusFromEntry(R) RevocationTime = %v, want %v", status.RevocationTime, revTime)
	}
}

func TestU_statusFromEntry_RevokedWithReason(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	store := &mockCAStore{caCert: caCert}

	responder, _ := NewResponder(&ResponderConfig{
		Signer:  caKey,
		CACert:  caCert,
		CAStore: store,
	})

	tests := []struct {
		name       string
		caReason   ca.RevocationReason
		wantReason RevocationReason
	}{
		{"keyCompromise", ca.ReasonKeyCompromise, ReasonKeyCompromise},
		{"caCompromise", ca.ReasonCACompromise, ReasonCACompromise},
		{"affiliationChanged", ca.ReasonAffiliationChanged, ReasonAffiliationChanged},
		{"superseded", ca.ReasonSuperseded, ReasonSuperseded},
		{"cessationOfOperation", ca.ReasonCessationOfOperation, ReasonCessationOfOperation},
		{"certificateHold", ca.ReasonCertificateHold, ReasonCertificateHold},
		{"privilegeWithdrawn", ca.ReasonPrivilegeWithdrawn, ReasonPrivilegeWithdrawn},
		{"unspecified", ca.ReasonUnspecified, ReasonUnspecified},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			revTime := time.Now().Add(-1 * time.Hour)
			entry := &ca.IndexEntry{
				Status:           "R",
				Revocation:       revTime,
				RevocationReason: tt.caReason,
			}
			status := responder.statusFromEntry(entry)

			if status.Status != CertStatusRevoked {
				t.Errorf("statusFromEntry() Status = %v, want %v", status.Status, CertStatusRevoked)
			}
			if status.RevocationReason != tt.wantReason {
				t.Errorf("statusFromEntry() RevocationReason = %v, want %v", status.RevocationReason, tt.wantReason)
			}
		})
	}
}

func TestU_statusFromEntry_Expired(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	store := &mockCAStore{caCert: caCert}

	responder, _ := NewResponder(&ResponderConfig{
		Signer:  caKey,
		CACert:  caCert,
		CAStore: store,
	})

	entry := &ca.IndexEntry{Status: "E"}
	status := responder.statusFromEntry(entry)

	// Expired certs are still "good" from OCSP perspective
	if status.Status != CertStatusGood {
		t.Errorf("statusFromEntry(E) = %v, want %v", status.Status, CertStatusGood)
	}
}

func TestU_statusFromEntry_Unknown(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	store := &mockCAStore{caCert: caCert}

	responder, _ := NewResponder(&ResponderConfig{
		Signer:  caKey,
		CACert:  caCert,
		CAStore: store,
	})

	entry := &ca.IndexEntry{Status: "X"} // Unknown status
	status := responder.statusFromEntry(entry)

	if status.Status != CertStatusUnknown {
		t.Errorf("statusFromEntry(X) = %v, want %v", status.Status, CertStatusUnknown)
	}
}

// =============================================================================
// CheckStatusBySerial Tests
// =============================================================================

func TestU_CheckStatusBySerial_Valid(t *testing.T) {
	caCert, caKey := generateTestCA(t)

	serial := big.NewInt(12345)
	store := &mockCAStore{
		caCert: caCert,
		index: []ca.IndexEntry{
			{
				Status: "V",
				Serial: serial.Bytes(),
			},
		},
	}

	responder, _ := NewResponder(&ResponderConfig{
		Signer:  caKey,
		CACert:  caCert,
		CAStore: store,
	})

	status, err := responder.CheckStatusBySerial(context.Background(), serial)
	if err != nil {
		t.Fatalf("CheckStatusBySerial() error = %v", err)
	}
	if status.Status != CertStatusGood {
		t.Errorf("CheckStatusBySerial() status = %v, want %v", status.Status, CertStatusGood)
	}
}

// =============================================================================
// CheckStatusBySerialHex Tests
// =============================================================================

func TestU_CheckStatusBySerialHex_Valid(t *testing.T) {
	caCert, caKey := generateTestCA(t)

	serial := big.NewInt(12345)
	serialHex := hex.EncodeToString(serial.Bytes())

	store := &mockCAStore{
		caCert: caCert,
		index: []ca.IndexEntry{
			{
				Status: "V",
				Serial: serial.Bytes(),
			},
		},
	}

	responder, _ := NewResponder(&ResponderConfig{
		Signer:  caKey,
		CACert:  caCert,
		CAStore: store,
	})

	status, err := responder.CheckStatusBySerialHex(context.Background(), serialHex)
	if err != nil {
		t.Fatalf("CheckStatusBySerialHex() error = %v", err)
	}
	if status.Status != CertStatusGood {
		t.Errorf("CheckStatusBySerialHex() status = %v, want %v", status.Status, CertStatusGood)
	}
}

func TestU_CheckStatusBySerialHex_Invalid(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	store := &mockCAStore{caCert: caCert}

	responder, _ := NewResponder(&ResponderConfig{
		Signer:  caKey,
		CACert:  caCert,
		CAStore: store,
	})

	_, err := responder.CheckStatusBySerialHex(context.Background(), "not-hex")
	if err == nil {
		t.Error("CheckStatusBySerialHex() expected error for invalid hex")
	}
}

// =============================================================================
// CreateResponseForSerial Tests
// =============================================================================

func TestU_CreateResponseForSerial_Good(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	store := &mockCAStore{caCert: caCert}

	responder, _ := NewResponder(&ResponderConfig{
		Signer:  caKey,
		CACert:  caCert,
		CAStore: store,
	})

	serial := big.NewInt(12345)
	responseBytes, err := responder.CreateResponseForSerial(serial, CertStatusGood, time.Time{}, ReasonUnspecified)
	if err != nil {
		t.Fatalf("CreateResponseForSerial() error = %v", err)
	}
	if responseBytes == nil {
		t.Fatal("CreateResponseForSerial() returned nil")
	}
}

func TestU_CreateResponseForSerial_Revoked(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	store := &mockCAStore{caCert: caCert}

	responder, _ := NewResponder(&ResponderConfig{
		Signer:  caKey,
		CACert:  caCert,
		CAStore: store,
	})

	serial := big.NewInt(12345)
	revTime := time.Now().Add(-1 * time.Hour)
	responseBytes, err := responder.CreateResponseForSerial(serial, CertStatusRevoked, revTime, ReasonKeyCompromise)
	if err != nil {
		t.Fatalf("CreateResponseForSerial() error = %v", err)
	}
	if responseBytes == nil {
		t.Fatal("CreateResponseForSerial() returned nil")
	}
}

func TestU_CreateResponseForSerial_Unknown(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	store := &mockCAStore{caCert: caCert}

	responder, _ := NewResponder(&ResponderConfig{
		Signer:  caKey,
		CACert:  caCert,
		CAStore: store,
	})

	serial := big.NewInt(12345)
	responseBytes, err := responder.CreateResponseForSerial(serial, CertStatusUnknown, time.Time{}, ReasonUnspecified)
	if err != nil {
		t.Fatalf("CreateResponseForSerial() error = %v", err)
	}
	if responseBytes == nil {
		t.Fatal("CreateResponseForSerial() returned nil")
	}
}

// =============================================================================
// CreateResponseForSerialHex Tests
// =============================================================================

func TestU_CreateResponseForSerialHex_Valid(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	store := &mockCAStore{caCert: caCert}

	responder, _ := NewResponder(&ResponderConfig{
		Signer:  caKey,
		CACert:  caCert,
		CAStore: store,
	})

	serial := big.NewInt(12345)
	serialHex := hex.EncodeToString(serial.Bytes())

	responseBytes, err := responder.CreateResponseForSerialHex(serialHex, CertStatusGood, time.Time{}, ReasonUnspecified)
	if err != nil {
		t.Fatalf("CreateResponseForSerialHex() error = %v", err)
	}
	if responseBytes == nil {
		t.Fatal("CreateResponseForSerialHex() returned nil")
	}
}

func TestU_CreateResponseForSerialHex_InvalidHex(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	store := &mockCAStore{caCert: caCert}

	responder, _ := NewResponder(&ResponderConfig{
		Signer:  caKey,
		CACert:  caCert,
		CAStore: store,
	})

	_, err := responder.CreateResponseForSerialHex("not-hex", CertStatusGood, time.Time{}, ReasonUnspecified)
	if err == nil {
		t.Error("CreateResponseForSerialHex() expected error for invalid hex")
	}
}

// =============================================================================
// ServeOCSP Tests
// =============================================================================

func TestU_ServeOCSP_ValidRequest(t *testing.T) {
	caCert, caKey := generateTestCA(t)

	serial := big.NewInt(12345)
	store := &mockCAStore{
		caCert: caCert,
		index: []ca.IndexEntry{
			{
				Status: "V",
				Serial: serial.Bytes(),
			},
		},
	}

	responder, _ := NewResponder(&ResponderConfig{
		Signer:  caKey,
		CACert:  caCert,
		CAStore: store,
	})

	// Create a valid OCSP request manually
	certID, err := NewCertIDFromSerial(crypto.SHA256, caCert, serial)
	if err != nil {
		t.Fatalf("NewCertIDFromSerial() error = %v", err)
	}

	req := &OCSPRequest{
		TBSRequest: TBSRequest{
			RequestList: []Request{
				{ReqCert: *certID},
			},
		},
	}

	reqBytes, err := req.Marshal()
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	responseBytes, err := responder.ServeOCSP(context.Background(), reqBytes)
	if err != nil {
		t.Fatalf("ServeOCSP() error = %v", err)
	}
	if responseBytes == nil {
		t.Fatal("ServeOCSP() returned nil")
	}
}

func TestU_ServeOCSP_InvalidRequest(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	store := &mockCAStore{caCert: caCert}

	responder, _ := NewResponder(&ResponderConfig{
		Signer:  caKey,
		CACert:  caCert,
		CAStore: store,
	})

	// Invalid request data
	responseBytes, err := responder.ServeOCSP(context.Background(), []byte("invalid"))
	if err != nil {
		t.Fatalf("ServeOCSP() error = %v", err)
	}
	// Should return a malformed response, not an error
	if responseBytes == nil {
		t.Fatal("ServeOCSP() returned nil for invalid request")
	}
}

// =============================================================================
// VerifyResponderCert Tests
// =============================================================================

func TestU_VerifyResponderCert_ValidWithEKU(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	responderKP := generateECDSAKeyPair(t, elliptic.P256())
	responderCert := generateOCSPResponderCert(t, caCert, caKey, responderKP)

	err := VerifyResponderCert(responderCert, caCert)
	if err != nil {
		t.Errorf("VerifyResponderCert() error = %v, want nil", err)
	}
}

func TestU_VerifyResponderCert_CAWithoutEKU(t *testing.T) {
	caCert, _ := generateTestCA(t)

	// CA certificates are allowed even without OCSP Signing EKU
	err := VerifyResponderCert(caCert, nil)
	if err != nil {
		t.Errorf("VerifyResponderCert() for CA error = %v, want nil", err)
	}
}

func TestU_VerifyResponderCert_MissingEKU(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	endEntityKP := generateECDSAKeyPair(t, elliptic.P256())
	// Generate a certificate without OCSP Signing EKU
	endEntityCert := issueTestCertificate(t, caCert, caKey, endEntityKP)

	err := VerifyResponderCert(endEntityCert, caCert)
	if err == nil {
		t.Error("VerifyResponderCert() expected error for missing EKU")
	}
}

func TestU_VerifyResponderCert_WrongIssuer(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	otherCA, _ := generateTestCA(t)

	responderKP := generateECDSAKeyPair(t, elliptic.P256())
	responderCert := generateOCSPResponderCert(t, caCert, caKey, responderKP)

	// Verify against wrong CA
	err := VerifyResponderCert(responderCert, otherCA)
	if err == nil {
		t.Error("VerifyResponderCert() expected error for wrong issuer")
	}
}

func TestU_VerifyResponderCert_Expired(t *testing.T) {
	// Create an expired responder certificate
	kp := generateECDSAKeyPair(t, elliptic.P256())

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "Expired OCSP Responder",
		},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(-24 * time.Hour), // Already expired
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
		BasicConstraintsValid: true,
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, kp.PublicKey, kp.PrivateKey)
	expiredCert, _ := x509.ParseCertificate(certDER)

	err := VerifyResponderCert(expiredCert, nil)
	if err == nil {
		t.Error("VerifyResponderCert() expected error for expired cert")
	}
}

func TestU_VerifyResponderCert_NotYetValid(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "Future OCSP Responder",
		},
		NotBefore:             time.Now().Add(24 * time.Hour), // Not yet valid
		NotAfter:              time.Now().Add(48 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
		BasicConstraintsValid: true,
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, kp.PublicKey, kp.PrivateKey)
	futureCert, _ := x509.ParseCertificate(certDER)

	err := VerifyResponderCert(futureCert, nil)
	if err == nil {
		t.Error("VerifyResponderCert() expected error for not yet valid cert")
	}
}

// =============================================================================
// Integration Tests
// =============================================================================

func TestF_Responder_RoundTrip(t *testing.T) {
	caCert, caKey := generateTestCA(t)

	// Set up index with various certificate statuses
	serial1 := big.NewInt(1001)
	serial2 := big.NewInt(1002)
	serial3 := big.NewInt(1003)
	revTime := time.Now().Add(-1 * time.Hour)

	store := &mockCAStore{
		caCert: caCert,
		index: []ca.IndexEntry{
			{Status: "V", Serial: serial1.Bytes()},
			{Status: "R", Serial: serial2.Bytes(), Revocation: revTime},
			{Status: "E", Serial: serial3.Bytes()},
		},
	}

	responder, _ := NewResponder(&ResponderConfig{
		Signer:  caKey,
		CACert:  caCert,
		CAStore: store,
	})

	// Helper to create request bytes
	createReqBytes := func(serial *big.Int) []byte {
		certID, _ := NewCertIDFromSerial(crypto.SHA256, caCert, serial)
		req := &OCSPRequest{
			TBSRequest: TBSRequest{
				RequestList: []Request{{ReqCert: *certID}},
			},
		}
		reqBytes, _ := req.Marshal()
		return reqBytes
	}

	// Test good certificate
	reqBytes1 := createReqBytes(serial1)
	respBytes1, err := responder.ServeOCSP(context.Background(), reqBytes1)
	if err != nil {
		t.Fatalf("ServeOCSP(good) error = %v", err)
	}
	resp1, _ := ParseResponse(respBytes1)
	if resp1 == nil {
		t.Fatal("ParseResponse() returned nil")
	}

	// Test revoked certificate
	reqBytes2 := createReqBytes(serial2)
	respBytes2, err := responder.ServeOCSP(context.Background(), reqBytes2)
	if err != nil {
		t.Fatalf("ServeOCSP(revoked) error = %v", err)
	}
	if respBytes2 == nil {
		t.Fatal("ServeOCSP(revoked) returned nil")
	}

	// Test expired certificate (should still be "good")
	reqBytes3 := createReqBytes(serial3)
	respBytes3, err := responder.ServeOCSP(context.Background(), reqBytes3)
	if err != nil {
		t.Fatalf("ServeOCSP(expired) error = %v", err)
	}
	if respBytes3 == nil {
		t.Fatal("ServeOCSP(expired) returned nil")
	}
}

// TestF_Responder_RevocationReasonEndToEnd verifies the complete flow:
// revocation with reason → index storage → OCSP response with correct reason.
// This is a regression test to ensure revocation reasons are never lost.
func TestF_Responder_RevocationReasonEndToEnd(t *testing.T) {
	caCert, caKey := generateTestCA(t)

	tests := []struct {
		name       string
		caReason   ca.RevocationReason
		wantReason RevocationReason
	}{
		{"keyCompromise", ca.ReasonKeyCompromise, ReasonKeyCompromise},
		{"caCompromise", ca.ReasonCACompromise, ReasonCACompromise},
		{"superseded", ca.ReasonSuperseded, ReasonSuperseded},
		{"cessationOfOperation", ca.ReasonCessationOfOperation, ReasonCessationOfOperation},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serial := big.NewInt(int64(2000 + i))
			revTime := time.Now().Add(-1 * time.Hour)

			// Simulate index entry with revocation reason (as it would be stored)
			store := &mockCAStore{
				caCert: caCert,
				index: []ca.IndexEntry{
					{
						Status:           "R",
						Serial:           serial.Bytes(),
						Revocation:       revTime,
						RevocationReason: tt.caReason, // This is key - reason must be stored
					},
				},
			}

			responder, err := NewResponder(&ResponderConfig{
				Signer:  caKey,
				CACert:  caCert,
				CAStore: store,
			})
			if err != nil {
				t.Fatalf("NewResponder() error = %v", err)
			}

			// Check status via responder
			status, err := responder.CheckStatusBySerial(context.Background(), serial)
			if err != nil {
				t.Fatalf("CheckStatusBySerial() error = %v", err)
			}

			// CRITICAL: Verify revocation reason is correct
			if status.Status != CertStatusRevoked {
				t.Errorf("Status = %v, want %v", status.Status, CertStatusRevoked)
			}
			if status.RevocationReason != tt.wantReason {
				t.Errorf("RevocationReason = %v, want %v (this is a REGRESSION - reason was lost!)",
					status.RevocationReason, tt.wantReason)
			}

			// Also test the full OCSP response flow
			certID, _ := NewCertIDFromSerial(crypto.SHA256, caCert, serial)
			req := &OCSPRequest{
				TBSRequest: TBSRequest{
					RequestList: []Request{{ReqCert: *certID}},
				},
			}
			reqBytes, _ := req.Marshal()

			respBytes, err := responder.ServeOCSP(context.Background(), reqBytes)
			if err != nil {
				t.Fatalf("ServeOCSP() error = %v", err)
			}
			if respBytes == nil {
				t.Fatal("ServeOCSP() returned nil")
			}

			// Parse and verify the response contains the correct reason
			parsedResp, err := ParseResponse(respBytes)
			if err != nil {
				t.Fatalf("ParseResponse() error = %v", err)
			}
			if parsedResp == nil {
				t.Fatal("ParseResponse() returned nil")
			}
		})
	}
}
