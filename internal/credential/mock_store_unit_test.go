package credential

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"
)

// createCredMockTestCert creates a test certificate for credential mock store testing.
func createCredMockTestCert(t *testing.T, serial int64, cn string) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

func TestCredMockStore_SaveAndLoad(t *testing.T) {
	store := NewMockStore()

	subj := Subject{CommonName: "test.example.com"}
	cred := NewCredential("test-cred-1", subj)
	cred.CreateInitialVersion([]string{"ec/tls-server"}, []string{"ec"})

	certs := []*x509.Certificate{createCredMockTestCert(t, 1, "test.example.com")}

	err := store.Save(context.Background(), cred, certs, nil, nil)
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	loaded, err := store.Load(context.Background(), "test-cred-1")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if loaded.ID != cred.ID {
		t.Errorf("Loaded credential ID mismatch: got %s, want %s", loaded.ID, cred.ID)
	}

	if loaded.Subject.CommonName != cred.Subject.CommonName {
		t.Errorf("Loaded credential CN mismatch: got %s, want %s", loaded.Subject.CommonName, cred.Subject.CommonName)
	}

	if !store.WasCalled("Save") {
		t.Error("Save should have been called")
	}

	if !store.WasCalled("Load") {
		t.Error("Load should have been called")
	}
}

func TestCredMockStore_LoadNotFound(t *testing.T) {
	store := NewMockStore()

	_, err := store.Load(context.Background(), "nonexistent")
	if err == nil {
		t.Error("Expected error when loading nonexistent credential")
	}
}

func TestCredMockStore_LoadCertificates(t *testing.T) {
	store := NewMockStore()

	subj := Subject{CommonName: "test.example.com"}
	cred := NewCredential("test-cred", subj)
	certs := []*x509.Certificate{
		createCredMockTestCert(t, 1, "test.example.com"),
		createCredMockTestCert(t, 2, "test.example.com"),
	}

	_ = store.Save(context.Background(), cred, certs, nil, nil)

	loaded, err := store.LoadCertificates(context.Background(), "test-cred")
	if err != nil {
		t.Fatalf("LoadCertificates failed: %v", err)
	}

	if len(loaded) != 2 {
		t.Errorf("Expected 2 certificates, got %d", len(loaded))
	}
}

func TestCredMockStore_LoadCertificatesEmpty(t *testing.T) {
	store := NewMockStore()

	certs, err := store.LoadCertificates(context.Background(), "nonexistent")
	if err != nil {
		t.Fatalf("LoadCertificates should not error for missing: %v", err)
	}

	if certs != nil {
		t.Error("Expected nil certificates for nonexistent credential")
	}
}

func TestCredMockStore_List(t *testing.T) {
	store := NewMockStore()

	cred1 := NewCredential("cred-1", Subject{CommonName: "alice.example.com"})
	cred2 := NewCredential("cred-2", Subject{CommonName: "bob.example.com"})
	cred3 := NewCredential("cred-3", Subject{CommonName: "alice-test.example.com"})

	store.AddCredential(cred1)
	store.AddCredential(cred2)
	store.AddCredential(cred3)

	// List all
	ids, err := store.List(context.Background(), "")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if len(ids) != 3 {
		t.Errorf("Expected 3 credentials, got %d", len(ids))
	}

	// List with filter
	ids, err = store.List(context.Background(), "alice")
	if err != nil {
		t.Fatalf("List with filter failed: %v", err)
	}

	if len(ids) != 2 {
		t.Errorf("Expected 2 credentials with 'alice', got %d", len(ids))
	}
}

func TestCredMockStore_ListAll(t *testing.T) {
	store := NewMockStore()

	cred1 := NewCredential("cred-1", Subject{CommonName: "alice"})
	cred2 := NewCredential("cred-2", Subject{CommonName: "bob"})

	store.AddCredential(cred1)
	store.AddCredential(cred2)

	creds, err := store.ListAll(context.Background())
	if err != nil {
		t.Fatalf("ListAll failed: %v", err)
	}

	if len(creds) != 2 {
		t.Errorf("Expected 2 credentials, got %d", len(creds))
	}
}

func TestCredMockStore_UpdateStatus(t *testing.T) {
	store := NewMockStore()

	cred := NewCredential("cred-1", Subject{CommonName: "test"})
	cred.CreateInitialVersion([]string{"ec/tls-server"}, []string{"ec"})
	store.AddCredential(cred)

	err := store.UpdateStatus(context.Background(), "cred-1", StatusRevoked, "compromised")
	if err != nil {
		t.Fatalf("UpdateStatus failed: %v", err)
	}

	loaded, _ := store.Load(context.Background(), "cred-1")
	if loaded.RevokedAt == nil {
		t.Error("Credential should have revocation timestamp")
	}
}

func TestCredMockStore_UpdateStatusNotFound(t *testing.T) {
	store := NewMockStore()

	err := store.UpdateStatus(context.Background(), "nonexistent", StatusRevoked, "test")
	if err == nil {
		t.Error("Expected error when updating nonexistent credential")
	}
}

func TestCredMockStore_Delete(t *testing.T) {
	store := NewMockStore()

	cred := NewCredential("cred-1", Subject{CommonName: "test"})
	certs := []*x509.Certificate{createCredMockTestCert(t, 1, "test")}
	_ = store.Save(context.Background(), cred, certs, nil, nil)

	if !store.Exists(context.Background(), "cred-1") {
		t.Error("Credential should exist before delete")
	}

	err := store.Delete(context.Background(), "cred-1")
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	if store.Exists(context.Background(), "cred-1") {
		t.Error("Credential should not exist after delete")
	}

	// Verify certificates are also deleted
	certs, _ = store.LoadCertificates(context.Background(), "cred-1")
	if certs != nil {
		t.Error("Certificates should be deleted with credential")
	}
}

func TestCredMockStore_Exists(t *testing.T) {
	store := NewMockStore()

	if store.Exists(context.Background(), "nonexistent") {
		t.Error("Nonexistent credential should return false")
	}

	store.AddCredential(NewCredential("exists", Subject{CommonName: "test"}))

	if !store.Exists(context.Background(), "exists") {
		t.Error("Existing credential should return true")
	}
}

func TestCredMockStore_BasePath(t *testing.T) {
	store := NewMockStore()
	store.BasePath_ = "/custom/path"

	if store.BasePath() != "/custom/path" {
		t.Errorf("Unexpected BasePath: %s", store.BasePath())
	}
}

func TestCredMockStore_CallTracking(t *testing.T) {
	store := NewMockStore()

	cred := NewCredential("test", Subject{CommonName: "test"})
	_ = store.Save(context.Background(), cred, nil, nil, nil)
	_, _ = store.Load(context.Background(), "test")
	_, _ = store.Load(context.Background(), "test")
	_ = store.Exists(context.Background(), "test")

	if store.CallCount("Save") != 1 {
		t.Errorf("Expected 1 Save call, got %d", store.CallCount("Save"))
	}

	if store.CallCount("Load") != 2 {
		t.Errorf("Expected 2 Load calls, got %d", store.CallCount("Load"))
	}

	if !store.WasCalled("Exists") {
		t.Error("Exists should have been called")
	}

	if store.WasCalled("Delete") {
		t.Error("Delete should not have been called")
	}
}

func TestCredMockStore_Reset(t *testing.T) {
	store := NewMockStore()

	cred := NewCredential("test", Subject{CommonName: "test"})
	_ = store.Save(context.Background(), cred, nil, nil, nil)
	store.SaveErr = errors.New("some error")

	store.Reset()

	// Check calls first
	if len(store.Calls) != 0 {
		t.Error("Calls should be empty after reset")
	}

	if store.SaveErr != nil {
		t.Error("SaveErr should be nil after reset")
	}

	if len(store.Credentials) != 0 {
		t.Error("Credentials should be empty after reset")
	}
}

func TestCredMockStore_ErrorInjection(t *testing.T) {
	store := NewMockStore()
	testErr := errors.New("injected error")

	tests := []struct {
		name     string
		setError func()
		doCall   func() error
	}{
		{
			name:     "SaveErr",
			setError: func() { store.SaveErr = testErr },
			doCall: func() error {
				return store.Save(context.Background(), NewCredential("x", Subject{}), nil, nil, nil)
			},
		},
		{
			name:     "LoadErr",
			setError: func() { store.LoadErr = testErr },
			doCall: func() error {
				_, err := store.Load(context.Background(), "x")
				return err
			},
		},
		{
			name:     "LoadCertsErr",
			setError: func() { store.LoadCertsErr = testErr },
			doCall: func() error {
				_, err := store.LoadCertificates(context.Background(), "x")
				return err
			},
		},
		{
			name:     "LoadKeysErr",
			setError: func() { store.LoadKeysErr = testErr },
			doCall: func() error {
				_, err := store.LoadKeys(context.Background(), "x", nil)
				return err
			},
		},
		{
			name:     "ListErr",
			setError: func() { store.ListErr = testErr },
			doCall: func() error {
				_, err := store.List(context.Background(), "")
				return err
			},
		},
		{
			name:     "ListAllErr",
			setError: func() { store.ListAllErr = testErr },
			doCall: func() error {
				_, err := store.ListAll(context.Background())
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store.Reset()
			tt.setError()
			err := tt.doCall()
			if err != testErr {
				t.Errorf("Expected injected error, got: %v", err)
			}
		})
	}
}

func TestCredMockStore_ContextCancellation(t *testing.T) {
	store := NewMockStore()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	tests := []struct {
		name   string
		doCall func() error
	}{
		{
			name: "Save",
			doCall: func() error {
				return store.Save(ctx, NewCredential("x", Subject{}), nil, nil, nil)
			},
		},
		{
			name: "Load",
			doCall: func() error {
				_, err := store.Load(ctx, "x")
				return err
			},
		},
		{
			name: "LoadCertificates",
			doCall: func() error {
				_, err := store.LoadCertificates(ctx, "x")
				return err
			},
		},
		{
			name: "LoadKeys",
			doCall: func() error {
				_, err := store.LoadKeys(ctx, "x", nil)
				return err
			},
		},
		{
			name: "List",
			doCall: func() error {
				_, err := store.List(ctx, "")
				return err
			},
		},
		{
			name: "ListAll",
			doCall: func() error {
				_, err := store.ListAll(ctx)
				return err
			},
		},
		{
			name: "UpdateStatus",
			doCall: func() error {
				return store.UpdateStatus(ctx, "x", StatusRevoked, "")
			},
		},
		{
			name: "Delete",
			doCall: func() error {
				return store.Delete(ctx, "x")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.doCall()
			if err != context.Canceled {
				t.Errorf("Expected context.Canceled, got: %v", err)
			}
		})
	}
}

func TestCredMockStore_ExistsWithCancelledContext(t *testing.T) {
	store := NewMockStore()
	store.AddCredential(NewCredential("test", Subject{CommonName: "test"}))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Exists should return false on cancelled context
	if store.Exists(ctx, "test") {
		t.Error("Exists should return false on cancelled context")
	}
}
