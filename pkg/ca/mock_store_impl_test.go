package ca

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

// createMockTestCert creates a test certificate for mock store testing.
func createMockTestCert(t *testing.T, serial int64, cn string) *x509.Certificate {
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

func TestU_CA_MockStore_Init(t *testing.T) {
	store := NewMockStore()

	if store.Exists() {
		t.Error("Store should not exist before Init")
	}

	err := store.Init(context.Background())
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	if !store.Exists() {
		t.Error("Store should exist after Init")
	}

	if !store.Initialized {
		t.Error("Initialized flag should be true")
	}

	if !store.WasCalled("Init") {
		t.Error("Init should be recorded in calls")
	}
}

func TestU_CA_MockStore_InitWithError(t *testing.T) {
	store := NewMockStore()
	store.InitErr = errors.New("init failed")

	err := store.Init(context.Background())
	if err == nil {
		t.Error("Expected error from Init")
	}

	if store.Initialized {
		t.Error("Store should not be initialized on error")
	}
}

func TestU_CA_MockStore_InitWithCancelledContext(t *testing.T) {
	store := NewMockStore()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := store.Init(ctx)
	if err != context.Canceled {
		t.Errorf("Expected context.Canceled, got: %v", err)
	}
}

func TestU_CA_MockStore_SaveAndLoadCACert(t *testing.T) {
	store := NewMockStore()
	cert := createMockTestCert(t, 1, "Test CA")

	err := store.SaveCACert(context.Background(), cert)
	if err != nil {
		t.Fatalf("SaveCACert failed: %v", err)
	}

	loaded, err := store.LoadCACert(context.Background())
	if err != nil {
		t.Fatalf("LoadCACert failed: %v", err)
	}

	if loaded.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Error("Loaded certificate serial does not match")
	}
}

func TestU_CA_MockStore_LoadCACertNotFound(t *testing.T) {
	store := NewMockStore()

	_, err := store.LoadCACert(context.Background())
	if err == nil {
		t.Error("Expected error when CA cert not found")
	}
}

func TestU_CA_MockStore_SaveAndLoadCert(t *testing.T) {
	store := NewMockStore()
	cert := createMockTestCert(t, 42, "Test Cert")

	err := store.SaveCert(context.Background(), cert)
	if err != nil {
		t.Fatalf("SaveCert failed: %v", err)
	}

	loaded, err := store.LoadCert(context.Background(), cert.SerialNumber.Bytes())
	if err != nil {
		t.Fatalf("LoadCert failed: %v", err)
	}

	if loaded.Subject.CommonName != cert.Subject.CommonName {
		t.Error("Loaded certificate CN does not match")
	}

	// Verify index was updated
	index, err := store.ReadIndex(context.Background())
	if err != nil {
		t.Fatalf("ReadIndex failed: %v", err)
	}

	if len(index) != 1 {
		t.Fatalf("Expected 1 index entry, got %d", len(index))
	}

	if index[0].Status != "V" {
		t.Errorf("Expected status V, got %s", index[0].Status)
	}
}

func TestU_CA_MockStore_LoadCertNotFound(t *testing.T) {
	store := NewMockStore()

	_, err := store.LoadCert(context.Background(), []byte{0x99})
	if err == nil {
		t.Error("Expected error when cert not found")
	}
}

func TestU_CA_MockStore_NextSerial(t *testing.T) {
	store := NewMockStore()
	store.Serial = []byte{0x10}

	serial1, err := store.NextSerial(context.Background())
	if err != nil {
		t.Fatalf("NextSerial failed: %v", err)
	}

	if serial1[0] != 0x10 {
		t.Errorf("Expected 0x10, got 0x%x", serial1[0])
	}

	serial2, err := store.NextSerial(context.Background())
	if err != nil {
		t.Fatalf("NextSerial failed: %v", err)
	}

	if serial2[0] != 0x11 {
		t.Errorf("Expected 0x11, got 0x%x", serial2[0])
	}
}

func TestU_CA_MockStore_MarkRevoked(t *testing.T) {
	store := NewMockStore()
	cert := createMockTestCert(t, 100, "To Revoke")

	err := store.SaveCert(context.Background(), cert)
	if err != nil {
		t.Fatalf("SaveCert failed: %v", err)
	}

	err = store.MarkRevoked(context.Background(), cert.SerialNumber.Bytes(), ReasonKeyCompromise)
	if err != nil {
		t.Fatalf("MarkRevoked failed: %v", err)
	}

	index, err := store.ReadIndex(context.Background())
	if err != nil {
		t.Fatalf("ReadIndex failed: %v", err)
	}

	if index[0].Status != "R" {
		t.Errorf("Expected status R, got %s", index[0].Status)
	}
}

func TestU_CA_MockStore_MarkRevokedNotFound(t *testing.T) {
	store := NewMockStore()

	err := store.MarkRevoked(context.Background(), []byte{0x99}, ReasonUnspecified)
	if err == nil {
		t.Error("Expected error when cert not in index")
	}
}

func TestU_CA_MockStore_CRL(t *testing.T) {
	store := NewMockStore()
	crlData := []byte("mock CRL data")

	err := store.SaveCRL(context.Background(), crlData)
	if err != nil {
		t.Fatalf("SaveCRL failed: %v", err)
	}

	if string(store.CRLs["default"]) != string(crlData) {
		t.Error("CRL data not saved correctly")
	}

	// Test algorithm-specific CRL
	err = store.SaveCRLForAlgorithm(context.Background(), crlData, "ml-dsa-65")
	if err != nil {
		t.Fatalf("SaveCRLForAlgorithm failed: %v", err)
	}

	if string(store.CRLs["ml-dsa-65"]) != string(crlData) {
		t.Error("Algorithm CRL not saved correctly")
	}
}

func TestU_CA_MockStore_NextCRLNumber(t *testing.T) {
	store := NewMockStore()
	store.CRLNumber = []byte{0x05}

	crl1, err := store.NextCRLNumber(context.Background())
	if err != nil {
		t.Fatalf("NextCRLNumber failed: %v", err)
	}

	if crl1[0] != 0x05 {
		t.Errorf("Expected 0x05, got 0x%x", crl1[0])
	}

	crl2, err := store.NextCRLNumber(context.Background())
	if err != nil {
		t.Fatalf("NextCRLNumber failed: %v", err)
	}

	if crl2[0] != 0x06 {
		t.Errorf("Expected 0x06, got 0x%x", crl2[0])
	}
}

func TestU_CA_MockStore_Paths(t *testing.T) {
	store := NewMockStore()
	store.BasePath_ = "/test/ca"

	if store.BasePath() != "/test/ca" {
		t.Errorf("Unexpected BasePath: %s", store.BasePath())
	}

	if store.CACertPath() != "/test/ca/ca.crt" {
		t.Errorf("Unexpected CACertPath: %s", store.CACertPath())
	}

	if store.CAKeyPath() != "/test/ca/private/ca.key" {
		t.Errorf("Unexpected CAKeyPath: %s", store.CAKeyPath())
	}

	if store.CertPath([]byte{0x01}) != "/test/ca/certs/01.crt" {
		t.Errorf("Unexpected CertPath: %s", store.CertPath([]byte{0x01}))
	}
}

func TestU_CA_MockStore_CallTracking(t *testing.T) {
	store := NewMockStore()

	_ = store.Init(context.Background())
	_ = store.Exists()
	_ = store.BasePath()
	_, _ = store.NextSerial(context.Background())
	_, _ = store.NextSerial(context.Background())

	if store.CallCount("Init") != 1 {
		t.Errorf("Expected 1 Init call, got %d", store.CallCount("Init"))
	}

	if store.CallCount("NextSerial") != 2 {
		t.Errorf("Expected 2 NextSerial calls, got %d", store.CallCount("NextSerial"))
	}

	if !store.WasCalled("Exists") {
		t.Error("Exists should have been called")
	}

	if store.WasCalled("LoadCACert") {
		t.Error("LoadCACert should not have been called")
	}
}

func TestU_CA_MockStore_Reset(t *testing.T) {
	store := NewMockStore()
	cert := createMockTestCert(t, 1, "Test")

	_ = store.Init(context.Background())
	_ = store.SaveCACert(context.Background(), cert)
	store.InitErr = errors.New("some error")

	store.Reset()

	// Check calls first, before making any new calls
	if len(store.Calls) != 0 {
		t.Error("Calls should be empty after reset")
	}

	if store.InitErr != nil {
		t.Error("InitErr should be nil after reset")
	}

	if store.CACert != nil {
		t.Error("CACert should be nil after reset")
	}

	// This will add a call, so check it last
	if store.Exists() {
		t.Error("Store should not exist after reset")
	}
}

func TestU_CA_MockStore_ErrorInjection(t *testing.T) {
	store := NewMockStore()
	testErr := errors.New("injected error")

	tests := []struct {
		name     string
		setError func()
		doCall   func() error
	}{
		{
			name:     "SaveCACertErr",
			setError: func() { store.SaveCACertErr = testErr },
			doCall: func() error {
				return store.SaveCACert(context.Background(), createMockTestCert(t, 1, "Test"))
			},
		},
		{
			name:     "LoadCACertErr",
			setError: func() { store.LoadCACertErr = testErr },
			doCall: func() error {
				_, err := store.LoadCACert(context.Background())
				return err
			},
		},
		{
			name:     "SaveCertErr",
			setError: func() { store.SaveCertErr = testErr },
			doCall: func() error {
				return store.SaveCert(context.Background(), createMockTestCert(t, 1, "Test"))
			},
		},
		{
			name:     "NextSerialErr",
			setError: func() { store.NextSerialErr = testErr },
			doCall: func() error {
				_, err := store.NextSerial(context.Background())
				return err
			},
		},
		{
			name:     "ReadIndexErr",
			setError: func() { store.ReadIndexErr = testErr },
			doCall: func() error {
				_, err := store.ReadIndex(context.Background())
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

func TestU_CA_MockStore_ContextCancellation(t *testing.T) {
	store := NewMockStore()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	tests := []struct {
		name   string
		doCall func() error
	}{
		{
			name: "Init",
			doCall: func() error {
				return store.Init(ctx)
			},
		},
		{
			name: "SaveCACert",
			doCall: func() error {
				return store.SaveCACert(ctx, createMockTestCert(t, 1, "Test"))
			},
		},
		{
			name: "LoadCACert",
			doCall: func() error {
				_, err := store.LoadCACert(ctx)
				return err
			},
		},
		{
			name: "SaveCert",
			doCall: func() error {
				return store.SaveCert(ctx, createMockTestCert(t, 1, "Test"))
			},
		},
		{
			name: "LoadCert",
			doCall: func() error {
				_, err := store.LoadCert(ctx, []byte{0x01})
				return err
			},
		},
		{
			name: "NextSerial",
			doCall: func() error {
				_, err := store.NextSerial(ctx)
				return err
			},
		},
		{
			name: "ReadIndex",
			doCall: func() error {
				_, err := store.ReadIndex(ctx)
				return err
			},
		},
		{
			name: "MarkRevoked",
			doCall: func() error {
				return store.MarkRevoked(ctx, []byte{0x01}, ReasonUnspecified)
			},
		},
		{
			name: "NextCRLNumber",
			doCall: func() error {
				_, err := store.NextCRLNumber(ctx)
				return err
			},
		},
		{
			name: "SaveCRL",
			doCall: func() error {
				return store.SaveCRL(ctx, []byte{})
			},
		},
		{
			name: "SaveCRLForAlgorithm",
			doCall: func() error {
				return store.SaveCRLForAlgorithm(ctx, []byte{}, "ml-dsa-65")
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
