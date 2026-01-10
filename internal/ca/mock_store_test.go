package ca

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// MockStore implements Store interface for testing without filesystem.
type MockStore struct {
	mu sync.RWMutex

	// Configuration
	BasePath_ string

	// Storage
	CACert         *x509.Certificate
	AllCACerts     []*x509.Certificate
	CrossSignCerts []*x509.Certificate
	Certs          map[string]*x509.Certificate // serial hex -> cert
	Index          []IndexEntry
	Serial         []byte
	CRLNumber      []byte
	CRLs           map[string][]byte // algorithm -> CRL DER

	// Behavior controls
	Initialized bool
	Exists_     bool

	// Error injection
	InitErr              error
	SaveCACertErr        error
	LoadCACertErr        error
	LoadAllCACertsErr    error
	LoadCrossSignedErr   error
	SaveCertErr          error
	SaveCertAtErr        error
	LoadCertErr          error
	NextSerialErr        error
	ReadIndexErr         error
	MarkRevokedErr       error
	NextCRLNumberErr     error
	SaveCRLErr           error
	SaveCRLForAlgoErr    error

	// Call tracking
	Calls []MockCall
}

// MockCall records a method call for verification.
type MockCall struct {
	Method string
	Args   []interface{}
	Time   time.Time
}

// Compile-time interface check.
var _ Store = (*MockStore)(nil)

// NewMockStore creates a new mock store with default values.
func NewMockStore() *MockStore {
	return &MockStore{
		BasePath_: "/mock/ca",
		Certs:     make(map[string]*x509.Certificate),
		CRLs:      make(map[string][]byte),
		Serial:    []byte{0x01},
		CRLNumber: []byte{0x01},
		Exists_:   false,
	}
}

// recordCall records a method call for later verification.
func (m *MockStore) recordCall(method string, args ...interface{}) {
	m.Calls = append(m.Calls, MockCall{
		Method: method,
		Args:   args,
		Time:   time.Now(),
	})
}

// Init initializes the mock store.
func (m *MockStore) Init(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.recordCall("Init")

	if m.InitErr != nil {
		return m.InitErr
	}

	m.Initialized = true
	m.Exists_ = true
	return nil
}

// Exists checks if the store is initialized.
func (m *MockStore) Exists() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	m.recordCall("Exists")
	return m.Exists_
}

// BasePath returns the mock base path.
func (m *MockStore) BasePath() string {
	m.recordCall("BasePath")
	return m.BasePath_
}

// SaveCACert saves the CA certificate.
func (m *MockStore) SaveCACert(ctx context.Context, cert *x509.Certificate) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.recordCall("SaveCACert", cert)

	if m.SaveCACertErr != nil {
		return m.SaveCACertErr
	}

	m.CACert = cert
	m.Exists_ = true
	return nil
}

// LoadCACert loads the CA certificate.
func (m *MockStore) LoadCACert(ctx context.Context) (*x509.Certificate, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	m.recordCall("LoadCACert")

	if m.LoadCACertErr != nil {
		return nil, m.LoadCACertErr
	}

	if m.CACert == nil {
		return nil, fmt.Errorf("CA certificate not found")
	}

	return m.CACert, nil
}

// LoadAllCACerts loads all CA certificates.
func (m *MockStore) LoadAllCACerts(ctx context.Context) ([]*x509.Certificate, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	m.recordCall("LoadAllCACerts")

	if m.LoadAllCACertsErr != nil {
		return nil, m.LoadAllCACertsErr
	}

	if len(m.AllCACerts) > 0 {
		return m.AllCACerts, nil
	}

	if m.CACert != nil {
		return []*x509.Certificate{m.CACert}, nil
	}

	return nil, nil
}

// LoadCrossSignedCerts loads cross-signed certificates.
func (m *MockStore) LoadCrossSignedCerts(ctx context.Context) ([]*x509.Certificate, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	m.recordCall("LoadCrossSignedCerts")

	if m.LoadCrossSignedErr != nil {
		return nil, m.LoadCrossSignedErr
	}

	return m.CrossSignCerts, nil
}

// SaveCert saves an issued certificate.
func (m *MockStore) SaveCert(ctx context.Context, cert *x509.Certificate) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.recordCall("SaveCert", cert)

	if m.SaveCertErr != nil {
		return m.SaveCertErr
	}

	serialHex := hex.EncodeToString(cert.SerialNumber.Bytes())
	m.Certs[serialHex] = cert

	// Add to index
	m.Index = append(m.Index, IndexEntry{
		Status:  "V",
		Expiry:  cert.NotAfter,
		Serial:  cert.SerialNumber.Bytes(),
		Subject: cert.Subject.String(),
	})

	return nil
}

// SaveCertAt saves a certificate at a specific path (ignored in mock).
func (m *MockStore) SaveCertAt(ctx context.Context, path string, cert *x509.Certificate) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.recordCall("SaveCertAt", path, cert)

	if m.SaveCertAtErr != nil {
		return m.SaveCertAtErr
	}

	serialHex := hex.EncodeToString(cert.SerialNumber.Bytes())
	m.Certs[serialHex] = cert

	return nil
}

// LoadCert loads a certificate by serial number.
func (m *MockStore) LoadCert(ctx context.Context, serial []byte) (*x509.Certificate, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	m.recordCall("LoadCert", serial)

	if m.LoadCertErr != nil {
		return nil, m.LoadCertErr
	}

	serialHex := hex.EncodeToString(serial)
	cert, ok := m.Certs[serialHex]
	if !ok {
		return nil, fmt.Errorf("certificate not found: %s", serialHex)
	}

	return cert, nil
}

// CACertPath returns a mock CA certificate path.
func (m *MockStore) CACertPath() string {
	m.recordCall("CACertPath")
	return m.BasePath_ + "/ca.crt"
}

// CAKeyPath returns a mock CA key path.
func (m *MockStore) CAKeyPath() string {
	m.recordCall("CAKeyPath")
	return m.BasePath_ + "/private/ca.key"
}

// CertPath returns a mock certificate path for a serial.
func (m *MockStore) CertPath(serial []byte) string {
	m.recordCall("CertPath", serial)
	return m.BasePath_ + "/certs/" + hex.EncodeToString(serial) + ".crt"
}

// NextSerial returns the next serial number.
func (m *MockStore) NextSerial(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.recordCall("NextSerial")

	if m.NextSerialErr != nil {
		return nil, m.NextSerialErr
	}

	current := make([]byte, len(m.Serial))
	copy(current, m.Serial)

	// Increment serial for next call
	m.Serial = incrementSerial(m.Serial)

	return current, nil
}

// ReadIndex reads all index entries.
func (m *MockStore) ReadIndex(ctx context.Context) ([]IndexEntry, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	m.recordCall("ReadIndex")

	if m.ReadIndexErr != nil {
		return nil, m.ReadIndexErr
	}

	// Return a copy to avoid mutation
	result := make([]IndexEntry, len(m.Index))
	copy(result, m.Index)
	return result, nil
}

// MarkRevoked marks a certificate as revoked.
func (m *MockStore) MarkRevoked(ctx context.Context, serial []byte, reason RevocationReason) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.recordCall("MarkRevoked", serial, reason)

	if m.MarkRevokedErr != nil {
		return m.MarkRevokedErr
	}

	serialHex := hex.EncodeToString(serial)

	// Update index entry
	for i := range m.Index {
		if hex.EncodeToString(m.Index[i].Serial) == serialHex {
			m.Index[i].Status = "R"
			m.Index[i].Revocation = time.Now()
			return nil
		}
	}

	return fmt.Errorf("certificate not found in index: %s", serialHex)
}

// NextCRLNumber returns the next CRL number.
func (m *MockStore) NextCRLNumber(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.recordCall("NextCRLNumber")

	if m.NextCRLNumberErr != nil {
		return nil, m.NextCRLNumberErr
	}

	current := make([]byte, len(m.CRLNumber))
	copy(current, m.CRLNumber)

	// Increment for next call
	m.CRLNumber = incrementSerial(m.CRLNumber)

	return current, nil
}

// SaveCRL saves a CRL.
func (m *MockStore) SaveCRL(ctx context.Context, crlDER []byte) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.recordCall("SaveCRL", crlDER)

	if m.SaveCRLErr != nil {
		return m.SaveCRLErr
	}

	m.CRLs["default"] = crlDER
	return nil
}

// SaveCRLForAlgorithm saves a CRL for a specific algorithm.
func (m *MockStore) SaveCRLForAlgorithm(ctx context.Context, crlDER []byte, algorithm string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.recordCall("SaveCRLForAlgorithm", crlDER, algorithm)

	if m.SaveCRLForAlgoErr != nil {
		return m.SaveCRLForAlgoErr
	}

	m.CRLs[algorithm] = crlDER
	return nil
}

// Helper methods for test verification

// GetCalls returns all recorded calls.
func (m *MockStore) GetCalls() []MockCall {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]MockCall, len(m.Calls))
	copy(result, m.Calls)
	return result
}

// GetCallsForMethod returns all calls for a specific method.
func (m *MockStore) GetCallsForMethod(method string) []MockCall {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []MockCall
	for _, call := range m.Calls {
		if call.Method == method {
			result = append(result, call)
		}
	}
	return result
}

// WasCalled checks if a method was called.
func (m *MockStore) WasCalled(method string) bool {
	return len(m.GetCallsForMethod(method)) > 0
}

// CallCount returns how many times a method was called.
func (m *MockStore) CallCount(method string) int {
	return len(m.GetCallsForMethod(method))
}

// Reset clears all stored data and call history.
func (m *MockStore) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.CACert = nil
	m.AllCACerts = nil
	m.CrossSignCerts = nil
	m.Certs = make(map[string]*x509.Certificate)
	m.Index = nil
	m.Serial = []byte{0x01}
	m.CRLNumber = []byte{0x01}
	m.CRLs = make(map[string][]byte)
	m.Initialized = false
	m.Exists_ = false
	m.Calls = nil

	// Reset errors
	m.InitErr = nil
	m.SaveCACertErr = nil
	m.LoadCACertErr = nil
	m.LoadAllCACertsErr = nil
	m.LoadCrossSignedErr = nil
	m.SaveCertErr = nil
	m.SaveCertAtErr = nil
	m.LoadCertErr = nil
	m.NextSerialErr = nil
	m.ReadIndexErr = nil
	m.MarkRevokedErr = nil
	m.NextCRLNumberErr = nil
	m.SaveCRLErr = nil
	m.SaveCRLForAlgoErr = nil
}
