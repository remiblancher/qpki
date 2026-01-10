package credential

import (
	"context"
	"crypto/x509"
	"fmt"
	"sync"
	"time"

	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
)

// MockStore implements Store interface for testing without filesystem.
type MockStore struct {
	mu      sync.RWMutex
	callsMu sync.Mutex // Separate mutex for call recording

	// Configuration
	BasePath_ string

	// Storage
	Credentials  map[string]*Credential           // ID -> credential
	Certificates map[string][]*x509.Certificate   // ID -> certs
	Keys         map[string][]pkicrypto.Signer    // ID -> signers

	// Error injection
	SaveErr          error
	LoadErr          error
	LoadCertsErr     error
	LoadKeysErr      error
	ListErr          error
	ListAllErr       error
	UpdateStatusErr  error
	DeleteErr        error

	// Call tracking
	Calls []MockStoreCall
}

// MockStoreCall records a method call for verification.
type MockStoreCall struct {
	Method string
	Args   []interface{}
	Time   time.Time
}

// Compile-time interface check.
var _ Store = (*MockStore)(nil)

// NewMockStore creates a new mock credential store with default values.
func NewMockStore() *MockStore {
	return &MockStore{
		BasePath_:    "/mock/credentials",
		Credentials:  make(map[string]*Credential),
		Certificates: make(map[string][]*x509.Certificate),
		Keys:         make(map[string][]pkicrypto.Signer),
	}
}

// recordCall records a method call for later verification.
func (m *MockStore) recordCall(method string, args ...interface{}) {
	m.callsMu.Lock()
	defer m.callsMu.Unlock()
	m.Calls = append(m.Calls, MockStoreCall{
		Method: method,
		Args:   args,
		Time:   time.Now(),
	})
}

// Save saves a credential with its certificates and keys.
func (m *MockStore) Save(ctx context.Context, cred *Credential, certs []*x509.Certificate, signers []pkicrypto.Signer, passphrase []byte) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.recordCall("Save", cred, certs, signers)

	if m.SaveErr != nil {
		return m.SaveErr
	}

	m.Credentials[cred.ID] = cred
	if len(certs) > 0 {
		m.Certificates[cred.ID] = certs
	}
	if len(signers) > 0 {
		m.Keys[cred.ID] = signers
	}

	return nil
}

// Load loads a credential by ID.
func (m *MockStore) Load(ctx context.Context, credentialID string) (*Credential, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	m.recordCall("Load", credentialID)

	if m.LoadErr != nil {
		return nil, m.LoadErr
	}

	cred, ok := m.Credentials[credentialID]
	if !ok {
		return nil, fmt.Errorf("credential not found: %s", credentialID)
	}

	return cred, nil
}

// LoadCertificates loads the certificates for a credential.
func (m *MockStore) LoadCertificates(ctx context.Context, credentialID string) ([]*x509.Certificate, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	m.recordCall("LoadCertificates", credentialID)

	if m.LoadCertsErr != nil {
		return nil, m.LoadCertsErr
	}

	certs, ok := m.Certificates[credentialID]
	if !ok {
		return nil, nil // No certificates
	}

	return certs, nil
}

// LoadKeys loads the private keys for a credential.
func (m *MockStore) LoadKeys(ctx context.Context, credentialID string, passphrase []byte) ([]pkicrypto.Signer, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	m.recordCall("LoadKeys", credentialID)

	if m.LoadKeysErr != nil {
		return nil, m.LoadKeysErr
	}

	keys, ok := m.Keys[credentialID]
	if !ok {
		return nil, nil // No keys
	}

	return keys, nil
}

// List returns all credential IDs, optionally filtered by subject.
func (m *MockStore) List(ctx context.Context, subjectFilter string) ([]string, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	m.recordCall("List", subjectFilter)

	if m.ListErr != nil {
		return nil, m.ListErr
	}

	var ids []string
	for id, cred := range m.Credentials {
		if subjectFilter == "" || mockContains(cred.Subject.CommonName, subjectFilter) {
			ids = append(ids, id)
		}
	}

	return ids, nil
}

// mockContains checks if s contains substr (case-insensitive).
func mockContains(s, substr string) bool {
	return len(substr) == 0 || (len(s) >= len(substr) && mockContainsIgnoreCase(s, substr))
}

// mockContainsIgnoreCase is a simple case-insensitive contains.
func mockContainsIgnoreCase(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			sc := s[i+j]
			pc := substr[j]
			if sc >= 'A' && sc <= 'Z' {
				sc += 'a' - 'A'
			}
			if pc >= 'A' && pc <= 'Z' {
				pc += 'a' - 'A'
			}
			if sc != pc {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// ListAll returns all credentials.
func (m *MockStore) ListAll(ctx context.Context) ([]*Credential, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	m.recordCall("ListAll")

	if m.ListAllErr != nil {
		return nil, m.ListAllErr
	}

	var creds []*Credential
	for _, cred := range m.Credentials {
		creds = append(creds, cred)
	}

	return creds, nil
}

// UpdateStatus updates the status of a credential.
func (m *MockStore) UpdateStatus(ctx context.Context, credentialID string, status Status, reason string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.recordCall("UpdateStatus", credentialID, status, reason)

	if m.UpdateStatusErr != nil {
		return m.UpdateStatusErr
	}

	cred, ok := m.Credentials[credentialID]
	if !ok {
		return fmt.Errorf("credential not found: %s", credentialID)
	}

	switch status {
	case StatusRevoked:
		cred.Revoke(reason)
	case StatusExpired, StatusArchived:
		if ver, ok := cred.Versions[cred.Active]; ok {
			ver.Status = string(status)
			cred.Versions[cred.Active] = ver
		}
	}

	return nil
}

// Delete deletes a credential.
func (m *MockStore) Delete(ctx context.Context, credentialID string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.recordCall("Delete", credentialID)

	if m.DeleteErr != nil {
		return m.DeleteErr
	}

	delete(m.Credentials, credentialID)
	delete(m.Certificates, credentialID)
	delete(m.Keys, credentialID)

	return nil
}

// Exists checks if a credential exists.
func (m *MockStore) Exists(ctx context.Context, credentialID string) bool {
	select {
	case <-ctx.Done():
		return false
	default:
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	m.recordCall("Exists", credentialID)

	_, ok := m.Credentials[credentialID]
	return ok
}

// BasePath returns the credentials directory path.
func (m *MockStore) BasePath() string {
	m.recordCall("BasePath")
	return m.BasePath_
}

// Helper methods for test verification

// GetCalls returns all recorded calls.
func (m *MockStore) GetCalls() []MockStoreCall {
	m.callsMu.Lock()
	defer m.callsMu.Unlock()

	result := make([]MockStoreCall, len(m.Calls))
	copy(result, m.Calls)
	return result
}

// GetCallsForMethod returns all calls for a specific method.
func (m *MockStore) GetCallsForMethod(method string) []MockStoreCall {
	m.callsMu.Lock()
	defer m.callsMu.Unlock()

	var result []MockStoreCall
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
	m.callsMu.Lock()
	defer m.mu.Unlock()
	defer m.callsMu.Unlock()

	m.Credentials = make(map[string]*Credential)
	m.Certificates = make(map[string][]*x509.Certificate)
	m.Keys = make(map[string][]pkicrypto.Signer)
	m.Calls = nil

	// Reset errors
	m.SaveErr = nil
	m.LoadErr = nil
	m.LoadCertsErr = nil
	m.LoadKeysErr = nil
	m.ListErr = nil
	m.ListAllErr = nil
	m.UpdateStatusErr = nil
	m.DeleteErr = nil
}

// AddCredential adds a credential directly to the mock store (helper for tests).
func (m *MockStore) AddCredential(cred *Credential) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Credentials[cred.ID] = cred
}

// AddCertificates adds certificates for a credential (helper for tests).
func (m *MockStore) AddCertificates(credentialID string, certs []*x509.Certificate) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Certificates[credentialID] = certs
}

// AddKeys adds keys for a credential (helper for tests).
func (m *MockStore) AddKeys(credentialID string, keys []pkicrypto.Signer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Keys[credentialID] = keys
}
