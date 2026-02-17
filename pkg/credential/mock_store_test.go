package credential

import (
	"context"
	"crypto/x509"
	"fmt"
	"sync"
	"time"

	pkicrypto "github.com/remiblancher/post-quantum-pki/pkg/crypto"
)

// MockStore implements Store interface for testing without filesystem.
type MockStore struct {
	mu      sync.RWMutex
	callsMu sync.Mutex // Separate mutex for call recording

	// Configuration
	BasePath_ string

	// Storage (active version)
	Credentials  map[string]*Credential         // ID -> credential
	Certificates map[string][]*x509.Certificate // ID -> certs
	Keys         map[string][]pkicrypto.Signer  // ID -> signers

	// Versioned storage: "credID:versionID" -> certs/keys
	VersionedCertificates map[string][]*x509.Certificate
	VersionedKeys         map[string][]pkicrypto.Signer

	// Error injection (global)
	SaveErr             error
	LoadErr             error
	LoadCertsErr        error
	LoadKeysErr         error
	ListErr             error
	ListAllErr          error
	UpdateStatusErr     error
	DeleteErr           error
	ListVersionsErr     error
	LoadCertsVersionErr error
	LoadKeysVersionErr  error

	// Error injection (per-credential/version)
	ListVersionsErrors     map[string]error // credID -> error
	LoadKeysVersionErrors  map[string]error // "credID:versionID" -> error
	LoadCertsVersionErrors map[string]error // "credID:versionID" -> error

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
		BasePath_:              "/mock/credentials",
		Credentials:            make(map[string]*Credential),
		Certificates:           make(map[string][]*x509.Certificate),
		Keys:                   make(map[string][]pkicrypto.Signer),
		VersionedCertificates:  make(map[string][]*x509.Certificate),
		VersionedKeys:          make(map[string][]pkicrypto.Signer),
		ListVersionsErrors:     make(map[string]error),
		LoadKeysVersionErrors:  make(map[string]error),
		LoadCertsVersionErrors: make(map[string]error),
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

// ListVersions returns all version IDs for a credential.
func (m *MockStore) ListVersions(ctx context.Context, credentialID string) ([]string, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	m.recordCall("ListVersions", credentialID)

	// Check per-credential error first
	if err, ok := m.ListVersionsErrors[credentialID]; ok && err != nil {
		return nil, err
	}

	if m.ListVersionsErr != nil {
		return nil, m.ListVersionsErr
	}

	cred, ok := m.Credentials[credentialID]
	if !ok {
		return nil, fmt.Errorf("credential not found: %s", credentialID)
	}

	// Return version IDs from the credential's Versions map
	var versions []string
	for vID := range cred.Versions {
		versions = append(versions, vID)
	}

	if len(versions) == 0 {
		versions = []string{"v1"} // Default to v1 if no versions defined
	}

	return versions, nil
}

// LoadCertificatesForVersion loads certificates from a specific version.
func (m *MockStore) LoadCertificatesForVersion(ctx context.Context, credentialID, versionID string) ([]*x509.Certificate, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	m.recordCall("LoadCertificatesForVersion", credentialID, versionID)

	if m.LoadCertsVersionErr != nil {
		return nil, m.LoadCertsVersionErr
	}

	// Check versioned storage first
	key := credentialID + ":" + versionID
	if certs, ok := m.VersionedCertificates[key]; ok {
		return certs, nil
	}

	// Fall back to active certificates if version matches active
	cred, ok := m.Credentials[credentialID]
	if ok && (cred.Active == versionID || versionID == "v1") {
		return m.Certificates[credentialID], nil
	}

	return nil, nil
}

// LoadKeysForVersion loads private keys from a specific version.
func (m *MockStore) LoadKeysForVersion(ctx context.Context, credentialID, versionID string, passphrase []byte) ([]pkicrypto.Signer, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	m.recordCall("LoadKeysForVersion", credentialID, versionID)

	// Check per-credential/version error first
	key := credentialID + ":" + versionID
	if err, ok := m.LoadKeysVersionErrors[key]; ok && err != nil {
		return nil, err
	}

	if m.LoadKeysVersionErr != nil {
		return nil, m.LoadKeysVersionErr
	}

	// Check versioned storage first
	if keys, ok := m.VersionedKeys[key]; ok {
		return keys, nil
	}

	// Fall back to active keys if version matches active
	cred, ok := m.Credentials[credentialID]
	if ok && (cred.Active == versionID || versionID == "v1") {
		return m.Keys[credentialID], nil
	}

	return nil, nil
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
		// Archive by setting ArchivedAt (status is computed)
		if ver, ok := cred.Versions[cred.Active]; ok {
			now := time.Now()
			ver.ArchivedAt = &now
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
	m.VersionedCertificates = make(map[string][]*x509.Certificate)
	m.VersionedKeys = make(map[string][]pkicrypto.Signer)
	m.Calls = nil

	// Reset global errors
	m.SaveErr = nil
	m.LoadErr = nil
	m.LoadCertsErr = nil
	m.LoadKeysErr = nil
	m.ListErr = nil
	m.ListAllErr = nil
	m.UpdateStatusErr = nil
	m.DeleteErr = nil
	m.ListVersionsErr = nil
	m.LoadCertsVersionErr = nil
	m.LoadKeysVersionErr = nil

	// Reset per-credential/version errors
	m.ListVersionsErrors = make(map[string]error)
	m.LoadKeysVersionErrors = make(map[string]error)
	m.LoadCertsVersionErrors = make(map[string]error)
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

// AddVersionedCertificates adds certificates for a specific version (helper for tests).
func (m *MockStore) AddVersionedCertificates(credentialID, versionID string, certs []*x509.Certificate) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := credentialID + ":" + versionID
	m.VersionedCertificates[key] = certs
}

// AddVersionedKeys adds keys for a specific version (helper for tests).
func (m *MockStore) AddVersionedKeys(credentialID, versionID string, keys []pkicrypto.Signer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := credentialID + ":" + versionID
	m.VersionedKeys[key] = keys
}

// SetListVersionsError sets an error to be returned for ListVersions calls for a specific credential.
func (m *MockStore) SetListVersionsError(credentialID string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ListVersionsErrors[credentialID] = err
}

// SetLoadKeysForVersionError sets an error to be returned for LoadKeysForVersion calls.
func (m *MockStore) SetLoadKeysForVersionError(credentialID, versionID string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := credentialID + ":" + versionID
	m.LoadKeysVersionErrors[key] = err
}

// SetLoadCertsForVersionError sets an error to be returned for LoadCertificatesForVersion calls.
func (m *MockStore) SetLoadCertsForVersionError(credentialID, versionID string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := credentialID + ":" + versionID
	m.LoadCertsVersionErrors[key] = err
}
