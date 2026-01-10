package credential

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
)

// Store manages credential persistence.
type Store interface {
	// Save saves a credential with its certificates and keys.
	Save(ctx context.Context, cred *Credential, certs []*x509.Certificate, signers []pkicrypto.Signer, passphrase []byte) error

	// Load loads a credential by ID.
	Load(ctx context.Context, credentialID string) (*Credential, error)

	// LoadCertificates loads the certificates for a credential.
	LoadCertificates(ctx context.Context, credentialID string) ([]*x509.Certificate, error)

	// LoadKeys loads the private keys for a credential.
	LoadKeys(ctx context.Context, credentialID string, passphrase []byte) ([]pkicrypto.Signer, error)

	// List returns all credential IDs, optionally filtered by subject.
	List(ctx context.Context, subjectFilter string) ([]string, error)

	// ListAll returns all credentials.
	ListAll(ctx context.Context) ([]*Credential, error)

	// UpdateStatus updates the status of a credential.
	UpdateStatus(ctx context.Context, credentialID string, status Status, reason string) error

	// Delete deletes a credential.
	Delete(ctx context.Context, credentialID string) error

	// Exists checks if a credential exists.
	Exists(ctx context.Context, credentialID string) bool

	// BasePath returns the credentials directory path.
	BasePath() string
}

// FileStore implements Store using the filesystem.
// Credential layout:
//
//	{basePath}/{credentialID}/
//	    credential.meta.json     # Metadata
//	    certificates.pem         # All certificates
//	    private-keys.pem         # All private keys (encrypted)
type FileStore struct {
	basePath string
	mu       sync.RWMutex
}

// NewFileStore creates a new file-based credential store.
// The credentialsPath parameter is the directory where credentials are stored directly.
func NewFileStore(credentialsPath string) *FileStore {
	return &FileStore{
		basePath: credentialsPath,
	}
}

// credentialPath returns the path to a credential directory.
func (s *FileStore) credentialPath(credentialID string) string {
	return filepath.Join(s.basePath, credentialID)
}


// metadataPath returns the path to the credential metadata file.
func (s *FileStore) metadataPath(credentialID string) string {
	return filepath.Join(s.credentialPath(credentialID), "credential.meta.json")
}

// certsPath returns the path to the certificates PEM file.
// For versioned credentials, this returns the path in active/ directory.
func (s *FileStore) certsPath(credentialID string) string {
	vs := NewVersionStore(s.credentialPath(credentialID))
	if vs.IsVersioned() {
		// Read from active/ directory for versioned credentials
		return filepath.Join(vs.ActiveDir(), "certificates.pem")
	}
	// Legacy path for non-versioned credentials
	return filepath.Join(s.credentialPath(credentialID), "certificates.pem")
}

// keysPath returns the path to the private keys PEM file.
// For versioned credentials, this returns the path in active/ directory.
func (s *FileStore) keysPath(credentialID string) string {
	vs := NewVersionStore(s.credentialPath(credentialID))
	if vs.IsVersioned() {
		// Read from active/ directory for versioned credentials
		return filepath.Join(vs.ActiveDir(), "private-keys.pem")
	}
	// Legacy path for non-versioned credentials
	return filepath.Join(s.credentialPath(credentialID), "private-keys.pem")
}

// Save saves a credential with its certificates and keys.
func (s *FileStore) Save(ctx context.Context, cred *Credential, certs []*x509.Certificate, signers []pkicrypto.Signer, passphrase []byte) error {
	// Check for cancellation before acquiring lock
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	credDir := s.credentialPath(cred.ID)

	// Create credential directory
	if err := os.MkdirAll(credDir, 0700); err != nil {
		return fmt.Errorf("failed to create credential directory: %w", err)
	}

	// Check for cancellation before metadata write
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Save metadata
	metaData, err := json.MarshalIndent(cred, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal credential metadata: %w", err)
	}

	if err := os.WriteFile(s.metadataPath(cred.ID), metaData, 0644); err != nil {
		return fmt.Errorf("failed to write credential metadata: %w", err)
	}

	// Save certificates
	if len(certs) > 0 {
		// Check for cancellation before certificate write
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		certsPEM, err := EncodeCertificatesPEM(certs)
		if err != nil {
			return fmt.Errorf("failed to encode certificates: %w", err)
		}

		if err := os.WriteFile(s.certsPath(cred.ID), certsPEM, 0644); err != nil {
			return fmt.Errorf("failed to write certificates: %w", err)
		}
	}

	// Save private keys (encrypted)
	// Note: Only software keys are saved; HSM keys are stored in the HSM and
	// referenced via storage refs in the credential metadata.
	if len(signers) > 0 {
		// Check for cancellation before key write
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		keysPEM, err := EncodePrivateKeysPEM(signers, passphrase)
		if err != nil {
			return fmt.Errorf("failed to encode private keys: %w", err)
		}

		// Only write the file if there are software keys to save
		if len(keysPEM) > 0 {
			if err := os.WriteFile(s.keysPath(cred.ID), keysPEM, 0600); err != nil {
				return fmt.Errorf("failed to write private keys: %w", err)
			}
		}
	}

	return nil
}

// Load loads a credential by ID.
func (s *FileStore) Load(ctx context.Context, credentialID string) (*Credential, error) {
	// Check for cancellation before acquiring lock
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	metaPath := s.metadataPath(credentialID)

	data, err := os.ReadFile(metaPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("credential not found: %s", credentialID)
		}
		return nil, fmt.Errorf("failed to read credential metadata: %w", err)
	}

	var cred Credential
	if err := json.Unmarshal(data, &cred); err != nil {
		return nil, fmt.Errorf("failed to parse credential metadata: %w", err)
	}

	cred.basePath = s.credentialPath(credentialID)
	return &cred, nil
}

// LoadCertificates loads the certificates for a credential.
// For versioned credentials, this loads from active/ directory.
func (s *FileStore) LoadCertificates(ctx context.Context, credentialID string) ([]*x509.Certificate, error) {
	// Check for cancellation before acquiring lock
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	vs := NewVersionStore(s.credentialPath(credentialID))

	// For versioned credentials, load from all algorithm families in active/
	if vs.IsVersioned() {
		return s.loadActiveCertificatesUnlocked(credentialID)
	}

	// Legacy: load from root
	certsPath := s.certsPath(credentialID)
	data, err := os.ReadFile(certsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No certificates
		}
		return nil, fmt.Errorf("failed to read certificates: %w", err)
	}

	return DecodeCertificatesPEM(data)
}

// loadActiveCertificatesUnlocked loads all certificates from active/ directory.
func (s *FileStore) loadActiveCertificatesUnlocked(credentialID string) ([]*x509.Certificate, error) {
	vs := NewVersionStore(s.credentialPath(credentialID))
	activeDir := vs.ActiveDir()

	entries, err := os.ReadDir(activeDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read active directory: %w", err)
	}

	var allCerts []*x509.Certificate
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		algoFamily := entry.Name()
		certPath := filepath.Join(activeDir, algoFamily, "certificates.pem")

		data, err := os.ReadFile(certPath)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("failed to read certificates for %s: %w", algoFamily, err)
		}

		certs, err := DecodeCertificatesPEM(data)
		if err != nil {
			return nil, fmt.Errorf("failed to decode certificates for %s: %w", algoFamily, err)
		}

		allCerts = append(allCerts, certs...)
	}

	return allCerts, nil
}

// LoadKeys loads the private keys for a credential.
// For versioned credentials, this loads from active/ directory.
func (s *FileStore) LoadKeys(ctx context.Context, credentialID string, passphrase []byte) ([]pkicrypto.Signer, error) {
	// Check for cancellation before acquiring lock
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	vs := NewVersionStore(s.credentialPath(credentialID))

	// For versioned credentials, load from all algorithm families in active/
	if vs.IsVersioned() {
		return s.loadActiveKeysUnlocked(credentialID, passphrase)
	}

	// Legacy: load from root
	keysPath := s.keysPath(credentialID)
	data, err := os.ReadFile(keysPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No keys
		}
		return nil, fmt.Errorf("failed to read private keys: %w", err)
	}

	return DecodePrivateKeysPEM(data, passphrase)
}

// loadActiveKeysUnlocked loads all private keys from active/ directory.
func (s *FileStore) loadActiveKeysUnlocked(credentialID string, passphrase []byte) ([]pkicrypto.Signer, error) {
	vs := NewVersionStore(s.credentialPath(credentialID))
	activeDir := vs.ActiveDir()

	entries, err := os.ReadDir(activeDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read active directory: %w", err)
	}

	var allSigners []pkicrypto.Signer
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		algoFamily := entry.Name()
		keyPath := filepath.Join(activeDir, algoFamily, "private-keys.pem")

		data, err := os.ReadFile(keyPath)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("failed to read private keys for %s: %w", algoFamily, err)
		}

		signers, err := DecodePrivateKeysPEM(data, passphrase)
		if err != nil {
			return nil, fmt.Errorf("failed to decode private keys for %s: %w", algoFamily, err)
		}

		allSigners = append(allSigners, signers...)
	}

	return allSigners, nil
}

// List returns all credential IDs, optionally filtered by subject.
func (s *FileStore) List(ctx context.Context, subjectFilter string) ([]string, error) {
	// Check for cancellation before acquiring lock
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	entries, err := os.ReadDir(s.basePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read credentials directory: %w", err)
	}

	var ids []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		credentialID := entry.Name()

		// If filter provided, load credential and check subject
		if subjectFilter != "" {
			cred, err := s.loadUnlocked(credentialID)
			if err != nil {
				continue
			}

			if !strings.Contains(strings.ToLower(cred.Subject.CommonName), strings.ToLower(subjectFilter)) {
				continue
			}
		}

		ids = append(ids, credentialID)
	}

	sort.Strings(ids)
	return ids, nil
}

// loadUnlocked loads a credential without locking (for internal use).
func (s *FileStore) loadUnlocked(credentialID string) (*Credential, error) {
	metaPath := s.metadataPath(credentialID)

	data, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, err
	}

	var cred Credential
	if err := json.Unmarshal(data, &cred); err != nil {
		return nil, err
	}

	cred.basePath = s.credentialPath(credentialID)
	return &cred, nil
}

// ListAll returns all credentials.
func (s *FileStore) ListAll(ctx context.Context) ([]*Credential, error) {
	// Check for cancellation before acquiring lock
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	entries, err := os.ReadDir(s.basePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read credentials directory: %w", err)
	}

	var credentials []*Credential
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		cred, err := s.loadUnlocked(entry.Name())
		if err != nil {
			continue
		}

		credentials = append(credentials, cred)
	}

	return credentials, nil
}

// UpdateStatus updates the status of a credential.
func (s *FileStore) UpdateStatus(ctx context.Context, credentialID string, status Status, reason string) error {
	// Check for cancellation before acquiring lock
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	cred, err := s.loadUnlocked(credentialID)
	if err != nil {
		return fmt.Errorf("failed to load credential: %w", err)
	}

	switch status {
	case StatusRevoked:
		cred.Revoke(reason)
	case StatusExpired, StatusArchived:
		// Archive the active version
		if ver, ok := cred.Versions[cred.Active]; ok {
			ver.Status = string(status)
			cred.Versions[cred.Active] = ver
		}
	}

	return cred.Save()
}

// Delete deletes a credential.
func (s *FileStore) Delete(ctx context.Context, credentialID string) error {
	// Check for cancellation before acquiring lock
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	credDir := s.credentialPath(credentialID)

	if err := os.RemoveAll(credDir); err != nil {
		return fmt.Errorf("failed to delete credential: %w", err)
	}

	return nil
}

// Exists checks if a credential exists.
func (s *FileStore) Exists(ctx context.Context, credentialID string) bool {
	// Check for cancellation before acquiring lock
	select {
	case <-ctx.Done():
		return false // Return false if context cancelled
	default:
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	_, err := os.Stat(s.metadataPath(credentialID))
	return err == nil
}

// BasePath returns the credentials directory path.
func (s *FileStore) BasePath() string {
	return s.basePath
}

// Init ensures the credentials directory exists.
func (s *FileStore) Init() error {
	return os.MkdirAll(s.basePath, 0700)
}

