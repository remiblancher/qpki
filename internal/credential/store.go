package credential

import (
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
	Save(cred *Credential, certs []*x509.Certificate, signers []pkicrypto.Signer, passphrase []byte) error

	// Load loads a credential by ID.
	Load(credentialID string) (*Credential, error)

	// LoadCertificates loads the certificates for a credential.
	LoadCertificates(credentialID string) ([]*x509.Certificate, error)

	// LoadKeys loads the private keys for a credential.
	LoadKeys(credentialID string, passphrase []byte) ([]pkicrypto.Signer, error)

	// List returns all credential IDs, optionally filtered by subject.
	List(subjectFilter string) ([]string, error)

	// ListAll returns all credentials.
	ListAll() ([]*Credential, error)

	// UpdateStatus updates the status of a credential.
	UpdateStatus(credentialID string, status Status, reason string) error

	// Delete deletes a credential.
	Delete(credentialID string) error

	// Exists checks if a credential exists.
	Exists(credentialID string) bool
}

// FileStore implements Store using the filesystem.
// Credential layout:
//
//	{basePath}/credentials/{credentialID}/
//	    credential.json     # Metadata
//	    certificates.pem    # All certificates
//	    private-keys.pem    # All private keys (encrypted)
type FileStore struct {
	basePath string
	mu       sync.RWMutex
}

// NewFileStore creates a new file-based credential store.
func NewFileStore(caPath string) *FileStore {
	return &FileStore{
		basePath: filepath.Join(caPath, "credentials"),
	}
}

// credentialPath returns the path to a credential directory.
func (s *FileStore) credentialPath(credentialID string) string {
	return filepath.Join(s.basePath, credentialID)
}

// metadataPath returns the path to the credential metadata file.
func (s *FileStore) metadataPath(credentialID string) string {
	return filepath.Join(s.credentialPath(credentialID), "credential.json")
}

// certsPath returns the path to the certificates PEM file.
func (s *FileStore) certsPath(credentialID string) string {
	return filepath.Join(s.credentialPath(credentialID), "certificates.pem")
}

// keysPath returns the path to the private keys PEM file.
func (s *FileStore) keysPath(credentialID string) string {
	return filepath.Join(s.credentialPath(credentialID), "private-keys.pem")
}

// Save saves a credential with its certificates and keys.
func (s *FileStore) Save(cred *Credential, certs []*x509.Certificate, signers []pkicrypto.Signer, passphrase []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	credDir := s.credentialPath(cred.ID)

	// Create credential directory
	if err := os.MkdirAll(credDir, 0700); err != nil {
		return fmt.Errorf("failed to create credential directory: %w", err)
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
func (s *FileStore) Load(credentialID string) (*Credential, error) {
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

	return &cred, nil
}

// LoadCertificates loads the certificates for a credential.
func (s *FileStore) LoadCertificates(credentialID string) ([]*x509.Certificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

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

// LoadKeys loads the private keys for a credential.
func (s *FileStore) LoadKeys(credentialID string, passphrase []byte) ([]pkicrypto.Signer, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

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

// List returns all credential IDs, optionally filtered by subject.
func (s *FileStore) List(subjectFilter string) ([]string, error) {
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

	return &cred, nil
}

// ListAll returns all credentials.
func (s *FileStore) ListAll() ([]*Credential, error) {
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
func (s *FileStore) UpdateStatus(credentialID string, status Status, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cred, err := s.loadUnlocked(credentialID)
	if err != nil {
		return fmt.Errorf("failed to load credential: %w", err)
	}

	cred.Status = status
	if status == StatusRevoked {
		cred.Revoke(reason)
	}

	// Save updated metadata
	metaData, err := json.MarshalIndent(cred, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal credential metadata: %w", err)
	}

	if err := os.WriteFile(s.metadataPath(credentialID), metaData, 0644); err != nil {
		return fmt.Errorf("failed to write credential metadata: %w", err)
	}

	return nil
}

// Delete deletes a credential.
func (s *FileStore) Delete(credentialID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	credDir := s.credentialPath(credentialID)

	if err := os.RemoveAll(credDir); err != nil {
		return fmt.Errorf("failed to delete credential: %w", err)
	}

	return nil
}

// Exists checks if a credential exists.
func (s *FileStore) Exists(credentialID string) bool {
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
