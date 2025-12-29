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

// Store manages bundle persistence.
type Store interface {
	// Save saves a bundle with its certificates and keys.
	Save(bundle *Bundle, certs []*x509.Certificate, signers []pkicrypto.Signer, passphrase []byte) error

	// Load loads a bundle by ID.
	Load(bundleID string) (*Bundle, error)

	// LoadCertificates loads the certificates for a bundle.
	LoadCertificates(bundleID string) ([]*x509.Certificate, error)

	// LoadKeys loads the private keys for a bundle.
	LoadKeys(bundleID string, passphrase []byte) ([]pkicrypto.Signer, error)

	// List returns all bundle IDs, optionally filtered by subject.
	List(subjectFilter string) ([]string, error)

	// ListAll returns all bundles.
	ListAll() ([]*Bundle, error)

	// UpdateStatus updates the status of a bundle.
	UpdateStatus(bundleID string, status Status, reason string) error

	// Delete deletes a bundle.
	Delete(bundleID string) error

	// Exists checks if a bundle exists.
	Exists(bundleID string) bool
}

// FileStore implements Store using the filesystem.
// Bundle layout:
//
//	{basePath}/bundles/{bundleID}/
//	    bundle.json         # Metadata
//	    certificates.pem    # All certificates
//	    private-keys.pem    # All private keys (encrypted)
type FileStore struct {
	basePath string
	mu       sync.RWMutex
}

// NewFileStore creates a new file-based bundle store.
func NewFileStore(caPath string) *FileStore {
	return &FileStore{
		basePath: filepath.Join(caPath, "bundles"),
	}
}

// bundlePath returns the path to a bundle directory.
func (s *FileStore) bundlePath(bundleID string) string {
	return filepath.Join(s.basePath, bundleID)
}

// metadataPath returns the path to the bundle metadata file.
func (s *FileStore) metadataPath(bundleID string) string {
	return filepath.Join(s.bundlePath(bundleID), "bundle.json")
}

// certsPath returns the path to the certificates PEM file.
func (s *FileStore) certsPath(bundleID string) string {
	return filepath.Join(s.bundlePath(bundleID), "certificates.pem")
}

// keysPath returns the path to the private keys PEM file.
func (s *FileStore) keysPath(bundleID string) string {
	return filepath.Join(s.bundlePath(bundleID), "private-keys.pem")
}

// Save saves a bundle with its certificates and keys.
func (s *FileStore) Save(bundle *Bundle, certs []*x509.Certificate, signers []pkicrypto.Signer, passphrase []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	bundleDir := s.bundlePath(bundle.ID)

	// Create bundle directory
	if err := os.MkdirAll(bundleDir, 0700); err != nil {
		return fmt.Errorf("failed to create bundle directory: %w", err)
	}

	// Save metadata
	metaData, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal bundle metadata: %w", err)
	}

	if err := os.WriteFile(s.metadataPath(bundle.ID), metaData, 0644); err != nil {
		return fmt.Errorf("failed to write bundle metadata: %w", err)
	}

	// Save certificates
	if len(certs) > 0 {
		certsPEM, err := EncodeCertificatesPEM(certs)
		if err != nil {
			return fmt.Errorf("failed to encode certificates: %w", err)
		}

		if err := os.WriteFile(s.certsPath(bundle.ID), certsPEM, 0644); err != nil {
			return fmt.Errorf("failed to write certificates: %w", err)
		}
	}

	// Save private keys (encrypted)
	if len(signers) > 0 {
		keysPEM, err := EncodePrivateKeysPEM(signers, passphrase)
		if err != nil {
			return fmt.Errorf("failed to encode private keys: %w", err)
		}

		if err := os.WriteFile(s.keysPath(bundle.ID), keysPEM, 0600); err != nil {
			return fmt.Errorf("failed to write private keys: %w", err)
		}
	}

	return nil
}

// Load loads a bundle by ID.
func (s *FileStore) Load(bundleID string) (*Bundle, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	metaPath := s.metadataPath(bundleID)

	data, err := os.ReadFile(metaPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("bundle not found: %s", bundleID)
		}
		return nil, fmt.Errorf("failed to read bundle metadata: %w", err)
	}

	var bundle Bundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, fmt.Errorf("failed to parse bundle metadata: %w", err)
	}

	return &bundle, nil
}

// LoadCertificates loads the certificates for a bundle.
func (s *FileStore) LoadCertificates(bundleID string) ([]*x509.Certificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	certsPath := s.certsPath(bundleID)

	data, err := os.ReadFile(certsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No certificates
		}
		return nil, fmt.Errorf("failed to read certificates: %w", err)
	}

	return DecodeCertificatesPEM(data)
}

// LoadKeys loads the private keys for a bundle.
func (s *FileStore) LoadKeys(bundleID string, passphrase []byte) ([]pkicrypto.Signer, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	keysPath := s.keysPath(bundleID)

	data, err := os.ReadFile(keysPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No keys
		}
		return nil, fmt.Errorf("failed to read private keys: %w", err)
	}

	return DecodePrivateKeysPEM(data, passphrase)
}

// List returns all bundle IDs, optionally filtered by subject.
func (s *FileStore) List(subjectFilter string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entries, err := os.ReadDir(s.basePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read bundles directory: %w", err)
	}

	var ids []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		bundleID := entry.Name()

		// If filter provided, load bundle and check subject
		if subjectFilter != "" {
			bundle, err := s.loadUnlocked(bundleID)
			if err != nil {
				continue
			}

			if !strings.Contains(strings.ToLower(bundle.Subject.CommonName), strings.ToLower(subjectFilter)) {
				continue
			}
		}

		ids = append(ids, bundleID)
	}

	sort.Strings(ids)
	return ids, nil
}

// loadUnlocked loads a bundle without locking (for internal use).
func (s *FileStore) loadUnlocked(bundleID string) (*Bundle, error) {
	metaPath := s.metadataPath(bundleID)

	data, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, err
	}

	var bundle Bundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, err
	}

	return &bundle, nil
}

// ListAll returns all bundles.
func (s *FileStore) ListAll() ([]*Bundle, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entries, err := os.ReadDir(s.basePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read bundles directory: %w", err)
	}

	var bundles []*Bundle
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		bundle, err := s.loadUnlocked(entry.Name())
		if err != nil {
			continue
		}

		bundles = append(bundles, bundle)
	}

	return bundles, nil
}

// UpdateStatus updates the status of a bundle.
func (s *FileStore) UpdateStatus(bundleID string, status Status, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	bundle, err := s.loadUnlocked(bundleID)
	if err != nil {
		return fmt.Errorf("failed to load bundle: %w", err)
	}

	bundle.Status = status
	if status == StatusRevoked {
		bundle.Revoke(reason)
	}

	// Save updated metadata
	metaData, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal bundle metadata: %w", err)
	}

	if err := os.WriteFile(s.metadataPath(bundleID), metaData, 0644); err != nil {
		return fmt.Errorf("failed to write bundle metadata: %w", err)
	}

	return nil
}

// Delete deletes a bundle.
func (s *FileStore) Delete(bundleID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	bundleDir := s.bundlePath(bundleID)

	if err := os.RemoveAll(bundleDir); err != nil {
		return fmt.Errorf("failed to delete bundle: %w", err)
	}

	return nil
}

// Exists checks if a bundle exists.
func (s *FileStore) Exists(bundleID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	_, err := os.Stat(s.metadataPath(bundleID))
	return err == nil
}

// BasePath returns the bundles directory path.
func (s *FileStore) BasePath() string {
	return s.basePath
}

// Init ensures the bundles directory exists.
func (s *FileStore) Init() error {
	return os.MkdirAll(s.basePath, 0700)
}
