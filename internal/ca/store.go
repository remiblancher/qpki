// Package ca implements Certificate Authority functionality.
package ca

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Store manages certificate storage on the filesystem.
// Directory structure:
//
//	{base}/
//	  ├── ca.crt           # CA certificate
//	  ├── ca.key           # CA private key (encrypted)
//	  ├── certs/           # Issued certificates
//	  │   └── {serial}.crt
//	  ├── index.txt        # Certificate database (OpenSSL-like)
//	  └── serial           # Next serial number
type Store struct {
	basePath string
}

// NewStore creates a new certificate store at the given path.
func NewStore(basePath string) *Store {
	return &Store{basePath: basePath}
}

// Init initializes the store directory structure.
func (s *Store) Init() error {
	dirs := []string{
		s.basePath,
		filepath.Join(s.basePath, "certs"),
		filepath.Join(s.basePath, "crl"),
		filepath.Join(s.basePath, "private"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// Initialize serial file if it doesn't exist
	serialPath := filepath.Join(s.basePath, "serial")
	if _, err := os.Stat(serialPath); os.IsNotExist(err) {
		if err := os.WriteFile(serialPath, []byte("01\n"), 0644); err != nil {
			return fmt.Errorf("failed to create serial file: %w", err)
		}
	}

	// Initialize index file if it doesn't exist
	indexPath := filepath.Join(s.basePath, "index.txt")
	if _, err := os.Stat(indexPath); os.IsNotExist(err) {
		if err := os.WriteFile(indexPath, []byte(""), 0644); err != nil {
			return fmt.Errorf("failed to create index file: %w", err)
		}
	}

	return nil
}

// CACertPath returns the path to the CA certificate.
// Returns cert.pem if it exists, otherwise ca.crt for legacy compatibility.
func (s *Store) CACertPath() string {
	certPem := filepath.Join(s.basePath, "cert.pem")
	if _, err := os.Stat(certPem); err == nil {
		return certPem
	}
	return filepath.Join(s.basePath, "ca.crt")
}

// CAKeyPath returns the path to the CA private key.
// Returns key.pem if it exists, otherwise private/ca.key for legacy compatibility.
func (s *Store) CAKeyPath() string {
	keyPem := filepath.Join(s.basePath, "key.pem")
	if _, err := os.Stat(keyPem); err == nil {
		return keyPem
	}
	return filepath.Join(s.basePath, "private", "ca.key")
}

// CertPath returns the path for a certificate with the given serial.
func (s *Store) CertPath(serial []byte) string {
	return filepath.Join(s.basePath, "certs", hex.EncodeToString(serial)+".crt")
}

// SaveCACert saves the CA certificate to the store.
func (s *Store) SaveCACert(cert *x509.Certificate) error {
	// Always save to cert.pem in new versioned structure
	certPath := filepath.Join(s.basePath, "cert.pem")
	return s.saveCert(certPath, cert)
}

// LoadCACert loads the CA certificate from the store.
// For versioned CAs, this loads from the active version directory.
func (s *Store) LoadCACert() (*x509.Certificate, error) {
	// Check if new format CA (has ca.json)
	info, err := LoadCAInfo(s.basePath)
	if err == nil && info != nil && info.Active != "" {
		// New format - load from versions/{active}/certs/
		activeVer := info.ActiveVersion()
		if activeVer != nil && len(activeVer.Algos) > 0 {
			// Check if this is a hybrid CA (composite or catalyst)
			certPath := s.getHybridCertPath(info, activeVer)
			return s.loadCert(certPath)
		}
	}

	// Check if old versioned CA (has versions.json)
	versionIndex := filepath.Join(s.basePath, "versions.json")
	if _, err := os.Stat(versionIndex); err == nil {
		// Versioned CA - load from active/ directory
		activeCert := filepath.Join(s.basePath, "active", "ca.crt")
		if _, err := os.Stat(activeCert); err == nil {
			return s.loadCert(activeCert)
		}
	}

	// Legacy CA - load from root
	return s.loadCert(s.CACertPath())
}

// getHybridCertPath determines the certificate path based on CA type.
// For hybrid CAs (composite/catalyst), uses the new naming convention.
// For single-algorithm CAs, uses the standard algorithm-based naming.
func (s *Store) getHybridCertPath(info *CAInfo, activeVer *CAVersion) string {
	// Check if this is a hybrid CA by looking at profiles
	isComposite := false
	isCatalyst := false
	for _, profile := range activeVer.Profiles {
		if strings.Contains(profile, "composite") {
			isComposite = true
			break
		}
		if strings.Contains(profile, "catalyst") {
			isCatalyst = true
			break
		}
	}

	// For hybrid CAs, get classical and PQC algorithm IDs from keys
	if isComposite || isCatalyst {
		classicalKey := info.GetClassicalKey()
		pqcKey := info.GetPQCKey()
		if classicalKey != nil && pqcKey != nil {
			if isComposite {
				return info.HybridCertPathForVersion(info.Active, HybridCertComposite, classicalKey.Algorithm, pqcKey.Algorithm, false)
			}
			return info.HybridCertPathForVersion(info.Active, HybridCertCatalyst, classicalKey.Algorithm, pqcKey.Algorithm, false)
		}
	}

	// Single-algorithm CA - use first algorithm
	return info.CertPath(info.Active, activeVer.Algos[0])
}

// LoadAllCACerts loads all CA certificates from the store.
// For hybrid CAs (composite/catalyst), this returns a single certificate containing both algorithms.
// For multi-profile CAs (separate algorithms), this returns one certificate per algorithm.
// For simple CAs, this returns a single certificate (same as LoadCACert).
func (s *Store) LoadAllCACerts() ([]*x509.Certificate, error) {
	// Check if new format CA (has ca.json)
	info, err := LoadCAInfo(s.basePath)
	if err == nil && info != nil && info.Active != "" {
		activeVer := info.ActiveVersion()
		if activeVer != nil && len(activeVer.Algos) > 0 {
			// Check if this is a hybrid CA (composite/catalyst)
			isHybrid := false
			for _, profile := range activeVer.Profiles {
				if strings.Contains(profile, "composite") || strings.Contains(profile, "catalyst") {
					isHybrid = true
					break
				}
			}

			if isHybrid {
				// Hybrid CA - use the hybrid-aware cert path resolution (single cert)
				certPath := s.getHybridCertPath(info, activeVer)
				cert, err := s.loadCert(certPath)
				if err != nil {
					return nil, fmt.Errorf("failed to load CA cert: %w", err)
				}
				return []*x509.Certificate{cert}, nil
			}

			// Multi-profile or single-algorithm CA - load all algorithm certs
			var certs []*x509.Certificate
			for _, algo := range activeVer.Algos {
				certPath := info.CertPath(info.Active, algo)
				cert, err := s.loadCert(certPath)
				if err != nil {
					return nil, fmt.Errorf("failed to load CA cert for %s: %w", algo, err)
				}
				certs = append(certs, cert)
			}
			return certs, nil
		}
	}

	// Check if old versioned CA (has versions.json)
	versionIndex := filepath.Join(s.basePath, "versions.json")
	if _, err := os.Stat(versionIndex); err == nil {
		activeCert := filepath.Join(s.basePath, "active", "ca.crt")
		if _, err := os.Stat(activeCert); err == nil {
			cert, err := s.loadCert(activeCert)
			if err != nil {
				return nil, err
			}
			return []*x509.Certificate{cert}, nil
		}
	}

	// Legacy CA - load from root
	cert, err := s.loadCert(s.CACertPath())
	if err != nil {
		return nil, err
	}
	return []*x509.Certificate{cert}, nil
}

// LoadCrossSignedCerts loads cross-signed certificates for the active version.
// Cross-signed certificates are stored in versions/{versionID}/cross-signed/.
// Returns empty slice if no cross-signed certificates exist.
func (s *Store) LoadCrossSignedCerts() ([]*x509.Certificate, error) {
	info, err := LoadCAInfo(s.basePath)
	if err != nil || info == nil || info.Active == "" {
		return nil, nil // No versioned CA, no cross-certs
	}

	crossSignDir := filepath.Join(s.basePath, "versions", info.Active, "cross-signed")
	entries, err := os.ReadDir(crossSignDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No cross-signed directory
		}
		return nil, fmt.Errorf("failed to read cross-signed directory: %w", err)
	}

	var certs []*x509.Certificate
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".crt") {
			continue
		}
		certPath := filepath.Join(crossSignDir, entry.Name())
		cert, err := s.loadCert(certPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load cross-signed cert %s: %w", entry.Name(), err)
		}
		certs = append(certs, cert)
	}

	return certs, nil
}

// SaveCert saves an issued certificate to the store.
func (s *Store) SaveCert(cert *x509.Certificate) error {
	path := s.CertPath(cert.SerialNumber.Bytes())
	if err := s.saveCert(path, cert); err != nil {
		return err
	}
	return s.appendIndex(cert)
}

// LoadCert loads a certificate by serial number.
func (s *Store) LoadCert(serial []byte) (*x509.Certificate, error) {
	return s.loadCert(s.CertPath(serial))
}

// NextSerial returns the next serial number and increments the counter.
func (s *Store) NextSerial() ([]byte, error) {
	serialPath := filepath.Join(s.basePath, "serial")

	data, err := os.ReadFile(serialPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read serial file: %w", err)
	}

	// Parse hex serial
	serialHex := strings.TrimSpace(string(data))
	serial, err := hex.DecodeString(serialHex)
	if err != nil {
		return nil, fmt.Errorf("failed to parse serial: %w", err)
	}

	// Increment for next use
	next := incrementSerial(serial)
	if err := os.WriteFile(serialPath, []byte(hex.EncodeToString(next)+"\n"), 0644); err != nil {
		return nil, fmt.Errorf("failed to update serial file: %w", err)
	}

	return serial, nil
}

// incrementSerial increments a big-endian byte slice by 1.
func incrementSerial(serial []byte) []byte {
	result := make([]byte, len(serial))
	copy(result, serial)

	for i := len(result) - 1; i >= 0; i-- {
		result[i]++
		if result[i] != 0 {
			return result
		}
	}

	// Overflow - prepend a byte
	return append([]byte{1}, result...)
}

// saveCert saves a certificate to a PEM file.
func (s *Store) saveCert(path string, cert *x509.Certificate) error {
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to create certificate file: %w", err)
	}
	defer func() { _ = f.Close() }()

	if err := pem.Encode(f, block); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	return nil
}

// loadCert loads a certificate from a PEM file.
func (s *Store) loadCert(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("no certificate found in %s", path)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

// appendIndex appends a certificate entry to the index file.
// Format: status\texpiry\trevocation\tserial\tunknown\tsubject
// Status: V=valid, R=revoked, E=expired
func (s *Store) appendIndex(cert *x509.Certificate) error {
	indexPath := filepath.Join(s.basePath, "index.txt")
	f, err := os.OpenFile(indexPath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open index file: %w", err)
	}
	defer func() { _ = f.Close() }()

	// Format: V\t{expiry}\t\t{serial}\tunknown\t{subject}
	entry := fmt.Sprintf("V\t%s\t\t%s\tunknown\t%s\n",
		cert.NotAfter.UTC().Format("060102150405Z"),
		hex.EncodeToString(cert.SerialNumber.Bytes()),
		cert.Subject.String(),
	)

	if _, err := f.WriteString(entry); err != nil {
		return fmt.Errorf("failed to write index entry: %w", err)
	}

	return nil
}

// IndexEntry represents an entry in the certificate index.
type IndexEntry struct {
	Status     string
	Expiry     time.Time
	Revocation time.Time
	Serial     []byte
	Subject    string
}

// ReadIndex reads all entries from the index file.
func (s *Store) ReadIndex() ([]IndexEntry, error) {
	indexPath := filepath.Join(s.basePath, "index.txt")
	data, err := os.ReadFile(indexPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read index file: %w", err)
	}

	var entries []IndexEntry
	lines := splitLines(string(data))

	for _, line := range lines {
		if line == "" {
			continue
		}

		entry, err := parseIndexLine(line)
		if err != nil {
			continue // Skip malformed entries
		}
		entries = append(entries, entry)
	}

	return entries, nil
}

// parseIndexLine parses a single index line.
func parseIndexLine(line string) (IndexEntry, error) {
	var entry IndexEntry
	parts := splitTabs(line)

	if len(parts) < 6 {
		return entry, fmt.Errorf("malformed index line")
	}

	entry.Status = parts[0]

	// Parse expiry date
	if parts[1] != "" {
		t, err := time.Parse("060102150405Z", parts[1])
		if err == nil {
			entry.Expiry = t
		}
	}

	// Parse revocation date (if present)
	if parts[2] != "" {
		t, err := time.Parse("060102150405Z", parts[2])
		if err == nil {
			entry.Revocation = t
		}
	}

	// Parse serial
	serial, err := hex.DecodeString(parts[3])
	if err != nil {
		return entry, fmt.Errorf("invalid serial: %w", err)
	}
	entry.Serial = serial

	// Subject is the last field
	entry.Subject = parts[5]

	return entry, nil
}

// splitLines splits a string into lines.
func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

// splitTabs splits a string by tabs.
func splitTabs(s string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\t' {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}

// Exists checks if the store is already initialized.
// Returns true for both legacy CAs (ca.crt at root) and new versioned CAs (ca.json).
func (s *Store) Exists() bool {
	// Check new format (ca.json)
	if CAInfoExists(s.basePath) {
		return true
	}
	// Check legacy location
	if _, err := os.Stat(s.CACertPath()); err == nil {
		return true
	}
	// Check old versioned location (deprecated)
	activeCert := filepath.Join(s.basePath, "active", "ca.crt")
	if _, err := os.Stat(activeCert); err == nil {
		return true
	}
	return false
}

// BasePath returns the base path of the store.
func (s *Store) BasePath() string {
	return s.basePath
}
