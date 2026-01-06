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
func (s *Store) CACertPath() string {
	return filepath.Join(s.basePath, "ca.crt")
}

// CAKeyPath returns the path to the CA private key.
func (s *Store) CAKeyPath() string {
	return filepath.Join(s.basePath, "private", "ca.key")
}

// CertPath returns the path for a certificate with the given serial.
func (s *Store) CertPath(serial []byte) string {
	return filepath.Join(s.basePath, "certs", hex.EncodeToString(serial)+".crt")
}

// SaveCACert saves the CA certificate to the store.
func (s *Store) SaveCACert(cert *x509.Certificate) error {
	return s.saveCert(s.CACertPath(), cert)
}

// LoadCACert loads the CA certificate from the store.
// For versioned CAs, this loads from the active/ directory.
func (s *Store) LoadCACert() (*x509.Certificate, error) {
	// Check if versioned CA (has versions.json)
	versionIndex := filepath.Join(s.basePath, "versions.json")
	if _, err := os.Stat(versionIndex); err == nil {
		// Versioned CA - load from active/ directory
		// First try active/ca.crt (migrated single-profile CA)
		activeCert := filepath.Join(s.basePath, "active", "ca.crt")
		if _, err := os.Stat(activeCert); err == nil {
			return s.loadCert(activeCert)
		}
		// For multi-profile, certificate is in active/{algo}/ca.crt
		// The caller should use the profile directory store instead
	}
	// Legacy CA - load from root
	return s.loadCert(s.CACertPath())
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
// Returns true for both legacy CAs (ca.crt at root) and versioned CAs (active/ca.crt).
func (s *Store) Exists() bool {
	// Check legacy location
	if _, err := os.Stat(s.CACertPath()); err == nil {
		return true
	}
	// Check versioned location
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
