package ca

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// MarkRevoked marks a certificate as revoked in the index file.
func (s *FileStore) MarkRevoked(ctx context.Context, serial []byte, reason RevocationReason) error {
	// Check for cancellation before I/O
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	indexPath := filepath.Join(s.basePath, "index.txt")

	data, err := os.ReadFile(indexPath)
	if err != nil {
		return fmt.Errorf("failed to read index file: %w", err)
	}

	serialHex := hex.EncodeToString(serial)
	lines := splitLines(string(data))
	var newLines []string
	found := false

	for _, line := range lines {
		if line == "" {
			continue
		}

		parts := splitTabs(line)
		if len(parts) >= 4 && parts[3] == serialHex {
			// Update this line - change V to R and add revocation date with reason
			parts[0] = "R"
			revDate := time.Now().UTC().Format("060102150405Z")
			if reason != ReasonUnspecified {
				parts[2] = fmt.Sprintf("%s,%s", revDate, reason.String())
			} else {
				parts[2] = revDate
			}
			line = strings.Join(parts, "\t")
			found = true
		}
		newLines = append(newLines, line)
	}

	if !found {
		return fmt.Errorf("certificate with serial %s not found", serialHex)
	}

	// Check for cancellation before write
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	content := strings.Join(newLines, "\n") + "\n"
	if err := os.WriteFile(indexPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write index file: %w", err)
	}

	return nil
}

// NextCRLNumber returns the next CRL number and increments the counter.
func (s *FileStore) NextCRLNumber(ctx context.Context) ([]byte, error) {
	// Check for cancellation before I/O
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	crlNumPath := filepath.Join(s.basePath, "crlnumber")

	// Initialize if doesn't exist
	if _, err := os.Stat(crlNumPath); os.IsNotExist(err) {
		if err := os.WriteFile(crlNumPath, []byte("01\n"), 0644); err != nil {
			return nil, err
		}
	}

	data, err := os.ReadFile(crlNumPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read crlnumber file: %w", err)
	}

	numHex := strings.TrimSpace(string(data))
	num, err := hex.DecodeString(numHex)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CRL number: %w", err)
	}

	// Check for cancellation before write
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Increment for next use
	next := incrementSerial(num)
	if err := os.WriteFile(crlNumPath, []byte(hex.EncodeToString(next)+"\n"), 0644); err != nil {
		return nil, err
	}

	return num, nil
}

// SaveCRL saves the CRL to the store.
func (s *FileStore) SaveCRL(ctx context.Context, crlDER []byte) error {
	// Check for cancellation before I/O
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	crlPath := filepath.Join(s.basePath, "crl", "ca.crl")

	block := &pem.Block{
		Type:  "X509 CRL",
		Bytes: crlDER,
	}

	f, err := os.OpenFile(crlPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to create CRL file: %w", err)
	}
	defer func() { _ = f.Close() }()

	if err := pem.Encode(f, block); err != nil {
		return fmt.Errorf("failed to write CRL: %w", err)
	}

	// Check for cancellation before second write
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Also save as DER
	derPath := filepath.Join(s.basePath, "crl", "ca.crl.der")
	if err := os.WriteFile(derPath, crlDER, 0644); err != nil {
		return fmt.Errorf("failed to write DER CRL: %w", err)
	}

	return nil
}

// CRLPath returns the path to the current CRL.
func (s *FileStore) CRLPath() string {
	return filepath.Join(s.basePath, "crl", "ca.crl")
}

// LoadCRL loads the current CRL from the store.
func (s *FileStore) LoadCRL() (*x509.RevocationList, error) {
	data, err := os.ReadFile(s.CRLPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No CRL yet
		}
		return nil, fmt.Errorf("failed to read CRL: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != "X509 CRL" {
		return nil, fmt.Errorf("no CRL found in file")
	}

	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CRL: %w", err)
	}

	return crl, nil
}

// ListRevoked returns all revoked certificates.
func (s *FileStore) ListRevoked(ctx context.Context) ([]RevokedCertificate, error) {
	entries, err := s.ReadIndex(ctx)
	if err != nil {
		return nil, err
	}

	var revoked []RevokedCertificate
	for _, e := range entries {
		if e.Status != "R" {
			continue
		}

		revoked = append(revoked, RevokedCertificate{
			Serial:    e.Serial,
			RevokedAt: e.Revocation,
			Subject:   e.Subject,
		})
	}

	return revoked, nil
}

// IsRevoked checks if a certificate is revoked.
func (s *FileStore) IsRevoked(ctx context.Context, serial []byte) (bool, error) {
	entries, err := s.ReadIndex(ctx)
	if err != nil {
		return false, err
	}

	serialHex := hex.EncodeToString(serial)
	for _, e := range entries {
		if hex.EncodeToString(e.Serial) == serialHex {
			return e.Status == "R", nil
		}
	}

	return false, fmt.Errorf("certificate not found")
}

// CRLDir returns the CRL directory path.
func (s *FileStore) CRLDir() string {
	return filepath.Join(s.basePath, "crl")
}

// CRLPathForAlgorithm returns the CRL path for a specific algorithm.
// Format: crl/ca.{algorithm}.crl
func (s *FileStore) CRLPathForAlgorithm(algorithm string) string {
	return filepath.Join(s.CRLDir(), fmt.Sprintf("ca.%s.crl", algorithm))
}

// CRLDERPathForAlgorithm returns the DER CRL path for a specific algorithm.
// Format: crl/ca.{algorithm}.crl.der
func (s *FileStore) CRLDERPathForAlgorithm(algorithm string) string {
	return filepath.Join(s.CRLDir(), fmt.Sprintf("ca.%s.crl.der", algorithm))
}

// SaveCRLForAlgorithm saves a CRL for a specific algorithm.
// Uses the new path structure: crl/ca.{algorithm}.crl
func (s *FileStore) SaveCRLForAlgorithm(ctx context.Context, crlDER []byte, algorithm string) error {
	// Check for cancellation before I/O
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	crlDir := s.CRLDir()
	if err := os.MkdirAll(crlDir, 0755); err != nil {
		return fmt.Errorf("failed to create CRL directory: %w", err)
	}

	crlPath := s.CRLPathForAlgorithm(algorithm)

	block := &pem.Block{
		Type:  "X509 CRL",
		Bytes: crlDER,
	}

	f, err := os.OpenFile(crlPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to create CRL file: %w", err)
	}
	defer func() { _ = f.Close() }()

	if err := pem.Encode(f, block); err != nil {
		return fmt.Errorf("failed to write CRL: %w", err)
	}

	// Check for cancellation before second write
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Also save as DER
	derPath := s.CRLDERPathForAlgorithm(algorithm)
	if err := os.WriteFile(derPath, crlDER, 0644); err != nil {
		return fmt.Errorf("failed to write DER CRL: %w", err)
	}

	return nil
}

// LoadCRLForAlgorithm loads a CRL for a specific algorithm.
func (s *FileStore) LoadCRLForAlgorithm(algorithm string) (*x509.RevocationList, error) {
	crlPath := s.CRLPathForAlgorithm(algorithm)
	data, err := os.ReadFile(crlPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No CRL yet
		}
		return nil, fmt.Errorf("failed to read CRL: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != "X509 CRL" {
		return nil, fmt.Errorf("no CRL found in file")
	}

	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CRL: %w", err)
	}

	return crl, nil
}

// ListCRLAlgorithms returns all algorithms that have CRLs.
// Parses file names like ca.{algorithm}.crl to extract algorithms.
func (s *FileStore) ListCRLAlgorithms() ([]string, error) {
	crlDir := filepath.Join(s.basePath, "crl")
	entries, err := os.ReadDir(crlDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read CRL directory: %w", err)
	}

	var algos []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		// Parse file names like ca.{algorithm}.crl
		name := entry.Name()
		if strings.HasPrefix(name, "ca.") && strings.HasSuffix(name, ".crl") {
			// Skip files that don't have an algorithm in the middle (like ca.crl)
			withoutPrefix := strings.TrimPrefix(name, "ca.")
			if !strings.HasSuffix(withoutPrefix, ".crl") {
				// This is ca.crl (legacy format), not ca.{algo}.crl
				continue
			}
			// Extract algorithm: ca.ecdsa-p256.crl -> ecdsa-p256
			algo := strings.TrimSuffix(withoutPrefix, ".crl")
			if algo != "" {
				algos = append(algos, algo)
			}
		}
	}

	return algos, nil
}
