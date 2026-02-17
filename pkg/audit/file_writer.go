package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
)

const (
	// GenesisHash is the initial hash for the first event in the chain.
	GenesisHash = "sha256:genesis"

	// HashPrefix is prepended to all hash values.
	HashPrefix = "sha256:"
)

// FileWriter writes audit events to a JSONL file with hash chaining.
type FileWriter struct {
	mu       sync.Mutex
	file     *os.File
	lastHash string
	path     string
}

var _ Writer = (*FileWriter)(nil)

// NewFileWriter creates a new file-based audit writer.
// If the file exists, it reads the last hash for chain continuity.
// The file is opened in append mode with exclusive access.
func NewFileWriter(path string) (*FileWriter, error) {
	// Read existing file to get last hash
	lastHash := GenesisHash
	if existingData, err := os.ReadFile(path); err == nil && len(existingData) > 0 {
		hash, err := readLastHash(existingData)
		if err != nil {
			return nil, fmt.Errorf("failed to read last hash from existing log: %w", err)
		}
		lastHash = hash
	}

	// Open file for appending
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log: %w", err)
	}

	return &FileWriter{
		file:     file,
		lastHash: lastHash,
		path:     path,
	}, nil
}

// readLastHash reads the last event from a JSONL file and returns its hash.
func readLastHash(data []byte) (string, error) {
	var lastLine string
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lastLine = line
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}

	if lastLine == "" {
		return GenesisHash, nil
	}

	var event struct {
		Hash string `json:"hash"`
	}
	if err := json.Unmarshal([]byte(lastLine), &event); err != nil {
		return "", fmt.Errorf("failed to parse last event: %w", err)
	}

	if event.Hash == "" {
		return "", fmt.Errorf("last event has no hash")
	}

	return event.Hash, nil
}

// Write logs an audit event with hash chaining.
func (w *FileWriter) Write(event *Event) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Validate event
	if err := event.Validate(); err != nil {
		return fmt.Errorf("invalid event: %w", err)
	}

	// Set hash chain
	event.HashPrev = w.lastHash

	// Calculate hash: SHA256(canonical_json || prev_hash)
	canonical, err := event.CanonicalJSON()
	if err != nil {
		return fmt.Errorf("failed to serialize event: %w", err)
	}

	hash := calculateHash(canonical, w.lastHash)
	event.Hash = hash

	// Serialize full event
	eventJSON, err := event.JSON()
	if err != nil {
		return fmt.Errorf("failed to serialize event: %w", err)
	}

	// Write to file
	if _, err := w.file.Write(append(eventJSON, '\n')); err != nil {
		return fmt.Errorf("failed to write event: %w", err)
	}

	// Sync to disk - this is critical for audit reliability
	if err := w.file.Sync(); err != nil {
		return fmt.Errorf("failed to sync audit log: %w", err)
	}

	// Update last hash for next event
	w.lastHash = hash

	return nil
}

// Close closes the audit log file.
func (w *FileWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file != nil {
		if err := w.file.Sync(); err != nil {
			return err
		}
		return w.file.Close()
	}
	return nil
}

// LastHash returns the hash of the last written event.
func (w *FileWriter) LastHash() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.lastHash
}

// Path returns the file path of the audit log.
func (w *FileWriter) Path() string {
	return w.path
}

// calculateHash computes SHA256(data || prevHash).
func calculateHash(data []byte, prevHash string) string {
	h := sha256.New()
	_, _ = h.Write(data)
	_, _ = h.Write([]byte(prevHash))
	return HashPrefix + hex.EncodeToString(h.Sum(nil))
}

// VerifyChain verifies the hash chain integrity of an audit log file.
// Returns the number of valid events and any error encountered.
func VerifyChain(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("failed to read audit log: %w", err)
	}

	if len(data) == 0 {
		return 0, nil // Empty log is valid
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	expectedPrevHash := GenesisHash
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var event Event
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			return lineNum - 1, fmt.Errorf("line %d: invalid JSON: %w", lineNum, err)
		}

		// Verify hash_prev matches expected
		if event.HashPrev != expectedPrevHash {
			return lineNum - 1, fmt.Errorf("line %d: hash chain broken: expected prev=%s, got prev=%s",
				lineNum, expectedPrevHash, event.HashPrev)
		}

		// Recalculate and verify hash
		canonical, err := event.CanonicalJSON()
		if err != nil {
			return lineNum - 1, fmt.Errorf("line %d: failed to serialize: %w", lineNum, err)
		}

		calculatedHash := calculateHash(canonical, event.HashPrev)
		if event.Hash != calculatedHash {
			return lineNum - 1, fmt.Errorf("line %d: hash mismatch: expected=%s, got=%s",
				lineNum, calculatedHash, event.Hash)
		}

		expectedPrevHash = event.Hash
	}

	if err := scanner.Err(); err != nil {
		return lineNum, fmt.Errorf("scan error: %w", err)
	}

	return lineNum, nil
}
