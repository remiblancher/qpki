package audit

import "io"

// Writer defines the interface for audit log writers.
//
// Implementations MUST:
//   - Return an error if the write fails (audit fails = operation fails)
//   - Perform fsync/flush before returning from Write
//   - Calculate and set the hash chain (HashPrev, Hash)
//   - Never write sensitive data (keys, passphrases)
type Writer interface {
	// Write logs an audit event.
	// The implementation must:
	//   1. Validate the event
	//   2. Set HashPrev from the previous event's Hash
	//   3. Calculate and set Hash for this event
	//   4. Write to persistent storage
	//   5. Sync to disk (fsync)
	//   6. Return error if any step fails
	Write(event *Event) error

	// Close flushes any pending writes and closes the writer.
	Close() error

	// LastHash returns the hash of the last written event.
	// Returns "sha256:genesis" if no events have been written.
	LastHash() string
}

// NopWriter is a no-op writer that discards all events.
// Used when audit logging is disabled.
type NopWriter struct{}

var _ Writer = (*NopWriter)(nil)

func (NopWriter) Write(*Event) error { return nil }
func (NopWriter) Close() error       { return nil }
func (NopWriter) LastHash() string   { return GenesisHash }

// MultiWriter writes to multiple audit writers.
// If any writer fails, the write fails.
type MultiWriter struct {
	writers []Writer
}

var _ Writer = (*MultiWriter)(nil)

// NewMultiWriter creates a writer that writes to all provided writers.
func NewMultiWriter(writers ...Writer) *MultiWriter {
	return &MultiWriter{writers: writers}
}

func (m *MultiWriter) Write(event *Event) error {
	for _, w := range m.writers {
		if err := w.Write(event); err != nil {
			return err
		}
	}
	return nil
}

func (m *MultiWriter) Close() error {
	var lastErr error
	for _, w := range m.writers {
		if err := w.Close(); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

func (m *MultiWriter) LastHash() string {
	if len(m.writers) > 0 {
		return m.writers[0].LastHash()
	}
	return GenesisHash
}

// Ensure Writer extends io.Closer for proper resource management.
var _ io.Closer = (Writer)(nil)
