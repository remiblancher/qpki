package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// =============================================================================
// Event Tests
// =============================================================================

func TestU_NewEvent_Creation(t *testing.T) {
	event := NewEvent(EventCertIssued, ResultSuccess)

	if event.EventType != EventCertIssued {
		t.Errorf("expected EventType=%s, got %s", EventCertIssued, event.EventType)
	}
	if event.Result != ResultSuccess {
		t.Errorf("expected Result=%s, got %s", ResultSuccess, event.Result)
	}
	if event.Timestamp == "" {
		t.Error("Timestamp should not be empty")
	}
	if event.Actor.Type != "user" {
		t.Errorf("expected Actor.Type=user, got %s", event.Actor.Type)
	}
}

func TestU_Event_Validate(t *testing.T) {
	tests := []struct {
		name    string
		event   *Event
		wantErr bool
	}{
		{
			name:    "[Unit] Validate: valid event",
			event:   NewEvent(EventCertIssued, ResultSuccess),
			wantErr: false,
		},
		{
			name: "[Unit] Validate: missing event_type",
			event: &Event{
				Timestamp: "2024-01-15T10:00:00Z",
				Actor:     Actor{Type: "user", ID: "admin"},
				Result:    ResultSuccess,
			},
			wantErr: true,
		},
		{
			name: "[Unit] Validate: missing result",
			event: &Event{
				EventType: EventCertIssued,
				Timestamp: "2024-01-15T10:00:00Z",
				Actor:     Actor{Type: "user", ID: "admin"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.event.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestU_Event_CanonicalJSON(t *testing.T) {
	event := NewEvent(EventCertIssued, ResultSuccess).
		WithObject(Object{Type: "certificate", Serial: "0x01"})
	event.HashPrev = GenesisHash

	canonical, err := event.CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON() error = %v", err)
	}

	// Verify it doesn't contain the Hash field
	if strings.Contains(string(canonical), `"hash":`) {
		t.Error("CanonicalJSON should not contain hash field")
	}

	// Verify it's valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal(canonical, &parsed); err != nil {
		t.Errorf("CanonicalJSON produced invalid JSON: %v", err)
	}
}

// =============================================================================
// FileWriter Tests
// =============================================================================

func TestU_FileWriter_Write(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.jsonl")

	writer, err := NewFileWriter(logPath)
	if err != nil {
		t.Fatalf("NewFileWriter() error = %v", err)
	}
	defer func() { _ = writer.Close() }()

	// Write first event
	event1 := NewEvent(EventCACreated, ResultSuccess).
		WithObject(Object{Type: "ca", Path: "/test/ca"})

	if err := writer.Write(event1); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	// Verify first event has genesis as prev hash
	if event1.HashPrev != GenesisHash {
		t.Errorf("First event HashPrev = %s, want %s", event1.HashPrev, GenesisHash)
	}
	if !strings.HasPrefix(event1.Hash, HashPrefix) {
		t.Errorf("First event Hash should start with %s, got %s", HashPrefix, event1.Hash)
	}

	// Write second event
	event2 := NewEvent(EventCertIssued, ResultSuccess).
		WithObject(Object{Type: "certificate", Serial: "0x01"})

	if err := writer.Write(event2); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	// Verify chain
	if event2.HashPrev != event1.Hash {
		t.Errorf("Second event HashPrev = %s, want %s", event2.HashPrev, event1.Hash)
	}

	// Close and verify file contents
	_ = writer.Close()

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Errorf("Expected 2 lines, got %d", len(lines))
	}
}

func TestU_FileWriter_Append(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.jsonl")

	// Write first event
	writer1, err := NewFileWriter(logPath)
	if err != nil {
		t.Fatalf("NewFileWriter() error = %v", err)
	}

	event1 := NewEvent(EventCACreated, ResultSuccess)
	if err := writer1.Write(event1); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	_ = writer1.Close()

	// Open again and write second event
	writer2, err := NewFileWriter(logPath)
	if err != nil {
		t.Fatalf("NewFileWriter() error = %v", err)
	}

	// Verify last hash is preserved
	if writer2.LastHash() != event1.Hash {
		t.Errorf("LastHash() = %s, want %s", writer2.LastHash(), event1.Hash)
	}

	event2 := NewEvent(EventCertIssued, ResultSuccess)
	if err := writer2.Write(event2); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	_ = writer2.Close()

	// Verify chain continues
	if event2.HashPrev != event1.Hash {
		t.Errorf("Event2 HashPrev = %s, want %s", event2.HashPrev, event1.Hash)
	}
}

// =============================================================================
// VerifyChain Tests
// =============================================================================

func TestU_VerifyChain_ValidLog(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.jsonl")

	// Create valid log
	writer, _ := NewFileWriter(logPath)
	for i := 0; i < 5; i++ {
		event := NewEvent(EventCertIssued, ResultSuccess).
			WithObject(Object{Serial: "0x" + string(rune('1'+i))})
		_ = writer.Write(event)
	}
	_ = writer.Close()

	// Verify valid log
	count, err := VerifyChain(logPath)
	if err != nil {
		t.Errorf("VerifyChain() error = %v", err)
	}
	if count != 5 {
		t.Errorf("VerifyChain() count = %d, want 5", count)
	}
}

func TestU_VerifyChain_Tampering(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.jsonl")

	// Create valid log
	writer, _ := NewFileWriter(logPath)
	for i := 0; i < 3; i++ {
		event := NewEvent(EventCertIssued, ResultSuccess)
		_ = writer.Write(event)
	}
	_ = writer.Close()

	// Read and tamper with the log
	data, _ := os.ReadFile(logPath)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")

	// Modify the second line
	var event Event
	_ = json.Unmarshal([]byte(lines[1]), &event)
	event.Object.Serial = "TAMPERED"
	tamperedLine, _ := event.JSON()
	lines[1] = string(tamperedLine)

	_ = os.WriteFile(logPath, []byte(strings.Join(lines, "\n")+"\n"), 0644)

	// Verify should fail
	count, err := VerifyChain(logPath)
	if err == nil {
		t.Error("VerifyChain() should fail on tampered log")
	}
	if count != 1 {
		t.Errorf("VerifyChain() count = %d, want 1 (events before tampering)", count)
	}
}

// =============================================================================
// NopWriter Tests
// =============================================================================

func TestU_NopWriter_Write(t *testing.T) {
	var w NopWriter

	event := NewEvent(EventCertIssued, ResultSuccess)
	if err := w.Write(event); err != nil {
		t.Errorf("NopWriter.Write() error = %v", err)
	}
	if err := w.Close(); err != nil {
		t.Errorf("NopWriter.Close() error = %v", err)
	}
	if w.LastHash() != GenesisHash {
		t.Errorf("NopWriter.LastHash() = %s, want %s", w.LastHash(), GenesisHash)
	}
}

// =============================================================================
// Global Audit Tests
// =============================================================================

func TestU_GlobalAudit_InitAndLog(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.jsonl")

	// Initialize global audit
	if err := InitFile(logPath); err != nil {
		t.Fatalf("InitFile() error = %v", err)
	}

	if !Enabled() {
		t.Error("Enabled() should return true after InitFile")
	}

	// Log an event
	event := NewEvent(EventCertIssued, ResultSuccess)
	if err := Log(event); err != nil {
		t.Errorf("Log() error = %v", err)
	}

	// Close
	if err := Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}

	if Enabled() {
		t.Error("Enabled() should return false after Close")
	}

	// Verify the event was written
	count, err := VerifyChain(logPath)
	if err != nil {
		t.Errorf("VerifyChain() error = %v", err)
	}
	if count != 1 {
		t.Errorf("VerifyChain() count = %d, want 1", count)
	}
}

// =============================================================================
// Helper Functions Tests
// =============================================================================

func TestU_LogHelpers_AllEvents(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.jsonl")

	if err := InitFile(logPath); err != nil {
		t.Fatalf("InitFile() error = %v", err)
	}
	defer func() { _ = Close() }()

	// Test LogCACreated
	if err := LogCACreated("/test/ca", "CN=Test CA", "ecdsa-p256", true); err != nil {
		t.Errorf("LogCACreated() error = %v", err)
	}

	// Test LogCertIssued
	if err := LogCertIssued("/test/ca", "0x01", "CN=Test", "tls-server", "ECDSA-SHA256", true); err != nil {
		t.Errorf("LogCertIssued() error = %v", err)
	}

	// Test LogCertRevoked
	if err := LogCertRevoked("/test/ca", "0x01", "CN=Test", "keyCompromise", true); err != nil {
		t.Errorf("LogCertRevoked() error = %v", err)
	}

	// Test LogCRLGenerated
	if err := LogCRLGenerated("/test/ca", 1, true); err != nil {
		t.Errorf("LogCRLGenerated() error = %v", err)
	}

	// Test LogAuthFailed
	if err := LogAuthFailed("/test/ca", "invalid passphrase"); err != nil {
		t.Errorf("LogAuthFailed() error = %v", err)
	}

	_ = Close()

	// Verify all events
	count, err := VerifyChain(logPath)
	if err != nil {
		t.Errorf("VerifyChain() error = %v", err)
	}
	if count != 5 {
		t.Errorf("VerifyChain() count = %d, want 5", count)
	}
}

func TestU_LogCALoaded_Success(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.jsonl")

	if err := InitFile(logPath); err != nil {
		t.Fatalf("InitFile() error = %v", err)
	}
	defer func() { _ = Close() }()

	// Test LogCALoaded
	if err := LogCALoaded("/test/ca", "CN=Test CA", true); err != nil {
		t.Errorf("LogCALoaded() error = %v", err)
	}

	_ = Close()

	// Verify event was written
	count, err := VerifyChain(logPath)
	if err != nil {
		t.Errorf("VerifyChain() error = %v", err)
	}
	if count != 1 {
		t.Errorf("VerifyChain() count = %d, want 1", count)
	}
}

func TestU_LogKeyAccessed_Success(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.jsonl")

	if err := InitFile(logPath); err != nil {
		t.Fatalf("InitFile() error = %v", err)
	}
	defer func() { _ = Close() }()

	// Test LogKeyAccessed
	if err := LogKeyAccessed("/test/ca", true, "signing key loaded"); err != nil {
		t.Errorf("LogKeyAccessed() error = %v", err)
	}

	_ = Close()

	// Verify event was written
	count, err := VerifyChain(logPath)
	if err != nil {
		t.Errorf("VerifyChain() error = %v", err)
	}
	if count != 1 {
		t.Errorf("VerifyChain() count = %d, want 1", count)
	}
}

func TestU_LogCARotated_Success(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.jsonl")

	if err := InitFile(logPath); err != nil {
		t.Fatalf("InitFile() error = %v", err)
	}
	defer func() { _ = Close() }()

	// Test LogCARotated
	if err := LogCARotated("/test/ca", "v2", "ecdsa-p256", true); err != nil {
		t.Errorf("LogCARotated() error = %v", err)
	}

	_ = Close()

	// Verify event was written
	count, err := VerifyChain(logPath)
	if err != nil {
		t.Errorf("VerifyChain() error = %v", err)
	}
	if count != 1 {
		t.Errorf("VerifyChain() count = %d, want 1", count)
	}
}

func TestU_Event_WithActor(t *testing.T) {
	event := NewEvent(EventCertIssued, ResultSuccess)

	// Test WithActor
	actor := Actor{
		Type: "service",
		ID:   "test-service",
	}
	event = event.WithActor(actor)

	if event.Actor.Type != "service" {
		t.Errorf("Actor.Type = %s, want service", event.Actor.Type)
	}
	if event.Actor.ID != "test-service" {
		t.Errorf("Actor.ID = %s, want test-service", event.Actor.ID)
	}
}

func TestU_FileWriter_Path(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.jsonl")

	writer, err := NewFileWriter(logPath)
	if err != nil {
		t.Fatalf("NewFileWriter() error = %v", err)
	}
	defer func() { _ = writer.Close() }()

	// Test Path method
	if writer.Path() != logPath {
		t.Errorf("Path() = %s, want %s", writer.Path(), logPath)
	}
}

// =============================================================================
// MultiWriter Tests
// =============================================================================

func TestU_MultiWriter_Write(t *testing.T) {
	tmpDir := t.TempDir()
	logPath1 := filepath.Join(tmpDir, "audit1.jsonl")
	logPath2 := filepath.Join(tmpDir, "audit2.jsonl")

	writer1, err := NewFileWriter(logPath1)
	if err != nil {
		t.Fatalf("NewFileWriter() error = %v", err)
	}

	writer2, err := NewFileWriter(logPath2)
	if err != nil {
		t.Fatalf("NewFileWriter() error = %v", err)
	}

	// Create MultiWriter
	multi := NewMultiWriter(writer1, writer2)

	// Test Write
	event := NewEvent(EventCertIssued, ResultSuccess).
		WithObject(Object{Type: "certificate", Serial: "0x01"})

	if err := multi.Write(event); err != nil {
		t.Errorf("MultiWriter.Write() error = %v", err)
	}

	// Test LastHash (should return first writer's hash)
	if multi.LastHash() != writer1.LastHash() {
		t.Errorf("MultiWriter.LastHash() = %s, want %s", multi.LastHash(), writer1.LastHash())
	}

	// Test Close
	if err := multi.Close(); err != nil {
		t.Errorf("MultiWriter.Close() error = %v", err)
	}

	// Verify both files have the event
	count1, err := VerifyChain(logPath1)
	if err != nil {
		t.Errorf("VerifyChain(log1) error = %v", err)
	}
	if count1 != 1 {
		t.Errorf("VerifyChain(log1) count = %d, want 1", count1)
	}

	count2, err := VerifyChain(logPath2)
	if err != nil {
		t.Errorf("VerifyChain(log2) error = %v", err)
	}
	if count2 != 1 {
		t.Errorf("VerifyChain(log2) count = %d, want 1", count2)
	}
}

func TestU_MustLog_Success(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.jsonl")

	if err := InitFile(logPath); err != nil {
		t.Fatalf("InitFile() error = %v", err)
	}
	defer func() { _ = Close() }()

	// MustLog should not panic with valid event
	event := NewEvent(EventCertIssued, ResultSuccess)
	if err := MustLog(event); err != nil {
		t.Fatalf("MustLog() error = %v", err)
	}

	_ = Close()

	// Verify event was written
	count, err := VerifyChain(logPath)
	if err != nil {
		t.Errorf("VerifyChain() error = %v", err)
	}
	if count != 1 {
		t.Errorf("VerifyChain() count = %d, want 1", count)
	}
}

// =============================================================================
// FileWriter Error Handling Tests
// =============================================================================

func TestU_FileWriter_InvalidPath(t *testing.T) {
	// Try to create in a non-existent directory
	invalidPath := "/nonexistent/directory/audit.jsonl"
	_, err := NewFileWriter(invalidPath)
	if err == nil {
		t.Error("NewFileWriter() should fail with invalid path")
	}
}

func TestU_FileWriter_CloseIdempotent(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.jsonl")

	writer, err := NewFileWriter(logPath)
	if err != nil {
		t.Fatalf("NewFileWriter() error = %v", err)
	}

	// First close should succeed
	if err := writer.Close(); err != nil {
		t.Errorf("First Close() error = %v", err)
	}

	// Second close should not panic (may return error for closed file)
	_ = writer.Close()
}

func TestU_FileWriter_WriteAfterClose(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.jsonl")

	writer, err := NewFileWriter(logPath)
	if err != nil {
		t.Fatalf("NewFileWriter() error = %v", err)
	}

	// Close the writer
	_ = writer.Close()

	// Write after close should fail
	event := NewEvent(EventCertIssued, ResultSuccess)
	err = writer.Write(event)
	if err == nil {
		t.Error("Write() after Close() should fail")
	}
}

func TestU_FileWriter_LargeEvent(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.jsonl")

	writer, err := NewFileWriter(logPath)
	if err != nil {
		t.Fatalf("NewFileWriter() error = %v", err)
	}
	defer func() { _ = writer.Close() }()

	// Create event with large payload
	largeSubject := strings.Repeat("CN=Test,O=Organization,C=US,", 1000)
	event := NewEvent(EventCertIssued, ResultSuccess).
		WithObject(Object{Type: "certificate", Subject: largeSubject})

	if err := writer.Write(event); err != nil {
		t.Errorf("Write() with large event error = %v", err)
	}

	// Verify it was written correctly
	_ = writer.Close()
	count, err := VerifyChain(logPath)
	if err != nil {
		t.Errorf("VerifyChain() error = %v", err)
	}
	if count != 1 {
		t.Errorf("VerifyChain() count = %d, want 1", count)
	}
}

func TestU_FileWriter_SpecialChars(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.jsonl")

	writer, err := NewFileWriter(logPath)
	if err != nil {
		t.Fatalf("NewFileWriter() error = %v", err)
	}
	defer func() { _ = writer.Close() }()

	// Create event with special characters (UTF-8, quotes, newlines in subject)
	event := NewEvent(EventCertIssued, ResultSuccess).
		WithObject(Object{
			Type:    "certificate",
			Subject: `CN=Test "Quoted",O=日本語,C=🔐`,
		})

	if err := writer.Write(event); err != nil {
		t.Errorf("Write() with special chars error = %v", err)
	}

	// Verify it was written correctly
	_ = writer.Close()
	count, err := VerifyChain(logPath)
	if err != nil {
		t.Errorf("VerifyChain() error = %v", err)
	}
	if count != 1 {
		t.Errorf("VerifyChain() count = %d, want 1", count)
	}
}

// =============================================================================
// MultiWriter Edge Cases Tests
// =============================================================================

func TestU_MultiWriter_Empty(t *testing.T) {
	// Create MultiWriter with no writers
	multi := NewMultiWriter()

	// Write should succeed (no writers to fail)
	event := NewEvent(EventCertIssued, ResultSuccess)
	if err := multi.Write(event); err != nil {
		t.Errorf("MultiWriter.Write() with no writers error = %v", err)
	}

	// LastHash should return genesis
	if multi.LastHash() != GenesisHash {
		t.Errorf("MultiWriter.LastHash() = %s, want %s", multi.LastHash(), GenesisHash)
	}

	// Close should succeed
	if err := multi.Close(); err != nil {
		t.Errorf("MultiWriter.Close() error = %v", err)
	}
}

func TestU_MultiWriter_Single(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.jsonl")

	writer, err := NewFileWriter(logPath)
	if err != nil {
		t.Fatalf("NewFileWriter() error = %v", err)
	}

	// Create MultiWriter with single writer
	multi := NewMultiWriter(writer)

	event := NewEvent(EventCertIssued, ResultSuccess)
	if err := multi.Write(event); err != nil {
		t.Errorf("MultiWriter.Write() error = %v", err)
	}

	// LastHash should match the single writer
	if multi.LastHash() != writer.LastHash() {
		t.Errorf("MultiWriter.LastHash() = %s, want %s", multi.LastHash(), writer.LastHash())
	}

	_ = multi.Close()

	// Verify event was written
	count, err := VerifyChain(logPath)
	if err != nil {
		t.Errorf("VerifyChain() error = %v", err)
	}
	if count != 1 {
		t.Errorf("VerifyChain() count = %d, want 1", count)
	}
}

// failingWriter is a mock writer that fails on Write.
type failingWriter struct {
	failOnWrite bool
	failOnClose bool
}

func (f *failingWriter) Write(*Event) error {
	if f.failOnWrite {
		return os.ErrPermission
	}
	return nil
}

func (f *failingWriter) Close() error {
	if f.failOnClose {
		return os.ErrClosed
	}
	return nil
}

func (f *failingWriter) LastHash() string {
	return GenesisHash
}

func TestU_MultiWriter_FirstFails(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.jsonl")

	failing := &failingWriter{failOnWrite: true}
	working, _ := NewFileWriter(logPath)
	defer func() { _ = working.Close() }()

	// First writer fails
	multi := NewMultiWriter(failing, working)

	event := NewEvent(EventCertIssued, ResultSuccess)
	err := multi.Write(event)
	if err == nil {
		t.Error("MultiWriter.Write() should fail when first writer fails")
	}
}

func TestU_MultiWriter_SecondFails(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.jsonl")

	working, _ := NewFileWriter(logPath)
	failing := &failingWriter{failOnWrite: true}
	defer func() { _ = working.Close() }()

	// Second writer fails
	multi := NewMultiWriter(working, failing)

	event := NewEvent(EventCertIssued, ResultSuccess)
	err := multi.Write(event)
	if err == nil {
		t.Error("MultiWriter.Write() should fail when second writer fails")
	}
}

func TestU_MultiWriter_CloseErrors(t *testing.T) {
	failing1 := &failingWriter{failOnClose: true}
	failing2 := &failingWriter{failOnClose: true}

	multi := NewMultiWriter(failing1, failing2)

	// Close should return an error (the last one)
	err := multi.Close()
	if err == nil {
		t.Error("MultiWriter.Close() should return error when writers fail")
	}
}

// =============================================================================
// Concurrency Tests
// =============================================================================

func TestU_FileWriter_ConcurrentWrites(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit_concurrent.jsonl")

	writer, err := NewFileWriter(logPath)
	if err != nil {
		t.Fatalf("NewFileWriter() error = %v", err)
	}
	defer func() { _ = writer.Close() }()

	// Write events concurrently
	const numGoroutines = 10
	const eventsPerGoroutine = 10

	done := make(chan bool)
	errors := make(chan error, numGoroutines*eventsPerGoroutine)

	for i := 0; i < numGoroutines; i++ {
		go func(goroutineID int) {
			for j := 0; j < eventsPerGoroutine; j++ {
				event := NewEvent(EventCertIssued, ResultSuccess).
					WithObject(Object{
						Type:   "certificate",
						Serial: "0x" + string(rune('0'+goroutineID)) + string(rune('0'+j)),
					})
				if err := writer.Write(event); err != nil {
					errors <- err
				}
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		<-done
	}
	close(errors)

	// Check for errors
	for err := range errors {
		t.Errorf("Concurrent write error: %v", err)
	}

	// Close and verify chain
	_ = writer.Close()

	count, err := VerifyChain(logPath)
	if err != nil {
		t.Errorf("VerifyChain() error = %v", err)
	}
	if count != numGoroutines*eventsPerGoroutine {
		t.Errorf("VerifyChain() count = %d, want %d", count, numGoroutines*eventsPerGoroutine)
	}
}

// =============================================================================
// Global Audit Init/Close Edge Cases
// =============================================================================

func TestU_GlobalAudit_InitWithNil(t *testing.T) {
	// Init with nil should set NopWriter
	if err := Init(nil); err != nil {
		t.Errorf("Init(nil) error = %v", err)
	}

	// Should be disabled
	if Enabled() {
		t.Error("Enabled() should return false after Init(nil)")
	}

	// Log should succeed (NopWriter)
	event := NewEvent(EventCertIssued, ResultSuccess)
	if err := Log(event); err != nil {
		t.Errorf("Log() error = %v (should succeed with NopWriter)", err)
	}

	// Close
	if err := Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

func TestU_GlobalAudit_MultipleInit(t *testing.T) {
	tmpDir := t.TempDir()
	logPath1 := filepath.Join(tmpDir, "audit1.jsonl")
	logPath2 := filepath.Join(tmpDir, "audit2.jsonl")

	// First init
	if err := InitFile(logPath1); err != nil {
		t.Fatalf("First InitFile() error = %v", err)
	}

	// Write event to first log
	event1 := NewEvent(EventCACreated, ResultSuccess)
	if err := Log(event1); err != nil {
		t.Errorf("Log() to first log error = %v", err)
	}

	// Second init should work (replaces writer)
	if err := InitFile(logPath2); err != nil {
		t.Fatalf("Second InitFile() error = %v", err)
	}

	// Write event to second log
	event2 := NewEvent(EventCertIssued, ResultSuccess)
	if err := Log(event2); err != nil {
		t.Errorf("Log() to second log error = %v", err)
	}

	// Close
	if err := Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}

	// Verify first log has 1 event
	count1, err := VerifyChain(logPath1)
	if err != nil {
		t.Errorf("VerifyChain(log1) error = %v", err)
	}
	if count1 != 1 {
		t.Errorf("VerifyChain(log1) count = %d, want 1", count1)
	}

	// Verify second log has 1 event
	count2, err := VerifyChain(logPath2)
	if err != nil {
		t.Errorf("VerifyChain(log2) error = %v", err)
	}
	if count2 != 1 {
		t.Errorf("VerifyChain(log2) count = %d, want 1", count2)
	}
}

func TestU_GlobalAudit_InitFileEmptyPath(t *testing.T) {
	// InitFile with empty path should disable audit
	if err := InitFile(""); err != nil {
		t.Errorf("InitFile(\"\") error = %v", err)
	}

	if Enabled() {
		t.Error("Enabled() should return false after InitFile(\"\")")
	}

	// Close
	if err := Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

func TestU_GlobalAudit_CloseMultipleTimes(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.jsonl")

	if err := InitFile(logPath); err != nil {
		t.Fatalf("InitFile() error = %v", err)
	}

	// First close
	if err := Close(); err != nil {
		t.Errorf("First Close() error = %v", err)
	}

	// Second close should not error (NopWriter)
	if err := Close(); err != nil {
		t.Errorf("Second Close() error = %v", err)
	}
}

func TestU_GlobalAudit_LogWhenDisabled(t *testing.T) {
	// Ensure audit is disabled
	if err := Init(nil); err != nil {
		t.Fatalf("Init(nil) error = %v", err)
	}

	if Enabled() {
		t.Error("Enabled() should return false")
	}

	// Log should succeed (NopWriter discards)
	event := NewEvent(EventCertIssued, ResultSuccess)
	if err := Log(event); err != nil {
		t.Errorf("Log() when disabled error = %v", err)
	}

	// MustLog should also succeed
	if err := MustLog(event); err != nil {
		t.Errorf("MustLog() when disabled error = %v", err)
	}

	_ = Close()
}

// =============================================================================
// VerifyChain Edge Cases
// =============================================================================

func TestU_VerifyChain_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "empty.jsonl")

	// Create empty file
	if err := os.WriteFile(logPath, []byte{}, 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	count, err := VerifyChain(logPath)
	if err != nil {
		t.Errorf("VerifyChain() error = %v", err)
	}
	if count != 0 {
		t.Errorf("VerifyChain() count = %d, want 0", count)
	}
}

func TestU_VerifyChain_NonExistentFile(t *testing.T) {
	_, err := VerifyChain("/nonexistent/path/audit.jsonl")
	if err == nil {
		t.Error("VerifyChain() should fail for non-existent file")
	}
}

func TestU_VerifyChain_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "invalid.jsonl")

	// Create file with invalid JSON
	if err := os.WriteFile(logPath, []byte("not valid json\n"), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, err := VerifyChain(logPath)
	if err == nil {
		t.Error("VerifyChain() should fail for invalid JSON")
	}
}

func TestU_VerifyChain_BrokenChain(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "broken.jsonl")

	// Create valid log
	writer, _ := NewFileWriter(logPath)
	for i := 0; i < 3; i++ {
		event := NewEvent(EventCertIssued, ResultSuccess)
		_ = writer.Write(event)
	}
	_ = writer.Close()

	// Read and break the chain by modifying hash_prev
	data, _ := os.ReadFile(logPath)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")

	// Modify the second line's hash_prev
	var event Event
	_ = json.Unmarshal([]byte(lines[1]), &event)
	event.HashPrev = "sha256:broken"
	modifiedLine, _ := event.JSON()
	lines[1] = string(modifiedLine)

	_ = os.WriteFile(logPath, []byte(strings.Join(lines, "\n")+"\n"), 0644)

	// Verify should fail
	count, err := VerifyChain(logPath)
	if err == nil {
		t.Error("VerifyChain() should fail for broken chain")
	}
	if count != 1 {
		t.Errorf("VerifyChain() count = %d, want 1 (valid events before break)", count)
	}
}

// =============================================================================
// Log Helper Failure Cases
// =============================================================================

func TestU_LogHelpers_FailureCases(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.jsonl")

	if err := InitFile(logPath); err != nil {
		t.Fatalf("InitFile() error = %v", err)
	}
	defer func() { _ = Close() }()

	// Test LogCACreated with failure
	if err := LogCACreated("/test/ca", "CN=Test CA", "ecdsa-p256", false); err != nil {
		t.Errorf("LogCACreated(success=false) error = %v", err)
	}

	// Test LogCALoaded with failure
	if err := LogCALoaded("/test/ca", "CN=Test CA", false); err != nil {
		t.Errorf("LogCALoaded(success=false) error = %v", err)
	}

	// Test LogKeyAccessed with failure
	if err := LogKeyAccessed("/test/ca", false, "wrong passphrase"); err != nil {
		t.Errorf("LogKeyAccessed(success=false) error = %v", err)
	}

	// Test LogCertIssued with failure
	if err := LogCertIssued("/test/ca", "0x01", "CN=Test", "tls-server", "ECDSA-SHA256", false); err != nil {
		t.Errorf("LogCertIssued(success=false) error = %v", err)
	}

	// Test LogCertRevoked with failure
	if err := LogCertRevoked("/test/ca", "0x01", "CN=Test", "keyCompromise", false); err != nil {
		t.Errorf("LogCertRevoked(success=false) error = %v", err)
	}

	// Test LogCRLGenerated with failure
	if err := LogCRLGenerated("/test/ca", 0, false); err != nil {
		t.Errorf("LogCRLGenerated(success=false) error = %v", err)
	}

	_ = Close()

	// Verify all events were written
	count, err := VerifyChain(logPath)
	if err != nil {
		t.Errorf("VerifyChain() error = %v", err)
	}
	if count != 6 {
		t.Errorf("VerifyChain() count = %d, want 6", count)
	}
}

// =============================================================================
// Event Validation Edge Cases
// =============================================================================

func TestU_Event_Validate_MissingTimestamp(t *testing.T) {
	event := &Event{
		EventType: EventCertIssued,
		Result:    ResultSuccess,
		Actor:     Actor{Type: "user", ID: "admin"},
		// Missing Timestamp
	}

	err := event.Validate()
	if err == nil {
		t.Error("Validate() should fail for missing timestamp")
	}
}

func TestU_Event_Validate_MissingActor(t *testing.T) {
	event := &Event{
		EventType: EventCertIssued,
		Timestamp: "2024-01-15T10:00:00Z",
		Result:    ResultSuccess,
		// Missing Actor
	}

	err := event.Validate()
	if err == nil {
		t.Error("Validate() should fail for missing actor")
	}
}

// =============================================================================
// MustLog Error Path Tests
// =============================================================================

func TestU_MustLog_Error(t *testing.T) {
	// Create a failing writer to trigger the error path in MustLog
	failing := &failingWriter{failOnWrite: true}

	if err := Init(failing); err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	defer func() { _ = Close() }()

	event := NewEvent(EventCertIssued, ResultSuccess)
	err := MustLog(event)
	if err == nil {
		t.Error("MustLog() should return error when Log fails")
	}

	// Verify the error is wrapped correctly
	if !strings.Contains(err.Error(), "audit log failed") {
		t.Errorf("MustLog() error should contain 'audit log failed', got: %v", err)
	}
}

// =============================================================================
// NewEvent Environment Variable Fallback Tests
// =============================================================================

func TestU_NewEvent_UnknownUser(t *testing.T) {
	// Save original env vars
	originalUser := os.Getenv("USER")
	originalUsername := os.Getenv("USERNAME")

	// Clear both env vars to trigger "unknown" fallback
	_ = os.Unsetenv("USER")
	_ = os.Unsetenv("USERNAME")

	defer func() {
		// Restore original env vars
		if originalUser != "" {
			_ = os.Setenv("USER", originalUser)
		}
		if originalUsername != "" {
			_ = os.Setenv("USERNAME", originalUsername)
		}
	}()

	event := NewEvent(EventCertIssued, ResultSuccess)

	if event.Actor.ID != "unknown" {
		t.Errorf("Actor.ID = %s, want 'unknown' when both USER and USERNAME are empty", event.Actor.ID)
	}
}

func TestU_NewEvent_UsernameEnvVar(t *testing.T) {
	// Save original env vars
	originalUser := os.Getenv("USER")
	originalUsername := os.Getenv("USERNAME")

	// Clear USER but set USERNAME (Windows-style)
	_ = os.Unsetenv("USER")
	_ = os.Setenv("USERNAME", "testuser")

	defer func() {
		// Restore original env vars
		if originalUser != "" {
			_ = os.Setenv("USER", originalUser)
		} else {
			_ = os.Unsetenv("USER")
		}
		if originalUsername != "" {
			_ = os.Setenv("USERNAME", originalUsername)
		} else {
			_ = os.Unsetenv("USERNAME")
		}
	}()

	event := NewEvent(EventCertIssued, ResultSuccess)

	if event.Actor.ID != "testuser" {
		t.Errorf("Actor.ID = %s, want 'testuser' when using USERNAME env var", event.Actor.ID)
	}
}

// =============================================================================
// readLastHash Edge Cases Tests
// =============================================================================

func TestU_ReadLastHash_EmptyHash(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.jsonl")

	// Create a file with an event that has an empty hash
	eventWithEmptyHash := `{"event_type":"CERT_ISSUED","timestamp":"2024-01-15T10:00:00Z","actor":{"type":"user","id":"test"},"object":{},"result":"success","hash_prev":"sha256:genesis","hash":""}`
	if err := os.WriteFile(logPath, []byte(eventWithEmptyHash+"\n"), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	// Try to create a new writer - should fail because last event has no hash
	_, err := NewFileWriter(logPath)
	if err == nil {
		t.Error("NewFileWriter() should fail when last event has empty hash")
	}
	if !strings.Contains(err.Error(), "last event has no hash") {
		t.Errorf("Error should mention 'last event has no hash', got: %v", err)
	}
}

func TestU_ReadLastHash_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.jsonl")

	// Create a file with invalid JSON as last line
	if err := os.WriteFile(logPath, []byte("not valid json\n"), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	// Try to create a new writer - should fail due to invalid JSON
	_, err := NewFileWriter(logPath)
	if err == nil {
		t.Error("NewFileWriter() should fail when last line is invalid JSON")
	}
	if !strings.Contains(err.Error(), "failed to parse last event") {
		t.Errorf("Error should mention 'failed to parse last event', got: %v", err)
	}
}

func TestU_ReadLastHash_EmptyLines(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.jsonl")

	// Create a valid event followed by empty lines
	writer, err := NewFileWriter(logPath)
	if err != nil {
		t.Fatalf("NewFileWriter() error = %v", err)
	}
	event := NewEvent(EventCertIssued, ResultSuccess)
	if err := writer.Write(event); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	firstHash := writer.LastHash()
	_ = writer.Close()

	// Append empty lines to the file
	data, _ := os.ReadFile(logPath)
	_ = os.WriteFile(logPath, append(data, []byte("\n\n\n")...), 0644)

	// Create a new writer - should correctly read the last hash ignoring empty lines
	writer2, err := NewFileWriter(logPath)
	if err != nil {
		t.Fatalf("NewFileWriter() error = %v (should handle trailing empty lines)", err)
	}
	defer func() { _ = writer2.Close() }()

	if writer2.LastHash() != firstHash {
		t.Errorf("LastHash() = %s, want %s (should ignore empty lines)", writer2.LastHash(), firstHash)
	}
}

// =============================================================================
// FileWriter Write Validation Error Tests
// =============================================================================

func TestU_FileWriter_Write_InvalidEvent(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.jsonl")

	writer, err := NewFileWriter(logPath)
	if err != nil {
		t.Fatalf("NewFileWriter() error = %v", err)
	}
	defer func() { _ = writer.Close() }()

	// Create an invalid event (missing required fields)
	invalidEvent := &Event{
		// Missing EventType, Timestamp, Actor, Result
	}

	err = writer.Write(invalidEvent)
	if err == nil {
		t.Error("Write() should fail for invalid event")
	}
	if !strings.Contains(err.Error(), "invalid event") {
		t.Errorf("Error should contain 'invalid event', got: %v", err)
	}
}

// =============================================================================
// InitFile Error Path Tests
// =============================================================================

func TestU_InitFile_NewFileWriterError(t *testing.T) {
	// Use a path that will cause NewFileWriter to fail
	// (non-existent directory)
	invalidPath := "/nonexistent/directory/audit.jsonl"

	err := InitFile(invalidPath)
	if err == nil {
		t.Error("InitFile() should fail when NewFileWriter fails")
	}
}

// =============================================================================
// VerifyChain Additional Edge Cases
// =============================================================================

func TestU_VerifyChain_BlankLines(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.jsonl")

	// Create valid log
	writer, _ := NewFileWriter(logPath)
	for i := 0; i < 3; i++ {
		event := NewEvent(EventCertIssued, ResultSuccess)
		_ = writer.Write(event)
	}
	_ = writer.Close()

	// Insert blank lines between events
	data, _ := os.ReadFile(logPath)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	withBlanks := lines[0] + "\n\n" + lines[1] + "\n\n\n" + lines[2] + "\n"
	_ = os.WriteFile(logPath, []byte(withBlanks), 0644)

	// Verify should still succeed, skipping blank lines
	// Note: VerifyChain returns line count (including blank lines), not event count
	_, err := VerifyChain(logPath)
	if err != nil {
		t.Errorf("VerifyChain() error = %v (should handle blank lines)", err)
	}
}

func TestU_VerifyChain_WhitespaceOnlyLines(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.jsonl")

	// Create valid log
	writer, _ := NewFileWriter(logPath)
	event := NewEvent(EventCertIssued, ResultSuccess)
	_ = writer.Write(event)
	_ = writer.Close()

	// Insert whitespace-only lines
	data, _ := os.ReadFile(logPath)
	withWhitespace := "   \n\t\t\n" + string(data) + "   \n\t\n"
	_ = os.WriteFile(logPath, []byte(withWhitespace), 0644)

	// Verify should still succeed
	// Note: VerifyChain returns line count, not event count
	_, err := VerifyChain(logPath)
	if err != nil {
		t.Errorf("VerifyChain() error = %v (should handle whitespace lines)", err)
	}
}

// =============================================================================
// Event JSON Methods Tests
// =============================================================================

func TestU_Event_JSON(t *testing.T) {
	event := NewEvent(EventCertIssued, ResultSuccess).
		WithObject(Object{Type: "certificate", Serial: "0x01"}).
		WithContext(Context{Algorithm: "ECDSA-SHA256"})
	event.HashPrev = GenesisHash
	event.Hash = "sha256:abc123"

	jsonData, err := event.JSON()
	if err != nil {
		t.Fatalf("JSON() error = %v", err)
	}

	// Verify it contains the hash field
	if !strings.Contains(string(jsonData), `"hash":"sha256:abc123"`) {
		t.Error("JSON() should contain hash field")
	}

	// Verify it's valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal(jsonData, &parsed); err != nil {
		t.Errorf("JSON() produced invalid JSON: %v", err)
	}
}

// =============================================================================
// LogCARotated Cross-Signed Test
// =============================================================================

func TestU_LogCARotated_NotCrossSigned(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.jsonl")

	if err := InitFile(logPath); err != nil {
		t.Fatalf("InitFile() error = %v", err)
	}
	defer func() { _ = Close() }()

	// Test LogCARotated without cross-signing
	if err := LogCARotated("/test/ca", "v2", "ecdsa-p256", false); err != nil {
		t.Errorf("LogCARotated(crossSigned=false) error = %v", err)
	}

	_ = Close()

	// Verify event was written
	count, err := VerifyChain(logPath)
	if err != nil {
		t.Errorf("VerifyChain() error = %v", err)
	}
	if count != 1 {
		t.Errorf("VerifyChain() count = %d, want 1", count)
	}
}
