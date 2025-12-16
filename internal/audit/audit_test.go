package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEventCreation(t *testing.T) {
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

func TestEventValidation(t *testing.T) {
	tests := []struct {
		name    string
		event   *Event
		wantErr bool
	}{
		{
			name:    "valid event",
			event:   NewEvent(EventCertIssued, ResultSuccess),
			wantErr: false,
		},
		{
			name: "missing event_type",
			event: &Event{
				Timestamp: "2024-01-15T10:00:00Z",
				Actor:     Actor{Type: "user", ID: "admin"},
				Result:    ResultSuccess,
			},
			wantErr: true,
		},
		{
			name: "missing result",
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

func TestEventCanonicalJSON(t *testing.T) {
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

func TestFileWriter(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.jsonl")

	writer, err := NewFileWriter(logPath)
	if err != nil {
		t.Fatalf("NewFileWriter() error = %v", err)
	}
	defer writer.Close()

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
	writer.Close()

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Errorf("Expected 2 lines, got %d", len(lines))
	}
}

func TestFileWriterAppend(t *testing.T) {
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
	writer1.Close()

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
	writer2.Close()

	// Verify chain continues
	if event2.HashPrev != event1.Hash {
		t.Errorf("Event2 HashPrev = %s, want %s", event2.HashPrev, event1.Hash)
	}
}

func TestVerifyChain(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.jsonl")

	// Create valid log
	writer, _ := NewFileWriter(logPath)
	for i := 0; i < 5; i++ {
		event := NewEvent(EventCertIssued, ResultSuccess).
			WithObject(Object{Serial: "0x" + string(rune('1'+i))})
		writer.Write(event)
	}
	writer.Close()

	// Verify valid log
	count, err := VerifyChain(logPath)
	if err != nil {
		t.Errorf("VerifyChain() error = %v", err)
	}
	if count != 5 {
		t.Errorf("VerifyChain() count = %d, want 5", count)
	}
}

func TestVerifyChainTampering(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.jsonl")

	// Create valid log
	writer, _ := NewFileWriter(logPath)
	for i := 0; i < 3; i++ {
		event := NewEvent(EventCertIssued, ResultSuccess)
		writer.Write(event)
	}
	writer.Close()

	// Read and tamper with the log
	data, _ := os.ReadFile(logPath)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")

	// Modify the second line
	var event Event
	json.Unmarshal([]byte(lines[1]), &event)
	event.Object.Serial = "TAMPERED"
	tamperedLine, _ := event.JSON()
	lines[1] = string(tamperedLine)

	os.WriteFile(logPath, []byte(strings.Join(lines, "\n")+"\n"), 0644)

	// Verify should fail
	count, err := VerifyChain(logPath)
	if err == nil {
		t.Error("VerifyChain() should fail on tampered log")
	}
	if count != 1 {
		t.Errorf("VerifyChain() count = %d, want 1 (events before tampering)", count)
	}
}

func TestNopWriter(t *testing.T) {
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

func TestGlobalAudit(t *testing.T) {
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

func TestHelperFunctions(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.jsonl")

	if err := InitFile(logPath); err != nil {
		t.Fatalf("InitFile() error = %v", err)
	}
	defer Close()

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

	Close()

	// Verify all events
	count, err := VerifyChain(logPath)
	if err != nil {
		t.Errorf("VerifyChain() error = %v", err)
	}
	if count != 5 {
		t.Errorf("VerifyChain() count = %d, want 5", count)
	}
}
