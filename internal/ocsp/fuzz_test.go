package ocsp

import (
	"testing"
)

// =============================================================================
// Fuzz Tests
// =============================================================================

// FuzzU_ParseRequest tests that parsing arbitrary OCSP request data doesn't panic.
func FuzzU_ParseRequest(f *testing.F) {
	// Seed corpus with valid and edge case inputs
	f.Add([]byte{0x30, 0x00})                   // Empty SEQUENCE
	f.Add([]byte{0x30, 0x03, 0x30, 0x01, 0x00}) // Nested SEQUENCE
	f.Add([]byte{0x30, 0x80})                   // Indefinite length
	f.Add([]byte{0x00, 0x00, 0x00, 0x00})       // Null bytes
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})       // All 1s
	f.Add([]byte{0xa0, 0x00})                   // Context-specific tag

	f.Fuzz(func(t *testing.T, data []byte) {
		// ParseRequest should not panic regardless of input
		_, _ = ParseRequest(data)
	})
}

// FuzzU_ParseResponse tests that parsing arbitrary OCSP response data doesn't panic.
func FuzzU_ParseResponse(f *testing.F) {
	// Seed corpus
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte{0x30, 0x03, 0x0a, 0x01, 0x00}) // With responseStatus
	f.Add([]byte{0x30, 0x80})
	f.Add([]byte{0x00, 0x00, 0x00, 0x00})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseResponse(data)
	})
}
