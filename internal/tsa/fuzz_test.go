package tsa

import (
	"testing"
)

// =============================================================================
// Request Parsing Fuzz Tests
// =============================================================================

// FuzzU_Request_Parse tests that parsing arbitrary TSA request data doesn't panic.
func FuzzU_Request_Parse(f *testing.F) {
	// Seed corpus with valid and edge case inputs
	f.Add([]byte{0x30, 0x00})                           // Empty SEQUENCE
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x01})         // Simple SEQUENCE with version
	f.Add([]byte{0x30, 0x80})                           // Indefinite length
	f.Add([]byte{0x00, 0x00, 0x00, 0x00})               // Null bytes
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})               // All 1s

	f.Fuzz(func(t *testing.T, data []byte) {
		// ParseRequest should not panic regardless of input
		_, _ = ParseRequest(data)
	})
}

// =============================================================================
// Response Parsing Fuzz Tests
// =============================================================================

// FuzzU_Response_Parse tests that parsing arbitrary TSA response data doesn't panic.
func FuzzU_Response_Parse(f *testing.F) {
	// Seed corpus
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte{0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x00})
	f.Add([]byte{0x30, 0x80})
	f.Add([]byte{0x00, 0x00, 0x00, 0x00})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseResponse(data)
	})
}

// =============================================================================
// Token Parsing Fuzz Tests
// =============================================================================

// FuzzU_Token_Parse tests that parsing arbitrary TSA token data doesn't panic.
func FuzzU_Token_Parse(f *testing.F) {
	// Seed corpus
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x01})
	f.Add([]byte{0x30, 0x80})
	f.Add([]byte{0x00, 0x00, 0x00, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseToken(data)
	})
}
