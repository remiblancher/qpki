package cms

import (
	"context"
	"testing"
)

// FuzzParseSignedData tests that parsing arbitrary data doesn't panic.
func FuzzParseSignedData(f *testing.F) {
	// Seed corpus with valid and edge case inputs
	f.Add([]byte{0x30, 0x00})                   // Empty SEQUENCE
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x03}) // Simple SEQUENCE with INTEGER
	f.Add([]byte{0x30, 0x80})                   // Indefinite length
	f.Add([]byte{0xa0, 0x00})                   // Context-specific tag
	f.Add([]byte{0x00, 0x00, 0x00, 0x00})       // Null bytes
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})       // All 1s

	f.Fuzz(func(t *testing.T, data []byte) {
		// Parse should not panic regardless of input
		// Errors are expected and fine
		_, _ = Verify(context.Background(), data, nil)
	})
}

// FuzzParseEnvelopedData tests that parsing arbitrary data doesn't panic.
func FuzzParseEnvelopedData(f *testing.F) {
	// Seed corpus
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x02})
	f.Add([]byte{0x30, 0x80})
	f.Add([]byte{0xa0, 0x00})
	f.Add([]byte{0x00, 0x00, 0x00, 0x00})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Decrypt should not panic regardless of input
		_, _ = Decrypt(context.Background(), data, &DecryptOptions{})
	})
}

// FuzzParseRecipientIdentifier tests RecipientIdentifier parsing.
func FuzzParseRecipientIdentifier(f *testing.F) {
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte{0x80, 0x04, 0x01, 0x02, 0x03, 0x04})       // [0] SKI
	f.Add([]byte{0x30, 0x06, 0x30, 0x00, 0x02, 0x01, 0x01}) // IssuerAndSerial

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = ParseRecipientIdentifier(data)
	})
}

// FuzzParseKeyTransRecipientInfo tests KeyTransRecipientInfo parsing.
func FuzzParseKeyTransRecipientInfo(f *testing.F) {
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseKeyTransRecipientInfo(data)
	})
}

// FuzzParseKeyAgreeRecipientInfo tests KeyAgreeRecipientInfo parsing.
func FuzzParseKeyAgreeRecipientInfo(f *testing.F) {
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte{0x02, 0x01, 0x03})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseKeyAgreeRecipientInfo(data)
	})
}

// FuzzParseKEMRecipientInfo tests KEMRecipientInfo parsing.
func FuzzParseKEMRecipientInfo(f *testing.F) {
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte{0x02, 0x01, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseKEMRecipientInfo(data)
	})
}
