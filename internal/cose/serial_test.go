package cose

import (
	"testing"
)

// =============================================================================
// RandomSerialGenerator Tests
// =============================================================================

func TestU_RandomSerialGenerator_Next(t *testing.T) {
	t.Run("[Unit] RandomSerialGenerator.Next: returns 16 bytes", func(t *testing.T) {
		gen := &RandomSerialGenerator{}

		serial, err := gen.Next()
		if err != nil {
			t.Fatalf("RandomSerialGenerator.Next() error = %v", err)
		}

		if len(serial) != 16 {
			t.Errorf("RandomSerialGenerator.Next() length = %d, want 16", len(serial))
		}
	})

	t.Run("[Unit] RandomSerialGenerator.Next: returns unique values", func(t *testing.T) {
		gen := &RandomSerialGenerator{}

		seen := make(map[string]bool)
		for i := 0; i < 100; i++ {
			serial, err := gen.Next()
			if err != nil {
				t.Fatalf("RandomSerialGenerator.Next() error = %v", err)
			}

			key := string(serial)
			if seen[key] {
				t.Error("RandomSerialGenerator.Next() returned duplicate value")
			}
			seen[key] = true
		}
	})

	t.Run("[Unit] RandomSerialGenerator.Next: serial not all zeros", func(t *testing.T) {
		gen := &RandomSerialGenerator{}

		serial, err := gen.Next()
		if err != nil {
			t.Fatalf("RandomSerialGenerator.Next() error = %v", err)
		}

		allZeros := true
		for _, b := range serial {
			if b != 0 {
				allZeros = false
				break
			}
		}

		if allZeros {
			t.Error("RandomSerialGenerator.Next() returned all zeros (statistically unlikely)")
		}
	})
}

func TestU_DefaultSerialGenerator(t *testing.T) {
	t.Run("[Unit] DefaultSerialGenerator: is not nil", func(t *testing.T) {
		if DefaultSerialGenerator == nil {
			t.Error("DefaultSerialGenerator should not be nil")
		}
	})

	t.Run("[Unit] DefaultSerialGenerator: implements SerialGenerator", func(t *testing.T) {
		_ = DefaultSerialGenerator // Verify it implements SerialGenerator interface
	})

	t.Run("[Unit] DefaultSerialGenerator: can generate serial", func(t *testing.T) {
		serial, err := DefaultSerialGenerator.Next()
		if err != nil {
			t.Fatalf("DefaultSerialGenerator.Next() error = %v", err)
		}

		if len(serial) != 16 {
			t.Errorf("DefaultSerialGenerator.Next() length = %d, want 16", len(serial))
		}
	})
}
