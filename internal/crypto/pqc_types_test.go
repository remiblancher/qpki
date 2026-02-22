package crypto

import (
	"bytes"
	"testing"
)

// =============================================================================
// MLDSAPublicKey Tests
// =============================================================================

func TestU_MLDSAPublicKey_Bytes(t *testing.T) {
	t.Run("[Unit] MLDSAPublicKey.Bytes: returns public key bytes", func(t *testing.T) {
		expected := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
		key := &MLDSAPublicKey{
			Algorithm: AlgMLDSA65,
			PublicKey: expected,
		}

		result := key.Bytes()
		if !bytes.Equal(result, expected) {
			t.Errorf("MLDSAPublicKey.Bytes() = %v, want %v", result, expected)
		}
	})

	t.Run("[Unit] MLDSAPublicKey.Bytes: returns nil for nil public key", func(t *testing.T) {
		key := &MLDSAPublicKey{
			Algorithm: AlgMLDSA65,
			PublicKey: nil,
		}

		result := key.Bytes()
		if result != nil {
			t.Errorf("MLDSAPublicKey.Bytes() = %v, want nil", result)
		}
	})

	t.Run("[Unit] MLDSAPublicKey.Bytes: returns empty slice for empty public key", func(t *testing.T) {
		key := &MLDSAPublicKey{
			Algorithm: AlgMLDSA44,
			PublicKey: []byte{},
		}

		result := key.Bytes()
		if len(result) != 0 {
			t.Errorf("MLDSAPublicKey.Bytes() length = %d, want 0", len(result))
		}
	})
}

func TestU_MLDSAPublicKey_Struct(t *testing.T) {
	t.Run("[Unit] MLDSAPublicKey: stores algorithm correctly", func(t *testing.T) {
		tests := []struct {
			name string
			alg  AlgorithmID
		}{
			{"ML-DSA-44", AlgMLDSA44},
			{"ML-DSA-65", AlgMLDSA65},
			{"ML-DSA-87", AlgMLDSA87},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				key := &MLDSAPublicKey{
					Algorithm: tt.alg,
					PublicKey: []byte{0x01},
				}

				if key.Algorithm != tt.alg {
					t.Errorf("MLDSAPublicKey.Algorithm = %v, want %v", key.Algorithm, tt.alg)
				}
			})
		}
	})
}

// =============================================================================
// MLKEMPublicKey Tests
// =============================================================================

func TestU_MLKEMPublicKey_Bytes(t *testing.T) {
	t.Run("[Unit] MLKEMPublicKey.Bytes: returns public key bytes", func(t *testing.T) {
		expected := []byte{0x0A, 0x0B, 0x0C, 0x0D, 0x0E}
		key := &MLKEMPublicKey{
			Algorithm: AlgMLKEM768,
			PublicKey: expected,
		}

		result := key.Bytes()
		if !bytes.Equal(result, expected) {
			t.Errorf("MLKEMPublicKey.Bytes() = %v, want %v", result, expected)
		}
	})

	t.Run("[Unit] MLKEMPublicKey.Bytes: returns nil for nil public key", func(t *testing.T) {
		key := &MLKEMPublicKey{
			Algorithm: AlgMLKEM768,
			PublicKey: nil,
		}

		result := key.Bytes()
		if result != nil {
			t.Errorf("MLKEMPublicKey.Bytes() = %v, want nil", result)
		}
	})

	t.Run("[Unit] MLKEMPublicKey.Bytes: returns empty slice for empty public key", func(t *testing.T) {
		key := &MLKEMPublicKey{
			Algorithm: AlgMLKEM512,
			PublicKey: []byte{},
		}

		result := key.Bytes()
		if len(result) != 0 {
			t.Errorf("MLKEMPublicKey.Bytes() length = %d, want 0", len(result))
		}
	})
}

func TestU_MLKEMPublicKey_Struct(t *testing.T) {
	t.Run("[Unit] MLKEMPublicKey: stores algorithm correctly", func(t *testing.T) {
		tests := []struct {
			name string
			alg  AlgorithmID
		}{
			{"ML-KEM-512", AlgMLKEM512},
			{"ML-KEM-768", AlgMLKEM768},
			{"ML-KEM-1024", AlgMLKEM1024},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				key := &MLKEMPublicKey{
					Algorithm: tt.alg,
					PublicKey: []byte{0x01},
				}

				if key.Algorithm != tt.alg {
					t.Errorf("MLKEMPublicKey.Algorithm = %v, want %v", key.Algorithm, tt.alg)
				}
			})
		}
	})
}

// =============================================================================
// Large Key Size Tests
// =============================================================================

func TestU_PQCPublicKey_LargeKeys(t *testing.T) {
	t.Run("[Unit] MLDSAPublicKey.Bytes: handles ML-DSA-87 size key", func(t *testing.T) {
		// ML-DSA-87 public key is 2592 bytes
		largeKey := make([]byte, 2592)
		for i := range largeKey {
			largeKey[i] = byte(i % 256)
		}

		key := &MLDSAPublicKey{
			Algorithm: AlgMLDSA87,
			PublicKey: largeKey,
		}

		result := key.Bytes()
		if len(result) != 2592 {
			t.Errorf("MLDSAPublicKey.Bytes() length = %d, want 2592", len(result))
		}
		if !bytes.Equal(result, largeKey) {
			t.Error("MLDSAPublicKey.Bytes() returned incorrect data for large key")
		}
	})

	t.Run("[Unit] MLKEMPublicKey.Bytes: handles ML-KEM-1024 size key", func(t *testing.T) {
		// ML-KEM-1024 public key is 1568 bytes
		largeKey := make([]byte, 1568)
		for i := range largeKey {
			largeKey[i] = byte(i % 256)
		}

		key := &MLKEMPublicKey{
			Algorithm: AlgMLKEM1024,
			PublicKey: largeKey,
		}

		result := key.Bytes()
		if len(result) != 1568 {
			t.Errorf("MLKEMPublicKey.Bytes() length = %d, want 1568", len(result))
		}
		if !bytes.Equal(result, largeKey) {
			t.Error("MLKEMPublicKey.Bytes() returned incorrect data for large key")
		}
	})
}
