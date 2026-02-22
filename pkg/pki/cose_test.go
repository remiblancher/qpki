package pki

import (
	"testing"
)

// =============================================================================
// COSENewClaims Tests
// =============================================================================

func TestU_COSENewClaims(t *testing.T) {
	t.Run("[Unit] COSENewClaims: returns non-nil claims", func(t *testing.T) {
		claims := COSENewClaims()
		if claims == nil {
			t.Error("COSENewClaims() returned nil")
		}
	})
}

// =============================================================================
// COSEParse Tests
// =============================================================================

func TestU_COSEParse(t *testing.T) {
	t.Run("[Unit] COSEParse: invalid data", func(t *testing.T) {
		_, err := COSEParse([]byte("not valid CBOR data"))
		if err == nil {
			t.Error("COSEParse() should fail for invalid data")
		}
	})

	t.Run("[Unit] COSEParse: empty data", func(t *testing.T) {
		_, err := COSEParse([]byte{})
		if err == nil {
			t.Error("COSEParse() should fail for empty data")
		}
	})
}

// =============================================================================
// COSEParseSign1 Tests
// =============================================================================

func TestU_COSEParseSign1(t *testing.T) {
	t.Run("[Unit] COSEParseSign1: invalid data", func(t *testing.T) {
		_, err := COSEParseSign1([]byte("not valid CBOR data"))
		if err == nil {
			t.Error("COSEParseSign1() should fail for invalid data")
		}
	})
}

// =============================================================================
// COSEParseCWT Tests
// =============================================================================

func TestU_COSEParseCWT(t *testing.T) {
	t.Run("[Unit] COSEParseCWT: invalid data", func(t *testing.T) {
		_, err := COSEParseCWT([]byte("not valid CWT data"))
		if err == nil {
			t.Error("COSEParseCWT() should fail for invalid data")
		}
	})
}

// =============================================================================
// COSEGetInfo Tests
// =============================================================================

func TestU_COSEGetInfo(t *testing.T) {
	t.Run("[Unit] COSEGetInfo: invalid data", func(t *testing.T) {
		_, err := COSEGetInfo([]byte("not valid COSE data"))
		if err == nil {
			t.Error("COSEGetInfo() should fail for invalid data")
		}
	})
}

// =============================================================================
// COSEAlgorithmName Tests
// =============================================================================

func TestU_COSEAlgorithmName(t *testing.T) {
	t.Run("[Unit] COSEAlgorithmName: returns name for algorithm", func(t *testing.T) {
		// Test with a known algorithm constant
		// ES256 = -7 in COSE
		name := COSEAlgorithmName(COSEAlgorithm(-7))
		if name == "" {
			t.Error("COSEAlgorithmName() returned empty string for ES256")
		}
	})

	t.Run("[Unit] COSEAlgorithmName: handles unknown algorithm", func(t *testing.T) {
		// Unknown algorithm should return some string (possibly "unknown" or the number)
		name := COSEAlgorithmName(COSEAlgorithm(99999))
		// Just verify it doesn't panic
		_ = name
	})
}

// =============================================================================
// COSE Constants Tests
// =============================================================================

func TestU_COSEConstants(t *testing.T) {
	t.Run("[Unit] COSEConstants: message types are defined", func(t *testing.T) {
		types := []COSEMessageType{
			COSETypeCWT,
			COSETypeSign1,
			COSETypeSign,
		}

		for _, typ := range types {
			// Just verify constants are accessible
			_ = typ
		}
	})

	t.Run("[Unit] COSEConstants: signing modes are defined", func(t *testing.T) {
		modes := []COSESigningMode{
			COSEModeClassical,
			COSEModePQC,
			COSEModeHybrid,
		}

		for _, mode := range modes {
			// Just verify constants are accessible
			_ = mode
		}
	})
}

// =============================================================================
// COSE Type Aliases Tests
// =============================================================================

func TestU_COSETypes(t *testing.T) {
	t.Run("[Unit] COSETypes: COSEMessageConfig can be instantiated", func(t *testing.T) {
		cfg := &COSEMessageConfig{}
		_ = cfg // verify it compiles
	})

	t.Run("[Unit] COSETypes: COSECWTConfig can be instantiated", func(t *testing.T) {
		cfg := &COSECWTConfig{}
		_ = cfg // verify it compiles
	})

	t.Run("[Unit] COSETypes: COSEVerifyConfig can be instantiated", func(t *testing.T) {
		cfg := &COSEVerifyConfig{}
		_ = cfg // verify it compiles
	})
}
