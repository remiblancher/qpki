package pki

import (
	"testing"
)

// =============================================================================
// CMSParseSignedData Tests
// =============================================================================

func TestU_CMSParseSignedData(t *testing.T) {
	t.Run("[Unit] CMSParseSignedData: invalid data", func(t *testing.T) {
		_, err := CMSParseSignedData([]byte("not valid CMS data"))
		if err == nil {
			t.Error("CMSParseSignedData() should fail for invalid data")
		}
	})

	t.Run("[Unit] CMSParseSignedData: empty data", func(t *testing.T) {
		_, err := CMSParseSignedData([]byte{})
		if err == nil {
			t.Error("CMSParseSignedData() should fail for empty data")
		}
	})

	t.Run("[Unit] CMSParseSignedData: nil data", func(t *testing.T) {
		_, err := CMSParseSignedData(nil)
		if err == nil {
			t.Error("CMSParseSignedData() should fail for nil data")
		}
	})
}

// =============================================================================
// CMSParseEnvelopedData Tests
// =============================================================================

func TestU_CMSParseEnvelopedData(t *testing.T) {
	t.Run("[Unit] CMSParseEnvelopedData: invalid data", func(t *testing.T) {
		_, err := CMSParseEnvelopedData([]byte("not valid CMS data"))
		if err == nil {
			t.Error("CMSParseEnvelopedData() should fail for invalid data")
		}
	})

	t.Run("[Unit] CMSParseEnvelopedData: empty data", func(t *testing.T) {
		_, err := CMSParseEnvelopedData([]byte{})
		if err == nil {
			t.Error("CMSParseEnvelopedData() should fail for empty data")
		}
	})
}

// =============================================================================
// CMSParseContentInfo Tests
// =============================================================================

func TestU_CMSParseContentInfo(t *testing.T) {
	t.Run("[Unit] CMSParseContentInfo: invalid data", func(t *testing.T) {
		_, err := CMSParseContentInfo([]byte("not valid ASN.1 data"))
		if err == nil {
			t.Error("CMSParseContentInfo() should fail for invalid data")
		}
	})

	t.Run("[Unit] CMSParseContentInfo: empty data", func(t *testing.T) {
		_, err := CMSParseContentInfo([]byte{})
		if err == nil {
			t.Error("CMSParseContentInfo() should fail for empty data")
		}
	})
}

// =============================================================================
// Type Aliases Tests
// =============================================================================

func TestU_CMSTypes(t *testing.T) {
	// Test that type aliases are properly defined by checking
	// that we can create instances of the types

	t.Run("[Unit] CMSTypes: CMSSignerConfig can be instantiated", func(t *testing.T) {
		cfg := &CMSSignerConfig{}
		_ = cfg // verify it compiles
	})

	t.Run("[Unit] CMSTypes: CMSEncryptOptions can be instantiated", func(t *testing.T) {
		opts := &CMSEncryptOptions{}
		_ = opts // verify it compiles
	})

	t.Run("[Unit] CMSTypes: CMSDecryptOptions can be instantiated", func(t *testing.T) {
		opts := &CMSDecryptOptions{}
		_ = opts // verify it compiles
	})

	t.Run("[Unit] CMSTypes: CMSVerifyConfig can be instantiated", func(t *testing.T) {
		cfg := &CMSVerifyConfig{}
		_ = cfg // verify it compiles
	})
}
