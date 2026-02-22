package pki

import (
	"crypto"
	"math/big"
	"testing"
)

// =============================================================================
// TSACreateRequest Tests
// =============================================================================

func TestU_TSACreateRequest(t *testing.T) {
	t.Run("[Unit] TSACreateRequest: with SHA-256", func(t *testing.T) {
		data := []byte("test data to timestamp")
		req, err := TSACreateRequest(data, crypto.SHA256, nil, false)
		if err != nil {
			t.Fatalf("TSACreateRequest() error = %v", err)
		}
		if req == nil {
			t.Error("TSACreateRequest() returned nil")
		}
	})

	t.Run("[Unit] TSACreateRequest: with nonce", func(t *testing.T) {
		data := []byte("test data")
		nonce := big.NewInt(12345)
		req, err := TSACreateRequest(data, crypto.SHA256, nonce, false)
		if err != nil {
			t.Fatalf("TSACreateRequest() error = %v", err)
		}
		if req == nil {
			t.Error("TSACreateRequest() returned nil")
		}
	})

	t.Run("[Unit] TSACreateRequest: with cert request", func(t *testing.T) {
		data := []byte("test data")
		req, err := TSACreateRequest(data, crypto.SHA256, nil, true)
		if err != nil {
			t.Fatalf("TSACreateRequest() error = %v", err)
		}
		if req == nil {
			t.Error("TSACreateRequest() returned nil")
		}
	})
}

// =============================================================================
// TSAParseRequest Tests
// =============================================================================

func TestU_TSAParseRequest(t *testing.T) {
	t.Run("[Unit] TSAParseRequest: invalid data", func(t *testing.T) {
		_, err := TSAParseRequest([]byte("not valid TSA request"))
		if err == nil {
			t.Error("TSAParseRequest() should fail for invalid data")
		}
	})

	t.Run("[Unit] TSAParseRequest: empty data", func(t *testing.T) {
		_, err := TSAParseRequest([]byte{})
		if err == nil {
			t.Error("TSAParseRequest() should fail for empty data")
		}
	})

	t.Run("[Unit] TSAParseRequest: roundtrip", func(t *testing.T) {
		data := []byte("test data")
		req, err := TSACreateRequest(data, crypto.SHA256, nil, false)
		if err != nil {
			t.Fatalf("TSACreateRequest() error = %v", err)
		}

		encoded, err := req.Marshal()
		if err != nil {
			t.Fatalf("Request.Marshal() error = %v", err)
		}

		parsed, err := TSAParseRequest(encoded)
		if err != nil {
			t.Fatalf("TSAParseRequest() error = %v", err)
		}
		if parsed == nil {
			t.Error("TSAParseRequest() returned nil")
		}
	})
}

// =============================================================================
// TSAParseToken Tests
// =============================================================================

func TestU_TSAParseToken(t *testing.T) {
	t.Run("[Unit] TSAParseToken: invalid data", func(t *testing.T) {
		_, err := TSAParseToken([]byte("not valid TSA token"))
		if err == nil {
			t.Error("TSAParseToken() should fail for invalid data")
		}
	})

	t.Run("[Unit] TSAParseToken: empty data", func(t *testing.T) {
		_, err := TSAParseToken([]byte{})
		if err == nil {
			t.Error("TSAParseToken() should fail for empty data")
		}
	})
}

// =============================================================================
// TSAParseResponse Tests
// =============================================================================

func TestU_TSAParseResponse(t *testing.T) {
	t.Run("[Unit] TSAParseResponse: invalid data", func(t *testing.T) {
		_, err := TSAParseResponse([]byte("not valid TSA response"))
		if err == nil {
			t.Error("TSAParseResponse() should fail for invalid data")
		}
	})

	t.Run("[Unit] TSAParseResponse: empty data", func(t *testing.T) {
		_, err := TSAParseResponse([]byte{})
		if err == nil {
			t.Error("TSAParseResponse() should fail for empty data")
		}
	})
}

// =============================================================================
// TSANewMessageImprint Tests
// =============================================================================

func TestU_TSANewMessageImprint(t *testing.T) {
	t.Run("[Unit] TSANewMessageImprint: with SHA-256", func(t *testing.T) {
		digest := make([]byte, 32) // SHA-256 digest size
		imprint := TSANewMessageImprint(crypto.SHA256, digest)
		// Just verify it doesn't panic
		_ = imprint
	})

	t.Run("[Unit] TSANewMessageImprint: with SHA-384", func(t *testing.T) {
		digest := make([]byte, 48) // SHA-384 digest size
		imprint := TSANewMessageImprint(crypto.SHA384, digest)
		_ = imprint
	})
}

// =============================================================================
// TSANewGrantedResponse Tests
// =============================================================================

func TestU_TSANewGrantedResponse(t *testing.T) {
	t.Run("[Unit] TSANewGrantedResponse: with nil token", func(t *testing.T) {
		resp := TSANewGrantedResponse(nil)
		if resp == nil {
			t.Error("TSANewGrantedResponse() returned nil")
		}
	})
}

// =============================================================================
// TSANewRejectionResponse Tests
// =============================================================================

func TestU_TSANewRejectionResponse(t *testing.T) {
	t.Run("[Unit] TSANewRejectionResponse: with message", func(t *testing.T) {
		resp := TSANewRejectionResponse(1, "Request rejected")
		if resp == nil {
			t.Error("TSANewRejectionResponse() returned nil")
		}
	})

	t.Run("[Unit] TSANewRejectionResponse: empty message", func(t *testing.T) {
		resp := TSANewRejectionResponse(0, "")
		if resp == nil {
			t.Error("TSANewRejectionResponse() returned nil")
		}
	})
}

// =============================================================================
// TSA Type Aliases Tests
// =============================================================================

func TestU_TSATypes(t *testing.T) {
	t.Run("[Unit] TSATypes: TSATokenConfig can be instantiated", func(t *testing.T) {
		cfg := &TSATokenConfig{}
		_ = cfg // verify it compiles
	})

	t.Run("[Unit] TSATypes: TSAVerifyConfig can be instantiated", func(t *testing.T) {
		cfg := &TSAVerifyConfig{}
		_ = cfg // verify it compiles
	})
}

// =============================================================================
// TSACreateRequest with different hash algorithms
// =============================================================================

func TestU_TSACreateRequest_HashAlgorithms(t *testing.T) {
	data := []byte("test data for hashing")

	t.Run("[Unit] TSACreateRequest: SHA-384", func(t *testing.T) {
		req, err := TSACreateRequest(data, crypto.SHA384, nil, false)
		if err != nil {
			t.Fatalf("TSACreateRequest(SHA384) error = %v", err)
		}
		if req == nil {
			t.Error("TSACreateRequest(SHA384) returned nil")
		}
	})

	t.Run("[Unit] TSACreateRequest: SHA-512", func(t *testing.T) {
		req, err := TSACreateRequest(data, crypto.SHA512, nil, false)
		if err != nil {
			t.Fatalf("TSACreateRequest(SHA512) error = %v", err)
		}
		if req == nil {
			t.Error("TSACreateRequest(SHA512) returned nil")
		}
	})

	t.Run("[Unit] TSACreateRequest: with all options", func(t *testing.T) {
		nonce := big.NewInt(9876543210)
		req, err := TSACreateRequest(data, crypto.SHA256, nonce, true)
		if err != nil {
			t.Fatalf("TSACreateRequest() error = %v", err)
		}
		if req == nil {
			t.Error("TSACreateRequest() returned nil")
		}
	})
}
