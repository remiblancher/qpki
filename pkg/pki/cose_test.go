package pki

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
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

// =============================================================================
// COSE Test Helpers
// =============================================================================

// generateCOSETestKey generates an ECDSA key pair for COSE testing.
func generateCOSETestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}
	return key
}

// generateCOSETestCertificate creates a self-signed certificate for COSE testing.
func generateCOSETestCertificate(t *testing.T, key *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "COSE Test Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

// =============================================================================
// COSENewSigner Tests
// =============================================================================

func TestU_COSENewSigner(t *testing.T) {
	t.Run("[Unit] COSENewSigner: creates signer from ECDSA key", func(t *testing.T) {
		key := generateCOSETestKey(t)

		signer, err := COSENewSigner(key)
		if err != nil {
			t.Fatalf("COSENewSigner() error = %v", err)
		}
		if signer == nil {
			t.Error("COSENewSigner() returned nil")
		}
	})
}

// =============================================================================
// COSENewVerifier Tests
// =============================================================================

func TestU_COSENewVerifier(t *testing.T) {
	t.Run("[Unit] COSENewVerifier: creates verifier from ECDSA public key", func(t *testing.T) {
		key := generateCOSETestKey(t)

		verifier, err := COSENewVerifier(&key.PublicKey)
		if err != nil {
			t.Fatalf("COSENewVerifier() error = %v", err)
		}
		if verifier == nil {
			t.Error("COSENewVerifier() returned nil")
		}
	})
}

// =============================================================================
// COSEIssueSign1 and COSEVerifySign1 Tests
// =============================================================================

func TestU_COSEIssueSign1(t *testing.T) {
	t.Run("[Unit] COSEIssueSign1: creates Sign1 message", func(t *testing.T) {
		key := generateCOSETestKey(t)
		cert := generateCOSETestCertificate(t, key)

		payload := []byte("Hello, COSE!")
		config := &COSEMessageConfig{
			Signer:      key, // Use crypto.Signer directly
			Certificate: cert,
		}

		signedData, err := COSEIssueSign1(context.Background(), payload, config)
		if err != nil {
			t.Fatalf("COSEIssueSign1() error = %v", err)
		}
		if len(signedData) == 0 {
			t.Error("COSEIssueSign1() returned empty data")
		}
	})

	t.Run("[Unit] COSEIssueSign1: fails without signer", func(t *testing.T) {
		config := &COSEMessageConfig{}

		_, err := COSEIssueSign1(context.Background(), []byte("test"), config)
		if err == nil {
			t.Error("COSEIssueSign1() should fail without signer")
		}
	})
}

func TestU_COSEVerifySign1(t *testing.T) {
	t.Run("[Unit] COSEVerifySign1: verifies valid signature", func(t *testing.T) {
		key := generateCOSETestKey(t)
		cert := generateCOSETestCertificate(t, key)

		payload := []byte("Verifiable payload")
		config := &COSEMessageConfig{
			Signer:      key, // Use crypto.Signer directly
			Certificate: cert,
		}

		signedData, err := COSEIssueSign1(context.Background(), payload, config)
		if err != nil {
			t.Fatalf("COSEIssueSign1() error = %v", err)
		}

		verifyConfig := &COSEVerifyConfig{
			PublicKey: &key.PublicKey,
		}

		result, err := COSEVerifySign1(signedData, verifyConfig)
		if err != nil {
			t.Fatalf("COSEVerifySign1() error = %v", err)
		}
		if result == nil {
			t.Error("COSEVerifySign1() returned nil result")
		}
	})

	t.Run("[Unit] COSEVerifySign1: fails with invalid data", func(t *testing.T) {
		_, err := COSEVerifySign1([]byte("invalid"), nil)
		if err == nil {
			t.Error("COSEVerifySign1() should fail with invalid data")
		}
	})
}

// =============================================================================
// COSEIssueCWT and COSEVerifyCWT Tests
// =============================================================================

func TestU_COSEIssueCWT(t *testing.T) {
	t.Run("[Unit] COSEIssueCWT: creates CWT with claims", func(t *testing.T) {
		key := generateCOSETestKey(t)
		cert := generateCOSETestCertificate(t, key)

		claims := COSENewClaims()
		claims.Subject = "test-subject"
		claims.Issuer = "test-issuer"

		config := &COSECWTConfig{
			Claims: claims,
			MessageConfig: COSEMessageConfig{
				Signer:      key, // Use crypto.Signer directly
				Certificate: cert,
			},
		}

		cwt, err := COSEIssueCWT(context.Background(), config)
		if err != nil {
			t.Fatalf("COSEIssueCWT() error = %v", err)
		}
		if len(cwt) == 0 {
			t.Error("COSEIssueCWT() returned empty data")
		}
	})

	t.Run("[Unit] COSEIssueCWT: fails without claims", func(t *testing.T) {
		key := generateCOSETestKey(t)
		cert := generateCOSETestCertificate(t, key)

		config := &COSECWTConfig{
			MessageConfig: COSEMessageConfig{
				Signer:      key, // Use crypto.Signer directly
				Certificate: cert,
			},
		}

		_, err := COSEIssueCWT(context.Background(), config)
		if err == nil {
			t.Error("COSEIssueCWT() should fail without claims")
		}
	})
}

func TestU_COSEVerifyCWT(t *testing.T) {
	t.Run("[Unit] COSEVerifyCWT: verifies valid CWT", func(t *testing.T) {
		key := generateCOSETestKey(t)
		cert := generateCOSETestCertificate(t, key)

		claims := COSENewClaims()
		claims.Subject = "cwt-subject"

		config := &COSECWTConfig{
			Claims: claims,
			MessageConfig: COSEMessageConfig{
				Signer:      key, // Use crypto.Signer directly
				Certificate: cert,
			},
		}

		cwt, err := COSEIssueCWT(context.Background(), config)
		if err != nil {
			t.Fatalf("COSEIssueCWT() error = %v", err)
		}

		verifyConfig := &COSEVerifyConfig{
			PublicKey: &key.PublicKey,
		}

		result, err := COSEVerifyCWT(cwt, verifyConfig)
		if err != nil {
			t.Fatalf("COSEVerifyCWT() error = %v", err)
		}
		if result == nil {
			t.Error("COSEVerifyCWT() returned nil result")
		}
	})

	t.Run("[Unit] COSEVerifyCWT: fails with invalid data", func(t *testing.T) {
		_, err := COSEVerifyCWT([]byte("invalid"), nil)
		if err == nil {
			t.Error("COSEVerifyCWT() should fail with invalid data")
		}
	})
}

// =============================================================================
// COSEVerifyWithTime Tests
// =============================================================================

func TestU_COSEVerifyWithTime(t *testing.T) {
	t.Run("[Unit] COSEVerifyWithTime: verifies with specific time", func(t *testing.T) {
		key := generateCOSETestKey(t)
		cert := generateCOSETestCertificate(t, key)

		claims := COSENewClaims()
		claims.Subject = "time-test"

		config := &COSECWTConfig{
			Claims: claims,
			MessageConfig: COSEMessageConfig{
				Signer:      key, // Use crypto.Signer directly
				Certificate: cert,
			},
		}

		cwt, err := COSEIssueCWT(context.Background(), config)
		if err != nil {
			t.Fatalf("COSEIssueCWT() error = %v", err)
		}

		verifyConfig := &COSEVerifyConfig{
			PublicKey: &key.PublicKey,
		}

		// Verify with current time
		result, err := COSEVerifyWithTime(cwt, verifyConfig, time.Now())
		if err != nil {
			t.Fatalf("COSEVerifyWithTime() error = %v", err)
		}
		if result == nil {
			t.Error("COSEVerifyWithTime() returned nil result")
		}
	})
}
