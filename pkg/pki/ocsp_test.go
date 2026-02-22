package pki

import (
	"crypto"
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
// OCSPParseRequest Tests
// =============================================================================

func TestU_OCSPParseRequest(t *testing.T) {
	t.Run("[Unit] OCSPParseRequest: invalid data", func(t *testing.T) {
		_, err := OCSPParseRequest([]byte("not valid OCSP data"))
		if err == nil {
			t.Error("OCSPParseRequest() should fail for invalid data")
		}
	})

	t.Run("[Unit] OCSPParseRequest: empty data", func(t *testing.T) {
		_, err := OCSPParseRequest([]byte{})
		if err == nil {
			t.Error("OCSPParseRequest() should fail for empty data")
		}
	})
}

// =============================================================================
// OCSPParseResponse Tests
// =============================================================================

func TestU_OCSPParseResponse(t *testing.T) {
	t.Run("[Unit] OCSPParseResponse: invalid data", func(t *testing.T) {
		_, err := OCSPParseResponse([]byte("not valid OCSP response"))
		if err == nil {
			t.Error("OCSPParseResponse() should fail for invalid data")
		}
	})

	t.Run("[Unit] OCSPParseResponse: empty data", func(t *testing.T) {
		_, err := OCSPParseResponse([]byte{})
		if err == nil {
			t.Error("OCSPParseResponse() should fail for empty data")
		}
	})
}

// =============================================================================
// OCSPNewMalformedResponse Tests
// =============================================================================

func TestU_OCSPNewMalformedResponse(t *testing.T) {
	t.Run("[Unit] OCSPNewMalformedResponse: returns valid response", func(t *testing.T) {
		data, err := OCSPNewMalformedResponse()
		if err != nil {
			t.Fatalf("OCSPNewMalformedResponse() error = %v", err)
		}
		if len(data) == 0 {
			t.Error("OCSPNewMalformedResponse() returned empty data")
		}
	})
}

// =============================================================================
// OCSPNewInternalErrorResponse Tests
// =============================================================================

func TestU_OCSPNewInternalErrorResponse(t *testing.T) {
	t.Run("[Unit] OCSPNewInternalErrorResponse: returns valid response", func(t *testing.T) {
		data, err := OCSPNewInternalErrorResponse()
		if err != nil {
			t.Fatalf("OCSPNewInternalErrorResponse() error = %v", err)
		}
		if len(data) == 0 {
			t.Error("OCSPNewInternalErrorResponse() returned empty data")
		}
	})
}

// =============================================================================
// OCSP Certificate Status Constants Tests
// =============================================================================

func TestU_OCSPCertStatusConstants(t *testing.T) {
	t.Run("[Unit] OCSPCertStatusConstants: are defined", func(t *testing.T) {
		statuses := []OCSPCertStatus{
			OCSPCertStatusGood,
			OCSPCertStatusRevoked,
			OCSPCertStatusUnknown,
		}

		seen := make(map[OCSPCertStatus]bool)
		for _, s := range statuses {
			if seen[s] {
				t.Errorf("OCSPCertStatus %v is duplicated", s)
			}
			seen[s] = true
		}
	})
}

// =============================================================================
// OCSP Response Status Constants Tests
// =============================================================================

func TestU_OCSPResponseStatusConstants(t *testing.T) {
	t.Run("[Unit] OCSPResponseStatusConstants: are defined", func(t *testing.T) {
		statuses := []OCSPResponseStatus{
			OCSPStatusSuccessful,
			OCSPStatusMalformedRequest,
			OCSPStatusInternalError,
			OCSPStatusTryLater,
			OCSPStatusSigRequired,
			OCSPStatusUnauthorized,
		}

		for _, s := range statuses {
			// Just verify constants are accessible
			_ = s
		}
	})
}

// =============================================================================
// OCSP Revocation Reason Constants Tests
// =============================================================================

func TestU_OCSPRevocationReasonConstants(t *testing.T) {
	t.Run("[Unit] OCSPRevocationReasonConstants: are defined", func(t *testing.T) {
		reasons := []OCSPRevocationReason{
			OCSPReasonUnspecified,
			OCSPReasonKeyCompromise,
			OCSPReasonCACompromise,
			OCSPReasonAffiliationChanged,
			OCSPReasonSuperseded,
			OCSPReasonCessationOfOperation,
			OCSPReasonCertificateHold,
			OCSPReasonRemoveFromCRL,
			OCSPReasonPrivilegeWithdrawn,
			OCSPReasonAACompromise,
		}

		for _, r := range reasons {
			// Just verify constants are accessible
			_ = r
		}
	})
}

// =============================================================================
// OCSP Type Aliases Tests
// =============================================================================

func TestU_OCSPTypes(t *testing.T) {
	t.Run("[Unit] OCSPTypes: OCSPResponderConfig can be instantiated", func(t *testing.T) {
		cfg := &OCSPResponderConfig{}
		_ = cfg // verify it compiles
	})

	t.Run("[Unit] OCSPTypes: OCSPVerifyConfig can be instantiated", func(t *testing.T) {
		cfg := &OCSPVerifyConfig{}
		_ = cfg // verify it compiles
	})

	t.Run("[Unit] OCSPTypes: OCSPStatusInfo can be instantiated", func(t *testing.T) {
		info := &OCSPStatusInfo{}
		_ = info // verify it compiles
	})
}

// =============================================================================
// OCSPNewErrorResponse Tests
// =============================================================================

func TestU_OCSPNewErrorResponse(t *testing.T) {
	tests := []struct {
		name   string
		status OCSPResponseStatus
	}{
		{
			name:   "[Unit] OCSPNewErrorResponse: malformed request",
			status: OCSPStatusMalformedRequest,
		},
		{
			name:   "[Unit] OCSPNewErrorResponse: internal error",
			status: OCSPStatusInternalError,
		},
		{
			name:   "[Unit] OCSPNewErrorResponse: try later",
			status: OCSPStatusTryLater,
		},
		{
			name:   "[Unit] OCSPNewErrorResponse: sig required",
			status: OCSPStatusSigRequired,
		},
		{
			name:   "[Unit] OCSPNewErrorResponse: unauthorized",
			status: OCSPStatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := OCSPNewErrorResponse(tt.status)
			if err != nil {
				t.Fatalf("OCSPNewErrorResponse() error = %v", err)
			}
			if len(data) == 0 {
				t.Error("OCSPNewErrorResponse() returned empty data")
			}
		})
	}
}

// =============================================================================
// OCSP Test Helpers
// =============================================================================

// generateOCSPTestKey generates an ECDSA key pair for OCSP testing.
func generateOCSPTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}
	return key
}

// generateOCSPTestCertificate creates a self-signed certificate for OCSP testing.
func generateOCSPTestCertificate(t *testing.T, key *ecdsa.PrivateKey, isCA bool) *x509.Certificate {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "OCSP Test Certificate",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
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
// OCSPNewResponseBuilder Tests
// =============================================================================

func TestU_OCSPNewResponseBuilder(t *testing.T) {
	t.Run("[Unit] OCSPNewResponseBuilder: creates builder", func(t *testing.T) {
		key := generateOCSPTestKey(t)
		cert := generateOCSPTestCertificate(t, key, false)

		builder := OCSPNewResponseBuilder(cert, key)
		if builder == nil {
			t.Error("OCSPNewResponseBuilder() returned nil")
		}
	})
}

// =============================================================================
// OCSPCreateRequest Tests
// =============================================================================

func TestU_OCSPCreateRequest(t *testing.T) {
	t.Run("[Unit] OCSPCreateRequest: creates request", func(t *testing.T) {
		issuerKey := generateOCSPTestKey(t)
		issuerCert := generateOCSPTestCertificate(t, issuerKey, true)

		subjectKey := generateOCSPTestKey(t)
		subjectCert := generateOCSPTestCertificate(t, subjectKey, false)

		req, err := OCSPCreateRequest(issuerCert, []*x509.Certificate{subjectCert}, crypto.SHA256)
		if err != nil {
			t.Fatalf("OCSPCreateRequest() error = %v", err)
		}
		if req == nil {
			t.Error("OCSPCreateRequest() returned nil")
		}
	})

	t.Run("[Unit] OCSPCreateRequest: fails with empty certs", func(t *testing.T) {
		issuerKey := generateOCSPTestKey(t)
		issuerCert := generateOCSPTestCertificate(t, issuerKey, true)

		_, err := OCSPCreateRequest(issuerCert, []*x509.Certificate{}, crypto.SHA256)
		if err == nil {
			t.Error("OCSPCreateRequest() should fail with empty certs")
		}
	})
}

// =============================================================================
// OCSPNewResponder Tests
// =============================================================================

// Note: OCSPNewResponder requires a full CA setup with store, so we skip testing it here.
// Integration tests for the full OCSP responder are in internal/ocsp.

// =============================================================================
// OCSPVerify Tests
// =============================================================================

func TestU_OCSPVerify(t *testing.T) {
	t.Run("[Unit] OCSPVerify: fails with invalid data", func(t *testing.T) {
		_, err := OCSPVerify([]byte("invalid"), nil)
		if err == nil {
			t.Error("OCSPVerify() should fail with invalid data")
		}
	})

	t.Run("[Unit] OCSPVerify: fails with empty data", func(t *testing.T) {
		_, err := OCSPVerify([]byte{}, nil)
		if err == nil {
			t.Error("OCSPVerify() should fail with empty data")
		}
	})
}
