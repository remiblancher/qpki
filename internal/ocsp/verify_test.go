package ocsp

import (
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

// =============================================================================
// Basic Verify Tests
// =============================================================================

// TestU_Verify_Good tests verifying a "good" response.
func TestU_Verify_Good(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, caCert, caKey, kp)
	responderCert := generateOCSPResponderCert(t, caCert, caKey, kp)

	certID, _ := NewCertID(crypto.SHA256, caCert, cert)
	now := time.Now().UTC()

	builder := NewResponseBuilder(responderCert, kp.PrivateKey)
	builder.AddGood(certID, now.Add(-1*time.Hour), now.Add(1*time.Hour))

	data, err := builder.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	result, err := Verify(data, &VerifyConfig{
		IssuerCert:    caCert,
		ResponderCert: responderCert,
		Certificate:   cert,
	})
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if result.Status != StatusSuccessful {
		t.Errorf("Expected successful status, got %v", result.Status)
	}

	if result.CertStatus != CertStatusGood {
		t.Errorf("Expected good cert status, got %v", result.CertStatus)
	}
}

// TestU_Verify_Revoked tests verifying a "revoked" response.
func TestU_Verify_Revoked(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, caCert, caKey, kp)
	responderCert := generateOCSPResponderCert(t, caCert, caKey, kp)

	certID, _ := NewCertID(crypto.SHA256, caCert, cert)
	now := time.Now().UTC()
	revocationTime := now.Add(-24 * time.Hour)

	builder := NewResponseBuilder(responderCert, kp.PrivateKey)
	builder.AddRevoked(certID, now.Add(-1*time.Hour), now.Add(1*time.Hour), revocationTime, ReasonKeyCompromise)

	data, err := builder.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	result, err := Verify(data, &VerifyConfig{
		IssuerCert:    caCert,
		ResponderCert: responderCert,
	})
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if result.CertStatus != CertStatusRevoked {
		t.Errorf("Expected revoked cert status, got %v", result.CertStatus)
	}

	if result.RevocationReason != ReasonKeyCompromise {
		t.Errorf("Expected key compromise reason, got %v", result.RevocationReason)
	}

	if result.RevocationTime.IsZero() {
		t.Error("Expected revocation time to be set")
	}
}

// TestU_Verify_Unknown tests verifying an "unknown" response.
func TestU_Verify_Unknown(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	responderCert := generateOCSPResponderCert(t, caCert, caKey, kp)

	certID, _ := NewCertIDFromSerial(crypto.SHA256, caCert, big.NewInt(999999))
	now := time.Now().UTC()

	builder := NewResponseBuilder(responderCert, kp.PrivateKey)
	builder.AddUnknown(certID, now.Add(-1*time.Hour), now.Add(1*time.Hour))

	data, err := builder.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	result, err := Verify(data, &VerifyConfig{
		IssuerCert:    caCert,
		ResponderCert: responderCert,
	})
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if result.CertStatus != CertStatusUnknown {
		t.Errorf("Expected unknown cert status, got %v", result.CertStatus)
	}
}

// =============================================================================
// Time Validation Tests
// =============================================================================

// TestU_Verify_ThisUpdateInFutureInvalid tests rejection when thisUpdate is in the future.
func TestU_Verify_ThisUpdateInFutureInvalid(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, caCert, caKey, kp)
	responderCert := generateOCSPResponderCert(t, caCert, caKey, kp)

	certID, _ := NewCertID(crypto.SHA256, caCert, cert)
	now := time.Now().UTC()

	// Set thisUpdate to the future
	builder := NewResponseBuilder(responderCert, kp.PrivateKey)
	builder.AddGood(certID, now.Add(1*time.Hour), now.Add(2*time.Hour))

	data, err := builder.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	_, err = Verify(data, &VerifyConfig{
		IssuerCert:    caCert,
		ResponderCert: responderCert,
	})
	if err == nil {
		t.Error("Expected error for thisUpdate in the future")
	}
}

// TestU_Verify_NextUpdateExpiredInvalid tests rejection when nextUpdate has passed.
func TestU_Verify_NextUpdateExpiredInvalid(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, caCert, caKey, kp)
	responderCert := generateOCSPResponderCert(t, caCert, caKey, kp)

	certID, _ := NewCertID(crypto.SHA256, caCert, cert)
	now := time.Now().UTC()

	// Set nextUpdate to the past
	builder := NewResponseBuilder(responderCert, kp.PrivateKey)
	builder.AddGood(certID, now.Add(-2*time.Hour), now.Add(-1*time.Hour))

	data, err := builder.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	_, err = Verify(data, &VerifyConfig{
		IssuerCert:    caCert,
		ResponderCert: responderCert,
	})
	if err == nil {
		t.Error("Expected error for expired nextUpdate")
	}
}

// =============================================================================
// CertID Validation Tests
// =============================================================================

// TestU_Verify_CertIDMismatchInvalid tests rejection when CertID doesn't match.
func TestU_Verify_CertIDMismatchInvalid(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, caCert, caKey, kp)
	responderCert := generateOCSPResponderCert(t, caCert, caKey, kp)

	// Create response for a different certificate
	differentCert := issueTestCertificate(t, caCert, caKey, kp)
	certID, _ := NewCertID(crypto.SHA256, caCert, differentCert)
	now := time.Now().UTC()

	builder := NewResponseBuilder(responderCert, kp.PrivateKey)
	builder.AddGood(certID, now.Add(-1*time.Hour), now.Add(1*time.Hour))

	data, err := builder.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// Try to verify with original cert (should fail)
	_, err = Verify(data, &VerifyConfig{
		IssuerCert:    caCert,
		ResponderCert: responderCert,
		Certificate:   cert, // Different from the one in response
	})
	if err == nil {
		t.Error("Expected error for CertID mismatch")
	}
}

// =============================================================================
// Nonce Validation Tests
// =============================================================================

// TestU_ValidateNonce_Match tests nonce validation when matching.
func TestU_ValidateNonce_Match(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, caCert, caKey, kp)
	responderCert := generateOCSPResponderCert(t, caCert, caKey, kp)

	nonce := []byte("test-nonce-123")

	// Create request with nonce
	req, _ := CreateRequestWithNonce(caCert, []*x509.Certificate{cert}, crypto.SHA256, nonce)
	reqData, _ := req.Marshal()

	// Create response with same nonce
	certID, _ := NewCertID(crypto.SHA256, caCert, cert)
	now := time.Now().UTC()

	builder := NewResponseBuilder(responderCert, kp.PrivateKey)
	builder.AddGood(certID, now.Add(-1*time.Hour), now.Add(1*time.Hour))
	builder.AddNonce(nonce)

	respData, _ := builder.Build()

	err := ValidateNonce(reqData, respData)
	if err != nil {
		t.Errorf("ValidateNonce failed: %v", err)
	}
}

// TestU_ValidateNonce_MismatchInvalid tests nonce validation when mismatching.
func TestU_ValidateNonce_MismatchInvalid(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, caCert, caKey, kp)
	responderCert := generateOCSPResponderCert(t, caCert, caKey, kp)

	// Create request with one nonce
	req, _ := CreateRequestWithNonce(caCert, []*x509.Certificate{cert}, crypto.SHA256, []byte("nonce-a"))
	reqData, _ := req.Marshal()

	// Create response with different nonce
	certID, _ := NewCertID(crypto.SHA256, caCert, cert)
	now := time.Now().UTC()

	builder := NewResponseBuilder(responderCert, kp.PrivateKey)
	builder.AddGood(certID, now.Add(-1*time.Hour), now.Add(1*time.Hour))
	builder.AddNonce([]byte("nonce-b"))

	respData, _ := builder.Build()

	err := ValidateNonce(reqData, respData)
	if err == nil {
		t.Error("Expected error for nonce mismatch")
	}
}

// TestU_ValidateNonce_MissingInResponseInvalid tests when response has no nonce but request does.
func TestU_ValidateNonce_MissingInResponseInvalid(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, caCert, caKey, kp)
	responderCert := generateOCSPResponderCert(t, caCert, caKey, kp)

	// Create request with nonce
	req, _ := CreateRequestWithNonce(caCert, []*x509.Certificate{cert}, crypto.SHA256, []byte("nonce"))
	reqData, _ := req.Marshal()

	// Create response without nonce
	certID, _ := NewCertID(crypto.SHA256, caCert, cert)
	now := time.Now().UTC()

	builder := NewResponseBuilder(responderCert, kp.PrivateKey)
	builder.AddGood(certID, now.Add(-1*time.Hour), now.Add(1*time.Hour))
	// No nonce added

	respData, _ := builder.Build()

	err := ValidateNonce(reqData, respData)
	if err == nil {
		t.Error("Expected error when response missing nonce but request has one")
	}
}

// TestU_ValidateNonce_NoNonceInRequest tests when request has no nonce.
func TestU_ValidateNonce_NoNonceInRequest(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, caCert, caKey, kp)
	responderCert := generateOCSPResponderCert(t, caCert, caKey, kp)

	// Create request without nonce
	req, _ := CreateRequest(caCert, []*x509.Certificate{cert}, crypto.SHA256)
	reqData, _ := req.Marshal()

	// Create response (with or without nonce doesn't matter)
	certID, _ := NewCertID(crypto.SHA256, caCert, cert)
	now := time.Now().UTC()

	builder := NewResponseBuilder(responderCert, kp.PrivateKey)
	builder.AddGood(certID, now.Add(-1*time.Hour), now.Add(1*time.Hour))

	respData, _ := builder.Build()

	err := ValidateNonce(reqData, respData)
	if err != nil {
		t.Errorf("ValidateNonce should pass when request has no nonce: %v", err)
	}
}

// =============================================================================
// Signature Verification Tests
// =============================================================================

// TestU_Verify_ValidSignature_ECDSA tests signature verification with ECDSA.
func TestU_Verify_ValidSignature_ECDSA(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, caCert, caKey, kp)
	responderCert := generateOCSPResponderCert(t, caCert, caKey, kp)

	certID, _ := NewCertID(crypto.SHA256, caCert, cert)
	now := time.Now().UTC()

	builder := NewResponseBuilder(responderCert, kp.PrivateKey)
	builder.AddGood(certID, now.Add(-1*time.Hour), now.Add(1*time.Hour))

	data, _ := builder.Build()

	// Verify with signature verification enabled
	_, err := Verify(data, &VerifyConfig{
		IssuerCert:          caCert,
		ResponderCert:       responderCert,
		SkipSignatureVerify: false,
	})
	if err != nil {
		t.Errorf("Verify with valid ECDSA signature failed: %v", err)
	}
}

// TestU_Verify_ValidSignature_RSA tests signature verification with RSA.
func TestU_Verify_ValidSignature_RSA(t *testing.T) {
	rsaKP := generateRSAKeyPair(t, 2048)
	caCert, caKey := generateTestCAWithKey(t, rsaKP)

	responderKP := generateRSAKeyPair(t, 2048)
	responderCert := generateOCSPResponderCert(t, caCert, caKey, responderKP)

	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, caCert, caKey, kp)

	certID, _ := NewCertID(crypto.SHA256, caCert, cert)
	now := time.Now().UTC()

	builder := NewResponseBuilder(responderCert, responderKP.PrivateKey)
	builder.AddGood(certID, now.Add(-1*time.Hour), now.Add(1*time.Hour))

	data, _ := builder.Build()

	_, err := Verify(data, &VerifyConfig{
		IssuerCert:          caCert,
		ResponderCert:       responderCert,
		SkipSignatureVerify: false,
	})
	if err != nil {
		t.Errorf("Verify with valid RSA signature failed: %v", err)
	}
}

// TestU_Verify_ValidSignature_Ed25519 tests signature verification with Ed25519.
func TestU_Verify_ValidSignature_Ed25519(t *testing.T) {
	caCert, caKey := generateTestCA(t)

	ed25519KP := generateEd25519KeyPair(t)
	responderCert := generateOCSPResponderCert(t, caCert, caKey, ed25519KP)

	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, caCert, caKey, kp)

	certID, _ := NewCertID(crypto.SHA256, caCert, cert)
	now := time.Now().UTC()

	builder := NewResponseBuilder(responderCert, ed25519KP.PrivateKey)
	builder.AddGood(certID, now.Add(-1*time.Hour), now.Add(1*time.Hour))

	data, _ := builder.Build()

	_, err := Verify(data, &VerifyConfig{
		IssuerCert:          caCert,
		ResponderCert:       responderCert,
		SkipSignatureVerify: false,
	})
	if err != nil {
		t.Errorf("Verify with valid Ed25519 signature failed: %v", err)
	}
}

// TestU_Verify_InvalidSignatureInvalid tests rejection of invalid signature.
func TestU_Verify_InvalidSignatureInvalid(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, caCert, caKey, kp)
	responderCert := generateOCSPResponderCert(t, caCert, caKey, kp)

	certID, _ := NewCertID(crypto.SHA256, caCert, cert)
	now := time.Now().UTC()

	builder := NewResponseBuilder(responderCert, kp.PrivateKey)
	builder.AddGood(certID, now.Add(-1*time.Hour), now.Add(1*time.Hour))

	data, _ := builder.Build()

	// Tamper with the signature
	tamperedData := tamperSignature(t, data)

	_, err := Verify(tamperedData, &VerifyConfig{
		IssuerCert:          caCert,
		ResponderCert:       responderCert,
		SkipSignatureVerify: false,
	})
	if err == nil {
		t.Error("Expected error for tampered signature")
	}
}

// TestU_Verify_NoResponderCertMissing tests rejection when no responder cert available.
func TestU_Verify_NoResponderCertMissing(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, caCert, caKey, kp)
	responderCert := generateOCSPResponderCert(t, caCert, caKey, kp)

	certID, _ := NewCertID(crypto.SHA256, caCert, cert)
	now := time.Now().UTC()

	builder := NewResponseBuilder(responderCert, kp.PrivateKey)
	builder.IncludeCerts(false) // Don't include responder cert
	builder.AddGood(certID, now.Add(-1*time.Hour), now.Add(1*time.Hour))

	data, _ := builder.Build()

	// Try to verify without providing responder cert
	_, err := Verify(data, &VerifyConfig{
		IssuerCert:          caCert,
		ResponderCert:       nil, // No responder cert
		SkipSignatureVerify: false,
	})
	if err == nil {
		t.Error("Expected error when no responder cert available")
	}
}

// =============================================================================
// Error Response Verification Tests
// =============================================================================

// TestU_Verify_ErrorResponse tests verifying error responses.
func TestU_Verify_ErrorResponse(t *testing.T) {
	errorStatuses := []struct {
		name   string
		status ResponseStatus
	}{
		{"[Unit] Verify: ErrorResponse MalformedRequest", StatusMalformedRequest},
		{"[Unit] Verify: ErrorResponse InternalError", StatusInternalError},
		{"[Unit] Verify: ErrorResponse TryLater", StatusTryLater},
		{"[Unit] Verify: ErrorResponse SigRequired", StatusSigRequired},
		{"[Unit] Verify: ErrorResponse Unauthorized", StatusUnauthorized},
	}

	for _, tc := range errorStatuses {
		t.Run(tc.name, func(t *testing.T) {
			data, err := NewErrorResponse(tc.status)
			if err != nil {
				t.Fatalf("NewErrorResponse failed: %v", err)
			}

			result, err := Verify(data, nil)
			if err != nil {
				t.Fatalf("Verify failed: %v", err)
			}

			if result.Status != tc.status {
				t.Errorf("Expected status %v, got %v", tc.status, result.Status)
			}
		})
	}
}

// =============================================================================
// Helper Functions Tests
// =============================================================================

// TestU_IsGood_True tests IsGood returns true for good response.
func TestU_IsGood_True(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, caCert, caKey, kp)
	responderCert := generateOCSPResponderCert(t, caCert, caKey, kp)

	certID, _ := NewCertID(crypto.SHA256, caCert, cert)
	now := time.Now().UTC()

	builder := NewResponseBuilder(responderCert, kp.PrivateKey)
	builder.AddGood(certID, now.Add(-1*time.Hour), now.Add(1*time.Hour))

	data, _ := builder.Build()

	isGood, err := IsGood(data)
	if err != nil {
		t.Fatalf("IsGood failed: %v", err)
	}
	if !isGood {
		t.Error("Expected IsGood to return true")
	}
}

// TestU_IsGood_False tests IsGood returns false for revoked response.
func TestU_IsGood_False(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, caCert, caKey, kp)
	responderCert := generateOCSPResponderCert(t, caCert, caKey, kp)

	certID, _ := NewCertID(crypto.SHA256, caCert, cert)
	now := time.Now().UTC()

	builder := NewResponseBuilder(responderCert, kp.PrivateKey)
	builder.AddRevoked(certID, now.Add(-1*time.Hour), now.Add(1*time.Hour), now.Add(-24*time.Hour), ReasonKeyCompromise)

	data, _ := builder.Build()

	isGood, err := IsGood(data)
	if err != nil {
		t.Fatalf("IsGood failed: %v", err)
	}
	if isGood {
		t.Error("Expected IsGood to return false for revoked cert")
	}
}

// TestU_IsRevoked_True tests IsRevoked returns true for revoked response.
func TestU_IsRevoked_True(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, caCert, caKey, kp)
	responderCert := generateOCSPResponderCert(t, caCert, caKey, kp)

	certID, _ := NewCertID(crypto.SHA256, caCert, cert)
	now := time.Now().UTC()

	builder := NewResponseBuilder(responderCert, kp.PrivateKey)
	builder.AddRevoked(certID, now.Add(-1*time.Hour), now.Add(1*time.Hour), now.Add(-24*time.Hour), ReasonKeyCompromise)

	data, _ := builder.Build()

	isRevoked, err := IsRevoked(data)
	if err != nil {
		t.Fatalf("IsRevoked failed: %v", err)
	}
	if !isRevoked {
		t.Error("Expected IsRevoked to return true")
	}
}

// =============================================================================
// Helper Functions
// =============================================================================

// tamperSignature modifies the signature in an OCSP response.
func tamperSignature(t *testing.T, data []byte) []byte {
	t.Helper()

	var resp OCSPResponse
	_, err := asn1.Unmarshal(data, &resp)
	if err != nil {
		t.Fatalf("Failed to parse OCSP response: %v", err)
	}

	var basicResp BasicOCSPResponse
	_, err = asn1.Unmarshal(resp.ResponseBytes.Response, &basicResp)
	if err != nil {
		t.Fatalf("Failed to parse BasicOCSPResponse: %v", err)
	}

	// Tamper with signature
	if len(basicResp.Signature.Bytes) > 0 {
		basicResp.Signature.Bytes[0] ^= 0xFF
	}

	// Re-marshal
	basicRespBytes, err := asn1.Marshal(basicResp)
	if err != nil {
		t.Fatalf("Failed to marshal BasicOCSPResponse: %v", err)
	}

	resp.ResponseBytes.Response = basicRespBytes

	result, err := asn1.Marshal(resp)
	if err != nil {
		t.Fatalf("Failed to marshal OCSP response: %v", err)
	}

	return result
}
