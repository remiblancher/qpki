package ocsp

import (
	"crypto"
	"crypto/elliptic"
	"math/big"
	"testing"
	"time"

	pkicrypto "github.com/remiblancher/qpki/pkg/crypto"
)

// =============================================================================
// Response Status Tests
// =============================================================================

// TestU_ResponseStatus_String tests ResponseStatus string conversion.
func TestU_ResponseStatus_String(t *testing.T) {
	tests := []struct {
		name   string
		status ResponseStatus
	}{
		{"[Unit] ResponseStatus: Successful", StatusSuccessful},
		{"[Unit] ResponseStatus: MalformedRequest", StatusMalformedRequest},
		{"[Unit] ResponseStatus: InternalError", StatusInternalError},
		{"[Unit] ResponseStatus: TryLater", StatusTryLater},
		{"[Unit] ResponseStatus: SigRequired", StatusSigRequired},
		{"[Unit] ResponseStatus: Unauthorized", StatusUnauthorized},
		{"[Unit] ResponseStatus: Unknown", ResponseStatus(99)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_ = tc.status.String()
		})
	}
}

// TestU_CertStatus_String tests CertStatus string conversion.
func TestU_CertStatus_String(t *testing.T) {
	tests := []struct {
		name   string
		status CertStatus
	}{
		{"[Unit] CertStatus: Good", CertStatusGood},
		{"[Unit] CertStatus: Revoked", CertStatusRevoked},
		{"[Unit] CertStatus: Unknown", CertStatusUnknown},
		{"[Unit] CertStatus: UnknownValue", CertStatus(99)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_ = tc.status.String()
		})
	}
}

// =============================================================================
// Error Response Tests
// =============================================================================

// TestU_NewErrorResponse_MalformedRequest tests malformed request response.
func TestU_NewErrorResponse_MalformedRequest(t *testing.T) {
	data, err := NewMalformedResponse()
	if err != nil {
		t.Fatalf("NewMalformedResponse failed: %v", err)
	}

	status, err := GetResponseStatus(data)
	if err != nil {
		t.Fatalf("GetResponseStatus failed: %v", err)
	}

	if status != StatusMalformedRequest {
		t.Errorf("Expected malformedRequest, got %v", status)
	}
}

// TestU_NewErrorResponse_InternalError tests internal error response.
func TestU_NewErrorResponse_InternalError(t *testing.T) {
	data, err := NewInternalErrorResponse()
	if err != nil {
		t.Fatalf("NewInternalErrorResponse failed: %v", err)
	}

	status, err := GetResponseStatus(data)
	if err != nil {
		t.Fatalf("GetResponseStatus failed: %v", err)
	}

	if status != StatusInternalError {
		t.Errorf("Expected internalError, got %v", status)
	}
}

// TestU_NewErrorResponse_Unauthorized tests unauthorized response.
func TestU_NewErrorResponse_Unauthorized(t *testing.T) {
	data, err := NewUnauthorizedResponse()
	if err != nil {
		t.Fatalf("NewUnauthorizedResponse failed: %v", err)
	}

	status, err := GetResponseStatus(data)
	if err != nil {
		t.Fatalf("GetResponseStatus failed: %v", err)
	}

	if status != StatusUnauthorized {
		t.Errorf("Expected unauthorized, got %v", status)
	}
}

// TestU_NewErrorResponse_SuccessfulStatusInvalid tests successful status is rejected.
func TestU_NewErrorResponse_SuccessfulStatusInvalid(t *testing.T) {
	_, err := NewErrorResponse(StatusSuccessful)
	if err == nil {
		t.Error("Expected error when creating error response with successful status")
	}
}

// =============================================================================
// ResponseBuilder Tests
// =============================================================================

// TestU_ResponseBuilder_Good tests building a "good" response.
func TestU_ResponseBuilder_Good(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, caCert, caKey, kp)
	responderCert := generateOCSPResponderCert(t, caCert, caKey, kp)

	certID, err := NewCertID(crypto.SHA256, caCert, cert)
	if err != nil {
		t.Fatalf("NewCertID failed: %v", err)
	}

	now := time.Now().UTC()
	thisUpdate := now
	nextUpdate := now.Add(1 * time.Hour)

	builder := NewResponseBuilder(responderCert, kp.PrivateKey)
	builder.AddGood(certID, thisUpdate, nextUpdate)

	data, err := builder.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// Verify response
	isGood, err := IsGood(data)
	if err != nil {
		t.Fatalf("IsGood failed: %v", err)
	}
	if !isGood {
		t.Error("Expected certificate to be good")
	}
}

// TestU_ResponseBuilder_Revoked tests building a "revoked" response.
func TestU_ResponseBuilder_Revoked(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, caCert, caKey, kp)
	responderCert := generateOCSPResponderCert(t, caCert, caKey, kp)

	certID, err := NewCertID(crypto.SHA256, caCert, cert)
	if err != nil {
		t.Fatalf("NewCertID failed: %v", err)
	}

	now := time.Now().UTC()
	thisUpdate := now
	nextUpdate := now.Add(1 * time.Hour)
	revocationTime := now.Add(-24 * time.Hour)

	builder := NewResponseBuilder(responderCert, kp.PrivateKey)
	builder.AddRevoked(certID, thisUpdate, nextUpdate, revocationTime, ReasonKeyCompromise)

	data, err := builder.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// Verify response
	isRevoked, err := IsRevoked(data)
	if err != nil {
		t.Fatalf("IsRevoked failed: %v", err)
	}
	if !isRevoked {
		t.Error("Expected certificate to be revoked")
	}
}

// TestU_ResponseBuilder_Unknown tests building an "unknown" response.
func TestU_ResponseBuilder_Unknown(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	responderCert := generateOCSPResponderCert(t, caCert, caKey, kp)

	// Create a CertID for an unknown certificate
	certID, err := NewCertIDFromSerial(crypto.SHA256, caCert, big.NewInt(999999))
	if err != nil {
		t.Fatalf("NewCertIDFromSerial failed: %v", err)
	}

	now := time.Now().UTC()
	thisUpdate := now
	nextUpdate := now.Add(1 * time.Hour)

	builder := NewResponseBuilder(responderCert, kp.PrivateKey)
	builder.AddUnknown(certID, thisUpdate, nextUpdate)

	data, err := builder.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	result, err := Verify(data, &VerifyConfig{SkipSignatureVerify: true})
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if result.CertStatus != CertStatusUnknown {
		t.Errorf("Expected unknown status, got %v", result.CertStatus)
	}
}

// TestU_ResponseBuilder_WithNonce tests response with nonce.
func TestU_ResponseBuilder_WithNonce(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, caCert, caKey, kp)
	responderCert := generateOCSPResponderCert(t, caCert, caKey, kp)

	certID, err := NewCertID(crypto.SHA256, caCert, cert)
	if err != nil {
		t.Fatalf("NewCertID failed: %v", err)
	}

	nonce := []byte("test-response-nonce")
	now := time.Now().UTC()

	builder := NewResponseBuilder(responderCert, kp.PrivateKey)
	builder.AddGood(certID, now, now.Add(1*time.Hour))
	builder.AddNonce(nonce)

	data, err := builder.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// Extract nonce
	extractedNonce, err := GetResponseNonce(data)
	if err != nil {
		t.Fatalf("GetResponseNonce failed: %v", err)
	}

	if string(extractedNonce) != string(nonce) {
		t.Errorf("Nonce mismatch: expected %x, got %x", nonce, extractedNonce)
	}
}

// TestU_ResponseBuilder_IncludeCerts tests certificate inclusion.
func TestU_ResponseBuilder_IncludeCerts(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, caCert, caKey, kp)
	responderCert := generateOCSPResponderCert(t, caCert, caKey, kp)

	certID, err := NewCertID(crypto.SHA256, caCert, cert)
	if err != nil {
		t.Fatalf("NewCertID failed: %v", err)
	}

	now := time.Now().UTC()

	// With certs included
	builder := NewResponseBuilder(responderCert, kp.PrivateKey)
	builder.IncludeCerts(true)
	builder.AddGood(certID, now, now.Add(1*time.Hour))

	data, err := builder.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	certs, err := ExtractCertificates(data)
	if err != nil {
		t.Fatalf("ExtractCertificates failed: %v", err)
	}

	if len(certs) != 1 {
		t.Errorf("Expected 1 certificate, got %d", len(certs))
	}

	// Without certs
	builder2 := NewResponseBuilder(responderCert, kp.PrivateKey)
	builder2.IncludeCerts(false)
	builder2.AddGood(certID, now, now.Add(1*time.Hour))

	data2, err := builder2.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	certs2, err := ExtractCertificates(data2)
	if err != nil {
		t.Fatalf("ExtractCertificates failed: %v", err)
	}

	if len(certs2) != 0 {
		t.Errorf("Expected 0 certificates, got %d", len(certs2))
	}
}

// TestU_ResponseBuilder_SetProducedAt tests setting producedAt time.
func TestU_ResponseBuilder_SetProducedAt(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, caCert, caKey, kp)
	responderCert := generateOCSPResponderCert(t, caCert, caKey, kp)

	certID, err := NewCertID(crypto.SHA256, caCert, cert)
	if err != nil {
		t.Fatalf("NewCertID failed: %v", err)
	}

	producedAt := time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC)
	now := time.Now().UTC()

	builder := NewResponseBuilder(responderCert, kp.PrivateKey)
	builder.SetProducedAt(producedAt)
	builder.AddGood(certID, now.Add(-1*time.Hour), now.Add(1*time.Hour))

	data, err := builder.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	info, err := GetResponseInfo(data)
	if err != nil {
		t.Fatalf("GetResponseInfo failed: %v", err)
	}

	if !info.ProducedAt.Equal(producedAt) {
		t.Errorf("ProducedAt mismatch: expected %v, got %v", producedAt, info.ProducedAt)
	}
}

// TestU_ResponseBuilder_NoResponsesMissing tests building with no responses.
func TestU_ResponseBuilder_NoResponsesMissing(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	responderCert := generateOCSPResponderCert(t, caCert, caKey, kp)

	builder := NewResponseBuilder(responderCert, kp.PrivateKey)

	_, err := builder.Build()
	if err == nil {
		t.Error("Expected error when building with no responses")
	}
}

// =============================================================================
// Response Builder with Different Key Types
// =============================================================================

// TestU_ResponseBuilder_RSA tests response building with RSA key.
func TestU_ResponseBuilder_RSA(t *testing.T) {
	rsaKP := generateRSAKeyPair(t, 2048)
	caCert, caKey := generateTestCAWithKey(t, rsaKP)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, caCert, caKey, kp)

	responderKP := generateRSAKeyPair(t, 2048)
	responderCert := generateOCSPResponderCert(t, caCert, caKey, responderKP)

	certID, err := NewCertID(crypto.SHA256, caCert, cert)
	if err != nil {
		t.Fatalf("NewCertID failed: %v", err)
	}

	now := time.Now().UTC()
	builder := NewResponseBuilder(responderCert, responderKP.PrivateKey)
	builder.AddGood(certID, now, now.Add(1*time.Hour))

	data, err := builder.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// Verify RSA signature algorithm OID
	info, err := GetResponseInfo(data)
	if err != nil {
		t.Fatalf("GetResponseInfo failed: %v", err)
	}

	expectedOID := OIDSHA256WithRSA.String()
	if info.SignatureAlg != expectedOID {
		t.Errorf("Expected RSA-SHA256 OID %s, got %s", expectedOID, info.SignatureAlg)
	}
}

// TestU_ResponseBuilder_Ed25519 tests response building with Ed25519 key.
func TestU_ResponseBuilder_Ed25519(t *testing.T) {
	// Use ECDSA for CA (Ed25519 CA cert creation has issues)
	caCert, caKey := generateTestCA(t)

	ed25519KP := generateEd25519KeyPair(t)
	responderCert := generateOCSPResponderCert(t, caCert, caKey, ed25519KP)

	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, caCert, caKey, kp)

	certID, err := NewCertID(crypto.SHA256, caCert, cert)
	if err != nil {
		t.Fatalf("NewCertID failed: %v", err)
	}

	now := time.Now().UTC()
	builder := NewResponseBuilder(responderCert, ed25519KP.PrivateKey)
	builder.AddGood(certID, now, now.Add(1*time.Hour))

	data, err := builder.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// Verify Ed25519 signature algorithm OID
	info, err := GetResponseInfo(data)
	if err != nil {
		t.Fatalf("GetResponseInfo failed: %v", err)
	}

	expectedOID := OIDEd25519.String()
	if info.SignatureAlg != expectedOID {
		t.Errorf("Expected Ed25519 OID %s, got %s", expectedOID, info.SignatureAlg)
	}
}

// TestU_ResponseBuilder_ECDSA_P384 tests response building with ECDSA P-384.
func TestU_ResponseBuilder_ECDSA_P384(t *testing.T) {
	caCert, caKey := generateTestCA(t)

	p384KP := generateECDSAKeyPair(t, elliptic.P384())
	responderCert := generateOCSPResponderCert(t, caCert, caKey, p384KP)

	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, caCert, caKey, kp)

	certID, err := NewCertID(crypto.SHA256, caCert, cert)
	if err != nil {
		t.Fatalf("NewCertID failed: %v", err)
	}

	now := time.Now().UTC()
	builder := NewResponseBuilder(responderCert, p384KP.PrivateKey)
	builder.AddGood(certID, now, now.Add(1*time.Hour))

	data, err := builder.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// Verify ECDSA P-384 signature algorithm OID
	info, err := GetResponseInfo(data)
	if err != nil {
		t.Fatalf("GetResponseInfo failed: %v", err)
	}

	expectedOID := OIDECDSAWithSHA384.String()
	if info.SignatureAlg != expectedOID {
		t.Errorf("Expected ECDSA-SHA384 OID %s, got %s", expectedOID, info.SignatureAlg)
	}
}

// =============================================================================
// Response Info Tests
// =============================================================================

// TestU_GetResponseInfo_Basic tests extracting detailed response info.
func TestU_GetResponseInfo_Basic(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, caCert, caKey, kp)
	responderCert := generateOCSPResponderCert(t, caCert, caKey, kp)

	certID, err := NewCertID(crypto.SHA256, caCert, cert)
	if err != nil {
		t.Fatalf("NewCertID failed: %v", err)
	}

	now := time.Now().UTC()
	thisUpdate := now.Truncate(time.Second)
	nextUpdate := now.Add(1 * time.Hour).Truncate(time.Second)

	builder := NewResponseBuilder(responderCert, kp.PrivateKey)
	builder.AddGood(certID, thisUpdate, nextUpdate)

	data, err := builder.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	info, err := GetResponseInfo(data)
	if err != nil {
		t.Fatalf("GetResponseInfo failed: %v", err)
	}

	if info.Status != StatusSuccessful {
		t.Errorf("Expected successful status, got %v", info.Status)
	}

	if len(info.CertStatuses) != 1 {
		t.Errorf("Expected 1 cert status, got %d", len(info.CertStatuses))
	}

	if info.CertStatuses[0].Status != CertStatusGood {
		t.Errorf("Expected good status, got %v", info.CertStatuses[0].Status)
	}

	if info.CertStatuses[0].SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Error("Serial number mismatch")
	}
}

// TestU_GetResponseInfo_ErrorResponse tests info from error response.
func TestU_GetResponseInfo_ErrorResponse(t *testing.T) {
	data, err := NewMalformedResponse()
	if err != nil {
		t.Fatalf("NewMalformedResponse failed: %v", err)
	}

	info, err := GetResponseInfo(data)
	if err != nil {
		t.Fatalf("GetResponseInfo failed: %v", err)
	}

	if info.Status != StatusMalformedRequest {
		t.Errorf("Expected malformedRequest status, got %v", info.Status)
	}

	if len(info.CertStatuses) != 0 {
		t.Errorf("Expected 0 cert statuses for error response, got %d", len(info.CertStatuses))
	}
}

// =============================================================================
// ParseResponse Tests
// =============================================================================

// TestU_ParseResponse_RoundTrip tests response parse round trip.
func TestU_ParseResponse_RoundTrip(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, caCert, caKey, kp)
	responderCert := generateOCSPResponderCert(t, caCert, caKey, kp)

	certID, _ := NewCertID(crypto.SHA256, caCert, cert)
	now := time.Now().UTC()

	builder := NewResponseBuilder(responderCert, kp.PrivateKey)
	builder.AddGood(certID, now, now.Add(1*time.Hour))

	data, err := builder.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	resp, err := ParseResponse(data)
	if err != nil {
		t.Fatalf("ParseResponse failed: %v", err)
	}

	if ResponseStatus(resp.Status) != StatusSuccessful {
		t.Errorf("Expected successful status, got %v", resp.Status)
	}
}

// TestU_ParseResponse_InvalidDataInvalid tests parsing invalid data.
func TestU_ParseResponse_InvalidDataInvalid(t *testing.T) {
	_, err := ParseResponse([]byte("not a valid OCSP response"))
	if err == nil {
		t.Error("Expected error for invalid data")
	}
}

// TestU_ParseResponse_TrailingDataInvalid tests parsing with trailing data.
func TestU_ParseResponse_TrailingDataInvalid(t *testing.T) {
	data, _ := NewMalformedResponse()
	dataWithTrailing := append(data, []byte("trailing")...)

	_, err := ParseResponse(dataWithTrailing)
	if err == nil {
		t.Error("Expected error for trailing data")
	}
}

// =============================================================================
// Multiple Responses Tests
// =============================================================================

// TestU_ResponseBuilder_MultipleResponses tests multiple certificate statuses.
func TestU_ResponseBuilder_MultipleResponses(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	responderCert := generateOCSPResponderCert(t, caCert, caKey, kp)

	cert1 := issueTestCertificate(t, caCert, caKey, kp)
	cert2 := issueTestCertificate(t, caCert, caKey, kp)
	cert3 := issueTestCertificate(t, caCert, caKey, kp)

	certID1, _ := NewCertID(crypto.SHA256, caCert, cert1)
	certID2, _ := NewCertID(crypto.SHA256, caCert, cert2)
	certID3, _ := NewCertID(crypto.SHA256, caCert, cert3)

	now := time.Now().UTC()
	thisUpdate := now
	nextUpdate := now.Add(1 * time.Hour)
	revocationTime := now.Add(-24 * time.Hour)

	builder := NewResponseBuilder(responderCert, kp.PrivateKey)
	builder.AddGood(certID1, thisUpdate, nextUpdate)
	builder.AddRevoked(certID2, thisUpdate, nextUpdate, revocationTime, ReasonKeyCompromise)
	builder.AddUnknown(certID3, thisUpdate, nextUpdate)

	data, err := builder.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	info, err := GetResponseInfo(data)
	if err != nil {
		t.Fatalf("GetResponseInfo failed: %v", err)
	}

	if len(info.CertStatuses) != 3 {
		t.Errorf("Expected 3 cert statuses, got %d", len(info.CertStatuses))
	}

	// Verify each status
	statusMap := make(map[CertStatus]int)
	for _, cs := range info.CertStatuses {
		statusMap[cs.Status]++
	}

	if statusMap[CertStatusGood] != 1 {
		t.Errorf("Expected 1 good status, got %d", statusMap[CertStatusGood])
	}
	if statusMap[CertStatusRevoked] != 1 {
		t.Errorf("Expected 1 revoked status, got %d", statusMap[CertStatusRevoked])
	}
	if statusMap[CertStatusUnknown] != 1 {
		t.Errorf("Expected 1 unknown status, got %d", statusMap[CertStatusUnknown])
	}
}

// =============================================================================
// Revocation Reason Tests
// =============================================================================

// TestU_RevocationReasons_AllCodes tests all revocation reason codes.
func TestU_RevocationReasons_AllCodes(t *testing.T) {
	reasons := []struct {
		name   string
		reason RevocationReason
	}{
		{"[Unit] RevocationReason: Unspecified", ReasonUnspecified},
		{"[Unit] RevocationReason: KeyCompromise", ReasonKeyCompromise},
		{"[Unit] RevocationReason: CACompromise", ReasonCACompromise},
		{"[Unit] RevocationReason: AffiliationChanged", ReasonAffiliationChanged},
		{"[Unit] RevocationReason: Superseded", ReasonSuperseded},
		{"[Unit] RevocationReason: CessationOfOperation", ReasonCessationOfOperation},
		{"[Unit] RevocationReason: CertificateHold", ReasonCertificateHold},
		{"[Unit] RevocationReason: RemoveFromCRL", ReasonRemoveFromCRL},
		{"[Unit] RevocationReason: PrivilegeWithdrawn", ReasonPrivilegeWithdrawn},
		{"[Unit] RevocationReason: AACompromise", ReasonAACompromise},
	}

	caCert, caKey := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	responderCert := generateOCSPResponderCert(t, caCert, caKey, kp)

	for _, tc := range reasons {
		t.Run(tc.name, func(t *testing.T) {
			cert := issueTestCertificate(t, caCert, caKey, kp)
			certID, _ := NewCertID(crypto.SHA256, caCert, cert)

			now := time.Now().UTC()
			builder := NewResponseBuilder(responderCert, kp.PrivateKey)
			builder.AddRevoked(certID, now, now.Add(1*time.Hour), now.Add(-1*time.Hour), tc.reason)

			data, err := builder.Build()
			if err != nil {
				t.Fatalf("Build failed: %v", err)
			}

			result, err := Verify(data, &VerifyConfig{SkipSignatureVerify: true})
			if err != nil {
				t.Fatalf("Verify failed: %v", err)
			}

			if result.CertStatus != CertStatusRevoked {
				t.Errorf("Expected revoked status, got %v", result.CertStatus)
			}

			if result.RevocationReason != tc.reason {
				t.Errorf("Expected reason %d, got %d", tc.reason, result.RevocationReason)
			}
		})
	}
}

// =============================================================================
// Additional Algorithm Tests
// =============================================================================

// TestU_ResponseBuilder_ECDSA_P521 tests response building with ECDSA P-521.
func TestU_ResponseBuilder_ECDSA_P521(t *testing.T) {
	caCert, caKey := generateTestCA(t)

	p521KP := generateECDSAKeyPair(t, elliptic.P521())
	responderCert := generateOCSPResponderCert(t, caCert, caKey, p521KP)

	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, caCert, caKey, kp)

	certID, err := NewCertID(crypto.SHA512, caCert, cert)
	if err != nil {
		t.Fatalf("NewCertID failed: %v", err)
	}

	now := time.Now().UTC()
	builder := NewResponseBuilder(responderCert, p521KP.PrivateKey)
	builder.AddGood(certID, now, now.Add(1*time.Hour))

	data, err := builder.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// Verify ECDSA P-521 signature algorithm OID
	info, err := GetResponseInfo(data)
	if err != nil {
		t.Fatalf("GetResponseInfo failed: %v", err)
	}

	expectedOID := OIDECDSAWithSHA512.String()
	if info.SignatureAlg != expectedOID {
		t.Errorf("Expected ECDSA-SHA512 OID %s, got %s", expectedOID, info.SignatureAlg)
	}
}

// =============================================================================
// Post-Quantum Algorithm Tests
// =============================================================================

// TestU_ResponseBuilder_MLDSA tests response building with ML-DSA algorithms.
func TestU_ResponseBuilder_MLDSA(t *testing.T) {
	algorithms := []struct {
		name        string
		alg         pkicrypto.AlgorithmID
		expectedOID string
	}{
		{"ML-DSA-44", pkicrypto.AlgMLDSA44, OIDMLDSA44.String()},
		{"ML-DSA-65", pkicrypto.AlgMLDSA65, OIDMLDSA65.String()},
		{"ML-DSA-87", pkicrypto.AlgMLDSA87, OIDMLDSA87.String()},
	}

	caCert, caKey := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, caCert, caKey, kp)

	for _, tc := range algorithms {
		t.Run(tc.name, func(t *testing.T) {
			// Generate ML-DSA responder key pair
			responderKP := generateMLDSAKeyPair(t, tc.alg)
			responderCert := generatePQCOCSPResponderCert(t, caCert, caKey, responderKP, tc.alg)

			certID, err := NewCertID(crypto.SHA256, caCert, cert)
			if err != nil {
				t.Fatalf("NewCertID failed: %v", err)
			}

			now := time.Now().UTC()
			builder := NewResponseBuilder(responderCert, responderKP.PrivateKey)
			builder.AddGood(certID, now, now.Add(1*time.Hour))

			data, err := builder.Build()
			if err != nil {
				t.Fatalf("Build failed: %v", err)
			}

			// Verify signature algorithm OID
			info, err := GetResponseInfo(data)
			if err != nil {
				t.Fatalf("GetResponseInfo failed: %v", err)
			}

			if info.SignatureAlg != tc.expectedOID {
				t.Errorf("Expected OID %s, got %s", tc.expectedOID, info.SignatureAlg)
			}
		})
	}
}

// TestU_ResponseBuilder_SLHDSA tests response building with SLH-DSA algorithms.
func TestU_ResponseBuilder_SLHDSA(t *testing.T) {
	algorithms := []struct {
		name        string
		alg         pkicrypto.AlgorithmID
		expectedOID string
	}{
		{"SLH-DSA-128f", pkicrypto.AlgSLHDSA128f, OIDSLHDSA128f.String()},
		{"SLH-DSA-192f", pkicrypto.AlgSLHDSA192f, OIDSLHDSA192f.String()},
		{"SLH-DSA-256f", pkicrypto.AlgSLHDSA256f, OIDSLHDSA256f.String()},
	}

	caCert, caKey := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, caCert, caKey, kp)

	for _, tc := range algorithms {
		t.Run(tc.name, func(t *testing.T) {
			// Generate SLH-DSA responder key pair
			responderKP := generateSLHDSAKeyPair(t, tc.alg)
			responderCert := generatePQCOCSPResponderCert(t, caCert, caKey, responderKP, tc.alg)

			certID, err := NewCertID(crypto.SHA256, caCert, cert)
			if err != nil {
				t.Fatalf("NewCertID failed: %v", err)
			}

			now := time.Now().UTC()
			builder := NewResponseBuilder(responderCert, responderKP.PrivateKey)
			builder.AddGood(certID, now, now.Add(1*time.Hour))

			data, err := builder.Build()
			if err != nil {
				t.Fatalf("Build failed: %v", err)
			}

			// Verify signature algorithm OID
			info, err := GetResponseInfo(data)
			if err != nil {
				t.Fatalf("GetResponseInfo failed: %v", err)
			}

			if info.SignatureAlg != tc.expectedOID {
				t.Errorf("Expected OID %s, got %s", tc.expectedOID, info.SignatureAlg)
			}
		})
	}
}

// TestU_ResponseBuilder_MLDSA_Revoked tests ML-DSA signature on revoked response.
func TestU_ResponseBuilder_MLDSA_Revoked(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, caCert, caKey, kp)

	responderKP := generateMLDSAKeyPair(t, pkicrypto.AlgMLDSA65)
	responderCert := generatePQCOCSPResponderCert(t, caCert, caKey, responderKP, pkicrypto.AlgMLDSA65)

	certID, err := NewCertID(crypto.SHA256, caCert, cert)
	if err != nil {
		t.Fatalf("NewCertID failed: %v", err)
	}

	now := time.Now().UTC()
	revocationTime := now.Add(-24 * time.Hour)
	builder := NewResponseBuilder(responderCert, responderKP.PrivateKey)
	builder.AddRevoked(certID, now, now.Add(1*time.Hour), revocationTime, ReasonKeyCompromise)

	data, err := builder.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	info, err := GetResponseInfo(data)
	if err != nil {
		t.Fatalf("GetResponseInfo failed: %v", err)
	}

	if info.SignatureAlg != OIDMLDSA65.String() {
		t.Errorf("Expected ML-DSA-65 OID, got %s", info.SignatureAlg)
	}

	if len(info.CertStatuses) != 1 {
		t.Fatalf("Expected 1 cert status, got %d", len(info.CertStatuses))
	}

	if info.CertStatuses[0].Status != CertStatusRevoked {
		t.Errorf("Expected revoked status, got %v", info.CertStatuses[0].Status)
	}
}

// =============================================================================
// Catalyst Certificate Tests (signClassical with HybridSigner)
// =============================================================================

// TestU_ResponseBuilder_Catalyst_ECDSA tests response building with Catalyst cert and ECDSA classical signer.
func TestU_ResponseBuilder_Catalyst_ECDSA(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, caCert, caKey, kp)

	// Create a hybrid signer with ECDSA classical and ML-DSA PQC
	hybridSigner, err := pkicrypto.GenerateHybridSigner(pkicrypto.AlgECDSAP256, pkicrypto.AlgMLDSA65)
	if err != nil {
		t.Fatalf("Failed to generate hybrid signer: %v", err)
	}

	// Create a Catalyst OCSP responder certificate
	responderCert := generateCatalystOCSPResponderCert(t, caCert, caKey, hybridSigner)

	certID, err := NewCertID(crypto.SHA256, caCert, cert)
	if err != nil {
		t.Fatalf("NewCertID failed: %v", err)
	}

	now := time.Now().UTC()
	builder := NewResponseBuilder(responderCert, hybridSigner)
	builder.AddGood(certID, now, now.Add(1*time.Hour))

	data, err := builder.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// Verify the response uses classical signature (ECDSA)
	info, err := GetResponseInfo(data)
	if err != nil {
		t.Fatalf("GetResponseInfo failed: %v", err)
	}

	// Catalyst responses should use classical signature
	if info.SignatureAlg != OIDECDSAWithSHA256.String() {
		t.Errorf("Expected ECDSA-SHA256 OID for Catalyst response, got %s", info.SignatureAlg)
	}
}

// TestU_ResponseBuilder_Catalyst_RSA tests response building with Catalyst cert and RSA classical signer.
func TestU_ResponseBuilder_Catalyst_RSA(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, caCert, caKey, kp)

	// Create a hybrid signer with RSA classical and ML-DSA PQC
	hybridSigner, err := pkicrypto.GenerateHybridSigner(pkicrypto.AlgRSA2048, pkicrypto.AlgMLDSA65)
	if err != nil {
		t.Fatalf("Failed to generate hybrid signer: %v", err)
	}

	// Create a Catalyst OCSP responder certificate
	responderCert := generateCatalystOCSPResponderCert(t, caCert, caKey, hybridSigner)

	certID, err := NewCertID(crypto.SHA256, caCert, cert)
	if err != nil {
		t.Fatalf("NewCertID failed: %v", err)
	}

	now := time.Now().UTC()
	builder := NewResponseBuilder(responderCert, hybridSigner)
	builder.AddGood(certID, now, now.Add(1*time.Hour))

	data, err := builder.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// Verify the response uses classical signature (RSA)
	info, err := GetResponseInfo(data)
	if err != nil {
		t.Fatalf("GetResponseInfo failed: %v", err)
	}

	// Catalyst responses should use classical signature
	if info.SignatureAlg != OIDSHA256WithRSA.String() {
		t.Errorf("Expected RSA-SHA256 OID for Catalyst response, got %s", info.SignatureAlg)
	}
}

// TestU_ResponseBuilder_Catalyst_Ed25519 tests response building with Catalyst cert and Ed25519 classical signer.
func TestU_ResponseBuilder_Catalyst_Ed25519(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, caCert, caKey, kp)

	// Create a hybrid signer with Ed25519 classical and ML-DSA PQC
	hybridSigner, err := pkicrypto.GenerateHybridSigner(pkicrypto.AlgEd25519, pkicrypto.AlgMLDSA65)
	if err != nil {
		t.Fatalf("Failed to generate hybrid signer: %v", err)
	}

	// Create a Catalyst OCSP responder certificate
	responderCert := generateCatalystOCSPResponderCert(t, caCert, caKey, hybridSigner)

	certID, err := NewCertID(crypto.SHA256, caCert, cert)
	if err != nil {
		t.Fatalf("NewCertID failed: %v", err)
	}

	now := time.Now().UTC()
	builder := NewResponseBuilder(responderCert, hybridSigner)
	builder.AddGood(certID, now, now.Add(1*time.Hour))

	data, err := builder.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// Verify the response uses classical signature (Ed25519)
	info, err := GetResponseInfo(data)
	if err != nil {
		t.Fatalf("GetResponseInfo failed: %v", err)
	}

	// Catalyst responses should use classical signature
	if info.SignatureAlg != OIDEd25519.String() {
		t.Errorf("Expected Ed25519 OID for Catalyst response, got %s", info.SignatureAlg)
	}
}

// TestU_ResponseBuilder_Catalyst_ECDSA_P384 tests response building with Catalyst cert and ECDSA P-384.
func TestU_ResponseBuilder_Catalyst_ECDSA_P384(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, caCert, caKey, kp)

	// Create a hybrid signer with ECDSA P-384 classical and ML-DSA PQC
	hybridSigner, err := pkicrypto.GenerateHybridSigner(pkicrypto.AlgECDSAP384, pkicrypto.AlgMLDSA65)
	if err != nil {
		t.Fatalf("Failed to generate hybrid signer: %v", err)
	}

	// Create a Catalyst OCSP responder certificate
	responderCert := generateCatalystOCSPResponderCert(t, caCert, caKey, hybridSigner)

	certID, err := NewCertID(crypto.SHA256, caCert, cert)
	if err != nil {
		t.Fatalf("NewCertID failed: %v", err)
	}

	now := time.Now().UTC()
	builder := NewResponseBuilder(responderCert, hybridSigner)
	builder.AddGood(certID, now, now.Add(1*time.Hour))

	data, err := builder.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// Verify the response uses classical signature (ECDSA P-384)
	info, err := GetResponseInfo(data)
	if err != nil {
		t.Fatalf("GetResponseInfo failed: %v", err)
	}

	// Catalyst responses should use classical signature
	if info.SignatureAlg != OIDECDSAWithSHA384.String() {
		t.Errorf("Expected ECDSA-SHA384 OID for Catalyst response, got %s", info.SignatureAlg)
	}
}

// =============================================================================
// SLH-DSA OID Mapping Tests
// =============================================================================

// TestU_ResponseBuilder_SLHDSA_Slow tests response building with slow SLH-DSA algorithms.
func TestU_ResponseBuilder_SLHDSA_Slow(t *testing.T) {
	algorithms := []struct {
		name        string
		alg         pkicrypto.AlgorithmID
		expectedOID string
	}{
		{"SLH-DSA-128s", pkicrypto.AlgSLHDSA128s, OIDSLHDSA128s.String()},
		{"SLH-DSA-192s", pkicrypto.AlgSLHDSA192s, OIDSLHDSA192s.String()},
		{"SLH-DSA-256s", pkicrypto.AlgSLHDSA256s, OIDSLHDSA256s.String()},
	}

	caCert, caKey := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, caCert, caKey, kp)

	for _, tc := range algorithms {
		t.Run(tc.name, func(t *testing.T) {
			// Generate SLH-DSA responder key pair
			responderKP := generateSLHDSAKeyPair(t, tc.alg)
			responderCert := generatePQCOCSPResponderCert(t, caCert, caKey, responderKP, tc.alg)

			certID, err := NewCertID(crypto.SHA256, caCert, cert)
			if err != nil {
				t.Fatalf("NewCertID failed: %v", err)
			}

			now := time.Now().UTC()
			builder := NewResponseBuilder(responderCert, responderKP.PrivateKey)
			builder.AddGood(certID, now, now.Add(1*time.Hour))

			data, err := builder.Build()
			if err != nil {
				t.Fatalf("Build failed: %v", err)
			}

			// Verify signature algorithm OID
			info, err := GetResponseInfo(data)
			if err != nil {
				t.Fatalf("GetResponseInfo failed: %v", err)
			}

			if info.SignatureAlg != tc.expectedOID {
				t.Errorf("Expected OID %s, got %s", tc.expectedOID, info.SignatureAlg)
			}
		})
	}
}
