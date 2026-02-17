package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/remiblancher/post-quantum-pki/pkg/ocsp"
)

// =============================================================================
// Unit Tests for cert_verify_helpers.go
// =============================================================================

// createTestCertWithValidity creates a test certificate with specific validity period.
func createTestCertWithValidity(t *testing.T, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("Failed to generate serial: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "Test Certificate",
			Organization: []string{"Test Org"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
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
// checkValidityPeriod Tests
// =============================================================================

func TestU_CheckValidityPeriod_Valid(t *testing.T) {
	// Create certificate valid from 1 hour ago to 24 hours from now
	cert := createTestCertWithValidity(t,
		time.Now().Add(-1*time.Hour),
		time.Now().Add(24*time.Hour),
	)

	valid, statusMsg, expiredInfo := checkValidityPeriod(cert)

	if !valid {
		t.Errorf("Expected certificate to be valid, got invalid")
	}
	if statusMsg != "" {
		t.Errorf("Expected empty status message, got %q", statusMsg)
	}
	if expiredInfo != "" {
		t.Errorf("Expected empty expired info, got %q", expiredInfo)
	}
}

func TestU_CheckValidityPeriod_NotYetValid(t *testing.T) {
	// Create certificate valid starting 10 days from now
	cert := createTestCertWithValidity(t,
		time.Now().Add(10*24*time.Hour),
		time.Now().Add(20*24*time.Hour),
	)

	valid, statusMsg, expiredInfo := checkValidityPeriod(cert)

	if valid {
		t.Errorf("Expected certificate to be invalid (not yet valid)")
	}
	if statusMsg != "NOT YET VALID" {
		t.Errorf("Expected status 'NOT YET VALID', got %q", statusMsg)
	}
	if expiredInfo == "" {
		t.Error("Expected expiredInfo to contain validity info")
	}
	if !strings.Contains(expiredInfo, "Not valid until") {
		t.Errorf("Expected expiredInfo to mention 'Not valid until', got %q", expiredInfo)
	}
}

func TestU_CheckValidityPeriod_Expired(t *testing.T) {
	// Create certificate that expired 5 days ago
	cert := createTestCertWithValidity(t,
		time.Now().Add(-10*24*time.Hour),
		time.Now().Add(-5*24*time.Hour),
	)

	valid, statusMsg, expiredInfo := checkValidityPeriod(cert)

	if valid {
		t.Errorf("Expected certificate to be invalid (expired)")
	}
	if statusMsg != "EXPIRED" {
		t.Errorf("Expected status 'EXPIRED', got %q", statusMsg)
	}
	if expiredInfo == "" {
		t.Error("Expected expiredInfo to contain expiry info")
	}
	if !strings.Contains(expiredInfo, "Expired") {
		t.Errorf("Expected expiredInfo to mention 'Expired', got %q", expiredInfo)
	}
	if !strings.Contains(expiredInfo, "days ago") {
		t.Errorf("Expected expiredInfo to mention 'days ago', got %q", expiredInfo)
	}
}

func TestU_CheckValidityPeriod_JustExpired(t *testing.T) {
	// Create certificate that expired 1 hour ago (0 days ago)
	cert := createTestCertWithValidity(t,
		time.Now().Add(-48*time.Hour),
		time.Now().Add(-1*time.Hour),
	)

	valid, statusMsg, _ := checkValidityPeriod(cert)

	if valid {
		t.Errorf("Expected certificate to be invalid (just expired)")
	}
	if statusMsg != "EXPIRED" {
		t.Errorf("Expected status 'EXPIRED', got %q", statusMsg)
	}
}

// =============================================================================
// checkRevocationStatus Tests
// =============================================================================

func TestU_CheckRevocationStatus_NoCheck(t *testing.T) {
	cert := createTestCertWithValidity(t,
		time.Now().Add(-1*time.Hour),
		time.Now().Add(24*time.Hour),
	)

	revoked, info, err := checkRevocationStatus(cert, cert, "", "")

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if revoked {
		t.Error("Expected not revoked when no check performed")
	}
	if !strings.Contains(info, "Not checked") {
		t.Errorf("Expected info to mention 'Not checked', got %q", info)
	}
}

func TestU_CheckRevocationStatus_CRLFileNotFound(t *testing.T) {
	cert := createTestCertWithValidity(t,
		time.Now().Add(-1*time.Hour),
		time.Now().Add(24*time.Hour),
	)

	_, _, err := checkRevocationStatus(cert, cert, "/nonexistent/path.crl", "")

	if err == nil {
		t.Error("Expected error for non-existent CRL file")
	}
	if !strings.Contains(err.Error(), "CRL check failed") {
		t.Errorf("Expected CRL check failed error, got %v", err)
	}
}

// =============================================================================
// printVerifyResult Tests
// =============================================================================

func TestU_PrintVerifyResult_Valid(t *testing.T) {
	cert := createTestCertWithValidity(t,
		time.Now().Add(-1*time.Hour),
		time.Now().Add(24*time.Hour),
	)

	result := &verifyResult{
		IsValid:        true,
		StatusMsg:      "VALID",
		RevocationInfo: "  Revocation: Not checked",
		ExpiredInfo:    "",
	}

	// Just verify it doesn't panic - output goes to stdout
	printVerifyResult(cert, result)
}

func TestU_PrintVerifyResult_Invalid(t *testing.T) {
	cert := createTestCertWithValidity(t,
		time.Now().Add(-10*24*time.Hour),
		time.Now().Add(-5*24*time.Hour),
	)

	result := &verifyResult{
		IsValid:        false,
		StatusMsg:      "EXPIRED",
		RevocationInfo: "  Revocation: Not checked",
		ExpiredInfo:    "  Expired: 5 days ago",
	}

	// Just verify it doesn't panic
	printVerifyResult(cert, result)
}

// =============================================================================
// verifyCertificateSignature Tests
// =============================================================================

func TestU_VerifyCertificateSignature_SelfSigned(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Self-signed cert should verify against itself
	err = verifyCertificateSignature(cert, cert, nil)
	if err != nil {
		t.Errorf("Expected self-signed cert to verify, got error: %v", err)
	}
}

func TestU_VerifyCertificateSignature_WrongIssuer(t *testing.T) {
	// Create two separate CAs
	priv1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	priv2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	serial1, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	serial2, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template1 := &x509.Certificate{
		SerialNumber:          serial1,
		Subject:               pkix.Name{CommonName: "CA 1"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	template2 := &x509.Certificate{
		SerialNumber:          serial2,
		Subject:               pkix.Name{CommonName: "CA 2"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	cert1DER, _ := x509.CreateCertificate(rand.Reader, template1, template1, &priv1.PublicKey, priv1)
	cert2DER, _ := x509.CreateCertificate(rand.Reader, template2, template2, &priv2.PublicKey, priv2)

	cert1, _ := x509.ParseCertificate(cert1DER)
	cert2, _ := x509.ParseCertificate(cert2DER)

	// Cert1 should NOT verify against Cert2
	err := verifyCertificateSignature(cert1, cert2, nil)
	if err == nil {
		t.Error("Expected verification to fail with wrong issuer")
	}
}

func TestU_VerifyCertificateSignature_IssuedCert(t *testing.T) {
	// Create CA
	caPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	caTemplate := &x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caPriv.PublicKey, caPriv)
	caCert, _ := x509.ParseCertificate(caCertDER)

	// Create end-entity cert signed by CA
	eePriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	eeSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	eeTemplate := &x509.Certificate{
		SerialNumber:          eeSerial,
		Subject:               pkix.Name{CommonName: "End Entity"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	eeCertDER, _ := x509.CreateCertificate(rand.Reader, eeTemplate, caCert, &eePriv.PublicKey, caPriv)
	eeCert, _ := x509.ParseCertificate(eeCertDER)

	// End-entity cert should verify against CA
	err := verifyCertificateSignature(eeCert, caCert, nil)
	if err != nil {
		t.Errorf("Expected issued cert to verify against CA, got error: %v", err)
	}
}

// =============================================================================
// getOCSPRevocationReasonString Tests
// =============================================================================

func TestU_GetOCSPRevocationReasonString(t *testing.T) {
	tests := []struct {
		reason   ocsp.RevocationReason
		expected string
	}{
		{0, "unspecified"},
		{1, "keyCompromise"},
		{2, "cACompromise"},
		{3, "affiliationChanged"},
		{4, "superseded"},
		{5, "cessationOfOperation"},
		{6, "certificateHold"},
		{8, "removeFromCRL"},
		{9, "privilegeWithdrawn"},
		{10, "aACompromise"},
		{99, "unknown (99)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := getOCSPRevocationReasonString(tt.reason)
			if result != tt.expected {
				t.Errorf("getOCSPRevocationReasonString(%d) = %q, want %q", tt.reason, result, tt.expected)
			}
		})
	}
}

// =============================================================================
// loadAllCertificates Tests
// =============================================================================

func TestU_LoadAllCertificates_Single(t *testing.T) {
	// Create a temp file with a single certificate
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Test Cert"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)

	// Write to temp file
	tmpDir := t.TempDir()
	certPath := tmpDir + "/cert.pem"
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	_ = os.WriteFile(certPath, pemData, 0644)

	// Load
	certs, err := loadAllCertificates(certPath)
	if err != nil {
		t.Fatalf("loadAllCertificates failed: %v", err)
	}

	if len(certs) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(certs))
	}
}

func TestU_LoadAllCertificates_Multiple(t *testing.T) {
	// Create two certificates
	tmpDir := t.TempDir()
	certPath := tmpDir + "/bundle.pem"

	var pemData []byte
	for i := 0; i < 2; i++ {
		priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

		template := &x509.Certificate{
			SerialNumber:          serial,
			Subject:               pkix.Name{CommonName: "Test Cert"},
			NotBefore:             time.Now().Add(-1 * time.Hour),
			NotAfter:              time.Now().Add(24 * time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
		}

		certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
		pemData = append(pemData, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})...)
	}

	_ = os.WriteFile(certPath, pemData, 0644)

	// Load
	certs, err := loadAllCertificates(certPath)
	if err != nil {
		t.Fatalf("loadAllCertificates failed: %v", err)
	}

	if len(certs) != 2 {
		t.Errorf("expected 2 certificates, got %d", len(certs))
	}
}

func TestU_LoadAllCertificates_FileNotFound(t *testing.T) {
	_, err := loadAllCertificates("/nonexistent/path.pem")
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestU_LoadAllCertificates_NoCerts(t *testing.T) {
	tmpDir := t.TempDir()
	emptyPath := tmpDir + "/empty.pem"
	_ = os.WriteFile(emptyPath, []byte("not a certificate"), 0644)

	_, err := loadAllCertificates(emptyPath)
	if err == nil {
		t.Error("expected error when no certificates found")
	}
	if !strings.Contains(err.Error(), "no certificates found") {
		t.Errorf("expected 'no certificates found' error, got: %v", err)
	}
}

// =============================================================================
// findMatchingCA Tests
// =============================================================================

func TestU_FindMatchingCA_Match(t *testing.T) {
	// Create CA certificate with SubjectKeyId
	caPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	subjectKeyId := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}

	caTemplate := &x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          subjectKeyId,
	}

	caCertDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caPriv.PublicKey, caPriv)
	caCert, _ := x509.ParseCertificate(caCertDER)

	// Create leaf certificate with matching AuthorityKeyId
	leafPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	leafTemplate := &x509.Certificate{
		SerialNumber:          leafSerial,
		Subject:               pkix.Name{CommonName: "Leaf Cert"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		AuthorityKeyId:        subjectKeyId,
	}

	leafCertDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafPriv.PublicKey, caPriv)
	leafCert, _ := x509.ParseCertificate(leafCertDER)

	// Find matching CA
	result := findMatchingCA(leafCert, []*x509.Certificate{caCert})
	if result == nil {
		t.Error("expected to find matching CA")
	}
	if result != caCert {
		t.Error("returned CA doesn't match expected CA")
	}
}

func TestU_FindMatchingCA_NoMatch(t *testing.T) {
	// Create CA certificate
	caPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	caTemplate := &x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{1, 2, 3, 4, 5},
	}

	caCertDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caPriv.PublicKey, caPriv)
	caCert, _ := x509.ParseCertificate(caCertDER)

	// Create leaf with different AuthorityKeyId
	leafPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	leafTemplate := &x509.Certificate{
		SerialNumber:          leafSerial,
		Subject:               pkix.Name{CommonName: "Leaf Cert"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		AuthorityKeyId:        []byte{99, 99, 99}, // Different
	}

	leafCertDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, leafTemplate, &leafPriv.PublicKey, leafPriv)
	leafCert, _ := x509.ParseCertificate(leafCertDER)

	// Should not find matching CA
	result := findMatchingCA(leafCert, []*x509.Certificate{caCert})
	if result != nil {
		t.Error("expected no match for different AuthorityKeyId")
	}
}

func TestU_FindMatchingCA_NoAuthorityKeyId(t *testing.T) {
	// Create CA certificate
	caPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	caTemplate := &x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{1, 2, 3, 4, 5},
	}

	caCertDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caPriv.PublicKey, caPriv)
	caCert, _ := x509.ParseCertificate(caCertDER)

	// Create leaf without AuthorityKeyId
	leafPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	leafTemplate := &x509.Certificate{
		SerialNumber:          leafSerial,
		Subject:               pkix.Name{CommonName: "Leaf Cert"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		// No AuthorityKeyId
	}

	leafCertDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, leafTemplate, &leafPriv.PublicKey, leafPriv)
	leafCert, _ := x509.ParseCertificate(leafCertDER)

	// Should not find matching CA when cert has no AuthorityKeyId
	result := findMatchingCA(leafCert, []*x509.Certificate{caCert})
	if result != nil {
		t.Error("expected no match when leaf has no AuthorityKeyId")
	}
}
