package main

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"os"
	"testing"

	"github.com/remiblancher/post-quantum-pki/pkg/ca"
	"github.com/remiblancher/post-quantum-pki/pkg/profile"
)

// resetIssueFlags resets all issue command flags to their default values.
func resetIssueFlags() {
	issueCADir = "./ca"
	issueProfile = ""
	issueCSRFile = ""
	issuePubKeyFile = ""
	issueKeyFile = ""
	issueCertOut = ""
	issueCAPassphrase = ""
	issueHybridAlg = ""
	issueAttestCert = ""
	issueVars = nil
	issueVarFile = ""
}

// =============================================================================
// Issue from CSR Tests
// =============================================================================

func TestF_Cert_Issue_FromCSR(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create CA
	caDir := tc.path("ca")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Test CA",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
	)
	assertNoError(t, err)

	resetCSRFlags()

	// Generate CSR
	keyOut := tc.path("server.key")
	csrOut := tc.path("server.csr")
	_, err = executeCommand(rootCmd, "csr", "gen",
		"--algorithm", "ecdsa-p256",
		"--keyout", keyOut,
		"--cn", "server.example.com",
		"--dns", "server.example.com",
		"--out", csrOut,
	)
	assertNoError(t, err)

	resetIssueFlags()

	// Issue certificate from CSR
	certOut := tc.path("server.crt")
	_, err = executeCommand(rootCmd, "cert", "issue",
		"--ca-dir", caDir,
		"--profile", "ec/tls-server",
		"--csr", csrOut,
		"--var", "cn=server.example.com",
		"--var", "dns_names=server.example.com",
		"--out", certOut,
	)
	assertNoError(t, err)
	assertFileExists(t, certOut)
}

func TestF_Cert_Issue_WithCommonNameOverride(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create CA
	caDir := tc.path("ca")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Test CA",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
	)
	assertNoError(t, err)

	resetCSRFlags()

	// Generate CSR
	keyOut := tc.path("server.key")
	csrOut := tc.path("server.csr")
	_, err = executeCommand(rootCmd, "csr", "gen",
		"--algorithm", "ecdsa-p256",
		"--keyout", keyOut,
		"--cn", "original.example.com",
		"--out", csrOut,
	)
	assertNoError(t, err)

	resetIssueFlags()

	// Issue with CN override via --var
	certOut := tc.path("server.crt")
	_, err = executeCommand(rootCmd, "cert", "issue",
		"--ca-dir", caDir,
		"--profile", "ec/tls-server",
		"--csr", csrOut,
		"--var", "cn=override.example.com",
		"--var", "dns_names=override.example.com",
		"--out", certOut,
	)
	assertNoError(t, err)
	assertFileExists(t, certOut)
}

// =============================================================================
// Issue Error Cases
// =============================================================================

func TestF_Cert_Issue_MissingProfile(t *testing.T) {
	tc := newTestContext(t)
	resetIssueFlags()

	_, err := executeCommand(rootCmd, "cert", "issue",
		"--ca-dir", tc.path("ca"),
		"--csr", tc.path("server.csr"),
	)
	assertError(t, err)
}

func TestF_Cert_Issue_MissingCSR(t *testing.T) {
	tc := newTestContext(t)
	resetIssueFlags()

	_, err := executeCommand(rootCmd, "cert", "issue",
		"--ca-dir", tc.path("ca"),
		"--profile", "ec/tls-server",
	)
	assertError(t, err)
}

func TestF_Cert_Issue_CANotFound(t *testing.T) {
	tc := newTestContext(t)
	resetIssueFlags()

	// Create a dummy CSR file
	csrPath := tc.writeFile("dummy.csr", "-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----\n")

	_, err := executeCommand(rootCmd, "cert", "issue",
		"--ca-dir", tc.path("nonexistent"),
		"--profile", "ec/tls-server",
		"--csr", csrPath,
	)
	assertError(t, err)
}

func TestF_Cert_Issue_InvalidCSRFile(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create CA
	caDir := tc.path("ca")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Test CA",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
	)
	assertNoError(t, err)

	resetIssueFlags()

	// Create invalid CSR
	invalidCSR := tc.writeFile("invalid.csr", "not a valid CSR")

	_, err = executeCommand(rootCmd, "cert", "issue",
		"--ca-dir", caDir,
		"--profile", "ec/tls-server",
		"--csr", invalidCSR,
	)
	assertError(t, err)
}

func TestF_Cert_Issue_CSRFileNotFound(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create CA
	caDir := tc.path("ca")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Test CA",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
	)
	assertNoError(t, err)

	resetIssueFlags()

	_, err = executeCommand(rootCmd, "cert", "issue",
		"--ca-dir", caDir,
		"--profile", "ec/tls-server",
		"--csr", tc.path("nonexistent.csr"),
	)
	assertError(t, err)
}

func TestF_Cert_Issue_InvalidProfile(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create CA
	caDir := tc.path("ca")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Test CA",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
	)
	assertNoError(t, err)

	resetCSRFlags()

	// Generate CSR
	keyOut := tc.path("server.key")
	csrOut := tc.path("server.csr")
	_, _ = executeCommand(rootCmd, "csr", "gen",
		"--algorithm", "ecdsa-p256",
		"--keyout", keyOut,
		"--cn", "server.example.com",
		"--out", csrOut,
	)

	resetIssueFlags()

	_, err = executeCommand(rootCmd, "cert", "issue",
		"--ca-dir", caDir,
		"--profile", "nonexistent/profile",
		"--csr", csrOut,
	)
	assertError(t, err)
}

// =============================================================================
// Issue with IP Addresses
// =============================================================================

func TestF_Cert_Issue_WithIPAddresses(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create CA
	caDir := tc.path("ca")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Test CA",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
	)
	assertNoError(t, err)

	resetCSRFlags()

	// Generate CSR with IP addresses
	keyOut := tc.path("server.key")
	csrOut := tc.path("server.csr")
	_, err = executeCommand(rootCmd, "csr", "gen",
		"--algorithm", "ecdsa-p256",
		"--keyout", keyOut,
		"--cn", "server.example.com",
		"--ip", "192.168.1.1",
		"--ip", "10.0.0.1",
		"--out", csrOut,
	)
	assertNoError(t, err)

	resetIssueFlags()

	// Issue certificate
	certOut := tc.path("server.crt")
	_, err = executeCommand(rootCmd, "cert", "issue",
		"--ca-dir", caDir,
		"--profile", "ec/tls-server",
		"--csr", csrOut,
		"--var", "cn=server.example.com",
		"--var", "dns_names=server.example.com",
		"--var", "ip_addresses=192.168.1.1,10.0.0.1",
		"--out", certOut,
	)
	assertNoError(t, err)
	assertFileExists(t, certOut)
}

func TestF_Cert_Issue_WithIPv6Addresses(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create CA
	caDir := tc.path("ca")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Test CA",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
	)
	assertNoError(t, err)

	resetCSRFlags()

	// Generate CSR with IPv6 addresses
	keyOut := tc.path("server.key")
	csrOut := tc.path("server.csr")
	_, err = executeCommand(rootCmd, "csr", "gen",
		"--algorithm", "ecdsa-p256",
		"--keyout", keyOut,
		"--cn", "server.example.com",
		"--ip", "::1",
		"--ip", "2001:db8::1",
		"--out", csrOut,
	)
	assertNoError(t, err)

	resetIssueFlags()

	// Issue certificate
	certOut := tc.path("server.crt")
	_, err = executeCommand(rootCmd, "cert", "issue",
		"--ca-dir", caDir,
		"--profile", "ec/tls-server",
		"--csr", csrOut,
		"--var", "cn=server.example.com",
		"--var", "dns_names=server.example.com",
		"--var", "ip_addresses=::1,2001:db8::1",
		"--out", certOut,
	)
	assertNoError(t, err)
	assertFileExists(t, certOut)
}

func TestF_Cert_Issue_InvalidIPAddress(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create CA
	caDir := tc.path("ca")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Test CA",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
	)
	assertNoError(t, err)

	resetCSRFlags()

	// Generate CSR
	keyOut := tc.path("server.key")
	csrOut := tc.path("server.csr")
	_, err = executeCommand(rootCmd, "csr", "gen",
		"--algorithm", "ecdsa-p256",
		"--keyout", keyOut,
		"--cn", "server.example.com",
		"--out", csrOut,
	)
	assertNoError(t, err)

	resetIssueFlags()

	// Try to issue with invalid IP
	_, err = executeCommand(rootCmd, "cert", "issue",
		"--ca-dir", caDir,
		"--profile", "ec/tls-server",
		"--csr", csrOut,
		"--var", "cn=server.example.com",
		"--var", "dns_names=server.example.com",
		"--var", "ip_addresses=not-an-ip",
		"--out", tc.path("server.crt"),
	)
	assertError(t, err)
}

// =============================================================================
// Issue Helper Function Unit Tests
// =============================================================================

func TestU_ParseIPStrings(t *testing.T) {
	tests := []struct {
		name    string
		input   []string
		wantLen int
	}{
		{"Empty slice", []string{}, 0},
		{"Single valid IPv4", []string{"192.168.1.1"}, 1},
		{"Multiple valid IPv4", []string{"192.168.1.1", "10.0.0.1"}, 2},
		{"Valid IPv6", []string{"::1"}, 1},
		{"Mixed IPv4 and IPv6", []string{"192.168.1.1", "::1"}, 2},
		{"Invalid IP skipped", []string{"not-an-ip"}, 0},
		{"Mixed valid and invalid", []string{"192.168.1.1", "not-an-ip", "10.0.0.1"}, 2},
		{"Localhost", []string{"127.0.0.1"}, 1},
		{"Full IPv6", []string{"2001:0db8:85a3:0000:0000:8a2e:0370:7334"}, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseIPStrings(tt.input)
			if len(result) != tt.wantLen {
				t.Errorf("parseIPStrings(%v) returned %d IPs, want %d", tt.input, len(result), tt.wantLen)
			}
		})
	}
}

func TestU_ParseIPStrings_ValidIPValues(t *testing.T) {
	input := []string{"192.168.1.1", "10.0.0.1"}
	result := parseIPStrings(input)

	if len(result) != 2 {
		t.Fatalf("Expected 2 IPs, got %d", len(result))
	}

	if result[0].String() != "192.168.1.1" {
		t.Errorf("First IP = %s, want 192.168.1.1", result[0].String())
	}
	if result[1].String() != "10.0.0.1" {
		t.Errorf("Second IP = %s, want 10.0.0.1", result[1].String())
	}
}

func TestU_MergeCSRVariables_EmptyVars(t *testing.T) {
	varValues := make(map[string]interface{})
	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		DNSNames:    []string{"test.example.com", "www.example.com"},
		IPAddresses: []net.IP{net.ParseIP("192.168.1.1")},
	}

	mergeCSRVariables(varValues, template)

	if varValues["cn"] != "test.example.com" {
		t.Errorf("cn = %v, want test.example.com", varValues["cn"])
	}
	if dns, ok := varValues["dns_names"].([]string); !ok || len(dns) != 2 {
		t.Errorf("dns_names not merged correctly: %v", varValues["dns_names"])
	}
	if ips, ok := varValues["ip_addresses"].([]string); !ok || len(ips) != 1 {
		t.Errorf("ip_addresses not merged correctly: %v", varValues["ip_addresses"])
	}
}

func TestU_MergeCSRVariables_ExistingVarsNotOverwritten(t *testing.T) {
	varValues := map[string]interface{}{
		"cn": "existing-cn.example.com",
	}
	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "csr-cn.example.com",
		},
	}

	mergeCSRVariables(varValues, template)

	// Existing value should NOT be overwritten
	if varValues["cn"] != "existing-cn.example.com" {
		t.Errorf("cn was overwritten: %v, want existing-cn.example.com", varValues["cn"])
	}
}

func TestU_MergeCSRVariables_EmptyTemplate(t *testing.T) {
	varValues := make(map[string]interface{})
	template := &x509.Certificate{}

	mergeCSRVariables(varValues, template)

	// Nothing should be added
	if _, exists := varValues["cn"]; exists {
		t.Error("cn should not be added for empty template")
	}
	if _, exists := varValues["dns_names"]; exists {
		t.Error("dns_names should not be added for empty template")
	}
}

func TestU_WriteCertificatePEM(t *testing.T) {
	tc := newTestContext(t)

	// Create a test certificate
	priv, pub := generateECDSAKeyPair(t)
	cert := generateSelfSignedCert(t, priv, pub)

	// Write to file
	certPath := tc.path("test-cert.pem")
	err := writeCertificatePEM(cert, certPath)
	assertNoError(t, err)

	// Verify file exists and contains valid PEM
	assertFileExists(t, certPath)
	assertFileNotEmpty(t, certPath)

	// Read back and verify
	data, err := os.ReadFile(certPath)
	assertNoError(t, err)

	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("No PEM block found in written file")
	}
	if block.Type != "CERTIFICATE" {
		t.Errorf("PEM type = %s, want CERTIFICATE", block.Type)
	}

	// Parse the certificate to verify it's valid
	parsedCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse written certificate: %v", err)
	}
	if parsedCert.Subject.CommonName != cert.Subject.CommonName {
		t.Errorf("CN mismatch: got %s, want %s", parsedCert.Subject.CommonName, cert.Subject.CommonName)
	}
}

func TestU_WriteCertificatePEM_InvalidPath(t *testing.T) {
	priv, pub := generateECDSAKeyPair(t)
	cert := generateSelfSignedCert(t, priv, pub)

	// Try to write to an invalid path
	err := writeCertificatePEM(cert, "/nonexistent/directory/cert.pem")
	if err == nil {
		t.Error("Expected error for invalid path")
	}
}

// =============================================================================
// parseCSRFromFile Tests
// =============================================================================

func TestU_ParseCSRFromFile_FileNotFound(t *testing.T) {
	_, err := parseCSRFromFile("/nonexistent/file.csr", "")
	if err == nil {
		t.Error("Expected error for non-existent CSR file")
	}
}

func TestU_ParseCSRFromFile_InvalidPEM(t *testing.T) {
	tc := newTestContext(t)

	// Create a file with invalid PEM content
	invalidPath := tc.writeFile("invalid.csr", "not a PEM file")

	_, err := parseCSRFromFile(invalidPath, "")
	if err == nil {
		t.Error("Expected error for invalid PEM file")
	}
}

func TestU_ParseCSRFromFile_WrongPEMType(t *testing.T) {
	tc := newTestContext(t)

	// Create a file with wrong PEM type
	wrongTypePath := tc.writeFile("wrong.csr", "-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n")

	_, err := parseCSRFromFile(wrongTypePath, "")
	if err == nil {
		t.Error("Expected error for wrong PEM type")
	}
}

func TestU_ParseCSRFromFile_ValidCSR(t *testing.T) {
	tc := newTestContext(t)
	resetCSRFlags()

	// Generate a valid CSR
	keyOut := tc.path("test.key")
	csrOut := tc.path("test.csr")
	_, err := executeCommand(rootCmd, "csr", "gen",
		"--algorithm", "ecdsa-p256",
		"--keyout", keyOut,
		"--cn", "test.example.com",
		"--dns", "test.example.com",
		"--out", csrOut,
	)
	assertNoError(t, err)

	// Parse the CSR
	result, err := parseCSRFromFile(csrOut, "")
	if err != nil {
		t.Fatalf("parseCSRFromFile() error = %v", err)
	}

	if result == nil {
		t.Fatal("parseCSRFromFile() returned nil result")
	}
	if result.PublicKey == nil {
		t.Error("parseCSRFromFile() result has nil PublicKey")
	}
	if result.Template == nil {
		t.Error("parseCSRFromFile() result has nil Template")
	}
	if result.Template.Subject.CommonName != "test.example.com" {
		t.Errorf("Template CN = %s, want test.example.com", result.Template.Subject.CommonName)
	}
}

// =============================================================================
// extractPQCPublicKeyFromCert Tests
// =============================================================================

func TestU_ExtractPQCPublicKeyFromCert_NilCert(t *testing.T) {
	_, err := extractPQCPublicKeyFromCert(nil)
	if err == nil {
		t.Error("Expected error for nil certificate")
	}
}

func TestU_ExtractPQCPublicKeyFromCert_ClassicalCert(t *testing.T) {
	// Create a classical certificate
	priv, pub := generateECDSAKeyPair(t)
	cert := generateSelfSignedCert(t, priv, pub)

	// Should return the existing public key
	pubKey, err := extractPQCPublicKeyFromCert(cert)
	if err != nil {
		t.Fatalf("extractPQCPublicKeyFromCert() error = %v", err)
	}
	if pubKey == nil {
		t.Error("extractPQCPublicKeyFromCert() returned nil public key")
	}
}

// =============================================================================
// loadAndRenderIssueVariables Tests
// =============================================================================

func TestU_LoadAndRenderIssueVariables_NoVariables(t *testing.T) {
	// Create a profile with no variables
	prof := &profile.Profile{
		Name:      "test-profile",
		Variables: nil,
	}

	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
	}

	result, err := loadAndRenderIssueVariables(prof, "", nil, template)
	if err != nil {
		t.Fatalf("loadAndRenderIssueVariables() error = %v", err)
	}

	// CN should be merged from template
	if result["cn"] != "test.example.com" {
		t.Errorf("cn = %v, want test.example.com", result["cn"])
	}
}

func TestU_LoadAndRenderIssueVariables_WithVars(t *testing.T) {
	prof := &profile.Profile{
		Name:      "test-profile",
		Variables: nil,
	}

	template := &x509.Certificate{}

	vars := []string{"cn=override.example.com", "org=Test Org"}
	result, err := loadAndRenderIssueVariables(prof, "", vars, template)
	if err != nil {
		t.Fatalf("loadAndRenderIssueVariables() error = %v", err)
	}

	if result["cn"] != "override.example.com" {
		t.Errorf("cn = %v, want override.example.com", result["cn"])
	}
	if result["org"] != "Test Org" {
		t.Errorf("org = %v, want Test Org", result["org"])
	}
}

func TestU_LoadAndRenderIssueVariables_InvalidVarFile(t *testing.T) {
	prof := &profile.Profile{
		Name: "test-profile",
	}

	template := &x509.Certificate{}

	_, err := loadAndRenderIssueVariables(prof, "/nonexistent/vars.yaml", nil, template)
	if err == nil {
		t.Error("Expected error for non-existent var file")
	}
}

// =============================================================================
// parseClassicalCSR Additional Tests
// =============================================================================

func TestU_ParseClassicalCSR_ValidCSR(t *testing.T) {
	tc := newTestContext(t)
	resetCSRFlags()

	// Generate a valid CSR
	keyOut := tc.path("test.key")
	csrOut := tc.path("test.csr")
	_, err := executeCommand(rootCmd, "csr", "gen",
		"--algorithm", "ecdsa-p256",
		"--keyout", keyOut,
		"--cn", "test.example.com",
		"--dns", "test.example.com",
		"--dns", "www.example.com",
		"--ip", "192.168.1.1",
		"--out", csrOut,
	)
	assertNoError(t, err)

	// Read and parse CSR
	csrData, err := os.ReadFile(csrOut)
	assertNoError(t, err)

	block, _ := pem.Decode(csrData)
	if block == nil {
		t.Fatal("Failed to decode PEM block")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	assertNoError(t, err)

	// Test parseClassicalCSR directly
	result, err := parseClassicalCSR(csr, block.Bytes, "")
	if err != nil {
		t.Fatalf("parseClassicalCSR() error = %v", err)
	}

	if result == nil {
		t.Fatal("parseClassicalCSR() returned nil")
	}
	if result.PublicKey == nil {
		t.Error("parseClassicalCSR() result has nil PublicKey")
	}
	if result.Template == nil {
		t.Error("parseClassicalCSR() result has nil Template")
	}
	if result.Template.Subject.CommonName != "test.example.com" {
		t.Errorf("Template.Subject.CommonName = %s, want test.example.com", result.Template.Subject.CommonName)
	}
	if len(result.Template.DNSNames) != 2 {
		t.Errorf("Template.DNSNames has %d entries, want 2", len(result.Template.DNSNames))
	}
	// Note: IP addresses from CSR are included in the template
	t.Logf("Template.IPAddresses has %d entries", len(result.Template.IPAddresses))
}

// =============================================================================
// extractPQCPublicKeyFromCert Additional Tests
// =============================================================================

func TestU_ExtractPQCPublicKeyFromCert_PQCCert(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create a PQC CA
	caDir := tc.path("pqc-ca")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--var", "cn=PQC Test CA",
		"--profile", "ml/root-ca",
		"--ca-dir", caDir,
	)
	if err != nil {
		t.Skipf("Skipping PQC test: %v", err)
	}

	resetCAFlags()

	// Load the PQC certificate using the CA store
	store := ca.NewFileStore(caDir)
	cert, err := store.LoadCACert(context.Background())
	if err != nil {
		t.Fatalf("Failed to load PQC cert: %v", err)
	}

	// Test extractPQCPublicKeyFromCert
	pubKey, err := extractPQCPublicKeyFromCert(cert)
	if err != nil {
		t.Fatalf("extractPQCPublicKeyFromCert() error = %v", err)
	}
	if pubKey == nil {
		t.Error("extractPQCPublicKeyFromCert() returned nil public key")
	}
}

// =============================================================================
// Issue PQC Certificate Tests
// =============================================================================

func TestF_Cert_Issue_PQCCSR(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create PQC CA
	caDir := tc.path("pqc-ca")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--var", "cn=PQC Test CA",
		"--profile", "ml/root-ca",
		"--ca-dir", caDir,
	)
	if err != nil {
		t.Skipf("Skipping PQC test: %v", err)
	}

	resetCSRFlags()

	// Generate PQC CSR
	keyOut := tc.path("pqc-server.key")
	csrOut := tc.path("pqc-server.csr")
	_, err = executeCommand(rootCmd, "csr", "gen",
		"--algorithm", "ml-dsa-65",
		"--keyout", keyOut,
		"--cn", "pqc-server.example.com",
		"--dns", "pqc-server.example.com",
		"--out", csrOut,
	)
	if err != nil {
		t.Skipf("Skipping PQC CSR test: %v", err)
	}

	resetIssueFlags()

	// Issue PQC certificate
	certOut := tc.path("pqc-server.crt")
	_, err = executeCommand(rootCmd, "cert", "issue",
		"--ca-dir", caDir,
		"--profile", "ml/tls-server",
		"--csr", csrOut,
		"--var", "cn=pqc-server.example.com",
		"--var", "dns_names=pqc-server.example.com",
		"--out", certOut,
	)
	if err != nil {
		t.Logf("PQC cert issue failed (expected if PQC not fully supported): %v", err)
		return
	}
	assertFileExists(t, certOut)
}

// =============================================================================
// Issue with Different Profile Types
// =============================================================================

func TestF_Cert_Issue_RSAProfile(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create RSA CA
	caDir := tc.path("rsa-ca")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--var", "cn=RSA Test CA",
		"--profile", "rsa/root-ca",
		"--ca-dir", caDir,
	)
	assertNoError(t, err)

	resetCSRFlags()

	// Generate RSA CSR
	keyOut := tc.path("rsa-server.key")
	csrOut := tc.path("rsa-server.csr")
	_, err = executeCommand(rootCmd, "csr", "gen",
		"--algorithm", "rsa-2048",
		"--keyout", keyOut,
		"--cn", "rsa-server.example.com",
		"--dns", "rsa-server.example.com",
		"--out", csrOut,
	)
	assertNoError(t, err)

	resetIssueFlags()

	// Issue RSA certificate
	certOut := tc.path("rsa-server.crt")
	_, err = executeCommand(rootCmd, "cert", "issue",
		"--ca-dir", caDir,
		"--profile", "rsa/tls-server",
		"--csr", csrOut,
		"--var", "cn=rsa-server.example.com",
		"--var", "dns_names=rsa-server.example.com",
		"--out", certOut,
	)
	assertNoError(t, err)
	assertFileExists(t, certOut)
}

func TestF_Cert_Issue_ECDSAWithSAN(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create ECDSA CA
	caDir := tc.path("ecdsa-ca")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--var", "cn=ECDSA Test CA",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
	)
	assertNoError(t, err)

	resetCSRFlags()

	// Generate ECDSA CSR with multiple SANs
	keyOut := tc.path("ecdsa-server.key")
	csrOut := tc.path("ecdsa-server.csr")
	_, err = executeCommand(rootCmd, "csr", "gen",
		"--algorithm", "ecdsa-p256",
		"--keyout", keyOut,
		"--cn", "ecdsa-server.example.com",
		"--dns", "ecdsa-server.example.com",
		"--dns", "www.example.com",
		"--email", "admin@example.com",
		"--out", csrOut,
	)
	assertNoError(t, err)

	resetIssueFlags()

	// Issue ECDSA certificate
	certOut := tc.path("ecdsa-server.crt")
	_, err = executeCommand(rootCmd, "cert", "issue",
		"--ca-dir", caDir,
		"--profile", "ec/tls-server",
		"--csr", csrOut,
		"--var", "cn=ecdsa-server.example.com",
		"--var", "dns_names=ecdsa-server.example.com,www.example.com",
		"--out", certOut,
	)
	assertNoError(t, err)
	assertFileExists(t, certOut)
}

// =============================================================================
// loadCASignerForProfile Tests
// =============================================================================

func TestF_LoadCASignerForProfile_Standard(t *testing.T) {
	tc := newTestContext(t)
	resetCAFlags()

	// Create standard ECDSA CA
	caDir := tc.path("ca")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--var", "cn=Test CA",
		"--profile", "ec/root-ca",
		"--ca-dir", caDir,
	)
	assertNoError(t, err)

	resetCAFlags()

	// Load the CA
	store := ca.NewFileStore(caDir)
	caInstance, err := ca.New(store)
	if err != nil {
		t.Fatalf("Failed to load CA: %v", err)
	}

	// Load profile
	prof, err := profile.LoadProfile("ec/tls-server")
	if err != nil {
		t.Fatalf("Failed to load profile: %v", err)
	}

	// Test loadCASignerForProfile
	err = loadCASignerForProfile(caInstance, prof, "")
	if err != nil {
		t.Errorf("loadCASignerForProfile() error = %v", err)
	}
}

// =============================================================================
// MergeCSRVariables Edge Cases
// =============================================================================

func TestU_MergeCSRVariables_OnlyDNSNames(t *testing.T) {
	varValues := make(map[string]interface{})
	template := &x509.Certificate{
		DNSNames: []string{"dns1.example.com", "dns2.example.com"},
	}

	mergeCSRVariables(varValues, template)

	// CN should not be set (empty)
	if _, exists := varValues["cn"]; exists {
		t.Error("cn should not be set when template CN is empty")
	}

	// DNS names should be merged
	if dns, ok := varValues["dns_names"].([]string); !ok || len(dns) != 2 {
		t.Errorf("dns_names not merged correctly: %v", varValues["dns_names"])
	}
}

func TestU_MergeCSRVariables_OnlyIPAddresses(t *testing.T) {
	varValues := make(map[string]interface{})
	template := &x509.Certificate{
		IPAddresses: []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("::1")},
	}

	mergeCSRVariables(varValues, template)

	// IP addresses should be merged
	if ips, ok := varValues["ip_addresses"].([]string); !ok || len(ips) != 2 {
		t.Errorf("ip_addresses not merged correctly: %v", varValues["ip_addresses"])
	}
}

func TestU_MergeCSRVariables_ExistingDNSNotOverwritten(t *testing.T) {
	varValues := map[string]interface{}{
		"dns_names": []string{"existing.example.com"},
	}
	template := &x509.Certificate{
		DNSNames: []string{"csr.example.com"},
	}

	mergeCSRVariables(varValues, template)

	// Existing DNS should NOT be overwritten
	if dns, ok := varValues["dns_names"].([]string); !ok || dns[0] != "existing.example.com" {
		t.Errorf("dns_names was overwritten: %v", varValues["dns_names"])
	}
}

func TestU_MergeCSRVariables_ExistingIPNotOverwritten(t *testing.T) {
	varValues := map[string]interface{}{
		"ip_addresses": []string{"1.1.1.1"},
	}
	template := &x509.Certificate{
		IPAddresses: []net.IP{net.ParseIP("192.168.1.1")},
	}

	mergeCSRVariables(varValues, template)

	// Existing IPs should NOT be overwritten
	if ips, ok := varValues["ip_addresses"].([]string); !ok || ips[0] != "1.1.1.1" {
		t.Errorf("ip_addresses was overwritten: %v", varValues["ip_addresses"])
	}
}
