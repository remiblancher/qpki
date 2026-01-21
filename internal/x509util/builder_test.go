package x509util

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"
)

// =============================================================================
// Unit Tests: CertificateBuilder Methods
// =============================================================================

func TestU_CertificateBuilder_Subject(t *testing.T) {
	subject := pkix.Name{
		CommonName:         "test.example.com",
		Organization:       []string{"Test Org"},
		OrganizationalUnit: []string{"Test OU"},
		Country:            []string{"FR"},
		Province:           []string{"IDF"},
		Locality:           []string{"Paris"},
	}

	template, err := NewCertificateBuilder().
		Subject(subject).
		EndEntity().
		Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if template.Subject.CommonName != "test.example.com" {
		t.Errorf("CommonName = %q, want %q", template.Subject.CommonName, "test.example.com")
	}
	if len(template.Subject.Organization) != 1 || template.Subject.Organization[0] != "Test Org" {
		t.Errorf("Organization = %v, want [Test Org]", template.Subject.Organization)
	}
	if len(template.Subject.Country) != 1 || template.Subject.Country[0] != "FR" {
		t.Errorf("Country = %v, want [FR]", template.Subject.Country)
	}
}

func TestU_CertificateBuilder_Country(t *testing.T) {
	template, err := NewCertificateBuilder().
		CommonName("test.example.com").
		Country("US").
		EndEntity().
		Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if len(template.Subject.Country) != 1 || template.Subject.Country[0] != "US" {
		t.Errorf("Country = %v, want [US]", template.Subject.Country)
	}
}

func TestU_CertificateBuilder_EmailAddresses(t *testing.T) {
	template, err := NewCertificateBuilder().
		CommonName("test@example.com").
		EmailAddresses("admin@example.com", "support@example.com").
		EndEntity().
		Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if len(template.EmailAddresses) != 2 {
		t.Errorf("EmailAddresses count = %d, want 2", len(template.EmailAddresses))
	}
	if template.EmailAddresses[0] != "admin@example.com" {
		t.Errorf("EmailAddresses[0] = %q, want %q", template.EmailAddresses[0], "admin@example.com")
	}
	if template.EmailAddresses[1] != "support@example.com" {
		t.Errorf("EmailAddresses[1] = %q, want %q", template.EmailAddresses[1], "support@example.com")
	}
}

func TestU_CertificateBuilder_URIs(t *testing.T) {
	uri1, _ := url.Parse("https://example.com/path1")
	uri2, _ := url.Parse("https://example.com/path2")

	template, err := NewCertificateBuilder().
		CommonName("test.example.com").
		URIs(uri1, uri2).
		EndEntity().
		Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if len(template.URIs) != 2 {
		t.Errorf("URIs count = %d, want 2", len(template.URIs))
	}
	if template.URIs[0].String() != "https://example.com/path1" {
		t.Errorf("URIs[0] = %q, want %q", template.URIs[0].String(), "https://example.com/path1")
	}
}

func TestU_CertificateBuilder_ValidFor(t *testing.T) {
	before := time.Now()
	template, err := NewCertificateBuilder().
		CommonName("test.example.com").
		ValidFor(30 * 24 * time.Hour). // 30 days
		EndEntity().
		Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	after := time.Now()

	// NotBefore should be approximately now
	if template.NotBefore.Before(before) || template.NotBefore.After(after.Add(time.Second)) {
		t.Error("NotBefore should be approximately now")
	}

	// NotAfter should be approximately 30 days from now
	expectedAfter := before.Add(30 * 24 * time.Hour)
	if template.NotAfter.Before(expectedAfter.Add(-time.Second)) || template.NotAfter.After(expectedAfter.Add(time.Minute)) {
		t.Errorf("NotAfter = %v, expected around %v", template.NotAfter, expectedAfter)
	}
}

func TestU_CertificateBuilder_KeyUsage(t *testing.T) {
	template, err := NewCertificateBuilder().
		CommonName("test.example.com").
		KeyUsage(x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment).
		EndEntity().
		Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if template.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("KeyUsage should include DigitalSignature")
	}
	if template.KeyUsage&x509.KeyUsageContentCommitment == 0 {
		t.Error("KeyUsage should include ContentCommitment")
	}
}

func TestU_CertificateBuilder_ExtKeyUsage(t *testing.T) {
	template, err := NewCertificateBuilder().
		CommonName("test.example.com").
		ExtKeyUsage(x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageCodeSigning).
		EndEntity().
		Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if len(template.ExtKeyUsage) != 3 {
		t.Errorf("ExtKeyUsage count = %d, want 3", len(template.ExtKeyUsage))
	}

	hasServerAuth := false
	hasClientAuth := false
	hasCodeSigning := false
	for _, eku := range template.ExtKeyUsage {
		switch eku {
		case x509.ExtKeyUsageServerAuth:
			hasServerAuth = true
		case x509.ExtKeyUsageClientAuth:
			hasClientAuth = true
		case x509.ExtKeyUsageCodeSigning:
			hasCodeSigning = true
		}
	}

	if !hasServerAuth {
		t.Error("ExtKeyUsage should include ServerAuth")
	}
	if !hasClientAuth {
		t.Error("ExtKeyUsage should include ClientAuth")
	}
	if !hasCodeSigning {
		t.Error("ExtKeyUsage should include CodeSigning")
	}
}

func TestU_CertificateBuilder_TLSClient(t *testing.T) {
	template, err := NewCertificateBuilder().
		CommonName("client.example.com").
		TLSClient().
		Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if template.IsCA {
		t.Error("TLS client should not be CA")
	}
	if template.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("TLS client should have DigitalSignature key usage")
	}
	if len(template.ExtKeyUsage) != 1 || template.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Error("TLS client should have ClientAuth extended key usage")
	}
}

func TestU_CertificateBuilder_CodeSigning(t *testing.T) {
	template, err := NewCertificateBuilder().
		CommonName("Code Signing Cert").
		CodeSigning().
		Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if template.IsCA {
		t.Error("CodeSigning cert should not be CA")
	}
	if template.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("CodeSigning cert should have DigitalSignature key usage")
	}
	if len(template.ExtKeyUsage) != 1 || template.ExtKeyUsage[0] != x509.ExtKeyUsageCodeSigning {
		t.Error("CodeSigning cert should have CodeSigning extended key usage")
	}
}

func TestU_CertificateBuilder_SerialNumber(t *testing.T) {
	serial := big.NewInt(12345678)

	template, err := NewCertificateBuilder().
		CommonName("test.example.com").
		SerialNumber(serial).
		EndEntity().
		Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if template.SerialNumber.Cmp(serial) != 0 {
		t.Errorf("SerialNumber = %v, want %v", template.SerialNumber, serial)
	}
}

func TestU_CertificateBuilder_CRLDistributionPoints(t *testing.T) {
	template, err := NewCertificateBuilder().
		CommonName("test.example.com").
		CRLDistributionPoints("http://crl.example.com/ca.crl", "http://crl2.example.com/ca.crl").
		EndEntity().
		Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if len(template.CRLDistributionPoints) != 2 {
		t.Errorf("CRLDistributionPoints count = %d, want 2", len(template.CRLDistributionPoints))
	}
	if template.CRLDistributionPoints[0] != "http://crl.example.com/ca.crl" {
		t.Errorf("CRLDistributionPoints[0] = %q, want %q", template.CRLDistributionPoints[0], "http://crl.example.com/ca.crl")
	}
}

func TestU_CertificateBuilder_OCSPServers(t *testing.T) {
	template, err := NewCertificateBuilder().
		CommonName("test.example.com").
		OCSPServers("http://ocsp.example.com", "http://ocsp2.example.com").
		EndEntity().
		Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if len(template.OCSPServer) != 2 {
		t.Errorf("OCSPServer count = %d, want 2", len(template.OCSPServer))
	}
	if template.OCSPServer[0] != "http://ocsp.example.com" {
		t.Errorf("OCSPServer[0] = %q, want %q", template.OCSPServer[0], "http://ocsp.example.com")
	}
}

func TestU_CertificateBuilder_IssuingCertificateURL(t *testing.T) {
	template, err := NewCertificateBuilder().
		CommonName("test.example.com").
		IssuingCertificateURL("http://pki.example.com/ca.crt").
		EndEntity().
		Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if len(template.IssuingCertificateURL) != 1 {
		t.Errorf("IssuingCertificateURL count = %d, want 1", len(template.IssuingCertificateURL))
	}
	if template.IssuingCertificateURL[0] != "http://pki.example.com/ca.crt" {
		t.Errorf("IssuingCertificateURL[0] = %q, want %q", template.IssuingCertificateURL[0], "http://pki.example.com/ca.crt")
	}
}

func TestU_CertificateBuilder_AddExtension(t *testing.T) {
	customExt := pkix.Extension{
		Id:       []int{1, 2, 3, 4, 5},
		Critical: false,
		Value:    []byte{0x01, 0x02, 0x03},
	}

	template, err := NewCertificateBuilder().
		CommonName("test.example.com").
		AddExtension(customExt).
		EndEntity().
		Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if len(template.ExtraExtensions) != 1 {
		t.Errorf("ExtraExtensions count = %d, want 1", len(template.ExtraExtensions))
	}
	if !OIDEqual(template.ExtraExtensions[0].Id, []int{1, 2, 3, 4, 5}) {
		t.Errorf("Extension OID = %v, want [1 2 3 4 5]", template.ExtraExtensions[0].Id)
	}
}

func TestU_CertificateBuilder_AddExtension_Multiple(t *testing.T) {
	ext1 := pkix.Extension{Id: []int{1, 2, 3}, Value: []byte{0x01}}
	ext2 := pkix.Extension{Id: []int{4, 5, 6}, Value: []byte{0x02}}

	template, err := NewCertificateBuilder().
		CommonName("test.example.com").
		AddExtension(ext1).
		AddExtension(ext2).
		EndEntity().
		Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if len(template.ExtraExtensions) != 2 {
		t.Errorf("ExtraExtensions count = %d, want 2", len(template.ExtraExtensions))
	}
}

// =============================================================================
// Unit Tests: BuildAndSign
// =============================================================================

func TestU_CertificateBuilder_BuildAndSign_SelfSigned(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	cert, certDER, err := NewCertificateBuilder().
		CommonName("Self-Signed CA").
		Organization("Test Org").
		CA(0).
		ValidForYears(10).
		BuildAndSign(&priv.PublicKey, nil, priv) // nil issuer = self-signed
	if err != nil {
		t.Fatalf("BuildAndSign() error = %v", err)
	}

	if cert == nil {
		t.Fatal("BuildAndSign() returned nil certificate")
	}
	if len(certDER) == 0 {
		t.Fatal("BuildAndSign() returned empty DER")
	}

	// Verify the certificate is self-signed
	if cert.Subject.CommonName != "Self-Signed CA" {
		t.Errorf("Subject.CommonName = %q, want %q", cert.Subject.CommonName, "Self-Signed CA")
	}
	if !cert.IsCA {
		t.Error("Certificate should be CA")
	}
}

func TestU_CertificateBuilder_BuildAndSign_IssuedBySigner(t *testing.T) {
	// Generate CA key
	caPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	// Create CA certificate
	caCert, _, err := NewCertificateBuilder().
		CommonName("Test CA").
		CA(1).
		ValidForYears(10).
		BuildAndSign(&caPriv.PublicKey, nil, caPriv)
	if err != nil {
		t.Fatalf("BuildAndSign() CA error = %v", err)
	}

	// Generate end-entity key
	eePriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	// Create end-entity certificate signed by CA
	cert, certDER, err := NewCertificateBuilder().
		CommonName("test.example.com").
		DNSNames("test.example.com").
		TLSServer().
		ValidForYears(1).
		BuildAndSign(&eePriv.PublicKey, caCert, caPriv)
	if err != nil {
		t.Fatalf("BuildAndSign() EE error = %v", err)
	}

	if cert == nil {
		t.Fatal("BuildAndSign() returned nil certificate")
	}
	if len(certDER) == 0 {
		t.Fatal("BuildAndSign() returned empty DER")
	}

	// Verify issuer
	if cert.Issuer.CommonName != "Test CA" {
		t.Errorf("Issuer.CommonName = %q, want %q", cert.Issuer.CommonName, "Test CA")
	}

	// Verify signature
	err = cert.CheckSignatureFrom(caCert)
	if err != nil {
		t.Errorf("Signature verification failed: %v", err)
	}
}

// =============================================================================
// Unit Tests: parseHybridAlgorithm
// =============================================================================

func TestU_parseHybridAlgorithm_AllAlgorithms(t *testing.T) {
	tests := []struct {
		name    string
		alg     string
		wantOID []int
		wantErr bool
	}{
		{"ml-dsa-44", "ml-dsa-44", []int{2, 16, 840, 1, 101, 3, 4, 3, 17}, false},
		{"ml-dsa-65", "ml-dsa-65", []int{2, 16, 840, 1, 101, 3, 4, 3, 18}, false},
		{"ml-dsa-87", "ml-dsa-87", []int{2, 16, 840, 1, 101, 3, 4, 3, 19}, false},
		{"ml-kem-512", "ml-kem-512", []int{2, 16, 840, 1, 101, 3, 4, 4, 1}, false},
		{"ml-kem-768", "ml-kem-768", []int{2, 16, 840, 1, 101, 3, 4, 4, 2}, false},
		{"ml-kem-1024", "ml-kem-1024", []int{2, 16, 840, 1, 101, 3, 4, 4, 3}, false},
		{"invalid", "invalid-algo", nil, true},
		{"empty", "", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oid, err := parseHybridAlgorithm(tt.alg)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseHybridAlgorithm() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !OIDEqual(oid, tt.wantOID) {
				t.Errorf("parseHybridAlgorithm() = %v, want %v", oid, tt.wantOID)
			}
		})
	}
}

// =============================================================================
// Unit Tests: Build with invalid hybrid algorithm
// =============================================================================

func TestU_CertificateBuilder_Build_InvalidHybridAlgorithm(t *testing.T) {
	_, err := NewCertificateBuilder().
		CommonName("test.example.com").
		HybridPQC("invalid-algo", []byte{0x01, 0x02, 0x03}, HybridPolicyInformational).
		Build()
	if err == nil {
		t.Error("Build() should fail for invalid hybrid algorithm")
	}
}

// =============================================================================
// Unit Tests: Full certificate chain with all options
// =============================================================================

func TestU_CertificateBuilder_FullOptions(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	uri, _ := url.Parse("https://example.com/resource")

	template, err := NewCertificateBuilder().
		CommonName("test.example.com").
		Organization("Test Org").
		Country("FR").
		DNSNames("test.example.com", "www.test.example.com").
		IPAddresses(net.ParseIP("192.168.1.1"), net.ParseIP("10.0.0.1")).
		EmailAddresses("admin@example.com").
		URIs(uri).
		TLSServer().
		CRLDistributionPoints("http://crl.example.com/ca.crl").
		OCSPServers("http://ocsp.example.com").
		IssuingCertificateURL("http://pki.example.com/ca.crt").
		Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	// Verify all options
	if template.Subject.CommonName != "test.example.com" {
		t.Error("CommonName not set")
	}
	if len(template.Subject.Organization) != 1 || template.Subject.Organization[0] != "Test Org" {
		t.Error("Organization not set")
	}
	if len(template.Subject.Country) != 1 || template.Subject.Country[0] != "FR" {
		t.Error("Country not set")
	}
	if len(template.DNSNames) != 2 {
		t.Error("DNSNames not set")
	}
	if len(template.IPAddresses) != 2 {
		t.Error("IPAddresses not set")
	}
	if len(template.EmailAddresses) != 1 {
		t.Error("EmailAddresses not set")
	}
	if len(template.URIs) != 1 {
		t.Error("URIs not set")
	}
	if len(template.CRLDistributionPoints) != 1 {
		t.Error("CRLDistributionPoints not set")
	}
	if len(template.OCSPServer) != 1 {
		t.Error("OCSPServer not set")
	}
	if len(template.IssuingCertificateURL) != 1 {
		t.Error("IssuingCertificateURL not set")
	}

	// Create and verify certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}

	// Verify parsed certificate
	if len(cert.CRLDistributionPoints) != 1 {
		t.Errorf("Parsed CRLDistributionPoints = %d, want 1", len(cert.CRLDistributionPoints))
	}
	if len(cert.OCSPServer) != 1 {
		t.Errorf("Parsed OCSPServer = %d, want 1", len(cert.OCSPServer))
	}
	if len(cert.IssuingCertificateURL) != 1 {
		t.Errorf("Parsed IssuingCertificateURL = %d, want 1", len(cert.IssuingCertificateURL))
	}
}
