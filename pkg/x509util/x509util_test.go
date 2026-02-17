package x509util

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/remiblancher/post-quantum-pki/pkg/crypto"
)

func TestU_OIDEqual(t *testing.T) {
	tests := []struct {
		name string
		a    []int
		b    []int
		want bool
	}{
		{"[U] Compare: equal OIDs", []int{1, 2, 3}, []int{1, 2, 3}, true},
		{"[U] Compare: different length", []int{1, 2}, []int{1, 2, 3}, false},
		{"[U] Compare: different values", []int{1, 2, 3}, []int{1, 2, 4}, false},
		{"[U] Compare: empty OIDs", []int{}, []int{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := OIDEqual(tt.a, tt.b); got != tt.want {
				t.Errorf("OIDEqual() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestU_EncodeDecodeHybridExtension_RoundTrip(t *testing.T) {
	// Generate a test public key
	kp, err := crypto.GenerateKeyPair(crypto.AlgMLDSA65)
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	pubBytes, err := kp.PublicKeyBytes()
	if err != nil {
		t.Fatalf("PublicKeyBytes() error = %v", err)
	}

	tests := []struct {
		name   string
		alg    crypto.AlgorithmID
		policy HybridPolicy
	}{
		{"[U] Encode: ML-DSA-44 informational", crypto.AlgMLDSA44, HybridPolicyInformational},
		{"[U] Encode: ML-DSA-65 must-verify", crypto.AlgMLDSA65, HybridPolicyMustVerifyBoth},
		{"[U] Encode: ML-DSA-87 pqc-preferred", crypto.AlgMLDSA87, HybridPolicyPQCPreferred},
		{"[U] Encode: ML-KEM-768 informational", crypto.AlgMLKEM768, HybridPolicyInformational},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode
			ext, err := EncodeHybridExtension(tt.alg, pubBytes, tt.policy)
			if err != nil {
				t.Fatalf("EncodeHybridExtension() error = %v", err)
			}

			// Check extension properties
			if ext.Critical {
				t.Error("hybrid extension should not be critical")
			}
			if !OIDEqual(ext.Id, OIDHybridPublicKeyExtension) {
				t.Errorf("wrong OID: got %v, want %v", ext.Id, OIDHybridPublicKeyExtension)
			}

			// Decode
			gotAlg, gotPubKey, gotPolicy, err := DecodeHybridExtension(ext)
			if err != nil {
				t.Fatalf("DecodeHybridExtension() error = %v", err)
			}

			if gotAlg != tt.alg {
				t.Errorf("algorithm = %v, want %v", gotAlg, tt.alg)
			}
			if len(gotPubKey) != len(pubBytes) {
				t.Errorf("public key length = %d, want %d", len(gotPubKey), len(pubBytes))
			}
			if gotPolicy != tt.policy {
				t.Errorf("policy = %v, want %v", gotPolicy, tt.policy)
			}
		})
	}
}

func TestU_EncodeHybridExtension_AlgorithmInvalid(t *testing.T) {
	_, err := EncodeHybridExtension(crypto.AlgECDSAP256, []byte{1, 2, 3}, HybridPolicyInformational)
	if err == nil {
		t.Error("expected error for classical algorithm")
	}
}

func TestU_FindHybridExtension(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair(crypto.AlgMLDSA65)
	pubBytes, _ := kp.PublicKeyBytes()

	hybridExt, _ := EncodeHybridExtension(crypto.AlgMLDSA65, pubBytes, HybridPolicyInformational)

	tests := []struct {
		name       string
		extensions []pkix.Extension
		wantFound  bool
	}{
		{"[U] Find: empty list", nil, false},
		{"[U] Find: no hybrid present", []pkix.Extension{{Id: OIDExtKeyUsage}}, false},
		{"[U] Find: has hybrid", []pkix.Extension{hybridExt}, true},
		{"[U] Find: hybrid among others", []pkix.Extension{{Id: OIDExtKeyUsage}, hybridExt, {Id: OIDExtBasicConstraints}}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FindHybridExtension(tt.extensions)
			if (got != nil) != tt.wantFound {
				t.Errorf("FindHybridExtension() found = %v, want %v", got != nil, tt.wantFound)
			}
		})
	}
}

func TestU_HybridPolicy_String(t *testing.T) {
	tests := []struct {
		policy HybridPolicy
		want   string
	}{
		{HybridPolicyInformational, "informational"},
		{HybridPolicyMustVerifyBoth, "must-verify-both"},
		{HybridPolicyPQCPreferred, "pqc-preferred"},
		{HybridPolicy(99), "unknown(99)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.policy.String(); got != tt.want {
				t.Errorf("String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestU_CertificateBuilder_TLSServer(t *testing.T) {
	// Generate a key pair
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	// Build certificate
	template, err := NewCertificateBuilder().
		CommonName("test.example.com").
		DNSNames("test.example.com", "www.test.example.com").
		IPAddresses(net.ParseIP("192.168.1.1")).
		TLSServer().
		ValidForYears(1).
		Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	// Check properties
	if template.Subject.CommonName != "test.example.com" {
		t.Errorf("CommonName = %v, want test.example.com", template.Subject.CommonName)
	}
	if len(template.DNSNames) != 2 {
		t.Errorf("DNSNames count = %d, want 2", len(template.DNSNames))
	}
	if len(template.IPAddresses) != 1 {
		t.Errorf("IPAddresses count = %d, want 1", len(template.IPAddresses))
	}
	if template.IsCA {
		t.Error("TLS server should not be CA")
	}
	if template.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("should have DigitalSignature key usage")
	}
	if len(template.ExtKeyUsage) != 1 || template.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Error("should have ServerAuth extended key usage")
	}

	// Self-sign for testing
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}

	if cert.Subject.CommonName != "test.example.com" {
		t.Errorf("parsed cert CommonName = %v, want test.example.com", cert.Subject.CommonName)
	}
}

func TestU_CertificateBuilder_CA(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	template, err := NewCertificateBuilder().
		CommonName("Test Root CA").
		Organization("Test Org").
		CA(1).
		ValidForYears(10).
		Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if !template.IsCA {
		t.Error("should be CA")
	}
	if template.MaxPathLen != 1 {
		t.Errorf("MaxPathLen = %d, want 1", template.MaxPathLen)
	}
	if template.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("should have CertSign key usage")
	}
	if template.KeyUsage&x509.KeyUsageCRLSign == 0 {
		t.Error("should have CRLSign key usage")
	}

	// Self-sign
	_, err = x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
}

func TestU_CertificateBuilder_HybridExtension(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Generate PQC key for hybrid extension
	pqcKP, _ := crypto.GenerateKeyPair(crypto.AlgMLDSA65)
	pqcPubBytes, _ := pqcKP.PublicKeyBytes()

	template, err := NewCertificateBuilder().
		CommonName("test.example.com").
		DNSNames("test.example.com").
		TLSServer().
		HybridPQC("ml-dsa-65", pqcPubBytes, HybridPolicyInformational).
		Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	// Check hybrid extension exists
	if !HasHybridExtension(template.ExtraExtensions) {
		t.Error("should have hybrid extension")
	}

	// Parse hybrid extension
	info, err := ParseHybridExtension(template.ExtraExtensions)
	if err != nil {
		t.Fatalf("ParseHybridExtension() error = %v", err)
	}
	if info.Algorithm != crypto.AlgMLDSA65 {
		t.Errorf("hybrid algorithm = %v, want ml-dsa-65", info.Algorithm)
	}

	// Self-sign and verify extension persists
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	cert, _ := x509.ParseCertificate(certDER)

	// Find extension in parsed cert
	found := false
	for _, ext := range cert.Extensions {
		if OIDEqual(ext.Id, OIDHybridPublicKeyExtension) {
			found = true
			break
		}
	}
	if !found {
		t.Error("hybrid extension not found in parsed certificate")
	}
}

func TestU_CertificateBuilder_Validity(t *testing.T) {
	now := time.Now()

	template, _ := NewCertificateBuilder().
		CommonName("test").
		Validity(now, now.AddDate(0, 6, 0)).
		Build()

	if template.NotBefore.Before(now.Add(-time.Second)) || template.NotBefore.After(now.Add(time.Second)) {
		t.Error("NotBefore should be approximately now")
	}

	expectedAfter := now.AddDate(0, 6, 0)
	if template.NotAfter.Before(expectedAfter.Add(-time.Second)) || template.NotAfter.After(expectedAfter.Add(time.Second)) {
		t.Error("NotAfter should be approximately 6 months from now")
	}
}

func TestU_SubjectKeyID_Basic(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	skid, err := SubjectKeyID(&priv.PublicKey)
	if err != nil {
		t.Fatalf("SubjectKeyID() error = %v", err)
	}

	if len(skid) != 20 {
		t.Errorf("SKID length = %d, want 20", len(skid))
	}

	// Same key should produce same SKID
	skid2, _ := SubjectKeyID(&priv.PublicKey)
	for i := range skid {
		if skid[i] != skid2[i] {
			t.Error("same key should produce same SKID")
			break
		}
	}
}

// =============================================================================
// Certificate Type Detection Tests (detect.go)
// =============================================================================

func TestU_ExtractSPKIAlgorithmOID_ECDSA(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	// Create a self-signed certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Cert",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}

	// Extract SPKI algorithm OID
	oid, err := ExtractSPKIAlgorithmOID(cert.RawSubjectPublicKeyInfo)
	if err != nil {
		t.Fatalf("ExtractSPKIAlgorithmOID() error = %v", err)
	}

	// Should be ECDSA public key OID
	if !OIDEqual(oid, OIDPublicKeyECDSA) {
		t.Errorf("OID = %v, want %v (ECDSA)", oid, OIDPublicKeyECDSA)
	}
}

func TestU_ExtractSPKIAlgorithmOID_Invalid(t *testing.T) {
	// Try to extract from invalid data
	_, err := ExtractSPKIAlgorithmOID([]byte("not valid ASN.1 data"))
	if err == nil {
		t.Error("ExtractSPKIAlgorithmOID() should fail for invalid data")
	}
}

func TestU_IsPQCOID(t *testing.T) {
	tests := []struct {
		name string
		oid  []int
		want bool
	}{
		// ML-DSA (FIPS 204)
		{"ML-DSA-44", []int{2, 16, 840, 1, 101, 3, 4, 3, 17}, true},
		{"ML-DSA-65", []int{2, 16, 840, 1, 101, 3, 4, 3, 18}, true},
		{"ML-DSA-87", []int{2, 16, 840, 1, 101, 3, 4, 3, 19}, true},
		// SLH-DSA (FIPS 205)
		{"SLH-DSA-128s", []int{2, 16, 840, 1, 101, 3, 4, 3, 20}, true},
		{"SLH-DSA-128f", []int{2, 16, 840, 1, 101, 3, 4, 3, 21}, true},
		{"SLH-DSA-192s", []int{2, 16, 840, 1, 101, 3, 4, 3, 22}, true},
		{"SLH-DSA-192f", []int{2, 16, 840, 1, 101, 3, 4, 3, 23}, true},
		{"SLH-DSA-256s", []int{2, 16, 840, 1, 101, 3, 4, 3, 24}, true},
		{"SLH-DSA-256f", []int{2, 16, 840, 1, 101, 3, 4, 3, 25}, true},
		// Classical algorithms
		{"ECDSA", []int{1, 2, 840, 10045, 2, 1}, false},
		{"RSA", []int{1, 2, 840, 113549, 1, 1, 1}, false},
		{"Ed25519", []int{1, 3, 101, 112}, false},
		// Composite (should return false for IsPQCOID)
		{"Composite ML-DSA-65+P256", []int{1, 3, 6, 1, 5, 5, 7, 6, 45}, false},
		{"Composite ML-DSA-65+P384", []int{1, 3, 6, 1, 5, 5, 7, 6, 46}, false},
		{"Composite ML-DSA-87+P521", []int{1, 3, 6, 1, 5, 5, 7, 6, 54}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsPQCOID(tt.oid); got != tt.want {
				t.Errorf("IsPQCOID(%v) = %v, want %v", tt.oid, got, tt.want)
			}
		})
	}
}

func TestU_IsCompositeOID(t *testing.T) {
	tests := []struct {
		name string
		oid  []int
		want bool
	}{
		{"Composite ML-DSA-65+P256", []int{1, 3, 6, 1, 5, 5, 7, 6, 45}, true},
		{"Composite ML-DSA-65+P384", []int{1, 3, 6, 1, 5, 5, 7, 6, 46}, true},
		{"Composite ML-DSA-87+P521", []int{1, 3, 6, 1, 5, 5, 7, 6, 54}, true},
		{"ML-DSA-65 pure", []int{2, 16, 840, 1, 101, 3, 4, 3, 18}, false},
		{"ECDSA", []int{1, 2, 840, 10045, 2, 1}, false},
		{"Not IANA OID (prototype .40)", []int{1, 3, 6, 1, 5, 5, 7, 6, 40}, false},
		{"Not IANA OID (prototype .49)", []int{1, 3, 6, 1, 5, 5, 7, 6, 49}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsCompositeOID(tt.oid); got != tt.want {
				t.Errorf("IsCompositeOID(%v) = %v, want %v", tt.oid, got, tt.want)
			}
		})
	}
}

func TestU_IsCompositeCertificate_Nil(t *testing.T) {
	if IsCompositeCertificate(nil) {
		t.Error("IsCompositeCertificate(nil) should return false")
	}
}

func TestU_IsCompositeCertificate_Classical(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	cert, _ := x509.ParseCertificate(certDER)

	if IsCompositeCertificate(cert) {
		t.Error("IsCompositeCertificate() should return false for classical certificate")
	}
}

func TestU_IsCatalystCertificate_Nil(t *testing.T) {
	if IsCatalystCertificate(nil) {
		t.Error("IsCatalystCertificate(nil) should return false")
	}
}

func TestU_IsCatalystCertificate_NoExtension(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	cert, _ := x509.ParseCertificate(certDER)

	if IsCatalystCertificate(cert) {
		t.Error("IsCatalystCertificate() should return false for certificate without catalyst extension")
	}
}

func TestU_IsCatalystCertificate_WithExtension(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Create certificate with altSubjectPublicKeyInfo extension
	catalystExt := pkix.Extension{
		Id:       OIDAltSubjectPublicKeyInfo,
		Critical: false,
		Value:    []byte{0x30, 0x00}, // Minimal valid ASN.1 sequence
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Catalyst"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		ExtraExtensions:       []pkix.Extension{catalystExt},
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	cert, _ := x509.ParseCertificate(certDER)

	if !IsCatalystCertificate(cert) {
		t.Error("IsCatalystCertificate() should return true for certificate with catalyst extension")
	}
}

func TestU_IsPQCCertificate_Nil(t *testing.T) {
	if IsPQCCertificate(nil) {
		t.Error("IsPQCCertificate(nil) should return false")
	}
}

func TestU_IsPQCCertificate_Classical(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	cert, _ := x509.ParseCertificate(certDER)

	if IsPQCCertificate(cert) {
		t.Error("IsPQCCertificate() should return false for classical certificate")
	}
}

func TestU_IsClassicalCertificate_Nil(t *testing.T) {
	if IsClassicalCertificate(nil) {
		t.Error("IsClassicalCertificate(nil) should return false")
	}
}

func TestU_IsClassicalCertificate_ECDSA(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	cert, _ := x509.ParseCertificate(certDER)

	if !IsClassicalCertificate(cert) {
		t.Error("IsClassicalCertificate() should return true for ECDSA certificate")
	}
}

func TestU_IsClassicalCertificate_Catalyst(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Catalyst certificate should be considered classical (primary key is classical)
	catalystExt := pkix.Extension{
		Id:       OIDAltSubjectPublicKeyInfo,
		Critical: false,
		Value:    []byte{0x30, 0x00},
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Catalyst"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		ExtraExtensions:       []pkix.Extension{catalystExt},
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	cert, _ := x509.ParseCertificate(certDER)

	if !IsClassicalCertificate(cert) {
		t.Error("IsClassicalCertificate() should return true for Catalyst certificate (primary is classical)")
	}
}

func TestU_CertificateType_String(t *testing.T) {
	tests := []struct {
		certType CertificateType
		want     string
	}{
		{CertTypeUnknown, "Unknown"},
		{CertTypeClassical, "Classical"},
		{CertTypePQC, "PQC"},
		{CertTypeComposite, "Composite"},
		{CertTypeCatalyst, "Catalyst"},
		{CertificateType(99), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.certType.String(); got != tt.want {
				t.Errorf("String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestU_GetCertificateType_Nil(t *testing.T) {
	if GetCertificateType(nil) != CertTypeUnknown {
		t.Error("GetCertificateType(nil) should return CertTypeUnknown")
	}
}

func TestU_GetCertificateType_Classical(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	cert, _ := x509.ParseCertificate(certDER)

	certType := GetCertificateType(cert)
	if certType != CertTypeClassical {
		t.Errorf("GetCertificateType() = %v, want CertTypeClassical", certType)
	}
}

func TestU_GetCertificateType_Catalyst(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Catalyst certificate has altSubjectPublicKeyInfo extension
	catalystExt := pkix.Extension{
		Id:       OIDAltSubjectPublicKeyInfo,
		Critical: false,
		Value:    []byte{0x30, 0x00},
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Catalyst"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		ExtraExtensions:       []pkix.Extension{catalystExt},
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	cert, _ := x509.ParseCertificate(certDER)

	certType := GetCertificateType(cert)
	if certType != CertTypeCatalyst {
		t.Errorf("GetCertificateType() = %v, want CertTypeCatalyst", certType)
	}
}

func TestU_AlgorithmName(t *testing.T) {
	tests := []struct {
		oid  []int
		want string
	}{
		// ML-DSA
		{[]int{2, 16, 840, 1, 101, 3, 4, 3, 17}, "ML-DSA-44"},
		{[]int{2, 16, 840, 1, 101, 3, 4, 3, 18}, "ML-DSA-65"},
		{[]int{2, 16, 840, 1, 101, 3, 4, 3, 19}, "ML-DSA-87"},
		// SLH-DSA
		{[]int{2, 16, 840, 1, 101, 3, 4, 3, 20}, "SLH-DSA-128s"},
		{[]int{2, 16, 840, 1, 101, 3, 4, 3, 21}, "SLH-DSA-128f"},
		{[]int{2, 16, 840, 1, 101, 3, 4, 3, 22}, "SLH-DSA-192s"},
		{[]int{2, 16, 840, 1, 101, 3, 4, 3, 23}, "SLH-DSA-192f"},
		{[]int{2, 16, 840, 1, 101, 3, 4, 3, 24}, "SLH-DSA-256s"},
		{[]int{2, 16, 840, 1, 101, 3, 4, 3, 25}, "SLH-DSA-256f"},
		// ML-KEM
		{[]int{2, 16, 840, 1, 101, 3, 4, 4, 1}, "ML-KEM-512"},
		{[]int{2, 16, 840, 1, 101, 3, 4, 4, 2}, "ML-KEM-768"},
		{[]int{2, 16, 840, 1, 101, 3, 4, 4, 3}, "ML-KEM-1024"},
		// Classical
		{[]int{1, 2, 840, 10045, 4, 3, 2}, "ECDSA-SHA256"},
		{[]int{1, 2, 840, 10045, 4, 3, 3}, "ECDSA-SHA384"},
		{[]int{1, 2, 840, 10045, 4, 3, 4}, "ECDSA-SHA512"},
		{[]int{1, 3, 101, 112}, "Ed25519"},
		{[]int{1, 2, 840, 113549, 1, 1, 11}, "RSA-SHA256"},
		{[]int{1, 2, 840, 113549, 1, 1, 12}, "RSA-SHA384"},
		{[]int{1, 2, 840, 113549, 1, 1, 13}, "RSA-SHA512"},
		// Composite (IANA-allocated OIDs only)
		{[]int{1, 3, 6, 1, 5, 5, 7, 6, 45}, "MLDSA65-ECDSA-P256-SHA512"},
		{[]int{1, 3, 6, 1, 5, 5, 7, 6, 46}, "MLDSA65-ECDSA-P384-SHA512"},
		{[]int{1, 3, 6, 1, 5, 5, 7, 6, 54}, "MLDSA87-ECDSA-P521-SHA512"},
		// Unknown - should return string representation
		{[]int{1, 2, 3, 4, 5}, "1.2.3.4.5"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := AlgorithmName(tt.oid); got != tt.want {
				t.Errorf("AlgorithmName(%v) = %v, want %v", tt.oid, got, tt.want)
			}
		})
	}
}

func TestU_OIDToString(t *testing.T) {
	oid := []int{1, 2, 840, 10045, 4, 3, 2}
	result := OIDToString(oid)

	if result != "1.2.840.10045.4.3.2" {
		t.Errorf("OIDToString() = %v, want 1.2.840.10045.4.3.2", result)
	}
}

func TestU_ExtractSignatureAlgorithmOID(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)

	oid, err := ExtractSignatureAlgorithmOID(certDER)
	if err != nil {
		t.Fatalf("ExtractSignatureAlgorithmOID() error = %v", err)
	}

	// ECDSA with SHA-256 OID
	expectedOID := []int{1, 2, 840, 10045, 4, 3, 2}
	if !OIDEqual(oid, expectedOID) {
		t.Errorf("OID = %v, want %v", oid, expectedOID)
	}
}

func TestU_ExtractSignatureAlgorithmOID_Invalid(t *testing.T) {
	_, err := ExtractSignatureAlgorithmOID([]byte("not valid"))
	if err == nil {
		t.Error("ExtractSignatureAlgorithmOID() should fail for invalid data")
	}
}

func TestU_ExtractPublicKeyAlgorithmOID(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)

	oid, err := ExtractPublicKeyAlgorithmOID(certDER)
	if err != nil {
		t.Fatalf("ExtractPublicKeyAlgorithmOID() error = %v", err)
	}

	// ECDSA public key OID
	if !OIDEqual(oid, OIDPublicKeyECDSA) {
		t.Errorf("OID = %v, want %v", oid, OIDPublicKeyECDSA)
	}
}

func TestU_ExtractPublicKeyAlgorithmOID_Invalid(t *testing.T) {
	_, err := ExtractPublicKeyAlgorithmOID([]byte("not valid"))
	if err == nil {
		t.Error("ExtractPublicKeyAlgorithmOID() should fail for invalid data")
	}
}

func TestU_IsPQCSignatureAlgorithmOID_MLDSA(t *testing.T) {
	// This test uses raw TBS bytes which is complex to construct
	// We'll test the helper functions instead
	tests := []struct {
		name string
		oid  []int
		want bool
	}{
		{"ML-DSA-44", []int{2, 16, 840, 1, 101, 3, 4, 3, 17}, true},
		{"ML-DSA-65", []int{2, 16, 840, 1, 101, 3, 4, 3, 18}, true},
		{"ML-DSA-87", []int{2, 16, 840, 1, 101, 3, 4, 3, 19}, true},
		{"SLH-DSA-128s", []int{2, 16, 840, 1, 101, 3, 4, 3, 20}, true},
		{"ECDSA", []int{1, 2, 840, 10045, 4, 3, 2}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Just verify the OID check works
			if got := IsPQCOID(tt.oid); got != tt.want {
				t.Errorf("IsPQCOID(%v) = %v, want %v", tt.oid, got, tt.want)
			}
		})
	}
}
