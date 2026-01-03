package x509util

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"testing"
	"time"

	"github.com/remiblancher/post-quantum-pki/internal/crypto"
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
