package x509util

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

func TestU_X509Util_OIDEqual(t *testing.T) {
	tests := []struct {
		name string
		a    asn1.ObjectIdentifier
		b    asn1.ObjectIdentifier
		want bool
	}{
		{
			name: "equal OIDs",
			a:    asn1.ObjectIdentifier{1, 2, 3, 4},
			b:    asn1.ObjectIdentifier{1, 2, 3, 4},
			want: true,
		},
		{
			name: "different length",
			a:    asn1.ObjectIdentifier{1, 2, 3},
			b:    asn1.ObjectIdentifier{1, 2, 3, 4},
			want: false,
		},
		{
			name: "different values",
			a:    asn1.ObjectIdentifier{1, 2, 3, 4},
			b:    asn1.ObjectIdentifier{1, 2, 3, 5},
			want: false,
		},
		{
			name: "empty OIDs",
			a:    asn1.ObjectIdentifier{},
			b:    asn1.ObjectIdentifier{},
			want: true,
		},
		{
			name: "nil vs empty",
			a:    nil,
			b:    asn1.ObjectIdentifier{},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := OIDEqual(tt.a, tt.b); got != tt.want {
				t.Errorf("OIDEqual() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestU_X509Util_IsCompositeOID(t *testing.T) {
	tests := []struct {
		name string
		oid  asn1.ObjectIdentifier
		want bool
	}{
		{
			name: "composite MLDSA65-ECDSA-P256-SHA512",
			oid:  OIDMLDSA65ECDSAP256SHA512,
			want: true,
		},
		{
			name: "composite MLDSA65-ECDSA-P384-SHA512",
			oid:  OIDMLDSA65ECDSAP384SHA512,
			want: true,
		},
		{
			name: "composite MLDSA87-ECDSA-P521-SHA512",
			oid:  OIDMLDSA87ECDSAP521SHA512,
			want: true,
		},
		{
			name: "non-composite ML-DSA-65",
			oid:  OIDMLDSA65,
			want: false,
		},
		{
			name: "non-composite ECDSA",
			oid:  asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}, // ECDSA SHA256
			want: false,
		},
		{
			name: "empty OID",
			oid:  asn1.ObjectIdentifier{},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsCompositeOID(tt.oid); got != tt.want {
				t.Errorf("IsCompositeOID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestU_X509Util_OIDToString(t *testing.T) {
	tests := []struct {
		name string
		oid  asn1.ObjectIdentifier
		want string
	}{
		{
			name: "simple OID",
			oid:  asn1.ObjectIdentifier{1, 2, 3, 4},
			want: "1.2.3.4",
		},
		{
			name: "ML-DSA-65 OID",
			oid:  OIDMLDSA65,
			want: "2.16.840.1.101.3.4.3.18",
		},
		{
			name: "empty OID",
			oid:  asn1.ObjectIdentifier{},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := OIDToString(tt.oid); got != tt.want {
				t.Errorf("OIDToString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAlgorithmName(t *testing.T) {
	tests := []struct {
		name string
		oid  asn1.ObjectIdentifier
		want string
	}{
		{
			name: "ML-DSA-65",
			oid:  OIDMLDSA65,
			want: "ML-DSA-65",
		},
		{
			name: "ML-DSA-87",
			oid:  OIDMLDSA87,
			want: "ML-DSA-87",
		},
		{
			name: "ML-KEM-768",
			oid:  OIDMLKEM768,
			want: "ML-KEM-768",
		},
		{
			name: "SLH-DSA-128s",
			oid:  OIDSLHDSA128s,
			want: "SLH-DSA-128s",
		},
		{
			name: "composite MLDSA65-ECDSA-P256-SHA512",
			oid:  OIDMLDSA65ECDSAP256SHA512,
			want: "MLDSA65-ECDSA-P256-SHA512",
		},
		{
			name: "unknown OID",
			oid:  asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7, 8},
			want: "1.2.3.4.5.6.7.8",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AlgorithmName(tt.oid); got != tt.want {
				t.Errorf("AlgorithmName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestU_X509Util_IsPQCOID(t *testing.T) {
	tests := []struct {
		name string
		oid  asn1.ObjectIdentifier
		want bool
	}{
		{
			name: "ML-DSA-44",
			oid:  OIDMLDSA44,
			want: true,
		},
		{
			name: "ML-DSA-65",
			oid:  OIDMLDSA65,
			want: true,
		},
		{
			name: "ML-DSA-87",
			oid:  OIDMLDSA87,
			want: true,
		},
		{
			name: "SLH-DSA-128s",
			oid:  OIDSLHDSA128s,
			want: true,
		},
		{
			name: "ML-KEM-768 (KEM not signature, returns false)",
			oid:  OIDMLKEM768,
			want: false,
		},
		{
			name: "ECDSA SHA256",
			oid:  asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2},
			want: false,
		},
		{
			name: "RSA",
			oid:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1},
			want: false,
		},
		{
			name: "empty OID",
			oid:  asn1.ObjectIdentifier{},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsPQCOID(tt.oid); got != tt.want {
				t.Errorf("IsPQCOID() = %v, want %v", got, tt.want)
			}
		})
	}
}

// =============================================================================
// Test Helpers for OID Extraction Tests
// =============================================================================

// generateECDSACertDER creates a self-signed ECDSA certificate DER bytes for testing.
func generateECDSACertDER(t *testing.T, curve elliptic.Curve) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test ECDSA Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}

	return certDER
}

// generateECDSACSRDER creates an ECDSA CSR DER bytes for testing.
func generateECDSACSRDER(t *testing.T, curve elliptic.Curve) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "Test ECDSA CSR",
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest() error = %v", err)
	}

	return csrDER
}

// generateTestCRLDER creates a CRL DER bytes for testing using ECDSA CA.
func generateTestCRLDER(t *testing.T) []byte {
	t.Helper()

	// Generate CA key
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	// Create CA certificate
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}

	// Create CRL
	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(24 * time.Hour),
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, crlTemplate, caCert, caKey)
	if err != nil {
		t.Fatalf("CreateRevocationList() error = %v", err)
	}

	return crlDER
}

// =============================================================================
// Tests for OID Extraction Functions - Additional Coverage
// =============================================================================

func TestU_ExtractSignatureAlgorithmOID_AllCurves(t *testing.T) {
	tests := []struct {
		name        string
		curve       elliptic.Curve
		wantOIDFunc func() asn1.ObjectIdentifier
	}{
		{
			name:        "ECDSA P-256 certificate",
			curve:       elliptic.P256(),
			wantOIDFunc: func() asn1.ObjectIdentifier { return OIDSignatureECDSAWithSHA256 },
		},
		{
			name:        "ECDSA P-384 certificate",
			curve:       elliptic.P384(),
			wantOIDFunc: func() asn1.ObjectIdentifier { return OIDSignatureECDSAWithSHA384 },
		},
		{
			name:        "ECDSA P-521 certificate",
			curve:       elliptic.P521(),
			wantOIDFunc: func() asn1.ObjectIdentifier { return OIDSignatureECDSAWithSHA512 },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certDER := generateECDSACertDER(t, tt.curve)
			got, err := ExtractSignatureAlgorithmOID(certDER)
			if err != nil {
				t.Errorf("ExtractSignatureAlgorithmOID() error = %v", err)
				return
			}
			wantOID := tt.wantOIDFunc()
			if !OIDEqual(got, wantOID) {
				t.Errorf("ExtractSignatureAlgorithmOID() = %v, want %v", got, wantOID)
			}
		})
	}
}

func TestU_ExtractSignatureAlgorithmOID_Errors(t *testing.T) {
	tests := []struct {
		name    string
		certDER []byte
	}{
		{
			name:    "empty bytes",
			certDER: []byte{},
		},
		{
			name:    "invalid ASN.1",
			certDER: []byte{0x30, 0x03, 0x01, 0x02},
		},
		{
			name:    "truncated certificate",
			certDER: []byte{0x30, 0x82, 0x01, 0x00},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ExtractSignatureAlgorithmOID(tt.certDER)
			if err == nil {
				t.Error("ExtractSignatureAlgorithmOID() expected error, got nil")
			}
		})
	}
}

func TestU_ExtractPublicKeyAlgorithmOID_AllCurves(t *testing.T) {
	tests := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"ECDSA P-256 certificate", elliptic.P256()},
		{"ECDSA P-384 certificate", elliptic.P384()},
		{"ECDSA P-521 certificate", elliptic.P521()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certDER := generateECDSACertDER(t, tt.curve)
			got, err := ExtractPublicKeyAlgorithmOID(certDER)
			if err != nil {
				t.Errorf("ExtractPublicKeyAlgorithmOID() error = %v", err)
				return
			}
			// All ECDSA certificates use the same public key OID
			if !OIDEqual(got, OIDPublicKeyECDSA) {
				t.Errorf("ExtractPublicKeyAlgorithmOID() = %v, want %v", got, OIDPublicKeyECDSA)
			}
		})
	}
}

func TestU_ExtractPublicKeyAlgorithmOID_Errors(t *testing.T) {
	tests := []struct {
		name    string
		certDER []byte
	}{
		{
			name:    "empty bytes",
			certDER: []byte{},
		},
		{
			name:    "invalid ASN.1",
			certDER: []byte{0x30, 0x03, 0x01, 0x02},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ExtractPublicKeyAlgorithmOID(tt.certDER)
			if err == nil {
				t.Error("ExtractPublicKeyAlgorithmOID() expected error, got nil")
			}
		})
	}
}

func TestU_ExtractCSRSignatureAlgorithmOID(t *testing.T) {
	tests := []struct {
		name        string
		csrDER      func(t *testing.T) []byte
		wantOIDFunc func() asn1.ObjectIdentifier
		wantErr     bool
	}{
		{
			name:        "ECDSA P-256 CSR",
			csrDER:      func(t *testing.T) []byte { return generateECDSACSRDER(t, elliptic.P256()) },
			wantOIDFunc: func() asn1.ObjectIdentifier { return OIDSignatureECDSAWithSHA256 },
			wantErr:     false,
		},
		{
			name:        "ECDSA P-384 CSR",
			csrDER:      func(t *testing.T) []byte { return generateECDSACSRDER(t, elliptic.P384()) },
			wantOIDFunc: func() asn1.ObjectIdentifier { return OIDSignatureECDSAWithSHA384 },
			wantErr:     false,
		},
		{
			name:        "ECDSA P-521 CSR",
			csrDER:      func(t *testing.T) []byte { return generateECDSACSRDER(t, elliptic.P521()) },
			wantOIDFunc: func() asn1.ObjectIdentifier { return OIDSignatureECDSAWithSHA512 },
			wantErr:     false,
		},
		{
			name:        "empty bytes",
			csrDER:      func(t *testing.T) []byte { return []byte{} },
			wantOIDFunc: func() asn1.ObjectIdentifier { return nil },
			wantErr:     true,
		},
		{
			name:        "invalid ASN.1",
			csrDER:      func(t *testing.T) []byte { return []byte{0x30, 0x03, 0x01, 0x02} },
			wantOIDFunc: func() asn1.ObjectIdentifier { return nil },
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			csrDER := tt.csrDER(t)
			got, err := ExtractCSRSignatureAlgorithmOID(csrDER)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractCSRSignatureAlgorithmOID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				wantOID := tt.wantOIDFunc()
				if !OIDEqual(got, wantOID) {
					t.Errorf("ExtractCSRSignatureAlgorithmOID() = %v, want %v", got, wantOID)
				}
			}
		})
	}
}

func TestU_ExtractCSRPublicKeyAlgorithmOID(t *testing.T) {
	tests := []struct {
		name        string
		csrDER      func(t *testing.T) []byte
		wantOIDFunc func() asn1.ObjectIdentifier
		wantErr     bool
	}{
		{
			name:        "ECDSA P-256 CSR",
			csrDER:      func(t *testing.T) []byte { return generateECDSACSRDER(t, elliptic.P256()) },
			wantOIDFunc: func() asn1.ObjectIdentifier { return OIDPublicKeyECDSA },
			wantErr:     false,
		},
		{
			name:        "ECDSA P-384 CSR",
			csrDER:      func(t *testing.T) []byte { return generateECDSACSRDER(t, elliptic.P384()) },
			wantOIDFunc: func() asn1.ObjectIdentifier { return OIDPublicKeyECDSA },
			wantErr:     false,
		},
		{
			name:        "empty bytes",
			csrDER:      func(t *testing.T) []byte { return []byte{} },
			wantOIDFunc: func() asn1.ObjectIdentifier { return nil },
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			csrDER := tt.csrDER(t)
			got, err := ExtractCSRPublicKeyAlgorithmOID(csrDER)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractCSRPublicKeyAlgorithmOID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				wantOID := tt.wantOIDFunc()
				if !OIDEqual(got, wantOID) {
					t.Errorf("ExtractCSRPublicKeyAlgorithmOID() = %v, want %v", got, wantOID)
				}
			}
		})
	}
}

func TestU_ExtractCRLSignatureAlgorithmOID(t *testing.T) {
	tests := []struct {
		name        string
		crlDER      func(t *testing.T) []byte
		wantOIDFunc func() asn1.ObjectIdentifier
		wantErr     bool
	}{
		{
			name:        "ECDSA P-256 CRL",
			crlDER:      generateTestCRLDER,
			wantOIDFunc: func() asn1.ObjectIdentifier { return OIDSignatureECDSAWithSHA256 },
			wantErr:     false,
		},
		{
			name:        "empty bytes",
			crlDER:      func(t *testing.T) []byte { return []byte{} },
			wantOIDFunc: func() asn1.ObjectIdentifier { return nil },
			wantErr:     true,
		},
		{
			name:        "invalid ASN.1",
			crlDER:      func(t *testing.T) []byte { return []byte{0x30, 0x03, 0x01, 0x02} },
			wantOIDFunc: func() asn1.ObjectIdentifier { return nil },
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			crlDER := tt.crlDER(t)
			got, err := ExtractCRLSignatureAlgorithmOID(crlDER)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractCRLSignatureAlgorithmOID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				wantOID := tt.wantOIDFunc()
				if !OIDEqual(got, wantOID) {
					t.Errorf("ExtractCRLSignatureAlgorithmOID() = %v, want %v", got, wantOID)
				}
			}
		})
	}
}

func TestU_IsPQCSignatureAlgorithmOID_Classical(t *testing.T) {
	// Generate test TBS bytes from ECDSA certificate
	ecdsaCertDER := generateECDSACertDER(t, elliptic.P256())

	// Extract TBS from certificate
	// Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
	var ecdsaCert struct {
		TBS asn1.RawValue
	}
	if _, err := asn1.Unmarshal(ecdsaCertDER, &ecdsaCert); err != nil {
		t.Fatalf("Failed to unmarshal ECDSA cert: %v", err)
	}

	tests := []struct {
		name   string
		rawTBS []byte
		want   bool
	}{
		{
			name:   "ECDSA TBS (should return false)",
			rawTBS: ecdsaCert.TBS.FullBytes,
			want:   false,
		},
		{
			name:   "empty bytes",
			rawTBS: []byte{},
			want:   false,
		},
		{
			name:   "invalid ASN.1",
			rawTBS: []byte{0x30, 0x03, 0x01, 0x02},
			want:   false,
		},
		{
			name:   "nil bytes",
			rawTBS: nil,
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsPQCSignatureAlgorithmOID(tt.rawTBS); got != tt.want {
				t.Errorf("IsPQCSignatureAlgorithmOID() = %v, want %v", got, tt.want)
			}
		})
	}
}
