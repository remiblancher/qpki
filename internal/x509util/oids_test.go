package x509util

import (
	"encoding/asn1"
	"testing"
)

func TestOIDEqual(t *testing.T) {
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

func TestIsCompositeOID(t *testing.T) {
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

func TestOIDToString(t *testing.T) {
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

func TestIsPQCOID(t *testing.T) {
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
