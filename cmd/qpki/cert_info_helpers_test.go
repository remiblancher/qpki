package main

import (
	"crypto/x509"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/remiblancher/qpki/pkg/ca"
)

// =============================================================================
// getKeyUsageNames Tests
// =============================================================================

func TestF_CertInfo_GetKeyUsageNames(t *testing.T) {
	tests := []struct {
		name     string
		keyUsage x509.KeyUsage
		want     []string
	}{
		{
			name:     "digital signature only",
			keyUsage: x509.KeyUsageDigitalSignature,
			want:     []string{"digitalSignature"},
		},
		{
			name:     "key encipherment only",
			keyUsage: x509.KeyUsageKeyEncipherment,
			want:     []string{"keyEncipherment"},
		},
		{
			name:     "CA key usage (cert sign + CRL sign)",
			keyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			want:     []string{"keyCertSign", "cRLSign"},
		},
		{
			name:     "TLS server key usage",
			keyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			want:     []string{"digitalSignature", "keyEncipherment"},
		},
		{
			name:     "no key usage",
			keyUsage: 0,
			want:     nil,
		},
		{
			name: "all key usages",
			keyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment |
				x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment |
				x509.KeyUsageKeyAgreement | x509.KeyUsageCertSign |
				x509.KeyUsageCRLSign | x509.KeyUsageEncipherOnly | x509.KeyUsageDecipherOnly,
			want: []string{
				"digitalSignature", "contentCommitment", "keyEncipherment",
				"dataEncipherment", "keyAgreement", "keyCertSign", "cRLSign",
				"encipherOnly", "decipherOnly",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getKeyUsageNames(tt.keyUsage)
			if len(got) != len(tt.want) {
				t.Errorf("getKeyUsageNames() = %v, want %v", got, tt.want)
				return
			}
			for i, name := range got {
				if name != tt.want[i] {
					t.Errorf("getKeyUsageNames()[%d] = %s, want %s", i, name, tt.want[i])
				}
			}
		})
	}
}

// =============================================================================
// getExtKeyUsageNames Tests
// =============================================================================

func TestF_CertInfo_GetExtKeyUsageNames(t *testing.T) {
	tests := []struct {
		name string
		ekus []x509.ExtKeyUsage
		want []string
	}{
		{
			name: "server auth only",
			ekus: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			want: []string{"serverAuth"},
		},
		{
			name: "client auth only",
			ekus: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			want: []string{"clientAuth"},
		},
		{
			name: "server and client auth",
			ekus: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			want: []string{"serverAuth", "clientAuth"},
		},
		{
			name: "code signing",
			ekus: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			want: []string{"codeSigning"},
		},
		{
			name: "email protection",
			ekus: []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
			want: []string{"emailProtection"},
		},
		{
			name: "time stamping",
			ekus: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
			want: []string{"timeStamping"},
		},
		{
			name: "OCSP signing",
			ekus: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
			want: []string{"OCSPSigning"},
		},
		{
			name: "empty list",
			ekus: nil,
			want: nil,
		},
		{
			name: "unknown EKU",
			ekus: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			want: nil, // ExtKeyUsageAny is not in the map
		},
		{
			name: "all known EKUs",
			ekus: []x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth,
				x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageEmailProtection,
				x509.ExtKeyUsageTimeStamping, x509.ExtKeyUsageOCSPSigning,
			},
			want: []string{
				"serverAuth", "clientAuth", "codeSigning",
				"emailProtection", "timeStamping", "OCSPSigning",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getExtKeyUsageNames(tt.ekus)
			if len(got) != len(tt.want) {
				t.Errorf("getExtKeyUsageNames() = %v, want %v", got, tt.want)
				return
			}
			for i, name := range got {
				if name != tt.want[i] {
					t.Errorf("getExtKeyUsageNames()[%d] = %s, want %s", i, name, tt.want[i])
				}
			}
		})
	}
}

// =============================================================================
// formatSANs Tests
// =============================================================================

func TestFormatSANs(t *testing.T) {
	tests := []struct {
		name string
		cert *x509.Certificate
		want []string
	}{
		{
			name: "DNS names only",
			cert: &x509.Certificate{
				DNSNames: []string{"example.com", "www.example.com"},
			},
			want: []string{"DNS:example.com", "DNS:www.example.com"},
		},
		{
			name: "IP addresses only",
			cert: &x509.Certificate{
				IPAddresses: []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("::1")},
			},
			want: []string{"IP:192.168.1.1", "IP:::1"},
		},
		{
			name: "Email addresses only",
			cert: &x509.Certificate{
				EmailAddresses: []string{"admin@example.com", "support@example.com"},
			},
			want: []string{"Email:admin@example.com", "Email:support@example.com"},
		},
		{
			name: "URIs only",
			cert: &x509.Certificate{
				URIs: []*url.URL{
					{Scheme: "https", Host: "example.com"},
					{Scheme: "spiffe", Host: "cluster.local", Path: "/ns/default/sa/foo"},
				},
			},
			want: []string{"URI:https://example.com", "URI:spiffe://cluster.local/ns/default/sa/foo"},
		},
		{
			name: "mixed SANs",
			cert: &x509.Certificate{
				DNSNames:       []string{"example.com"},
				IPAddresses:    []net.IP{net.ParseIP("10.0.0.1")},
				EmailAddresses: []string{"admin@example.com"},
			},
			want: []string{"DNS:example.com", "IP:10.0.0.1", "Email:admin@example.com"},
		},
		{
			name: "no SANs",
			cert: &x509.Certificate{},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatSANs(tt.cert)
			if len(got) != len(tt.want) {
				t.Errorf("formatSANs() = %v, want %v", got, tt.want)
				return
			}
			for i, san := range got {
				if san != tt.want[i] {
					t.Errorf("formatSANs()[%d] = %s, want %s", i, san, tt.want[i])
				}
			}
		})
	}
}

// =============================================================================
// getCertStatus Tests
// =============================================================================

func TestF_CertInfo_GetCertStatus(t *testing.T) {
	serial := []byte{0x01, 0x02, 0x03}
	serialHex := "010203"
	otherSerial := []byte{0x04, 0x05, 0x06}

	now := time.Now()
	pastExpiry := now.Add(-24 * time.Hour)
	futureExpiry := now.Add(24 * time.Hour)
	pastRevocation := now.Add(-48 * time.Hour)

	tests := []struct {
		name      string
		entries   []ca.IndexEntry
		serialHex string
		want      string
	}{
		{
			name: "valid certificate",
			entries: []ca.IndexEntry{
				{Serial: serial, Status: "V", Expiry: futureExpiry},
			},
			serialHex: serialHex,
			want:      "Valid",
		},
		{
			name: "expired certificate (status V but expired)",
			entries: []ca.IndexEntry{
				{Serial: serial, Status: "V", Expiry: pastExpiry},
			},
			serialHex: serialHex,
			want:      "Expired",
		},
		{
			name: "revoked certificate with date",
			entries: []ca.IndexEntry{
				{Serial: serial, Status: "R", Revocation: pastRevocation},
			},
			serialHex: serialHex,
			want:      "Revoked (" + pastRevocation.Format("2006-01-02") + ")",
		},
		{
			name: "revoked certificate without date",
			entries: []ca.IndexEntry{
				{Serial: serial, Status: "R"},
			},
			serialHex: serialHex,
			want:      "Revoked",
		},
		{
			name: "expired status",
			entries: []ca.IndexEntry{
				{Serial: serial, Status: "E"},
			},
			serialHex: serialHex,
			want:      "Expired",
		},
		{
			name: "certificate not in index",
			entries: []ca.IndexEntry{
				{Serial: otherSerial, Status: "V"},
			},
			serialHex: serialHex,
			want:      "Valid", // Default when not found
		},
		{
			name:      "empty entries",
			entries:   nil,
			serialHex: serialHex,
			want:      "Valid", // Default when not found
		},
		{
			name: "multiple entries, correct one is valid",
			entries: []ca.IndexEntry{
				{Serial: otherSerial, Status: "R"},
				{Serial: serial, Status: "V", Expiry: futureExpiry},
			},
			serialHex: serialHex,
			want:      "Valid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getCertStatus(tt.entries, tt.serialHex)
			if got != tt.want {
				t.Errorf("getCertStatus() = %s, want %s", got, tt.want)
			}
		})
	}
}

// =============================================================================
// formatPathLen Tests
// =============================================================================

func TestFormatPathLen(t *testing.T) {
	tests := []struct {
		name string
		cert *x509.Certificate
		want string
	}{
		{
			name: "not a CA",
			cert: &x509.Certificate{
				IsCA: false,
			},
			want: "",
		},
		{
			name: "CA with path length 0",
			cert: &x509.Certificate{
				IsCA:           true,
				MaxPathLen:     0,
				MaxPathLenZero: true,
			},
			want: "0",
		},
		{
			name: "CA with path length 1",
			cert: &x509.Certificate{
				IsCA:           true,
				MaxPathLen:     1,
				MaxPathLenZero: false,
			},
			want: "1",
		},
		{
			name: "CA with path length 5",
			cert: &x509.Certificate{
				IsCA:           true,
				MaxPathLen:     5,
				MaxPathLenZero: false,
			},
			want: "5",
		},
		{
			name: "CA with unlimited path length",
			cert: &x509.Certificate{
				IsCA:           true,
				MaxPathLen:     -1,
				MaxPathLenZero: false,
			},
			want: "unlimited",
		},
		{
			name: "CA with MaxPathLen=0 but MaxPathLenZero=false",
			cert: &x509.Certificate{
				IsCA:           true,
				MaxPathLen:     0,
				MaxPathLenZero: false,
			},
			want: "0", // MaxPathLen=0 with MaxPathLenZero=false still shows 0
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatPathLen(tt.cert)
			if got != tt.want {
				t.Errorf("formatPathLen() = %s, want %s", got, tt.want)
			}
		})
	}
}
