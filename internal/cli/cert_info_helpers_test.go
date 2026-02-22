package cli

import (
	"crypto/x509"
	"encoding/hex"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/remiblancher/qpki/internal/ca"
)

// =============================================================================
// GetKeyUsageNames Tests
// =============================================================================

func TestU_GetKeyUsageNames(t *testing.T) {
	tests := []struct {
		name     string
		ku       x509.KeyUsage
		expected []string
	}{
		{
			name:     "[Unit] GetKeyUsageNames: no key usage",
			ku:       0,
			expected: nil,
		},
		{
			name:     "[Unit] GetKeyUsageNames: single usage - digital signature",
			ku:       x509.KeyUsageDigitalSignature,
			expected: []string{"digitalSignature"},
		},
		{
			name:     "[Unit] GetKeyUsageNames: CA key usages",
			ku:       x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			expected: []string{"keyCertSign", "cRLSign"},
		},
		{
			name:     "[Unit] GetKeyUsageNames: multiple usages",
			ku:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment,
			expected: []string{"digitalSignature", "keyEncipherment", "dataEncipherment"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetKeyUsageNames(tt.ku)
			if len(result) != len(tt.expected) {
				t.Errorf("GetKeyUsageNames() returned %d items, want %d", len(result), len(tt.expected))
				return
			}
			for i, expected := range tt.expected {
				if result[i] != expected {
					t.Errorf("GetKeyUsageNames()[%d] = %s, want %s", i, result[i], expected)
				}
			}
		})
	}
}

// =============================================================================
// GetExtKeyUsageNames Tests
// =============================================================================

func TestU_GetExtKeyUsageNames(t *testing.T) {
	tests := []struct {
		name     string
		ekus     []x509.ExtKeyUsage
		expected []string
	}{
		{
			name:     "[Unit] GetExtKeyUsageNames: no extended key usage",
			ekus:     nil,
			expected: nil,
		},
		{
			name:     "[Unit] GetExtKeyUsageNames: server auth",
			ekus:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			expected: []string{"serverAuth"},
		},
		{
			name:     "[Unit] GetExtKeyUsageNames: TLS client and server",
			ekus:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			expected: []string{"serverAuth", "clientAuth"},
		},
		{
			name:     "[Unit] GetExtKeyUsageNames: code signing",
			ekus:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			expected: []string{"codeSigning"},
		},
		{
			name:     "[Unit] GetExtKeyUsageNames: OCSP signing",
			ekus:     []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
			expected: []string{"OCSPSigning"},
		},
		{
			name:     "[Unit] GetExtKeyUsageNames: unknown usage",
			ekus:     []x509.ExtKeyUsage{x509.ExtKeyUsage(999)},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetExtKeyUsageNames(tt.ekus)
			if len(result) != len(tt.expected) {
				t.Errorf("GetExtKeyUsageNames() returned %d items, want %d", len(result), len(tt.expected))
				return
			}
			for i, expected := range tt.expected {
				if result[i] != expected {
					t.Errorf("GetExtKeyUsageNames()[%d] = %s, want %s", i, result[i], expected)
				}
			}
		})
	}
}

// =============================================================================
// FormatSANs Tests
// =============================================================================

func TestU_FormatSANs(t *testing.T) {
	t.Run("[Unit] FormatSANs: empty certificate", func(t *testing.T) {
		cert := &x509.Certificate{}
		result := FormatSANs(cert)
		if len(result) != 0 {
			t.Errorf("FormatSANs() returned %d items, want 0", len(result))
		}
	})

	t.Run("[Unit] FormatSANs: DNS names", func(t *testing.T) {
		cert := &x509.Certificate{
			DNSNames: []string{"example.com", "www.example.com"},
		}
		result := FormatSANs(cert)
		if len(result) != 2 {
			t.Errorf("FormatSANs() returned %d items, want 2", len(result))
		}
		if result[0] != "DNS:example.com" {
			t.Errorf("FormatSANs()[0] = %s, want DNS:example.com", result[0])
		}
	})

	t.Run("[Unit] FormatSANs: IP addresses", func(t *testing.T) {
		cert := &x509.Certificate{
			IPAddresses: []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("::1")},
		}
		result := FormatSANs(cert)
		if len(result) != 2 {
			t.Errorf("FormatSANs() returned %d items, want 2", len(result))
		}
		if result[0] != "IP:192.168.1.1" {
			t.Errorf("FormatSANs()[0] = %s, want IP:192.168.1.1", result[0])
		}
	})

	t.Run("[Unit] FormatSANs: email addresses", func(t *testing.T) {
		cert := &x509.Certificate{
			EmailAddresses: []string{"test@example.com"},
		}
		result := FormatSANs(cert)
		if len(result) != 1 {
			t.Errorf("FormatSANs() returned %d items, want 1", len(result))
		}
		if result[0] != "Email:test@example.com" {
			t.Errorf("FormatSANs()[0] = %s, want Email:test@example.com", result[0])
		}
	})

	t.Run("[Unit] FormatSANs: URIs", func(t *testing.T) {
		uri, _ := url.Parse("https://example.com/path")
		cert := &x509.Certificate{
			URIs: []*url.URL{uri},
		}
		result := FormatSANs(cert)
		if len(result) != 1 {
			t.Errorf("FormatSANs() returned %d items, want 1", len(result))
		}
		if result[0] != "URI:https://example.com/path" {
			t.Errorf("FormatSANs()[0] = %s, want URI:https://example.com/path", result[0])
		}
	})

	t.Run("[Unit] FormatSANs: mixed SANs", func(t *testing.T) {
		uri, _ := url.Parse("https://example.com")
		cert := &x509.Certificate{
			DNSNames:       []string{"example.com"},
			IPAddresses:    []net.IP{net.ParseIP("10.0.0.1")},
			EmailAddresses: []string{"admin@example.com"},
			URIs:           []*url.URL{uri},
		}
		result := FormatSANs(cert)
		if len(result) != 4 {
			t.Errorf("FormatSANs() returned %d items, want 4", len(result))
		}
	})
}

// =============================================================================
// GetCertStatus Tests
// =============================================================================

func TestU_GetCertStatus(t *testing.T) {
	now := time.Now()
	futureExpiry := now.Add(365 * 24 * time.Hour)
	pastExpiry := now.Add(-30 * 24 * time.Hour)
	pastRevocation := now.Add(-10 * 24 * time.Hour)

	tests := []struct {
		name      string
		entries   []ca.IndexEntry
		serialHex string
		expected  string
	}{
		{
			name:      "[Unit] GetCertStatus: valid certificate",
			serialHex: "01",
			entries: []ca.IndexEntry{
				{Serial: []byte{0x01}, Status: "V", Expiry: futureExpiry},
			},
			expected: "Valid",
		},
		{
			name:      "[Unit] GetCertStatus: expired certificate",
			serialHex: "02",
			entries: []ca.IndexEntry{
				{Serial: []byte{0x02}, Status: "V", Expiry: pastExpiry},
			},
			expected: "Expired",
		},
		{
			name:      "[Unit] GetCertStatus: revoked certificate with date",
			serialHex: "03",
			entries: []ca.IndexEntry{
				{Serial: []byte{0x03}, Status: "R", Revocation: pastRevocation},
			},
			expected: "Revoked (" + pastRevocation.Format("2006-01-02") + ")",
		},
		{
			name:      "[Unit] GetCertStatus: revoked certificate without date",
			serialHex: "04",
			entries: []ca.IndexEntry{
				{Serial: []byte{0x04}, Status: "R"},
			},
			expected: "Revoked",
		},
		{
			name:      "[Unit] GetCertStatus: explicitly expired",
			serialHex: "05",
			entries: []ca.IndexEntry{
				{Serial: []byte{0x05}, Status: "E"},
			},
			expected: "Expired",
		},
		{
			name:      "[Unit] GetCertStatus: not found",
			serialHex: "ff",
			entries: []ca.IndexEntry{
				{Serial: []byte{0x01}, Status: "V"},
			},
			expected: "Valid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetCertStatus(tt.entries, tt.serialHex)
			if result != tt.expected {
				t.Errorf("GetCertStatus() = %s, want %s", result, tt.expected)
			}
		})
	}
}

// =============================================================================
// FormatPathLen Tests
// =============================================================================

func TestU_FormatPathLen(t *testing.T) {
	tests := []struct {
		name     string
		cert     *x509.Certificate
		expected string
	}{
		{
			name: "[Unit] FormatPathLen: non-CA certificate",
			cert: &x509.Certificate{
				IsCA: false,
			},
			expected: "",
		},
		{
			name: "[Unit] FormatPathLen: CA with pathLen 0",
			cert: &x509.Certificate{
				IsCA:           true,
				MaxPathLen:     0,
				MaxPathLenZero: true,
			},
			expected: "0",
		},
		{
			name: "[Unit] FormatPathLen: CA with pathLen 1",
			cert: &x509.Certificate{
				IsCA:       true,
				MaxPathLen: 1,
			},
			expected: "1",
		},
		{
			name: "[Unit] FormatPathLen: CA with unlimited pathLen",
			cert: &x509.Certificate{
				IsCA:       true,
				MaxPathLen: -1,
			},
			expected: "unlimited",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatPathLen(tt.cert)
			if result != tt.expected {
				t.Errorf("FormatPathLen() = %s, want %s", result, tt.expected)
			}
		})
	}
}

func TestU_SerialHexMatching(t *testing.T) {
	// Test that serial hex matching works correctly
	serial := []byte{0x01, 0x02, 0x03}
	serialHex := hex.EncodeToString(serial)

	if serialHex != "010203" {
		t.Errorf("hex.EncodeToString() = %s, want 010203", serialHex)
	}
}
