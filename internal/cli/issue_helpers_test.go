package cli

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"testing"
)

// =============================================================================
// ParseIPStrings Tests
// =============================================================================

func TestU_ParseIPStrings(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected int
	}{
		{
			name:     "[Unit] ParseIPStrings: empty input",
			input:    []string{},
			expected: 0,
		},
		{
			name:     "[Unit] ParseIPStrings: nil input",
			input:    nil,
			expected: 0,
		},
		{
			name:     "[Unit] ParseIPStrings: valid IPv4",
			input:    []string{"192.168.1.1"},
			expected: 1,
		},
		{
			name:     "[Unit] ParseIPStrings: valid IPv6",
			input:    []string{"::1", "2001:db8::1"},
			expected: 2,
		},
		{
			name:     "[Unit] ParseIPStrings: mixed valid and invalid",
			input:    []string{"192.168.1.1", "invalid", "10.0.0.1"},
			expected: 2,
		},
		{
			name:     "[Unit] ParseIPStrings: all invalid",
			input:    []string{"invalid", "not.an.ip", "abc"},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseIPStrings(tt.input)
			if len(result) != tt.expected {
				t.Errorf("ParseIPStrings() returned %d IPs, want %d", len(result), tt.expected)
			}
		})
	}
}

func TestU_ParseIPStrings_ValidIPs(t *testing.T) {
	input := []string{"192.168.1.1", "10.0.0.1", "::1"}
	result := ParseIPStrings(input)

	if len(result) != 3 {
		t.Fatalf("ParseIPStrings() returned %d IPs, want 3", len(result))
	}

	expected := []net.IP{
		net.ParseIP("192.168.1.1"),
		net.ParseIP("10.0.0.1"),
		net.ParseIP("::1"),
	}

	for i, ip := range result {
		if !ip.Equal(expected[i]) {
			t.Errorf("ParseIPStrings()[%d] = %s, want %s", i, ip, expected[i])
		}
	}
}

// =============================================================================
// MergeCSRVariables Tests
// =============================================================================

func TestU_MergeCSRVariables(t *testing.T) {
	t.Run("[Unit] MergeCSRVariables: empty varValues", func(t *testing.T) {
		varValues := make(map[string]interface{})
		template := &x509.Certificate{
			Subject: pkix.Name{
				CommonName: "test.example.com",
			},
			DNSNames:    []string{"test.example.com", "www.example.com"},
			IPAddresses: []net.IP{net.ParseIP("192.168.1.1")},
		}

		MergeCSRVariables(varValues, template)

		if varValues["cn"] != "test.example.com" {
			t.Errorf("MergeCSRVariables() cn = %v, want test.example.com", varValues["cn"])
		}
		if varValues["dns_names"] == nil {
			t.Error("MergeCSRVariables() dns_names should be set")
		}
		if varValues["ip_addresses"] == nil {
			t.Error("MergeCSRVariables() ip_addresses should be set")
		}
	})

	t.Run("[Unit] MergeCSRVariables: existing values not overwritten", func(t *testing.T) {
		varValues := map[string]interface{}{
			"cn": "existing.com",
		}
		template := &x509.Certificate{
			Subject: pkix.Name{
				CommonName: "new.example.com",
			},
		}

		MergeCSRVariables(varValues, template)

		if varValues["cn"] != "existing.com" {
			t.Errorf("MergeCSRVariables() cn = %v, want existing.com (should not be overwritten)", varValues["cn"])
		}
	})

	t.Run("[Unit] MergeCSRVariables: empty CSR template", func(t *testing.T) {
		varValues := make(map[string]interface{})
		template := &x509.Certificate{}

		MergeCSRVariables(varValues, template)

		if _, exists := varValues["cn"]; exists {
			t.Error("MergeCSRVariables() cn should not be set for empty template")
		}
	})
}

// =============================================================================
// CSRParseResult Tests
// =============================================================================

func TestU_CSRParseResult_Structure(t *testing.T) {
	result := &CSRParseResult{
		PublicKey: nil,
		Template: &x509.Certificate{
			DNSNames: []string{"example.com"},
		},
	}

	if result.Template == nil {
		t.Error("CSRParseResult.Template should not be nil")
	}

	if len(result.Template.DNSNames) != 1 {
		t.Errorf("CSRParseResult.Template.DNSNames length = %d, want 1", len(result.Template.DNSNames))
	}
}

// =============================================================================
// WriteCertificatePEM Tests
// =============================================================================

func TestU_WriteCertificatePEM(t *testing.T) {
	t.Run("[Unit] WriteCertificatePEM: success", func(t *testing.T) {
		tmpDir := t.TempDir()
		certPath := tmpDir + "/test.pem"

		cert := generateTestCert(t)

		err := WriteCertificatePEM(cert, certPath)
		if err != nil {
			t.Fatalf("WriteCertificatePEM() error = %v", err)
		}

		// Verify file was created and can be loaded
		loaded, err := LoadCertFromPath(certPath)
		if err != nil {
			t.Fatalf("failed to load written cert: %v", err)
		}

		if loaded.Subject.CommonName != cert.Subject.CommonName {
			t.Errorf("loaded cert CN = %s, want %s", loaded.Subject.CommonName, cert.Subject.CommonName)
		}
	})

	t.Run("[Unit] WriteCertificatePEM: invalid path", func(t *testing.T) {
		cert := generateTestCert(t)
		err := WriteCertificatePEM(cert, "/nonexistent/directory/cert.pem")
		if err == nil {
			t.Error("WriteCertificatePEM() should fail for invalid path")
		}
	})
}

// =============================================================================
// SPKIForPQC Tests
// =============================================================================

func TestU_SPKIForPQC_Structure(t *testing.T) {
	spki := SPKIForPQC{}

	// Just verify the struct exists and has expected fields
	if len(spki.Algorithm.Algorithm) > 0 {
		t.Error("SPKIForPQC.Algorithm should be empty initially")
	}

	if len(spki.PublicKey.Bytes) > 0 {
		t.Error("SPKIForPQC.PublicKey should be empty initially")
	}
}
