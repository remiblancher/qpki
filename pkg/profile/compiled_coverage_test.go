package profile

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"testing"
	"time"
)

// =============================================================================
// Unit Tests: CompiledProfile Functions
// =============================================================================

// TestU_CompiledProfile_BuildTemplateWithValidity tests the BuildTemplateWithValidity function
func TestU_CompiledProfile_BuildTemplateWithValidity(t *testing.T) {
	p := createTestProfile()
	cp, err := p.Compile()
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	subject := pkix.Name{
		CommonName:   "test.example.com",
		Organization: []string{"Test Org"},
	}
	dnsNames := []string{"api.example.com"}
	ips := []net.IP{net.ParseIP("192.168.1.1")}
	emails := []string{"test@example.com"}
	notBefore := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	serialNumber := []byte{0x01, 0x02, 0x03, 0x04}

	tmpl := cp.BuildTemplateWithValidity(subject, dnsNames, ips, emails, notBefore, serialNumber)

	if tmpl == nil {
		t.Fatal("BuildTemplateWithValidity() returned nil")
	}

	// Verify NotBefore
	if !tmpl.NotBefore.Equal(notBefore) {
		t.Errorf("NotBefore = %v, want %v", tmpl.NotBefore, notBefore)
	}

	// Verify NotAfter is computed from validity
	expectedNotAfter := notBefore.Add(p.Validity)
	if !tmpl.NotAfter.Equal(expectedNotAfter) {
		t.Errorf("NotAfter = %v, want %v", tmpl.NotAfter, expectedNotAfter)
	}

	// Verify SerialNumber
	if tmpl.SerialNumber == nil {
		t.Error("SerialNumber should not be nil")
	}

	// Verify Subject
	if tmpl.Subject.CommonName != "test.example.com" {
		t.Errorf("Subject.CommonName = %q, want %q", tmpl.Subject.CommonName, "test.example.com")
	}
}

// TestU_CompiledProfile_KeyUsage tests the KeyUsage accessor function
func TestU_CompiledProfile_KeyUsage(t *testing.T) {
	p := createTestProfile()
	cp, err := p.Compile()
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	ku := cp.KeyUsage()

	// Should have the key usage values from createTestProfile()
	if ku&x509.KeyUsageDigitalSignature == 0 {
		t.Error("KeyUsage should include DigitalSignature")
	}
	if ku&x509.KeyUsageKeyEncipherment == 0 {
		t.Error("KeyUsage should include KeyEncipherment")
	}
}

// TestU_CompiledProfile_KeyUsage_NoExtensions tests KeyUsage when no extensions
func TestU_CompiledProfile_KeyUsage_NoExtensions(t *testing.T) {
	p := &Profile{
		Name:      "no-extensions",
		Algorithm: "ecdsa-p256",
		Validity:  365 * 24 * time.Hour,
	}
	cp, err := p.Compile()
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	ku := cp.KeyUsage()

	if ku != 0 {
		t.Errorf("KeyUsage() = %v, want 0 (no extensions)", ku)
	}
}

// TestU_CompiledProfile_ExtKeyUsage tests the ExtKeyUsage accessor function
func TestU_CompiledProfile_ExtKeyUsage(t *testing.T) {
	p := createTestProfile()
	cp, err := p.Compile()
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	eku := cp.ExtKeyUsage()

	if len(eku) != 2 {
		t.Errorf("ExtKeyUsage() returned %d values, want 2", len(eku))
	}

	// Should have serverAuth and clientAuth from createTestProfile()
	hasServerAuth := false
	hasClientAuth := false
	for _, usage := range eku {
		if usage == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
		}
		if usage == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
		}
	}

	if !hasServerAuth {
		t.Error("ExtKeyUsage should include ServerAuth")
	}
	if !hasClientAuth {
		t.Error("ExtKeyUsage should include ClientAuth")
	}
}

// TestU_CompiledProfile_ExtKeyUsage_NoExtensions tests ExtKeyUsage when no extensions
func TestU_CompiledProfile_ExtKeyUsage_NoExtensions(t *testing.T) {
	p := &Profile{
		Name:      "no-extensions",
		Algorithm: "ecdsa-p256",
		Validity:  365 * 24 * time.Hour,
	}
	cp, err := p.Compile()
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	eku := cp.ExtKeyUsage()

	if len(eku) != 0 {
		t.Errorf("ExtKeyUsage() returned %d values, want 0 (no extensions)", len(eku))
	}
}

// TestU_CompiledProfile_IsCAProfile tests the IsCAProfile function
func TestU_CompiledProfile_IsCAProfile_True(t *testing.T) {
	critical := true
	p := &Profile{
		Name:      "ca-profile",
		Algorithm: "ecdsa-p256",
		Validity:  10 * 365 * 24 * time.Hour,
		Extensions: &ExtensionsConfig{
			BasicConstraints: &BasicConstraintsConfig{
				Critical: &critical,
				CA:       true,
			},
			KeyUsage: &KeyUsageConfig{
				Values: []string{"keyCertSign", "cRLSign"},
			},
		},
	}
	cp, err := p.Compile()
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	if !cp.IsCAProfile() {
		t.Error("IsCAProfile() should return true for CA profile")
	}
}

// TestU_CompiledProfile_IsCAProfile_False tests the IsCAProfile function for non-CA
func TestU_CompiledProfile_IsCAProfile_False(t *testing.T) {
	p := createTestProfile()
	cp, err := p.Compile()
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	if cp.IsCAProfile() {
		t.Error("IsCAProfile() should return false for end-entity profile")
	}
}

// TestU_CompiledProfile_IsCAProfile_NoExtensions tests IsCAProfile with no extensions
func TestU_CompiledProfile_IsCAProfile_NoExtensions(t *testing.T) {
	p := &Profile{
		Name:      "no-extensions",
		Algorithm: "ecdsa-p256",
		Validity:  365 * 24 * time.Hour,
	}
	cp, err := p.Compile()
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	if cp.IsCAProfile() {
		t.Error("IsCAProfile() should return false when no extensions")
	}
}

// =============================================================================
// Unit Tests: FileCompiledStore.All
// =============================================================================

func TestU_FileCompiledStore_All(t *testing.T) {
	store := NewCompiledProfileStore("")
	if err := store.Load(); err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	all := store.All()

	if all == nil {
		t.Fatal("All() returned nil")
	}

	// Should have the same count as List()
	if len(all) != store.Count() {
		t.Errorf("All() returned %d profiles, Count() = %d", len(all), store.Count())
	}

	// Verify it's a copy (modifying it shouldn't affect the store)
	originalCount := store.Count()
	all["fake-profile"] = nil
	if store.Count() != originalCount {
		t.Error("All() should return a copy, not the internal map")
	}
}

// =============================================================================
// Unit Tests: Compile Error Cases
// =============================================================================

func TestU_Profile_Compile_InvalidKeyUsage(t *testing.T) {
	p := &Profile{
		Name:      "invalid-keyusage",
		Algorithm: "ecdsa-p256",
		Validity:  365 * 24 * time.Hour,
		Extensions: &ExtensionsConfig{
			KeyUsage: &KeyUsageConfig{
				Values: []string{"invalid-usage"},
			},
		},
	}

	_, err := p.Compile()
	if err == nil {
		t.Error("Compile() should return error for invalid key usage")
	}
}

func TestU_Profile_Compile_InvalidExtKeyUsage(t *testing.T) {
	p := &Profile{
		Name:      "invalid-extkeyusage",
		Algorithm: "ecdsa-p256",
		Validity:  365 * 24 * time.Hour,
		Extensions: &ExtensionsConfig{
			ExtKeyUsage: &ExtKeyUsageConfig{
				Values: []string{"invalid-ext-usage"},
			},
		},
	}

	_, err := p.Compile()
	if err == nil {
		t.Error("Compile() should return error for invalid extended key usage")
	}
}

func TestU_Profile_Compile_InvalidNameConstraintsCIDR(t *testing.T) {
	p := &Profile{
		Name:      "invalid-cidr",
		Algorithm: "ecdsa-p256",
		Validity:  365 * 24 * time.Hour,
		Extensions: &ExtensionsConfig{
			BasicConstraints: &BasicConstraintsConfig{
				CA: true,
			},
			KeyUsage: &KeyUsageConfig{
				Values: []string{"keyCertSign"},
			},
			NameConstraints: &NameConstraintsConfig{
				Permitted: &NameConstraintsSubtrees{
					IP: []string{"invalid-cidr"},
				},
			},
		},
	}

	_, err := p.Compile()
	if err == nil {
		t.Error("Compile() should return error for invalid CIDR in name constraints")
	}
}

func TestU_Profile_Compile_InvalidExcludedNameConstraintsCIDR(t *testing.T) {
	p := &Profile{
		Name:      "invalid-excluded-cidr",
		Algorithm: "ecdsa-p256",
		Validity:  365 * 24 * time.Hour,
		Extensions: &ExtensionsConfig{
			BasicConstraints: &BasicConstraintsConfig{
				CA: true,
			},
			KeyUsage: &KeyUsageConfig{
				Values: []string{"keyCertSign"},
			},
			NameConstraints: &NameConstraintsConfig{
				Excluded: &NameConstraintsSubtrees{
					IP: []string{"not-a-valid-cidr"},
				},
			},
		},
	}

	_, err := p.Compile()
	if err == nil {
		t.Error("Compile() should return error for invalid excluded CIDR in name constraints")
	}
}

func TestU_Profile_Compile_InvalidSANIP(t *testing.T) {
	p := &Profile{
		Name:      "invalid-san-ip",
		Algorithm: "ecdsa-p256",
		Validity:  365 * 24 * time.Hour,
		Extensions: &ExtensionsConfig{
			SubjectAltName: &SubjectAltNameConfig{
				IP: []string{"not-an-ip-address"},
			},
		},
	}

	_, err := p.Compile()
	if err == nil {
		t.Error("Compile() should return error for invalid IP in SAN")
	}
}

func TestU_Profile_Compile_InvalidSANURI(t *testing.T) {
	p := &Profile{
		Name:      "invalid-san-uri",
		Algorithm: "ecdsa-p256",
		Validity:  365 * 24 * time.Hour,
		Extensions: &ExtensionsConfig{
			SubjectAltName: &SubjectAltNameConfig{
				URI: []string{"://invalid-uri"},
			},
		},
	}

	_, err := p.Compile()
	if err == nil {
		t.Error("Compile() should return error for invalid URI in SAN")
	}
}

func TestU_Profile_Compile_InvalidCertificatePolicy(t *testing.T) {
	p := &Profile{
		Name:      "invalid-policy",
		Algorithm: "ecdsa-p256",
		Validity:  365 * 24 * time.Hour,
		Extensions: &ExtensionsConfig{
			CertificatePolicies: &CertificatePoliciesConfig{
				Policies: []PolicyConfig{
					{OID: "not.a.valid.oid.abc"},
				},
			},
		},
	}

	_, err := p.Compile()
	if err == nil {
		t.Error("Compile() should return error for invalid OID in certificate policies")
	}
}

// =============================================================================
// Unit Tests: isTemplateVar
// =============================================================================

func TestU_isTemplateVar(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"{{ variable }}", true},
		{"{{variable}}", true},
		{"{{  variable  }}", true},
		{"{{ cn }}", true},
		{"static-value", false},
		{"", false},
		{"{ variable }", false},
		{"{variable}", false},
		{"{{ }}", true}, // Empty variable name still matches pattern
		{"prefix {{ var }}", false},
		{"{{ var }} suffix", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := isTemplateVar(tt.input)
			if result != tt.expected {
				t.Errorf("isTemplateVar(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

// =============================================================================
// Unit Tests: Compile with NameConstraints email and DNS
// =============================================================================

func TestU_Profile_Compile_NameConstraints_Email(t *testing.T) {
	p := &Profile{
		Name:      "nc-email",
		Algorithm: "ecdsa-p256",
		Validity:  365 * 24 * time.Hour,
		Extensions: &ExtensionsConfig{
			BasicConstraints: &BasicConstraintsConfig{
				CA: true,
			},
			KeyUsage: &KeyUsageConfig{
				Values: []string{"keyCertSign"},
			},
			NameConstraints: &NameConstraintsConfig{
				Permitted: &NameConstraintsSubtrees{
					Email: []string{"@example.com"},
				},
				Excluded: &NameConstraintsSubtrees{
					Email: []string{"@denied.com"},
				},
			},
		},
	}

	cp, err := p.Compile()
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	if len(cp.permittedEmailAddresses) != 1 {
		t.Errorf("permittedEmailAddresses has %d entries, want 1", len(cp.permittedEmailAddresses))
	}

	if len(cp.excludedEmailAddresses) != 1 {
		t.Errorf("excludedEmailAddresses has %d entries, want 1", len(cp.excludedEmailAddresses))
	}
}

// =============================================================================
// Unit Tests: ApplyToTemplate with URIs
// =============================================================================

func TestU_CompiledProfile_ApplyToTemplate_WithURIs(t *testing.T) {
	p := &Profile{
		Name:      "with-uris",
		Algorithm: "ecdsa-p256",
		Validity:  365 * 24 * time.Hour,
		Extensions: &ExtensionsConfig{
			SubjectAltName: &SubjectAltNameConfig{
				URI: []string{"https://example.com/resource"},
			},
		},
	}

	cp, err := p.Compile()
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	subject := pkix.Name{CommonName: "test"}
	tmpl := cp.ApplyToTemplate(subject, nil, nil, nil)

	if len(tmpl.URIs) != 1 {
		t.Errorf("URIs has %d entries, want 1", len(tmpl.URIs))
	}

	if tmpl.URIs[0].String() != "https://example.com/resource" {
		t.Errorf("URI = %q, want %q", tmpl.URIs[0].String(), "https://example.com/resource")
	}
}

// =============================================================================
// Unit Tests: ApplyToTemplate with ExtraExtensions
// =============================================================================

func TestU_CompiledProfile_ApplyToTemplate_WithOCSPNoCheck(t *testing.T) {
	p := &Profile{
		Name:      "with-ocsp-no-check",
		Algorithm: "ecdsa-p256",
		Validity:  365 * 24 * time.Hour,
		Extensions: &ExtensionsConfig{
			OCSPNoCheck: &OCSPNoCheckConfig{},
		},
	}

	cp, err := p.Compile()
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	subject := pkix.Name{CommonName: "ocsp-responder"}
	tmpl := cp.ApplyToTemplate(subject, nil, nil, nil)

	if len(tmpl.ExtraExtensions) != 1 {
		t.Errorf("ExtraExtensions has %d entries, want 1", len(tmpl.ExtraExtensions))
	}
}
