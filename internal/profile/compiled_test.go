package profile

import (
	"crypto/x509/pkix"
	"net"
	"testing"
	"time"
)

// =============================================================================
// Unit Tests: Profile Compilation
// =============================================================================

// Test profile for benchmarks
func createTestProfile() *Profile {
	critical := true
	pathLen := 0

	return &Profile{
		Name:        "test/benchmark",
		Description: "Profile for benchmark testing",
		Algorithm:   "ecdsa-p256",
		Validity:    365 * 24 * time.Hour,
		Extensions: &ExtensionsConfig{
			KeyUsage: &KeyUsageConfig{
				Critical: &critical,
				Values:   []string{"digitalSignature", "keyEncipherment"},
			},
			ExtKeyUsage: &ExtKeyUsageConfig{
				Values: []string{"serverAuth", "clientAuth"},
			},
			BasicConstraints: &BasicConstraintsConfig{
				Critical: &critical,
				CA:       false,
				PathLen:  &pathLen,
			},
			SubjectAltName: &SubjectAltNameConfig{
				DNS:   []string{"fixed.example.com"},
				IP:    []string{"10.0.0.1"},
				Email: []string{"admin@example.com"},
			},
			NameConstraints: &NameConstraintsConfig{
				Permitted: &NameConstraintsSubtrees{
					DNS: []string{".example.com", ".internal"},
					IP:  []string{"10.0.0.0/8", "192.168.0.0/16"},
				},
			},
			CRLDistributionPoints: &CRLDistributionPointsConfig{
				URLs: []string{"http://crl.example.com/ca.crl"},
			},
			AuthorityInfoAccess: &AuthorityInfoAccessConfig{
				OCSP:      []string{"http://ocsp.example.com"},
				CAIssuers: []string{"http://ca.example.com/ca.crt"},
			},
		},
	}
}

func TestU_ProfileCompile_AllExtensions(t *testing.T) {
	p := createTestProfile()

	cp, err := p.Compile()
	if err != nil {
		t.Fatalf("Compile() failed: %v", err)
	}

	// Verify key usage was pre-parsed
	if cp.keyUsage == 0 {
		t.Error("KeyUsage should be non-zero")
	}

	// Verify extended key usage was pre-parsed
	if len(cp.extKeyUsage) != 2 {
		t.Errorf("ExtKeyUsage should have 2 values, got %d", len(cp.extKeyUsage))
	}

	// Verify basic constraints
	if cp.isCA {
		t.Error("isCA should be false")
	}
	if !cp.basicConstraintsValid {
		t.Error("basicConstraintsValid should be true")
	}

	// Verify fixed SANs were pre-parsed
	if len(cp.fixedDNSNames) != 1 || cp.fixedDNSNames[0] != "fixed.example.com" {
		t.Errorf("fixedDNSNames not parsed correctly: %v", cp.fixedDNSNames)
	}
	if len(cp.fixedIPs) != 1 {
		t.Errorf("fixedIPs should have 1 value, got %d", len(cp.fixedIPs))
	}

	// Verify name constraints were pre-parsed
	if len(cp.permittedDNSDomains) != 2 {
		t.Errorf("permittedDNSDomains should have 2 values, got %d", len(cp.permittedDNSDomains))
	}
	if len(cp.permittedIPRanges) != 2 {
		t.Errorf("permittedIPRanges should have 2 values, got %d", len(cp.permittedIPRanges))
	}
}

func TestU_ApplyToTemplate_MergesSANs(t *testing.T) {
	p := createTestProfile()
	cp, err := p.Compile()
	if err != nil {
		t.Fatalf("Compile() failed: %v", err)
	}

	subject := pkix.Name{
		CommonName:   "test.example.com",
		Organization: []string{"Test Org"},
	}
	dnsNames := []string{"api.example.com", "www.example.com"}
	ips := []net.IP{net.ParseIP("192.168.1.1")}
	emails := []string{"test@example.com"}

	tmpl := cp.ApplyToTemplate(subject, dnsNames, ips, emails)

	// Verify subject was applied
	if tmpl.Subject.CommonName != "test.example.com" {
		t.Errorf("Subject.CommonName = %q, want %q", tmpl.Subject.CommonName, "test.example.com")
	}

	// Verify DNS names were merged (fixed + user)
	expectedDNS := 3 // 1 fixed + 2 user
	if len(tmpl.DNSNames) != expectedDNS {
		t.Errorf("DNSNames has %d entries, want %d", len(tmpl.DNSNames), expectedDNS)
	}

	// Verify IPs were merged (fixed + user)
	expectedIPs := 2 // 1 fixed + 1 user
	if len(tmpl.IPAddresses) != expectedIPs {
		t.Errorf("IPAddresses has %d entries, want %d", len(tmpl.IPAddresses), expectedIPs)
	}

	// Verify emails were merged (fixed + user)
	expectedEmails := 2 // 1 fixed + 1 user
	if len(tmpl.EmailAddresses) != expectedEmails {
		t.Errorf("EmailAddresses has %d entries, want %d", len(tmpl.EmailAddresses), expectedEmails)
	}

	// Verify KeyUsage was applied
	if tmpl.KeyUsage == 0 {
		t.Error("KeyUsage should be non-zero")
	}

	// Verify name constraints were applied
	if len(tmpl.PermittedDNSDomains) != 2 {
		t.Errorf("PermittedDNSDomains should have 2 values, got %d", len(tmpl.PermittedDNSDomains))
	}
}

// =============================================================================
// Unit Tests: CompiledProfileStore
// =============================================================================

func TestU_CompiledProfileStore_LoadBuiltins(t *testing.T) {
	// Create a store with empty path (will use builtins only)
	store := NewCompiledProfileStore("")

	err := store.Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Should have loaded builtin profiles
	count := store.Count()
	if count == 0 {
		t.Error("Store should have loaded builtin profiles")
	}

	// Test Get
	profiles := store.List()
	if len(profiles) > 0 {
		p, ok := store.Get(profiles[0])
		if !ok {
			t.Errorf("Get(%q) should return true", profiles[0])
		}
		if p == nil {
			t.Errorf("Get(%q) should return non-nil profile", profiles[0])
		}
	}

	// Test Get non-existent
	_, ok := store.Get("non-existent-profile")
	if ok {
		t.Error("Get(non-existent) should return false")
	}
}

// =============================================================================
// Benchmarks (no naming convention changes needed)
// =============================================================================

func BenchmarkCompileProfile(b *testing.B) {
	p := createTestProfile()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := p.Compile()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkApplyToTemplate(b *testing.B) {
	p := createTestProfile()
	cp, err := p.Compile()
	if err != nil {
		b.Fatal(err)
	}

	subject := pkix.Name{CommonName: "test.example.com"}
	dnsNames := []string{"api.example.com", "www.example.com"}
	ips := []net.IP{net.ParseIP("192.168.1.1")}
	emails := []string{"test@example.com"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cp.ApplyToTemplate(subject, dnsNames, ips, emails)
	}
}

func BenchmarkApplyToTemplate_NoUserSANs(b *testing.B) {
	p := createTestProfile()
	cp, err := p.Compile()
	if err != nil {
		b.Fatal(err)
	}

	subject := pkix.Name{CommonName: "test.example.com"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cp.ApplyToTemplate(subject, nil, nil, nil)
	}
}

func BenchmarkExtensionsApply_Baseline(b *testing.B) {
	// Baseline: current approach with Apply() on each request
	p := createTestProfile()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Simulate current approach: parse on every call
		_, _ = p.Extensions.KeyUsage.ToKeyUsage()
		_, _, _ = p.Extensions.ExtKeyUsage.ToExtKeyUsage()
	}
}

func BenchmarkCompiledProfileStore_Get(b *testing.B) {
	store := NewCompiledProfileStore("")
	if err := store.Load(); err != nil {
		b.Fatal(err)
	}

	profiles := store.List()
	if len(profiles) == 0 {
		b.Skip("No profiles loaded")
	}

	profileName := profiles[0]

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = store.Get(profileName)
	}
}

// Parallel benchmark for concurrent access
func BenchmarkCompiledProfileStore_GetParallel(b *testing.B) {
	store := NewCompiledProfileStore("")
	if err := store.Load(); err != nil {
		b.Fatal(err)
	}

	profiles := store.List()
	if len(profiles) == 0 {
		b.Skip("No profiles loaded")
	}

	profileName := profiles[0]

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = store.Get(profileName)
		}
	})
}
