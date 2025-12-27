package profile

import (
	"testing"
	"time"
)

// =============================================================================
// EmailValidator Tests
// =============================================================================

func TestEmailValidator_Validate(t *testing.T) {
	validator := &EmailValidator{}

	tests := []struct {
		name    string
		value   interface{}
		wantErr bool
	}{
		// Valid emails
		{"simple email", "user@example.com", false},
		{"with subdomain", "user@mail.example.com", false},
		{"with plus", "user+tag@example.com", false},
		{"with dots", "user.name@example.com", false},
		{"uppercase", "User@Example.COM", false},

		// Invalid emails
		{"missing @", "userexample.com", true},
		{"missing domain", "user@", true},
		{"missing local", "@example.com", true},
		{"double @", "user@@example.com", true},
		{"empty string", "", true},
		{"not a string", 123, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.Validate(tt.value, &Variable{}, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("EmailValidator.Validate(%v) error = %v, wantErr %v", tt.value, err, tt.wantErr)
			}
		})
	}
}

func TestEmailValidator_Constraints(t *testing.T) {
	validator := &EmailValidator{}

	tests := []struct {
		name       string
		email      string
		variable   *Variable
		wantErr    bool
	}{
		// Allowed suffixes
		{
			"allowed suffix @example.com",
			"user@example.com",
			&Variable{Constraints: &ListConstraints{AllowedSuffixes: []string{"@example.com"}}},
			false,
		},
		{
			"allowed suffix example.com (no @)",
			"user@example.com",
			&Variable{Constraints: &ListConstraints{AllowedSuffixes: []string{"example.com"}}},
			false,
		},
		{
			"subdomain of allowed",
			"user@mail.example.com",
			&Variable{Constraints: &ListConstraints{AllowedSuffixes: []string{"example.com"}}},
			false,
		},
		{
			"not in allowed suffixes",
			"user@other.com",
			&Variable{Constraints: &ListConstraints{AllowedSuffixes: []string{"example.com"}}},
			true,
		},

		// Denied prefixes
		{
			"allowed local part",
			"alice@example.com",
			&Variable{Constraints: &ListConstraints{DeniedPrefixes: []string{"admin", "root"}}},
			false,
		},
		{
			"denied prefix admin",
			"admin@example.com",
			&Variable{Constraints: &ListConstraints{DeniedPrefixes: []string{"admin", "root"}}},
			true,
		},
		{
			"denied prefix root",
			"root@example.com",
			&Variable{Constraints: &ListConstraints{DeniedPrefixes: []string{"admin", "root"}}},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.Validate(tt.email, tt.variable, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("EmailValidator.Validate(%q) error = %v, wantErr %v", tt.email, err, tt.wantErr)
			}
		})
	}
}

func TestEmailValidator_Normalize(t *testing.T) {
	validator := &EmailValidator{}

	tests := []struct {
		input    interface{}
		expected interface{}
	}{
		{"User@Example.COM", "user@example.com"},
		{"ALICE@MAIL.EXAMPLE.COM", "alice@mail.example.com"},
		{"user@example.com", "user@example.com"},
		{123, 123}, // Non-string returns as-is
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			got, _ := validator.Normalize(tt.input)
			if got != tt.expected {
				t.Errorf("EmailValidator.Normalize(%v) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

// =============================================================================
// URIValidator Tests
// =============================================================================

func TestURIValidator_Validate(t *testing.T) {
	validator := &URIValidator{}

	tests := []struct {
		name    string
		value   interface{}
		wantErr bool
	}{
		// Valid URIs
		{"http", "http://example.com", false},
		{"https", "https://example.com", false},
		{"https with path", "https://example.com/path", false},
		{"https with port", "https://example.com:8443", false},
		{"https with query", "https://example.com?query=1", false},
		{"ldap", "ldap://ldap.example.com", false},

		// Invalid URIs
		{"no scheme", "example.com", true},
		{"empty", "", true},
		{"not a string", 123, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.Validate(tt.value, &Variable{}, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("URIValidator.Validate(%v) error = %v, wantErr %v", tt.value, err, tt.wantErr)
			}
		})
	}
}

func TestURIValidator_Constraints(t *testing.T) {
	validator := &URIValidator{}

	tests := []struct {
		name     string
		uri      string
		variable *Variable
		wantErr  bool
	}{
		// Allowed schemes
		{
			"allowed http",
			"http://example.com",
			&Variable{Constraints: &ListConstraints{AllowedSchemes: []string{"http", "https"}}},
			false,
		},
		{
			"allowed https",
			"https://example.com",
			&Variable{Constraints: &ListConstraints{AllowedSchemes: []string{"http", "https"}}},
			false,
		},
		{
			"scheme not allowed",
			"ftp://example.com",
			&Variable{Constraints: &ListConstraints{AllowedSchemes: []string{"http", "https"}}},
			true,
		},

		// Allowed hosts
		{
			"allowed host",
			"https://ocsp.example.com",
			&Variable{Constraints: &ListConstraints{AllowedHosts: []string{"ocsp.example.com", "ocsp2.example.com"}}},
			false,
		},
		{
			"host not allowed",
			"https://other.com",
			&Variable{Constraints: &ListConstraints{AllowedHosts: []string{"ocsp.example.com"}}},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.Validate(tt.uri, tt.variable, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("URIValidator.Validate(%q) error = %v, wantErr %v", tt.uri, err, tt.wantErr)
			}
		})
	}
}

func TestURIValidator_Normalize(t *testing.T) {
	validator := &URIValidator{}

	tests := []struct {
		input    string
		expected string
	}{
		{"HTTP://Example.COM/Path", "http://Example.COM/Path"},
		{"HTTPS://example.com", "https://example.com"},
		{"http://example.com", "http://example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, _ := validator.Normalize(tt.input)
			if got != tt.expected {
				t.Errorf("URIValidator.Normalize(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// =============================================================================
// OIDValidator Tests
// =============================================================================

func TestOIDValidator_Validate(t *testing.T) {
	validator := &OIDValidator{}

	tests := []struct {
		name    string
		value   interface{}
		wantErr bool
	}{
		// Valid OIDs
		{"simple OID", "1.2.3", false},
		{"long OID", "1.2.840.113549.1.1.11", false},
		{"ML-DSA OID", "2.16.840.1.101.3.4.3.17", false},
		{"first arc 0", "0.2.3", false},
		{"first arc 1", "1.2.3", false},
		{"first arc 2", "2.999.3", false},

		// Invalid OIDs
		{"empty", "", true},
		{"single number", "1", true},
		{"first arc > 2", "3.2.3", true},
		{"second arc >= 40 under arc 0", "0.40.1", true},
		{"second arc >= 40 under arc 1", "1.40.1", true},
		{"leading zeros", "1.02.3", false}, // ParseUint handles this
		{"negative", "1.-2.3", true},
		{"letters", "1.a.3", true},
		{"not a string", 123, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.Validate(tt.value, &Variable{}, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("OIDValidator.Validate(%v) error = %v, wantErr %v", tt.value, err, tt.wantErr)
			}
		})
	}
}

func TestOIDValidator_Constraints(t *testing.T) {
	validator := &OIDValidator{}

	tests := []struct {
		name     string
		oid      string
		variable *Variable
		wantErr  bool
	}{
		// Allowed prefixes (using AllowedSuffixes for OID prefix constraint)
		{
			"allowed NIST prefix",
			"2.16.840.1.101.3.4.3.17",
			&Variable{Constraints: &ListConstraints{AllowedSuffixes: []string{"2.16.840.1.101.3.4"}}},
			false,
		},
		{
			"prefix not allowed",
			"1.2.3.4.5",
			&Variable{Constraints: &ListConstraints{AllowedSuffixes: []string{"2.16.840"}}},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.Validate(tt.oid, tt.variable, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("OIDValidator.Validate(%q) error = %v, wantErr %v", tt.oid, err, tt.wantErr)
			}
		})
	}
}

// =============================================================================
// DurationValidator Tests
// =============================================================================

func TestDurationValidator_Validate(t *testing.T) {
	validator := &DurationValidator{}

	tests := []struct {
		name    string
		value   interface{}
		wantErr bool
	}{
		// Valid durations (Go format)
		{"hours", "24h", false},
		{"minutes", "30m", false},
		{"seconds", "60s", false},
		{"combined", "1h30m", false},

		// Valid durations (extended format)
		{"days", "365d", false},
		{"weeks", "2w", false},
		{"years", "1y", false},
		{"combined extended", "1y6m", false},
		{"days and hours", "30d12h", false},

		// Invalid durations
		{"empty", "", true},
		{"invalid format", "abc", true},
		{"not a string", 123, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.Validate(tt.value, &Variable{}, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("DurationValidator.Validate(%v) error = %v, wantErr %v", tt.value, err, tt.wantErr)
			}
		})
	}
}

func TestDurationValidator_MinMax(t *testing.T) {
	validator := &DurationValidator{}

	tests := []struct {
		name     string
		duration string
		variable *Variable
		wantErr  bool
	}{
		// Min constraint
		{
			"above min",
			"30d",
			&Variable{MinDuration: "7d"},
			false,
		},
		{
			"below min",
			"1d",
			&Variable{MinDuration: "7d"},
			true,
		},

		// Max constraint
		{
			"below max",
			"365d",
			&Variable{MaxDuration: "825d"},
			false,
		},
		{
			"above max",
			"1000d",
			&Variable{MaxDuration: "825d"},
			true,
		},

		// Both constraints
		{
			"within range",
			"365d",
			&Variable{MinDuration: "1d", MaxDuration: "825d"},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.Validate(tt.duration, tt.variable, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("DurationValidator.Validate(%q) error = %v, wantErr %v", tt.duration, err, tt.wantErr)
			}
		})
	}
}

func TestParseDuration(t *testing.T) {
	tests := []struct {
		input    string
		expected time.Duration
		wantErr  bool
	}{
		// Standard Go durations
		{"1h", time.Hour, false},
		{"30m", 30 * time.Minute, false},
		{"60s", 60 * time.Second, false},
		{"1h30m", time.Hour + 30*time.Minute, false},

		// Extended format
		{"1d", 24 * time.Hour, false},
		{"7d", 7 * 24 * time.Hour, false},
		{"1w", 7 * 24 * time.Hour, false},
		{"2w", 14 * 24 * time.Hour, false},
		{"1y", 365 * 24 * time.Hour, false},
		{"365d", 365 * 24 * time.Hour, false},

		// Combined
		{"1d12h", 36 * time.Hour, false},
		{"1w1d", 8 * 24 * time.Hour, false},
		{"1y1d", 366 * 24 * time.Hour, false},

		// Invalid
		{"", 0, true},
		{"abc", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseDuration(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseDuration(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.expected {
				t.Errorf("ParseDuration(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

// =============================================================================
// Type Registry Tests
// =============================================================================

func TestTypeRegistry(t *testing.T) {
	// Test that built-in types are registered
	types := []VariableType{
		VarTypeEmail,
		VarTypeURI,
		VarTypeOID,
		VarTypeDuration,
	}

	for _, vt := range types {
		t.Run(string(vt), func(t *testing.T) {
			validator, ok := GetTypeValidator(vt)
			if !ok {
				t.Errorf("GetTypeValidator(%q) not found", vt)
				return
			}
			if validator.Type() != vt {
				t.Errorf("validator.Type() = %q, want %q", validator.Type(), vt)
			}
		})
	}
}

func TestListTypeValidators(t *testing.T) {
	types := ListTypeValidators()
	if len(types) < 4 {
		t.Errorf("ListTypeValidators() returned %d types, want at least 4", len(types))
	}

	// Check that our new types are in the list
	found := make(map[VariableType]bool)
	for _, vt := range types {
		found[vt] = true
	}

	expected := []VariableType{VarTypeEmail, VarTypeURI, VarTypeOID, VarTypeDuration}
	for _, vt := range expected {
		if !found[vt] {
			t.Errorf("type %q not found in ListTypeValidators()", vt)
		}
	}
}

// =============================================================================
// Integration Tests with VariableValidator
// =============================================================================

func TestVariableValidator_Email(t *testing.T) {
	vars := map[string]*Variable{
		"email": {
			Name:     "email",
			Type:     VarTypeEmail,
			Required: true,
			Constraints: &ListConstraints{
				AllowedSuffixes: []string{"@example.com", "@acme.com"},
			},
		},
	}

	v, err := NewVariableValidator(vars)
	if err != nil {
		t.Fatalf("NewVariableValidator failed: %v", err)
	}

	tests := []struct {
		name    string
		value   interface{}
		wantErr bool
	}{
		{"valid example.com", "user@example.com", false},
		{"valid acme.com", "user@acme.com", false},
		{"invalid domain", "user@other.com", true},
		{"invalid format", "not-an-email", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate("email", tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate(%q) error = %v, wantErr %v", tt.value, err, tt.wantErr)
			}
		})
	}
}

func TestVariableValidator_URI(t *testing.T) {
	vars := map[string]*Variable{
		"ocsp_url": {
			Name:     "ocsp_url",
			Type:     VarTypeURI,
			Required: false,
			Default:  "http://ocsp.example.com",
			Constraints: &ListConstraints{
				AllowedSchemes: []string{"http", "https"},
				AllowedHosts:   []string{"ocsp.example.com", "ocsp2.example.com"},
			},
		},
	}

	v, err := NewVariableValidator(vars)
	if err != nil {
		t.Fatalf("NewVariableValidator failed: %v", err)
	}

	tests := []struct {
		name    string
		value   interface{}
		wantErr bool
	}{
		{"valid http", "http://ocsp.example.com", false},
		{"valid https", "https://ocsp2.example.com", false},
		{"invalid scheme", "ftp://ocsp.example.com", true},
		{"invalid host", "http://other.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate("ocsp_url", tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate(%q) error = %v, wantErr %v", tt.value, err, tt.wantErr)
			}
		})
	}
}

func TestVariableValidator_OID(t *testing.T) {
	vars := map[string]*Variable{
		"policy_oid": {
			Name:     "policy_oid",
			Type:     VarTypeOID,
			Required: false,
			Default:  "1.3.6.1.4.1.99999.1",
		},
	}

	v, err := NewVariableValidator(vars)
	if err != nil {
		t.Fatalf("NewVariableValidator failed: %v", err)
	}

	tests := []struct {
		name    string
		value   interface{}
		wantErr bool
	}{
		{"valid OID", "1.3.6.1.4.1.99999.1", false},
		{"valid NIST OID", "2.16.840.1.101.3.4.3.17", false},
		{"invalid format", "not.an.oid.a", true},
		{"single number", "1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate("policy_oid", tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate(%q) error = %v, wantErr %v", tt.value, err, tt.wantErr)
			}
		})
	}
}

func TestVariableValidator_Duration(t *testing.T) {
	vars := map[string]*Variable{
		"validity": {
			Name:        "validity",
			Type:        VarTypeDuration,
			Required:    false,
			Default:     "365d",
			MinDuration: "1d",
			MaxDuration: "825d",
		},
	}

	v, err := NewVariableValidator(vars)
	if err != nil {
		t.Fatalf("NewVariableValidator failed: %v", err)
	}

	tests := []struct {
		name    string
		value   interface{}
		wantErr bool
	}{
		{"valid 365d", "365d", false},
		{"valid 1y", "1y", false},
		{"valid 2w", "2w", false},
		{"below min", "12h", true},
		{"above max", "3y", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate("validity", tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate(%q) error = %v, wantErr %v", tt.value, err, tt.wantErr)
			}
		})
	}
}

// =============================================================================
// Benchmarks
// =============================================================================

func BenchmarkEmailValidator(b *testing.B) {
	validator := &EmailValidator{}
	variable := &Variable{
		Constraints: &ListConstraints{
			AllowedSuffixes: []string{"@example.com", "@acme.com"},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = validator.Validate("user@example.com", variable, nil)
	}
}

func BenchmarkURIValidator(b *testing.B) {
	validator := &URIValidator{}
	variable := &Variable{
		Constraints: &ListConstraints{
			AllowedSchemes: []string{"http", "https"},
			AllowedHosts:   []string{"ocsp.example.com"},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = validator.Validate("https://ocsp.example.com/status", variable, nil)
	}
}

func BenchmarkOIDValidator(b *testing.B) {
	validator := &OIDValidator{}
	variable := &Variable{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = validator.Validate("2.16.840.1.101.3.4.3.17", variable, nil)
	}
}

func BenchmarkDurationValidator(b *testing.B) {
	validator := &DurationValidator{}
	variable := &Variable{
		MinDuration: "1d",
		MaxDuration: "825d",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = validator.Validate("365d", variable, nil)
	}
}

func BenchmarkParseDuration(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseDuration("1y6m15d")
	}
}
