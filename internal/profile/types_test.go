package profile

import (
	"testing"
	"time"
)

// =============================================================================
// Unit Tests: EmailValidator
// =============================================================================

func TestU_EmailValidator_Validate(t *testing.T) {
	validator := &EmailValidator{}

	tests := []struct {
		name    string
		value   interface{}
		wantErr bool
	}{
		// Valid emails
		{"[Unit] Validate: Simple Email", "user@example.com", false},
		{"[Unit] Validate: Email With Subdomain", "user@mail.example.com", false},
		{"[Unit] Validate: Email With Plus", "user+tag@example.com", false},
		{"[Unit] Validate: Email With Dots", "user.name@example.com", false},
		{"[Unit] Validate: Email Uppercase", "User@Example.COM", false},

		// Invalid emails
		{"[Unit] Validate: Email Missing At", "userexample.com", true},
		{"[Unit] Validate: Email Missing Domain", "user@", true},
		{"[Unit] Validate: Email Missing Local", "@example.com", true},
		{"[Unit] Validate: Email Double At", "user@@example.com", true},
		{"[Unit] Validate: Email Empty String", "", true},
		{"[Unit] Validate: Email Not A String", 123, true},
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

func TestU_EmailValidator_Constraints(t *testing.T) {
	validator := &EmailValidator{}

	tests := []struct {
		name     string
		email    string
		variable *Variable
		wantErr  bool
	}{
		// Allowed suffixes
		{
			"[Unit] Constraints: Allowed Suffix With At",
			"user@example.com",
			&Variable{Constraints: &ListConstraints{AllowedSuffixes: []string{"@example.com"}}},
			false,
		},
		{
			"[Unit] Constraints: Allowed Suffix Without At",
			"user@example.com",
			&Variable{Constraints: &ListConstraints{AllowedSuffixes: []string{"example.com"}}},
			false,
		},
		{
			"[Unit] Constraints: Subdomain Of Allowed",
			"user@mail.example.com",
			&Variable{Constraints: &ListConstraints{AllowedSuffixes: []string{"example.com"}}},
			false,
		},
		{
			"[Unit] Constraints: Suffix Not Allowed",
			"user@other.com",
			&Variable{Constraints: &ListConstraints{AllowedSuffixes: []string{"example.com"}}},
			true,
		},

		// Denied prefixes
		{
			"[Unit] Constraints: Allowed Local Part",
			"alice@example.com",
			&Variable{Constraints: &ListConstraints{DeniedPrefixes: []string{"admin", "root"}}},
			false,
		},
		{
			"[Unit] Constraints: Denied Prefix Admin",
			"admin@example.com",
			&Variable{Constraints: &ListConstraints{DeniedPrefixes: []string{"admin", "root"}}},
			true,
		},
		{
			"[Unit] Constraints: Denied Prefix Root",
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

func TestU_EmailValidator_Normalize(t *testing.T) {
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
// Unit Tests: URIValidator
// =============================================================================

func TestU_URIValidator_Validate(t *testing.T) {
	validator := &URIValidator{}

	tests := []struct {
		name    string
		value   interface{}
		wantErr bool
	}{
		// Valid URIs
		{"[Unit] Validate: HTTP Scheme", "http://example.com", false},
		{"[Unit] Validate: HTTPS Scheme", "https://example.com", false},
		{"[Unit] Validate: HTTPS With Path", "https://example.com/path", false},
		{"[Unit] Validate: HTTPS With Port", "https://example.com:8443", false},
		{"[Unit] Validate: HTTPS With Query", "https://example.com?query=1", false},
		{"[Unit] Validate: LDAP Scheme", "ldap://ldap.example.com", false},

		// Invalid URIs
		{"[Unit] Validate: URI Missing Scheme", "example.com", true},
		{"[Unit] Validate: URI Empty", "", true},
		{"[Unit] Validate: URI Not A String", 123, true},
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

func TestU_URIValidator_Constraints(t *testing.T) {
	validator := &URIValidator{}

	tests := []struct {
		name     string
		uri      string
		variable *Variable
		wantErr  bool
	}{
		// Allowed schemes
		{
			"[Unit] Constraints: Allowed HTTP Scheme",
			"http://example.com",
			&Variable{Constraints: &ListConstraints{AllowedSchemes: []string{"http", "https"}}},
			false,
		},
		{
			"[Unit] Constraints: Allowed HTTPS Scheme",
			"https://example.com",
			&Variable{Constraints: &ListConstraints{AllowedSchemes: []string{"http", "https"}}},
			false,
		},
		{
			"[Unit] Constraints: Scheme Not Allowed",
			"ftp://example.com",
			&Variable{Constraints: &ListConstraints{AllowedSchemes: []string{"http", "https"}}},
			true,
		},

		// Allowed hosts
		{
			"[Unit] Constraints: Allowed Host",
			"https://ocsp.example.com",
			&Variable{Constraints: &ListConstraints{AllowedHosts: []string{"ocsp.example.com", "ocsp2.example.com"}}},
			false,
		},
		{
			"[Unit] Constraints: Host Not Allowed",
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

func TestU_URIValidator_Normalize(t *testing.T) {
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
// Unit Tests: OIDValidator
// =============================================================================

func TestU_OIDValidator_Validate(t *testing.T) {
	validator := &OIDValidator{}

	tests := []struct {
		name    string
		value   interface{}
		wantErr bool
	}{
		// Valid OIDs
		{"[Unit] Validate: OID Simple", "1.2.3", false},
		{"[Unit] Validate: OID Long", "1.2.840.113549.1.1.11", false},
		{"[Unit] Validate: OID ML-DSA", "2.16.840.1.101.3.4.3.17", false},
		{"[Unit] Validate: OID First Arc 0", "0.2.3", false},
		{"[Unit] Validate: OID First Arc 1", "1.2.3", false},
		{"[Unit] Validate: OID First Arc 2", "2.999.3", false},

		// Invalid OIDs
		{"[Unit] Validate: OID Empty", "", true},
		{"[Unit] Validate: OID Single Number", "1", true},
		{"[Unit] Validate: OID First Arc Invalid", "3.2.3", true},
		{"[Unit] Validate: OID Second Arc Invalid Under Arc 0", "0.40.1", true},
		{"[Unit] Validate: OID Second Arc Invalid Under Arc 1", "1.40.1", true},
		{"[Unit] Validate: OID Leading Zeros", "1.02.3", false}, // ParseUint handles this
		{"[Unit] Validate: OID Negative", "1.-2.3", true},
		{"[Unit] Validate: OID Letters", "1.a.3", true},
		{"[Unit] Validate: OID Not A String", 123, true},
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

func TestU_OIDValidator_Constraints(t *testing.T) {
	validator := &OIDValidator{}

	tests := []struct {
		name     string
		oid      string
		variable *Variable
		wantErr  bool
	}{
		// Allowed prefixes (using AllowedSuffixes for OID prefix constraint)
		{
			"[Unit] Constraints: Allowed NIST Prefix",
			"2.16.840.1.101.3.4.3.17",
			&Variable{Constraints: &ListConstraints{AllowedSuffixes: []string{"2.16.840.1.101.3.4"}}},
			false,
		},
		{
			"[Unit] Constraints: Prefix Not Allowed",
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
// Unit Tests: DurationValidator
// =============================================================================

func TestU_DurationValidator_Validate(t *testing.T) {
	validator := &DurationValidator{}

	tests := []struct {
		name    string
		value   interface{}
		wantErr bool
	}{
		// Valid durations (Go format)
		{"[Unit] Validate: Duration Hours", "24h", false},
		{"[Unit] Validate: Duration Minutes", "30m", false},
		{"[Unit] Validate: Duration Seconds", "60s", false},
		{"[Unit] Validate: Duration Combined", "1h30m", false},

		// Valid durations (extended format)
		{"[Unit] Validate: Duration Days", "365d", false},
		{"[Unit] Validate: Duration Weeks", "2w", false},
		{"[Unit] Validate: Duration Years", "1y", false},
		{"[Unit] Validate: Duration Combined Extended", "1y6m", false},
		{"[Unit] Validate: Duration Days And Hours", "30d12h", false},

		// Invalid durations
		{"[Unit] Validate: Duration Empty", "", true},
		{"[Unit] Validate: Duration Invalid Format", "abc", true},
		{"[Unit] Validate: Duration Not A String", 123, true},
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

func TestU_DurationValidator_MinMax(t *testing.T) {
	validator := &DurationValidator{}

	tests := []struct {
		name     string
		duration string
		variable *Variable
		wantErr  bool
	}{
		// Min constraint
		{
			"[Unit] MinMax: Above Min",
			"30d",
			&Variable{MinDuration: "7d"},
			false,
		},
		{
			"[Unit] MinMax: Below Min Invalid",
			"1d",
			&Variable{MinDuration: "7d"},
			true,
		},

		// Max constraint
		{
			"[Unit] MinMax: Below Max",
			"365d",
			&Variable{MaxDuration: "825d"},
			false,
		},
		{
			"[Unit] MinMax: Above Max Invalid",
			"1000d",
			&Variable{MaxDuration: "825d"},
			true,
		},

		// Both constraints
		{
			"[Unit] MinMax: Within Range",
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

func TestU_ParseDuration_AllFormats(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected time.Duration
		wantErr  bool
	}{
		// Standard Go durations
		{"[Unit] ParseDuration: Hours", "1h", time.Hour, false},
		{"[Unit] ParseDuration: Minutes", "30m", 30 * time.Minute, false},
		{"[Unit] ParseDuration: Seconds", "60s", 60 * time.Second, false},
		{"[Unit] ParseDuration: Combined", "1h30m", time.Hour + 30*time.Minute, false},

		// Extended format
		{"[Unit] ParseDuration: Day", "1d", 24 * time.Hour, false},
		{"[Unit] ParseDuration: Week", "7d", 7 * 24 * time.Hour, false},
		{"[Unit] ParseDuration: One Week", "1w", 7 * 24 * time.Hour, false},
		{"[Unit] ParseDuration: Two Weeks", "2w", 14 * 24 * time.Hour, false},
		{"[Unit] ParseDuration: Year", "1y", 365 * 24 * time.Hour, false},
		{"[Unit] ParseDuration: 365 Days", "365d", 365 * 24 * time.Hour, false},

		// Combined
		{"[Unit] ParseDuration: Day And Hours", "1d12h", 36 * time.Hour, false},
		{"[Unit] ParseDuration: Week And Day", "1w1d", 8 * 24 * time.Hour, false},
		{"[Unit] ParseDuration: Year And Day", "1y1d", 366 * 24 * time.Hour, false},

		// Invalid
		{"[Unit] ParseDuration: Empty Invalid", "", 0, true},
		{"[Unit] ParseDuration: Abc Invalid", "abc", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
// Unit Tests: Type Registry
// =============================================================================

func TestU_TypeRegistry_BuiltinTypes(t *testing.T) {
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

func TestU_ListTypeValidators_ReturnsAll(t *testing.T) {
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
// Functional Tests: VariableValidator Integration
// =============================================================================

func TestF_VariableValidator_Email(t *testing.T) {
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
		{"[Functional] Email: Valid Example Domain", "user@example.com", false},
		{"[Functional] Email: Valid Acme Domain", "user@acme.com", false},
		{"[Functional] Email: Domain Not Allowed", "user@other.com", true},
		{"[Functional] Email: Format Invalid", "not-an-email", true},
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

func TestF_VariableValidator_URI(t *testing.T) {
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
		{"[Functional] URI: Valid HTTP", "http://ocsp.example.com", false},
		{"[Functional] URI: Valid HTTPS", "https://ocsp2.example.com", false},
		{"[Functional] URI: Scheme Not Allowed", "ftp://ocsp.example.com", true},
		{"[Functional] URI: Host Not Allowed", "http://other.com", true},
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

func TestF_VariableValidator_OID(t *testing.T) {
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
		{"[Functional] OID: Valid", "1.3.6.1.4.1.99999.1", false},
		{"[Functional] OID: Valid NIST", "2.16.840.1.101.3.4.3.17", false},
		{"[Functional] OID: Format Invalid", "not.an.oid.a", true},
		{"[Functional] OID: Single Number Invalid", "1", true},
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

func TestF_VariableValidator_Duration(t *testing.T) {
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
		{"[Functional] Duration: Valid 365d", "365d", false},
		{"[Functional] Duration: Valid 1y", "1y", false},
		{"[Functional] Duration: Valid 2w", "2w", false},
		{"[Functional] Duration: Below Min Invalid", "12h", true},
		{"[Functional] Duration: Above Max Invalid", "3y", true},
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
// Benchmarks (no naming convention changes needed)
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
