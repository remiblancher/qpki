package profile

import (
	"testing"
)

func TestU_Profile_VariableValidator_String(t *testing.T) {
	vars := map[string]*Variable{
		"cn": {
			Name:     "cn",
			Type:     VarTypeString,
			Required: true,
			Pattern:  `^[a-zA-Z0-9][a-zA-Z0-9.-]+$`,
		},
		"country": {
			Name:      "country",
			Type:      VarTypeString,
			Required:  false,
			Default:   "FR",
			Pattern:   `^[A-Z]{2}$`,
			MinLength: 2,
			MaxLength: 2,
		},
		"env": {
			Name:    "env",
			Type:    VarTypeString,
			Default: "production",
			Enum:    []string{"dev", "staging", "production"},
		},
	}

	v, err := NewVariableValidator(vars)
	if err != nil {
		t.Fatalf("NewVariableValidator failed: %v", err)
	}

	tests := []struct {
		name    string
		varName string
		value   interface{}
		wantErr bool
	}{
		{"valid cn", "cn", "api.example.com", false},
		{"invalid cn pattern", "cn", "-invalid", true},
		{"valid country", "country", "US", false},
		{"invalid country pattern", "country", "USA", true},
		{"invalid country length", "country", "U", true},
		{"valid env", "env", "staging", false},
		{"invalid env enum", "env", "invalid", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(tt.varName, tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestU_Profile_VariableValidator_Integer(t *testing.T) {
	min := 1
	max := 825

	vars := map[string]*Variable{
		"validity_days": {
			Name:     "validity_days",
			Type:     VarTypeInteger,
			Required: false,
			Default:  365,
			Min:      &min,
			Max:      &max,
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
		{"valid 365", 365, false},
		{"valid 1", 1, false},
		{"valid 825", 825, false},
		{"below min", 0, true},
		{"above max", 1000, true},
		{"float64", float64(100), false}, // JSON/YAML decode as float64
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate("validity_days", tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestU_Profile_VariableValidator_List(t *testing.T) {
	vars := map[string]*Variable{
		"dns_names": {
			Name:     "dns_names",
			Type:     VarTypeList,
			Required: false,
			Default:  []string{},
			Constraints: &ListConstraints{
				AllowedSuffixes: []string{".example.com", ".internal"},
				DeniedPrefixes:  []string{"test-"},
				MaxItems:        5,
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
		{"valid single", []string{"api.example.com"}, false},
		{"valid multiple", []string{"api.example.com", "db.internal"}, false},
		{"invalid suffix", []string{"api.other.com"}, true},
		{"denied prefix", []string{"test-api.example.com"}, true},
		{"too many items", []string{"a.example.com", "b.example.com", "c.example.com", "d.example.com", "e.example.com", "f.example.com"}, true},
		{"empty list", []string{}, false},
		{"interface list", []interface{}{"api.example.com"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate("dns_names", tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestU_Profile_VariableValidator_IPList(t *testing.T) {
	vars := map[string]*Variable{
		"ip_addresses": {
			Name:     "ip_addresses",
			Type:     VarTypeIPList,
			Required: false,
			Constraints: &ListConstraints{
				AllowedRanges: []string{"10.0.0.0/8", "192.168.0.0/16"},
				MaxItems:      3,
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
		{"valid 10.x", []string{"10.0.0.1"}, false},
		{"valid 192.168.x", []string{"192.168.1.1"}, false},
		{"valid multiple", []string{"10.0.0.1", "192.168.1.1"}, false},
		{"outside range", []string{"8.8.8.8"}, true},
		{"invalid IP", []string{"not-an-ip"}, true},
		{"too many IPs", []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"}, true},
		{"empty list", []string{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate("ip_addresses", tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestU_Profile_VariableValidator_ValidateAll(t *testing.T) {
	vars := map[string]*Variable{
		"cn": {
			Name:     "cn",
			Type:     VarTypeString,
			Required: true,
		},
		"org": {
			Name:    "org",
			Type:    VarTypeString,
			Default: "ACME Corp",
		},
	}

	v, err := NewVariableValidator(vars)
	if err != nil {
		t.Fatalf("NewVariableValidator failed: %v", err)
	}

	tests := []struct {
		name    string
		values  VariableValues
		wantErr bool
	}{
		{
			"all provided",
			VariableValues{"cn": "test.example.com", "org": "Test Inc"},
			false,
		},
		{
			"required only",
			VariableValues{"cn": "test.example.com"},
			false,
		},
		{
			"missing required",
			VariableValues{"org": "Test Inc"},
			true,
		},
		{
			"empty",
			VariableValues{},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.ValidateAll(tt.values)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateAll() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestU_Profile_VariableValidator_MergeWithDefaults(t *testing.T) {
	vars := map[string]*Variable{
		"cn": {
			Name:     "cn",
			Type:     VarTypeString,
			Required: true,
		},
		"org": {
			Name:    "org",
			Type:    VarTypeString,
			Default: "ACME Corp",
		},
		"country": {
			Name:    "country",
			Type:    VarTypeString,
			Default: "FR",
		},
	}

	v, err := NewVariableValidator(vars)
	if err != nil {
		t.Fatalf("NewVariableValidator failed: %v", err)
	}

	userValues := VariableValues{
		"cn":  "test.example.com",
		"org": "Custom Org",
	}

	merged := v.MergeWithDefaults(userValues)

	// Check user value preserved
	if cn, ok := merged.GetString("cn"); !ok || cn != "test.example.com" {
		t.Errorf("cn = %q, want %q", cn, "test.example.com")
	}

	// Check user override
	if org, ok := merged.GetString("org"); !ok || org != "Custom Org" {
		t.Errorf("org = %q, want %q", org, "Custom Org")
	}

	// Check default used
	if country, ok := merged.GetString("country"); !ok || country != "FR" {
		t.Errorf("country = %q, want %q", country, "FR")
	}
}

func TestU_Profile_ParseVarFlags(t *testing.T) {
	tests := []struct {
		name    string
		flags   []string
		want    VariableValues
		wantErr bool
	}{
		{
			"single value",
			[]string{"cn=api.example.com"},
			VariableValues{"cn": "api.example.com"},
			false,
		},
		{
			"list value",
			[]string{"dns_names=a.example.com,b.example.com"},
			VariableValues{"dns_names": []string{"a.example.com", "b.example.com"}},
			false,
		},
		{
			"multiple flags",
			[]string{"cn=api.example.com", "env=production"},
			VariableValues{"cn": "api.example.com", "env": "production"},
			false,
		},
		{
			"invalid format",
			[]string{"invalid"},
			nil,
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseVarFlags(tt.flags)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseVarFlags() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			for key, wantVal := range tt.want {
				gotVal, ok := got[key]
				if !ok {
					t.Errorf("missing key %q", key)
					continue
				}

				switch w := wantVal.(type) {
				case string:
					if g, ok := gotVal.(string); !ok || g != w {
						t.Errorf("got[%q] = %v, want %v", key, gotVal, wantVal)
					}
				case []string:
					if g, ok := gotVal.([]string); !ok || len(g) != len(w) {
						t.Errorf("got[%q] = %v, want %v", key, gotVal, wantVal)
					}
				}
			}
		})
	}
}

func TestU_Profile_TemplateEngine_SubstituteString(t *testing.T) {
	profile := &Profile{
		Name:      "test",
		Algorithm: "ecdsa-p256",
		Variables: map[string]*Variable{
			"cn": {
				Name:     "cn",
				Type:     VarTypeString,
				Required: true,
			},
			"days": {
				Name:    "days",
				Type:    VarTypeInteger,
				Default: 365,
			},
		},
	}

	engine, err := NewTemplateEngine(profile)
	if err != nil {
		t.Fatalf("NewTemplateEngine failed: %v", err)
	}

	values := VariableValues{
		"cn":   "api.example.com",
		"days": 730,
	}

	tests := []struct {
		name     string
		template string
		want     string
		wantErr  bool
	}{
		{"simple", "{{ cn }}", "api.example.com", false},
		{"with spaces", "{{  cn  }}", "api.example.com", false},
		{"integer", "{{ days }}", "730", false},
		{"mixed", "CN={{ cn }}, days={{ days }}", "CN=api.example.com, days=730", false},
		{"missing var", "{{ unknown }}", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := engine.SubstituteString(tt.template, values)
			if (err != nil) != tt.wantErr {
				t.Errorf("SubstituteString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("SubstituteString() = %q, want %q", got, tt.want)
			}
		})
	}
}

// DNS Validation Tests (RFC 1035/1123)

func TestU_Profile_ValidateDNSName(t *testing.T) {
	tests := []struct {
		name    string
		dns     string
		wantErr bool
	}{
		// Valid DNS names
		{"valid simple", "example.com", false},
		{"valid subdomain", "api.example.com", false},
		{"valid deep subdomain", "api.v2.example.com", false},
		{"valid with numbers", "api123.example.com", false},
		{"valid with hyphens", "my-api.example.com", false},
		{"valid wildcard", "*.example.com", false},
		{"valid uppercase", "API.Example.COM", false},       // Normalized to lowercase
		{"valid trailing dot", "example.com.", false},       // Trailing dot stripped (FQDN)
		{"valid uppercase trailing", "Example.COM.", false}, // Both normalized

		// Invalid DNS names
		{"empty", "", true},
		{"single label", "localhost", true},
		{"double dot", "example..com", true},
		{"leading dot", ".example.com", true},
		{"leading hyphen", "-example.com", true},
		{"trailing hyphen", "example-.com", true},
		{"invalid char @", "ex@mple.com", true},
		{"invalid char space", "exa mple.com", true},
		{"invalid char underscore", "ex_ample.com", true},
		{"label too long", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com", true}, // 66 chars
		{"wildcard not leftmost", "api.*.example.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDNSName(tt.dns)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateDNSName(%q) error = %v, wantErr %v", tt.dns, err, tt.wantErr)
			}
		})
	}
}

func TestU_Profile_NormalizeDNSName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"example.com", "example.com"},
		{"Example.COM", "example.com"},
		{"API.Example.Com", "api.example.com"},
		{"example.com.", "example.com"},
		{"Example.COM.", "example.com"},
		{"*.EXAMPLE.COM", "*.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := NormalizeDNSName(tt.input)
			if got != tt.expected {
				t.Errorf("NormalizeDNSName(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestU_Profile_ValidateDNSNameWithOptions(t *testing.T) {
	tests := []struct {
		name             string
		dns              string
		allowSingleLabel bool
		wantErr          bool
	}{
		// Standard (2+ labels required)
		{"valid 2 labels", "example.com", false, false},
		{"invalid single label", "localhost", false, true},

		// With single label allowed
		{"single label allowed", "localhost", true, false},
		{"single label db-master", "db-master", true, false},
		{"single label with numbers", "server1", true, false},
		{"still valid with multi labels", "example.com", true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDNSNameWithOptions(tt.dns, tt.allowSingleLabel)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateDNSNameWithOptions(%q, %v) error = %v, wantErr %v",
					tt.dns, tt.allowSingleLabel, err, tt.wantErr)
			}
		})
	}
}

func TestU_Profile_ValidateWildcard(t *testing.T) {
	allowWildcard := &WildcardPolicy{Allowed: true, SingleLabel: true}
	denyWildcard := &WildcardPolicy{Allowed: false}

	tests := []struct {
		name    string
		dns     string
		policy  *WildcardPolicy
		wantErr bool
	}{
		// Non-wildcard names (always valid regardless of policy)
		{"non-wildcard with allow", "api.example.com", allowWildcard, false},
		{"non-wildcard with deny", "api.example.com", denyWildcard, false},
		{"non-wildcard with nil", "api.example.com", nil, false},

		// Valid wildcards (when allowed)
		{"valid wildcard", "*.example.com", allowWildcard, false},
		{"valid wildcard deep", "*.api.example.com", allowWildcard, false},

		// Invalid wildcards
		{"wildcard with nil policy", "*.example.com", nil, true},
		{"wildcard denied", "*.example.com", denyWildcard, true},
		{"wildcard not leftmost", "api.*.example.com", allowWildcard, true},
		{"double wildcard", "*.*.example.com", allowWildcard, true},
		{"wildcard too short", "*.com", allowWildcard, true},
		{"single wildcard", "*", allowWildcard, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateWildcard(tt.dns, tt.policy)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateWildcard(%q, %+v) error = %v, wantErr %v", tt.dns, tt.policy, err, tt.wantErr)
			}
		})
	}
}

func TestU_Profile_VariableValidator_DNSName(t *testing.T) {
	vars := map[string]*Variable{
		"cn_no_wildcard": {
			Name:     "cn_no_wildcard",
			Type:     VarTypeDNSName,
			Required: true,
			Wildcard: nil, // No wildcards allowed (default)
		},
		"cn_with_wildcard": {
			Name:     "cn_with_wildcard",
			Type:     VarTypeDNSName,
			Required: true,
			Wildcard: &WildcardPolicy{Allowed: true, SingleLabel: true},
		},
	}

	v, err := NewVariableValidator(vars)
	if err != nil {
		t.Fatalf("NewVariableValidator failed: %v", err)
	}

	tests := []struct {
		name    string
		varName string
		value   interface{}
		wantErr bool
	}{
		// Valid DNS names (no wildcard)
		{"valid dns", "cn_no_wildcard", "api.example.com", false},
		{"valid dns subdomain", "cn_no_wildcard", "api.v2.example.com", false},

		// Invalid DNS names (no wildcard)
		{"wildcard when not allowed", "cn_no_wildcard", "*.example.com", true},
		{"invalid dns", "cn_no_wildcard", "example..com", true},
		{"single label", "cn_no_wildcard", "localhost", true},

		// Valid with wildcard allowed
		{"wildcard allowed", "cn_with_wildcard", "*.example.com", false},
		{"non-wildcard when allowed", "cn_with_wildcard", "api.example.com", false},

		// Invalid with wildcard allowed
		{"double wildcard", "cn_with_wildcard", "*.*.example.com", true},
		{"short wildcard", "cn_with_wildcard", "*.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(tt.varName, tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate(%q, %q) error = %v, wantErr %v", tt.varName, tt.value, err, tt.wantErr)
			}
		})
	}
}

func TestU_Profile_VariableValidator_DNSNames(t *testing.T) {
	vars := map[string]*Variable{
		"sans": {
			Name:     "sans",
			Type:     VarTypeDNSNames,
			Required: false,
			Wildcard: nil, // No wildcards in SANs
			Constraints: &ListConstraints{
				AllowedSuffixes: []string{".example.com"},
				MaxItems:        5,
			},
		},
		"sans_wildcard": {
			Name:     "sans_wildcard",
			Type:     VarTypeDNSNames,
			Required: false,
			Wildcard: &WildcardPolicy{Allowed: true, SingleLabel: true},
		},
	}

	v, err := NewVariableValidator(vars)
	if err != nil {
		t.Fatalf("NewVariableValidator failed: %v", err)
	}

	tests := []struct {
		name    string
		varName string
		value   interface{}
		wantErr bool
	}{
		// Valid DNS names list
		{"valid single", "sans", []string{"api.example.com"}, false},
		{"valid multiple", "sans", []string{"api.example.com", "db.example.com"}, false},
		{"empty list", "sans", []string{}, false},

		// Invalid (wrong suffix)
		{"wrong suffix", "sans", []string{"api.other.com"}, true},

		// Invalid (wildcard not allowed)
		{"wildcard not allowed", "sans", []string{"*.example.com"}, true},

		// Too many items
		{"too many items", "sans", []string{"a.example.com", "b.example.com", "c.example.com", "d.example.com", "e.example.com", "f.example.com"}, true},

		// Invalid DNS format
		{"invalid dns", "sans", []string{"api..example.com"}, true},

		// Wildcard allowed
		{"wildcard allowed", "sans_wildcard", []string{"*.example.com", "api.test.com"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(tt.varName, tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate(%q, %v) error = %v, wantErr %v", tt.varName, tt.value, err, tt.wantErr)
			}
		})
	}
}

// Test label boundary suffix matching (security fix)
func TestU_Profile_MatchesSuffixOnLabelBoundary(t *testing.T) {
	tests := []struct {
		dnsName string
		suffix  string
		want    bool
	}{
		// Valid matches with leading dot
		{"api.example.com", ".example.com", true},
		{"db.example.com", ".example.com", true},
		{"api.v2.example.com", ".example.com", true},
		{"example.com", ".example.com", true}, // Exact match

		// Security: Should NOT match without label boundary
		{"fakeexample.com", ".example.com", false},
		{"notexample.com", ".example.com", false},

		// Case insensitive
		{"API.Example.COM", ".example.com", true},
		{"api.EXAMPLE.com", ".EXAMPLE.COM", true},

		// Without leading dot (should work on boundary too)
		{"api.example.com", "example.com", true},
		{"example.com", "example.com", true},
		{"fakeexample.com", "example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.dnsName+"_"+tt.suffix, func(t *testing.T) {
			got := matchesSuffixOnLabelBoundary(tt.dnsName, tt.suffix)
			if got != tt.want {
				t.Errorf("matchesSuffixOnLabelBoundary(%q, %q) = %v, want %v",
					tt.dnsName, tt.suffix, got, tt.want)
			}
		})
	}
}

// Test AllowSingleLabel option in validator
func TestU_Profile_VariableValidator_DNSName_SingleLabel(t *testing.T) {
	vars := map[string]*Variable{
		"cn_single": {
			Name:             "cn_single",
			Type:             VarTypeDNSName,
			Required:         true,
			AllowSingleLabel: true, // Allow localhost, db-master, etc.
		},
		"cn_multi": {
			Name:             "cn_multi",
			Type:             VarTypeDNSName,
			Required:         true,
			AllowSingleLabel: false, // Require 2+ labels
		},
	}

	v, err := NewVariableValidator(vars)
	if err != nil {
		t.Fatalf("NewVariableValidator failed: %v", err)
	}

	tests := []struct {
		name    string
		varName string
		value   string
		wantErr bool
	}{
		// Single label allowed
		{"localhost allowed", "cn_single", "localhost", false},
		{"db-master allowed", "cn_single", "db-master", false},
		{"multi-label also ok", "cn_single", "api.example.com", false},

		// Single label not allowed
		{"localhost denied", "cn_multi", "localhost", true},
		{"db-master denied", "cn_multi", "db-master", true},
		{"multi-label required", "cn_multi", "api.example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(tt.varName, tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate(%q, %q) error = %v, wantErr %v", tt.varName, tt.value, err, tt.wantErr)
			}
		})
	}
}

// Test ForbidPublicSuffix option
func TestU_Profile_ValidateWildcard_ForbidPublicSuffix(t *testing.T) {
	allowNoCheck := &WildcardPolicy{Allowed: true, ForbidPublicSuffix: false}
	allowWithCheck := &WildcardPolicy{Allowed: true, ForbidPublicSuffix: true}

	tests := []struct {
		name    string
		dns     string
		policy  *WildcardPolicy
		wantErr bool
	}{
		// Without PSL check - all valid wildcards pass
		{"valid wildcard no check", "*.example.com", allowNoCheck, false},
		{"psl wildcard no check", "*.co.uk", allowNoCheck, false}, // Would be blocked with check

		// With PSL check
		{"valid wildcard with check", "*.example.com", allowWithCheck, false},
		{"valid deep wildcard", "*.api.example.com", allowWithCheck, false},

		// Public suffixes should be blocked
		{"block co.uk", "*.co.uk", allowWithCheck, true},
		{"block com.au", "*.com.au", allowWithCheck, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateWildcard(tt.dns, tt.policy)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateWildcard(%q, %+v) error = %v, wantErr %v",
					tt.dns, tt.policy, err, tt.wantErr)
			}
		})
	}
}

// =============================================================================
// Unit Tests: Variable Methods
// =============================================================================

func TestU_DefaultWildcardPolicy(t *testing.T) {
	policy := DefaultWildcardPolicy()

	if policy == nil {
		t.Fatal("DefaultWildcardPolicy() returned nil")
	}

	if policy.Allowed {
		t.Error("Default policy should not allow wildcards")
	}

	if !policy.SingleLabel {
		t.Error("Default policy should enforce single label (RFC 6125)")
	}

	if policy.ForbidPublicSuffix {
		t.Error("Default policy should not forbid public suffix by default")
	}
}

func TestU_Variable_GetDefaultString_NotString(t *testing.T) {
	v := &Variable{
		Name:    "test",
		Type:    VarTypeString,
		Default: 123, // Wrong type
	}

	result := v.GetDefaultString()
	if result != "" {
		t.Errorf("GetDefaultString() = %q, want empty string for non-string default", result)
	}
}

func TestU_Variable_GetDefaultString_Nil(t *testing.T) {
	v := &Variable{
		Name: "test",
		Type: VarTypeString,
		// No default
	}

	result := v.GetDefaultString()
	if result != "" {
		t.Errorf("GetDefaultString() = %q, want empty string for nil default", result)
	}
}

func TestU_Variable_GetDefaultInt_Int(t *testing.T) {
	v := &Variable{
		Name:    "test",
		Type:    VarTypeInteger,
		Default: 42,
	}

	result := v.GetDefaultInt()
	if result != 42 {
		t.Errorf("GetDefaultInt() = %d, want 42", result)
	}
}

func TestU_Variable_GetDefaultInt_Float64(t *testing.T) {
	v := &Variable{
		Name:    "test",
		Type:    VarTypeInteger,
		Default: float64(123.0), // YAML/JSON decodes as float64
	}

	result := v.GetDefaultInt()
	if result != 123 {
		t.Errorf("GetDefaultInt() = %d, want 123", result)
	}
}

func TestU_Variable_GetDefaultInt_NotNumeric(t *testing.T) {
	v := &Variable{
		Name:    "test",
		Type:    VarTypeInteger,
		Default: "not a number",
	}

	result := v.GetDefaultInt()
	if result != 0 {
		t.Errorf("GetDefaultInt() = %d, want 0 for non-numeric default", result)
	}
}

func TestU_Variable_GetDefaultBool_True(t *testing.T) {
	v := &Variable{
		Name:    "test",
		Type:    VarTypeBoolean,
		Default: true,
	}

	result := v.GetDefaultBool()
	if result != true {
		t.Errorf("GetDefaultBool() = %v, want true", result)
	}
}

func TestU_Variable_GetDefaultBool_NotBool(t *testing.T) {
	v := &Variable{
		Name:    "test",
		Type:    VarTypeBoolean,
		Default: "true", // String, not bool
	}

	result := v.GetDefaultBool()
	if result != false {
		t.Errorf("GetDefaultBool() = %v, want false for non-bool default", result)
	}
}

func TestU_Variable_GetDefaultStringList_StringSlice(t *testing.T) {
	v := &Variable{
		Name:    "test",
		Type:    VarTypeList,
		Default: []string{"a", "b", "c"},
	}

	result := v.GetDefaultStringList()
	if len(result) != 3 || result[0] != "a" || result[1] != "b" || result[2] != "c" {
		t.Errorf("GetDefaultStringList() = %v, want [a b c]", result)
	}
}

func TestU_Variable_GetDefaultStringList_InterfaceSlice(t *testing.T) {
	v := &Variable{
		Name:    "test",
		Type:    VarTypeList,
		Default: []interface{}{"x", "y", "z"},
	}

	result := v.GetDefaultStringList()
	if len(result) != 3 || result[0] != "x" || result[1] != "y" || result[2] != "z" {
		t.Errorf("GetDefaultStringList() = %v, want [x y z]", result)
	}
}

func TestU_Variable_GetDefaultStringList_InterfaceSliceMixed(t *testing.T) {
	v := &Variable{
		Name:    "test",
		Type:    VarTypeList,
		Default: []interface{}{"string", 123, "another"}, // Mixed types
	}

	result := v.GetDefaultStringList()
	// Should only include strings
	if len(result) != 2 || result[0] != "string" || result[1] != "another" {
		t.Errorf("GetDefaultStringList() = %v, want [string another]", result)
	}
}

func TestU_Variable_GetDefaultStringList_WrongType(t *testing.T) {
	v := &Variable{
		Name:    "test",
		Type:    VarTypeList,
		Default: "single string", // Not a slice
	}

	result := v.GetDefaultStringList()
	if result != nil {
		t.Errorf("GetDefaultStringList() = %v, want nil for non-slice default", result)
	}
}

func TestU_Variable_GetDefaultStringList_Nil(t *testing.T) {
	v := &Variable{
		Name: "test",
		Type: VarTypeList,
		// No default - nil
	}

	result := v.GetDefaultStringList()
	if result != nil {
		t.Errorf("GetDefaultStringList() = %v, want nil for nil default", result)
	}
}

// =============================================================================
// Unit Tests: VariableValues Methods
// =============================================================================

func TestU_VariableValues_GetInt_Int(t *testing.T) {
	vv := VariableValues{"count": 42}

	result, ok := vv.GetInt("count")
	if !ok {
		t.Error("GetInt() returned false for int value")
	}
	if result != 42 {
		t.Errorf("GetInt() = %d, want 42", result)
	}
}

func TestU_VariableValues_GetInt_Float64(t *testing.T) {
	vv := VariableValues{"count": float64(99.0)}

	result, ok := vv.GetInt("count")
	if !ok {
		t.Error("GetInt() returned false for float64 value")
	}
	if result != 99 {
		t.Errorf("GetInt() = %d, want 99", result)
	}
}

func TestU_VariableValues_GetInt_NotNumeric(t *testing.T) {
	vv := VariableValues{"count": "not a number"}

	result, ok := vv.GetInt("count")
	if ok {
		t.Error("GetInt() returned true for non-numeric value")
	}
	if result != 0 {
		t.Errorf("GetInt() = %d, want 0 for non-numeric", result)
	}
}

func TestU_VariableValues_GetInt_NotFound(t *testing.T) {
	vv := VariableValues{}

	result, ok := vv.GetInt("nonexistent")
	if ok {
		t.Error("GetInt() returned true for nonexistent key")
	}
	if result != 0 {
		t.Errorf("GetInt() = %d, want 0 for nonexistent", result)
	}
}

func TestU_VariableValues_GetBool_True(t *testing.T) {
	vv := VariableValues{"flag": true}

	result, ok := vv.GetBool("flag")
	if !ok {
		t.Error("GetBool() returned false for bool value")
	}
	if result != true {
		t.Errorf("GetBool() = %v, want true", result)
	}
}

func TestU_VariableValues_GetBool_NotFound(t *testing.T) {
	vv := VariableValues{}

	result, ok := vv.GetBool("nonexistent")
	if ok {
		t.Error("GetBool() returned true for nonexistent key")
	}
	if result != false {
		t.Errorf("GetBool() = %v, want false for nonexistent", result)
	}
}

func TestU_VariableValues_GetBool_NotBool(t *testing.T) {
	vv := VariableValues{"flag": "true"} // String, not bool

	result, ok := vv.GetBool("flag")
	if ok {
		t.Error("GetBool() returned true for non-bool value")
	}
	if result != false {
		t.Errorf("GetBool() = %v, want false for non-bool", result)
	}
}

func TestU_VariableValues_GetStringList_StringSlice(t *testing.T) {
	vv := VariableValues{"names": []string{"alice", "bob"}}

	result, ok := vv.GetStringList("names")
	if !ok {
		t.Error("GetStringList() returned false for []string value")
	}
	if len(result) != 2 || result[0] != "alice" || result[1] != "bob" {
		t.Errorf("GetStringList() = %v, want [alice bob]", result)
	}
}

func TestU_VariableValues_GetStringList_InterfaceSlice(t *testing.T) {
	vv := VariableValues{"names": []interface{}{"one", "two", "three"}}

	result, ok := vv.GetStringList("names")
	if !ok {
		t.Error("GetStringList() returned false for []interface{} value")
	}
	if len(result) != 3 {
		t.Errorf("GetStringList() = %v, want 3 items", result)
	}
}

func TestU_VariableValues_GetStringList_SingleEmptyString(t *testing.T) {
	vv := VariableValues{"names": ""}

	result, ok := vv.GetStringList("names")
	if ok {
		t.Error("GetStringList() should return false for empty string")
	}
	if result != nil {
		t.Errorf("GetStringList() = %v, want nil for empty string", result)
	}
}

func TestU_VariableValues_GetStringList_NotList(t *testing.T) {
	vv := VariableValues{"names": 123}

	result, ok := vv.GetStringList("names")
	if ok {
		t.Error("GetStringList() returned true for non-list value")
	}
	if result != nil {
		t.Errorf("GetStringList() = %v, want nil for non-list", result)
	}
}

func TestU_VariableValues_SetInt(t *testing.T) {
	vv := make(VariableValues)
	vv.SetInt("count", 42)

	result, ok := vv.GetInt("count")
	if !ok || result != 42 {
		t.Errorf("SetInt/GetInt roundtrip failed: got %d, ok=%v", result, ok)
	}
}

func TestU_VariableValues_SetBool(t *testing.T) {
	vv := make(VariableValues)
	vv.SetBool("enabled", true)

	result, ok := vv.GetBool("enabled")
	if !ok || result != true {
		t.Errorf("SetBool/GetBool roundtrip failed: got %v, ok=%v", result, ok)
	}
}

func TestU_VariableValues_SetStringList(t *testing.T) {
	vv := make(VariableValues)
	vv.SetStringList("names", []string{"a", "b", "c"})

	result, ok := vv.GetStringList("names")
	if !ok || len(result) != 3 {
		t.Errorf("SetStringList/GetStringList roundtrip failed: got %v, ok=%v", result, ok)
	}
}

// =============================================================================
// Benchmarks
// =============================================================================

func BenchmarkVariableValidator_Validate(b *testing.B) {
	vars := map[string]*Variable{
		"cn": {
			Name:     "cn",
			Type:     VarTypeString,
			Required: true,
			Pattern:  `^[a-zA-Z0-9][a-zA-Z0-9.-]+$`,
		},
	}

	v, _ := NewVariableValidator(vars)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = v.Validate("cn", "api.example.com")
	}
}

func BenchmarkVariableValidator_ValidateList(b *testing.B) {
	vars := map[string]*Variable{
		"dns_names": {
			Name: "dns_names",
			Type: VarTypeList,
			Constraints: &ListConstraints{
				AllowedSuffixes: []string{".example.com", ".internal"},
				MaxItems:        10,
			},
		},
	}

	v, _ := NewVariableValidator(vars)
	list := []string{"api.example.com", "db.example.com", "cache.internal"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = v.Validate("dns_names", list)
	}
}

func BenchmarkParseVarFlags(b *testing.B) {
	flags := []string{
		"cn=api.example.com",
		"dns_names=a.example.com,b.example.com,c.example.com",
		"env=production",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseVarFlags(flags)
	}
}
