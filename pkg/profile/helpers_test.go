package profile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestU_Profile_LoadVariables(t *testing.T) {
	t.Run("empty inputs", func(t *testing.T) {
		values, err := LoadVariables("", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(values) != 0 {
			t.Errorf("expected empty map, got %v", values)
		}
	})

	t.Run("flags only", func(t *testing.T) {
		flags := []string{"cn=example.com", "dns_names=a.com,b.com"}
		values, err := LoadVariables("", flags)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if cn, ok := values.GetString("cn"); !ok || cn != "example.com" {
			t.Errorf("expected cn=example.com, got %v", values["cn"])
		}

		dns, ok := values.GetStringList("dns_names")
		if !ok || len(dns) != 2 {
			t.Errorf("expected dns_names list with 2 items, got %v", values["dns_names"])
		}
	})

	t.Run("file only", func(t *testing.T) {
		// Create temp file
		tmpDir := t.TempDir()
		varFile := filepath.Join(tmpDir, "vars.yaml")
		content := `
cn: test.example.com
organization: Test Org
dns_names:
  - test.example.com
  - www.test.example.com
`
		if err := os.WriteFile(varFile, []byte(content), 0644); err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}

		values, err := LoadVariables(varFile, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if cn, ok := values.GetString("cn"); !ok || cn != "test.example.com" {
			t.Errorf("expected cn=test.example.com, got %v", values["cn"])
		}

		if o, ok := values.GetString("organization"); !ok || o != "Test Org" {
			t.Errorf("expected organization=Test Org, got %v", values["organization"])
		}
	})

	t.Run("flags override file", func(t *testing.T) {
		// Create temp file
		tmpDir := t.TempDir()
		varFile := filepath.Join(tmpDir, "vars.yaml")
		content := `
cn: from-file.com
organization: File Org
`
		if err := os.WriteFile(varFile, []byte(content), 0644); err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}

		flags := []string{"cn=from-flag.com"}
		values, err := LoadVariables(varFile, flags)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Flag should override file
		if cn, ok := values.GetString("cn"); !ok || cn != "from-flag.com" {
			t.Errorf("expected cn=from-flag.com (from flag), got %v", values["cn"])
		}

		// File value should remain
		if o, ok := values.GetString("organization"); !ok || o != "File Org" {
			t.Errorf("expected organization=File Org (from file), got %v", values["organization"])
		}
	})

	t.Run("invalid file path", func(t *testing.T) {
		_, err := LoadVariables("/nonexistent/path/vars.yaml", nil)
		if err == nil {
			t.Error("expected error for nonexistent file")
		}
	})

	t.Run("invalid yaml", func(t *testing.T) {
		tmpDir := t.TempDir()
		varFile := filepath.Join(tmpDir, "invalid.yaml")
		if err := os.WriteFile(varFile, []byte("invalid: yaml: content: ["), 0644); err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}

		_, err := LoadVariables(varFile, nil)
		if err == nil {
			t.Error("expected error for invalid yaml")
		}
	})
}

func TestU_Profile_BuildSubject(t *testing.T) {
	t.Run("cn only", func(t *testing.T) {
		vars := VariableValues{"cn": "example.com"}
		subject, err := BuildSubject(vars)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if subject.CommonName != "example.com" {
			t.Errorf("expected CN=example.com, got %s", subject.CommonName)
		}
	})

	t.Run("full subject with short aliases", func(t *testing.T) {
		vars := VariableValues{
			"cn": "example.com",
			"o":  "Example Org",
			"ou": "IT",
			"c":  "US",
			"st": "California",
			"l":  "San Francisco",
		}
		subject, err := BuildSubject(vars)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if subject.CommonName != "example.com" {
			t.Errorf("expected CN=example.com, got %s", subject.CommonName)
		}
		if len(subject.Organization) != 1 || subject.Organization[0] != "Example Org" {
			t.Errorf("expected O=Example Org, got %v", subject.Organization)
		}
		if len(subject.OrganizationalUnit) != 1 || subject.OrganizationalUnit[0] != "IT" {
			t.Errorf("expected OU=IT, got %v", subject.OrganizationalUnit)
		}
		if len(subject.Country) != 1 || subject.Country[0] != "US" {
			t.Errorf("expected C=US, got %v", subject.Country)
		}
		if len(subject.Province) != 1 || subject.Province[0] != "California" {
			t.Errorf("expected ST=California, got %v", subject.Province)
		}
		if len(subject.Locality) != 1 || subject.Locality[0] != "San Francisco" {
			t.Errorf("expected L=San Francisco, got %v", subject.Locality)
		}
	})

	t.Run("full subject with long aliases", func(t *testing.T) {
		vars := VariableValues{
			"cn":           "example.com",
			"organization": "Example Org",
			"country":      "FR",
			"state":        "Île-de-France",
			"locality":     "Paris",
		}
		subject, err := BuildSubject(vars)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(subject.Organization) != 1 || subject.Organization[0] != "Example Org" {
			t.Errorf("expected organization=Example Org, got %v", subject.Organization)
		}
		if len(subject.Country) != 1 || subject.Country[0] != "FR" {
			t.Errorf("expected country=FR, got %v", subject.Country)
		}
	})

	t.Run("missing cn", func(t *testing.T) {
		vars := VariableValues{"o": "Example Org"}
		_, err := BuildSubject(vars)
		if err == nil {
			t.Error("expected error for missing CN")
		}
	})

	t.Run("empty vars", func(t *testing.T) {
		vars := VariableValues{}
		_, err := BuildSubject(vars)
		if err == nil {
			t.Error("expected error for empty vars")
		}
	})
}

func TestU_Profile_BuildSubjectFromProfile(t *testing.T) {
	t.Run("profile defaults used when vars missing", func(t *testing.T) {
		prof := &Profile{
			Subject: &SubjectConfig{
				Fixed: map[string]string{
					"c": "FR",
					"o": "Demo Organization",
				},
			},
		}
		vars := VariableValues{"cn": "Test CA"}

		subject, err := BuildSubjectFromProfile(prof, vars)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if subject.CommonName != "Test CA" {
			t.Errorf("expected CN=Test CA, got %s", subject.CommonName)
		}
		if len(subject.Organization) != 1 || subject.Organization[0] != "Demo Organization" {
			t.Errorf("expected O=Demo Organization, got %v", subject.Organization)
		}
		if len(subject.Country) != 1 || subject.Country[0] != "FR" {
			t.Errorf("expected C=FR, got %v", subject.Country)
		}
	})

	t.Run("vars override profile defaults", func(t *testing.T) {
		prof := &Profile{
			Subject: &SubjectConfig{
				Fixed: map[string]string{
					"c": "FR",
					"o": "Default Org",
				},
			},
		}
		vars := VariableValues{
			"cn": "Test CA",
			"o":  "Override Org",
		}

		subject, err := BuildSubjectFromProfile(prof, vars)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Var should override profile default
		if len(subject.Organization) != 1 || subject.Organization[0] != "Override Org" {
			t.Errorf("expected O=Override Org (override), got %v", subject.Organization)
		}
		// Profile default still used for C
		if len(subject.Country) != 1 || subject.Country[0] != "FR" {
			t.Errorf("expected C=FR (from profile), got %v", subject.Country)
		}
	})

	t.Run("nil profile works like BuildSubject", func(t *testing.T) {
		vars := VariableValues{
			"cn": "example.com",
			"o":  "Example Org",
		}

		subject, err := BuildSubjectFromProfile(nil, vars)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if subject.CommonName != "example.com" {
			t.Errorf("expected CN=example.com, got %s", subject.CommonName)
		}
		if len(subject.Organization) != 1 || subject.Organization[0] != "Example Org" {
			t.Errorf("expected O=Example Org, got %v", subject.Organization)
		}
	})

	t.Run("profile with nil subject works", func(t *testing.T) {
		prof := &Profile{Subject: nil}
		vars := VariableValues{"cn": "Test CA"}

		subject, err := BuildSubjectFromProfile(prof, vars)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if subject.CommonName != "Test CA" {
			t.Errorf("expected CN=Test CA, got %s", subject.CommonName)
		}
	})

	t.Run("all profile subject fields", func(t *testing.T) {
		prof := &Profile{
			Subject: &SubjectConfig{
				Fixed: map[string]string{
					"c":  "FR",
					"o":  "Demo Org",
					"ou": "IT Dept",
					"st": "Île-de-France",
					"l":  "Paris",
				},
			},
		}
		vars := VariableValues{"cn": "Full Subject CA"}

		subject, err := BuildSubjectFromProfile(prof, vars)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if subject.CommonName != "Full Subject CA" {
			t.Errorf("expected CN=Full Subject CA, got %s", subject.CommonName)
		}
		if len(subject.Organization) != 1 || subject.Organization[0] != "Demo Org" {
			t.Errorf("expected O=Demo Org, got %v", subject.Organization)
		}
		if len(subject.OrganizationalUnit) != 1 || subject.OrganizationalUnit[0] != "IT Dept" {
			t.Errorf("expected OU=IT Dept, got %v", subject.OrganizationalUnit)
		}
		if len(subject.Country) != 1 || subject.Country[0] != "FR" {
			t.Errorf("expected C=FR, got %v", subject.Country)
		}
		if len(subject.Province) != 1 || subject.Province[0] != "Île-de-France" {
			t.Errorf("expected ST=Île-de-France, got %v", subject.Province)
		}
		if len(subject.Locality) != 1 || subject.Locality[0] != "Paris" {
			t.Errorf("expected L=Paris, got %v", subject.Locality)
		}
	})
}

func TestU_Profile_ExtractTemplateVariables_SAN(t *testing.T) {
	t.Run("all SAN types", func(t *testing.T) {
		vars := VariableValues{
			"dns_names":    []string{"a.com", "b.com"},
			"ip_addresses": []string{"192.168.1.1", "10.0.0.1"},
			"email":        []string{"admin@example.com"},
		}

		result := ExtractTemplateVariables(vars)

		if len(result["dns_names"]) != 2 {
			t.Errorf("expected 2 dns_names, got %v", result["dns_names"])
		}
		if len(result["ip_addresses"]) != 2 {
			t.Errorf("expected 2 ip_addresses, got %v", result["ip_addresses"])
		}
		if len(result["email"]) != 1 {
			t.Errorf("expected 1 email, got %v", result["email"])
		}
	})

	t.Run("partial SANs", func(t *testing.T) {
		vars := VariableValues{
			"dns_names": []string{"example.com"},
			"cn":        "example.com", // Should be ignored
		}

		result := ExtractTemplateVariables(vars)

		if len(result["dns_names"]) != 1 {
			t.Errorf("expected 1 dns_names, got %v", result["dns_names"])
		}
		if _, exists := result["ip_addresses"]; exists {
			t.Error("ip_addresses should not be in result")
		}
		if _, exists := result["cn"]; exists {
			t.Error("cn should not be in result")
		}
	})

	t.Run("empty vars", func(t *testing.T) {
		vars := VariableValues{}
		result := ExtractTemplateVariables(vars)

		if len(result) != 0 {
			t.Errorf("expected empty result, got %v", result)
		}
	})
}

func TestU_Profile_ExtractAllTemplateVariables(t *testing.T) {
	t.Run("extracts all variables", func(t *testing.T) {
		vars := VariableValues{
			"dns":          "example.com",
			"custom_var":   "custom_value",
			"dns_names":    []string{"a.com", "b.com"},
			"ip_addresses": []interface{}{"192.168.1.1", "10.0.0.1"},
		}

		result := ExtractAllTemplateVariables(vars)

		if len(result["dns"]) != 1 || result["dns"][0] != "example.com" {
			t.Errorf("expected dns=[example.com], got %v", result["dns"])
		}
		if len(result["custom_var"]) != 1 || result["custom_var"][0] != "custom_value" {
			t.Errorf("expected custom_var=[custom_value], got %v", result["custom_var"])
		}
		if len(result["dns_names"]) != 2 {
			t.Errorf("expected 2 dns_names, got %v", result["dns_names"])
		}
		if len(result["ip_addresses"]) != 2 {
			t.Errorf("expected 2 ip_addresses, got %v", result["ip_addresses"])
		}
	})
}

func TestU_Profile_ResolveProfileExtensions_TemplateValidation(t *testing.T) {
	t.Run("required variable missing returns error", func(t *testing.T) {
		prof := &Profile{
			Name: "test",
			Variables: map[string]*Variable{
				"dns_names": {
					Name:     "dns_names",
					Type:     VarTypeDNSNames,
					Required: true,
				},
			},
			Extensions: &ExtensionsConfig{
				SubjectAltName: &SubjectAltNameConfig{
					DNS: StringOrSlice{"{{ dns_names }}"},
				},
			},
		}

		vars := VariableValues{} // dns_names not provided

		_, err := ResolveProfileExtensions(prof, vars)
		if err == nil {
			t.Error("expected error for missing required variable")
		}
		if err != nil && !containsString(err.Error(), "missing required variable") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("optional variable missing is omitted", func(t *testing.T) {
		prof := &Profile{
			Name: "test",
			Variables: map[string]*Variable{
				"dns_names": {
					Name:     "dns_names",
					Type:     VarTypeDNSNames,
					Required: false, // Optional
				},
			},
			Extensions: &ExtensionsConfig{
				SubjectAltName: &SubjectAltNameConfig{
					DNS: StringOrSlice{"{{ dns_names }}"},
				},
			},
		}

		vars := VariableValues{} // dns_names not provided

		result, err := ResolveProfileExtensions(prof, vars)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// SAN should be nil (RFC 5280: empty SAN not allowed)
		if result.SubjectAltName != nil {
			t.Errorf("expected nil SubjectAltName for empty optional variable, got %+v", result.SubjectAltName)
		}
	})

	t.Run("mixed static and template - static preserved", func(t *testing.T) {
		prof := &Profile{
			Name: "test",
			Variables: map[string]*Variable{
				"extra_dns": {
					Name:     "extra_dns",
					Type:     VarTypeDNSNames,
					Required: false,
				},
			},
			Extensions: &ExtensionsConfig{
				SubjectAltName: &SubjectAltNameConfig{
					DNS: StringOrSlice{"static.example.com", "{{ extra_dns }}"},
				},
			},
		}

		vars := VariableValues{} // extra_dns not provided

		result, err := ResolveProfileExtensions(prof, vars)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Should keep static value, omit template
		if result.SubjectAltName == nil {
			t.Fatal("expected SubjectAltName to be preserved with static value")
		}
		if len(result.SubjectAltName.DNS) != 1 {
			t.Errorf("expected 1 DNS, got %d", len(result.SubjectAltName.DNS))
		}
		if result.SubjectAltName.DNS[0] != "static.example.com" {
			t.Errorf("expected static value preserved, got %s", result.SubjectAltName.DNS[0])
		}
	})

	t.Run("undeclared variable is omitted", func(t *testing.T) {
		// Variable used in template but not declared in profile
		prof := &Profile{
			Name:      "test",
			Variables: map[string]*Variable{}, // No variables declared
			Extensions: &ExtensionsConfig{
				SubjectAltName: &SubjectAltNameConfig{
					DNS: StringOrSlice{"{{ undeclared_var }}"},
				},
			},
		}

		vars := VariableValues{}

		result, err := ResolveProfileExtensions(prof, vars)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Undeclared variable should be treated as optional and omitted
		// SAN should be nil (RFC 5280: empty SAN not allowed)
		if result.SubjectAltName != nil {
			t.Errorf("expected nil SubjectAltName for undeclared variable, got %+v", result.SubjectAltName)
		}
	})

	t.Run("RFC 5280: empty SAN omitted entirely", func(t *testing.T) {
		prof := &Profile{
			Name: "test",
			Variables: map[string]*Variable{
				"dns": {Name: "dns", Type: VarTypeDNSNames, Required: false},
				"ip":  {Name: "ip", Type: VarTypeIPList, Required: false},
			},
			Extensions: &ExtensionsConfig{
				SubjectAltName: &SubjectAltNameConfig{
					DNS: StringOrSlice{"{{ dns }}"},
					IP:  StringOrSlice{"{{ ip }}"},
				},
			},
		}

		vars := VariableValues{} // Nothing provided

		result, err := ResolveProfileExtensions(prof, vars)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// SAN should be nil per RFC 5280
		if result.SubjectAltName != nil {
			t.Errorf("expected nil SubjectAltName when all fields empty, got %+v", result.SubjectAltName)
		}
	})

	t.Run("variable provided is substituted", func(t *testing.T) {
		prof := &Profile{
			Name: "test",
			Variables: map[string]*Variable{
				"dns_names": {
					Name:     "dns_names",
					Type:     VarTypeDNSNames,
					Required: true,
				},
			},
			Extensions: &ExtensionsConfig{
				SubjectAltName: &SubjectAltNameConfig{
					DNS: StringOrSlice{"{{ dns_names }}"},
				},
			},
		}

		vars := VariableValues{
			"dns_names": []string{"api.example.com", "www.example.com"},
		}

		result, err := ResolveProfileExtensions(prof, vars)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.SubjectAltName == nil {
			t.Fatal("expected SubjectAltName to be present")
		}
		if len(result.SubjectAltName.DNS) != 2 {
			t.Errorf("expected 2 DNS names, got %d", len(result.SubjectAltName.DNS))
		}
		if result.SubjectAltName.DNS[0] != "api.example.com" {
			t.Errorf("expected first DNS to be api.example.com, got %s", result.SubjectAltName.DNS[0])
		}
	})

	t.Run("nil profile returns nil", func(t *testing.T) {
		result, err := ResolveProfileExtensions(nil, VariableValues{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result != nil {
			t.Errorf("expected nil result for nil profile, got %+v", result)
		}
	})

	t.Run("nil extensions returns nil", func(t *testing.T) {
		prof := &Profile{Name: "test", Extensions: nil}
		result, err := ResolveProfileExtensions(prof, VariableValues{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result != nil {
			t.Errorf("expected nil result for nil extensions, got %+v", result)
		}
	})
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestU_Profile_ResolveProfileExtensions_DNSIncludeCN(t *testing.T) {
	t.Run("adds CN to DNS SANs when flag is true", func(t *testing.T) {
		prof := &Profile{
			Name:      "test",
			Variables: map[string]*Variable{},
			Extensions: &ExtensionsConfig{
				SubjectAltName: &SubjectAltNameConfig{
					DNS:          StringOrSlice{"api.example.com"},
					DNSIncludeCN: true,
				},
			},
		}

		vars := VariableValues{
			"cn": "www.example.com",
		}

		result, err := ResolveProfileExtensions(prof, vars)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.SubjectAltName == nil {
			t.Fatal("expected SubjectAltName to be present")
		}
		if len(result.SubjectAltName.DNS) != 2 {
			t.Errorf("expected 2 DNS names (original + CN), got %d: %v", len(result.SubjectAltName.DNS), result.SubjectAltName.DNS)
		}
		// Check both original and CN are present
		foundOriginal := false
		foundCN := false
		for _, dns := range result.SubjectAltName.DNS {
			if dns == "api.example.com" {
				foundOriginal = true
			}
			if dns == "www.example.com" {
				foundCN = true
			}
		}
		if !foundOriginal {
			t.Error("expected original DNS name to be preserved")
		}
		if !foundCN {
			t.Error("expected CN to be added to DNS SANs")
		}
	})

	t.Run("does not duplicate CN if already in DNS", func(t *testing.T) {
		prof := &Profile{
			Name:      "test",
			Variables: map[string]*Variable{},
			Extensions: &ExtensionsConfig{
				SubjectAltName: &SubjectAltNameConfig{
					DNS:          StringOrSlice{"www.example.com", "api.example.com"},
					DNSIncludeCN: true,
				},
			},
		}

		vars := VariableValues{
			"cn": "www.example.com", // Same as first DNS entry
		}

		result, err := ResolveProfileExtensions(prof, vars)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.SubjectAltName == nil {
			t.Fatal("expected SubjectAltName to be present")
		}
		// Should still be 2, not 3
		if len(result.SubjectAltName.DNS) != 2 {
			t.Errorf("expected 2 DNS names (no duplicate), got %d: %v", len(result.SubjectAltName.DNS), result.SubjectAltName.DNS)
		}
	})

	t.Run("does not add CN when flag is false", func(t *testing.T) {
		prof := &Profile{
			Name:      "test",
			Variables: map[string]*Variable{},
			Extensions: &ExtensionsConfig{
				SubjectAltName: &SubjectAltNameConfig{
					DNS:          StringOrSlice{"api.example.com"},
					DNSIncludeCN: false,
				},
			},
		}

		vars := VariableValues{
			"cn": "www.example.com",
		}

		result, err := ResolveProfileExtensions(prof, vars)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.SubjectAltName == nil {
			t.Fatal("expected SubjectAltName to be present")
		}
		if len(result.SubjectAltName.DNS) != 1 {
			t.Errorf("expected 1 DNS name (CN not added), got %d: %v", len(result.SubjectAltName.DNS), result.SubjectAltName.DNS)
		}
	})

	t.Run("handles empty CN gracefully", func(t *testing.T) {
		prof := &Profile{
			Name:      "test",
			Variables: map[string]*Variable{},
			Extensions: &ExtensionsConfig{
				SubjectAltName: &SubjectAltNameConfig{
					DNS:          StringOrSlice{"api.example.com"},
					DNSIncludeCN: true,
				},
			},
		}

		vars := VariableValues{
			"cn": "", // Empty CN
		}

		result, err := ResolveProfileExtensions(prof, vars)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.SubjectAltName == nil {
			t.Fatal("expected SubjectAltName to be present")
		}
		// Should still be 1, empty CN not added
		if len(result.SubjectAltName.DNS) != 1 {
			t.Errorf("expected 1 DNS name (empty CN not added), got %d: %v", len(result.SubjectAltName.DNS), result.SubjectAltName.DNS)
		}
	})

	t.Run("handles missing CN variable gracefully", func(t *testing.T) {
		prof := &Profile{
			Name:      "test",
			Variables: map[string]*Variable{},
			Extensions: &ExtensionsConfig{
				SubjectAltName: &SubjectAltNameConfig{
					DNS:          StringOrSlice{"api.example.com"},
					DNSIncludeCN: true,
				},
			},
		}

		vars := VariableValues{} // No CN provided

		result, err := ResolveProfileExtensions(prof, vars)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.SubjectAltName == nil {
			t.Fatal("expected SubjectAltName to be present")
		}
		// Should still be 1, no CN to add
		if len(result.SubjectAltName.DNS) != 1 {
			t.Errorf("expected 1 DNS name (no CN to add), got %d: %v", len(result.SubjectAltName.DNS), result.SubjectAltName.DNS)
		}
	})

	t.Run("adds CN even when DNS list is empty from template", func(t *testing.T) {
		prof := &Profile{
			Name: "test",
			Variables: map[string]*Variable{
				"dns_names": {Name: "dns_names", Type: VarTypeDNSNames, Required: false},
			},
			Extensions: &ExtensionsConfig{
				SubjectAltName: &SubjectAltNameConfig{
					DNS:          StringOrSlice{"{{ dns_names }}"},
					DNSIncludeCN: true,
				},
			},
		}

		vars := VariableValues{
			"cn": "www.example.com",
			// dns_names not provided
		}

		result, err := ResolveProfileExtensions(prof, vars)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// SAN should exist because CN is added
		if result.SubjectAltName == nil {
			t.Fatal("expected SubjectAltName to be present (CN added)")
		}
		if len(result.SubjectAltName.DNS) != 1 {
			t.Errorf("expected 1 DNS name (CN only), got %d: %v", len(result.SubjectAltName.DNS), result.SubjectAltName.DNS)
		}
		if result.SubjectAltName.DNS[0] != "www.example.com" {
			t.Errorf("expected CN as DNS, got %s", result.SubjectAltName.DNS[0])
		}
	})
}
