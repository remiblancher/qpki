package profile

import (
	"testing"

	"github.com/remiblancher/qpki/pkg/crypto"
)

// =============================================================================
// Unit Tests: NewTemplateEngine
// =============================================================================

func TestU_NewTemplateEngine_NoVariables(t *testing.T) {
	profile := &Profile{
		Name:      "test-profile",
		Algorithm: crypto.AlgECDSAP256,
	}

	engine, err := NewTemplateEngine(profile)
	if err != nil {
		t.Fatalf("NewTemplateEngine() error = %v", err)
	}

	if engine == nil {
		t.Fatal("NewTemplateEngine() returned nil")
	}

	// With no variables defined, HasVariables should be false
	if engine.HasVariables() {
		t.Error("HasVariables() should return false when no variables are defined")
	}
}

func TestU_NewTemplateEngine_WithVariables(t *testing.T) {
	profile := &Profile{
		Name:      "test-profile",
		Algorithm: crypto.AlgECDSAP256,
		Variables: map[string]*Variable{
			"cn": {
				Type:     VarTypeString,
				Required: true,
			},
			"dns_names": {
				Type: VarTypeDNSNames,
			},
		},
	}

	engine, err := NewTemplateEngine(profile)
	if err != nil {
		t.Fatalf("NewTemplateEngine() error = %v", err)
	}

	if engine == nil {
		t.Fatal("NewTemplateEngine() returned nil")
	}

	if !engine.HasVariables() {
		t.Error("HasVariables() should return true when profile has variables")
	}
}

func TestU_NewTemplateEngine_InvalidPattern(t *testing.T) {
	profile := &Profile{
		Name:      "test-profile",
		Algorithm: crypto.AlgECDSAP256,
		Variables: map[string]*Variable{
			"cn": {
				Type:    VarTypeString,
				Pattern: "[invalid regex",
			},
		},
	}

	_, err := NewTemplateEngine(profile)
	if err == nil {
		t.Error("NewTemplateEngine() should return error for invalid regex pattern")
	}
}

// =============================================================================
// Unit Tests: TemplateEngine.Render
// =============================================================================

func TestU_TemplateEngine_Render_ValidValues(t *testing.T) {
	profile := &Profile{
		Name:      "test-profile",
		Algorithm: crypto.AlgECDSAP256,
		Variables: map[string]*Variable{
			"cn": {
				Type:     VarTypeString,
				Required: true,
			},
		},
	}

	engine, err := NewTemplateEngine(profile)
	if err != nil {
		t.Fatalf("NewTemplateEngine() error = %v", err)
	}

	values := VariableValues{"cn": "example.com"}
	rendered, err := engine.Render(values)
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}

	if rendered == nil {
		t.Fatal("Render() returned nil")
	}

	if rendered.ResolvedValues["cn"] != "example.com" {
		t.Errorf("ResolvedValues[cn] = %v, want %v", rendered.ResolvedValues["cn"], "example.com")
	}
}

func TestU_TemplateEngine_Render_MissingRequired(t *testing.T) {
	profile := &Profile{
		Name:      "test-profile",
		Algorithm: crypto.AlgECDSAP256,
		Variables: map[string]*Variable{
			"cn": {
				Type:     VarTypeString,
				Required: true,
			},
		},
	}

	engine, err := NewTemplateEngine(profile)
	if err != nil {
		t.Fatalf("NewTemplateEngine() error = %v", err)
	}

	values := VariableValues{} // Missing required "cn"
	_, err = engine.Render(values)
	if err == nil {
		t.Error("Render() should return error for missing required variable")
	}
}

func TestU_TemplateEngine_Render_WithDefaults(t *testing.T) {
	profile := &Profile{
		Name:      "test-profile",
		Algorithm: crypto.AlgECDSAP256,
		Variables: map[string]*Variable{
			"validity": {
				Type:    VarTypeString,
				Default: "365d",
			},
		},
	}

	engine, err := NewTemplateEngine(profile)
	if err != nil {
		t.Fatalf("NewTemplateEngine() error = %v", err)
	}

	values := VariableValues{} // No values, should use default
	rendered, err := engine.Render(values)
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}

	if rendered.ResolvedValues["validity"] != "365d" {
		t.Errorf("ResolvedValues[validity] = %v, want %v", rendered.ResolvedValues["validity"], "365d")
	}
}

// =============================================================================
// Unit Tests: TemplateEngine.SubstituteString
// =============================================================================

func TestU_TemplateEngine_SubstituteString_Simple(t *testing.T) {
	profile := &Profile{
		Name:      "test-profile",
		Algorithm: crypto.AlgECDSAP256,
	}

	engine, err := NewTemplateEngine(profile)
	if err != nil {
		t.Fatalf("NewTemplateEngine() error = %v", err)
	}

	values := VariableValues{"name": "example"}
	result, err := engine.SubstituteString("Hello {{ name }}", values)
	if err != nil {
		t.Fatalf("SubstituteString() error = %v", err)
	}

	if result != "Hello example" {
		t.Errorf("SubstituteString() = %q, want %q", result, "Hello example")
	}
}

func TestU_TemplateEngine_SubstituteString_Integer(t *testing.T) {
	profile := &Profile{
		Name:      "test-profile",
		Algorithm: crypto.AlgECDSAP256,
	}

	engine, err := NewTemplateEngine(profile)
	if err != nil {
		t.Fatalf("NewTemplateEngine() error = %v", err)
	}

	values := VariableValues{"count": 42}
	result, err := engine.SubstituteString("Count: {{ count }}", values)
	if err != nil {
		t.Fatalf("SubstituteString() error = %v", err)
	}

	if result != "Count: 42" {
		t.Errorf("SubstituteString() = %q, want %q", result, "Count: 42")
	}
}

func TestU_TemplateEngine_SubstituteString_Boolean(t *testing.T) {
	profile := &Profile{
		Name:      "test-profile",
		Algorithm: crypto.AlgECDSAP256,
	}

	engine, err := NewTemplateEngine(profile)
	if err != nil {
		t.Fatalf("NewTemplateEngine() error = %v", err)
	}

	values := VariableValues{"enabled": true}
	result, err := engine.SubstituteString("Enabled: {{ enabled }}", values)
	if err != nil {
		t.Fatalf("SubstituteString() error = %v", err)
	}

	if result != "Enabled: true" {
		t.Errorf("SubstituteString() = %q, want %q", result, "Enabled: true")
	}
}

func TestU_TemplateEngine_SubstituteString_UnsubstitutedVariable(t *testing.T) {
	profile := &Profile{
		Name:      "test-profile",
		Algorithm: crypto.AlgECDSAP256,
	}

	engine, err := NewTemplateEngine(profile)
	if err != nil {
		t.Fatalf("NewTemplateEngine() error = %v", err)
	}

	values := VariableValues{} // No values
	_, err = engine.SubstituteString("Hello {{ missing }}", values)
	if err == nil {
		t.Error("SubstituteString() should return error for unsubstituted variables")
	}
}

func TestU_TemplateEngine_SubstituteString_NoVariables(t *testing.T) {
	profile := &Profile{
		Name:      "test-profile",
		Algorithm: crypto.AlgECDSAP256,
	}

	engine, err := NewTemplateEngine(profile)
	if err != nil {
		t.Fatalf("NewTemplateEngine() error = %v", err)
	}

	values := VariableValues{}
	result, err := engine.SubstituteString("Static text", values)
	if err != nil {
		t.Fatalf("SubstituteString() error = %v", err)
	}

	if result != "Static text" {
		t.Errorf("SubstituteString() = %q, want %q", result, "Static text")
	}
}

// =============================================================================
// Unit Tests: TemplateEngine.GetResolvedSubject
// =============================================================================

func TestU_TemplateEngine_GetResolvedSubject_NoSubjectConfig(t *testing.T) {
	profile := &Profile{
		Name:      "test-profile",
		Algorithm: crypto.AlgECDSAP256,
	}

	engine, err := NewTemplateEngine(profile)
	if err != nil {
		t.Fatalf("NewTemplateEngine() error = %v", err)
	}

	values := VariableValues{"cn": "example.com"}
	subject, err := engine.GetResolvedSubject(values)
	if err != nil {
		t.Fatalf("GetResolvedSubject() error = %v", err)
	}

	if subject["cn"] != "example.com" {
		t.Errorf("subject[cn] = %q, want %q", subject["cn"], "example.com")
	}
}

func TestU_TemplateEngine_GetResolvedSubject_WithTemplate(t *testing.T) {
	profile := &Profile{
		Name:      "test-profile",
		Algorithm: crypto.AlgECDSAP256,
		Subject: &SubjectConfig{
			Fixed: map[string]string{
				"cn": "{{ cn }}",
				"o":  "Test Org",
			},
		},
	}

	engine, err := NewTemplateEngine(profile)
	if err != nil {
		t.Fatalf("NewTemplateEngine() error = %v", err)
	}

	values := VariableValues{"cn": "example.com"}
	subject, err := engine.GetResolvedSubject(values)
	if err != nil {
		t.Fatalf("GetResolvedSubject() error = %v", err)
	}

	if subject["cn"] != "example.com" {
		t.Errorf("subject[cn] = %q, want %q", subject["cn"], "example.com")
	}
	if subject["o"] != "Test Org" {
		t.Errorf("subject[o] = %q, want %q", subject["o"], "Test Org")
	}
}

// =============================================================================
// Unit Tests: TemplateEngine.GetResolvedDNSNames
// =============================================================================

func TestU_TemplateEngine_GetResolvedDNSNames_WithDnsNames(t *testing.T) {
	profile := &Profile{
		Name:      "test-profile",
		Algorithm: crypto.AlgECDSAP256,
	}

	engine, err := NewTemplateEngine(profile)
	if err != nil {
		t.Fatalf("NewTemplateEngine() error = %v", err)
	}

	values := VariableValues{"dns_names": []string{"example.com", "www.example.com"}}
	dnsNames := engine.GetResolvedDNSNames(values)

	if len(dnsNames) != 2 {
		t.Errorf("GetResolvedDNSNames() returned %d names, want 2", len(dnsNames))
	}
}

func TestU_TemplateEngine_GetResolvedDNSNames_WithDns(t *testing.T) {
	profile := &Profile{
		Name:      "test-profile",
		Algorithm: crypto.AlgECDSAP256,
	}

	engine, err := NewTemplateEngine(profile)
	if err != nil {
		t.Fatalf("NewTemplateEngine() error = %v", err)
	}

	values := VariableValues{"dns": []string{"example.com"}}
	dnsNames := engine.GetResolvedDNSNames(values)

	if len(dnsNames) != 1 {
		t.Errorf("GetResolvedDNSNames() returned %d names, want 1", len(dnsNames))
	}
}

func TestU_TemplateEngine_GetResolvedDNSNames_NoValues(t *testing.T) {
	profile := &Profile{
		Name:      "test-profile",
		Algorithm: crypto.AlgECDSAP256,
	}

	engine, err := NewTemplateEngine(profile)
	if err != nil {
		t.Fatalf("NewTemplateEngine() error = %v", err)
	}

	values := VariableValues{}
	dnsNames := engine.GetResolvedDNSNames(values)

	if dnsNames != nil {
		t.Errorf("GetResolvedDNSNames() returned %v, want nil", dnsNames)
	}
}

// =============================================================================
// Unit Tests: TemplateEngine.GetResolvedIPAddresses
// =============================================================================

func TestU_TemplateEngine_GetResolvedIPAddresses_WithIpAddresses(t *testing.T) {
	profile := &Profile{
		Name:      "test-profile",
		Algorithm: crypto.AlgECDSAP256,
	}

	engine, err := NewTemplateEngine(profile)
	if err != nil {
		t.Fatalf("NewTemplateEngine() error = %v", err)
	}

	values := VariableValues{"ip_addresses": []string{"192.168.1.1", "10.0.0.1"}}
	ips := engine.GetResolvedIPAddresses(values)

	if len(ips) != 2 {
		t.Errorf("GetResolvedIPAddresses() returned %d IPs, want 2", len(ips))
	}
}

func TestU_TemplateEngine_GetResolvedIPAddresses_WithIps(t *testing.T) {
	profile := &Profile{
		Name:      "test-profile",
		Algorithm: crypto.AlgECDSAP256,
	}

	engine, err := NewTemplateEngine(profile)
	if err != nil {
		t.Fatalf("NewTemplateEngine() error = %v", err)
	}

	values := VariableValues{"ips": []string{"192.168.1.1"}}
	ips := engine.GetResolvedIPAddresses(values)

	if len(ips) != 1 {
		t.Errorf("GetResolvedIPAddresses() returned %d IPs, want 1", len(ips))
	}
}

func TestU_TemplateEngine_GetResolvedIPAddresses_NoValues(t *testing.T) {
	profile := &Profile{
		Name:      "test-profile",
		Algorithm: crypto.AlgECDSAP256,
	}

	engine, err := NewTemplateEngine(profile)
	if err != nil {
		t.Fatalf("NewTemplateEngine() error = %v", err)
	}

	values := VariableValues{}
	ips := engine.GetResolvedIPAddresses(values)

	if ips != nil {
		t.Errorf("GetResolvedIPAddresses() returned %v, want nil", ips)
	}
}

// =============================================================================
// Unit Tests: TemplateEngine.GetResolvedEmails
// =============================================================================

func TestU_TemplateEngine_GetResolvedEmails_WithEmails(t *testing.T) {
	profile := &Profile{
		Name:      "test-profile",
		Algorithm: crypto.AlgECDSAP256,
	}

	engine, err := NewTemplateEngine(profile)
	if err != nil {
		t.Fatalf("NewTemplateEngine() error = %v", err)
	}

	values := VariableValues{"emails": []string{"test@example.com"}}
	emails := engine.GetResolvedEmails(values)

	if len(emails) != 1 {
		t.Errorf("GetResolvedEmails() returned %d emails, want 1", len(emails))
	}
}

func TestU_TemplateEngine_GetResolvedEmails_WithEmail(t *testing.T) {
	profile := &Profile{
		Name:      "test-profile",
		Algorithm: crypto.AlgECDSAP256,
	}

	engine, err := NewTemplateEngine(profile)
	if err != nil {
		t.Fatalf("NewTemplateEngine() error = %v", err)
	}

	values := VariableValues{"email": []string{"admin@example.com", "support@example.com"}}
	emails := engine.GetResolvedEmails(values)

	if len(emails) != 2 {
		t.Errorf("GetResolvedEmails() returned %d emails, want 2", len(emails))
	}
}

func TestU_TemplateEngine_GetResolvedEmails_NoValues(t *testing.T) {
	profile := &Profile{
		Name:      "test-profile",
		Algorithm: crypto.AlgECDSAP256,
	}

	engine, err := NewTemplateEngine(profile)
	if err != nil {
		t.Fatalf("NewTemplateEngine() error = %v", err)
	}

	values := VariableValues{}
	emails := engine.GetResolvedEmails(values)

	if emails != nil {
		t.Errorf("GetResolvedEmails() returned %v, want nil", emails)
	}
}

// =============================================================================
// Unit Tests: TemplateEngine accessor methods
// =============================================================================

func TestU_TemplateEngine_Validator(t *testing.T) {
	profile := &Profile{
		Name:      "test-profile",
		Algorithm: crypto.AlgECDSAP256,
		Variables: map[string]*Variable{
			"cn": {Type: VarTypeString},
		},
	}

	engine, err := NewTemplateEngine(profile)
	if err != nil {
		t.Fatalf("NewTemplateEngine() error = %v", err)
	}

	validator := engine.Validator()
	if validator == nil {
		t.Error("Validator() returned nil")
	}
}

func TestU_TemplateEngine_Profile(t *testing.T) {
	profile := &Profile{
		Name:      "test-profile",
		Algorithm: crypto.AlgECDSAP256,
	}

	engine, err := NewTemplateEngine(profile)
	if err != nil {
		t.Fatalf("NewTemplateEngine() error = %v", err)
	}

	if engine.Profile() != profile {
		t.Error("Profile() should return the original profile")
	}
}

func TestU_TemplateEngine_RequiredVariables(t *testing.T) {
	profile := &Profile{
		Name:      "test-profile",
		Algorithm: crypto.AlgECDSAP256,
		Variables: map[string]*Variable{
			"cn": {
				Type:     VarTypeString,
				Required: true,
			},
			"optional": {
				Type: VarTypeString,
			},
			"with_default": {
				Type:    VarTypeString,
				Default: "default-value",
			},
		},
	}

	engine, err := NewTemplateEngine(profile)
	if err != nil {
		t.Fatalf("NewTemplateEngine() error = %v", err)
	}

	required := engine.RequiredVariables()

	// Only "cn" should be required (with_default has a default, optional is not required)
	if len(required) != 1 {
		t.Errorf("RequiredVariables() returned %d variables, want 1", len(required))
	}

	found := false
	for _, name := range required {
		if name == "cn" {
			found = true
			break
		}
	}
	if !found {
		t.Error("RequiredVariables() should include 'cn'")
	}
}

// =============================================================================
// Unit Tests: ParseVarFlags
// =============================================================================

func TestU_ParseVarFlags_SingleValue(t *testing.T) {
	flags := []string{"cn=example.com"}

	values, err := ParseVarFlags(flags)
	if err != nil {
		t.Fatalf("ParseVarFlags() error = %v", err)
	}

	if values["cn"] != "example.com" {
		t.Errorf("values[cn] = %v, want %v", values["cn"], "example.com")
	}
}

func TestU_ParseVarFlags_ListValue(t *testing.T) {
	flags := []string{"dns_names=a.com,b.com,c.com"}

	values, err := ParseVarFlags(flags)
	if err != nil {
		t.Fatalf("ParseVarFlags() error = %v", err)
	}

	list, ok := values["dns_names"].([]string)
	if !ok {
		t.Fatalf("values[dns_names] is not a []string")
	}

	if len(list) != 3 {
		t.Errorf("values[dns_names] has %d elements, want 3", len(list))
	}
}

func TestU_ParseVarFlags_MultipleFlags(t *testing.T) {
	flags := []string{"cn=example.com", "o=Test Org", "c=FR"}

	values, err := ParseVarFlags(flags)
	if err != nil {
		t.Fatalf("ParseVarFlags() error = %v", err)
	}

	if len(values) != 3 {
		t.Errorf("ParseVarFlags() returned %d values, want 3", len(values))
	}
}

func TestU_ParseVarFlags_InvalidFormat(t *testing.T) {
	flags := []string{"invalid-format-no-equals"}

	_, err := ParseVarFlags(flags)
	if err == nil {
		t.Error("ParseVarFlags() should return error for invalid format")
	}
}

func TestU_ParseVarFlags_EmptyValue(t *testing.T) {
	flags := []string{"key="}

	values, err := ParseVarFlags(flags)
	if err != nil {
		t.Fatalf("ParseVarFlags() error = %v", err)
	}

	if values["key"] != "" {
		t.Errorf("values[key] = %q, want empty string", values["key"])
	}
}

func TestU_ParseVarFlags_ValueWithEquals(t *testing.T) {
	flags := []string{"url=https://example.com?param=value"}

	values, err := ParseVarFlags(flags)
	if err != nil {
		t.Fatalf("ParseVarFlags() error = %v", err)
	}

	if values["url"] != "https://example.com?param=value" {
		t.Errorf("values[url] = %q, want %q", values["url"], "https://example.com?param=value")
	}
}

// =============================================================================
// Unit Tests: CompileWithTemplate
// =============================================================================

func TestU_Profile_CompileWithTemplate_Valid(t *testing.T) {
	profile := &Profile{
		Name:      "test-profile",
		Algorithm: crypto.AlgECDSAP256,
		Variables: map[string]*Variable{
			"cn": {Type: VarTypeString},
		},
	}

	ctp, err := profile.CompileWithTemplate()
	if err != nil {
		t.Fatalf("CompileWithTemplate() error = %v", err)
	}

	if ctp == nil {
		t.Fatal("CompileWithTemplate() returned nil")
	}

	if ctp.CompiledProfile == nil {
		t.Error("CompileWithTemplate().CompiledProfile should not be nil")
	}

	if ctp.Engine == nil {
		t.Error("CompileWithTemplate().Engine should not be nil")
	}
}

func TestU_Profile_CompileWithTemplate_InvalidPattern(t *testing.T) {
	profile := &Profile{
		Name:      "test-profile",
		Algorithm: crypto.AlgECDSAP256,
		Variables: map[string]*Variable{
			"cn": {
				Type:    VarTypeString,
				Pattern: "[invalid",
			},
		},
	}

	_, err := profile.CompileWithTemplate()
	if err == nil {
		t.Error("CompileWithTemplate() should return error for invalid pattern")
	}
}

// =============================================================================
// Unit Tests: CompiledTemplateProfile.Render
// =============================================================================

func TestU_CompiledTemplateProfile_Render(t *testing.T) {
	profile := &Profile{
		Name:      "test-profile",
		Algorithm: crypto.AlgECDSAP256,
		Variables: map[string]*Variable{
			"cn": {
				Type:     VarTypeString,
				Required: true,
			},
		},
	}

	ctp, err := profile.CompileWithTemplate()
	if err != nil {
		t.Fatalf("CompileWithTemplate() error = %v", err)
	}

	values := VariableValues{"cn": "example.com"}
	rendered, err := ctp.Render(values)
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}

	if rendered == nil {
		t.Fatal("Render() returned nil")
	}

	if rendered.ResolvedValues["cn"] != "example.com" {
		t.Errorf("ResolvedValues[cn] = %v, want %v", rendered.ResolvedValues["cn"], "example.com")
	}
}

// =============================================================================
// Unit Tests: RenderedProfile.Algorithm
// =============================================================================

func TestU_RenderedProfile_Algorithm(t *testing.T) {
	profile := &Profile{
		Name:      "test-profile",
		Algorithm: crypto.AlgECDSAP384,
	}

	rendered := &RenderedProfile{
		Profile: profile,
	}

	if rendered.Algorithm() != crypto.AlgECDSAP384 {
		t.Errorf("Algorithm() = %v, want %v", rendered.Algorithm(), crypto.AlgECDSAP384)
	}
}

func TestU_RenderedProfile_Algorithm_Catalyst(t *testing.T) {
	profile := &Profile{
		Name:       "test-catalyst",
		Mode:       ModeCatalyst,
		Algorithms: []crypto.AlgorithmID{crypto.AlgECDSAP256, crypto.AlgMLDSA65},
	}

	rendered := &RenderedProfile{
		Profile: profile,
	}

	// Should return the primary algorithm
	if rendered.Algorithm() != crypto.AlgECDSAP256 {
		t.Errorf("Algorithm() = %v, want %v", rendered.Algorithm(), crypto.AlgECDSAP256)
	}
}
