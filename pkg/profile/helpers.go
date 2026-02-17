// Package profile provides helpers for loading and building certificate data from variables.
package profile

import (
	"crypto/x509/pkix"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// LoadVariables loads variable values from a YAML file and/or --var flags.
// Flag values override file values.
func LoadVariables(varFile string, varFlags []string) (VariableValues, error) {
	values := make(VariableValues)

	// Load from file if specified
	if varFile != "" {
		data, err := os.ReadFile(varFile)
		if err != nil {
			return nil, fmt.Errorf("read var-file: %w", err)
		}

		var fileVars map[string]interface{}
		if err := yaml.Unmarshal(data, &fileVars); err != nil {
			return nil, fmt.Errorf("parse var-file: %w", err)
		}

		for k, v := range fileVars {
			values[k] = v
		}
	}

	// Parse --var flags (override file values)
	if len(varFlags) > 0 {
		flagVars, err := ParseVarFlags(varFlags)
		if err != nil {
			return nil, err
		}

		for k, v := range flagVars {
			values[k] = v
		}
	}

	return values, nil
}

// BuildSubject builds a pkix.Name from variables (cn, o, ou, c, etc.).
// Deprecated: Use BuildSubjectFromProfile to include profile defaults.
func BuildSubject(vars VariableValues) (pkix.Name, error) {
	return BuildSubjectFromProfile(nil, vars)
}

// BuildSubjectFromProfile builds a pkix.Name by merging profile defaults with runtime variables.
// Profile subject values are used as defaults, runtime variables (--var) override them.
func BuildSubjectFromProfile(prof *Profile, vars VariableValues) (pkix.Name, error) {
	result := pkix.Name{}

	// Helper to get value: first try vars, then profile subject
	getValue := func(varNames ...string) string {
		// Try runtime variables first (they override profile)
		for _, name := range varNames {
			if v, ok := vars.GetString(name); ok {
				return v
			}
		}
		// Fall back to profile subject defaults
		if prof != nil && prof.Subject != nil && prof.Subject.Fixed != nil {
			for _, name := range varNames {
				if v, ok := prof.Subject.Fixed[name]; ok && v != "" {
					return v
				}
			}
		}
		return ""
	}

	// Build subject from merged values
	if cn := getValue("cn", "commonName"); cn != "" {
		result.CommonName = cn
	}
	if o := getValue("o", "organization"); o != "" {
		result.Organization = []string{o}
	}
	if ou := getValue("ou", "organizationalUnit"); ou != "" {
		result.OrganizationalUnit = []string{ou}
	}
	if c := getValue("c", "country"); c != "" {
		result.Country = []string{c}
	}
	if st := getValue("st", "state", "province"); st != "" {
		result.Province = []string{st}
	}
	if l := getValue("l", "locality"); l != "" {
		result.Locality = []string{l}
	}

	if result.CommonName == "" {
		return result, fmt.Errorf("CN (CommonName) is required: use --var cn=value")
	}

	return result, nil
}

// ExtractTemplateVariables extracts template variables as map[string][]string
// for use with ExtensionsConfig.SubstituteVariables().
// Includes SAN variables (dns_names, ip_addresses, email) and CDP/AIA variables
// (crl_url, ca_issuer, ocsp_url, cps_url).
// Deprecated: Use ExtractAllTemplateVariables for dynamic variable extraction.
func ExtractTemplateVariables(vars VariableValues) map[string][]string {
	result := make(map[string][]string)

	// SAN variables (existing)
	if dns, ok := vars.GetStringList("dns_names"); ok {
		result["dns_names"] = dns
	}
	if ips, ok := vars.GetStringList("ip_addresses"); ok {
		result["ip_addresses"] = ips
	}
	if em, ok := vars.GetStringList("email"); ok {
		result["email"] = em
	}

	// CDP/AIA/CPS variables (new)
	if url, ok := vars.GetString("crl_url"); ok {
		result["crl_url"] = []string{url}
	}
	if url, ok := vars.GetString("ca_issuer"); ok {
		result["ca_issuer"] = []string{url}
	}
	if url, ok := vars.GetString("ocsp_url"); ok {
		result["ocsp_url"] = []string{url}
	}
	if url, ok := vars.GetString("cps_url"); ok {
		result["cps_url"] = []string{url}
	}

	return result
}

// ExtractAllTemplateVariables extracts all variables from VariableValues
// for use with template substitution. Unlike ExtractTemplateVariables,
// this function extracts all variables dynamically, not just hardcoded names.
func ExtractAllTemplateVariables(vars VariableValues) map[string][]string {
	result := make(map[string][]string)

	for name, value := range vars {
		result[name] = toStringSlice(value)
	}

	return result
}

// toStringSlice converts an interface{} value to a string slice.
func toStringSlice(value interface{}) []string {
	if value == nil {
		return nil
	}

	switch v := value.(type) {
	case string:
		if v != "" {
			return []string{v}
		}
		return nil
	case []string:
		return v
	case []interface{}:
		result := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	default:
		// Try to convert to string
		return []string{fmt.Sprintf("%v", v)}
	}
}

// ResolveProfileExtensions substitutes template variables in profile extensions.
// This validates that required variables are provided and omits optional missing variables.
//
// If a variable is defined with required: true and not provided, returns an error.
// If a variable is optional (required: false or undefined) and not provided, the field is omitted.
// RFC 5280 compliance: if SAN has no entries after substitution, the extension is omitted.
//
// If the profile has no extensions, returns nil without error.
func ResolveProfileExtensions(prof *Profile, varValues VariableValues) (*ExtensionsConfig, error) {
	if prof == nil || prof.Extensions == nil {
		return nil, nil
	}

	// Extract all variables dynamically
	varsForTemplates := ExtractAllTemplateVariables(varValues)

	// Substitute with validation against profile variable definitions
	resolved, err := prof.Extensions.SubstituteVariablesWithValidation(varsForTemplates, prof.Variables)
	if err != nil {
		return nil, err
	}

	// Safety check: ensure no templates remain
	if remaining := resolved.FindTemplateVariables(); len(remaining) > 0 {
		return nil, fmt.Errorf("unresolved template variables in extensions: %v", remaining)
	}

	return resolved, nil
}
