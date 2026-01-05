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
func BuildSubject(vars VariableValues) (pkix.Name, error) {
	result := pkix.Name{}

	if cn, ok := vars.GetString("cn"); ok {
		result.CommonName = cn
	}
	if o, ok := vars.GetString("o"); ok {
		result.Organization = []string{o}
	} else if o, ok := vars.GetString("organization"); ok {
		result.Organization = []string{o}
	}
	if ou, ok := vars.GetString("ou"); ok {
		result.OrganizationalUnit = []string{ou}
	}
	if c, ok := vars.GetString("c"); ok {
		result.Country = []string{c}
	} else if c, ok := vars.GetString("country"); ok {
		result.Country = []string{c}
	}
	if st, ok := vars.GetString("st"); ok {
		result.Province = []string{st}
	} else if st, ok := vars.GetString("state"); ok {
		result.Province = []string{st}
	}
	if l, ok := vars.GetString("l"); ok {
		result.Locality = []string{l}
	} else if l, ok := vars.GetString("locality"); ok {
		result.Locality = []string{l}
	}

	if result.CommonName == "" {
		return result, fmt.Errorf("CN (CommonName) is required: use --var cn=value")
	}

	return result, nil
}

// ExtractSANVariables extracts dns_names, ip_addresses, email as map[string][]string
// for use with ExtensionsConfig.SubstituteVariables().
func ExtractSANVariables(vars VariableValues) map[string][]string {
	result := make(map[string][]string)

	if dns, ok := vars.GetStringList("dns_names"); ok {
		result["dns_names"] = dns
	}
	if ips, ok := vars.GetStringList("ip_addresses"); ok {
		result["ip_addresses"] = ips
	}
	if em, ok := vars.GetStringList("email"); ok {
		result["email"] = em
	}

	return result
}

// ResolveProfileExtensions substitutes SAN template variables in profile extensions.
// This is a convenience function that combines ExtractSANVariables and SubstituteVariables.
//
// It replaces templates like "{{ dns_names }}", "{{ ip_addresses }}", "{{ email }}"
// in SubjectAltName configuration with the actual values from varValues.
//
// If the profile has no extensions, returns nil without error.
// If varValues has no SAN variables, returns the original extensions unchanged.
func ResolveProfileExtensions(prof *Profile, varValues VariableValues) (*ExtensionsConfig, error) {
	if prof == nil || prof.Extensions == nil {
		return nil, nil
	}

	varsForSAN := ExtractSANVariables(varValues)
	if len(varsForSAN) == 0 {
		// No SAN variables to substitute, return original extensions
		return prof.Extensions, nil
	}

	return prof.Extensions.SubstituteVariables(varsForSAN)
}
