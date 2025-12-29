// Package profile provides template rendering for certificate profiles.
package profile

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/remiblancher/post-quantum-pki/internal/crypto"
)

// templateVarRegex matches {{ variable_name }} patterns.
var templateVarRegex = regexp.MustCompile(`\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\}\}`)

// TemplateEngine renders profile templates with variable substitution.
// It validates user-provided values against variable constraints and
// substitutes {{ variable }} placeholders in the template.
type TemplateEngine struct {
	profile   *Profile
	validator *VariableValidator
}

// NewTemplateEngine creates a new template engine for the given profile.
// Returns an error if the profile's variable constraints are invalid.
func NewTemplateEngine(profile *Profile) (*TemplateEngine, error) {
	vars := profile.Variables
	if vars == nil {
		vars = make(map[string]*Variable)
	}

	// Set variable names from map keys
	for name, v := range vars {
		v.Name = name
	}

	validator, err := NewVariableValidator(vars)
	if err != nil {
		return nil, fmt.Errorf("invalid variable constraints: %w", err)
	}

	return &TemplateEngine{
		profile:   profile,
		validator: validator,
	}, nil
}

// RenderedProfile is a profile with all template variables substituted.
type RenderedProfile struct {
	*Profile

	// ResolvedValues contains the final values used for rendering.
	ResolvedValues VariableValues
}

// Render substitutes template variables and validates constraints.
// Returns a RenderedProfile ready for certificate generation.
func (e *TemplateEngine) Render(userValues VariableValues) (*RenderedProfile, error) {
	// Merge defaults with user values
	values := e.validator.MergeWithDefaults(userValues)

	// Validate all values
	if err := e.validator.ValidateAll(values); err != nil {
		return nil, err
	}

	// Create a copy of the profile with substituted values
	rendered := &RenderedProfile{
		Profile:        e.profile,
		ResolvedValues: values,
	}

	return rendered, nil
}

// SubstituteString replaces {{ variable }} placeholders in a string.
func (e *TemplateEngine) SubstituteString(template string, values VariableValues) (string, error) {
	result := templateVarRegex.ReplaceAllStringFunc(template, func(match string) string {
		// Extract variable name from {{ name }}
		submatch := templateVarRegex.FindStringSubmatch(match)
		if len(submatch) < 2 {
			return match
		}
		varName := submatch[1]

		// Look up value
		if val, ok := values[varName]; ok {
			switch v := val.(type) {
			case string:
				return v
			case int:
				return fmt.Sprintf("%d", v)
			case bool:
				return fmt.Sprintf("%t", v)
			default:
				return match
			}
		}
		return match
	})

	// Check for unsubstituted variables
	remaining := templateVarRegex.FindAllString(result, -1)
	if len(remaining) > 0 {
		return "", fmt.Errorf("unsubstituted variables: %v", remaining)
	}

	return result, nil
}

// GetResolvedSubject builds a subject from resolved variable values.
// It uses the subject template from the profile and substitutes variables.
// With the declarative variable format, all subject fields use {{ variable }} templates.
// Required/optional validation is handled by VariableValidator, not here.
func (e *TemplateEngine) GetResolvedSubject(values VariableValues) (map[string]string, error) {
	result := make(map[string]string)

	// If no subject config, just use CN from values
	if e.profile.Subject == nil {
		if cn, ok := values.GetString("cn"); ok {
			result["cn"] = cn
		}
		return result, nil
	}

	// Substitute template variables in subject fields
	// Example: "cn": "{{ cn }}" -> "cn": "example.com"
	for key, val := range e.profile.Subject.Fixed {
		resolved, err := e.SubstituteString(val, values)
		if err != nil {
			return nil, fmt.Errorf("subject.%s: %w", key, err)
		}
		// Only include non-empty values
		if resolved != "" {
			result[key] = resolved
		}
	}

	return result, nil
}

// GetResolvedDNSNames returns DNS names from resolved variable values.
func (e *TemplateEngine) GetResolvedDNSNames(values VariableValues) []string {
	if dns, ok := values.GetStringList("dns_names"); ok {
		return dns
	}
	if dns, ok := values.GetStringList("dns"); ok {
		return dns
	}
	return nil
}

// GetResolvedIPAddresses returns IP addresses from resolved variable values.
func (e *TemplateEngine) GetResolvedIPAddresses(values VariableValues) []string {
	if ips, ok := values.GetStringList("ip_addresses"); ok {
		return ips
	}
	if ips, ok := values.GetStringList("ips"); ok {
		return ips
	}
	return nil
}

// GetResolvedEmails returns email addresses from resolved variable values.
func (e *TemplateEngine) GetResolvedEmails(values VariableValues) []string {
	if emails, ok := values.GetStringList("emails"); ok {
		return emails
	}
	if emails, ok := values.GetStringList("email"); ok {
		return emails
	}
	return nil
}

// GetResolvedValidity returns the validity period from resolved variable values.
func (e *TemplateEngine) GetResolvedValidity(values VariableValues) time.Duration {
	// Check for validity_days variable
	if days, ok := values.GetInt("validity_days"); ok && days > 0 {
		return time.Duration(days) * 24 * time.Hour
	}

	// Check for validity_hours variable
	if hours, ok := values.GetInt("validity_hours"); ok && hours > 0 {
		return time.Duration(hours) * time.Hour
	}

	// Fall back to profile default
	return e.profile.Validity
}

// Validator returns the underlying variable validator.
func (e *TemplateEngine) Validator() *VariableValidator {
	return e.validator
}

// Profile returns the underlying profile.
func (e *TemplateEngine) Profile() *Profile {
	return e.profile
}

// HasVariables returns true if the profile has declarative variables.
func (e *TemplateEngine) HasVariables() bool {
	return len(e.profile.Variables) > 0
}

// RequiredVariables returns the names of all required variables.
func (e *TemplateEngine) RequiredVariables() []string {
	return e.validator.RequiredVariables()
}

// ParseVarFlags parses --var key=value flags into VariableValues.
// Supports comma-separated lists for list variables.
func ParseVarFlags(flags []string) (VariableValues, error) {
	values := make(VariableValues)

	for _, flag := range flags {
		parts := strings.SplitN(flag, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid --var format: %q (expected key=value)", flag)
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Check if value contains commas (list)
		if strings.Contains(value, ",") {
			listValues := strings.Split(value, ",")
			for i, v := range listValues {
				listValues[i] = strings.TrimSpace(v)
			}
			values[key] = listValues
		} else {
			values[key] = value
		}
	}

	return values, nil
}

// CompiledTemplateProfile combines a CompiledProfile with a TemplateEngine.
// This is the recommended way to use profiles with variables.
type CompiledTemplateProfile struct {
	*CompiledProfile
	Engine *TemplateEngine
}

// CompileWithTemplate compiles a profile and creates a template engine.
func (p *Profile) CompileWithTemplate() (*CompiledTemplateProfile, error) {
	compiled, err := p.Compile()
	if err != nil {
		return nil, fmt.Errorf("compile profile: %w", err)
	}

	engine, err := NewTemplateEngine(p)
	if err != nil {
		return nil, fmt.Errorf("create template engine: %w", err)
	}

	return &CompiledTemplateProfile{
		CompiledProfile: compiled,
		Engine:          engine,
	}, nil
}

// Render validates and resolves variable values.
func (ctp *CompiledTemplateProfile) Render(userValues VariableValues) (*RenderedProfile, error) {
	return ctp.Engine.Render(userValues)
}

// Algorithm returns the algorithm ID, substituting variables if needed.
func (rp *RenderedProfile) Algorithm() crypto.AlgorithmID {
	return rp.Profile.GetAlgorithm()
}
