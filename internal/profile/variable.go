// Package profile provides declarative variables for certificate profiles.
package profile

// VariableType defines the type of a profile variable.
type VariableType string

const (
	// VarTypeString is a string variable with optional pattern/enum validation.
	VarTypeString VariableType = "string"

	// VarTypeInteger is an integer variable with optional min/max validation.
	VarTypeInteger VariableType = "integer"

	// VarTypeBoolean is a boolean variable.
	VarTypeBoolean VariableType = "boolean"

	// VarTypeList is a list of strings with optional suffix/prefix constraints.
	VarTypeList VariableType = "list"

	// VarTypeIPList is a list of IP addresses with optional CIDR range constraints.
	VarTypeIPList VariableType = "ip_list"

	// VarTypeDNSName is a single DNS name with built-in RFC 1035/1123 validation.
	// Supports optional wildcard policy (RFC 6125).
	VarTypeDNSName VariableType = "dns_name"

	// VarTypeDNSNames is a list of DNS names with built-in RFC 1035/1123 validation.
	// Supports optional wildcard policy (RFC 6125).
	VarTypeDNSNames VariableType = "dns_names"
)

// WildcardPolicy defines constraints for wildcard DNS names (RFC 6125).
//
// Example YAML:
//
//	cn:
//	  type: dns_name
//	  wildcard:
//	    allowed: true              # Permit wildcards like *.example.com
//	    single_label: true         # RFC 6125: * matches exactly one label
//	    forbid_public_suffix: true # Block wildcards on public suffixes (*.co.uk)
type WildcardPolicy struct {
	// Allowed permits wildcard DNS names (e.g., *.example.com).
	// Default: false (wildcards rejected).
	Allowed bool `yaml:"allowed" json:"allowed"`

	// SingleLabel enforces RFC 6125 semantics where * matches exactly one label.
	// When true: *.example.com matches api.example.com but NOT api.v2.example.com.
	// Default: true (RFC 6125 compliant).
	SingleLabel bool `yaml:"single_label" json:"single_label"`

	// ForbidPublicSuffix blocks wildcards on public suffixes like *.co.uk, *.com.au.
	// Uses the Public Suffix List (PSL) to detect effective TLDs.
	// Default: false (for backward compatibility, but recommended: true).
	ForbidPublicSuffix bool `yaml:"forbid_public_suffix" json:"forbid_public_suffix"`
}

// DefaultWildcardPolicy returns a policy with RFC 6125 defaults.
func DefaultWildcardPolicy() *WildcardPolicy {
	return &WildcardPolicy{
		Allowed:     false,
		SingleLabel: true,
	}
}

// Variable defines a profile variable with its type and constraints.
// Variables are declared in the YAML profile and can be used in templates.
//
// Example YAML:
//
//	variables:
//	  cn:
//	    type: string
//	    required: true
//	    pattern: "^[a-zA-Z0-9][a-zA-Z0-9.-]+$"
//	    description: "Common Name (FQDN)"
//
//	  dns_names:
//	    type: list
//	    default: []
//	    constraints:
//	      allowed_suffixes: [".example.com"]
//	      max_items: 10
type Variable struct {
	// Name is set from the YAML map key, not from YAML content.
	Name string `yaml:"-" json:"-"`

	// Type defines the variable type (string, integer, boolean, list, ip_list).
	Type VariableType `yaml:"type" json:"type"`

	// Required indicates if the variable must be provided by the user.
	Required bool `yaml:"required,omitempty" json:"required,omitempty"`

	// Default is the default value if not provided by the user.
	// Type depends on the variable type:
	//   - string: string
	//   - integer: int
	//   - boolean: bool
	//   - list: []string or []interface{}
	//   - ip_list: []string
	Default interface{} `yaml:"default,omitempty" json:"default,omitempty"`

	// Description provides documentation for the variable.
	Description string `yaml:"description,omitempty" json:"description,omitempty"`

	// --- String constraints ---

	// Pattern is a regex pattern for string validation.
	Pattern string `yaml:"pattern,omitempty" json:"pattern,omitempty"`

	// Enum is a list of allowed values for string/integer variables.
	Enum []string `yaml:"enum,omitempty" json:"enum,omitempty"`

	// MinLength is the minimum string length.
	MinLength int `yaml:"minLength,omitempty" json:"minLength,omitempty"`

	// MaxLength is the maximum string length.
	MaxLength int `yaml:"maxLength,omitempty" json:"maxLength,omitempty"`

	// --- Numeric constraints ---

	// Min is the minimum value for integer variables.
	Min *int `yaml:"min,omitempty" json:"min,omitempty"`

	// Max is the maximum value for integer variables.
	Max *int `yaml:"max,omitempty" json:"max,omitempty"`

	// --- List constraints ---

	// Constraints defines constraints for list and ip_list variables.
	Constraints *ListConstraints `yaml:"constraints,omitempty" json:"constraints,omitempty"`

	// --- DNS constraints ---

	// Wildcard defines the wildcard policy for dns_name and dns_names types.
	// If nil, defaults to disallowing wildcards (RFC 6125 compliant).
	Wildcard *WildcardPolicy `yaml:"wildcard,omitempty" json:"wildcard,omitempty"`

	// AllowSingleLabel permits single-label DNS names (e.g., "localhost", "db-master").
	// Default: false (requires at least 2 labels like "example.com").
	// Useful for internal/private environments.
	AllowSingleLabel bool `yaml:"allow_single_label,omitempty" json:"allow_single_label,omitempty"`
}

// ListConstraints defines constraints for list and ip_list variables.
type ListConstraints struct {
	// AllowedSuffixes requires each list item to end with one of these suffixes.
	// Example: [".example.com", ".internal"]
	AllowedSuffixes []string `yaml:"allowed_suffixes,omitempty" json:"allowed_suffixes,omitempty"`

	// DeniedPrefixes rejects list items starting with any of these prefixes.
	// Example: ["internal-", "test-"]
	DeniedPrefixes []string `yaml:"denied_prefixes,omitempty" json:"denied_prefixes,omitempty"`

	// AllowedRanges (for ip_list) requires IPs to be within one of these CIDR ranges.
	// Example: ["10.0.0.0/8", "192.168.0.0/16"]
	AllowedRanges []string `yaml:"allowed_ranges,omitempty" json:"allowed_ranges,omitempty"`

	// MinItems is the minimum number of list items.
	MinItems int `yaml:"min_items,omitempty" json:"min_items,omitempty"`

	// MaxItems is the maximum number of list items.
	MaxItems int `yaml:"max_items,omitempty" json:"max_items,omitempty"`
}

// HasDefault returns true if the variable has a default value.
func (v *Variable) HasDefault() bool {
	return v.Default != nil
}

// IsRequired returns true if the variable must be provided.
func (v *Variable) IsRequired() bool {
	return v.Required && !v.HasDefault()
}

// GetDefaultString returns the default value as a string.
// Returns empty string if no default or wrong type.
func (v *Variable) GetDefaultString() string {
	if s, ok := v.Default.(string); ok {
		return s
	}
	return ""
}

// GetDefaultInt returns the default value as an integer.
// Returns 0 if no default or wrong type.
func (v *Variable) GetDefaultInt() int {
	switch d := v.Default.(type) {
	case int:
		return d
	case float64:
		return int(d)
	}
	return 0
}

// GetDefaultBool returns the default value as a boolean.
// Returns false if no default or wrong type.
func (v *Variable) GetDefaultBool() bool {
	if b, ok := v.Default.(bool); ok {
		return b
	}
	return false
}

// GetDefaultStringList returns the default value as a string slice.
// Returns nil if no default or wrong type.
func (v *Variable) GetDefaultStringList() []string {
	if v.Default == nil {
		return nil
	}

	switch d := v.Default.(type) {
	case []string:
		return d
	case []interface{}:
		result := make([]string, 0, len(d))
		for _, item := range d {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return nil
}

// VariableValues holds user-provided variable values.
type VariableValues map[string]interface{}

// GetString returns a string value from the map.
func (vv VariableValues) GetString(name string) (string, bool) {
	v, ok := vv[name]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// GetInt returns an integer value from the map.
func (vv VariableValues) GetInt(name string) (int, bool) {
	v, ok := vv[name]
	if !ok {
		return 0, false
	}
	switch i := v.(type) {
	case int:
		return i, true
	case float64:
		return int(i), true
	}
	return 0, false
}

// GetBool returns a boolean value from the map.
func (vv VariableValues) GetBool(name string) (bool, bool) {
	v, ok := vv[name]
	if !ok {
		return false, false
	}
	b, ok := v.(bool)
	return b, ok
}

// GetStringList returns a string slice value from the map.
func (vv VariableValues) GetStringList(name string) ([]string, bool) {
	v, ok := vv[name]
	if !ok {
		return nil, false
	}

	switch s := v.(type) {
	case []string:
		return s, true
	case []interface{}:
		result := make([]string, 0, len(s))
		for _, item := range s {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result, true
	}
	return nil, false
}

// SetString sets a string value in the map.
func (vv VariableValues) SetString(name, value string) {
	vv[name] = value
}

// SetInt sets an integer value in the map.
func (vv VariableValues) SetInt(name string, value int) {
	vv[name] = value
}

// SetBool sets a boolean value in the map.
func (vv VariableValues) SetBool(name string, value bool) {
	vv[name] = value
}

// SetStringList sets a string slice value in the map.
func (vv VariableValues) SetStringList(name string, value []string) {
	vv[name] = value
}
