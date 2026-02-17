package dto

// ProfileListResponse represents a list of profiles.
type ProfileListResponse struct {
	// Profiles is the list of profile summaries.
	Profiles []ProfileListItem `json:"profiles"`
}

// ProfileListItem represents a profile in a list.
type ProfileListItem struct {
	// Name is the profile name.
	Name string `json:"name"`

	// Description is the profile description.
	Description string `json:"description,omitempty"`

	// Category is the profile category.
	Category string `json:"category,omitempty"`

	// Algorithm is the primary algorithm.
	Algorithm string `json:"algorithm"`

	// IsCA indicates if this is a CA profile.
	IsCA bool `json:"is_ca"`
}

// ProfileInfoResponse represents detailed profile information.
type ProfileInfoResponse struct {
	// Name is the profile name.
	Name string `json:"name"`

	// Description is the profile description.
	Description string `json:"description,omitempty"`

	// Category is the profile category.
	Category string `json:"category,omitempty"`

	// Algorithm is the algorithm configuration.
	Algorithm AlgorithmInfo `json:"algorithm"`

	// HybridAlgorithm is present for hybrid profiles.
	HybridAlgorithm *AlgorithmInfo `json:"hybrid_algorithm,omitempty"`

	// Validity is the default validity period.
	Validity string `json:"validity"`

	// IsCA indicates if this is a CA profile.
	IsCA bool `json:"is_ca"`

	// PathLen is the path length constraint (for CA profiles).
	PathLen *int `json:"path_len,omitempty"`

	// KeyUsage lists key usage flags.
	KeyUsage []string `json:"key_usage,omitempty"`

	// ExtKeyUsage lists extended key usage purposes.
	ExtKeyUsage []string `json:"ext_key_usage,omitempty"`

	// Subject contains default subject configuration.
	Subject *ProfileSubjectConfig `json:"subject,omitempty"`

	// Variables lists available template variables.
	Variables []ProfileVariable `json:"variables,omitempty"`
}

// ProfileSubjectConfig represents profile subject configuration.
type ProfileSubjectConfig struct {
	// Fixed are fixed subject values.
	Fixed map[string]string `json:"fixed,omitempty"`

	// Required are required subject fields.
	Required []string `json:"required,omitempty"`

	// Optional are optional subject fields.
	Optional []string `json:"optional,omitempty"`
}

// ProfileVariable represents a profile template variable.
type ProfileVariable struct {
	// Name is the variable name.
	Name string `json:"name"`

	// Description is the variable description.
	Description string `json:"description,omitempty"`

	// Type is the variable type: "string", "string[]", "int", "bool".
	Type string `json:"type"`

	// Required indicates if the variable is required.
	Required bool `json:"required"`

	// Default is the default value.
	Default interface{} `json:"default,omitempty"`

	// Validation contains validation rules.
	Validation *VariableValidation `json:"validation,omitempty"`
}

// VariableValidation contains variable validation rules.
type VariableValidation struct {
	// Pattern is a regex pattern.
	Pattern string `json:"pattern,omitempty"`

	// MinLength is the minimum length.
	MinLength int `json:"min_length,omitempty"`

	// MaxLength is the maximum length.
	MaxLength int `json:"max_length,omitempty"`

	// Enum lists allowed values.
	Enum []string `json:"enum,omitempty"`
}

// ProfileVarsResponse represents profile variables.
type ProfileVarsResponse struct {
	// Variables lists available variables.
	Variables []ProfileVariable `json:"variables"`
}

// ProfileValidateRequest represents a profile validation request.
type ProfileValidateRequest struct {
	// YAML is the profile YAML content.
	YAML string `json:"yaml"`
}

// ProfileValidateResponse represents profile validation result.
type ProfileValidateResponse struct {
	// Valid indicates if the profile is valid.
	Valid bool `json:"valid"`

	// Errors lists validation errors.
	Errors []string `json:"errors,omitempty"`

	// Warnings lists validation warnings.
	Warnings []string `json:"warnings,omitempty"`

	// Profile contains parsed profile info (if valid).
	Profile *ProfileInfoResponse `json:"profile,omitempty"`
}
