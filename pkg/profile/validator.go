// Package profile provides variable validation for certificate profiles.
package profile

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// VariableValidator validates user-provided values against variable constraints.
// All expensive operations (regex compilation, CIDR parsing) are done once
// when the validator is created, not during validation.
type VariableValidator struct {
	variables map[string]*Variable

	// Pre-compiled regex patterns (one per variable with a pattern)
	compiled map[string]*regexp.Regexp

	// Pre-parsed CIDR ranges (for ip_list constraints)
	ipNets map[string][]*net.IPNet
}

// NewVariableValidator creates a new validator for the given variables.
// It pre-compiles all regex patterns and pre-parses all CIDR ranges.
func NewVariableValidator(vars map[string]*Variable) (*VariableValidator, error) {
	v := &VariableValidator{
		variables: vars,
		compiled:  make(map[string]*regexp.Regexp),
		ipNets:    make(map[string][]*net.IPNet),
	}

	// Pre-compile all patterns at load time
	for name, variable := range vars {
		if variable.Pattern != "" {
			re, err := regexp.Compile(variable.Pattern)
			if err != nil {
				return nil, fmt.Errorf("variable %s: invalid pattern %q: %w", name, variable.Pattern, err)
			}
			v.compiled[name] = re
		}

		// Pre-parse CIDR ranges for ip_list constraints
		if variable.Type == VarTypeIPList && variable.Constraints != nil {
			for _, cidr := range variable.Constraints.AllowedRanges {
				_, ipNet, err := net.ParseCIDR(cidr)
				if err != nil {
					return nil, fmt.Errorf("variable %s: invalid CIDR %q: %w", name, cidr, err)
				}
				v.ipNets[name] = append(v.ipNets[name], ipNet)
			}
		}
	}

	return v, nil
}

// Validate validates a single variable value.
func (v *VariableValidator) Validate(name string, value interface{}) error {
	variable, ok := v.variables[name]
	if !ok {
		return fmt.Errorf("unknown variable: %s", name)
	}

	// Nil value is only ok if variable has a default
	if value == nil {
		if variable.Required && !variable.HasDefault() {
			return fmt.Errorf("%s: required variable not provided", name)
		}
		return nil
	}

	// Validate based on type
	switch variable.Type {
	case VarTypeString:
		return v.validateString(name, variable, value)
	case VarTypeInteger:
		return v.validateInteger(name, variable, value)
	case VarTypeBoolean:
		return v.validateBoolean(name, value)
	case VarTypeList:
		return v.validateList(name, variable, value)
	case VarTypeIPList:
		return v.validateIPList(name, variable, value)
	case VarTypeDNSName:
		return v.validateDNSName(name, variable, value)
	case VarTypeDNSNames:
		return v.validateDNSNames(name, variable, value)
	case VarTypeEmail, VarTypeURI, VarTypeOID, VarTypeDuration:
		// Use the type validator registry for extensible types
		return v.validateWithRegistry(name, variable, value)
	default:
		return fmt.Errorf("%s: unknown variable type: %s", name, variable.Type)
	}
}

// validateWithRegistry validates a value using the TypeValidator registry.
func (v *VariableValidator) validateWithRegistry(name string, variable *Variable, value interface{}) error {
	validator, ok := GetTypeValidator(variable.Type)
	if !ok {
		return fmt.Errorf("%s: no validator registered for type %s", name, variable.Type)
	}

	// Build validation context
	ctx := &ValidationContext{
		CompiledPattern: v.compiled[name],
		ParsedIPNets:    v.ipNets[name],
	}

	// Validate
	if err := validator.Validate(value, variable, ctx); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}

	return nil
}

// ValidateAll validates all provided values and checks for required variables.
// Returns the first validation error encountered.
func (v *VariableValidator) ValidateAll(values VariableValues) error {
	// Check each provided value
	for name, value := range values {
		if err := v.Validate(name, value); err != nil {
			return err
		}
	}

	// Check that all required variables are provided
	for name, variable := range v.variables {
		if variable.Required && !variable.HasDefault() {
			if _, ok := values[name]; !ok {
				return fmt.Errorf("required variable %q not provided", name)
			}
		}
	}

	return nil
}

// MergeWithDefaults merges user-provided values with default values.
// Returns a new map with all variables resolved.
func (v *VariableValidator) MergeWithDefaults(values VariableValues) VariableValues {
	result := make(VariableValues, len(v.variables))

	// Start with defaults
	for name, variable := range v.variables {
		if variable.HasDefault() {
			result[name] = variable.Default
		}
	}

	// Override with user values
	for name, value := range values {
		result[name] = value
	}

	return result
}

func (v *VariableValidator) validateString(name string, variable *Variable, value interface{}) error {
	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("%s: expected string, got %T", name, value)
	}

	// Pattern check (using pre-compiled regex)
	if re, ok := v.compiled[name]; ok {
		if !re.MatchString(str) {
			return fmt.Errorf("%s: value %q does not match pattern %q", name, str, variable.Pattern)
		}
	}

	// Enum check
	if len(variable.Enum) > 0 {
		valid := false
		for _, e := range variable.Enum {
			if str == e {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("%s: value %q not in allowed values %v", name, str, variable.Enum)
		}
	}

	// Length checks
	if variable.MinLength > 0 && len(str) < variable.MinLength {
		return fmt.Errorf("%s: length %d below minimum %d", name, len(str), variable.MinLength)
	}
	if variable.MaxLength > 0 && len(str) > variable.MaxLength {
		return fmt.Errorf("%s: length %d exceeds maximum %d", name, len(str), variable.MaxLength)
	}

	return nil
}

func (v *VariableValidator) validateInteger(name string, variable *Variable, value interface{}) error {
	var intVal int

	switch i := value.(type) {
	case int:
		intVal = i
	case float64:
		intVal = int(i)
	default:
		return fmt.Errorf("%s: expected integer, got %T", name, value)
	}

	// Min check
	if variable.Min != nil && intVal < *variable.Min {
		return fmt.Errorf("%s: value %d below minimum %d", name, intVal, *variable.Min)
	}

	// Max check
	if variable.Max != nil && intVal > *variable.Max {
		return fmt.Errorf("%s: value %d exceeds maximum %d", name, intVal, *variable.Max)
	}

	// Enum check (for integer enums, compare as strings)
	if len(variable.Enum) > 0 {
		strVal := fmt.Sprintf("%d", intVal)
		valid := false
		for _, e := range variable.Enum {
			if strVal == e {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("%s: value %d not in allowed values %v", name, intVal, variable.Enum)
		}
	}

	return nil
}

func (v *VariableValidator) validateBoolean(name string, value interface{}) error {
	_, ok := value.(bool)
	if !ok {
		return fmt.Errorf("%s: expected boolean, got %T", name, value)
	}
	return nil
}

// toStringList converts various value types to a string slice.
func toStringList(name string, value interface{}) ([]string, error) {
	switch l := value.(type) {
	case []string:
		return l, nil
	case string:
		return []string{l}, nil
	case []interface{}:
		list := make([]string, 0, len(l))
		for _, item := range l {
			if s, ok := item.(string); ok {
				list = append(list, s)
			} else {
				return nil, fmt.Errorf("%s: list item is not a string: %T", name, item)
			}
		}
		return list, nil
	default:
		return nil, fmt.Errorf("%s: expected list, got %T", name, value)
	}
}

// validateListItemCount validates min/max item count constraints.
func validateListItemCount(name string, list []string, c *ListConstraints, itemType string) error {
	if c.MinItems > 0 && len(list) < c.MinItems {
		return fmt.Errorf("%s: need at least %d %s, got %d", name, c.MinItems, itemType, len(list))
	}
	if c.MaxItems > 0 && len(list) > c.MaxItems {
		return fmt.Errorf("%s: max %d %s allowed, got %d", name, c.MaxItems, itemType, len(list))
	}
	return nil
}

func (v *VariableValidator) validateList(name string, variable *Variable, value interface{}) error {
	var list []string

	switch l := value.(type) {
	case []string:
		list = l
	case string:
		// Single string value - convert to list with one element
		list = []string{l}
	case []interface{}:
		list = make([]string, 0, len(l))
		for _, item := range l {
			if s, ok := item.(string); ok {
				list = append(list, s)
			} else {
				return fmt.Errorf("%s: list item is not a string: %T", name, item)
			}
		}
	default:
		return fmt.Errorf("%s: expected list, got %T", name, value)
	}

	c := variable.Constraints
	if c == nil {
		return nil
	}

	// Item count checks
	if c.MinItems > 0 && len(list) < c.MinItems {
		return fmt.Errorf("%s: need at least %d items, got %d", name, c.MinItems, len(list))
	}
	if c.MaxItems > 0 && len(list) > c.MaxItems {
		return fmt.Errorf("%s: max %d items allowed, got %d", name, c.MaxItems, len(list))
	}

	// Check each item
	for _, item := range list {
		// Suffix check
		if len(c.AllowedSuffixes) > 0 {
			valid := false
			for _, suffix := range c.AllowedSuffixes {
				if strings.HasSuffix(item, suffix) {
					valid = true
					break
				}
			}
			if !valid {
				return fmt.Errorf("%s: %q does not match allowed suffixes %v", name, item, c.AllowedSuffixes)
			}
		}

		// Prefix deny check
		for _, prefix := range c.DeniedPrefixes {
			if strings.HasPrefix(item, prefix) {
				return fmt.Errorf("%s: %q matches denied prefix %q", name, item, prefix)
			}
		}
	}

	return nil
}

func (v *VariableValidator) validateIPList(name string, variable *Variable, value interface{}) error {
	var list []string

	switch l := value.(type) {
	case []string:
		list = l
	case string:
		// Single string value - convert to list with one element
		list = []string{l}
	case []interface{}:
		list = make([]string, 0, len(l))
		for _, item := range l {
			if s, ok := item.(string); ok {
				list = append(list, s)
			} else {
				return fmt.Errorf("%s: list item is not a string: %T", name, item)
			}
		}
	default:
		return fmt.Errorf("%s: expected ip_list, got %T", name, value)
	}

	c := variable.Constraints
	if c == nil {
		c = &ListConstraints{}
	}

	// Item count checks
	if c.MinItems > 0 && len(list) < c.MinItems {
		return fmt.Errorf("%s: need at least %d IPs, got %d", name, c.MinItems, len(list))
	}
	if c.MaxItems > 0 && len(list) > c.MaxItems {
		return fmt.Errorf("%s: max %d IPs allowed, got %d", name, c.MaxItems, len(list))
	}

	// Pre-parsed allowed ranges
	allowedRanges := v.ipNets[name]

	// Validate each IP
	for _, ipStr := range list {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return fmt.Errorf("%s: invalid IP address %q", name, ipStr)
		}

		// Check against allowed ranges (if any)
		if len(allowedRanges) > 0 {
			valid := false
			for _, ipNet := range allowedRanges {
				if ipNet.Contains(ip) {
					valid = true
					break
				}
			}
			if !valid {
				return fmt.Errorf("%s: IP %q not in allowed ranges %v", name, ipStr, c.AllowedRanges)
			}
		}
	}

	return nil
}

func (v *VariableValidator) validateDNSName(name string, variable *Variable, value interface{}) error {
	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("%s: expected string, got %T", name, value)
	}

	// Validate DNS format with options
	if err := ValidateDNSNameWithOptions(str, variable.AllowSingleLabel); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}

	// Validate wildcard policy
	if err := ValidateWildcard(str, variable.Wildcard); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}

	// Also apply string constraints (pattern, enum, length) if specified
	// Use normalized value for pattern matching
	normalizedValue := NormalizeDNSName(str)
	return v.validateString(name, variable, normalizedValue)
}

func (v *VariableValidator) validateDNSNames(name string, variable *Variable, value interface{}) error {
	list, err := toStringList(name, value)
	if err != nil {
		return err
	}

	c := variable.Constraints
	if c == nil {
		c = &ListConstraints{}
	}

	if err := validateListItemCount(name, list, c, "DNS names"); err != nil {
		return err
	}

	for _, dnsName := range list {
		if err := validateSingleDNSName(name, dnsName, variable, c); err != nil {
			return err
		}
	}

	return nil
}

// validateSingleDNSName validates a single DNS name against all constraints.
func validateSingleDNSName(name, dnsName string, variable *Variable, c *ListConstraints) error {
	normalizedDNS := NormalizeDNSName(dnsName)

	if err := ValidateDNSNameWithOptions(dnsName, variable.AllowSingleLabel); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}

	if err := ValidateWildcard(dnsName, variable.Wildcard); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}

	if err := validateDNSSuffix(name, dnsName, normalizedDNS, c.AllowedSuffixes); err != nil {
		return err
	}

	if err := validateDeniedPrefixes(name, dnsName, normalizedDNS, c.DeniedPrefixes); err != nil {
		return err
	}

	return nil
}

// validateDNSSuffix checks if DNS name matches allowed suffixes on label boundary.
func validateDNSSuffix(name, dnsName, normalizedDNS string, allowedSuffixes []string) error {
	if len(allowedSuffixes) == 0 {
		return nil
	}
	for _, suffix := range allowedSuffixes {
		if matchesSuffixOnLabelBoundary(normalizedDNS, suffix) {
			return nil
		}
	}
	return fmt.Errorf("%s: %q does not match allowed suffixes %v", name, dnsName, allowedSuffixes)
}

// validateDeniedPrefixes checks if DNS name matches any denied prefix.
func validateDeniedPrefixes(name, dnsName, normalizedDNS string, deniedPrefixes []string) error {
	for _, prefix := range deniedPrefixes {
		if strings.HasPrefix(normalizedDNS, strings.ToLower(prefix)) {
			return fmt.Errorf("%s: %q matches denied prefix %q", name, dnsName, prefix)
		}
	}
	return nil
}

// matchesSuffixOnLabelBoundary checks if a DNS name matches a suffix on a label boundary.
// This prevents "fakeexample.com" from matching suffix ".example.com".
//
// Examples:
//   - "api.example.com" matches ".example.com" ✓
//   - "fakeexample.com" does NOT match ".example.com" ✗
//   - "example.com" matches ".example.com" ✓ (exact match minus the dot)
func matchesSuffixOnLabelBoundary(dnsName, suffix string) bool {
	// Normalize both to lowercase
	dnsName = strings.ToLower(dnsName)
	suffix = strings.ToLower(suffix)

	// If suffix starts with a dot, it must match on a label boundary
	if strings.HasPrefix(suffix, ".") {
		// Check if dnsName ends with the suffix (including the dot)
		if strings.HasSuffix(dnsName, suffix) {
			return true
		}
		// Also check if dnsName equals the suffix without the leading dot
		// e.g., "example.com" should match ".example.com"
		if dnsName == suffix[1:] {
			return true
		}
		return false
	}

	// If suffix doesn't start with a dot, add one for label boundary check
	// e.g., suffix "example.com" should match "api.example.com" on boundary
	if strings.HasSuffix(dnsName, "."+suffix) {
		return true
	}
	// Exact match
	if dnsName == suffix {
		return true
	}

	return false
}

// NormalizeDNSName normalizes a DNS name:
//   - Converts to lowercase (RFC 4343: DNS is case-insensitive)
//   - Strips trailing dot (FQDN absolute form)
//
// Returns the normalized name.
func NormalizeDNSName(name string) string {
	// Lowercase (RFC 4343)
	name = strings.ToLower(name)

	// Strip trailing dot (FQDN absolute form)
	name = strings.TrimSuffix(name, ".")

	return name
}

// ValidateDNSName validates a DNS name according to RFC 1035/1123.
// It checks:
//   - Total length ≤ 253 characters
//   - Each label ≤ 63 characters
//   - No empty labels (double dots)
//   - Valid characters (alphanumeric, hyphen)
//   - Labels don't start or end with hyphen
//   - Wildcards are allowed in leftmost position only (validated separately)
//
// Note: This function requires at least 2 labels. Use ValidateDNSNameWithOptions
// for single-label support.
func ValidateDNSName(name string) error {
	return ValidateDNSNameWithOptions(name, false)
}

// ValidateDNSNameWithOptions validates a DNS name with configurable options.
// If allowSingleLabel is true, single-label names like "localhost" are allowed.
func ValidateDNSNameWithOptions(name string, allowSingleLabel bool) error {
	if name == "" {
		return fmt.Errorf("DNS name cannot be empty")
	}

	// Normalize before validation
	name = NormalizeDNSName(name)

	// RFC 1035: total DNS name ≤ 253 characters
	if len(name) > 253 {
		return fmt.Errorf("DNS name too long: %d > 253 characters", len(name))
	}

	labels := strings.Split(name, ".")

	// Check minimum labels
	minLabels := 2
	if allowSingleLabel {
		minLabels = 1
	}
	if len(labels) < minLabels {
		if allowSingleLabel {
			return fmt.Errorf("DNS name must have at least 1 label: %q", name)
		}
		return fmt.Errorf("DNS name must have at least 2 labels: %q", name)
	}

	for i, label := range labels {
		// Check for empty label (double dot or leading/trailing dot)
		if label == "" {
			return fmt.Errorf("empty label in DNS name (double dot or leading/trailing dot)")
		}

		// RFC 1035: label ≤ 63 characters
		if len(label) > 63 {
			return fmt.Errorf("label too long: %q (%d > 63 characters)", label, len(label))
		}

		// Wildcard is only valid in leftmost position
		if label == "*" {
			if i != 0 {
				return fmt.Errorf("wildcard (*) must be leftmost label")
			}
			continue // Skip other validation for wildcard label
		}

		// Validate label characters (RFC 1123: alphanumeric and hyphen)
		if !isValidDNSLabel(label) {
			return fmt.Errorf("invalid DNS label %q: must contain only alphanumeric characters and hyphens, and not start or end with a hyphen", label)
		}
	}

	return nil
}

// isValidDNSLabel checks if a DNS label is valid per RFC 1123.
// Valid labels contain only alphanumeric characters and hyphens,
// and don't start or end with a hyphen.
func isValidDNSLabel(label string) bool {
	if len(label) == 0 {
		return false
	}

	// Can't start or end with hyphen
	if label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}

	// Check all characters
	for _, c := range label {
		isLower := c >= 'a' && c <= 'z'
		isUpper := c >= 'A' && c <= 'Z'
		isDigit := c >= '0' && c <= '9'
		isHyphen := c == '-'
		if !isLower && !isUpper && !isDigit && !isHyphen {
			return false
		}
	}

	return true
}

// ValidateWildcard validates a DNS name against a wildcard policy (RFC 6125).
// If policy is nil, wildcards are not allowed (default safe behavior).
func ValidateWildcard(name string, policy *WildcardPolicy) error {
	// Normalize before validation
	name = NormalizeDNSName(name)

	labels := strings.Split(name, ".")

	// Find wildcard position
	wildcardPos := -1
	for i, label := range labels {
		if label == "*" {
			if wildcardPos >= 0 {
				return fmt.Errorf("multiple wildcards not allowed: %q", name)
			}
			wildcardPos = i
		}
	}

	// No wildcard, nothing to validate
	if wildcardPos < 0 {
		return nil
	}

	// Check if wildcards are allowed
	if policy == nil || !policy.Allowed {
		return fmt.Errorf("wildcards not allowed: %q", name)
	}

	// RFC 6125: wildcard must be leftmost label
	if wildcardPos != 0 {
		return fmt.Errorf("wildcard must be leftmost label: %q", name)
	}

	// Minimum: *.domain.tld (3 labels)
	// Prevents *.com or *.co.uk which would be too broad
	if len(labels) < 3 {
		return fmt.Errorf("wildcard requires at least 3 labels (*.domain.tld): %q has only %d", name, len(labels))
	}

	// Check for public suffix if forbidden
	if policy.ForbidPublicSuffix {
		// Get the base domain (without wildcard)
		baseDomain := strings.Join(labels[1:], ".")

		// Check if the base domain IS a public suffix
		// e.g., for *.co.uk, baseDomain = "co.uk" which is a public suffix
		suffix, icann := publicsuffix.PublicSuffix(baseDomain)

		// If the suffix equals the entire baseDomain, it's a public suffix
		// This means *.co.uk would have baseDomain="co.uk" and suffix="co.uk"
		if icann && suffix == baseDomain {
			return fmt.Errorf("wildcard on public suffix not allowed: %q (public suffix: %q)", name, suffix)
		}
	}

	return nil
}

// Variables returns the map of variables this validator checks.
func (v *VariableValidator) Variables() map[string]*Variable {
	return v.variables
}

// HasVariable returns true if the validator has the named variable.
func (v *VariableValidator) HasVariable(name string) bool {
	_, ok := v.variables[name]
	return ok
}

// GetVariable returns the variable definition for the given name.
func (v *VariableValidator) GetVariable(name string) (*Variable, bool) {
	variable, ok := v.variables[name]
	return variable, ok
}

// RequiredVariables returns the names of all required variables.
func (v *VariableValidator) RequiredVariables() []string {
	var required []string
	for name, variable := range v.variables {
		if variable.Required && !variable.HasDefault() {
			required = append(required, name)
		}
	}
	return required
}
