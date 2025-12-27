// Package profile provides type validators for certificate profile variables.
package profile

import (
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// TypeValidator validates and normalizes values for a specific variable type.
// Implement this interface to add custom variable types.
type TypeValidator interface {
	// Type returns the type identifier (e.g., "email", "uri").
	Type() VariableType

	// Validate checks if value is valid for this type.
	// The variable parameter provides access to constraints.
	// The ctx parameter provides pre-compiled patterns and parsed CIDR ranges.
	Validate(value interface{}, variable *Variable, ctx *ValidationContext) error

	// Normalize converts value to canonical form (e.g., lowercase email).
	// Returns the original value if no normalization is needed.
	Normalize(value interface{}) (interface{}, error)
}

// ValidationContext provides pre-compiled resources for validation.
// These are computed once when the validator is created.
type ValidationContext struct {
	// CompiledPattern is the pre-compiled regex pattern for this variable.
	CompiledPattern *regexp.Regexp

	// ParsedIPNets are the pre-parsed CIDR ranges for ip_list constraints.
	ParsedIPNets []*net.IPNet
}

var (
	typeValidatorsMu sync.RWMutex
	typeValidators   = make(map[VariableType]TypeValidator)
)

// RegisterType registers a type validator.
// This is typically called during package initialization.
func RegisterType(v TypeValidator) {
	typeValidatorsMu.Lock()
	defer typeValidatorsMu.Unlock()
	typeValidators[v.Type()] = v
}

// GetTypeValidator returns the validator for a type.
func GetTypeValidator(t VariableType) (TypeValidator, bool) {
	typeValidatorsMu.RLock()
	defer typeValidatorsMu.RUnlock()
	v, ok := typeValidators[t]
	return v, ok
}

// ListTypeValidators returns all registered type validators.
func ListTypeValidators() []VariableType {
	typeValidatorsMu.RLock()
	defer typeValidatorsMu.RUnlock()
	types := make([]VariableType, 0, len(typeValidators))
	for t := range typeValidators {
		types = append(types, t)
	}
	return types
}

// =============================================================================
// Built-in Type Validators
// =============================================================================

// EmailValidator validates email addresses per RFC 5322.
type EmailValidator struct{}

func (e *EmailValidator) Type() VariableType {
	return VarTypeEmail
}

func (e *EmailValidator) Validate(value interface{}, v *Variable, ctx *ValidationContext) error {
	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("expected string, got %T", value)
	}

	// RFC 5322 validation using net/mail
	addr, err := mail.ParseAddress(str)
	if err != nil {
		return fmt.Errorf("invalid email address: %w", err)
	}

	// Extract domain for constraint checking
	parts := strings.SplitN(addr.Address, "@", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid email format: missing @")
	}
	domain := strings.ToLower(parts[1])

	// Check domain constraints (allowed_suffixes)
	if v.Constraints != nil && len(v.Constraints.AllowedSuffixes) > 0 {
		valid := false
		for _, suffix := range v.Constraints.AllowedSuffixes {
			// Normalize: @example.com or example.com
			s := strings.TrimPrefix(strings.ToLower(suffix), "@")
			if strings.HasSuffix(domain, s) || domain == s {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("email domain %q not in allowed domains %v", domain, v.Constraints.AllowedSuffixes)
		}
	}

	// Check denied prefixes on local part
	if v.Constraints != nil && len(v.Constraints.DeniedPrefixes) > 0 {
		localPart := strings.ToLower(parts[0])
		for _, prefix := range v.Constraints.DeniedPrefixes {
			if strings.HasPrefix(localPart, strings.ToLower(prefix)) {
				return fmt.Errorf("email local part matches denied prefix %q", prefix)
			}
		}
	}

	return nil
}

func (e *EmailValidator) Normalize(value interface{}) (interface{}, error) {
	str, ok := value.(string)
	if !ok {
		return value, nil
	}
	// Lowercase the entire email (RFC 5321 recommends case-insensitive)
	return strings.ToLower(str), nil
}

// URIValidator validates URIs per RFC 3986.
type URIValidator struct{}

func (u *URIValidator) Type() VariableType {
	return VarTypeURI
}

func (u *URIValidator) Validate(value interface{}, v *Variable, ctx *ValidationContext) error {
	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("expected string, got %T", value)
	}

	// RFC 3986 validation
	parsed, err := url.Parse(str)
	if err != nil {
		return fmt.Errorf("invalid URI: %w", err)
	}

	// Must have scheme
	if parsed.Scheme == "" {
		return fmt.Errorf("URI must have a scheme (e.g., http://, https://)")
	}

	// Check allowed schemes
	if v.Constraints != nil && len(v.Constraints.AllowedSchemes) > 0 {
		valid := false
		for _, scheme := range v.Constraints.AllowedSchemes {
			if strings.EqualFold(parsed.Scheme, scheme) {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("URI scheme %q not in allowed schemes %v", parsed.Scheme, v.Constraints.AllowedSchemes)
		}
	}

	// Check allowed hosts
	if v.Constraints != nil && len(v.Constraints.AllowedHosts) > 0 {
		valid := false
		for _, host := range v.Constraints.AllowedHosts {
			if strings.EqualFold(parsed.Host, host) {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("URI host %q not in allowed hosts %v", parsed.Host, v.Constraints.AllowedHosts)
		}
	}

	return nil
}

func (u *URIValidator) Normalize(value interface{}) (interface{}, error) {
	str, ok := value.(string)
	if !ok {
		return value, nil
	}
	parsed, err := url.Parse(str)
	if err != nil {
		return str, nil
	}
	// Normalize scheme to lowercase
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	return parsed.String(), nil
}

// OIDValidator validates Object Identifiers (dot-notation).
type OIDValidator struct{}

func (o *OIDValidator) Type() VariableType {
	return VarTypeOID
}

// OID pattern: one or more integers separated by dots
// Examples: 1.2.3, 2.16.840.1.101.3.4.3.17
var oidPattern = regexp.MustCompile(`^\d+(\.\d+)+$`)

func (o *OIDValidator) Validate(value interface{}, v *Variable, ctx *ValidationContext) error {
	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("expected string, got %T", value)
	}

	if str == "" {
		return fmt.Errorf("OID cannot be empty")
	}

	// Validate OID format
	if !oidPattern.MatchString(str) {
		return fmt.Errorf("invalid OID format: %q (expected dot-notation like 1.2.3.4)", str)
	}

	// Validate each arc is a valid integer
	arcs := strings.Split(str, ".")
	for i, arc := range arcs {
		n, err := strconv.ParseUint(arc, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid OID arc %d: %q is not a valid integer", i, arc)
		}
		// First arc must be 0, 1, or 2
		if i == 0 && n > 2 {
			return fmt.Errorf("invalid OID: first arc must be 0, 1, or 2")
		}
		// Second arc under first arc 0 or 1 must be < 40
		if i == 1 && arcs[0] != "2" && n >= 40 {
			return fmt.Errorf("invalid OID: second arc must be < 40 when first arc is 0 or 1")
		}
	}

	// Check allowed prefixes if specified
	if v.Constraints != nil && len(v.Constraints.AllowedSuffixes) > 0 {
		// For OIDs, we use allowed_suffixes as allowed_prefixes
		valid := false
		for _, prefix := range v.Constraints.AllowedSuffixes {
			if strings.HasPrefix(str, prefix) {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("OID %q does not start with allowed prefixes %v", str, v.Constraints.AllowedSuffixes)
		}
	}

	return nil
}

func (o *OIDValidator) Normalize(value interface{}) (interface{}, error) {
	// OIDs don't need normalization
	return value, nil
}

// DurationValidator validates duration strings.
// Supports Go duration format (1h30m) plus d (days), w (weeks), y (years).
type DurationValidator struct{}

func (d *DurationValidator) Type() VariableType {
	return VarTypeDuration
}

func (d *DurationValidator) Validate(value interface{}, v *Variable, ctx *ValidationContext) error {
	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("expected string, got %T", value)
	}

	if str == "" {
		return fmt.Errorf("duration cannot be empty")
	}

	// Parse the duration
	dur, err := ParseDuration(str)
	if err != nil {
		return fmt.Errorf("invalid duration: %w", err)
	}

	// Check min/max constraints using string parsing
	if v.MinDuration != "" {
		minDur, err := ParseDuration(v.MinDuration)
		if err != nil {
			return fmt.Errorf("invalid min duration constraint: %w", err)
		}
		if dur < minDur {
			return fmt.Errorf("duration %s is below minimum %s", str, v.MinDuration)
		}
	}

	if v.MaxDuration != "" {
		maxDur, err := ParseDuration(v.MaxDuration)
		if err != nil {
			return fmt.Errorf("invalid max duration constraint: %w", err)
		}
		if dur > maxDur {
			return fmt.Errorf("duration %s exceeds maximum %s", str, v.MaxDuration)
		}
	}

	return nil
}

func (d *DurationValidator) Normalize(value interface{}) (interface{}, error) {
	// Durations don't need normalization
	return value, nil
}

// ParseDuration parses a duration string with extended format.
// Supports Go duration format plus: d (days), w (weeks), y (years).
// Examples: "1h30m", "365d", "1y", "2w", "30d12h"
func ParseDuration(s string) (time.Duration, error) {
	if s == "" {
		return 0, fmt.Errorf("empty duration string")
	}

	// First, try standard Go duration
	if dur, err := time.ParseDuration(s); err == nil {
		return dur, nil
	}

	// Handle extended format with d, w, y
	var total time.Duration
	var current string
	for _, r := range s {
		switch r {
		case 'y', 'Y':
			n, err := strconv.ParseFloat(current, 64)
			if err != nil {
				return 0, fmt.Errorf("invalid year value: %s", current)
			}
			total += time.Duration(n * 365 * 24 * float64(time.Hour))
			current = ""
		case 'w', 'W':
			n, err := strconv.ParseFloat(current, 64)
			if err != nil {
				return 0, fmt.Errorf("invalid week value: %s", current)
			}
			total += time.Duration(n * 7 * 24 * float64(time.Hour))
			current = ""
		case 'd', 'D':
			n, err := strconv.ParseFloat(current, 64)
			if err != nil {
				return 0, fmt.Errorf("invalid day value: %s", current)
			}
			total += time.Duration(n * 24 * float64(time.Hour))
			current = ""
		case 'h', 'H', 'm', 'M', 's', 'S':
			// Standard Go duration unit - accumulate and parse at end
			current += string(r)
		default:
			current += string(r)
		}
	}

	// Parse remaining as Go duration
	if current != "" {
		dur, err := time.ParseDuration(current)
		if err != nil {
			return 0, fmt.Errorf("invalid duration: %s", current)
		}
		total += dur
	}

	if total == 0 && s != "0" && s != "0s" {
		return 0, fmt.Errorf("invalid duration format: %s", s)
	}

	return total, nil
}

// =============================================================================
// Registration
// =============================================================================

func init() {
	// Register built-in validators
	RegisterType(&EmailValidator{})
	RegisterType(&URIValidator{})
	RegisterType(&OIDValidator{})
	RegisterType(&DurationValidator{})
}
