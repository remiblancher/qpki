package profile

import (
	"errors"
	"testing"
)

// =============================================================================
// Unit Tests: ProfileError
// =============================================================================

func TestU_ProfileError_Error_WithName(t *testing.T) {
	underlying := errors.New("something went wrong")
	err := &ProfileError{
		Name: "test-profile",
		Err:  underlying,
	}

	expected := `profile "test-profile": something went wrong`
	if err.Error() != expected {
		t.Errorf("ProfileError.Error() = %q, want %q", err.Error(), expected)
	}
}

func TestU_ProfileError_Error_WithoutName(t *testing.T) {
	underlying := errors.New("something went wrong")
	err := &ProfileError{
		Name: "",
		Err:  underlying,
	}

	expected := "profile: something went wrong"
	if err.Error() != expected {
		t.Errorf("ProfileError.Error() = %q, want %q", err.Error(), expected)
	}
}

func TestU_ProfileError_Unwrap(t *testing.T) {
	underlying := errors.New("underlying error")
	err := &ProfileError{
		Name: "test-profile",
		Err:  underlying,
	}

	if err.Unwrap() != underlying {
		t.Error("ProfileError.Unwrap() should return the underlying error")
	}
}

func TestU_ProfileError_Unwrap_Nil(t *testing.T) {
	err := &ProfileError{
		Name: "test-profile",
		Err:  nil,
	}

	if err.Unwrap() != nil {
		t.Error("ProfileError.Unwrap() should return nil when Err is nil")
	}
}

func TestU_ProfileError_ErrorsIs(t *testing.T) {
	underlying := ErrProfileNotFound
	err := &ProfileError{
		Name: "test-profile",
		Err:  underlying,
	}

	if !errors.Is(err, ErrProfileNotFound) {
		t.Error("errors.Is() should match the underlying error")
	}
}

func TestU_NewProfileError(t *testing.T) {
	underlying := errors.New("test error")
	err := NewProfileError("my-profile", underlying)

	if err == nil {
		t.Fatal("NewProfileError() returned nil")
	}

	if err.Name != "my-profile" {
		t.Errorf("NewProfileError().Name = %q, want %q", err.Name, "my-profile")
	}

	if err.Err != underlying {
		t.Error("NewProfileError().Err should be the underlying error")
	}

	expected := `profile "my-profile": test error`
	if err.Error() != expected {
		t.Errorf("NewProfileError().Error() = %q, want %q", err.Error(), expected)
	}
}

func TestU_NewProfileError_EmptyName(t *testing.T) {
	underlying := errors.New("test error")
	err := NewProfileError("", underlying)

	expected := "profile: test error"
	if err.Error() != expected {
		t.Errorf("NewProfileError().Error() = %q, want %q", err.Error(), expected)
	}
}

// =============================================================================
// Unit Tests: ValidationError
// =============================================================================

func TestU_ValidationError_Error_WithValue(t *testing.T) {
	err := &ValidationError{
		Field:   "algorithm",
		Value:   "invalid-algo",
		Message: "algorithm not supported",
	}

	expected := `validation failed for algorithm="invalid-algo": algorithm not supported`
	if err.Error() != expected {
		t.Errorf("ValidationError.Error() = %q, want %q", err.Error(), expected)
	}
}

func TestU_ValidationError_Error_WithoutValue(t *testing.T) {
	err := &ValidationError{
		Field:   "keyUsage",
		Value:   "",
		Message: "must not be empty",
	}

	expected := "validation failed for keyUsage: must not be empty"
	if err.Error() != expected {
		t.Errorf("ValidationError.Error() = %q, want %q", err.Error(), expected)
	}
}

func TestU_NewValidationError(t *testing.T) {
	err := NewValidationError("validity", "365d", "exceeds maximum allowed")

	if err == nil {
		t.Fatal("NewValidationError() returned nil")
	}

	if err.Field != "validity" {
		t.Errorf("NewValidationError().Field = %q, want %q", err.Field, "validity")
	}

	if err.Value != "365d" {
		t.Errorf("NewValidationError().Value = %q, want %q", err.Value, "365d")
	}

	if err.Message != "exceeds maximum allowed" {
		t.Errorf("NewValidationError().Message = %q, want %q", err.Message, "exceeds maximum allowed")
	}

	expected := `validation failed for validity="365d": exceeds maximum allowed`
	if err.Error() != expected {
		t.Errorf("NewValidationError().Error() = %q, want %q", err.Error(), expected)
	}
}

func TestU_NewValidationError_EmptyValue(t *testing.T) {
	err := NewValidationError("cn", "", "required field")

	expected := "validation failed for cn: required field"
	if err.Error() != expected {
		t.Errorf("NewValidationError().Error() = %q, want %q", err.Error(), expected)
	}
}

// =============================================================================
// Unit Tests: Sentinel Errors
// =============================================================================

func TestU_SentinelErrors_AreDistinct(t *testing.T) {
	sentinels := []error{
		ErrProfileNotFound,
		ErrInvalidProfile,
		ErrExtensionInvalid,
		ErrExtensionConflict,
		ErrConstraintViolation,
		ErrTemplateInvalid,
		ErrVariableUndefined,
		ErrVariableInvalid,
		ErrKeyUsageInvalid,
		ErrValidityInvalid,
	}

	// Check that each sentinel is distinct
	for i, err1 := range sentinels {
		for j, err2 := range sentinels {
			if i != j && errors.Is(err1, err2) {
				t.Errorf("Sentinel errors %d and %d should not be equal", i, j)
			}
		}
	}
}

func TestU_SentinelErrors_CanBeWrapped(t *testing.T) {
	tests := []struct {
		name     string
		sentinel error
	}{
		{"ErrProfileNotFound", ErrProfileNotFound},
		{"ErrInvalidProfile", ErrInvalidProfile},
		{"ErrExtensionInvalid", ErrExtensionInvalid},
		{"ErrExtensionConflict", ErrExtensionConflict},
		{"ErrConstraintViolation", ErrConstraintViolation},
		{"ErrTemplateInvalid", ErrTemplateInvalid},
		{"ErrVariableUndefined", ErrVariableUndefined},
		{"ErrVariableInvalid", ErrVariableInvalid},
		{"ErrKeyUsageInvalid", ErrKeyUsageInvalid},
		{"ErrValidityInvalid", ErrValidityInvalid},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapped := &ProfileError{Name: "test", Err: tt.sentinel}
			if !errors.Is(wrapped, tt.sentinel) {
				t.Errorf("Wrapped %s should match via errors.Is()", tt.name)
			}
		})
	}
}

func TestU_SentinelErrors_HaveMessages(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{"ErrProfileNotFound", ErrProfileNotFound, "profile not found"},
		{"ErrInvalidProfile", ErrInvalidProfile, "invalid profile configuration"},
		{"ErrExtensionInvalid", ErrExtensionInvalid, "invalid extension"},
		{"ErrExtensionConflict", ErrExtensionConflict, "extension conflict"},
		{"ErrConstraintViolation", ErrConstraintViolation, "constraint violation"},
		{"ErrTemplateInvalid", ErrTemplateInvalid, "invalid template"},
		{"ErrVariableUndefined", ErrVariableUndefined, "undefined variable"},
		{"ErrVariableInvalid", ErrVariableInvalid, "invalid variable value"},
		{"ErrKeyUsageInvalid", ErrKeyUsageInvalid, "invalid key usage"},
		{"ErrValidityInvalid", ErrValidityInvalid, "invalid validity period"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Error() != tt.expected {
				t.Errorf("%s.Error() = %q, want %q", tt.name, tt.err.Error(), tt.expected)
			}
		})
	}
}
