package main

import (
	"testing"
)

// =============================================================================
// HSM Helper Unit Tests
// =============================================================================

func TestU_MaskSerial(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "Short serial (1 char)",
			input:    "A",
			expected: "A",
		},
		{
			name:     "Short serial (2 chars)",
			input:    "AB",
			expected: "AB",
		},
		{
			name:     "Short serial (3 chars)",
			input:    "ABC",
			expected: "ABC",
		},
		{
			name:     "Short serial (4 chars)",
			input:    "ABCD",
			expected: "ABCD",
		},
		{
			name:     "5 char serial - minimal masking",
			input:    "ABCDE",
			expected: "ABC*E",
		},
		{
			name:     "8 char serial",
			input:    "12345678",
			expected: "123****8",
		},
		{
			name:     "16 char serial (typical HSM)",
			input:    "1234567890ABCDEF",
			expected: "123************F",
		},
		{
			name:     "Serial with spaces (trimmed)",
			input:    "  ABCDEF  ",
			expected: "ABC**F",
		},
		{
			name:     "Serial with leading spaces",
			input:    "   12345678",
			expected: "123****8",
		},
		{
			name:     "Serial with trailing spaces",
			input:    "12345678   ",
			expected: "123****8",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := maskSerial(tt.input)
			if result != tt.expected {
				t.Errorf("maskSerial(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// =============================================================================
// HSM Command Flag Reset
// =============================================================================

func resetHSMFlags() {
	hsmListConfigPath = ""
	hsmConfigPath = ""
	hsmInfoConfigPath = ""
}

// =============================================================================
// HSM List Tests (Error Cases)
// =============================================================================

func TestF_HSM_List_ConfigMissing(t *testing.T) {
	resetHSMFlags()

	_, err := executeCommand(rootCmd, "hsm", "list")

	assertError(t, err) // --hsm-config is required
}

func TestF_HSM_List_ConfigNotFound(t *testing.T) {
	tc := newTestContext(t)
	resetHSMFlags()

	_, err := executeCommand(rootCmd, "hsm", "list",
		"--hsm-config", tc.path("nonexistent.yaml"),
	)

	assertError(t, err) // Config file not found
}

func TestF_HSM_List_ConfigInvalid(t *testing.T) {
	tc := newTestContext(t)
	resetHSMFlags()

	// Create an invalid YAML config
	tc.writeFile("hsm-list.yaml", "not valid yaml: [")

	_, err := executeCommand(rootCmd, "hsm", "list",
		"--hsm-config", tc.path("hsm-list.yaml"),
	)

	assertError(t, err) // Invalid YAML
}

// =============================================================================
// HSM Test Command Tests (Error Cases)
// =============================================================================

func TestF_HSM_Test_ConfigMissing(t *testing.T) {
	resetHSMFlags()

	_, err := executeCommand(rootCmd, "hsm", "test")

	assertError(t, err) // --hsm-config is required
}

func TestF_HSM_Test_ConfigNotFound(t *testing.T) {
	tc := newTestContext(t)
	resetHSMFlags()

	_, err := executeCommand(rootCmd, "hsm", "test",
		"--hsm-config", tc.path("nonexistent.yaml"),
	)

	assertError(t, err) // Config file not found
}

func TestF_HSM_Test_ConfigInvalid(t *testing.T) {
	tc := newTestContext(t)
	resetHSMFlags()

	// Create an invalid YAML config
	tc.writeFile("hsm.yaml", "invalid: [yaml: content")

	_, err := executeCommand(rootCmd, "hsm", "test",
		"--hsm-config", tc.path("hsm.yaml"),
	)

	assertError(t, err) // Invalid YAML
}

// =============================================================================
// HSM Info Command Tests (Error Cases)
// =============================================================================

func TestF_HSM_Info_ConfigMissing(t *testing.T) {
	resetHSMFlags()

	_, err := executeCommand(rootCmd, "hsm", "info")

	assertError(t, err) // --hsm-config is required
}

func TestF_HSM_Info_ConfigNotFound(t *testing.T) {
	tc := newTestContext(t)
	resetHSMFlags()

	_, err := executeCommand(rootCmd, "hsm", "info",
		"--hsm-config", tc.path("nonexistent.yaml"),
	)

	assertError(t, err) // Config file not found
}

func TestF_HSM_Info_ConfigInvalid(t *testing.T) {
	tc := newTestContext(t)
	resetHSMFlags()

	// Create an invalid YAML config
	tc.writeFile("hsm-info.yaml", "not valid yaml: [")

	_, err := executeCommand(rootCmd, "hsm", "info",
		"--hsm-config", tc.path("hsm-info.yaml"),
	)

	assertError(t, err) // Invalid YAML
}
