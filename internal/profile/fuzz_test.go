package profile

import (
	"strings"
	"testing"
)

// =============================================================================
// YAML Profile Parsing Fuzz Tests
// =============================================================================

// FuzzLoadProfileFromBytes tests YAML profile parsing with arbitrary data.
// This catches panics from malformed YAML that could crash the CA.
func FuzzLoadProfileFromBytes(f *testing.F) {
	// Valid profiles
	f.Add([]byte(`name: test
algorithm: ecdsa-p256
validity: 365d`))

	f.Add([]byte(`name: catalyst-test
mode: catalyst
algorithms:
  - ecdsa-p384
  - ml-dsa-65
validity: 1y`))

	// Edge cases
	f.Add([]byte(``))                     // Empty
	f.Add([]byte(`{}`))                   // Empty object
	f.Add([]byte(`[]`))                   // Array instead of object
	f.Add([]byte(`name: [[[`))            // Malformed
	f.Add([]byte(`name: null`))           // Null value
	f.Add([]byte(`validity: -1d`))        // Negative duration
	f.Add([]byte(`validity: 999999999y`)) // Huge duration

	// YAML bombs / pathological cases
	f.Add([]byte(`a: &a [*a, *a, *a, *a]`))            // Circular reference
	f.Add([]byte(strings.Repeat("key: value\n", 100))) // Many keys (kept small for fast seed tests)

	// Type confusion
	f.Add([]byte(`name: 12345`))
	f.Add([]byte(`algorithm: [1, 2, 3]`))
	f.Add([]byte(`validity: {nested: true}`))
	f.Add([]byte(`extensions:
  key_usage: not-a-list`))

	// Injection attempts
	f.Add([]byte(`name: "{{ .Env.SECRET }}"`))
	f.Add([]byte(`name: "$(whoami)"`))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should not panic regardless of input
		_, _ = LoadProfileFromBytes(data)
	})
}

// =============================================================================
// Duration Parsing Fuzz Tests
// =============================================================================

// FuzzParseDuration tests duration string parsing.
func FuzzParseDuration(f *testing.F) {
	// Valid durations
	f.Add("1h")
	f.Add("24h")
	f.Add("365d")
	f.Add("1y")
	f.Add("1y6m")
	f.Add("30d12h")
	f.Add("8760h")

	// Edge cases
	f.Add("")
	f.Add("0")
	f.Add("0d")
	f.Add("-1d")
	f.Add("1.5d")
	f.Add("1d2d3d")                 // Multiple day specs
	f.Add("999999999999999999999d") // Overflow
	f.Add("d")                      // Missing number
	f.Add("abc")
	f.Add("1")  // Missing unit
	f.Add("1x") // Unknown unit

	f.Fuzz(func(t *testing.T, s string) {
		// Should not panic
		_, _ = parseDuration(s)
	})
}

// =============================================================================
// Variable Validation Fuzz Tests
// =============================================================================

// FuzzVariableGetters tests Variable getter methods with various default values.
func FuzzVariableGetters(f *testing.F) {
	f.Add("string-value")
	f.Add("")
	f.Add(strings.Repeat("x", 1000)) // Long string (kept reasonable for fast seed tests)

	f.Fuzz(func(t *testing.T, s string) {
		v := &Variable{
			Name:    "test",
			Type:    VarTypeString,
			Default: s,
		}

		// Should not panic
		_ = v.HasDefault()
		_ = v.IsRequired()
		_ = v.GetDefaultString()
		_ = v.GetDefaultInt()
		_ = v.GetDefaultBool()
		_ = v.GetDefaultStringList()
	})
}

// FuzzVariableValues tests VariableValues map operations.
func FuzzVariableValues(f *testing.F) {
	f.Add("key", "value")
	f.Add("", "")
	f.Add(strings.Repeat("k", 1000), strings.Repeat("v", 1000))

	f.Fuzz(func(t *testing.T, key, value string) {
		vv := make(VariableValues)

		// Should not panic
		vv.SetString(key, value)
		_, _ = vv.GetString(key)
		_, _ = vv.GetInt(key)
		_, _ = vv.GetBool(key)
		_, _ = vv.GetStringList(key)
	})
}

// =============================================================================
// Profile YAML Round-trip Fuzz Tests
// =============================================================================

// FuzzProfileYAMLRoundtrip tests that valid profiles can be saved and reloaded.
func FuzzProfileYAMLRoundtrip(f *testing.F) {
	f.Add("test-profile", "ecdsa-p256", "365d")
	f.Add("pqc-profile", "ml-dsa-65", "1y")
	f.Add("", "", "")
	f.Add("a", "b", "c")

	f.Fuzz(func(t *testing.T, name, alg, validity string) {
		// Create a minimal profile YAML
		yaml := []byte("name: " + name + "\nalgorithm: " + alg + "\nvalidity: " + validity)

		// Try to load it
		p, err := LoadProfileFromBytes(yaml)
		if err != nil {
			return // Invalid input, that's fine
		}

		// If it loaded, try to convert back to YAML
		py := profileToYAML(p)
		_ = py // Should not panic
	})
}

// =============================================================================
// Extensions Config Fuzz Tests
// =============================================================================

// FuzzExtensionsConfigParsing tests extensions configuration parsing.
func FuzzExtensionsConfigParsing(f *testing.F) {
	f.Add([]byte(`name: test
algorithm: ecdsa-p256
validity: 365d
extensions:
  key_usage:
    - digitalSignature
    - keyEncipherment`))

	f.Add([]byte(`name: test
algorithm: ecdsa-p256
validity: 365d
extensions:
  extended_key_usage:
    - serverAuth
    - clientAuth`))

	f.Add([]byte(`name: test
algorithm: ecdsa-p256
validity: 365d
extensions:
  basic_constraints:
    is_ca: true
    max_path_len: 0`))

	// Edge cases
	f.Add([]byte(`name: test
algorithm: ecdsa-p256
validity: 365d
extensions:
  key_usage: null`))

	f.Add([]byte(`name: test
algorithm: ecdsa-p256
validity: 365d
extensions:
  basic_constraints:
    max_path_len: -999`))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = LoadProfileFromBytes(data)
	})
}

// =============================================================================
// Subject Config Fuzz Tests
// =============================================================================

// FuzzSubjectConfigParsing tests subject DN configuration parsing.
func FuzzSubjectConfigParsing(f *testing.F) {
	f.Add([]byte(`name: test
algorithm: ecdsa-p256
validity: 365d
subject:
  cn: "{{ cn }}"
  o: "ACME Corp"
  c: "US"`))

	f.Add([]byte(`name: test
algorithm: ecdsa-p256
validity: 365d
subject:
  cn: null`))

	f.Add([]byte(`name: test
algorithm: ecdsa-p256
validity: 365d
subject: "not-a-map"`))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = LoadProfileFromBytes(data)
	})
}

// =============================================================================
// Signature Algorithm Config Fuzz Tests
// =============================================================================

// FuzzSignatureAlgoConfigParsing tests signature algorithm override parsing.
func FuzzSignatureAlgoConfigParsing(f *testing.F) {
	f.Add([]byte(`name: test
algorithm: ecdsa-p256
validity: 365d
signature:
  algorithm: ml-dsa-65`))

	f.Add([]byte(`name: test
algorithm: ecdsa-p256
validity: 365d
signature:
  hash: sha512`))

	f.Add([]byte(`name: test
algorithm: ecdsa-p256
validity: 365d
signature: null`))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = LoadProfileFromBytes(data)
	})
}
