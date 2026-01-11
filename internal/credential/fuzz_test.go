package credential

import (
	"encoding/json"
	"strings"
	"testing"
)

// =============================================================================
// Credential JSON Parsing Fuzz Tests
// =============================================================================

// FuzzCredentialUnmarshalJSON tests JSON parsing of Credential structures.
// This is critical as credential metadata comes from stored files.
func FuzzCredentialUnmarshalJSON(f *testing.F) {
	// Valid credential JSON
	f.Add([]byte(`{
		"id": "test-cred-123",
		"status": "valid",
		"subject": {"common_name": "test.example.com"},
		"profiles": ["tls-server"],
		"certificates": []
	}`))

	f.Add([]byte(`{
		"id": "alice-20250115-abc123",
		"status": "valid",
		"subject": {
			"common_name": "Alice",
			"organization": ["ACME Corp"],
			"country": ["US"]
		},
		"profiles": ["user-signature", "user-encryption"],
		"certificates": [
			{
				"serial": "0x1234",
				"role": "signature",
				"algorithm": "ml-dsa-65",
				"fingerprint": "ABCD1234"
			}
		],
		"not_before": "2025-01-15T00:00:00Z",
		"not_after": "2026-01-15T00:00:00Z"
	}`))

	// Edge cases
	f.Add([]byte(`{}`))            // Empty object
	f.Add([]byte(`[]`))            // Array instead of object
	f.Add([]byte(`null`))          // Null
	f.Add([]byte(``))              // Empty
	f.Add([]byte(`{`))             // Incomplete
	f.Add([]byte(`{"id": null}`))  // Null field
	f.Add([]byte(`{"id": 12345}`)) // Wrong type

	// Type confusion attacks
	f.Add([]byte(`{"status": ["valid", "invalid"]}`))
	f.Add([]byte(`{"certificates": "not-an-array"}`))
	f.Add([]byte(`{"subject": "not-an-object"}`))
	f.Add([]byte(`{"not_before": "not-a-date"}`))
	f.Add([]byte(`{"metadata": [1, 2, 3]}`))

	// Large/nested structures
	f.Add([]byte(`{"id": "` + strings.Repeat("x", 1000) + `"}`))
	f.Add([]byte(`{"certificates": [` + strings.Repeat(`{"serial":"x"},`, 100) + `{"serial":"y"}]}`))

	// Unicode and special characters
	f.Add([]byte(`{"id": "测试-cred-🔐"}`))
	f.Add([]byte(`{"id": "test\u0000null"}`))
	f.Add([]byte(`{"subject": {"common_name": "O'Malley & Sons"}}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var cred Credential
		// Should not panic
		_ = json.Unmarshal(data, &cred)
		_ = cred.UnmarshalJSON(data)
	})
}

// FuzzCertificateRefUnmarshalJSON tests JSON parsing of CertificateRef.
func FuzzCertificateRefUnmarshalJSON(f *testing.F) {
	f.Add([]byte(`{
		"serial": "0xABCD1234",
		"role": "signature",
		"profile": "tls-server",
		"algorithm": "ecdsa-p256",
		"fingerprint": "SHA256:abc123"
	}`))

	f.Add([]byte(`{
		"serial": "0x1",
		"role": "encryption-pqc",
		"algorithm": "ml-kem-768",
		"is_catalyst": true,
		"alt_algorithm": "ecdsa-p384",
		"related_serial": "0x2"
	}`))

	// Edge cases
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"serial": null}`))
	f.Add([]byte(`{"role": 12345}`))
	f.Add([]byte(`{"storage": "not-an-array"}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var ref CertificateRef
		_ = json.Unmarshal(data, &ref)
	})
}

// FuzzSubjectUnmarshalJSON tests JSON parsing of Subject.
func FuzzSubjectUnmarshalJSON(f *testing.F) {
	f.Add([]byte(`{"common_name": "test.example.com"}`))
	f.Add([]byte(`{
		"common_name": "Alice",
		"organization": ["ACME", "Corp"],
		"country": ["US", "FR"],
		"province": ["CA"],
		"locality": ["San Francisco"]
	}`))

	// Edge cases
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"common_name": null}`))
	f.Add([]byte(`{"organization": "not-an-array"}`))
	f.Add([]byte(`{"country": [1, 2, 3]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var subj Subject
		_ = json.Unmarshal(data, &subj)
	})
}

// =============================================================================
// Credential ID Generation Fuzz Tests
// =============================================================================

// FuzzGenerateCredentialID tests credential ID generation with arbitrary CNs.
func FuzzGenerateCredentialID(f *testing.F) {
	f.Add("Alice")
	f.Add("test.example.com")
	f.Add("O'Malley & Sons")
	f.Add("")
	f.Add(strings.Repeat("x", 1000))
	f.Add("测试用户")
	f.Add("user@example.com")
	f.Add("user\x00null")
	f.Add("---")
	f.Add("123")

	f.Fuzz(func(t *testing.T, cn string) {
		// Should not panic and should return non-empty ID
		id := GenerateCredentialID(cn)
		if id == "" {
			t.Error("GenerateCredentialID returned empty string")
		}
	})
}

// =============================================================================
// Credential Methods Fuzz Tests
// =============================================================================

// FuzzCredentialMethods tests Credential methods with various states.
func FuzzCredentialMethods(f *testing.F) {
	f.Add("cred-id", "test.example.com", "valid")
	f.Add("", "", "")
	f.Add("id", "cn", "revoked")
	f.Add("id", "cn", "expired")
	f.Add("id", "cn", "pending")
	f.Add("id", "cn", "unknown-status")

	f.Fuzz(func(t *testing.T, id, cn, status string) {
		subj := Subject{CommonName: cn}
		cred := NewCredential(id, subj)

		// Create a version with the fuzzed status
		cred.Versions["v1"] = CredVersion{
			Profiles: []string{"ec/tls-server"},
			Algos:    []string{"ec"},
			Status:   status,
		}
		cred.Active = "v1"

		// These should not panic
		_ = cred.IsValid()
		_ = cred.IsExpired()
		_ = cred.Summary()
		_ = cred.ActiveVersion()
	})
}

// FuzzCredentialMarshalUnmarshal tests JSON round-trip.
func FuzzCredentialMarshalUnmarshal(f *testing.F) {
	f.Add("cred-1", "test.example.com")
	f.Add("", "")
	f.Add("id-with-special-chars!@#", "CN with spaces")

	f.Fuzz(func(t *testing.T, id, cn string) {
		subj := Subject{CommonName: cn}
		cred := NewCredential(id, subj)
		cred.CreateInitialVersion([]string{"ec/tls-server"}, []string{"ec"})

		// Marshal
		data, err := cred.MarshalJSON()
		if err != nil {
			return // Some inputs may not marshal cleanly
		}

		// Unmarshal back
		var cred2 Credential
		if err := cred2.UnmarshalJSON(data); err != nil {
			t.Errorf("Failed to unmarshal marshaled credential: %v", err)
		}
	})
}

// FuzzSubjectToPkixName tests Subject to pkix.Name conversion.
func FuzzSubjectToPkixName(f *testing.F) {
	f.Add("Alice", "ACME Corp", "US")
	f.Add("", "", "")
	f.Add(strings.Repeat("x", 1000), "org", "country")

	f.Fuzz(func(t *testing.T, cn, org, country string) {
		subj := Subject{
			CommonName:   cn,
			Organization: []string{org},
			Country:      []string{country},
		}

		// Should not panic
		name := subj.ToPkixName()
		_ = name.String()

		// Round-trip
		subj2 := SubjectFromPkixName(name)
		_ = subj2
	})
}
