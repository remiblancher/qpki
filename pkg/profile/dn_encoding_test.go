package profile

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
)

func TestU_Profile_IsPrintableString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"empty", "", true},
		{"letters", "ABCxyz", true},
		{"digits", "0123456789", true},
		{"space", "Hello World", true},
		{"allowed_special", "a'b(c)d+e,f-g.h/i:j=k?l", true},
		{"uppercase", "ACME CORP", true},
		{"domain_like", "example.com", true},
		{"accents_not_allowed", "Café", false},
		{"unicode_not_allowed", "日本語", false},
		{"at_sign_not_allowed", "test@example.com", false},
		{"underscore_not_allowed", "test_value", false},
		{"asterisk_not_allowed", "*.example.com", false},
		{"hash_not_allowed", "#123", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsPrintableString(tt.input)
			if got != tt.expected {
				t.Errorf("IsPrintableString(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestU_Profile_IsIA5String(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"empty", "", true},
		{"ascii", "test@example.com", true},
		{"all_ascii", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", true},
		{"special_chars", "!@#$%^&*()_+-=[]{}|;':\",./<>?", true},
		{"accents_not_allowed", "café", false},
		{"unicode_not_allowed", "日本語", false},
		{"emoji_not_allowed", "test😀", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsIA5String(tt.input)
			if got != tt.expected {
				t.Errorf("IsIA5String(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestU_Profile_MarshalDNString_UTF8(t *testing.T) {
	value := "Test Value"
	raw, err := MarshalDNString(value, DNEncodingUTF8)
	if err != nil {
		t.Fatalf("MarshalDNString failed: %v", err)
	}

	if raw.Tag != asnTagUTF8String {
		t.Errorf("expected tag %d, got %d", asnTagUTF8String, raw.Tag)
	}
	if string(raw.Bytes) != value {
		t.Errorf("expected value %q, got %q", value, string(raw.Bytes))
	}
}

func TestU_Profile_MarshalDNString_Printable(t *testing.T) {
	value := "ACME Corp"
	raw, err := MarshalDNString(value, DNEncodingPrintable)
	if err != nil {
		t.Fatalf("MarshalDNString failed: %v", err)
	}

	if raw.Tag != asnTagPrintableString {
		t.Errorf("expected tag %d, got %d", asnTagPrintableString, raw.Tag)
	}
	if string(raw.Bytes) != value {
		t.Errorf("expected value %q, got %q", value, string(raw.Bytes))
	}
}

func TestU_Profile_MarshalDNString_PrintableInvalidChars(t *testing.T) {
	_, err := MarshalDNString("test@example.com", DNEncodingPrintable)
	if err == nil {
		t.Error("expected error for invalid PrintableString characters")
	}
}

func TestU_Profile_MarshalDNString_IA5(t *testing.T) {
	value := "test@example.com"
	raw, err := MarshalDNString(value, DNEncodingIA5)
	if err != nil {
		t.Fatalf("MarshalDNString failed: %v", err)
	}

	if raw.Tag != asnTagIA5String {
		t.Errorf("expected tag %d, got %d", asnTagIA5String, raw.Tag)
	}
}

func TestU_Profile_MarshalDNString_IA5InvalidChars(t *testing.T) {
	_, err := MarshalDNString("café@example.com", DNEncodingIA5)
	if err == nil {
		t.Error("expected error for non-ASCII characters in IA5String")
	}
}

func TestU_Profile_ValidateSubjectEncoding(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *SubjectConfig
		wantErr bool
	}{
		{
			name: "valid_country_printable",
			cfg: &SubjectConfig{
				Attrs: map[string]*SubjectAttribute{
					"c": {Value: "FR", Encoding: DNEncodingPrintable},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid_country_utf8",
			cfg: &SubjectConfig{
				Attrs: map[string]*SubjectAttribute{
					"c": {Value: "FR", Encoding: DNEncodingUTF8},
				},
			},
			wantErr: true,
		},
		{
			name: "valid_email_ia5",
			cfg: &SubjectConfig{
				Attrs: map[string]*SubjectAttribute{
					"email": {Value: "test@example.com", Encoding: DNEncodingIA5},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid_email_utf8",
			cfg: &SubjectConfig{
				Attrs: map[string]*SubjectAttribute{
					"email": {Value: "test@example.com", Encoding: DNEncodingUTF8},
				},
			},
			wantErr: true,
		},
		{
			name: "cn_can_be_utf8",
			cfg: &SubjectConfig{
				Attrs: map[string]*SubjectAttribute{
					"cn": {Value: "Test", Encoding: DNEncodingUTF8},
				},
			},
			wantErr: false,
		},
		{
			name: "cn_can_be_printable",
			cfg: &SubjectConfig{
				Attrs: map[string]*SubjectAttribute{
					"cn": {Value: "Test", Encoding: DNEncodingPrintable},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSubjectEncoding(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateSubjectEncoding() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestU_Profile_MarshalRDNSequence(t *testing.T) {
	attrs := []DNAttribute{
		{OID: oidCountry, Value: "FR", Encoding: DNEncodingPrintable},
		{OID: oidOrganization, Value: "ACME Corp", Encoding: DNEncodingUTF8},
		{OID: oidCommonName, Value: "Test Server", Encoding: DNEncodingUTF8},
	}

	der, err := MarshalRDNSequence(attrs)
	if err != nil {
		t.Fatalf("MarshalRDNSequence failed: %v", err)
	}

	if len(der) == 0 {
		t.Error("expected non-empty DER output")
	}

	// Verify it's valid ASN.1
	var seq asn1.RawValue
	_, err = asn1.Unmarshal(der, &seq)
	if err != nil {
		t.Fatalf("DER output is not valid ASN.1: %v", err)
	}
}

func TestU_Profile_SubjectConfigToAttributes(t *testing.T) {
	cfg := &SubjectConfig{
		Attrs: map[string]*SubjectAttribute{
			"cn": {Value: "server.example.com"},
			"o":  {Value: "ACME", Encoding: DNEncodingPrintable},
			"c":  {Value: "FR"},
		},
	}

	values := map[string]string{
		"cn": "resolved.example.com", // Override cn
	}

	attrs, err := SubjectConfigToAttributes(cfg, values)
	if err != nil {
		t.Fatalf("SubjectConfigToAttributes failed: %v", err)
	}

	// Check CN was resolved from values
	var foundCN bool
	for _, attr := range attrs {
		if attr.OID.Equal(oidCommonName) {
			foundCN = true
			if attr.Value != "resolved.example.com" {
				t.Errorf("CN value = %q, want %q", attr.Value, "resolved.example.com")
			}
		}
	}
	if !foundCN {
		t.Error("CN attribute not found")
	}
}

func TestU_Profile_BuildPkixName(t *testing.T) {
	cfg := &SubjectConfig{
		Fixed: map[string]string{
			"cn": "test.example.com",
			"o":  "ACME Corp",
			"c":  "US",
		},
	}

	name := BuildPkixName(cfg, nil)

	if name.CommonName != "test.example.com" {
		t.Errorf("CommonName = %q, want %q", name.CommonName, "test.example.com")
	}
	if len(name.Organization) != 1 || name.Organization[0] != "ACME Corp" {
		t.Errorf("Organization = %v, want [ACME Corp]", name.Organization)
	}
	if len(name.Country) != 1 || name.Country[0] != "US" {
		t.Errorf("Country = %v, want [US]", name.Country)
	}
}

func TestU_Profile_Rfc5280RequiredEncoding(t *testing.T) {
	tests := []struct {
		attr     string
		expected DNEncoding
	}{
		{"c", DNEncodingPrintable},
		{"country", DNEncodingPrintable},
		{"email", DNEncodingIA5},
		{"emailaddress", DNEncodingIA5},
		{"cn", ""},
		{"o", ""},
		{"ou", ""},
	}

	for _, tt := range tests {
		t.Run(tt.attr, func(t *testing.T) {
			got := rfc5280RequiredEncoding(tt.attr)
			if got != tt.expected {
				t.Errorf("rfc5280RequiredEncoding(%q) = %q, want %q", tt.attr, got, tt.expected)
			}
		})
	}
}

func TestU_Profile_MarshalPkixNameWithEncoding_NilConfig(t *testing.T) {
	name := pkix.Name{
		CommonName:   "test.example.com",
		Organization: []string{"ACME Corp"},
		Country:      []string{"US"},
	}

	// With nil config, should use Go's default encoding
	der, err := MarshalPkixNameWithEncoding(name, nil)
	if err != nil {
		t.Fatalf("MarshalPkixNameWithEncoding failed: %v", err)
	}

	if len(der) == 0 {
		t.Error("expected non-empty DER output")
	}

	// Verify it's valid ASN.1
	var seq asn1.RawValue
	_, err = asn1.Unmarshal(der, &seq)
	if err != nil {
		t.Fatalf("DER output is not valid ASN.1: %v", err)
	}
}

func TestU_Profile_MarshalPkixNameWithEncoding_EmptyAttrs(t *testing.T) {
	name := pkix.Name{
		CommonName:   "test.example.com",
		Organization: []string{"ACME Corp"},
	}

	cfg := &SubjectConfig{
		Attrs: map[string]*SubjectAttribute{}, // Empty attrs
	}

	// With empty attrs, should use Go's default encoding
	der, err := MarshalPkixNameWithEncoding(name, cfg)
	if err != nil {
		t.Fatalf("MarshalPkixNameWithEncoding failed: %v", err)
	}

	if len(der) == 0 {
		t.Error("expected non-empty DER output")
	}
}

func TestU_Profile_MarshalPkixNameWithEncoding_CustomEncoding(t *testing.T) {
	name := pkix.Name{
		CommonName:         "test.example.com",
		Organization:       []string{"ACME Corp"},
		Country:            []string{"US"},
		Province:           []string{"California"},
		Locality:           []string{"San Francisco"},
		OrganizationalUnit: []string{"IT"},
		SerialNumber:       "12345",
		StreetAddress:      []string{"123 Main St"},
		PostalCode:         []string{"94102"},
	}

	cfg := &SubjectConfig{
		Attrs: map[string]*SubjectAttribute{
			"cn": {Encoding: DNEncodingUTF8},
			"o":  {Encoding: DNEncodingPrintable},
			"c":  {Encoding: DNEncodingPrintable},
		},
	}

	der, err := MarshalPkixNameWithEncoding(name, cfg)
	if err != nil {
		t.Fatalf("MarshalPkixNameWithEncoding failed: %v", err)
	}

	if len(der) == 0 {
		t.Error("expected non-empty DER output")
	}

	// Verify it's valid ASN.1 RDN sequence
	var seq asn1.RawValue
	_, err = asn1.Unmarshal(der, &seq)
	if err != nil {
		t.Fatalf("DER output is not valid ASN.1: %v", err)
	}

	// The tag should be SEQUENCE (0x30)
	if seq.Tag != asn1.TagSequence {
		t.Errorf("expected SEQUENCE tag (0x30), got 0x%x", seq.Tag)
	}
}

func TestU_Profile_MarshalSubjectDN_ASN1Tags(t *testing.T) {
	cfg := &SubjectConfig{
		Attrs: map[string]*SubjectAttribute{
			"o":  {Value: "ACME Corp", Encoding: DNEncodingPrintable},
			"cn": {Value: "test.example.com", Encoding: DNEncodingUTF8},
			"c":  {Value: "FR", Encoding: DNEncodingPrintable},
		},
	}

	der, err := MarshalSubjectDN(cfg, nil)
	if err != nil {
		t.Fatalf("MarshalSubjectDN failed: %v", err)
	}

	// Parse the RDNSequence to verify ASN.1 tags
	var rdnSeq asn1.RawValue
	rest, err := asn1.Unmarshal(der, &rdnSeq)
	if err != nil {
		t.Fatalf("failed to unmarshal RDNSequence: %v", err)
	}
	if len(rest) > 0 {
		t.Errorf("unexpected trailing data: %d bytes", len(rest))
	}

	// Expected OIDs and their tags
	expectedTags := map[string]int{
		"2.5.4.6":  asnTagPrintableString, // Country (C) - tag 19
		"2.5.4.10": asnTagPrintableString, // Organization (O) - tag 19
		"2.5.4.3":  asnTagUTF8String,      // CommonName (CN) - tag 12
	}

	// Parse each RDN in the sequence
	data := rdnSeq.Bytes
	for len(data) > 0 {
		var rdn asn1.RawValue
		rest, err := asn1.Unmarshal(data, &rdn)
		if err != nil {
			t.Fatalf("failed to unmarshal RDN: %v", err)
		}
		data = rest

		// Parse the SET containing AttributeTypeAndValue
		var atv asn1.RawValue
		_, err = asn1.Unmarshal(rdn.Bytes, &atv)
		if err != nil {
			t.Fatalf("failed to unmarshal AttributeTypeAndValue: %v", err)
		}

		// Parse OID and value from the SEQUENCE
		var oid asn1.ObjectIdentifier
		rest, err = asn1.Unmarshal(atv.Bytes, &oid)
		if err != nil {
			t.Fatalf("failed to unmarshal OID: %v", err)
		}

		// The rest contains the value (wrapped in RawValue due to MarshalRDNSequence encoding)
		var valueWrapper asn1.RawValue
		_, err = asn1.Unmarshal(rest, &valueWrapper)
		if err != nil {
			t.Fatalf("failed to unmarshal value wrapper: %v", err)
		}

		// The actual value is inside the wrapper
		var actualValue asn1.RawValue
		_, err = asn1.Unmarshal(valueWrapper.FullBytes, &actualValue)
		if err != nil {
			t.Fatalf("failed to unmarshal actual value: %v", err)
		}

		// Check the tag
		oidStr := oid.String()
		if expectedTag, ok := expectedTags[oidStr]; ok {
			if actualValue.Tag != expectedTag {
				t.Errorf("OID %s: got tag %d, want %d", oidStr, actualValue.Tag, expectedTag)
			}
		}
	}
}
