package x509util

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
)

func TestU_X509Util_QCStatementsBuilder_QcCompliance(t *testing.T) {
	builder := NewQCStatementsBuilder()
	builder.AddQcCompliance()

	ext, err := builder.Build(false)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	if !OIDEqual(ext.Id, OIDQCStatements) {
		t.Errorf("Extension OID = %v, want %v", ext.Id, OIDQCStatements)
	}
	if ext.Critical {
		t.Error("Extension should not be critical")
	}

	// Decode and verify
	info, err := DecodeQCStatements(ext)
	if err != nil {
		t.Fatalf("DecodeQCStatements failed: %v", err)
	}
	if !info.QcCompliance {
		t.Error("QcCompliance should be true")
	}
}

func TestU_X509Util_QCStatementsBuilder_QcType(t *testing.T) {
	tests := []struct {
		name     string
		qcType   QcType
		wantType QcType
		wantErr  bool
	}{
		{"esign", QcTypeESign, QcTypeESign, false},
		{"eseal", QcTypeESeal, QcTypeESeal, false},
		{"web", QcTypeWeb, QcTypeWeb, false},
		{"invalid", QcType("invalid"), "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := NewQCStatementsBuilder()
			err := builder.AddQcType(tt.qcType)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error for invalid QcType")
				}
				return
			}

			if err != nil {
				t.Fatalf("AddQcType failed: %v", err)
			}

			ext, err := builder.Build(false)
			if err != nil {
				t.Fatalf("Build failed: %v", err)
			}

			info, err := DecodeQCStatements(ext)
			if err != nil {
				t.Fatalf("DecodeQCStatements failed: %v", err)
			}

			if len(info.QcType) != 1 {
				t.Fatalf("QcType length = %d, want 1", len(info.QcType))
			}
			if info.QcType[0] != tt.wantType {
				t.Errorf("QcType = %v, want %v", info.QcType[0], tt.wantType)
			}
		})
	}
}

func TestU_X509Util_QCStatementsBuilder_QcSSCD(t *testing.T) {
	builder := NewQCStatementsBuilder()
	builder.AddQcSSCD()

	ext, err := builder.Build(false)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	info, err := DecodeQCStatements(ext)
	if err != nil {
		t.Fatalf("DecodeQCStatements failed: %v", err)
	}
	if !info.QcSSCD {
		t.Error("QcSSCD should be true")
	}
}

func TestU_X509Util_QCStatementsBuilder_QcRetentionPeriod(t *testing.T) {
	tests := []struct {
		name    string
		years   int
		wantErr bool
	}{
		{"15 years", 15, false},
		{"0 years", 0, false},
		{"negative", -1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := NewQCStatementsBuilder()
			err := builder.AddQcRetentionPeriod(tt.years)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error for negative retention period")
				}
				return
			}

			if err != nil {
				t.Fatalf("AddQcRetentionPeriod failed: %v", err)
			}

			ext, err := builder.Build(false)
			if err != nil {
				t.Fatalf("Build failed: %v", err)
			}

			info, err := DecodeQCStatements(ext)
			if err != nil {
				t.Fatalf("DecodeQCStatements failed: %v", err)
			}

			if info.QcRetentionPeriod == nil {
				t.Fatal("QcRetentionPeriod should not be nil")
			}
			if *info.QcRetentionPeriod != tt.years {
				t.Errorf("QcRetentionPeriod = %d, want %d", *info.QcRetentionPeriod, tt.years)
			}
		})
	}
}

func TestU_X509Util_QCStatementsBuilder_QcPDS(t *testing.T) {
	tests := []struct {
		name      string
		locations []PDSLocation
		wantErr   bool
	}{
		{
			name: "single location",
			locations: []PDSLocation{
				{URL: "https://pki.example.com/pds.pdf", Language: "en"},
			},
			wantErr: false,
		},
		{
			name: "multiple locations",
			locations: []PDSLocation{
				{URL: "https://pki.example.com/pds-en.pdf", Language: "en"},
				{URL: "https://pki.example.com/pds-fr.pdf", Language: "fr"},
			},
			wantErr: false,
		},
		{
			name:      "empty locations",
			locations: []PDSLocation{},
			wantErr:   true,
		},
		{
			name: "invalid language code",
			locations: []PDSLocation{
				{URL: "https://example.com/pds.pdf", Language: "eng"}, // 3 chars
			},
			wantErr: true,
		},
		{
			name: "empty URL",
			locations: []PDSLocation{
				{URL: "", Language: "en"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := NewQCStatementsBuilder()
			err := builder.AddQcPDS(tt.locations)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error")
				}
				return
			}

			if err != nil {
				t.Fatalf("AddQcPDS failed: %v", err)
			}

			ext, err := builder.Build(false)
			if err != nil {
				t.Fatalf("Build failed: %v", err)
			}

			info, err := DecodeQCStatements(ext)
			if err != nil {
				t.Fatalf("DecodeQCStatements failed: %v", err)
			}

			if len(info.QcPDS) != len(tt.locations) {
				t.Fatalf("QcPDS length = %d, want %d", len(info.QcPDS), len(tt.locations))
			}

			for i, loc := range info.QcPDS {
				if loc.URL != tt.locations[i].URL {
					t.Errorf("QcPDS[%d].URL = %q, want %q", i, loc.URL, tt.locations[i].URL)
				}
				if loc.Language != tt.locations[i].Language {
					t.Errorf("QcPDS[%d].Language = %q, want %q", i, loc.Language, tt.locations[i].Language)
				}
			}
		})
	}
}

func TestU_X509Util_QCStatementsBuilder_CompleteEIDAS(t *testing.T) {
	// Build a complete eIDAS QCStatements extension
	builder := NewQCStatementsBuilder()
	builder.AddQcCompliance()

	if err := builder.AddQcType(QcTypeESign); err != nil {
		t.Fatalf("AddQcType failed: %v", err)
	}

	builder.AddQcSSCD()

	if err := builder.AddQcRetentionPeriod(15); err != nil {
		t.Fatalf("AddQcRetentionPeriod failed: %v", err)
	}

	if err := builder.AddQcPDS([]PDSLocation{
		{URL: "https://pki.example.com/pds-en.pdf", Language: "en"},
		{URL: "https://pki.example.com/pds-fr.pdf", Language: "fr"},
	}); err != nil {
		t.Fatalf("AddQcPDS failed: %v", err)
	}

	ext, err := builder.Build(false)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// Decode and verify all statements
	info, err := DecodeQCStatements(ext)
	if err != nil {
		t.Fatalf("DecodeQCStatements failed: %v", err)
	}

	if !info.QcCompliance {
		t.Error("QcCompliance should be true")
	}
	if len(info.QcType) != 1 || info.QcType[0] != QcTypeESign {
		t.Errorf("QcType = %v, want [esign]", info.QcType)
	}
	if !info.QcSSCD {
		t.Error("QcSSCD should be true")
	}
	if info.QcRetentionPeriod == nil || *info.QcRetentionPeriod != 15 {
		t.Errorf("QcRetentionPeriod = %v, want 15", info.QcRetentionPeriod)
	}
	if len(info.QcPDS) != 2 {
		t.Fatalf("QcPDS length = %d, want 2", len(info.QcPDS))
	}
}

func TestU_X509Util_QCStatementsBuilder_Critical(t *testing.T) {
	builder := NewQCStatementsBuilder()
	builder.AddQcCompliance()

	ext, err := builder.Build(true)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	if !ext.Critical {
		t.Error("Extension should be critical")
	}
}

func TestU_X509Util_QCStatementsBuilder_EmptyBuild(t *testing.T) {
	builder := NewQCStatementsBuilder()

	_, err := builder.Build(false)
	if err == nil {
		t.Error("expected error for empty QCStatements")
	}
}

func TestU_X509Util_DecodeQCStatements_InvalidExtension(t *testing.T) {
	// Test with wrong OID
	ext := pkix.Extension{
		Id:    asn1.ObjectIdentifier{1, 2, 3, 4},
		Value: []byte{0x30, 0x00}, // Empty sequence
	}

	_, err := DecodeQCStatements(ext)
	if err == nil {
		t.Error("expected error for invalid extension OID")
	}
}

func TestU_X509Util_DecodeQCStatements_InvalidASN1(t *testing.T) {
	ext := pkix.Extension{
		Id:    OIDQCStatements,
		Value: []byte{0xFF, 0xFF}, // Invalid ASN.1
	}

	_, err := DecodeQCStatements(ext)
	if err == nil {
		t.Error("expected error for invalid ASN.1")
	}
}

func TestFindQCStatements(t *testing.T) {
	// Build QCStatements extension
	builder := NewQCStatementsBuilder()
	builder.AddQcCompliance()
	qcExt, _ := builder.Build(false)

	// Create extension list
	extensions := []pkix.Extension{
		{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Value: []byte{0x03, 0x02, 0x05, 0xA0}}, // KeyUsage
		qcExt,
		{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Value: []byte{0x30, 0x03, 0x01, 0x01, 0xFF}}, // BasicConstraints
	}

	found := FindQCStatements(extensions)
	if found == nil {
		t.Fatal("FindQCStatements should find the extension")
	}
	if !OIDEqual(found.Id, OIDQCStatements) {
		t.Errorf("Found extension OID = %v, want %v", found.Id, OIDQCStatements)
	}
}

func TestFindQCStatements_NotFound(t *testing.T) {
	extensions := []pkix.Extension{
		{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Value: []byte{0x03, 0x02, 0x05, 0xA0}},
		{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Value: []byte{0x30, 0x03, 0x01, 0x01, 0xFF}},
	}

	found := FindQCStatements(extensions)
	if found != nil {
		t.Error("FindQCStatements should return nil when not found")
	}
}

func TestU_X509Util_HasQCStatements(t *testing.T) {
	builder := NewQCStatementsBuilder()
	builder.AddQcCompliance()
	qcExt, _ := builder.Build(false)

	withQC := []pkix.Extension{qcExt}
	withoutQC := []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Value: []byte{}}}

	if !HasQCStatements(withQC) {
		t.Error("HasQCStatements should return true when extension exists")
	}
	if HasQCStatements(withoutQC) {
		t.Error("HasQCStatements should return false when extension doesn't exist")
	}
}

func TestU_X509Util_QcTypeOIDs(t *testing.T) {
	// Verify OIDs are correctly defined
	if OIDQcTypeESign.String() != "0.4.0.1862.1.6.1" {
		t.Errorf("OIDQcTypeESign = %s, want 0.4.0.1862.1.6.1", OIDQcTypeESign.String())
	}
	if OIDQcTypeESeal.String() != "0.4.0.1862.1.6.2" {
		t.Errorf("OIDQcTypeESeal = %s, want 0.4.0.1862.1.6.2", OIDQcTypeESeal.String())
	}
	if OIDQcTypeWeb.String() != "0.4.0.1862.1.6.3" {
		t.Errorf("OIDQcTypeWeb = %s, want 0.4.0.1862.1.6.3", OIDQcTypeWeb.String())
	}
}

func TestU_X509Util_QCStatementsOIDs(t *testing.T) {
	// Verify main OIDs are correctly defined
	if OIDQCStatements.String() != "1.3.6.1.5.5.7.1.3" {
		t.Errorf("OIDQCStatements = %s, want 1.3.6.1.5.5.7.1.3", OIDQCStatements.String())
	}
	if OIDQcCompliance.String() != "0.4.0.1862.1.1" {
		t.Errorf("OIDQcCompliance = %s, want 0.4.0.1862.1.1", OIDQcCompliance.String())
	}
	if OIDQcRetentionPeriod.String() != "0.4.0.1862.1.3" {
		t.Errorf("OIDQcRetentionPeriod = %s, want 0.4.0.1862.1.3", OIDQcRetentionPeriod.String())
	}
	if OIDQcSSCD.String() != "0.4.0.1862.1.4" {
		t.Errorf("OIDQcSSCD = %s, want 0.4.0.1862.1.4", OIDQcSSCD.String())
	}
	if OIDQcPDS.String() != "0.4.0.1862.1.5" {
		t.Errorf("OIDQcPDS = %s, want 0.4.0.1862.1.5", OIDQcPDS.String())
	}
	if OIDQcType.String() != "0.4.0.1862.1.6" {
		t.Errorf("OIDQcType = %s, want 0.4.0.1862.1.6", OIDQcType.String())
	}
}

func TestU_X509Util_OIDesi4QtstStatement1(t *testing.T) {
	// Verify esi4-qtstStatement-1 OID for qualified timestamps (ETSI EN 319 422)
	if OIDesi4QtstStatement1.String() != "0.4.0.19422.1.1" {
		t.Errorf("OIDesi4QtstStatement1 = %s, want 0.4.0.19422.1.1", OIDesi4QtstStatement1.String())
	}
}

// TestQCStatements_RoundTrip verifies that Build → Decode produces consistent results.
func TestU_X509Util_QCStatements_RoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		build  func(*QCStatementsBuilder) error
		verify func(*testing.T, *QCStatementsInfo)
	}{
		{
			name: "all five statements",
			build: func(b *QCStatementsBuilder) error {
				b.AddQcCompliance()
				if err := b.AddQcType(QcTypeESeal); err != nil {
					return err
				}
				b.AddQcSSCD()
				if err := b.AddQcRetentionPeriod(10); err != nil {
					return err
				}
				return b.AddQcPDS([]PDSLocation{
					{URL: "https://example.com/pds-en.pdf", Language: "en"},
					{URL: "https://example.com/pds-de.pdf", Language: "de"},
				})
			},
			verify: func(t *testing.T, info *QCStatementsInfo) {
				if !info.QcCompliance {
					t.Error("QcCompliance should be true")
				}
				if len(info.QcType) != 1 || info.QcType[0] != QcTypeESeal {
					t.Errorf("QcType = %v, want [eseal]", info.QcType)
				}
				if !info.QcSSCD {
					t.Error("QcSSCD should be true")
				}
				if info.QcRetentionPeriod == nil || *info.QcRetentionPeriod != 10 {
					t.Errorf("QcRetentionPeriod = %v, want 10", info.QcRetentionPeriod)
				}
				if len(info.QcPDS) != 2 {
					t.Fatalf("QcPDS length = %d, want 2", len(info.QcPDS))
				}
				if info.QcPDS[0].URL != "https://example.com/pds-en.pdf" || info.QcPDS[0].Language != "en" {
					t.Errorf("QcPDS[0] = %+v, want en", info.QcPDS[0])
				}
				if info.QcPDS[1].URL != "https://example.com/pds-de.pdf" || info.QcPDS[1].Language != "de" {
					t.Errorf("QcPDS[1] = %+v, want de", info.QcPDS[1])
				}
			},
		},
		{
			name: "compliance only",
			build: func(b *QCStatementsBuilder) error {
				b.AddQcCompliance()
				return nil
			},
			verify: func(t *testing.T, info *QCStatementsInfo) {
				if !info.QcCompliance {
					t.Error("QcCompliance should be true")
				}
				if len(info.QcType) != 0 {
					t.Errorf("QcType should be empty, got %v", info.QcType)
				}
				if info.QcSSCD {
					t.Error("QcSSCD should be false")
				}
				if info.QcRetentionPeriod != nil {
					t.Errorf("QcRetentionPeriod should be nil, got %d", *info.QcRetentionPeriod)
				}
				if len(info.QcPDS) != 0 {
					t.Errorf("QcPDS should be empty, got %v", info.QcPDS)
				}
			},
		},
		{
			name: "web type with PDS",
			build: func(b *QCStatementsBuilder) error {
				b.AddQcCompliance()
				if err := b.AddQcType(QcTypeWeb); err != nil {
					return err
				}
				return b.AddQcPDS([]PDSLocation{
					{URL: "https://ca.example.org/disclosure.pdf", Language: "fr"},
				})
			},
			verify: func(t *testing.T, info *QCStatementsInfo) {
				if !info.QcCompliance {
					t.Error("QcCompliance should be true")
				}
				if len(info.QcType) != 1 || info.QcType[0] != QcTypeWeb {
					t.Errorf("QcType = %v, want [web]", info.QcType)
				}
				if len(info.QcPDS) != 1 || info.QcPDS[0].Language != "fr" {
					t.Errorf("QcPDS = %v, want fr", info.QcPDS)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := NewQCStatementsBuilder()
			if err := tt.build(builder); err != nil {
				t.Fatalf("build failed: %v", err)
			}

			ext, err := builder.Build(false)
			if err != nil {
				t.Fatalf("Build failed: %v", err)
			}

			info, err := DecodeQCStatements(ext)
			if err != nil {
				t.Fatalf("DecodeQCStatements failed: %v", err)
			}

			tt.verify(t, info)
		})
	}
}

// TestDecodeQCStatements_UnknownOID verifies unknown statement OIDs are silently skipped.
func TestU_X509Util_DecodeQCStatements_UnknownOID(t *testing.T) {
	// Build extension with QcCompliance + unknown OID manually
	unknownOID := asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7}
	statements := []qcStatement{
		{StatementID: OIDQcCompliance},
		{StatementID: unknownOID}, // Unknown OID should be skipped
	}

	value, err := asn1.Marshal(statements)
	if err != nil {
		t.Fatalf("failed to marshal statements: %v", err)
	}

	ext := pkix.Extension{
		Id:    OIDQCStatements,
		Value: value,
	}

	info, err := DecodeQCStatements(ext)
	if err != nil {
		t.Fatalf("DecodeQCStatements should not fail for unknown OIDs: %v", err)
	}

	if !info.QcCompliance {
		t.Error("QcCompliance should be true")
	}
}

// TestDecodeQCStatements_TrailingData verifies trailing data is rejected.
func TestU_X509Util_DecodeQCStatements_TrailingData(t *testing.T) {
	builder := NewQCStatementsBuilder()
	builder.AddQcCompliance()
	ext, _ := builder.Build(false)

	// Add trailing data
	ext.Value = append(ext.Value, 0x00, 0x00)

	_, err := DecodeQCStatements(ext)
	if err == nil {
		t.Error("expected error for trailing data")
	}
}

// TestHasQCCompliance_Scenarios tests various scenarios for HasQCCompliance.
func TestU_X509Util_HasQCCompliance_Scenarios(t *testing.T) {
	tests := []struct {
		name       string
		extensions []pkix.Extension
		want       bool
	}{
		{
			name:       "empty extensions",
			extensions: []pkix.Extension{},
			want:       false,
		},
		{
			name:       "nil extensions",
			extensions: nil,
			want:       false,
		},
		{
			name: "QCStatements with QcCompliance",
			extensions: func() []pkix.Extension {
				b := NewQCStatementsBuilder()
				b.AddQcCompliance()
				ext, _ := b.Build(false)
				return []pkix.Extension{ext}
			}(),
			want: true,
		},
		{
			name: "QCStatements without QcCompliance (only QcSSCD)",
			extensions: func() []pkix.Extension {
				b := NewQCStatementsBuilder()
				b.AddQcSSCD()
				ext, _ := b.Build(false)
				return []pkix.Extension{ext}
			}(),
			want: false,
		},
		{
			name: "QCStatements without QcCompliance (only QcType)",
			extensions: func() []pkix.Extension {
				b := NewQCStatementsBuilder()
				_ = b.AddQcType(QcTypeESign)
				ext, _ := b.Build(false)
				return []pkix.Extension{ext}
			}(),
			want: false,
		},
		{
			name: "malformed QCStatements extension",
			extensions: []pkix.Extension{
				{Id: OIDQCStatements, Value: []byte{0xFF, 0xFF}},
			},
			want: false,
		},
		{
			name: "other extensions only",
			extensions: []pkix.Extension{
				{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Value: []byte{0x03, 0x02, 0x05, 0xA0}},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HasQCCompliance(tt.extensions)
			if got != tt.want {
				t.Errorf("HasQCCompliance() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestQCStatementsBuilder_Chaining verifies method chaining works correctly.
func TestU_X509Util_QCStatementsBuilder_Chaining(t *testing.T) {
	builder := NewQCStatementsBuilder()

	// Chain methods that return *QCStatementsBuilder
	result := builder.AddQcCompliance().AddQcSSCD()

	if result != builder {
		t.Error("chained methods should return the same builder instance")
	}

	ext, err := builder.Build(false)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	info, err := DecodeQCStatements(ext)
	if err != nil {
		t.Fatalf("DecodeQCStatements failed: %v", err)
	}

	if !info.QcCompliance || !info.QcSSCD {
		t.Error("chained statements should all be present")
	}
}

// TestQCStatementsBuilder_RetentionPeriodBoundary tests boundary values for retention period.
func TestU_X509Util_QCStatementsBuilder_RetentionPeriodBoundary(t *testing.T) {
	tests := []struct {
		name    string
		years   int
		wantErr bool
	}{
		{"zero", 0, false},
		{"one", 1, false},
		{"large value", 100, false},
		{"negative one", -1, true},
		{"large negative", -1000, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := NewQCStatementsBuilder()
			err := builder.AddQcRetentionPeriod(tt.years)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			ext, err := builder.Build(false)
			if err != nil {
				t.Fatalf("Build failed: %v", err)
			}

			info, err := DecodeQCStatements(ext)
			if err != nil {
				t.Fatalf("DecodeQCStatements failed: %v", err)
			}

			if info.QcRetentionPeriod == nil || *info.QcRetentionPeriod != tt.years {
				t.Errorf("QcRetentionPeriod = %v, want %d", info.QcRetentionPeriod, tt.years)
			}
		})
	}
}

// TestQCStatementsBuilder_PDSLanguageCodes tests various language code formats.
func TestU_X509Util_QCStatementsBuilder_PDSLanguageCodes(t *testing.T) {
	tests := []struct {
		name     string
		language string
		wantErr  bool
	}{
		{"lowercase", "en", false},
		{"uppercase", "EN", false}, // Should work (PrintableString allows uppercase)
		{"mixed case", "En", false},
		{"single char", "e", true},
		{"three chars", "eng", true},
		{"empty", "", true},
		{"numbers", "12", false}, // PrintableString allows digits
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := NewQCStatementsBuilder()
			err := builder.AddQcPDS([]PDSLocation{
				{URL: "https://example.com/pds.pdf", Language: tt.language},
			})

			if tt.wantErr {
				if err == nil {
					t.Error("expected error")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			ext, err := builder.Build(false)
			if err != nil {
				t.Fatalf("Build failed: %v", err)
			}

			info, err := DecodeQCStatements(ext)
			if err != nil {
				t.Fatalf("DecodeQCStatements failed: %v", err)
			}

			if len(info.QcPDS) != 1 || info.QcPDS[0].Language != tt.language {
				t.Errorf("QcPDS[0].Language = %q, want %q", info.QcPDS[0].Language, tt.language)
			}
		})
	}
}

// TestFindQCStatements_EmptyList tests FindQCStatements with an empty list.
func TestFindQCStatements_EmptyList(t *testing.T) {
	found := FindQCStatements([]pkix.Extension{})
	if found != nil {
		t.Error("FindQCStatements should return nil for empty list")
	}

	found = FindQCStatements(nil)
	if found != nil {
		t.Error("FindQCStatements should return nil for nil list")
	}
}
