// Package profile provides DN encoding functions for X.509 certificates.
package profile

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"strings"
)

// ASN.1 string type tags for DN encoding.
const (
	asnTagPrintableString = 19
	asnTagIA5String       = 22
	asnTagUTF8String      = 12
)

// OIDs for DN attributes (RFC 5280).
var (
	oidCountry            = asn1.ObjectIdentifier{2, 5, 4, 6}
	oidOrganization       = asn1.ObjectIdentifier{2, 5, 4, 10}
	oidOrganizationalUnit = asn1.ObjectIdentifier{2, 5, 4, 11}
	oidCommonName         = asn1.ObjectIdentifier{2, 5, 4, 3}
	oidSerialNumber       = asn1.ObjectIdentifier{2, 5, 4, 5}
	oidLocality           = asn1.ObjectIdentifier{2, 5, 4, 7}
	oidProvince           = asn1.ObjectIdentifier{2, 5, 4, 8}
	oidStreetAddress      = asn1.ObjectIdentifier{2, 5, 4, 9}
	oidPostalCode         = asn1.ObjectIdentifier{2, 5, 4, 17}
	oidEmailAddress       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
)

// attributeOIDs maps attribute names to OIDs.
var attributeOIDs = map[string]asn1.ObjectIdentifier{
	"c":            oidCountry,
	"country":      oidCountry,
	"o":            oidOrganization,
	"organization": oidOrganization,
	"ou":           oidOrganizationalUnit,
	"cn":           oidCommonName,
	"commonname":   oidCommonName,
	"serialnumber": oidSerialNumber,
	"l":            oidLocality,
	"locality":     oidLocality,
	"st":           oidProvince,
	"state":        oidProvince,
	"province":     oidProvince,
	"street":       oidStreetAddress,
	"postalcode":   oidPostalCode,
	"email":        oidEmailAddress,
	"emailaddress": oidEmailAddress,
}

// rfc5280RequiredEncoding returns the encoding required by RFC 5280 for an attribute.
// Returns empty string if no specific encoding is required.
func rfc5280RequiredEncoding(attrName string) DNEncoding {
	switch strings.ToLower(attrName) {
	case "c", "country":
		return DNEncodingPrintable // RFC 5280: Country MUST be PrintableString
	case "email", "emailaddress":
		return DNEncodingIA5 // RFC 5280: Email MUST be IA5String
	default:
		return ""
	}
}

// ValidateSubjectEncoding validates that the subject encoding configuration
// complies with RFC 5280 requirements.
// Only validates explicitly set encodings - if no encoding is specified,
// the correct RFC 5280 encoding will be auto-applied at marshaling time.
// Note: Templates ({{ variable }}) are not validated here as the final value
// is not known. Validation happens at encoding time in MarshalSubjectDN.
func ValidateSubjectEncoding(cfg *SubjectConfig) error {
	if cfg == nil {
		return nil
	}

	for name, attr := range cfg.Attrs {
		if attr == nil {
			continue
		}

		// Skip validation for template values - will be validated at encoding time
		if strings.Contains(attr.Value, "{{") {
			continue
		}

		required := rfc5280RequiredEncoding(name)
		if required == "" {
			continue
		}

		// Only validate if encoding is explicitly set
		// If not set, the correct encoding will be auto-applied at marshaling time
		if attr.Encoding != "" && attr.Encoding != required {
			return fmt.Errorf("attribute %q requires %s encoding per RFC 5280, got %s",
				name, required, attr.Encoding)
		}
	}

	return nil
}

// IsPrintableString checks if a string contains only PrintableString characters.
// PrintableString allows: A-Za-z0-9 '()+,-./:=? and space.
func IsPrintableString(s string) bool {
	for _, r := range s {
		if !isPrintableChar(r) {
			return false
		}
	}
	return true
}

// isPrintableChar checks if a rune is valid in PrintableString.
func isPrintableChar(r rune) bool {
	if r >= 'a' && r <= 'z' {
		return true
	}
	if r >= 'A' && r <= 'Z' {
		return true
	}
	if r >= '0' && r <= '9' {
		return true
	}
	switch r {
	case ' ', '\'', '(', ')', '+', ',', '-', '.', '/', ':', '=', '?':
		return true
	}
	return false
}

// IsIA5String checks if a string contains only IA5String (ASCII 7-bit) characters.
func IsIA5String(s string) bool {
	for _, r := range s {
		if r > 127 {
			return false
		}
	}
	return true
}

// MarshalDNString encodes a string value with the specified ASN.1 encoding.
func MarshalDNString(value string, encoding DNEncoding) (asn1.RawValue, error) {
	switch encoding {
	case DNEncodingPrintable:
		if !IsPrintableString(value) {
			return asn1.RawValue{}, fmt.Errorf("value %q contains characters not allowed in PrintableString", value)
		}
		return asn1.RawValue{
			Tag:   asnTagPrintableString,
			Class: asn1.ClassUniversal,
			Bytes: []byte(value),
		}, nil

	case DNEncodingIA5:
		if !IsIA5String(value) {
			return asn1.RawValue{}, fmt.Errorf("value %q contains non-ASCII characters not allowed in IA5String", value)
		}
		return asn1.RawValue{
			Tag:   asnTagIA5String,
			Class: asn1.ClassUniversal,
			Bytes: []byte(value),
		}, nil

	case DNEncodingUTF8, "":
		return asn1.RawValue{
			Tag:   asnTagUTF8String,
			Class: asn1.ClassUniversal,
			Bytes: []byte(value),
		}, nil

	default:
		return asn1.RawValue{}, fmt.Errorf("unknown encoding: %s", encoding)
	}
}

// DNAttribute represents a DN attribute with its OID, value, and encoding.
type DNAttribute struct {
	OID      asn1.ObjectIdentifier
	Value    string
	Encoding DNEncoding
}

// MarshalRDNSequence encodes a list of DN attributes to an ASN.1 RDNSequence.
// The order follows RFC 5280 recommendations: C, ST, L, O, OU, CN.
func MarshalRDNSequence(attrs []DNAttribute) ([]byte, error) {
	var rdns pkix.RDNSequence

	for _, attr := range attrs {
		if attr.Value == "" {
			continue
		}

		rawValue, err := MarshalDNString(attr.Value, attr.Encoding)
		if err != nil {
			return nil, fmt.Errorf("encoding attribute %v: %w", attr.OID, err)
		}

		// Encode the value bytes
		valueBytes, err := asn1.Marshal(rawValue)
		if err != nil {
			return nil, fmt.Errorf("marshaling attribute value: %w", err)
		}

		rdn := pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{
				Type:  attr.OID,
				Value: asn1.RawValue{FullBytes: valueBytes},
			},
		}
		rdns = append(rdns, rdn)
	}

	return asn1.Marshal(rdns)
}

// SubjectConfigToAttributes converts a SubjectConfig to a list of DNAttributes
// with resolved values from the provided variable map.
func SubjectConfigToAttributes(cfg *SubjectConfig, values map[string]string) ([]DNAttribute, error) {
	if cfg == nil {
		return nil, nil
	}

	// Build attributes in RFC 5280 recommended order
	order := []string{"c", "st", "l", "o", "ou", "cn", "serialnumber", "email", "street", "postalcode"}

	var attrs []DNAttribute

	for _, name := range order {
		var value string
		var encoding DNEncoding

		// Check Attrs first (new format)
		if attr, ok := cfg.Attrs[name]; ok && attr != nil {
			value = attr.Value
			encoding = attr.Encoding
		} else if v, ok := cfg.Fixed[name]; ok {
			// Fall back to Fixed (legacy format)
			value = v
		} else {
			continue
		}

		// Resolve template variables in value
		if resolved, ok := values[name]; ok && resolved != "" {
			value = resolved
		}

		if value == "" {
			continue
		}

		// Determine final encoding (UTF8String by default)
		if encoding == "" {
			encoding = DNEncodingUTF8
		}

		// Apply RFC 5280 required encoding if applicable
		if required := rfc5280RequiredEncoding(name); required != "" {
			encoding = required
		}

		oid, ok := attributeOIDs[strings.ToLower(name)]
		if !ok {
			return nil, fmt.Errorf("unknown DN attribute: %s", name)
		}

		attrs = append(attrs, DNAttribute{
			OID:      oid,
			Value:    value,
			Encoding: encoding,
		})
	}

	return attrs, nil
}

// MarshalSubjectDN encodes a subject DN from SubjectConfig with resolved values.
func MarshalSubjectDN(cfg *SubjectConfig, values map[string]string) ([]byte, error) {
	attrs, err := SubjectConfigToAttributes(cfg, values)
	if err != nil {
		return nil, err
	}

	return MarshalRDNSequence(attrs)
}

// MarshalPkixNameWithEncoding encodes a pkix.Name to DER using the encoding
// configuration from SubjectConfig. If cfg is nil, uses Go's default encoding.
func MarshalPkixNameWithEncoding(name pkix.Name, cfg *SubjectConfig) ([]byte, error) {
	// If no custom encoding config, use Go's default
	if cfg == nil || len(cfg.Attrs) == 0 {
		return asn1.Marshal(name.ToRDNSequence())
	}

	getEncoding := func(attrName string) DNEncoding {
		// Check for per-attribute encoding
		if attr, ok := cfg.Attrs[attrName]; ok && attr != nil && attr.Encoding != "" {
			return attr.Encoding
		}
		// Check RFC 5280 requirements
		if required := rfc5280RequiredEncoding(attrName); required != "" {
			return required
		}
		// Default to UTF8String
		return DNEncodingUTF8
	}

	var attrs []DNAttribute

	// Build attributes in RFC 5280 order
	for _, c := range name.Country {
		attrs = append(attrs, DNAttribute{OID: oidCountry, Value: c, Encoding: getEncoding("c")})
	}
	for _, p := range name.Province {
		attrs = append(attrs, DNAttribute{OID: oidProvince, Value: p, Encoding: getEncoding("st")})
	}
	for _, l := range name.Locality {
		attrs = append(attrs, DNAttribute{OID: oidLocality, Value: l, Encoding: getEncoding("l")})
	}
	for _, o := range name.Organization {
		attrs = append(attrs, DNAttribute{OID: oidOrganization, Value: o, Encoding: getEncoding("o")})
	}
	for _, ou := range name.OrganizationalUnit {
		attrs = append(attrs, DNAttribute{OID: oidOrganizationalUnit, Value: ou, Encoding: getEncoding("ou")})
	}
	if name.CommonName != "" {
		attrs = append(attrs, DNAttribute{OID: oidCommonName, Value: name.CommonName, Encoding: getEncoding("cn")})
	}
	if name.SerialNumber != "" {
		attrs = append(attrs, DNAttribute{OID: oidSerialNumber, Value: name.SerialNumber, Encoding: getEncoding("serialnumber")})
	}
	for _, s := range name.StreetAddress {
		attrs = append(attrs, DNAttribute{OID: oidStreetAddress, Value: s, Encoding: getEncoding("street")})
	}
	for _, pc := range name.PostalCode {
		attrs = append(attrs, DNAttribute{OID: oidPostalCode, Value: pc, Encoding: getEncoding("postalcode")})
	}

	return MarshalRDNSequence(attrs)
}

// BuildPkixName creates a pkix.Name from SubjectConfig with resolved values.
// Note: This loses encoding information and uses Go's default encoding.
// Use MarshalSubjectDN for custom encoding.
func BuildPkixName(cfg *SubjectConfig, values map[string]string) pkix.Name {
	name := pkix.Name{}

	getValue := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := values[k]; ok && v != "" {
				return v
			}
			if cfg.Attrs != nil {
				if attr, ok := cfg.Attrs[k]; ok && attr != nil && attr.Value != "" {
					return attr.Value
				}
			}
			if v, ok := cfg.Fixed[k]; ok && v != "" {
				return v
			}
		}
		return ""
	}

	if v := getValue("cn", "commonname"); v != "" {
		name.CommonName = v
	}
	if v := getValue("o", "organization"); v != "" {
		name.Organization = []string{v}
	}
	if v := getValue("ou"); v != "" {
		name.OrganizationalUnit = []string{v}
	}
	if v := getValue("c", "country"); v != "" {
		name.Country = []string{v}
	}
	if v := getValue("st", "state", "province"); v != "" {
		name.Province = []string{v}
	}
	if v := getValue("l", "locality"); v != "" {
		name.Locality = []string{v}
	}
	if v := getValue("street"); v != "" {
		name.StreetAddress = []string{v}
	}
	if v := getValue("postalcode"); v != "" {
		name.PostalCode = []string{v}
	}
	if v := getValue("serialnumber"); v != "" {
		name.SerialNumber = v
	}

	return name
}
