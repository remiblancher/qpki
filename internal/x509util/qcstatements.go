// Package x509util provides QCStatements extension support for eIDAS qualified certificates.
// Implements RFC 3739 and ETSI EN 319 412-5.
package x509util

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

// QcType represents the type of qualified certificate.
type QcType string

const (
	// QcTypeESign indicates electronic signature (natural person).
	QcTypeESign QcType = "esign"

	// QcTypeESeal indicates electronic seal (legal person).
	QcTypeESeal QcType = "eseal"

	// QcTypeWeb indicates qualified website authentication (QWAC).
	QcTypeWeb QcType = "web"
)

// PDSLocation represents a PKI Disclosure Statement location.
type PDSLocation struct {
	URL      string
	Language string // ISO 639-1 (2 chars)
}

// qcStatement is the ASN.1 structure for a single QCStatement.
// QCStatement ::= SEQUENCE {
//
//	statementId   OBJECT IDENTIFIER,
//	statementInfo ANY DEFINED BY statementId OPTIONAL
//
// }
type qcStatement struct {
	StatementID   asn1.ObjectIdentifier
	StatementInfo asn1.RawValue `asn1:"optional"`
}

// pdsLocation is the ASN.1 structure for a PDS location entry.
// PDSLocation ::= SEQUENCE {
//
//	url      IA5String,
//	language PrintableString (SIZE(2))
//
// }
type pdsLocation struct {
	URL      string `asn1:"ia5"`
	Language string `asn1:"printable"`
}

// QCStatementsBuilder builds a QCStatements extension.
type QCStatementsBuilder struct {
	statements []qcStatement
}

// NewQCStatementsBuilder creates a new QCStatements builder.
func NewQCStatementsBuilder() *QCStatementsBuilder {
	return &QCStatementsBuilder{
		statements: make([]qcStatement, 0),
	}
}

// AddQcCompliance adds the QcCompliance statement (0.4.0.1862.1.1).
// This indicates the certificate is an EU qualified certificate.
func (b *QCStatementsBuilder) AddQcCompliance() *QCStatementsBuilder {
	// QcCompliance has no statementInfo
	b.statements = append(b.statements, qcStatement{
		StatementID: OIDQcCompliance,
	})
	return b
}

// AddQcType adds the QcType statement (0.4.0.1862.1.6).
// Valid types: "esign", "eseal", "web".
func (b *QCStatementsBuilder) AddQcType(qcType QcType) error {
	var typeOID asn1.ObjectIdentifier

	switch qcType {
	case QcTypeESign:
		typeOID = OIDQcTypeESign
	case QcTypeESeal:
		typeOID = OIDQcTypeESeal
	case QcTypeWeb:
		typeOID = OIDQcTypeWeb
	default:
		return fmt.Errorf("invalid QcType: %q (expected esign, eseal, or web)", qcType)
	}

	// QcType statementInfo is SEQUENCE OF OBJECT IDENTIFIER
	// Even for a single type, it's a sequence
	typeOIDs := []asn1.ObjectIdentifier{typeOID}
	infoBytes, err := asn1.Marshal(typeOIDs)
	if err != nil {
		return fmt.Errorf("failed to marshal QcType: %w", err)
	}

	b.statements = append(b.statements, qcStatement{
		StatementID:   OIDQcType,
		StatementInfo: asn1.RawValue{FullBytes: infoBytes},
	})
	return nil
}

// AddQcSSCD adds the QcSSCD statement (0.4.0.1862.1.4).
// This indicates the private key is stored in a Qualified Signature Creation Device.
func (b *QCStatementsBuilder) AddQcSSCD() *QCStatementsBuilder {
	// QcSSCD has no statementInfo
	b.statements = append(b.statements, qcStatement{
		StatementID: OIDQcSSCD,
	})
	return b
}

// AddQcRetentionPeriod adds the QcRetentionPeriod statement (0.4.0.1862.1.3).
// The retention period is specified in years.
func (b *QCStatementsBuilder) AddQcRetentionPeriod(years int) error {
	if years < 0 {
		return fmt.Errorf("retention period must be non-negative, got %d", years)
	}

	// QcRetentionPeriod statementInfo is INTEGER
	infoBytes, err := asn1.Marshal(years)
	if err != nil {
		return fmt.Errorf("failed to marshal QcRetentionPeriod: %w", err)
	}

	b.statements = append(b.statements, qcStatement{
		StatementID:   OIDQcRetentionPeriod,
		StatementInfo: asn1.RawValue{FullBytes: infoBytes},
	})
	return nil
}

// AddQcPDS adds the QcPDS statement (0.4.0.1862.1.5).
// This references PKI Disclosure Statement documents.
func (b *QCStatementsBuilder) AddQcPDS(locations []PDSLocation) error {
	if len(locations) == 0 {
		return fmt.Errorf("QcPDS requires at least one location")
	}

	// Validate language codes
	for i, loc := range locations {
		if len(loc.Language) != 2 {
			return fmt.Errorf("QcPDS location %d: language must be 2 characters (ISO 639-1), got %q", i, loc.Language)
		}
		if loc.URL == "" {
			return fmt.Errorf("QcPDS location %d: URL is required", i)
		}
	}

	// QcPDS statementInfo is SEQUENCE OF PDSLocation
	pdsLocations := make([]pdsLocation, len(locations))
	for i, loc := range locations {
		pdsLocations[i] = pdsLocation(loc)
	}

	infoBytes, err := asn1.Marshal(pdsLocations)
	if err != nil {
		return fmt.Errorf("failed to marshal QcPDS: %w", err)
	}

	b.statements = append(b.statements, qcStatement{
		StatementID:   OIDQcPDS,
		StatementInfo: asn1.RawValue{FullBytes: infoBytes},
	})
	return nil
}

// Build creates the QCStatements extension.
func (b *QCStatementsBuilder) Build(critical bool) (pkix.Extension, error) {
	if len(b.statements) == 0 {
		return pkix.Extension{}, fmt.Errorf("QCStatements must contain at least one statement")
	}

	// QCStatements is SEQUENCE OF QCStatement
	value, err := asn1.Marshal(b.statements)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("failed to marshal QCStatements: %w", err)
	}

	return pkix.Extension{
		Id:       OIDQCStatements,
		Critical: critical,
		Value:    value,
	}, nil
}

// QCStatementsInfo holds decoded QCStatements information.
type QCStatementsInfo struct {
	QcCompliance      bool
	QcType            []QcType
	QcSSCD            bool
	QcRetentionPeriod *int
	QcPDS             []PDSLocation
}

// DecodeQCStatements parses a QCStatements extension.
func DecodeQCStatements(ext pkix.Extension) (*QCStatementsInfo, error) {
	if !OIDEqual(ext.Id, OIDQCStatements) {
		return nil, fmt.Errorf("not a QCStatements extension: %s", ext.Id)
	}

	var statements []qcStatement
	rest, err := asn1.Unmarshal(ext.Value, &statements)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal QCStatements: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data in QCStatements")
	}

	info := &QCStatementsInfo{}

	for _, stmt := range statements {
		switch {
		case OIDEqual(stmt.StatementID, OIDQcCompliance):
			info.QcCompliance = true

		case OIDEqual(stmt.StatementID, OIDQcSSCD):
			info.QcSSCD = true

		case OIDEqual(stmt.StatementID, OIDQcType):
			if len(stmt.StatementInfo.FullBytes) > 0 {
				var typeOIDs []asn1.ObjectIdentifier
				if _, err := asn1.Unmarshal(stmt.StatementInfo.FullBytes, &typeOIDs); err != nil {
					return nil, fmt.Errorf("failed to parse QcType: %w", err)
				}
				for _, oid := range typeOIDs {
					switch {
					case OIDEqual(oid, OIDQcTypeESign):
						info.QcType = append(info.QcType, QcTypeESign)
					case OIDEqual(oid, OIDQcTypeESeal):
						info.QcType = append(info.QcType, QcTypeESeal)
					case OIDEqual(oid, OIDQcTypeWeb):
						info.QcType = append(info.QcType, QcTypeWeb)
					}
				}
			}

		case OIDEqual(stmt.StatementID, OIDQcRetentionPeriod):
			if len(stmt.StatementInfo.FullBytes) > 0 {
				var years int
				if _, err := asn1.Unmarshal(stmt.StatementInfo.FullBytes, &years); err != nil {
					return nil, fmt.Errorf("failed to parse QcRetentionPeriod: %w", err)
				}
				info.QcRetentionPeriod = &years
			}

		case OIDEqual(stmt.StatementID, OIDQcPDS):
			if len(stmt.StatementInfo.FullBytes) > 0 {
				var pdsLocs []pdsLocation
				if _, err := asn1.Unmarshal(stmt.StatementInfo.FullBytes, &pdsLocs); err != nil {
					return nil, fmt.Errorf("failed to parse QcPDS: %w", err)
				}
				for _, loc := range pdsLocs {
					info.QcPDS = append(info.QcPDS, PDSLocation(loc))
				}
			}
		}
	}

	return info, nil
}

// FindQCStatements searches for the QCStatements extension in a list of extensions.
// Returns nil if not found.
func FindQCStatements(extensions []pkix.Extension) *pkix.Extension {
	for i := range extensions {
		if OIDEqual(extensions[i].Id, OIDQCStatements) {
			return &extensions[i]
		}
	}
	return nil
}

// HasQCStatements returns true if the extensions contain a QCStatements extension.
func HasQCStatements(extensions []pkix.Extension) bool {
	return FindQCStatements(extensions) != nil
}

// HasQCCompliance returns true if the extensions contain QCStatements with QcCompliance.
// This indicates the certificate is an EU qualified certificate per eIDAS.
func HasQCCompliance(extensions []pkix.Extension) bool {
	ext := FindQCStatements(extensions)
	if ext == nil {
		return false
	}
	info, err := DecodeQCStatements(*ext)
	if err != nil {
		return false
	}
	return info.QcCompliance
}
