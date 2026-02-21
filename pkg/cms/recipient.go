package cms

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/remiblancher/qpki/pkg/credential"
)

// ExtractRecipientMatchers parses a CMS EnvelopedData or AuthEnvelopedData
// and extracts RecipientMatchers for each recipient.
// These matchers can be used with credential.FindDecryptionKeyByRecipient
// to find the appropriate decryption key from a credential store.
func ExtractRecipientMatchers(data []byte) ([]*credential.RecipientMatcher, error) {
	// Parse ContentInfo
	var ci ContentInfo
	rest, err := asn1.Unmarshal(data, &ci)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ContentInfo: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data after ContentInfo")
	}

	var recipientInfos []asn1.RawValue

	// Route based on content type
	if ci.ContentType.Equal(OIDAuthEnvelopedData) {
		var authEnv AuthEnvelopedData
		if _, err := asn1.Unmarshal(ci.Content.Bytes, &authEnv); err != nil {
			return nil, fmt.Errorf("failed to parse AuthEnvelopedData: %w", err)
		}
		recipientInfos = authEnv.RecipientInfos
	} else if ci.ContentType.Equal(OIDEnvelopedData) {
		var env EnvelopedData
		if _, err := asn1.Unmarshal(ci.Content.Bytes, &env); err != nil {
			return nil, fmt.Errorf("failed to parse EnvelopedData: %w", err)
		}
		recipientInfos = env.RecipientInfos
	} else {
		return nil, fmt.Errorf("not an EnvelopedData or AuthEnvelopedData: %v", ci.ContentType)
	}

	// Extract matchers from each RecipientInfo
	var matchers []*credential.RecipientMatcher
	for _, riRaw := range recipientInfos {
		ms, err := extractMatchersFromRecipientInfo(riRaw)
		if err != nil {
			// Skip unparseable recipients, continue with others
			continue
		}
		matchers = append(matchers, ms...)
	}

	if len(matchers) == 0 {
		return nil, fmt.Errorf("no recipient matchers could be extracted")
	}

	return matchers, nil
}

// extractMatchersFromRecipientInfo extracts RecipientMatchers from a single RecipientInfo.
// Returns multiple matchers for KeyAgreeRecipientInfo which can have multiple recipients.
func extractMatchersFromRecipientInfo(riRaw asn1.RawValue) ([]*credential.RecipientMatcher, error) {
	switch {
	case riRaw.Tag == asn1.TagSequence && riRaw.Class == asn1.ClassUniversal:
		// KeyTransRecipientInfo (SEQUENCE, no tag)
		ktri, err := ParseKeyTransRecipientInfo(riRaw.FullBytes)
		if err != nil {
			return nil, err
		}
		return matchersFromRecipientIdentifier(&ktri.RID), nil

	case riRaw.Tag == 1 && riRaw.Class == asn1.ClassContextSpecific:
		// [1] KeyAgreeRecipientInfo
		kari, err := ParseKeyAgreeRecipientInfo(riRaw.Bytes)
		if err != nil {
			return nil, err
		}
		return matchersFromKeyAgreeRecipientInfo(kari), nil

	case riRaw.Tag == 4 && riRaw.Class == asn1.ClassContextSpecific:
		// [4] OtherRecipientInfo - contains KEMRecipientInfo per RFC 9629
		kemri, err := parseOtherRecipientInfoKEM(riRaw.Bytes)
		if err != nil {
			return nil, err
		}
		return matchersFromRecipientIdentifier(&kemri.RID), nil

	default:
		return nil, fmt.Errorf("unsupported RecipientInfo type: tag=%d, class=%d", riRaw.Tag, riRaw.Class)
	}
}

// matchersFromRecipientIdentifier creates a RecipientMatcher from a RecipientIdentifier.
func matchersFromRecipientIdentifier(rid *RecipientIdentifier) []*credential.RecipientMatcher {
	var matchers []*credential.RecipientMatcher

	if rid.IssuerAndSerial != nil {
		matcher := &credential.RecipientMatcher{
			IssuerAndSerialNumber: &credential.IssuerAndSerial{
				Issuer:       convertIssuer(rid.IssuerAndSerial.Issuer),
				SerialNumber: rid.IssuerAndSerial.SerialNumber,
			},
		}
		matchers = append(matchers, matcher)
	}

	if len(rid.SKI) > 0 {
		matcher := &credential.RecipientMatcher{
			SubjectKeyIdentifier: rid.SKI,
		}
		matchers = append(matchers, matcher)
	}

	return matchers
}

// matchersFromKeyAgreeRecipientInfo extracts matchers from all recipients in a KARI.
func matchersFromKeyAgreeRecipientInfo(kari *KeyAgreeRecipientInfo) []*credential.RecipientMatcher {
	var matchers []*credential.RecipientMatcher

	for _, rek := range kari.RecipientEncryptedKeys {
		if rek.RID.IssuerAndSerial != nil {
			matcher := &credential.RecipientMatcher{
				IssuerAndSerialNumber: &credential.IssuerAndSerial{
					Issuer:       convertIssuer(rek.RID.IssuerAndSerial.Issuer),
					SerialNumber: rek.RID.IssuerAndSerial.SerialNumber,
				},
			}
			matchers = append(matchers, matcher)
		}

		if rek.RID.RKeyID != nil && len(rek.RID.RKeyID.SubjectKeyIdentifier) > 0 {
			matcher := &credential.RecipientMatcher{
				SubjectKeyIdentifier: rek.RID.RKeyID.SubjectKeyIdentifier,
			}
			matchers = append(matchers, matcher)
		}
	}

	return matchers
}

// convertIssuer converts a CMS IssuerAndSerialNumber.Issuer to pkix.RDNSequence.
func convertIssuer(issuer asn1.RawValue) pkix.RDNSequence {
	var rdn pkix.RDNSequence
	if _, err := asn1.Unmarshal(issuer.FullBytes, &rdn); err != nil {
		// If we can't parse it, return empty sequence
		// The raw bytes comparison in MatchesCertificate will still work
		return nil
	}
	return rdn
}

// IssuerAndSerialFromCertificate creates an IssuerAndSerial from an x509.Certificate.
// This is useful for creating matchers programmatically.
func IssuerAndSerialFromCertificate(issuerRaw []byte, serialNumber *big.Int) *credential.IssuerAndSerial {
	var issuer pkix.RDNSequence
	if _, err := asn1.Unmarshal(issuerRaw, &issuer); err != nil {
		return nil
	}
	return &credential.IssuerAndSerial{
		Issuer:       issuer,
		SerialNumber: serialNumber,
	}
}
