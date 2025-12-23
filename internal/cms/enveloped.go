package cms

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
)

// EnvelopedData represents CMS EnvelopedData (RFC 5652 Section 6).
//
//	EnvelopedData ::= SEQUENCE {
//	  version CMSVersion,
//	  originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
//	  recipientInfos RecipientInfos,
//	  encryptedContentInfo EncryptedContentInfo,
//	  unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
type EnvelopedData struct {
	Version              int
	OriginatorInfo       asn1.RawValue        `asn1:"optional,tag:0"`
	RecipientInfos       []asn1.RawValue      `asn1:"set"`
	EncryptedContentInfo EncryptedContentInfo
	UnprotectedAttrs     []Attribute          `asn1:"optional,set,tag:1"`
}

// EncryptedContentInfo contains the encrypted content (RFC 5652 Section 6.1).
//
//	EncryptedContentInfo ::= SEQUENCE {
//	  contentType ContentType,
//	  contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
//	  encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL }
type EncryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           []byte `asn1:"optional,tag:0"`
}

// RecipientInfo is the CHOICE for different key management techniques.
// We handle it as RawValue and parse based on tag.
//
//	RecipientInfo ::= CHOICE {
//	  ktri KeyTransRecipientInfo,
//	  kari [1] KeyAgreeRecipientInfo,
//	  kekri [2] KEKRecipientInfo,
//	  pwri [3] PasswordRecipientInfo,
//	  ori [4] OtherRecipientInfo }

// KeyTransRecipientInfo for RSA key transport (RFC 5652 Section 6.2.1).
//
//	KeyTransRecipientInfo ::= SEQUENCE {
//	  version CMSVersion,  -- always set to 0 or 2
//	  rid RecipientIdentifier,
//	  keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
//	  encryptedKey EncryptedKey }
type KeyTransRecipientInfo struct {
	Version                int
	RID                    RecipientIdentifier
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedKey           []byte
}

// RecipientIdentifier identifies the recipient's certificate.
//
//	RecipientIdentifier ::= CHOICE {
//	  issuerAndSerialNumber IssuerAndSerialNumber,
//	  subjectKeyIdentifier [0] SubjectKeyIdentifier }
type RecipientIdentifier struct {
	IssuerAndSerial *IssuerAndSerialNumber
	SKI             []byte `asn1:"optional,tag:0"`
}

// KeyAgreeRecipientInfo for ECDH key agreement (RFC 5652 Section 6.2.2).
//
//	KeyAgreeRecipientInfo ::= SEQUENCE {
//	  version CMSVersion,  -- always set to 3
//	  originator [0] EXPLICIT OriginatorIdentifierOrKey,
//	  ukm [1] EXPLICIT UserKeyingMaterial OPTIONAL,
//	  keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
//	  recipientEncryptedKeys RecipientEncryptedKeys }
type KeyAgreeRecipientInfo struct {
	Version                int
	Originator             asn1.RawValue `asn1:"explicit,tag:0"`
	UKM                    []byte        `asn1:"optional,explicit,tag:1"`
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	RecipientEncryptedKeys []RecipientEncryptedKey `asn1:"sequence"`
}

// OriginatorIdentifierOrKey identifies the sender for key agreement.
//
//	OriginatorIdentifierOrKey ::= CHOICE {
//	  issuerAndSerialNumber IssuerAndSerialNumber,
//	  subjectKeyIdentifier [0] SubjectKeyIdentifier,
//	  originatorKey [1] OriginatorPublicKey }
type OriginatorIdentifierOrKey struct {
	IssuerAndSerial *IssuerAndSerialNumber
	SKI             []byte `asn1:"optional,tag:0"`
	OriginatorKey   *OriginatorPublicKey `asn1:"optional,tag:1"`
}

// OriginatorPublicKey contains ephemeral public key for key agreement.
//
//	OriginatorPublicKey ::= SEQUENCE {
//	  algorithm AlgorithmIdentifier,
//	  publicKey BIT STRING }
type OriginatorPublicKey struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// RecipientEncryptedKey contains the encrypted CEK for a recipient.
//
//	RecipientEncryptedKey ::= SEQUENCE {
//	  rid KeyAgreeRecipientIdentifier,
//	  encryptedKey EncryptedKey }
type RecipientEncryptedKey struct {
	RID          KeyAgreeRecipientIdentifier
	EncryptedKey []byte
}

// KeyAgreeRecipientIdentifier identifies recipient in key agreement.
//
//	KeyAgreeRecipientIdentifier ::= CHOICE {
//	  issuerAndSerialNumber IssuerAndSerialNumber,
//	  rKeyId [0] IMPLICIT RecipientKeyIdentifier }
type KeyAgreeRecipientIdentifier struct {
	IssuerAndSerial *IssuerAndSerialNumber
	RKeyID          *RecipientKeyIdentifier `asn1:"optional,tag:0"`
}

// RecipientKeyIdentifier for key agreement recipient.
type RecipientKeyIdentifier struct {
	SubjectKeyIdentifier []byte
	Date                 asn1.RawValue `asn1:"optional"`
	Other                asn1.RawValue `asn1:"optional"`
}

// KEMRecipientInfo for ML-KEM (draft-ietf-lamps-cms-kemri).
//
//	KEMRecipientInfo ::= SEQUENCE {
//	  version CMSVersion,  -- always 0
//	  rid RecipientIdentifier,
//	  kem KEMAlgorithmIdentifier,
//	  kemct OCTET STRING,
//	  kdf KeyDerivationAlgorithmIdentifier,
//	  kekLength INTEGER (1..65535),
//	  ukm [0] EXPLICIT UserKeyingMaterial OPTIONAL,
//	  wrap KeyEncryptionAlgorithmIdentifier,
//	  encryptedKey EncryptedKey }
type KEMRecipientInfo struct {
	Version    int
	RID        RecipientIdentifier
	KEM        pkix.AlgorithmIdentifier
	KEMCT      []byte // KEM ciphertext
	KDF        pkix.AlgorithmIdentifier
	KEKLength  int
	UKM        []byte `asn1:"optional,explicit,tag:0"`
	Wrap       pkix.AlgorithmIdentifier
	EncryptedKey []byte
}

// GCMParameters for AES-GCM (RFC 5084).
//
//	GCMParameters ::= SEQUENCE {
//	  aes-nonce        OCTET STRING,
//	  aes-ICVlen       AES-GCM-ICVlen DEFAULT 12 }
type GCMParameters struct {
	Nonce  []byte
	ICVLen int `asn1:"optional,default:12"`
}

// RSAOAEPParams for RSA-OAEP (RFC 4055).
//
//	RSAES-OAEP-params ::= SEQUENCE {
//	  hashAlgorithm      [0] HashAlgorithm     DEFAULT sha1,
//	  maskGenAlgorithm   [1] MaskGenAlgorithm  DEFAULT mgf1SHA1,
//	  pSourceAlgorithm   [2] PSourceAlgorithm  DEFAULT pSpecifiedEmpty }
type RSAOAEPParams struct {
	HashAlgorithm    pkix.AlgorithmIdentifier `asn1:"optional,explicit,tag:0"`
	MaskGenAlgorithm pkix.AlgorithmIdentifier `asn1:"optional,explicit,tag:1"`
	PSourceAlgorithm pkix.AlgorithmIdentifier `asn1:"optional,explicit,tag:2"`
}

// MarshalKeyTransRecipientInfo marshals KeyTransRecipientInfo.
func MarshalKeyTransRecipientInfo(ktri *KeyTransRecipientInfo) ([]byte, error) {
	// KeyTransRecipientInfo is a SEQUENCE (tag 0x30)
	// For RecipientInfo CHOICE, ktri is the default (no implicit tag)
	return asn1.Marshal(*ktri)
}

// MarshalKeyAgreeRecipientInfo marshals KeyAgreeRecipientInfo with [1] IMPLICIT tag.
func MarshalKeyAgreeRecipientInfo(kari *KeyAgreeRecipientInfo) ([]byte, error) {
	// Marshal the content first
	content, err := asn1.Marshal(*kari)
	if err != nil {
		return nil, err
	}

	// Wrap with [1] IMPLICIT tag (0xa1 = context-specific constructed tag 1)
	return asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        1,
		IsCompound: true,
		Bytes:      content[2:], // Skip the SEQUENCE tag and length
	}.Bytes, nil
}

// MarshalKEMRecipientInfo marshals KEMRecipientInfo with [2] IMPLICIT tag.
func MarshalKEMRecipientInfo(kemri *KEMRecipientInfo) ([]byte, error) {
	// Build the SEQUENCE content manually for proper encoding
	var b []byte

	// version INTEGER
	versionBytes, err := asn1.Marshal(kemri.Version)
	if err != nil {
		return nil, err
	}
	b = append(b, versionBytes...)

	// rid RecipientIdentifier (IssuerAndSerialNumber)
	if kemri.RID.IssuerAndSerial != nil {
		ridBytes, err := asn1.Marshal(*kemri.RID.IssuerAndSerial)
		if err != nil {
			return nil, err
		}
		b = append(b, ridBytes...)
	}

	// kem AlgorithmIdentifier
	kemBytes, err := asn1.Marshal(kemri.KEM)
	if err != nil {
		return nil, err
	}
	b = append(b, kemBytes...)

	// kemct OCTET STRING
	kemctBytes, err := asn1.Marshal(kemri.KEMCT)
	if err != nil {
		return nil, err
	}
	b = append(b, kemctBytes...)

	// kdf AlgorithmIdentifier
	kdfBytes, err := asn1.Marshal(kemri.KDF)
	if err != nil {
		return nil, err
	}
	b = append(b, kdfBytes...)

	// kekLength INTEGER
	kekLenBytes, err := asn1.Marshal(kemri.KEKLength)
	if err != nil {
		return nil, err
	}
	b = append(b, kekLenBytes...)

	// ukm [0] EXPLICIT OPTIONAL - skip if empty
	if len(kemri.UKM) > 0 {
		ukmInner, err := asn1.Marshal(kemri.UKM)
		if err != nil {
			return nil, err
		}
		ukmBytes, err := asn1.Marshal(asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      ukmInner,
		})
		if err != nil {
			return nil, err
		}
		b = append(b, ukmBytes...)
	}

	// wrap AlgorithmIdentifier
	wrapBytes, err := asn1.Marshal(kemri.Wrap)
	if err != nil {
		return nil, err
	}
	b = append(b, wrapBytes...)

	// encryptedKey OCTET STRING
	encKeyBytes, err := asn1.Marshal(kemri.EncryptedKey)
	if err != nil {
		return nil, err
	}
	b = append(b, encKeyBytes...)

	// Wrap as [2] IMPLICIT SEQUENCE
	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        2,
		IsCompound: true,
		Bytes:      b,
	})
}

// ParseRecipientInfo parses a RecipientInfo from RawValue.
func ParseRecipientInfo(raw asn1.RawValue) (interface{}, error) {
	switch raw.Tag {
	case asn1.TagSequence:
		// KeyTransRecipientInfo (default, no tag)
		var ktri KeyTransRecipientInfo
		_, err := asn1.Unmarshal(raw.FullBytes, &ktri)
		return &ktri, err

	case 1:
		// [1] KeyAgreeRecipientInfo
		var kari KeyAgreeRecipientInfo
		_, err := asn1.Unmarshal(raw.Bytes, &kari)
		return &kari, err

	case 2:
		// [2] KEMRecipientInfo
		var kemri KEMRecipientInfo
		_, err := asn1.Unmarshal(raw.Bytes, &kemri)
		return &kemri, err

	default:
		return nil, asn1.StructuralError{Msg: "unsupported RecipientInfo type"}
	}
}

// RecipientIdentifierFromCert creates a RecipientIdentifier from a certificate.
func RecipientIdentifierFromCert(serialNumber *big.Int, issuerRaw []byte) RecipientIdentifier {
	return RecipientIdentifier{
		IssuerAndSerial: &IssuerAndSerialNumber{
			Issuer:       asn1.RawValue{FullBytes: issuerRaw},
			SerialNumber: serialNumber,
		},
	}
}
