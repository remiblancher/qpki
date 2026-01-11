package cms

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
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
	OriginatorInfo       asn1.RawValue   `asn1:"optional,tag:0"`
	RecipientInfos       []asn1.RawValue `asn1:"set"`
	EncryptedContentInfo EncryptedContentInfo
	UnprotectedAttrs     []Attribute `asn1:"optional,set,tag:1"`
}

// AuthEnvelopedData represents CMS AuthEnvelopedData (RFC 5083).
// Used for authenticated encryption (AES-GCM).
//
//	AuthEnvelopedData ::= SEQUENCE {
//	  version CMSVersion,
//	  originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
//	  recipientInfos RecipientInfos,
//	  authEncryptedContentInfo EncryptedContentInfo,
//	  authAttrs [1] IMPLICIT AuthAttributes OPTIONAL,
//	  mac MessageAuthenticationCode,
//	  unauthAttrs [2] IMPLICIT UnauthAttributes OPTIONAL }
type AuthEnvelopedData struct {
	Version                  int
	OriginatorInfo           asn1.RawValue   `asn1:"optional,tag:0"`
	RecipientInfos           []asn1.RawValue `asn1:"set"`
	AuthEncryptedContentInfo EncryptedContentInfo
	AuthAttrs                []Attribute `asn1:"optional,set,tag:1"`
	MAC                      []byte
	UnauthAttrs              []Attribute `asn1:"optional,set,tag:2"`
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
//
// Note: This is stored as RawValue because Go's encoding/asn1 cannot
// automatically handle CHOICE types. Use the helper methods to access.
type RecipientIdentifier struct {
	IssuerAndSerial *IssuerAndSerialNumber
	SKI             []byte `asn1:"optional,tag:0"`
}

// Marshal encodes RecipientIdentifier as ASN.1 DER.
// This handles the ASN.1 CHOICE by marshaling only the present alternative.
// Go's encoding/asn1 cannot automatically handle CHOICE types.
func (rid RecipientIdentifier) Marshal() ([]byte, error) {
	if rid.IssuerAndSerial != nil {
		// Marshal IssuerAndSerialNumber directly (no SEQUENCE wrapper needed,
		// IssuerAndSerialNumber is already a SEQUENCE)
		return asn1.Marshal(*rid.IssuerAndSerial)
	}
	if rid.SKI != nil {
		// Marshal as [0] IMPLICIT OCTET STRING
		return asn1.Marshal(asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: false,
			Bytes:      rid.SKI,
		})
	}
	return nil, asn1.StructuralError{Msg: "empty RecipientIdentifier: neither IssuerAndSerial nor SKI set"}
}

// ParseRecipientIdentifier parses a RecipientIdentifier from ASN.1 DER.
func ParseRecipientIdentifier(data []byte) (RecipientIdentifier, []byte, error) {
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(data, &raw)
	if err != nil {
		return RecipientIdentifier{}, nil, err
	}

	var rid RecipientIdentifier
	if raw.Tag == 0 && raw.Class == asn1.ClassContextSpecific {
		// SubjectKeyIdentifier [0]
		rid.SKI = raw.Bytes
	} else if raw.Tag == asn1.TagSequence && raw.Class == asn1.ClassUniversal {
		// IssuerAndSerialNumber (SEQUENCE)
		var ias IssuerAndSerialNumber
		if _, err := asn1.Unmarshal(raw.FullBytes, &ias); err != nil {
			return RecipientIdentifier{}, nil, err
		}
		rid.IssuerAndSerial = &ias
	} else {
		return RecipientIdentifier{}, nil, asn1.StructuralError{
			Msg: fmt.Sprintf("invalid RecipientIdentifier: tag=%d, class=%d", raw.Tag, raw.Class),
		}
	}

	return rid, rest, nil
}

// ParseKeyTransRecipientInfo parses a KeyTransRecipientInfo from ASN.1 DER.
// This handles the RecipientIdentifier CHOICE manually since Go's encoding/asn1
// cannot automatically handle CHOICE types with pointers.
func ParseKeyTransRecipientInfo(data []byte) (*KeyTransRecipientInfo, error) {
	// Parse outer SEQUENCE
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse KTRI outer: %w", err)
	}
	if raw.Tag != asn1.TagSequence {
		return nil, fmt.Errorf("expected SEQUENCE, got tag %d", raw.Tag)
	}

	remaining := raw.Bytes
	ktri := &KeyTransRecipientInfo{}

	// Parse version INTEGER
	var version int
	rest, err := asn1.Unmarshal(remaining, &version)
	if err != nil {
		return nil, fmt.Errorf("failed to parse version: %w", err)
	}
	ktri.Version = version
	remaining = rest

	// Parse RecipientIdentifier (CHOICE)
	rid, rest, err := ParseRecipientIdentifier(remaining)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RecipientIdentifier: %w", err)
	}
	ktri.RID = rid
	remaining = rest

	// Parse keyEncryptionAlgorithm AlgorithmIdentifier
	var alg pkix.AlgorithmIdentifier
	rest, err = asn1.Unmarshal(remaining, &alg)
	if err != nil {
		return nil, fmt.Errorf("failed to parse keyEncryptionAlgorithm: %w", err)
	}
	ktri.KeyEncryptionAlgorithm = alg
	remaining = rest

	// Parse encryptedKey OCTET STRING
	var encKey []byte
	_, err = asn1.Unmarshal(remaining, &encKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse encryptedKey: %w", err)
	}
	ktri.EncryptedKey = encKey

	return ktri, nil
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
	SKI             []byte               `asn1:"optional,tag:0"`
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

// Marshal encodes KeyAgreeRecipientIdentifier as ASN.1 DER.
func (karid KeyAgreeRecipientIdentifier) Marshal() ([]byte, error) {
	if karid.IssuerAndSerial != nil {
		return asn1.Marshal(*karid.IssuerAndSerial)
	}
	if karid.RKeyID != nil {
		// Marshal as [0] IMPLICIT RecipientKeyIdentifier
		rkiBytes, err := asn1.Marshal(*karid.RKeyID)
		if err != nil {
			return nil, err
		}
		// Wrap with [0] IMPLICIT tag
		return asn1.Marshal(asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      rkiBytes[2:], // Skip SEQUENCE tag
		})
	}
	return nil, asn1.StructuralError{Msg: "empty KeyAgreeRecipientIdentifier"}
}

// RecipientKeyIdentifier for key agreement recipient.
type RecipientKeyIdentifier struct {
	SubjectKeyIdentifier []byte
	Date                 asn1.RawValue `asn1:"optional"`
	Other                asn1.RawValue `asn1:"optional"`
}

// ParseKeyAgreeRecipientIdentifier parses a KeyAgreeRecipientIdentifier from ASN.1 DER.
func ParseKeyAgreeRecipientIdentifier(data []byte) (KeyAgreeRecipientIdentifier, []byte, error) {
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(data, &raw)
	if err != nil {
		return KeyAgreeRecipientIdentifier{}, nil, err
	}

	var karid KeyAgreeRecipientIdentifier
	if raw.Tag == 0 && raw.Class == asn1.ClassContextSpecific {
		// [0] RecipientKeyIdentifier
		var rki RecipientKeyIdentifier
		if _, err := asn1.Unmarshal(raw.Bytes, &rki); err != nil {
			return KeyAgreeRecipientIdentifier{}, nil, err
		}
		karid.RKeyID = &rki
	} else if raw.Tag == asn1.TagSequence && raw.Class == asn1.ClassUniversal {
		// IssuerAndSerialNumber (SEQUENCE)
		var ias IssuerAndSerialNumber
		if _, err := asn1.Unmarshal(raw.FullBytes, &ias); err != nil {
			return KeyAgreeRecipientIdentifier{}, nil, err
		}
		karid.IssuerAndSerial = &ias
	} else {
		return KeyAgreeRecipientIdentifier{}, nil, asn1.StructuralError{
			Msg: fmt.Sprintf("invalid KeyAgreeRecipientIdentifier: tag=%d, class=%d", raw.Tag, raw.Class),
		}
	}

	return karid, rest, nil
}

// ParseRecipientEncryptedKey parses a RecipientEncryptedKey from ASN.1 DER.
func ParseRecipientEncryptedKey(data []byte) (*RecipientEncryptedKey, []byte, error) {
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(data, &raw)
	if err != nil {
		return nil, nil, err
	}
	if raw.Tag != asn1.TagSequence {
		return nil, nil, fmt.Errorf("expected SEQUENCE, got tag %d", raw.Tag)
	}

	rek := &RecipientEncryptedKey{}
	remaining := raw.Bytes

	// Parse KeyAgreeRecipientIdentifier (CHOICE)
	karid, rest2, err := ParseKeyAgreeRecipientIdentifier(remaining)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse KeyAgreeRecipientIdentifier: %w", err)
	}
	rek.RID = karid
	remaining = rest2

	// Parse encryptedKey OCTET STRING
	var encKey []byte
	if _, err := asn1.Unmarshal(remaining, &encKey); err != nil {
		return nil, nil, fmt.Errorf("failed to parse encryptedKey: %w", err)
	}
	rek.EncryptedKey = encKey

	return rek, rest, nil
}

// ParseKeyAgreeRecipientInfo parses a KeyAgreeRecipientInfo from ASN.1 DER.
// The data should be the SEQUENCE content (after tag/length).
func ParseKeyAgreeRecipientInfo(data []byte) (*KeyAgreeRecipientInfo, error) {
	remaining := data
	kari := &KeyAgreeRecipientInfo{}

	// version INTEGER
	var version int
	rest, err := asn1.Unmarshal(remaining, &version)
	if err != nil {
		return nil, fmt.Errorf("failed to parse version: %w", err)
	}
	kari.Version = version
	remaining = rest

	// originator [0] EXPLICIT OriginatorIdentifierOrKey
	var originator asn1.RawValue
	rest, err = asn1.Unmarshal(remaining, &originator)
	if err != nil {
		return nil, fmt.Errorf("failed to parse originator: %w", err)
	}
	kari.Originator = originator
	remaining = rest

	// ukm [1] EXPLICIT OPTIONAL - check if next element is [1]
	var nextRaw asn1.RawValue
	peekRest, err := asn1.Unmarshal(remaining, &nextRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to peek next element: %w", err)
	}
	if nextRaw.Tag == 1 && nextRaw.Class == asn1.ClassContextSpecific {
		// UKM is present
		var ukm []byte
		if _, err := asn1.Unmarshal(nextRaw.Bytes, &ukm); err != nil {
			return nil, fmt.Errorf("failed to parse UKM: %w", err)
		}
		kari.UKM = ukm
		remaining = peekRest
	}

	// keyEncryptionAlgorithm AlgorithmIdentifier
	var alg pkix.AlgorithmIdentifier
	rest, err = asn1.Unmarshal(remaining, &alg)
	if err != nil {
		return nil, fmt.Errorf("failed to parse keyEncryptionAlgorithm: %w", err)
	}
	kari.KeyEncryptionAlgorithm = alg
	remaining = rest

	// recipientEncryptedKeys SEQUENCE OF RecipientEncryptedKey
	var reksRaw asn1.RawValue
	_, err = asn1.Unmarshal(remaining, &reksRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to parse recipientEncryptedKeys: %w", err)
	}
	if reksRaw.Tag != asn1.TagSequence {
		return nil, fmt.Errorf("expected SEQUENCE for recipientEncryptedKeys, got tag %d", reksRaw.Tag)
	}

	// Parse each RecipientEncryptedKey
	reksData := reksRaw.Bytes
	for len(reksData) > 0 {
		rek, rest2, err := ParseRecipientEncryptedKey(reksData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RecipientEncryptedKey: %w", err)
		}
		kari.RecipientEncryptedKeys = append(kari.RecipientEncryptedKeys, *rek)
		reksData = rest2
	}

	return kari, nil
}

// MarshalRecipientEncryptedKey marshals a RecipientEncryptedKey.
func MarshalRecipientEncryptedKey(rek *RecipientEncryptedKey) ([]byte, error) {
	var b []byte

	// rid KeyAgreeRecipientIdentifier (CHOICE)
	ridBytes, err := rek.RID.Marshal()
	if err != nil {
		return nil, err
	}
	b = append(b, ridBytes...)

	// encryptedKey OCTET STRING
	keyBytes, err := asn1.Marshal(rek.EncryptedKey)
	if err != nil {
		return nil, err
	}
	b = append(b, keyBytes...)

	// Wrap as SEQUENCE
	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      b,
	})
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
	Version      int
	RID          RecipientIdentifier
	KEM          pkix.AlgorithmIdentifier
	KEMCT        []byte // KEM ciphertext
	KDF          pkix.AlgorithmIdentifier
	KEKLength    int
	UKM          []byte `asn1:"optional,explicit,tag:0"`
	Wrap         pkix.AlgorithmIdentifier
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
// This manually constructs the ASN.1 SEQUENCE because RecipientIdentifier
// is a CHOICE type that Go's encoding/asn1 cannot automatically marshal.
func MarshalKeyTransRecipientInfo(ktri *KeyTransRecipientInfo) ([]byte, error) {
	var b []byte

	// version INTEGER
	versionBytes, err := asn1.Marshal(ktri.Version)
	if err != nil {
		return nil, err
	}
	b = append(b, versionBytes...)

	// rid RecipientIdentifier (CHOICE - requires manual marshaling)
	ridBytes, err := ktri.RID.Marshal()
	if err != nil {
		return nil, err
	}
	b = append(b, ridBytes...)

	// keyEncryptionAlgorithm AlgorithmIdentifier
	algBytes, err := asn1.Marshal(ktri.KeyEncryptionAlgorithm)
	if err != nil {
		return nil, err
	}
	b = append(b, algBytes...)

	// encryptedKey OCTET STRING
	keyBytes, err := asn1.Marshal(ktri.EncryptedKey)
	if err != nil {
		return nil, err
	}
	b = append(b, keyBytes...)

	// Wrap as SEQUENCE
	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      b,
	})
}

// MarshalKeyAgreeRecipientInfo marshals KeyAgreeRecipientInfo with [1] IMPLICIT tag.
// This manually constructs the ASN.1 because RecipientEncryptedKey contains
// KeyAgreeRecipientIdentifier which is a CHOICE type.
func MarshalKeyAgreeRecipientInfo(kari *KeyAgreeRecipientInfo) ([]byte, error) {
	var b []byte

	// version INTEGER
	versionBytes, err := asn1.Marshal(kari.Version)
	if err != nil {
		return nil, err
	}
	b = append(b, versionBytes...)

	// originator [0] EXPLICIT OriginatorIdentifierOrKey
	// The Originator is stored as RawValue, we need to wrap it properly
	var originatorBytes []byte
	if len(kari.Originator.FullBytes) > 0 {
		originatorBytes = kari.Originator.FullBytes
	} else {
		// Construct from Bytes with proper tag
		originatorBytes, err = asn1.Marshal(asn1.RawValue{
			Class:      kari.Originator.Class,
			Tag:        kari.Originator.Tag,
			IsCompound: kari.Originator.IsCompound,
			Bytes:      kari.Originator.Bytes,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to marshal originator: %w", err)
		}
	}
	// Wrap with [0] EXPLICIT tag
	originatorWrapped, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      originatorBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to wrap originator: %w", err)
	}
	b = append(b, originatorWrapped...)

	// ukm [1] EXPLICIT OPTIONAL
	if len(kari.UKM) > 0 {
		ukmInner, err := asn1.Marshal(kari.UKM)
		if err != nil {
			return nil, err
		}
		ukmBytes, err := asn1.Marshal(asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        1,
			IsCompound: true,
			Bytes:      ukmInner,
		})
		if err != nil {
			return nil, err
		}
		b = append(b, ukmBytes...)
	}

	// keyEncryptionAlgorithm AlgorithmIdentifier
	algBytes, err := asn1.Marshal(kari.KeyEncryptionAlgorithm)
	if err != nil {
		return nil, err
	}
	b = append(b, algBytes...)

	// recipientEncryptedKeys SEQUENCE OF RecipientEncryptedKey
	var reksBytes []byte
	for i := range kari.RecipientEncryptedKeys {
		rekBytes, err := MarshalRecipientEncryptedKey(&kari.RecipientEncryptedKeys[i])
		if err != nil {
			return nil, err
		}
		reksBytes = append(reksBytes, rekBytes...)
	}
	// Wrap as SEQUENCE
	reksSeq, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      reksBytes,
	})
	if err != nil {
		return nil, err
	}
	b = append(b, reksSeq...)

	// Wrap content as SEQUENCE, then apply [1] IMPLICIT tag
	seqBytes, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      b,
	})
	if err != nil {
		return nil, err
	}

	// Convert to [1] IMPLICIT by changing the tag
	// seqBytes[0] is 0x30 (SEQUENCE), change to 0xa1 ([1] context-specific constructed)
	result := make([]byte, len(seqBytes))
	copy(result, seqBytes)
	result[0] = 0xa1 // [1] IMPLICIT context-specific constructed

	return result, nil
}

// MarshalKEMRecipientInfo marshals KEMRecipientInfo wrapped in OtherRecipientInfo [4].
// Per RFC 9629, KEMRecipientInfo must be wrapped in OtherRecipientInfo with id-ori-kem OID.
func MarshalKEMRecipientInfo(kemri *KEMRecipientInfo) ([]byte, error) {
	// Build the KEMRecipientInfo SEQUENCE content manually for proper encoding
	var kemriContent []byte

	// version INTEGER
	versionBytes, err := asn1.Marshal(kemri.Version)
	if err != nil {
		return nil, err
	}
	kemriContent = append(kemriContent, versionBytes...)

	// rid RecipientIdentifier (IssuerAndSerialNumber)
	if kemri.RID.IssuerAndSerial != nil {
		ridBytes, err := asn1.Marshal(*kemri.RID.IssuerAndSerial)
		if err != nil {
			return nil, err
		}
		kemriContent = append(kemriContent, ridBytes...)
	}

	// kem AlgorithmIdentifier
	kemBytes, err := asn1.Marshal(kemri.KEM)
	if err != nil {
		return nil, err
	}
	kemriContent = append(kemriContent, kemBytes...)

	// kemct OCTET STRING
	kemctBytes, err := asn1.Marshal(kemri.KEMCT)
	if err != nil {
		return nil, err
	}
	kemriContent = append(kemriContent, kemctBytes...)

	// kdf AlgorithmIdentifier
	kdfBytes, err := asn1.Marshal(kemri.KDF)
	if err != nil {
		return nil, err
	}
	kemriContent = append(kemriContent, kdfBytes...)

	// kekLength INTEGER
	kekLenBytes, err := asn1.Marshal(kemri.KEKLength)
	if err != nil {
		return nil, err
	}
	kemriContent = append(kemriContent, kekLenBytes...)

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
		kemriContent = append(kemriContent, ukmBytes...)
	}

	// wrap AlgorithmIdentifier
	wrapBytes, err := asn1.Marshal(kemri.Wrap)
	if err != nil {
		return nil, err
	}
	kemriContent = append(kemriContent, wrapBytes...)

	// encryptedKey OCTET STRING
	encKeyBytes, err := asn1.Marshal(kemri.EncryptedKey)
	if err != nil {
		return nil, err
	}
	kemriContent = append(kemriContent, encKeyBytes...)

	// Build KEMRecipientInfo as SEQUENCE
	kemriSeqBytes, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      kemriContent,
	})
	if err != nil {
		return nil, err
	}

	// Build OtherRecipientInfo SEQUENCE content:
	// OtherRecipientInfo ::= SEQUENCE { oriType OID, oriValue ANY }
	var oriContent []byte

	// oriType: id-ori-kem OID
	oriTypeBytes, err := asn1.Marshal(OIDOriKEM)
	if err != nil {
		return nil, err
	}
	oriContent = append(oriContent, oriTypeBytes...)

	// oriValue: KEMRecipientInfo (already a SEQUENCE)
	oriContent = append(oriContent, kemriSeqBytes...)

	// Wrap as [4] IMPLICIT SEQUENCE (OtherRecipientInfo)
	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        4,
		IsCompound: true,
		Bytes:      oriContent,
	})
}

// ParseKEMRecipientInfo parses a KEMRecipientInfo from DER bytes.
// This handles the RecipientIdentifier CHOICE properly.
func ParseKEMRecipientInfo(data []byte) (*KEMRecipientInfo, error) {
	remaining := data
	kemri := &KEMRecipientInfo{}

	// version INTEGER
	var version int
	rest, err := asn1.Unmarshal(remaining, &version)
	if err != nil {
		return nil, fmt.Errorf("failed to parse version: %w", err)
	}
	kemri.Version = version
	remaining = rest

	// rid RecipientIdentifier (CHOICE)
	rid, rest, err := ParseRecipientIdentifier(remaining)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RecipientIdentifier: %w", err)
	}
	kemri.RID = rid
	remaining = rest

	// kem AlgorithmIdentifier
	var kem pkix.AlgorithmIdentifier
	rest, err = asn1.Unmarshal(remaining, &kem)
	if err != nil {
		return nil, fmt.Errorf("failed to parse KEM algorithm: %w", err)
	}
	kemri.KEM = kem
	remaining = rest

	// kemct OCTET STRING
	var kemct []byte
	rest, err = asn1.Unmarshal(remaining, &kemct)
	if err != nil {
		return nil, fmt.Errorf("failed to parse KEMCT: %w", err)
	}
	kemri.KEMCT = kemct
	remaining = rest

	// kdf AlgorithmIdentifier
	var kdf pkix.AlgorithmIdentifier
	rest, err = asn1.Unmarshal(remaining, &kdf)
	if err != nil {
		return nil, fmt.Errorf("failed to parse KDF algorithm: %w", err)
	}
	kemri.KDF = kdf
	remaining = rest

	// kekLength INTEGER
	var kekLength int
	rest, err = asn1.Unmarshal(remaining, &kekLength)
	if err != nil {
		return nil, fmt.Errorf("failed to parse KEK length: %w", err)
	}
	kemri.KEKLength = kekLength
	remaining = rest

	// ukm [0] EXPLICIT OPTIONAL
	var nextRaw asn1.RawValue
	rest, err = asn1.Unmarshal(remaining, &nextRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to peek next element: %w", err)
	}
	if nextRaw.Tag == 0 && nextRaw.Class == asn1.ClassContextSpecific {
		// UKM is present
		var ukm []byte
		if _, err := asn1.Unmarshal(nextRaw.Bytes, &ukm); err != nil {
			return nil, fmt.Errorf("failed to parse UKM: %w", err)
		}
		kemri.UKM = ukm
		remaining = rest
		// Re-peek for wrap
		rest, err = asn1.Unmarshal(remaining, &nextRaw)
		if err != nil {
			return nil, fmt.Errorf("failed to parse after UKM: %w", err)
		}
	}

	// wrap AlgorithmIdentifier - we already have nextRaw from above
	var wrap pkix.AlgorithmIdentifier
	if nextRaw.Tag == asn1.TagSequence && nextRaw.Class == asn1.ClassUniversal {
		if _, err := asn1.Unmarshal(nextRaw.FullBytes, &wrap); err != nil {
			return nil, fmt.Errorf("failed to parse wrap algorithm: %w", err)
		}
		remaining = rest
	} else {
		return nil, fmt.Errorf("expected wrap AlgorithmIdentifier, got tag=%d", nextRaw.Tag)
	}
	kemri.Wrap = wrap

	// encryptedKey OCTET STRING
	var encKey []byte
	_, err = asn1.Unmarshal(remaining, &encKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse encrypted key: %w", err)
	}
	kemri.EncryptedKey = encKey

	return kemri, nil
}

// ParseRecipientInfo parses a RecipientInfo from RawValue.
func ParseRecipientInfo(raw asn1.RawValue) (interface{}, error) {
	switch raw.Tag {
	case asn1.TagSequence:
		// KeyTransRecipientInfo (default, no tag)
		// Use custom parser to handle RecipientIdentifier CHOICE
		return ParseKeyTransRecipientInfo(raw.FullBytes)

	case 1:
		// [1] KeyAgreeRecipientInfo
		// Use custom parser - raw.Bytes doesn't have SEQUENCE wrapper
		return ParseKeyAgreeRecipientInfo(raw.Bytes)

	case 2:
		// [2] KEMRecipientInfo
		// Use custom parser - raw.Bytes doesn't have SEQUENCE wrapper
		return ParseKEMRecipientInfo(raw.Bytes)

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
