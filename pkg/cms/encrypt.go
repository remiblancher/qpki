package cms

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"hash"
	"io"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/kem/mlkem/mlkem512"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"golang.org/x/crypto/hkdf"

	pkicrypto "github.com/remiblancher/qpki/pkg/crypto"
)

// EncryptOptions configures CMS encryption.
type EncryptOptions struct {
	// Recipients is the list of recipient certificates.
	// Each recipient will have their own RecipientInfo in the EnvelopedData.
	Recipients []*x509.Certificate

	// ContentType is the OID for the content being encrypted.
	// Defaults to id-data (1.2.840.113549.1.7.1).
	ContentType asn1.ObjectIdentifier

	// ContentEncryption specifies the content encryption algorithm.
	// Defaults to AES-256-GCM.
	ContentEncryption ContentEncryptionAlgorithm
}

// ContentEncryptionAlgorithm identifies the content encryption algorithm.
type ContentEncryptionAlgorithm int

const (
	// AES256GCM is AES-256 in GCM mode (recommended).
	AES256GCM ContentEncryptionAlgorithm = iota
	// AES256CBC is AES-256 in CBC mode (legacy compatibility).
	AES256CBC
	// AES128GCM is AES-128 in GCM mode.
	AES128GCM
)

// Encrypt creates a CMS EnvelopedData or AuthEnvelopedData structure.
// For AES-GCM, uses AuthEnvelopedData (RFC 5083) for OpenSSL compatibility.
// For AES-CBC, uses EnvelopedData (RFC 5652).
//
// The data is encrypted with a random CEK (Content Encryption Key),
// and the CEK is encrypted for each recipient using their public key.
//
// Supported recipient key types:
//   - RSA: Uses RSA-OAEP with SHA-256
//   - ECDSA/EC: Uses ECDH with ANSI X9.63 KDF and AES Key Wrap
//   - ML-KEM: Uses ML-KEM encapsulation with HKDF and AES Key Wrap
func Encrypt(ctx context.Context, data []byte, opts *EncryptOptions) ([]byte, error) {
	_ = ctx // TODO: use for cancellation
	if opts == nil {
		opts = &EncryptOptions{}
	}

	// Route to AuthEnvelopedData for GCM algorithms
	switch opts.ContentEncryption {
	case AES256GCM, AES128GCM:
		return EncryptAuthEnveloped(ctx, data, opts)
	default:
		return encryptEnveloped(data, opts)
	}
}

// EncryptAuthEnveloped creates a CMS AuthEnvelopedData structure (RFC 5083).
// Used for authenticated encryption (AES-GCM).
// The GCM authentication tag is stored in the MAC field.
func EncryptAuthEnveloped(ctx context.Context, data []byte, opts *EncryptOptions) ([]byte, error) {
	_ = ctx // TODO: use for cancellation
	if opts == nil {
		opts = &EncryptOptions{}
	}

	if len(opts.Recipients) == 0 {
		return nil, fmt.Errorf("at least one recipient is required")
	}

	contentType := opts.ContentType
	if contentType == nil {
		contentType = OIDData
	}

	// Generate random CEK (Content Encryption Key)
	cekSize := 32 // AES-256
	if opts.ContentEncryption == AES128GCM {
		cekSize = 16
	}
	cek := make([]byte, cekSize)
	if _, err := rand.Read(cek); err != nil {
		return nil, fmt.Errorf("failed to generate CEK: %w", err)
	}

	// Encrypt content with CEK using AES-GCM, returning ciphertext and tag separately
	ciphertext, tag, contentEncAlg, err := encryptAESGCMAuth(data, cek, opts.ContentEncryption)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt content: %w", err)
	}

	// Create RecipientInfo for each recipient
	var recipientInfos []asn1.RawValue
	for _, cert := range opts.Recipients {
		ri, err := createRecipientInfo(cek, cert)
		if err != nil {
			return nil, fmt.Errorf("failed to create recipient info for %s: %w", cert.Subject.CommonName, err)
		}
		recipientInfos = append(recipientInfos, ri)
	}

	// AuthEnvelopedData version is always 0
	// RFC 5083: "version is always 0"
	version := 0

	// Build AuthEnvelopedData
	authEnv := AuthEnvelopedData{
		Version:        version,
		RecipientInfos: recipientInfos,
		AuthEncryptedContentInfo: EncryptedContentInfo{
			ContentType:                contentType,
			ContentEncryptionAlgorithm: contentEncAlg,
			EncryptedContent:           ciphertext,
		},
		MAC: tag, // GCM tag serves as the MAC
	}

	// Marshal AuthEnvelopedData
	authEnvBytes, err := asn1.Marshal(authEnv)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal AuthEnvelopedData: %w", err)
	}

	// Wrap in ContentInfo
	ci := ContentInfo{
		ContentType: OIDAuthEnvelopedData,
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      authEnvBytes,
		},
	}

	return asn1.Marshal(ci)
}

// encryptAESGCMAuth encrypts data using AES-GCM and returns ciphertext and tag separately.
// This is used for AuthEnvelopedData where the tag is stored in the MAC field.
func encryptAESGCMAuth(data, cek []byte, alg ContentEncryptionAlgorithm) (ciphertext, tag []byte, algID pkix.AlgorithmIdentifier, err error) {
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, nil, pkix.AlgorithmIdentifier{}, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, pkix.AlgorithmIdentifier{}, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, pkix.AlgorithmIdentifier{}, err
	}

	// Seal returns ciphertext || tag
	sealed := gcm.Seal(nil, nonce, data, nil)

	// Split ciphertext and tag
	tagSize := gcm.Overhead()
	ciphertext = sealed[:len(sealed)-tagSize]
	tag = sealed[len(sealed)-tagSize:]

	// GCM parameters: nonce and tag length
	params := GCMParameters{
		Nonce:  nonce,
		ICVLen: tagSize,
	}
	paramsBytes, err := asn1.Marshal(params)
	if err != nil {
		return nil, nil, pkix.AlgorithmIdentifier{}, err
	}

	var oid asn1.ObjectIdentifier
	if len(cek) == 32 {
		oid = OIDAES256GCM
	} else {
		oid = OIDAES128GCM
	}

	algID = pkix.AlgorithmIdentifier{
		Algorithm:  oid,
		Parameters: asn1.RawValue{FullBytes: paramsBytes},
	}

	return ciphertext, tag, algID, nil
}

// encryptEnveloped creates a CMS EnvelopedData structure (RFC 5652).
// Used for non-authenticated encryption (AES-CBC).
func encryptEnveloped(data []byte, opts *EncryptOptions) ([]byte, error) {
	if opts == nil {
		opts = &EncryptOptions{}
	}

	if len(opts.Recipients) == 0 {
		return nil, fmt.Errorf("at least one recipient is required")
	}

	contentType := opts.ContentType
	if contentType == nil {
		contentType = OIDData
	}

	// Generate random CEK (Content Encryption Key)
	cekSize := 32 // AES-256
	if opts.ContentEncryption == AES128GCM {
		cekSize = 16
	}
	cek := make([]byte, cekSize)
	if _, err := rand.Read(cek); err != nil {
		return nil, fmt.Errorf("failed to generate CEK: %w", err)
	}

	// Encrypt content with CEK
	encryptedContent, contentEncAlg, err := encryptContent(data, cek, opts.ContentEncryption)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt content: %w", err)
	}

	// Create RecipientInfo for each recipient
	var recipientInfos []asn1.RawValue
	for _, cert := range opts.Recipients {
		ri, err := createRecipientInfo(cek, cert)
		if err != nil {
			return nil, fmt.Errorf("failed to create recipient info for %s: %w", cert.Subject.CommonName, err)
		}
		recipientInfos = append(recipientInfos, ri)
	}

	// Determine EnvelopedData version per RFC 5652 Section 6.1
	// version 0: KeyTransRecipientInfo only
	// version 2: originatorInfo present, or KeyAgreeRecipientInfo [1]
	// version 3: pwri [3] or ori [4] (OtherRecipientInfo, including KEMRecipientInfo)
	version := 0
	for _, ri := range recipientInfos {
		// Check the tag from FullBytes first byte (context-specific tags)
		// 0xa0 = [0], 0xa1 = [1], 0xa2 = [2], 0xa3 = [3], 0xa4 = [4]
		tag := ri.Tag
		if len(ri.FullBytes) > 0 {
			firstByte := ri.FullBytes[0]
			// Context-specific constructed: 0xa0-0xbf maps to tags 0-31
			if firstByte >= 0xa0 && firstByte <= 0xbf {
				tag = int(firstByte & 0x1f)
			}
		}
		if tag == 4 { // OtherRecipientInfo (KEMRecipientInfo)
			version = 3
			break
		}
		if tag == 1 { // KeyAgreeRecipientInfo
			version = 2
		}
	}

	// Build EnvelopedData
	env := EnvelopedData{
		Version:        version,
		RecipientInfos: recipientInfos,
		EncryptedContentInfo: EncryptedContentInfo{
			ContentType:                contentType,
			ContentEncryptionAlgorithm: contentEncAlg,
			EncryptedContent:           encryptedContent,
		},
	}

	// Marshal EnvelopedData
	envBytes, err := asn1.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal EnvelopedData: %w", err)
	}

	// Wrap in ContentInfo
	ci := ContentInfo{
		ContentType: OIDEnvelopedData,
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      envBytes,
		},
	}

	return asn1.Marshal(ci)
}

// encryptContent encrypts the content with the CEK using the specified algorithm.
func encryptContent(data, cek []byte, alg ContentEncryptionAlgorithm) ([]byte, pkix.AlgorithmIdentifier, error) {
	switch alg {
	case AES256GCM, AES128GCM:
		return encryptAESGCM(data, cek)
	case AES256CBC:
		return encryptAESCBC(data, cek)
	default:
		return encryptAESGCM(data, cek)
	}
}

// encryptAESGCM encrypts data using AES-GCM.
func encryptAESGCM(data, cek []byte) ([]byte, pkix.AlgorithmIdentifier, error) {
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, pkix.AlgorithmIdentifier{}, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, pkix.AlgorithmIdentifier{}, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, pkix.AlgorithmIdentifier{}, err
	}

	ciphertext := gcm.Seal(nil, nonce, data, nil)

	// GCM parameters: nonce and tag length
	params := GCMParameters{
		Nonce:  nonce,
		ICVLen: gcm.Overhead(),
	}
	paramsBytes, err := asn1.Marshal(params)
	if err != nil {
		return nil, pkix.AlgorithmIdentifier{}, err
	}

	var oid asn1.ObjectIdentifier
	if len(cek) == 32 {
		oid = OIDAES256GCM
	} else {
		oid = OIDAES128GCM
	}

	algID := pkix.AlgorithmIdentifier{
		Algorithm:  oid,
		Parameters: asn1.RawValue{FullBytes: paramsBytes},
	}

	return ciphertext, algID, nil
}

// encryptAESCBC encrypts data using AES-CBC with PKCS#7 padding.
func encryptAESCBC(data, cek []byte) ([]byte, pkix.AlgorithmIdentifier, error) {
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, pkix.AlgorithmIdentifier{}, err
	}

	// PKCS#7 padding
	padLen := aes.BlockSize - len(data)%aes.BlockSize
	padded := make([]byte, len(data)+padLen)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}

	// Generate random IV
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, pkix.AlgorithmIdentifier{}, err
	}

	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)

	// IV as parameters
	ivBytes, err := asn1.Marshal(iv)
	if err != nil {
		return nil, pkix.AlgorithmIdentifier{}, err
	}

	algID := pkix.AlgorithmIdentifier{
		Algorithm:  OIDAES256CBC,
		Parameters: asn1.RawValue{FullBytes: ivBytes},
	}

	return ciphertext, algID, nil
}

// createRecipientInfo creates a RecipientInfo for a recipient certificate.
func createRecipientInfo(cek []byte, cert *x509.Certificate) (asn1.RawValue, error) {
	// Check for ML-KEM first (based on RawSubjectPublicKeyInfo OID)
	// This must be done before the type switch because the certificate
	// might have been created with a classical key and had its SPKI replaced.
	if isMLKEMCert(cert) {
		return createKEMRecipientInfo(cek, cert)
	}

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return createRSARecipientInfo(cek, cert, pub)
	case *ecdsa.PublicKey:
		return createECDHRecipientInfo(cek, cert, pub)
	default:
		return asn1.RawValue{}, fmt.Errorf("unsupported public key type: %T", pub)
	}
}

// isMLKEMCert checks if the certificate contains an ML-KEM public key.
func isMLKEMCert(cert *x509.Certificate) bool {
	// Check the public key algorithm OID
	// This is a simplified check - in production, parse the SPKI properly
	raw := cert.RawSubjectPublicKeyInfo
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(raw, &spki); err != nil {
		return false
	}

	return spki.Algorithm.Algorithm.Equal(OIDMLKEM512) ||
		spki.Algorithm.Algorithm.Equal(OIDMLKEM768) ||
		spki.Algorithm.Algorithm.Equal(OIDMLKEM1024)
}

// getMLKEMAlgorithm returns the ML-KEM algorithm from a certificate.
func getMLKEMAlgorithm(cert *x509.Certificate) (pkicrypto.AlgorithmID, error) {
	raw := cert.RawSubjectPublicKeyInfo
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(raw, &spki); err != nil {
		return "", fmt.Errorf("failed to parse SPKI: %w", err)
	}

	switch {
	case spki.Algorithm.Algorithm.Equal(OIDMLKEM512):
		return pkicrypto.AlgMLKEM512, nil
	case spki.Algorithm.Algorithm.Equal(OIDMLKEM768):
		return pkicrypto.AlgMLKEM768, nil
	case spki.Algorithm.Algorithm.Equal(OIDMLKEM1024):
		return pkicrypto.AlgMLKEM1024, nil
	default:
		return "", fmt.Errorf("unknown ML-KEM algorithm OID: %v", spki.Algorithm.Algorithm)
	}
}

// getMLKEMPublicKey extracts the ML-KEM public key from a certificate.
func getMLKEMPublicKey(cert *x509.Certificate) (crypto.PublicKey, pkicrypto.AlgorithmID, error) {
	raw := cert.RawSubjectPublicKeyInfo
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(raw, &spki); err != nil {
		return nil, "", fmt.Errorf("failed to parse SPKI: %w", err)
	}

	alg, err := getMLKEMAlgorithm(cert)
	if err != nil {
		return nil, "", err
	}

	pub, err := pkicrypto.ParseMLKEMPublicKey(alg, spki.PublicKey.Bytes)
	if err != nil {
		return nil, "", err
	}

	return pub, alg, nil
}

// createRSARecipientInfo creates a KeyTransRecipientInfo for RSA-OAEP.
func createRSARecipientInfo(cek []byte, cert *x509.Certificate, pub *rsa.PublicKey) (asn1.RawValue, error) {
	// Encrypt CEK with RSA-OAEP SHA-256
	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, cek, nil)
	if err != nil {
		return asn1.RawValue{}, fmt.Errorf("RSA-OAEP encryption failed: %w", err)
	}

	// RSA-OAEP parameters
	oaepParams := RSAOAEPParams{
		HashAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: OIDSHA256,
		},
		MaskGenAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}, // id-mgf1
		},
	}
	oaepParamsBytes, err := asn1.Marshal(oaepParams)
	if err != nil {
		return asn1.RawValue{}, err
	}

	ktri := KeyTransRecipientInfo{
		Version: 0,
		RID: RecipientIdentifier{
			IssuerAndSerial: &IssuerAndSerialNumber{
				Issuer:       asn1.RawValue{FullBytes: cert.RawIssuer},
				SerialNumber: cert.SerialNumber,
			},
		},
		KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm:  OIDRSAOAEP,
			Parameters: asn1.RawValue{FullBytes: oaepParamsBytes},
		},
		EncryptedKey: encryptedKey,
	}

	// Marshal using manual function to handle RecipientIdentifier CHOICE
	ktriBytes, err := MarshalKeyTransRecipientInfo(&ktri)
	if err != nil {
		return asn1.RawValue{}, err
	}

	return asn1.RawValue{FullBytes: ktriBytes}, nil
}

// createECDHRecipientInfo creates a KeyAgreeRecipientInfo for ECDH.
func createECDHRecipientInfo(cek []byte, cert *x509.Certificate, pub *ecdsa.PublicKey) (asn1.RawValue, error) {
	// Generate ephemeral key pair
	ephPriv, err := ecdsa.GenerateKey(pub.Curve, rand.Reader)
	if err != nil {
		return asn1.RawValue{}, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	// Compute shared secret
	sharedSecret, err := ecdhSharedSecret(ephPriv, pub)
	if err != nil {
		return asn1.RawValue{}, fmt.Errorf("ECDH failed: %w", err)
	}

	// Build ECC-CMS-SharedInfo for KDF (RFC 5753 Section 7.2)
	// ECC-CMS-SharedInfo ::= SEQUENCE {
	//   keyInfo AlgorithmIdentifier,
	//   entityUInfo [0] EXPLICIT OCTET STRING OPTIONAL,
	//   suppPubInfo [2] EXPLICIT OCTET STRING
	// }
	sharedInfo, err := buildECCCMSSharedInfo(OIDAESWrap256, 256)
	if err != nil {
		return asn1.RawValue{}, fmt.Errorf("failed to build SharedInfo: %w", err)
	}

	// Derive KEK using ANSI X9.63 KDF with SharedInfo
	kek, err := ansix963KDFSHA256(sharedSecret, 32, sharedInfo)
	if err != nil {
		return asn1.RawValue{}, fmt.Errorf("KDF failed: %w", err)
	}

	// Wrap CEK with KEK
	wrappedKey, err := aesKeyWrap(kek, cek)
	if err != nil {
		return asn1.RawValue{}, fmt.Errorf("key wrap failed: %w", err)
	}

	// Build OriginatorPublicKey
	var curveOID asn1.ObjectIdentifier
	switch pub.Curve {
	case elliptic.P256():
		curveOID = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	case elliptic.P384():
		curveOID = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	case elliptic.P521():
		curveOID = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
	default:
		return asn1.RawValue{}, fmt.Errorf("unsupported curve: %s", pub.Curve.Params().Name)
	}

	curveOIDBytes, _ := asn1.Marshal(curveOID)

	//nolint:staticcheck // elliptic.Marshal is deprecated but needed for X.509 compatibility
	ephPubBytes := elliptic.Marshal(ephPriv.Curve, ephPriv.X, ephPriv.Y)

	originatorKey := OriginatorPublicKey{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm:  asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}, // id-ecPublicKey
			Parameters: asn1.RawValue{FullBytes: curveOIDBytes},
		},
		PublicKey: asn1.BitString{Bytes: ephPubBytes, BitLength: len(ephPubBytes) * 8},
	}

	// Marshal OriginatorPublicKey and apply [1] IMPLICIT tag correctly.
	// For IMPLICIT tagging, we replace the SEQUENCE tag with the context-specific tag.
	// We need to extract just the content from the SEQUENCE and wrap with [1].
	originatorKeyBytes, err := asn1.Marshal(originatorKey)
	if err != nil {
		return asn1.RawValue{}, err
	}

	// Skip the SEQUENCE tag and length to get just the content.
	// originatorKeyBytes is: 0x30 <length> <content>
	// We need to extract <content> for IMPLICIT tagging.
	originatorKeyContent, err := extractASN1Content(originatorKeyBytes)
	if err != nil {
		return asn1.RawValue{}, fmt.Errorf("failed to extract originatorKey content: %w", err)
	}

	// Build [1] IMPLICIT OriginatorPublicKey
	originatorImplicit, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        1,
		IsCompound: true,
		Bytes:      originatorKeyContent,
	})
	if err != nil {
		return asn1.RawValue{}, err
	}

	// Build KeyEncryptionAlgorithm with ESDH scheme (RFC 5753)
	// dhSinglePass-stdDH-sha256kdf-scheme with KeyWrapAlgorithm as parameter
	// OpenSSL requires NULL parameters for AES key wrap algorithms for interoperability
	nullParams, _ := asn1.Marshal(asn1.RawValue{Tag: asn1.TagNull})
	wrapAlgBytes, err := asn1.Marshal(pkix.AlgorithmIdentifier{
		Algorithm:  OIDAESWrap256,
		Parameters: asn1.RawValue{FullBytes: nullParams},
	})
	if err != nil {
		return asn1.RawValue{}, fmt.Errorf("failed to marshal wrap algorithm: %w", err)
	}

	kari := KeyAgreeRecipientInfo{
		Version: 3,
		Originator: asn1.RawValue{
			FullBytes: originatorImplicit, // Use FullBytes so MarshalKeyAgreeRecipientInfo wraps with [0] EXPLICIT
		},
		KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm:  OIDECDHStdSHA256KDF, // dhSinglePass-stdDH-sha256kdf-scheme
			Parameters: asn1.RawValue{FullBytes: wrapAlgBytes},
		},
		RecipientEncryptedKeys: []RecipientEncryptedKey{
			{
				RID: KeyAgreeRecipientIdentifier{
					IssuerAndSerial: &IssuerAndSerialNumber{
						Issuer:       asn1.RawValue{FullBytes: cert.RawIssuer},
						SerialNumber: cert.SerialNumber,
					},
				},
				EncryptedKey: wrappedKey,
			},
		},
	}

	// Use manual marshaling to handle KeyAgreeRecipientIdentifier CHOICE
	kariBytes, err := MarshalKeyAgreeRecipientInfo(&kari)
	if err != nil {
		return asn1.RawValue{}, err
	}

	return asn1.RawValue{FullBytes: kariBytes}, nil
}

// createKEMRecipientInfo creates a KEMRecipientInfo for ML-KEM.
func createKEMRecipientInfo(cek []byte, cert *x509.Certificate) (asn1.RawValue, error) {
	// Get ML-KEM public key and algorithm from certificate
	pub, alg, err := getMLKEMPublicKey(cert)
	if err != nil {
		return asn1.RawValue{}, err
	}

	// Get the appropriate scheme and perform KEM encapsulation
	var scheme kem.Scheme
	var kemOID asn1.ObjectIdentifier
	switch alg {
	case pkicrypto.AlgMLKEM512:
		scheme = mlkem512.Scheme()
		kemOID = OIDMLKEM512
	case pkicrypto.AlgMLKEM768:
		scheme = mlkem768.Scheme()
		kemOID = OIDMLKEM768
	case pkicrypto.AlgMLKEM1024:
		scheme = mlkem1024.Scheme()
		kemOID = OIDMLKEM1024
	default:
		return asn1.RawValue{}, fmt.Errorf("unsupported KEM algorithm: %s", alg)
	}

	kemPub, ok := pub.(kem.PublicKey)
	if !ok {
		return asn1.RawValue{}, fmt.Errorf("invalid public key type for KEM: %T", pub)
	}

	kemCT, sharedSecret, err := scheme.Encapsulate(kemPub)
	if err != nil {
		return asn1.RawValue{}, fmt.Errorf("KEM encapsulation failed: %w", err)
	}

	// Build wrap algorithm identifier for KDF info (RFC 9629)
	wrapAlg := pkix.AlgorithmIdentifier{Algorithm: OIDAESWrap256}

	// Build CMSORIforKEMOtherInfo for HKDF info parameter (RFC 9629 Section 6)
	kdfInfo, err := buildKEMKDFInfo(wrapAlg, 32, nil)
	if err != nil {
		return asn1.RawValue{}, fmt.Errorf("failed to build KDF info: %w", err)
	}

	// Derive KEK from shared secret using HKDF with RFC 9629 info
	kek, err := deriveKEK(sharedSecret, 32, kdfInfo)
	if err != nil {
		return asn1.RawValue{}, fmt.Errorf("KDF failed: %w", err)
	}

	// Wrap CEK with KEK
	wrappedKey, err := aesKeyWrap(kek, cek)
	if err != nil {
		return asn1.RawValue{}, fmt.Errorf("key wrap failed: %w", err)
	}

	kemri := KEMRecipientInfo{
		Version: 0,
		RID: RecipientIdentifier{
			IssuerAndSerial: &IssuerAndSerialNumber{
				Issuer:       asn1.RawValue{FullBytes: cert.RawIssuer},
				SerialNumber: cert.SerialNumber,
			},
		},
		KEM:          pkix.AlgorithmIdentifier{Algorithm: kemOID},
		KEMCT:        kemCT,
		KDF:          pkix.AlgorithmIdentifier{Algorithm: OIDHKDFSHA256},
		KEKLength:    32,
		Wrap:         wrapAlg,
		EncryptedKey: wrappedKey,
	}

	// Marshal with [2] IMPLICIT tag
	kemriBytes, err := MarshalKEMRecipientInfo(&kemri)
	if err != nil {
		return asn1.RawValue{}, err
	}

	return asn1.RawValue{FullBytes: kemriBytes}, nil
}

// =============================================================================
// Helper functions for key wrap, KDF, and ECDH
// =============================================================================

// aesKeyWrap wraps a key using AES Key Wrap (RFC 3394).
func aesKeyWrap(kek, key []byte) ([]byte, error) {
	if len(key)%8 != 0 {
		return nil, fmt.Errorf("key length must be a multiple of 8 bytes")
	}
	if len(key) < 16 {
		return nil, fmt.Errorf("key must be at least 16 bytes")
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	n := len(key) / 8
	r := make([][]byte, n)
	for i := 0; i < n; i++ {
		r[i] = make([]byte, 8)
		copy(r[i], key[i*8:(i+1)*8])
	}

	// Default IV per RFC 3394
	a := []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}

	for j := 0; j < 6; j++ {
		for i := 1; i <= n; i++ {
			b := make([]byte, 16)
			copy(b[:8], a)
			copy(b[8:], r[i-1])

			block.Encrypt(b, b)

			t := uint64(n*j + i)
			for k := 0; k < 8; k++ {
				b[k] ^= byte(t >> (56 - 8*k))
			}

			copy(a, b[:8])
			copy(r[i-1], b[8:])
		}
	}

	// Output: A || R[1] || R[2] || ... || R[n]
	out := make([]byte, 8+len(key))
	copy(out[:8], a)
	for i := 0; i < n; i++ {
		copy(out[8+i*8:], r[i])
	}

	return out, nil
}

// ecdhSharedSecret computes the ECDH shared secret between a private key and a public key.
func ecdhSharedSecret(priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey) ([]byte, error) {
	// Convert ecdsa keys to ecdh keys
	privECDH, err := priv.ECDH()
	if err != nil {
		return nil, fmt.Errorf("failed to convert private key to ECDH: %w", err)
	}

	pubECDH, err := ecdsaToECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("failed to convert public key to ECDH: %w", err)
	}

	return privECDH.ECDH(pubECDH)
}

// ecdsaToECDH converts an ecdsa.PublicKey to an ecdh.PublicKey.
func ecdsaToECDH(pub *ecdsa.PublicKey) (*ecdh.PublicKey, error) {
	var curve ecdh.Curve
	switch pub.Curve.Params().Name {
	case "P-256":
		curve = ecdh.P256()
	case "P-384":
		curve = ecdh.P384()
	case "P-521":
		curve = ecdh.P521()
	default:
		return nil, fmt.Errorf("unsupported curve: %s", pub.Curve.Params().Name)
	}

	// Marshal the public key point to uncompressed format
	rawPub := ecMarshalUncompressed(pub)

	return curve.NewPublicKey(rawPub)
}

// ecMarshalUncompressed marshals an EC public key to uncompressed format.
func ecMarshalUncompressed(pub *ecdsa.PublicKey) []byte {
	byteLen := (pub.Curve.Params().BitSize + 7) / 8
	ret := make([]byte, 1+2*byteLen)
	ret[0] = 4 // uncompressed point
	pub.X.FillBytes(ret[1 : 1+byteLen])
	pub.Y.FillBytes(ret[1+byteLen : 1+2*byteLen])
	return ret
}

// CMSORIforKEMOtherInfo is the structure for HKDF info in KEMRecipientInfo (RFC 9629 Section 6).
// CMSORIforKEMOtherInfo ::= SEQUENCE {
//
//	wrap       KeyEncryptionAlgorithmIdentifier,
//	kekLength  INTEGER,
//	ukm        [0] EXPLICIT OtherKeyAttribute OPTIONAL
//
// }
type CMSORIforKEMOtherInfo struct {
	Wrap      pkix.AlgorithmIdentifier
	KEKLength int
	// UKM is optional and omitted if nil
}

// buildKEMKDFInfo builds the DER-encoded CMSORIforKEMOtherInfo for HKDF info (RFC 9629).
func buildKEMKDFInfo(wrap pkix.AlgorithmIdentifier, kekLength int, ukm []byte) ([]byte, error) {
	info := CMSORIforKEMOtherInfo{
		Wrap:      wrap,
		KEKLength: kekLength,
	}
	// Note: UKM (user keying material) is not included in this implementation
	return asn1.Marshal(info)
}

// deriveKEK derives a Key Encryption Key from shared secret using HKDF.
func deriveKEK(sharedSecret []byte, keySize int, info []byte) ([]byte, error) {
	kdf := hkdf.New(sha256.New, sharedSecret, nil, info)
	kek := make([]byte, keySize)
	if _, err := io.ReadFull(kdf, kek); err != nil {
		return nil, fmt.Errorf("HKDF failed: %w", err)
	}
	return kek, nil
}

// ansix963KDF derives a key using ANSI X9.63 KDF (used with ECDH in CMS).
func ansix963KDF(sharedSecret []byte, keySize int, sharedInfo []byte, h func() hash.Hash) ([]byte, error) {
	hashLen := h().Size()
	reps := (keySize + hashLen - 1) / hashLen

	var result []byte
	counter := uint32(1)

	for i := 0; i < reps; i++ {
		hasher := h()
		hasher.Write(sharedSecret)

		// Counter as big-endian 32-bit
		var counterBytes [4]byte
		binary.BigEndian.PutUint32(counterBytes[:], counter)
		hasher.Write(counterBytes[:])

		if len(sharedInfo) > 0 {
			hasher.Write(sharedInfo)
		}

		result = append(result, hasher.Sum(nil)...)
		counter++
	}

	return result[:keySize], nil
}

// ansix963KDFSHA256 is a convenience wrapper for ANSI X9.63 KDF with SHA-256.
func ansix963KDFSHA256(sharedSecret []byte, keySize int, sharedInfo []byte) ([]byte, error) {
	return ansix963KDF(sharedSecret, keySize, sharedInfo, sha256.New)
}

// buildECCCMSSharedInfo builds the ECC-CMS-SharedInfo structure for KDF (RFC 5753).
// ECC-CMS-SharedInfo ::= SEQUENCE {
//
//	keyInfo AlgorithmIdentifier,
//	entityUInfo [0] EXPLICIT OCTET STRING OPTIONAL,
//	suppPubInfo [2] EXPLICIT OCTET STRING
//
// }
// suppPubInfo contains the key length in bits as a 4-byte big-endian integer.
func buildECCCMSSharedInfo(wrapAlgOID asn1.ObjectIdentifier, keyBits int) ([]byte, error) {
	// keyInfo: AlgorithmIdentifier for wrap algorithm
	// OpenSSL requires NULL parameters for AES key wrap algorithms.
	// This MUST match what's in KeyEncryptionAlgorithm.parameters in the CMS message.
	nullParams, _ := asn1.Marshal(asn1.RawValue{Tag: asn1.TagNull})
	keyInfo := pkix.AlgorithmIdentifier{
		Algorithm:  wrapAlgOID,
		Parameters: asn1.RawValue{FullBytes: nullParams},
	}
	keyInfoBytes, err := asn1.Marshal(keyInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal keyInfo: %w", err)
	}

	// suppPubInfo: key length in bits as 4-byte big-endian in OCTET STRING
	// wrapped in [2] EXPLICIT
	keyLenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(keyLenBytes, uint32(keyBits))
	suppPubInfoOctetString, err := asn1.Marshal(keyLenBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal suppPubInfo octet string: %w", err)
	}

	// Wrap suppPubInfo with [2] EXPLICIT tag
	suppPubInfoTagged, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        2,
		IsCompound: true,
		Bytes:      suppPubInfoOctetString,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal suppPubInfo tagged: %w", err)
	}

	// Build complete ECC-CMS-SharedInfo SEQUENCE
	// RFC 5753: "the ECC-CMS-SharedInfo value ... is DER encoded and passed
	// as SharedInfo to the X9.63 KDF"
	seqContent := append(keyInfoBytes, suppPubInfoTagged...)
	sharedInfo, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      seqContent,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal SharedInfo sequence: %w", err)
	}

	return sharedInfo, nil
}

// extractASN1Content extracts the content from a DER-encoded ASN.1 value,
// skipping the tag and length bytes. This is used for IMPLICIT tagging
// where we need to replace the original tag with a context-specific tag.
func extractASN1Content(der []byte) ([]byte, error) {
	if len(der) < 2 {
		return nil, fmt.Errorf("DER too short")
	}

	// Skip tag byte
	pos := 1

	// Parse length
	length := int(der[pos])
	pos++

	if length < 128 {
		// Short form: length is directly encoded
		return der[pos:], nil
	}

	// Long form: first byte indicates number of length bytes
	numLenBytes := length & 0x7f
	if len(der) < pos+numLenBytes {
		return nil, fmt.Errorf("DER truncated in length field")
	}

	// Skip length bytes
	pos += numLenBytes

	return der[pos:], nil
}
