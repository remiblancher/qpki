package cms

import (
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

	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
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

// Encrypt creates a CMS EnvelopedData structure.
// The data is encrypted with a random CEK (Content Encryption Key),
// and the CEK is encrypted for each recipient using their public key.
//
// Supported recipient key types:
//   - RSA: Uses RSA-OAEP with SHA-256
//   - ECDSA/EC: Uses ECDH with ANSI X9.63 KDF and AES Key Wrap
//   - ML-KEM: Uses ML-KEM encapsulation with HKDF and AES Key Wrap
func Encrypt(data []byte, opts *EncryptOptions) ([]byte, error) {
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

	// Build EnvelopedData
	env := EnvelopedData{
		Version:        0, // version 0 for KeyTransRecipientInfo
		RecipientInfos: recipientInfos,
		EncryptedContentInfo: EncryptedContentInfo{
			ContentType:                contentType,
			ContentEncryptionAlgorithm: contentEncAlg,
			EncryptedContent:           encryptedContent,
		},
	}

	// Check if we have KeyAgreeRecipientInfo or KEMRecipientInfo (version 2)
	for _, ri := range recipientInfos {
		if ri.Tag == 1 || ri.Tag == 2 {
			env.Version = 2
			break
		}
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

	// Derive KEK using ANSI X9.63 KDF
	kek, err := ansix963KDFSHA256(sharedSecret, 32, nil)
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

	originatorKeyBytes, err := asn1.Marshal(originatorKey)
	if err != nil {
		return asn1.RawValue{}, err
	}

	kari := KeyAgreeRecipientInfo{
		Version: 3,
		Originator: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        1,
			IsCompound: true,
			Bytes:      originatorKeyBytes,
		},
		KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: OIDAESWrap256,
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

	// Derive KEK from shared secret using HKDF
	kek, err := deriveKEK(sharedSecret, 32, []byte("CMS-KEMRecipientInfo"))
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
		Wrap:         pkix.AlgorithmIdentifier{Algorithm: OIDAESWrap256},
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
