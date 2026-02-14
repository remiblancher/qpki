package cms

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
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
)

// DecryptOptions configures CMS decryption.
type DecryptOptions struct {
	// PrivateKey is the recipient's private key for decryption.
	PrivateKey crypto.PrivateKey

	// Certificate is the recipient's certificate (optional, used for matching RecipientInfo).
	Certificate *x509.Certificate
}

// DecryptResult contains the decryption result.
type DecryptResult struct {
	// Content is the decrypted data.
	Content []byte

	// ContentType is the OID of the decrypted content.
	ContentType asn1.ObjectIdentifier
}

// Decrypt decrypts a CMS EnvelopedData or AuthEnvelopedData structure.
// It finds the matching RecipientInfo for the provided private key,
// decrypts the CEK, and then decrypts the content.
func Decrypt(ctx context.Context, data []byte, opts *DecryptOptions) (*DecryptResult, error) {
	_ = ctx // TODO: use for cancellation
	if opts == nil || opts.PrivateKey == nil {
		return nil, fmt.Errorf("private key is required")
	}

	// Parse ContentInfo
	var ci ContentInfo
	rest, err := asn1.Unmarshal(data, &ci)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ContentInfo: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data after ContentInfo")
	}

	// Route based on content type
	if ci.ContentType.Equal(OIDAuthEnvelopedData) {
		return DecryptAuthEnveloped(ctx, ci.Content.Bytes, opts)
	}

	if !ci.ContentType.Equal(OIDEnvelopedData) {
		return nil, fmt.Errorf("not an EnvelopedData or AuthEnvelopedData: %v", ci.ContentType)
	}

	// Parse EnvelopedData
	var env EnvelopedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &env); err != nil {
		return nil, fmt.Errorf("failed to parse EnvelopedData: %w", err)
	}

	// Find matching RecipientInfo and decrypt CEK
	cek, err := decryptCEK(&env, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt CEK: %w", err)
	}

	// Decrypt content
	content, err := decryptContent(&env.EncryptedContentInfo, cek)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt content: %w", err)
	}

	return &DecryptResult{
		Content:     content,
		ContentType: env.EncryptedContentInfo.ContentType,
	}, nil
}

// DecryptAuthEnveloped decrypts a CMS AuthEnvelopedData structure (RFC 5083).
// For AES-GCM, the MAC field contains the authentication tag.
func DecryptAuthEnveloped(ctx context.Context, data []byte, opts *DecryptOptions) (*DecryptResult, error) {
	_ = ctx // TODO: use for cancellation
	if opts == nil || opts.PrivateKey == nil {
		return nil, fmt.Errorf("private key is required")
	}

	// Parse AuthEnvelopedData
	var authEnv AuthEnvelopedData
	if _, err := asn1.Unmarshal(data, &authEnv); err != nil {
		return nil, fmt.Errorf("failed to parse AuthEnvelopedData: %w", err)
	}

	// Find matching RecipientInfo and decrypt CEK
	cek, err := decryptCEKAuth(&authEnv, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt CEK: %w", err)
	}

	// Decrypt content with MAC verification
	content, err := decryptContentAuth(&authEnv, cek)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt content: %w", err)
	}

	return &DecryptResult{
		Content:     content,
		ContentType: authEnv.AuthEncryptedContentInfo.ContentType,
	}, nil
}

// decryptCEKAuth finds the matching RecipientInfo and decrypts the CEK for AuthEnvelopedData.
func decryptCEKAuth(authEnv *AuthEnvelopedData, opts *DecryptOptions) ([]byte, error) {
	for _, riRaw := range authEnv.RecipientInfos {
		cek, err := tryDecryptRecipientInfo(riRaw, opts)
		if err == nil {
			return cek, nil
		}
		// Continue trying other RecipientInfos
	}

	return nil, fmt.Errorf("no matching RecipientInfo found for provided key")
}

// decryptContentAuth decrypts the content from AuthEnvelopedData with MAC verification.
// For AES-GCM, the MAC is the GCM authentication tag.
func decryptContentAuth(authEnv *AuthEnvelopedData, cek []byte) ([]byte, error) {
	alg := authEnv.AuthEncryptedContentInfo.ContentEncryptionAlgorithm.Algorithm

	if !alg.Equal(OIDAES256GCM) && !alg.Equal(OIDAES128GCM) && !alg.Equal(OIDAES192GCM) {
		return nil, fmt.Errorf("AuthEnvelopedData requires AES-GCM, got: %v", alg)
	}

	// Parse GCM parameters
	var params GCMParameters
	if _, err := asn1.Unmarshal(authEnv.AuthEncryptedContentInfo.ContentEncryptionAlgorithm.Parameters.FullBytes, &params); err != nil {
		return nil, fmt.Errorf("failed to parse GCM parameters: %w", err)
	}

	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// For AuthEnvelopedData, the ciphertext and tag are stored separately:
	// - ciphertext in AuthEncryptedContentInfo.EncryptedContent
	// - tag in MAC field
	// GCM.Open expects ciphertext||tag, so we concatenate them
	ciphertextWithTag := append(authEnv.AuthEncryptedContentInfo.EncryptedContent, authEnv.MAC...)

	return gcm.Open(nil, params.Nonce, ciphertextWithTag, nil)
}

// decryptCEK finds the matching RecipientInfo and decrypts the CEK.
func decryptCEK(env *EnvelopedData, opts *DecryptOptions) ([]byte, error) {
	var lastErr error
	for _, riRaw := range env.RecipientInfos {
		cek, err := tryDecryptRecipientInfo(riRaw, opts)
		if err == nil {
			return cek, nil
		}
		lastErr = err
		// Continue trying other RecipientInfos
	}

	if lastErr != nil {
		return nil, fmt.Errorf("no matching RecipientInfo found for provided key: %w", lastErr)
	}
	return nil, fmt.Errorf("no matching RecipientInfo found for provided key")
}

// tryDecryptRecipientInfo attempts to decrypt the CEK from a RecipientInfo.
func tryDecryptRecipientInfo(riRaw asn1.RawValue, opts *DecryptOptions) ([]byte, error) {
	// Determine RecipientInfo type by tag
	switch {
	case riRaw.Tag == asn1.TagSequence && riRaw.Class == asn1.ClassUniversal:
		// KeyTransRecipientInfo (SEQUENCE, no tag)
		// Use manual parsing to handle RecipientIdentifier CHOICE
		ktri, err := ParseKeyTransRecipientInfo(riRaw.FullBytes)
		if err != nil {
			return nil, err
		}
		return decryptKeyTrans(ktri, opts)

	case riRaw.Tag == 1 && riRaw.Class == asn1.ClassContextSpecific:
		// [1] KeyAgreeRecipientInfo
		// Use manual parsing to handle KeyAgreeRecipientIdentifier CHOICE
		kari, err := ParseKeyAgreeRecipientInfo(riRaw.Bytes)
		if err != nil {
			return nil, err
		}
		return decryptKeyAgree(kari, opts)

	case riRaw.Tag == 4 && riRaw.Class == asn1.ClassContextSpecific:
		// [4] OtherRecipientInfo - contains KEMRecipientInfo per RFC 9629
		// OtherRecipientInfo ::= SEQUENCE { oriType OID, oriValue ANY }
		kemri, err := parseOtherRecipientInfoKEM(riRaw.Bytes)
		if err != nil {
			return nil, err
		}
		return decryptKEMRecipient(kemri, opts)

	default:
		return nil, fmt.Errorf("unsupported RecipientInfo type: tag=%d, class=%d", riRaw.Tag, riRaw.Class)
	}
}

// parseOtherRecipientInfoKEM parses OtherRecipientInfo containing KEMRecipientInfo.
// Per RFC 9629: OtherRecipientInfo ::= SEQUENCE { oriType OID, oriValue ANY }
func parseOtherRecipientInfoKEM(data []byte) (*KEMRecipientInfo, error) {
	remaining := data

	// Parse oriType OID
	var oriType asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(remaining, &oriType)
	if err != nil {
		return nil, fmt.Errorf("failed to parse oriType: %w", err)
	}

	// Verify it's id-ori-kem
	if !oriType.Equal(OIDOriKEM) {
		return nil, fmt.Errorf("unsupported OtherRecipientInfo type: %v (expected id-ori-kem)", oriType)
	}

	// Parse oriValue as KEMRecipientInfo SEQUENCE
	var oriValue asn1.RawValue
	_, err = asn1.Unmarshal(rest, &oriValue)
	if err != nil {
		return nil, fmt.Errorf("failed to parse oriValue: %w", err)
	}

	// oriValue should be a SEQUENCE containing KEMRecipientInfo
	if oriValue.Tag != asn1.TagSequence {
		return nil, fmt.Errorf("oriValue is not a SEQUENCE: tag=%d", oriValue.Tag)
	}

	// Parse the KEMRecipientInfo from the SEQUENCE bytes
	return ParseKEMRecipientInfo(oriValue.Bytes)
}

// decryptKeyTrans decrypts the CEK from a KeyTransRecipientInfo (RSA).
func decryptKeyTrans(ktri *KeyTransRecipientInfo, opts *DecryptOptions) ([]byte, error) {
	// Check if RecipientIdentifier matches
	if opts.Certificate != nil && ktri.RID.IssuerAndSerial != nil {
		if !matchesIssuerAndSerial(opts.Certificate, ktri.RID.IssuerAndSerial) {
			return nil, fmt.Errorf("certificate does not match RecipientIdentifier")
		}
	}

	// HSM support: try crypto.Decrypter interface first (e.g., PKCS11Signer)
	if decrypter, ok := opts.PrivateKey.(crypto.Decrypter); ok {
		var decOpts crypto.DecrypterOpts
		if ktri.KeyEncryptionAlgorithm.Algorithm.Equal(OIDRSAOAEP) {
			decOpts = &rsa.OAEPOptions{Hash: crypto.SHA256}
		} else if ktri.KeyEncryptionAlgorithm.Algorithm.Equal(OIDRSAES) {
			decOpts = &rsa.PKCS1v15DecryptOptions{}
		} else {
			return nil, fmt.Errorf("unsupported key encryption algorithm: %v", ktri.KeyEncryptionAlgorithm.Algorithm)
		}
		return decrypter.Decrypt(nil, ktri.EncryptedKey, decOpts)
	}

	// Software fallback: use raw RSA private key
	rsaPriv, ok := opts.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("RSA private key required (or key implementing crypto.Decrypter)")
	}

	// Determine decryption algorithm
	if ktri.KeyEncryptionAlgorithm.Algorithm.Equal(OIDRSAOAEP) {
		return rsa.DecryptOAEP(sha256.New(), nil, rsaPriv, ktri.EncryptedKey, nil)
	} else if ktri.KeyEncryptionAlgorithm.Algorithm.Equal(OIDRSAES) {
		return rsa.DecryptPKCS1v15(nil, rsaPriv, ktri.EncryptedKey)
	}

	return nil, fmt.Errorf("unsupported key encryption algorithm: %v", ktri.KeyEncryptionAlgorithm.Algorithm)
}

// decryptKeyAgree decrypts the CEK from a KeyAgreeRecipientInfo (ECDH).
// Supports both HSM keys (via ECDHDeriver interface) and software keys.
func decryptKeyAgree(kari *KeyAgreeRecipientInfo, opts *DecryptOptions) ([]byte, error) {
	var curve elliptic.Curve
	var sharedSecret []byte

	// Get KDF hash function
	kdfHash, err := getKDFHashFunc(kari.KeyEncryptionAlgorithm.Algorithm)
	if err != nil {
		return nil, err
	}

	// Try HSM path first: check for ECDHDeriver interface
	if deriver, ok := opts.PrivateKey.(ECDHDeriver); ok {
		// For HSM, get curve from the public key via crypto.Signer
		if signer, ok := opts.PrivateKey.(crypto.Signer); ok {
			if ecPub, ok := signer.Public().(*ecdsa.PublicKey); ok {
				curve = ecPub.Curve
			}
		}
		if curve == nil {
			return nil, fmt.Errorf("cannot determine curve for HSM ECDH derivation")
		}

		ephPub, err := parseOriginatorPublicKey(kari.Originator, curve)
		if err != nil {
			return nil, err
		}

		sharedSecret, err = deriver.DeriveECDH(ephPub)
		if err != nil {
			return nil, fmt.Errorf("HSM ECDH derivation failed: %w", err)
		}
	} else {
		// Software fallback: use raw ECDSA private key
		ecdsaPriv, ok := opts.PrivateKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("ECDSA private key or ECDHDeriver required for KeyAgreeRecipientInfo")
		}
		curve = ecdsaPriv.Curve

		ephPub, err := parseOriginatorPublicKey(kari.Originator, curve)
		if err != nil {
			return nil, err
		}

		sharedSecret, err = ecdhSharedSecretDecrypt(ecdsaPriv, ephPub)
		if err != nil {
			return nil, fmt.Errorf("ECDH failed: %w", err)
		}
	}

	// Build SharedInfo and derive KEK using ANSI X9.63 KDF
	wrapAlgBytes := getWrapAlgBytes(kari.KeyEncryptionAlgorithm)
	sharedInfo, err := buildECCCMSSharedInfoDecryptRaw(wrapAlgBytes, 256)
	if err != nil {
		return nil, fmt.Errorf("failed to build SharedInfo: %w", err)
	}

	kek, err := ansix963KDFDecrypt(sharedSecret, 32, sharedInfo, kdfHash)
	if err != nil {
		return nil, fmt.Errorf("KDF failed: %w", err)
	}

	encryptedKey, err := findMatchingRecipientKey(kari.RecipientEncryptedKeys, opts)
	if err != nil {
		return nil, err
	}

	return aesKeyUnwrap(kek, encryptedKey)
}

// getKDFHashFunc returns the hash function for KDF based on key encryption algorithm OID.
func getKDFHashFunc(keaOID asn1.ObjectIdentifier) (func() hash.Hash, error) {
	switch {
	case keaOID.Equal(OIDECDHStdSHA1KDF):
		return sha1.New, nil
	case keaOID.Equal(OIDECDHStdSHA256KDF):
		return sha256.New, nil
	case keaOID.Equal(OIDECDHStdSHA384KDF):
		return sha512.New384, nil
	case keaOID.Equal(OIDECDHStdSHA512KDF):
		return sha512.New, nil
	case keaOID.Equal(OIDAESWrap256), keaOID.Equal(OIDAESWrap128):
		return sha256.New, nil
	default:
		return nil, fmt.Errorf("unsupported key encryption algorithm: %v", keaOID)
	}
}

// parseOriginatorPublicKey parses the ephemeral public key from Originator field.
func parseOriginatorPublicKey(originator asn1.RawValue, curve elliptic.Curve) (*ecdsa.PublicKey, error) {
	var originatorWrapper asn1.RawValue
	if _, err := asn1.Unmarshal(originator.Bytes, &originatorWrapper); err != nil {
		return nil, fmt.Errorf("failed to parse originator wrapper: %w", err)
	}

	if originatorWrapper.Tag != 1 || originatorWrapper.Class != asn1.ClassContextSpecific {
		return nil, fmt.Errorf("expected originatorKey [1], got tag=%d class=%d",
			originatorWrapper.Tag, originatorWrapper.Class)
	}

	originatorKeySeq, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      originatorWrapper.Bytes,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to reconstruct OriginatorPublicKey SEQUENCE: %w", err)
	}

	var originatorKey OriginatorPublicKey
	if _, err := asn1.Unmarshal(originatorKeySeq, &originatorKey); err != nil {
		return nil, fmt.Errorf("failed to parse OriginatorPublicKey: %w", err)
	}

	ephPub, err := parseECPublicKey(originatorKey.PublicKey.Bytes, curve)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ephemeral public key: %w", err)
	}
	return ephPub, nil
}

// deriveKEKFromECDH computes the key encryption key using ECDH and KDF.
func deriveKEKFromECDH(ecdsaPriv *ecdsa.PrivateKey, ephPub *ecdsa.PublicKey, kea pkix.AlgorithmIdentifier, kdfHash func() hash.Hash) ([]byte, error) {
	sharedSecret, err := ecdhSharedSecretDecrypt(ecdsaPriv, ephPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}

	wrapAlgBytes := getWrapAlgBytes(kea)
	sharedInfo, err := buildECCCMSSharedInfoDecryptRaw(wrapAlgBytes, 256)
	if err != nil {
		return nil, fmt.Errorf("failed to build SharedInfo: %w", err)
	}

	kek, err := ansix963KDFDecrypt(sharedSecret, 32, sharedInfo, kdfHash)
	if err != nil {
		return nil, fmt.Errorf("KDF failed: %w", err)
	}
	return kek, nil
}

// getWrapAlgBytes extracts or builds the wrap algorithm bytes for SharedInfo.
func getWrapAlgBytes(kea pkix.AlgorithmIdentifier) []byte {
	if kea.Parameters.FullBytes != nil {
		return kea.Parameters.FullBytes
	}
	nullParams, _ := asn1.Marshal(asn1.RawValue{Tag: asn1.TagNull})
	defaultAlg := pkix.AlgorithmIdentifier{
		Algorithm:  OIDAESWrap256,
		Parameters: asn1.RawValue{FullBytes: nullParams},
	}
	wrapAlgBytes, _ := asn1.Marshal(defaultAlg)
	return wrapAlgBytes
}

// findMatchingRecipientKey finds the encrypted key for the matching recipient.
func findMatchingRecipientKey(reks []RecipientEncryptedKey, opts *DecryptOptions) ([]byte, error) {
	for _, rek := range reks {
		if opts.Certificate != nil && rek.RID.IssuerAndSerial != nil {
			if matchesIssuerAndSerial(opts.Certificate, rek.RID.IssuerAndSerial) {
				return rek.EncryptedKey, nil
			}
			continue
		}
		return rek.EncryptedKey, nil
	}
	return nil, fmt.Errorf("no matching RecipientEncryptedKey found")
}

// ECDHDeriver is implemented by keys that can perform ECDH key derivation in hardware (HSM).
// This enables CMS decryption with EC keys stored in HSM.
type ECDHDeriver interface {
	DeriveECDH(ephemeralPub *ecdsa.PublicKey) (sharedSecret []byte, err error)
}

// KEMDecapsulator is implemented by keys that can perform KEM decapsulation in hardware (HSM).
type KEMDecapsulator interface {
	DecapsulateKEM(ciphertext []byte) (sharedSecret []byte, err error)
}

// decryptKEMRecipient decrypts the CEK from a KEMRecipientInfo (ML-KEM).
func decryptKEMRecipient(kemri *KEMRecipientInfo, opts *DecryptOptions) ([]byte, error) {
	// Check if RecipientIdentifier matches
	if opts.Certificate != nil && kemri.RID.IssuerAndSerial != nil {
		if !matchesIssuerAndSerial(opts.Certificate, kemri.RID.IssuerAndSerial) {
			return nil, fmt.Errorf("certificate does not match RecipientIdentifier")
		}
	}

	var sharedSecret []byte
	var err error

	// HSM support: try KEMDecapsulator interface first (e.g., PKCS11Signer with Utimaco)
	if decap, ok := opts.PrivateKey.(KEMDecapsulator); ok {
		sharedSecret, err = decap.DecapsulateKEM(kemri.KEMCT)
		if err != nil {
			return nil, fmt.Errorf("HSM KEM decapsulation failed: %w", err)
		}
	} else {
		// Software fallback: use raw ML-KEM private key bytes
		var scheme kem.Scheme
		switch {
		case kemri.KEM.Algorithm.Equal(OIDMLKEM512):
			scheme = mlkem512.Scheme()
		case kemri.KEM.Algorithm.Equal(OIDMLKEM768):
			scheme = mlkem768.Scheme()
		case kemri.KEM.Algorithm.Equal(OIDMLKEM1024):
			scheme = mlkem1024.Scheme()
		default:
			return nil, fmt.Errorf("unsupported KEM algorithm: %v", kemri.KEM.Algorithm)
		}

		// Unpack private key
		privKey, err := scheme.UnmarshalBinaryPrivateKey(getMLKEMPrivateKeyBytes(opts.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal private key: %w", err)
		}

		// KEM decapsulation
		sharedSecret, err = scheme.Decapsulate(privKey, kemri.KEMCT)
		if err != nil {
			return nil, fmt.Errorf("KEM decapsulation failed: %w", err)
		}
	}

	// Build CMSORIforKEMOtherInfo for HKDF info parameter (RFC 9629 Section 6)
	kdfInfo, err := buildKEMKDFInfoDecrypt(kemri.Wrap, kemri.KEKLength, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build KDF info: %w", err)
	}

	// Derive KEK from shared secret using HKDF with RFC 9629 info
	kek, err := deriveKEKFromECDHDecrypt(sharedSecret, kemri.KEKLength, kdfInfo)
	if err != nil {
		return nil, fmt.Errorf("KDF failed: %w", err)
	}

	// Unwrap CEK
	return aesKeyUnwrap(kek, kemri.EncryptedKey)
}

// decryptContent decrypts the encrypted content with the CEK.
func decryptContent(eci *EncryptedContentInfo, cek []byte) ([]byte, error) {
	alg := eci.ContentEncryptionAlgorithm.Algorithm

	switch {
	case alg.Equal(OIDAES256GCM) || alg.Equal(OIDAES128GCM) || alg.Equal(OIDAES192GCM):
		return decryptAESGCM(eci, cek)
	case alg.Equal(OIDAES256CBC) || alg.Equal(OIDAES128CBC) || alg.Equal(OIDAES192CBC):
		return decryptAESCBC(eci, cek)
	default:
		return nil, fmt.Errorf("unsupported content encryption algorithm: %v", alg)
	}
}

// decryptAESGCM decrypts content encrypted with AES-GCM.
func decryptAESGCM(eci *EncryptedContentInfo, cek []byte) ([]byte, error) {
	// Parse GCM parameters
	var params GCMParameters
	if _, err := asn1.Unmarshal(eci.ContentEncryptionAlgorithm.Parameters.FullBytes, &params); err != nil {
		return nil, fmt.Errorf("failed to parse GCM parameters: %w", err)
	}

	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return gcm.Open(nil, params.Nonce, eci.EncryptedContent, nil)
}

// decryptAESCBC decrypts content encrypted with AES-CBC.
func decryptAESCBC(eci *EncryptedContentInfo, cek []byte) ([]byte, error) {
	// Parse IV from parameters
	var iv []byte
	if _, err := asn1.Unmarshal(eci.ContentEncryptionAlgorithm.Parameters.FullBytes, &iv); err != nil {
		return nil, fmt.Errorf("failed to parse IV: %w", err)
	}

	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("invalid IV length: %d", len(iv))
	}

	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}

	if len(eci.EncryptedContent)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of block size")
	}

	plaintext := make([]byte, len(eci.EncryptedContent))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, eci.EncryptedContent)

	// Remove PKCS#7 padding
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("plaintext is empty")
	}
	padLen := int(plaintext[len(plaintext)-1])
	if padLen > aes.BlockSize || padLen > len(plaintext) {
		return nil, fmt.Errorf("invalid padding")
	}
	for i := len(plaintext) - padLen; i < len(plaintext); i++ {
		if plaintext[i] != byte(padLen) {
			return nil, fmt.Errorf("invalid PKCS#7 padding")
		}
	}

	return plaintext[:len(plaintext)-padLen], nil
}

// matchesIssuerAndSerial checks if a certificate matches an IssuerAndSerialNumber.
func matchesIssuerAndSerial(cert *x509.Certificate, ias *IssuerAndSerialNumber) bool {
	if cert.SerialNumber.Cmp(ias.SerialNumber) != 0 {
		return false
	}
	// Compare raw issuer bytes
	return string(cert.RawIssuer) == string(ias.Issuer.FullBytes)
}

// parseECPublicKey parses an uncompressed EC public key point.
func parseECPublicKey(data []byte, curve elliptic.Curve) (*ecdsa.PublicKey, error) {
	//nolint:staticcheck // elliptic.Unmarshal is deprecated but needed for X.509 compatibility
	x, y := elliptic.Unmarshal(curve, data)
	if x == nil {
		return nil, fmt.Errorf("failed to unmarshal EC point")
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

// aesKeyUnwrap implements RFC 3394 AES Key Unwrap.
func aesKeyUnwrap(kek, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 24 || len(ciphertext)%8 != 0 {
		return nil, fmt.Errorf("invalid ciphertext length")
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}

	n := (len(ciphertext) / 8) - 1
	a := make([]byte, 8)
	copy(a, ciphertext[:8])
	r := make([][]byte, n)
	for i := 0; i < n; i++ {
		r[i] = make([]byte, 8)
		copy(r[i], ciphertext[8*(i+1):8*(i+2)])
	}

	// Unwrap
	buf := make([]byte, 16)
	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			t := uint64(n*j + i)
			// A ^= t
			for k := 0; k < 8; k++ {
				a[k] ^= byte(t >> (56 - 8*k))
			}
			copy(buf[:8], a)
			copy(buf[8:], r[i-1])
			block.Decrypt(buf, buf)
			copy(a, buf[:8])
			copy(r[i-1], buf[8:])
		}
	}

	// Check IV
	expectedIV := []byte{0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6}
	for i := 0; i < 8; i++ {
		if a[i] != expectedIV[i] {
			return nil, fmt.Errorf("key unwrap integrity check failed")
		}
	}

	// Concatenate R blocks
	result := make([]byte, 0, n*8)
	for i := 0; i < n; i++ {
		result = append(result, r[i]...)
	}

	return result, nil
}

// ecdhSharedSecretDecrypt computes ECDH shared secret for decryption.
func ecdhSharedSecretDecrypt(priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey) ([]byte, error) {
	ecdhPub, err := ecdsaToECDHDecrypt(pub)
	if err != nil {
		return nil, err
	}

	var curve ecdh.Curve
	switch priv.Curve {
	case elliptic.P256():
		curve = ecdh.P256()
	case elliptic.P384():
		curve = ecdh.P384()
	case elliptic.P521():
		curve = ecdh.P521()
	default:
		return nil, fmt.Errorf("unsupported curve")
	}

	ecdhPriv, err := curve.NewPrivateKey(priv.D.Bytes())
	if err != nil {
		return nil, err
	}

	return ecdhPriv.ECDH(ecdhPub)
}

// ecdsaToECDHDecrypt converts an ECDSA public key to ECDH for decryption.
func ecdsaToECDHDecrypt(pub *ecdsa.PublicKey) (*ecdh.PublicKey, error) {
	var curve ecdh.Curve
	switch pub.Curve {
	case elliptic.P256():
		curve = ecdh.P256()
	case elliptic.P384():
		curve = ecdh.P384()
	case elliptic.P521():
		curve = ecdh.P521()
	default:
		return nil, fmt.Errorf("unsupported curve")
	}

	// Build uncompressed point manually: 0x04 || X || Y
	// This avoids the deprecated elliptic.Marshal
	byteLen := (pub.Curve.Params().BitSize + 7) / 8
	pointBytes := make([]byte, 1+2*byteLen)
	pointBytes[0] = 0x04 // uncompressed point indicator
	pub.X.FillBytes(pointBytes[1 : 1+byteLen])
	pub.Y.FillBytes(pointBytes[1+byteLen:])
	return curve.NewPublicKey(pointBytes)
}

// ansix963KDFDecrypt implements ANSI X9.63 KDF for decryption.
func ansix963KDFDecrypt(sharedSecret []byte, keySize int, sharedInfo []byte, h func() hash.Hash) ([]byte, error) {
	hashSize := h().Size()
	reps := (keySize + hashSize - 1) / hashSize

	var result []byte
	counter := make([]byte, 4)
	for i := 1; i <= reps; i++ {
		binary.BigEndian.PutUint32(counter, uint32(i))
		hasher := h()
		hasher.Write(sharedSecret)
		hasher.Write(counter)
		if len(sharedInfo) > 0 {
			hasher.Write(sharedInfo)
		}
		result = append(result, hasher.Sum(nil)...)
	}

	return result[:keySize], nil
}

// CMSORIforKEMOtherInfoDecrypt is the structure for HKDF info in KEMRecipientInfo (RFC 9629 Section 6).
type CMSORIforKEMOtherInfoDecrypt struct {
	Wrap      pkix.AlgorithmIdentifier
	KEKLength int
	// UKM is optional and omitted if nil
}

// buildKEMKDFInfoDecrypt builds the DER-encoded CMSORIforKEMOtherInfo for HKDF info (RFC 9629).
func buildKEMKDFInfoDecrypt(wrap pkix.AlgorithmIdentifier, kekLength int, ukm []byte) ([]byte, error) {
	info := CMSORIforKEMOtherInfoDecrypt{
		Wrap:      wrap,
		KEKLength: kekLength,
	}
	return asn1.Marshal(info)
}

// deriveKEKFromECDHDecrypt derives a KEK from shared secret using HKDF for decryption.
func deriveKEKFromECDHDecrypt(sharedSecret []byte, keySize int, info []byte) ([]byte, error) {
	reader := hkdf.New(sha256.New, sharedSecret, nil, info)
	kek := make([]byte, keySize)
	if _, err := io.ReadFull(reader, kek); err != nil {
		return nil, err
	}
	return kek, nil
}

// getMLKEMPrivateKeyBytes extracts bytes from ML-KEM private key types.
func getMLKEMPrivateKeyBytes(priv crypto.PrivateKey) []byte {
	switch k := priv.(type) {
	case *mlkem512.PrivateKey:
		b, _ := k.MarshalBinary()
		return b
	case *mlkem768.PrivateKey:
		b, _ := k.MarshalBinary()
		return b
	case *mlkem1024.PrivateKey:
		b, _ := k.MarshalBinary()
		return b
	default:
		return nil
	}
}

// buildECCCMSSharedInfoDecryptRaw builds ECC-CMS-SharedInfo using raw keyInfo bytes.
// This is used for decryption to preserve the exact bytes from the CMS message,
// ensuring interoperability with different implementations (OpenSSL, BouncyCastle).
func buildECCCMSSharedInfoDecryptRaw(keyInfoBytes []byte, keyBits int) ([]byte, error) {
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
	// Use the EXACT keyInfoBytes as-is (do not re-marshal)
	// IMPORTANT: Copy keyInfoBytes first! It may be a slice into a shared buffer
	// (e.g., the original CMS message), and append would corrupt subsequent data.
	seqContent := make([]byte, 0, len(keyInfoBytes)+len(suppPubInfoTagged))
	seqContent = append(seqContent, keyInfoBytes...)
	seqContent = append(seqContent, suppPubInfoTagged...)
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
