package cms

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
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

// Decrypt decrypts a CMS EnvelopedData structure.
// It finds the matching RecipientInfo for the provided private key,
// decrypts the CEK, and then decrypts the content.
func Decrypt(data []byte, opts *DecryptOptions) (*DecryptResult, error) {
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

	if !ci.ContentType.Equal(OIDEnvelopedData) {
		return nil, fmt.Errorf("not an EnvelopedData: %v", ci.ContentType)
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

// decryptCEK finds the matching RecipientInfo and decrypts the CEK.
func decryptCEK(env *EnvelopedData, opts *DecryptOptions) ([]byte, error) {
	for _, riRaw := range env.RecipientInfos {
		cek, err := tryDecryptRecipientInfo(riRaw, opts)
		if err == nil {
			return cek, nil
		}
		// Continue trying other RecipientInfos
	}

	return nil, fmt.Errorf("no matching RecipientInfo found for provided key")
}

// tryDecryptRecipientInfo attempts to decrypt the CEK from a RecipientInfo.
func tryDecryptRecipientInfo(riRaw asn1.RawValue, opts *DecryptOptions) ([]byte, error) {
	// Determine RecipientInfo type by tag
	switch {
	case riRaw.Tag == asn1.TagSequence && riRaw.Class == asn1.ClassUniversal:
		// KeyTransRecipientInfo (SEQUENCE, no tag)
		var ktri KeyTransRecipientInfo
		if _, err := asn1.Unmarshal(riRaw.FullBytes, &ktri); err != nil {
			return nil, err
		}
		return decryptKeyTrans(&ktri, opts)

	case riRaw.Tag == 1 && riRaw.Class == asn1.ClassContextSpecific:
		// [1] KeyAgreeRecipientInfo
		var kari KeyAgreeRecipientInfo
		if _, err := asn1.Unmarshal(riRaw.Bytes, &kari); err != nil {
			return nil, err
		}
		return decryptKeyAgree(&kari, opts)

	case riRaw.Tag == 2 && riRaw.Class == asn1.ClassContextSpecific:
		// [2] KEMRecipientInfo
		var kemri KEMRecipientInfo
		if _, err := asn1.Unmarshal(riRaw.Bytes, &kemri); err != nil {
			return nil, err
		}
		return decryptKEMRecipient(&kemri, opts)

	default:
		return nil, fmt.Errorf("unsupported RecipientInfo type: tag=%d, class=%d", riRaw.Tag, riRaw.Class)
	}
}

// decryptKeyTrans decrypts the CEK from a KeyTransRecipientInfo (RSA).
func decryptKeyTrans(ktri *KeyTransRecipientInfo, opts *DecryptOptions) ([]byte, error) {
	rsaPriv, ok := opts.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("RSA private key required for KeyTransRecipientInfo")
	}

	// Check if RecipientIdentifier matches
	if opts.Certificate != nil && ktri.RID.IssuerAndSerial != nil {
		if !matchesIssuerAndSerial(opts.Certificate, ktri.RID.IssuerAndSerial) {
			return nil, fmt.Errorf("certificate does not match RecipientIdentifier")
		}
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
func decryptKeyAgree(kari *KeyAgreeRecipientInfo, opts *DecryptOptions) ([]byte, error) {
	ecdsaPriv, ok := opts.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("ECDSA private key required for KeyAgreeRecipientInfo")
	}

	// Parse OriginatorPublicKey from Originator
	var originatorKey OriginatorPublicKey
	if _, err := asn1.Unmarshal(kari.Originator.Bytes, &originatorKey); err != nil {
		return nil, fmt.Errorf("failed to parse OriginatorPublicKey: %w", err)
	}

	// Parse ephemeral public key
	ephPubBytes := originatorKey.PublicKey.Bytes
	ephPub, err := parseECPublicKey(ephPubBytes, ecdsaPriv.Curve)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ephemeral public key: %w", err)
	}

	// Compute shared secret
	sharedSecret, err := ecdhSharedSecretDecrypt(ecdsaPriv, ephPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}

	// Derive KEK using ANSI X9.63 KDF
	kek, err := ansix963KDFSHA256Decrypt(sharedSecret, 32, nil)
	if err != nil {
		return nil, fmt.Errorf("KDF failed: %w", err)
	}

	// Find matching RecipientEncryptedKey
	var encryptedKey []byte
	for _, rek := range kari.RecipientEncryptedKeys {
		if opts.Certificate != nil && rek.RID.IssuerAndSerial != nil {
			if matchesIssuerAndSerial(opts.Certificate, rek.RID.IssuerAndSerial) {
				encryptedKey = rek.EncryptedKey
				break
			}
		} else {
			// No certificate to match, try this one
			encryptedKey = rek.EncryptedKey
			break
		}
	}

	if encryptedKey == nil {
		return nil, fmt.Errorf("no matching RecipientEncryptedKey found")
	}

	// Unwrap CEK
	return aesKeyUnwrap(kek, encryptedKey)
}

// decryptKEMRecipient decrypts the CEK from a KEMRecipientInfo (ML-KEM).
func decryptKEMRecipient(kemri *KEMRecipientInfo, opts *DecryptOptions) ([]byte, error) {
	// Check if RecipientIdentifier matches
	if opts.Certificate != nil && kemri.RID.IssuerAndSerial != nil {
		if !matchesIssuerAndSerial(opts.Certificate, kemri.RID.IssuerAndSerial) {
			return nil, fmt.Errorf("certificate does not match RecipientIdentifier")
		}
	}

	// Determine ML-KEM scheme from OID and decapsulate
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
	sharedSecret, err := scheme.Decapsulate(privKey, kemri.KEMCT)
	if err != nil {
		return nil, fmt.Errorf("KEM decapsulation failed: %w", err)
	}

	// Derive KEK from shared secret using HKDF
	kek, err := deriveKEKDecrypt(sharedSecret, kemri.KEKLength, []byte("CMS-KEMRecipientInfo"))
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

	// Marshal to uncompressed point format
	pointBytes := elliptic.Marshal(pub.Curve, pub.X, pub.Y)
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

// ansix963KDFSHA256Decrypt implements ANSI X9.63 KDF with SHA-256 for decryption.
func ansix963KDFSHA256Decrypt(sharedSecret []byte, keySize int, sharedInfo []byte) ([]byte, error) {
	return ansix963KDFDecrypt(sharedSecret, keySize, sharedInfo, sha256.New)
}

// deriveKEKDecrypt derives a KEK from shared secret using HKDF for decryption.
func deriveKEKDecrypt(sharedSecret []byte, keySize int, info []byte) ([]byte, error) {
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

