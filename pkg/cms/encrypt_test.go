package cms

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"

	pkicrypto "github.com/remiblancher/post-quantum-pki/pkg/crypto"
)

// =============================================================================
// Functional Tests: RSA Encrypt/Decrypt Round-trip
// =============================================================================

// TestF_EncryptDecrypt_RSA_AES256GCM tests RSA encryption with AES-256-GCM.
// AES-GCM uses AuthEnvelopedData (RFC 5083) for authenticated encryption.
func TestF_EncryptDecrypt_RSA_AES256GCM(t *testing.T) {
	kp := generateRSAKeyPair(t, 2048)
	cert := generateTestCertificate(t, kp)

	plaintext := []byte("Hello, CMS Encryption with RSA!")

	// Encrypt
	ciphertext, err := Encrypt(context.Background(), plaintext, &EncryptOptions{
		Recipients:        []*x509.Certificate{cert},
		ContentEncryption: AES256GCM,
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Verify it's an AuthEnvelopedData (GCM uses authenticated encryption)
	var ci ContentInfo
	_, err = asn1.Unmarshal(ciphertext, &ci)
	if err != nil {
		t.Fatalf("Failed to parse ContentInfo: %v", err)
	}
	if !ci.ContentType.Equal(OIDAuthEnvelopedData) {
		t.Errorf("Expected AuthEnvelopedData OID for AES-GCM, got %v", ci.ContentType)
	}

	// Decrypt
	result, err := Decrypt(context.Background(), ciphertext, &DecryptOptions{
		PrivateKey:  kp.PrivateKey,
		Certificate: cert,
	})
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(result.Content, plaintext) {
		t.Errorf("Decrypted content mismatch: expected %q, got %q", plaintext, result.Content)
	}
}

// TestF_EncryptDecrypt_RSA_AES256CBC tests RSA with AES-256-CBC.
func TestF_EncryptDecrypt_RSA_AES256CBC(t *testing.T) {
	kp := generateRSAKeyPair(t, 2048)
	cert := generateTestCertificate(t, kp)

	plaintext := []byte("Hello, CMS with AES-256-CBC!")

	ciphertext, err := Encrypt(context.Background(), plaintext, &EncryptOptions{
		Recipients:        []*x509.Certificate{cert},
		ContentEncryption: AES256CBC,
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	result, err := Decrypt(context.Background(), ciphertext, &DecryptOptions{
		PrivateKey:  kp.PrivateKey,
		Certificate: cert,
	})
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(result.Content, plaintext) {
		t.Errorf("Decrypted content mismatch")
	}
}

// TestF_EncryptDecrypt_RSA_AES128GCM tests RSA with AES-128-GCM.
func TestF_EncryptDecrypt_RSA_AES128GCM(t *testing.T) {
	kp := generateRSAKeyPair(t, 2048)
	cert := generateTestCertificate(t, kp)

	plaintext := []byte("Hello, CMS with AES-128-GCM!")

	ciphertext, err := Encrypt(context.Background(), plaintext, &EncryptOptions{
		Recipients:        []*x509.Certificate{cert},
		ContentEncryption: AES128GCM,
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	result, err := Decrypt(context.Background(), ciphertext, &DecryptOptions{
		PrivateKey:  kp.PrivateKey,
		Certificate: cert,
	})
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(result.Content, plaintext) {
		t.Errorf("Decrypted content mismatch")
	}
}

// =============================================================================
// Functional Tests: ECDH Encrypt/Decrypt Round-trip
// =============================================================================

// TestF_EncryptDecrypt_ECDH_P256 tests ECDH P-256 encryption.
func TestF_EncryptDecrypt_ECDH_P256(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	plaintext := []byte("Hello, CMS with ECDH P-256!")

	ciphertext, err := Encrypt(context.Background(), plaintext, &EncryptOptions{
		Recipients:        []*x509.Certificate{cert},
		ContentEncryption: AES256GCM,
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	result, err := Decrypt(context.Background(), ciphertext, &DecryptOptions{
		PrivateKey:  kp.PrivateKey,
		Certificate: cert,
	})
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(result.Content, plaintext) {
		t.Errorf("Decrypted content mismatch")
	}
}

// TestF_EncryptDecrypt_ECDH_P384 tests ECDH P-384 encryption.
func TestF_EncryptDecrypt_ECDH_P384(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P384())
	cert := generateTestCertificate(t, kp)

	plaintext := []byte("Hello, CMS with ECDH P-384!")

	ciphertext, err := Encrypt(context.Background(), plaintext, &EncryptOptions{
		Recipients:        []*x509.Certificate{cert},
		ContentEncryption: AES256GCM,
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	result, err := Decrypt(context.Background(), ciphertext, &DecryptOptions{
		PrivateKey:  kp.PrivateKey,
		Certificate: cert,
	})
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(result.Content, plaintext) {
		t.Errorf("Decrypted content mismatch")
	}
}

// =============================================================================
// Functional Tests: Multiple Recipients
// =============================================================================

// TestF_EncryptDecrypt_MultipleRecipients_RSA tests multiple RSA recipients.
func TestF_EncryptDecrypt_MultipleRecipients_RSA(t *testing.T) {
	// Create two recipients
	kp1 := generateRSAKeyPair(t, 2048)
	cert1 := generateTestCertificate(t, kp1)

	kp2 := generateRSAKeyPair(t, 2048)
	cert2 := generateTestCertificate(t, kp2)

	plaintext := []byte("Hello to multiple recipients!")

	ciphertext, err := Encrypt(context.Background(), plaintext, &EncryptOptions{
		Recipients:        []*x509.Certificate{cert1, cert2},
		ContentEncryption: AES256GCM,
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// First recipient can decrypt
	result1, err := Decrypt(context.Background(), ciphertext, &DecryptOptions{
		PrivateKey:  kp1.PrivateKey,
		Certificate: cert1,
	})
	if err != nil {
		t.Fatalf("Decrypt with recipient 1 failed: %v", err)
	}
	if !bytes.Equal(result1.Content, plaintext) {
		t.Errorf("Recipient 1: content mismatch")
	}

	// Second recipient can decrypt
	result2, err := Decrypt(context.Background(), ciphertext, &DecryptOptions{
		PrivateKey:  kp2.PrivateKey,
		Certificate: cert2,
	})
	if err != nil {
		t.Fatalf("Decrypt with recipient 2 failed: %v", err)
	}
	if !bytes.Equal(result2.Content, plaintext) {
		t.Errorf("Recipient 2: content mismatch")
	}
}

// TestF_EncryptDecrypt_MultipleRecipients_Mixed tests RSA + ECDH recipients.
func TestF_EncryptDecrypt_MultipleRecipients_Mixed(t *testing.T) {
	// RSA recipient
	rsaKP := generateRSAKeyPair(t, 2048)
	rsaCert := generateTestCertificate(t, rsaKP)

	// ECDH recipient
	ecKP := generateECDSAKeyPair(t, elliptic.P256())
	ecCert := generateTestCertificate(t, ecKP)

	plaintext := []byte("Hello to mixed recipients!")

	ciphertext, err := Encrypt(context.Background(), plaintext, &EncryptOptions{
		Recipients:        []*x509.Certificate{rsaCert, ecCert},
		ContentEncryption: AES256GCM,
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// RSA recipient can decrypt
	result1, err := Decrypt(context.Background(), ciphertext, &DecryptOptions{
		PrivateKey:  rsaKP.PrivateKey,
		Certificate: rsaCert,
	})
	if err != nil {
		t.Fatalf("Decrypt with RSA failed: %v", err)
	}
	if !bytes.Equal(result1.Content, plaintext) {
		t.Errorf("RSA recipient: content mismatch")
	}

	// ECDH recipient can decrypt
	result2, err := Decrypt(context.Background(), ciphertext, &DecryptOptions{
		PrivateKey:  ecKP.PrivateKey,
		Certificate: ecCert,
	})
	if err != nil {
		t.Fatalf("Decrypt with ECDH failed: %v", err)
	}
	if !bytes.Equal(result2.Content, plaintext) {
		t.Errorf("ECDH recipient: content mismatch")
	}
}

// =============================================================================
// Functional Tests: Edge Cases
// =============================================================================

// TestF_Encrypt_EmptyContent tests encrypting empty content.
func TestF_Encrypt_EmptyContent(t *testing.T) {
	kp := generateRSAKeyPair(t, 2048)
	cert := generateTestCertificate(t, kp)

	plaintext := []byte{}

	ciphertext, err := Encrypt(context.Background(), plaintext, &EncryptOptions{
		Recipients:        []*x509.Certificate{cert},
		ContentEncryption: AES256GCM,
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	result, err := Decrypt(context.Background(), ciphertext, &DecryptOptions{
		PrivateKey:  kp.PrivateKey,
		Certificate: cert,
	})
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if len(result.Content) != 0 {
		t.Errorf("Expected empty content, got %d bytes", len(result.Content))
	}
}

// TestF_Encrypt_LargeContent tests encrypting large content.
func TestF_Encrypt_LargeContent(t *testing.T) {
	kp := generateRSAKeyPair(t, 2048)
	cert := generateTestCertificate(t, kp)

	// 100 KB content
	plaintext := make([]byte, 100*1024)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	ciphertext, err := Encrypt(context.Background(), plaintext, &EncryptOptions{
		Recipients:        []*x509.Certificate{cert},
		ContentEncryption: AES256GCM,
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	result, err := Decrypt(context.Background(), ciphertext, &DecryptOptions{
		PrivateKey:  kp.PrivateKey,
		Certificate: cert,
	})
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(result.Content, plaintext) {
		t.Errorf("Content mismatch for large content")
	}
}

// TestF_Encrypt_CustomContentType tests custom content type.
func TestF_Encrypt_CustomContentType(t *testing.T) {
	kp := generateRSAKeyPair(t, 2048)
	cert := generateTestCertificate(t, kp)

	plaintext := []byte("test content")
	customOID := asn1.ObjectIdentifier{1, 2, 3, 4, 5}

	ciphertext, err := Encrypt(context.Background(), plaintext, &EncryptOptions{
		Recipients:  []*x509.Certificate{cert},
		ContentType: customOID,
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	result, err := Decrypt(context.Background(), ciphertext, &DecryptOptions{
		PrivateKey:  kp.PrivateKey,
		Certificate: cert,
	})
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !result.ContentType.Equal(customOID) {
		t.Errorf("ContentType mismatch: expected %v, got %v", customOID, result.ContentType)
	}
}

// =============================================================================
// Unit Tests: Error Cases
// =============================================================================

// TestU_Encrypt_RecipientsMissing tests that no recipients is rejected.
func TestU_Encrypt_RecipientsMissing(t *testing.T) {
	plaintext := []byte("test content")

	_, err := Encrypt(context.Background(), plaintext, &EncryptOptions{
		Recipients: nil,
	})
	if err == nil {
		t.Error("Expected error for no recipients")
	}
}

// TestU_Decrypt_PrivateKeyMissing tests that nil private key is rejected.
func TestU_Decrypt_PrivateKeyMissing(t *testing.T) {
	_, err := Decrypt(context.Background(), []byte{}, nil)
	if err == nil {
		t.Error("Expected error for nil options")
	}

	_, err = Decrypt(context.Background(), []byte{}, &DecryptOptions{
		PrivateKey: nil,
	})
	if err == nil {
		t.Error("Expected error for nil private key")
	}
}

// TestU_Decrypt_WrongKey tests decryption with wrong key fails.
func TestU_Decrypt_WrongKey(t *testing.T) {
	// Encrypt with one key
	kp1 := generateRSAKeyPair(t, 2048)
	cert1 := generateTestCertificate(t, kp1)

	plaintext := []byte("secret message")

	ciphertext, err := Encrypt(context.Background(), plaintext, &EncryptOptions{
		Recipients: []*x509.Certificate{cert1},
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Try to decrypt with different key
	kp2 := generateRSAKeyPair(t, 2048)
	cert2 := generateTestCertificate(t, kp2)

	_, err = Decrypt(context.Background(), ciphertext, &DecryptOptions{
		PrivateKey:  kp2.PrivateKey,
		Certificate: cert2,
	})
	if err == nil {
		t.Error("Expected error when decrypting with wrong key")
	}
}

// TestU_Decrypt_InvalidData tests decryption of invalid data.
func TestU_Decrypt_InvalidData(t *testing.T) {
	kp := generateRSAKeyPair(t, 2048)

	_, err := Decrypt(context.Background(), []byte("not a CMS structure"), &DecryptOptions{
		PrivateKey: kp.PrivateKey,
	})
	if err == nil {
		t.Error("Expected error for invalid data")
	}
}

// =============================================================================
// Unit Tests: Key Wrap/Unwrap
// =============================================================================

// TestU_AESKeyWrap_RoundTrip tests AES key wrap round trip.
func TestU_AESKeyWrap_RoundTrip(t *testing.T) {
	kek := make([]byte, 32) // 256-bit KEK
	for i := range kek {
		kek[i] = byte(i)
	}

	key := make([]byte, 32) // 256-bit key to wrap
	for i := range key {
		key[i] = byte(i + 100)
	}

	wrapped, err := aesKeyWrap(kek, key)
	if err != nil {
		t.Fatalf("aesKeyWrap failed: %v", err)
	}

	// Wrapped key should be 8 bytes longer (IV)
	if len(wrapped) != len(key)+8 {
		t.Errorf("Wrapped key length: expected %d, got %d", len(key)+8, len(wrapped))
	}

	unwrapped, err := aesKeyUnwrap(kek, wrapped)
	if err != nil {
		t.Fatalf("aesKeyUnwrap failed: %v", err)
	}

	if !bytes.Equal(unwrapped, key) {
		t.Error("Unwrapped key doesn't match original")
	}
}

// TestU_AESKeyWrap_InvalidKeyLength tests key wrap with invalid key length.
func TestU_AESKeyWrap_InvalidKeyLength(t *testing.T) {
	kek := make([]byte, 32)
	key := make([]byte, 15) // Not a multiple of 8

	_, err := aesKeyWrap(kek, key)
	if err == nil {
		t.Error("Expected error for invalid key length")
	}
}

// TestU_AESKeyWrap_TooShort tests key wrap with too short key.
func TestU_AESKeyWrap_TooShort(t *testing.T) {
	kek := make([]byte, 32)
	key := make([]byte, 8) // Too short (minimum 16)

	_, err := aesKeyWrap(kek, key)
	if err == nil {
		t.Error("Expected error for too short key")
	}
}

// TestU_AESKeyUnwrap_IntegrityCheck tests unwrap detects tampering.
func TestU_AESKeyUnwrap_IntegrityCheck(t *testing.T) {
	kek := make([]byte, 32)
	for i := range kek {
		kek[i] = byte(i)
	}

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 100)
	}

	wrapped, err := aesKeyWrap(kek, key)
	if err != nil {
		t.Fatalf("aesKeyWrap failed: %v", err)
	}

	// Tamper with wrapped key
	wrapped[10] ^= 0xFF

	_, err = aesKeyUnwrap(kek, wrapped)
	if err == nil {
		t.Error("Expected integrity check failure")
	}
}

// =============================================================================
// Functional Tests: ML-KEM Encrypt/Decrypt
// =============================================================================

// TestF_EncryptDecrypt_MLKEM512 tests ML-KEM-512 encryption/decryption.
func TestF_EncryptDecrypt_MLKEM512(t *testing.T) {
	kemKP := generateMLKEMKeyPair(t, pkicrypto.AlgMLKEM512)
	cert := generateMLKEMCertificate(t, kemKP)

	plaintext := []byte("Hello, CMS with ML-KEM-512!")

	ciphertext, err := Encrypt(context.Background(), plaintext, &EncryptOptions{
		Recipients:        []*x509.Certificate{cert},
		ContentEncryption: AES256GCM,
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	result, err := Decrypt(context.Background(), ciphertext, &DecryptOptions{
		PrivateKey:  kemKP.PrivateKey,
		Certificate: cert,
	})
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(result.Content, plaintext) {
		t.Errorf("Decrypted content mismatch: expected %q, got %q", plaintext, result.Content)
	}
}

// TestF_EncryptDecrypt_MLKEM768 tests ML-KEM-768 encryption/decryption.
func TestF_EncryptDecrypt_MLKEM768(t *testing.T) {
	kemKP := generateMLKEMKeyPair(t, pkicrypto.AlgMLKEM768)
	cert := generateMLKEMCertificate(t, kemKP)

	plaintext := []byte("Hello, CMS with ML-KEM-768!")

	ciphertext, err := Encrypt(context.Background(), plaintext, &EncryptOptions{
		Recipients:        []*x509.Certificate{cert},
		ContentEncryption: AES256GCM,
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	result, err := Decrypt(context.Background(), ciphertext, &DecryptOptions{
		PrivateKey:  kemKP.PrivateKey,
		Certificate: cert,
	})
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(result.Content, plaintext) {
		t.Errorf("Decrypted content mismatch")
	}
}

// TestF_EncryptDecrypt_MLKEM1024 tests ML-KEM-1024 encryption/decryption.
func TestF_EncryptDecrypt_MLKEM1024(t *testing.T) {
	kemKP := generateMLKEMKeyPair(t, pkicrypto.AlgMLKEM1024)
	cert := generateMLKEMCertificate(t, kemKP)

	plaintext := []byte("Hello, CMS with ML-KEM-1024!")

	ciphertext, err := Encrypt(context.Background(), plaintext, &EncryptOptions{
		Recipients:        []*x509.Certificate{cert},
		ContentEncryption: AES256GCM,
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	result, err := Decrypt(context.Background(), ciphertext, &DecryptOptions{
		PrivateKey:  kemKP.PrivateKey,
		Certificate: cert,
	})
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(result.Content, plaintext) {
		t.Errorf("Decrypted content mismatch")
	}
}

// TestF_EncryptDecrypt_MLKEM_AllVariants tests all ML-KEM variants in a table-driven test.
func TestF_EncryptDecrypt_MLKEM_AllVariants(t *testing.T) {
	variants := []pkicrypto.AlgorithmID{
		pkicrypto.AlgMLKEM512,
		pkicrypto.AlgMLKEM768,
		pkicrypto.AlgMLKEM1024,
	}

	for _, variant := range variants {
		t.Run("[Functional] Encrypt: "+string(variant), func(t *testing.T) {
			kemKP := generateMLKEMKeyPair(t, variant)
			cert := generateMLKEMCertificate(t, kemKP)

			plaintext := []byte("Testing " + string(variant) + " encryption!")

			ciphertext, err := Encrypt(context.Background(), plaintext, &EncryptOptions{
				Recipients:        []*x509.Certificate{cert},
				ContentEncryption: AES256GCM,
			})
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			result, err := Decrypt(context.Background(), ciphertext, &DecryptOptions{
				PrivateKey:  kemKP.PrivateKey,
				Certificate: cert,
			})
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}

			if !bytes.Equal(result.Content, plaintext) {
				t.Errorf("Decrypted content mismatch")
			}
		})
	}
}

// TestF_EncryptDecrypt_MLKEM_WithAES128 tests ML-KEM with AES-128-GCM.
func TestF_EncryptDecrypt_MLKEM_WithAES128(t *testing.T) {
	kemKP := generateMLKEMKeyPair(t, pkicrypto.AlgMLKEM768)
	cert := generateMLKEMCertificate(t, kemKP)

	plaintext := []byte("ML-KEM with AES-128-GCM")

	ciphertext, err := Encrypt(context.Background(), plaintext, &EncryptOptions{
		Recipients:        []*x509.Certificate{cert},
		ContentEncryption: AES128GCM,
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	result, err := Decrypt(context.Background(), ciphertext, &DecryptOptions{
		PrivateKey: kemKP.PrivateKey,
	})
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(result.Content, plaintext) {
		t.Errorf("Decrypted content mismatch")
	}
}

// TestF_EncryptDecrypt_MLKEM_LargeContent tests ML-KEM with large content.
func TestF_EncryptDecrypt_MLKEM_LargeContent(t *testing.T) {
	kemKP := generateMLKEMKeyPair(t, pkicrypto.AlgMLKEM768)
	cert := generateMLKEMCertificate(t, kemKP)

	// 100 KB content
	plaintext := make([]byte, 100*1024)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	ciphertext, err := Encrypt(context.Background(), plaintext, &EncryptOptions{
		Recipients:        []*x509.Certificate{cert},
		ContentEncryption: AES256GCM,
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	result, err := Decrypt(context.Background(), ciphertext, &DecryptOptions{
		PrivateKey: kemKP.PrivateKey,
	})
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(result.Content, plaintext) {
		t.Errorf("Content mismatch for large content")
	}
}

// =============================================================================
// Functional Tests: AuthEnvelopedData (RFC 5083)
// =============================================================================

// TestF_AuthEnvelopedData_RSA_AES256GCM tests AuthEnvelopedData with RSA and AES-256-GCM.
func TestF_AuthEnvelopedData_RSA_AES256GCM(t *testing.T) {
	kp := generateRSAKeyPair(t, 2048)
	cert := generateTestCertificate(t, kp)

	plaintext := []byte("Hello, AuthEnvelopedData with RSA!")

	// Encrypt with AES-256-GCM (should produce AuthEnvelopedData)
	ciphertext, err := Encrypt(context.Background(), plaintext, &EncryptOptions{
		Recipients:        []*x509.Certificate{cert},
		ContentEncryption: AES256GCM,
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Verify it's an AuthEnvelopedData
	var ci ContentInfo
	_, err = asn1.Unmarshal(ciphertext, &ci)
	if err != nil {
		t.Fatalf("Failed to parse ContentInfo: %v", err)
	}
	if !ci.ContentType.Equal(OIDAuthEnvelopedData) {
		t.Errorf("Expected AuthEnvelopedData OID, got %v", ci.ContentType)
	}

	// Decrypt
	result, err := Decrypt(context.Background(), ciphertext, &DecryptOptions{
		PrivateKey:  kp.PrivateKey,
		Certificate: cert,
	})
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(result.Content, plaintext) {
		t.Errorf("Decrypted content mismatch: expected %q, got %q", plaintext, result.Content)
	}
}

// TestF_AuthEnvelopedData_ECDH_AES256GCM tests AuthEnvelopedData with ECDH and AES-256-GCM.
func TestF_AuthEnvelopedData_ECDH_AES256GCM(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	plaintext := []byte("Hello, AuthEnvelopedData with ECDH!")

	ciphertext, err := Encrypt(context.Background(), plaintext, &EncryptOptions{
		Recipients:        []*x509.Certificate{cert},
		ContentEncryption: AES256GCM,
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Verify it's an AuthEnvelopedData
	var ci ContentInfo
	_, err = asn1.Unmarshal(ciphertext, &ci)
	if err != nil {
		t.Fatalf("Failed to parse ContentInfo: %v", err)
	}
	if !ci.ContentType.Equal(OIDAuthEnvelopedData) {
		t.Errorf("Expected AuthEnvelopedData OID, got %v", ci.ContentType)
	}

	result, err := Decrypt(context.Background(), ciphertext, &DecryptOptions{
		PrivateKey:  kp.PrivateKey,
		Certificate: cert,
	})
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(result.Content, plaintext) {
		t.Errorf("Decrypted content mismatch")
	}
}

// TestF_AuthEnvelopedData_MLKEM_AES256GCM tests AuthEnvelopedData with ML-KEM and AES-256-GCM.
func TestF_AuthEnvelopedData_MLKEM_AES256GCM(t *testing.T) {
	kemKP := generateMLKEMKeyPair(t, pkicrypto.AlgMLKEM768)
	cert := generateMLKEMCertificate(t, kemKP)

	plaintext := []byte("Hello, AuthEnvelopedData with ML-KEM!")

	ciphertext, err := Encrypt(context.Background(), plaintext, &EncryptOptions{
		Recipients:        []*x509.Certificate{cert},
		ContentEncryption: AES256GCM,
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Verify it's an AuthEnvelopedData
	var ci ContentInfo
	_, err = asn1.Unmarshal(ciphertext, &ci)
	if err != nil {
		t.Fatalf("Failed to parse ContentInfo: %v", err)
	}
	if !ci.ContentType.Equal(OIDAuthEnvelopedData) {
		t.Errorf("Expected AuthEnvelopedData OID, got %v", ci.ContentType)
	}

	result, err := Decrypt(context.Background(), ciphertext, &DecryptOptions{
		PrivateKey:  kemKP.PrivateKey,
		Certificate: cert,
	})
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(result.Content, plaintext) {
		t.Errorf("Decrypted content mismatch")
	}
}

// TestF_AuthEnvelopedData_Structure tests the AuthEnvelopedData structure is correct.
func TestF_AuthEnvelopedData_Structure(t *testing.T) {
	kp := generateRSAKeyPair(t, 2048)
	cert := generateTestCertificate(t, kp)

	plaintext := []byte("Test structure")

	ciphertext, err := Encrypt(context.Background(), plaintext, &EncryptOptions{
		Recipients:        []*x509.Certificate{cert},
		ContentEncryption: AES256GCM,
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Parse and verify structure
	var ci ContentInfo
	_, err = asn1.Unmarshal(ciphertext, &ci)
	if err != nil {
		t.Fatalf("Failed to parse ContentInfo: %v", err)
	}

	var authEnv AuthEnvelopedData
	_, err = asn1.Unmarshal(ci.Content.Bytes, &authEnv)
	if err != nil {
		t.Fatalf("Failed to parse AuthEnvelopedData: %v", err)
	}

	// Verify version (should be 0 per RFC 5083)
	if authEnv.Version != 0 {
		t.Errorf("Expected version 0, got %d", authEnv.Version)
	}

	// Verify MAC is present and has correct size (16 bytes for GCM tag)
	if len(authEnv.MAC) != 16 {
		t.Errorf("Expected 16-byte MAC (GCM tag), got %d bytes", len(authEnv.MAC))
	}

	// Verify RecipientInfos is not empty
	if len(authEnv.RecipientInfos) == 0 {
		t.Error("Expected at least one RecipientInfo")
	}

	// Verify content encryption algorithm is AES-256-GCM
	if !authEnv.AuthEncryptedContentInfo.ContentEncryptionAlgorithm.Algorithm.Equal(OIDAES256GCM) {
		t.Errorf("Expected AES-256-GCM algorithm")
	}
}

// TestF_AuthEnvelopedData_AES128GCM tests AuthEnvelopedData with AES-128-GCM.
func TestF_AuthEnvelopedData_AES128GCM(t *testing.T) {
	kp := generateRSAKeyPair(t, 2048)
	cert := generateTestCertificate(t, kp)

	plaintext := []byte("Hello with AES-128-GCM!")

	ciphertext, err := Encrypt(context.Background(), plaintext, &EncryptOptions{
		Recipients:        []*x509.Certificate{cert},
		ContentEncryption: AES128GCM,
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Verify it's AuthEnvelopedData
	var ci ContentInfo
	_, err = asn1.Unmarshal(ciphertext, &ci)
	if err != nil {
		t.Fatalf("Failed to parse ContentInfo: %v", err)
	}
	if !ci.ContentType.Equal(OIDAuthEnvelopedData) {
		t.Errorf("Expected AuthEnvelopedData OID")
	}

	result, err := Decrypt(context.Background(), ciphertext, &DecryptOptions{
		PrivateKey:  kp.PrivateKey,
		Certificate: cert,
	})
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(result.Content, plaintext) {
		t.Errorf("Decrypted content mismatch")
	}
}

// TestF_EnvelopedData_AES256CBC tests that AES-CBC still produces EnvelopedData.
func TestF_EnvelopedData_AES256CBC(t *testing.T) {
	kp := generateRSAKeyPair(t, 2048)
	cert := generateTestCertificate(t, kp)

	plaintext := []byte("Hello with AES-256-CBC!")

	ciphertext, err := Encrypt(context.Background(), plaintext, &EncryptOptions{
		Recipients:        []*x509.Certificate{cert},
		ContentEncryption: AES256CBC,
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Verify it's EnvelopedData (NOT AuthEnvelopedData)
	var ci ContentInfo
	_, err = asn1.Unmarshal(ciphertext, &ci)
	if err != nil {
		t.Fatalf("Failed to parse ContentInfo: %v", err)
	}
	if !ci.ContentType.Equal(OIDEnvelopedData) {
		t.Errorf("Expected EnvelopedData OID for AES-CBC, got %v", ci.ContentType)
	}

	result, err := Decrypt(context.Background(), ciphertext, &DecryptOptions{
		PrivateKey:  kp.PrivateKey,
		Certificate: cert,
	})
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(result.Content, plaintext) {
		t.Errorf("Decrypted content mismatch")
	}
}

// TestF_AuthEnvelopedData_MultipleRecipients tests AuthEnvelopedData with multiple recipients.
func TestF_AuthEnvelopedData_MultipleRecipients(t *testing.T) {
	// RSA recipient
	rsaKP := generateRSAKeyPair(t, 2048)
	rsaCert := generateTestCertificate(t, rsaKP)

	// ECDH recipient
	ecKP := generateECDSAKeyPair(t, elliptic.P256())
	ecCert := generateTestCertificate(t, ecKP)

	// ML-KEM recipient
	kemKP := generateMLKEMKeyPair(t, pkicrypto.AlgMLKEM768)
	kemCert := generateMLKEMCertificate(t, kemKP)

	plaintext := []byte("Hello to all recipients with AuthEnvelopedData!")

	ciphertext, err := Encrypt(context.Background(), plaintext, &EncryptOptions{
		Recipients:        []*x509.Certificate{rsaCert, ecCert, kemCert},
		ContentEncryption: AES256GCM,
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Verify it's AuthEnvelopedData
	var ci ContentInfo
	_, err = asn1.Unmarshal(ciphertext, &ci)
	if err != nil {
		t.Fatalf("Failed to parse ContentInfo: %v", err)
	}
	if !ci.ContentType.Equal(OIDAuthEnvelopedData) {
		t.Errorf("Expected AuthEnvelopedData OID")
	}

	// Each recipient can decrypt
	for name, opts := range map[string]*DecryptOptions{
		"RSA":    {PrivateKey: rsaKP.PrivateKey, Certificate: rsaCert},
		"ECDH":   {PrivateKey: ecKP.PrivateKey, Certificate: ecCert},
		"ML-KEM": {PrivateKey: kemKP.PrivateKey, Certificate: kemCert},
	} {
		result, err := Decrypt(context.Background(), ciphertext, opts)
		if err != nil {
			t.Fatalf("%s decrypt failed: %v", name, err)
		}
		if !bytes.Equal(result.Content, plaintext) {
			t.Errorf("%s: decrypted content mismatch", name)
		}
	}
}

// TestF_AuthEnvelopedData_EmptyContent tests AuthEnvelopedData with empty content.
func TestF_AuthEnvelopedData_EmptyContent(t *testing.T) {
	kp := generateRSAKeyPair(t, 2048)
	cert := generateTestCertificate(t, kp)

	plaintext := []byte{}

	ciphertext, err := Encrypt(context.Background(), plaintext, &EncryptOptions{
		Recipients:        []*x509.Certificate{cert},
		ContentEncryption: AES256GCM,
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	result, err := Decrypt(context.Background(), ciphertext, &DecryptOptions{
		PrivateKey:  kp.PrivateKey,
		Certificate: cert,
	})
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if len(result.Content) != 0 {
		t.Errorf("Expected empty content, got %d bytes", len(result.Content))
	}
}

// TestF_AuthEnvelopedData_LargeContent tests AuthEnvelopedData with large content.
func TestF_AuthEnvelopedData_LargeContent(t *testing.T) {
	kp := generateRSAKeyPair(t, 2048)
	cert := generateTestCertificate(t, kp)

	// 100 KB content
	plaintext := make([]byte, 100*1024)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	ciphertext, err := Encrypt(context.Background(), plaintext, &EncryptOptions{
		Recipients:        []*x509.Certificate{cert},
		ContentEncryption: AES256GCM,
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	result, err := Decrypt(context.Background(), ciphertext, &DecryptOptions{
		PrivateKey:  kp.PrivateKey,
		Certificate: cert,
	})
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(result.Content, plaintext) {
		t.Errorf("Content mismatch for large content")
	}
}

// =============================================================================
// Unit Tests: Decrypt Helper Functions
// =============================================================================

// TestU_GetKDFHashFunc tests the getKDFHashFunc function.
func TestU_GetKDFHashFunc(t *testing.T) {
	tests := []struct {
		name    string
		oid     asn1.ObjectIdentifier
		wantErr bool
	}{
		{"SHA1 KDF", OIDECDHStdSHA1KDF, false},
		{"SHA256 KDF", OIDECDHStdSHA256KDF, false},
		{"SHA384 KDF", OIDECDHStdSHA384KDF, false},
		{"SHA512 KDF", OIDECDHStdSHA512KDF, false},
		{"AES Wrap 256", OIDAESWrap256, false},
		{"AES Wrap 128", OIDAESWrap128, false},
		{"Unsupported", asn1.ObjectIdentifier{1, 2, 3, 4, 5}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hashFunc, err := getKDFHashFunc(tt.oid)
			if (err != nil) != tt.wantErr {
				t.Errorf("getKDFHashFunc() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && hashFunc == nil {
				t.Error("getKDFHashFunc() returned nil hash function")
			}
		})
	}
}

// TestU_GetWrapAlgBytes tests the getWrapAlgBytes function.
func TestU_GetWrapAlgBytes(t *testing.T) {
	// Test with parameters present
	t.Run("WithParameters", func(t *testing.T) {
		params := []byte{0x05, 0x00} // NULL
		kea := pkix.AlgorithmIdentifier{
			Algorithm:  OIDAESWrap256,
			Parameters: asn1.RawValue{FullBytes: params},
		}
		result := getWrapAlgBytes(kea)
		if !bytes.Equal(result, params) {
			t.Errorf("getWrapAlgBytes() = %x, want %x", result, params)
		}
	})

	// Test without parameters (default path)
	t.Run("WithoutParameters", func(t *testing.T) {
		kea := pkix.AlgorithmIdentifier{
			Algorithm: OIDAESWrap256,
		}
		result := getWrapAlgBytes(kea)
		if len(result) == 0 {
			t.Error("getWrapAlgBytes() returned empty bytes")
		}
	})
}

// TestU_DecryptContent_UnsupportedAlgorithm tests decryptContent with unsupported algorithm.
func TestU_DecryptContent_UnsupportedAlgorithm(t *testing.T) {
	eci := &EncryptedContentInfo{
		ContentType: OIDData,
		ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6}, // Unknown OID
		},
		EncryptedContent: []byte{0x01, 0x02, 0x03},
	}

	_, err := decryptContent(eci, make([]byte, 32))
	if err == nil {
		t.Error("decryptContent() should fail with unsupported algorithm")
	}
}

// TestU_FindMatchingRecipientKey_NoMatch tests findMatchingRecipientKey with no match.
func TestU_FindMatchingRecipientKey_NoMatch(t *testing.T) {
	kp := generateRSAKeyPair(t, 2048)
	cert := generateTestCertificate(t, kp)

	// Create a recipient with different issuer/serial
	reks := []RecipientEncryptedKey{
		{
			RID: KeyAgreeRecipientIdentifier{
				IssuerAndSerial: &IssuerAndSerialNumber{
					Issuer:       asn1.RawValue{FullBytes: []byte{0x30, 0x00}},
					SerialNumber: big.NewInt(99999),
				},
			},
			EncryptedKey: []byte{0x01, 0x02, 0x03},
		},
	}

	opts := &DecryptOptions{
		Certificate: cert,
	}

	_, err := findMatchingRecipientKey(reks, opts)
	if err == nil {
		t.Error("findMatchingRecipientKey() should fail with no match")
	}
}

// TestU_FindMatchingRecipientKey_Match tests findMatchingRecipientKey with a match.
func TestU_FindMatchingRecipientKey_Match(t *testing.T) {
	kp := generateRSAKeyPair(t, 2048)
	cert := generateTestCertificate(t, kp)

	expectedKey := []byte{0xaa, 0xbb, 0xcc}
	reks := []RecipientEncryptedKey{
		{
			RID: KeyAgreeRecipientIdentifier{
				IssuerAndSerial: &IssuerAndSerialNumber{
					Issuer:       asn1.RawValue{FullBytes: cert.RawIssuer},
					SerialNumber: cert.SerialNumber,
				},
			},
			EncryptedKey: expectedKey,
		},
	}

	opts := &DecryptOptions{
		Certificate: cert,
	}

	key, err := findMatchingRecipientKey(reks, opts)
	if err != nil {
		t.Fatalf("findMatchingRecipientKey() error = %v", err)
	}

	if !bytes.Equal(key, expectedKey) {
		t.Errorf("findMatchingRecipientKey() = %x, want %x", key, expectedKey)
	}
}

// TestU_MatchesIssuerAndSerial tests the matchesIssuerAndSerial function.
func TestU_MatchesIssuerAndSerial(t *testing.T) {
	kp := generateRSAKeyPair(t, 2048)
	cert := generateTestCertificate(t, kp)

	// Test matching
	t.Run("Matching", func(t *testing.T) {
		ias := &IssuerAndSerialNumber{
			Issuer:       asn1.RawValue{FullBytes: cert.RawIssuer},
			SerialNumber: cert.SerialNumber,
		}
		if !matchesIssuerAndSerial(cert, ias) {
			t.Error("matchesIssuerAndSerial() should return true for matching cert")
		}
	})

	// Test non-matching serial
	t.Run("DifferentSerial", func(t *testing.T) {
		ias := &IssuerAndSerialNumber{
			Issuer:       asn1.RawValue{FullBytes: cert.RawIssuer},
			SerialNumber: big.NewInt(99999),
		}
		if matchesIssuerAndSerial(cert, ias) {
			t.Error("matchesIssuerAndSerial() should return false for different serial")
		}
	})

	// Test non-matching issuer
	t.Run("DifferentIssuer", func(t *testing.T) {
		ias := &IssuerAndSerialNumber{
			Issuer:       asn1.RawValue{FullBytes: []byte{0x30, 0x00}},
			SerialNumber: cert.SerialNumber,
		}
		if matchesIssuerAndSerial(cert, ias) {
			t.Error("matchesIssuerAndSerial() should return false for different issuer")
		}
	})
}

// TestU_ParseECPublicKey tests the parseECPublicKey function.
func TestU_ParseECPublicKey(t *testing.T) {
	// Test with valid EC point
	t.Run("ValidPoint", func(t *testing.T) {
		kp := generateECDSAKeyPair(t, elliptic.P256())
		ecPub := kp.PublicKey.(*ecdsa.PublicKey)
		//nolint:staticcheck // elliptic.Marshal is deprecated but needed for testing parseECPublicKey
		data := elliptic.Marshal(elliptic.P256(), ecPub.X, ecPub.Y)

		pub, err := parseECPublicKey(data, elliptic.P256())
		if err != nil {
			t.Fatalf("parseECPublicKey() error = %v", err)
		}
		if pub.X.Cmp(ecPub.X) != 0 || pub.Y.Cmp(ecPub.Y) != 0 {
			t.Error("parseECPublicKey() returned different coordinates")
		}
	})

	// Test with invalid point
	t.Run("InvalidPoint", func(t *testing.T) {
		_, err := parseECPublicKey([]byte{0x04, 0x00, 0x00}, elliptic.P256())
		if err == nil {
			t.Error("parseECPublicKey() should fail with invalid point")
		}
	})
}

// TestU_DecryptAESCBC_InvalidPadding tests decryptAESCBC with invalid PKCS#7 padding.
func TestU_DecryptAESCBC_InvalidPadding(t *testing.T) {
	// Create a valid CEK
	cek := make([]byte, 32)
	for i := range cek {
		cek[i] = byte(i)
	}

	iv := make([]byte, 16)
	ivBytes, _ := asn1.Marshal(iv)

	// Create content that will have invalid padding after decryption
	// This is 16 bytes (one block) of zeros - after decryption it will likely have invalid padding
	invalidCiphertext := make([]byte, 16)

	eci := &EncryptedContentInfo{
		ContentType: OIDData,
		ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm:  OIDAES256CBC,
			Parameters: asn1.RawValue{FullBytes: ivBytes},
		},
		EncryptedContent: invalidCiphertext,
	}

	_, err := decryptAESCBC(eci, cek)
	if err == nil {
		t.Error("decryptAESCBC() should fail with invalid padding")
	}
}

// TestU_DecryptAESCBC_InvalidBlockSize tests decryptAESCBC with non-block-aligned ciphertext.
func TestU_DecryptAESCBC_InvalidBlockSize(t *testing.T) {
	cek := make([]byte, 32)
	iv := make([]byte, 16)
	ivBytes, _ := asn1.Marshal(iv)

	// Ciphertext not a multiple of block size
	eci := &EncryptedContentInfo{
		ContentType: OIDData,
		ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm:  OIDAES256CBC,
			Parameters: asn1.RawValue{FullBytes: ivBytes},
		},
		EncryptedContent: make([]byte, 17), // Not 16
	}

	_, err := decryptAESCBC(eci, cek)
	if err == nil {
		t.Error("decryptAESCBC() should fail with invalid block size")
	}
}

// TestU_DecryptAESCBC_InvalidIVLength tests decryptAESCBC with wrong IV length.
func TestU_DecryptAESCBC_InvalidIVLength(t *testing.T) {
	cek := make([]byte, 32)
	iv := make([]byte, 8) // Wrong size - should be 16
	ivBytes, _ := asn1.Marshal(iv)

	eci := &EncryptedContentInfo{
		ContentType: OIDData,
		ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm:  OIDAES256CBC,
			Parameters: asn1.RawValue{FullBytes: ivBytes},
		},
		EncryptedContent: make([]byte, 16),
	}

	_, err := decryptAESCBC(eci, cek)
	if err == nil {
		t.Error("decryptAESCBC() should fail with invalid IV length")
	}
}

// TestU_DecryptAESGCM_InvalidParams tests decryptAESGCM with invalid GCM parameters.
func TestU_DecryptAESGCM_InvalidParams(t *testing.T) {
	cek := make([]byte, 32)

	// Invalid parameters (not a valid GCMParameters encoding)
	eci := &EncryptedContentInfo{
		ContentType: OIDData,
		ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm:  OIDAES256GCM,
			Parameters: asn1.RawValue{FullBytes: []byte{0x01, 0x02}}, // Invalid ASN.1
		},
		EncryptedContent: make([]byte, 16),
	}

	_, err := decryptAESGCM(eci, cek)
	if err == nil {
		t.Error("decryptAESGCM() should fail with invalid parameters")
	}
}

// TestU_DecryptAESGCM_InvalidCiphertext tests decryptAESGCM with invalid ciphertext.
func TestU_DecryptAESGCM_InvalidCiphertext(t *testing.T) {
	cek := make([]byte, 32)

	// Valid GCMParameters
	gcmParams := GCMParameters{
		Nonce:  make([]byte, 12),
		ICVLen: 16,
	}
	paramsBytes, _ := asn1.Marshal(gcmParams)

	eci := &EncryptedContentInfo{
		ContentType: OIDData,
		ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm:  OIDAES256GCM,
			Parameters: asn1.RawValue{FullBytes: paramsBytes},
		},
		EncryptedContent: []byte{0x01, 0x02, 0x03}, // Invalid/tampered ciphertext
	}

	_, err := decryptAESGCM(eci, cek)
	if err == nil {
		t.Error("decryptAESGCM() should fail with invalid ciphertext")
	}
}

// TestU_DecryptAESGCM_InvalidKeyLength tests decryptAESGCM with wrong key length.
func TestU_DecryptAESGCM_InvalidKeyLength(t *testing.T) {
	cek := make([]byte, 15) // Invalid key length (not 16, 24, or 32)

	gcmParams := GCMParameters{
		Nonce:  make([]byte, 12),
		ICVLen: 16,
	}
	paramsBytes, _ := asn1.Marshal(gcmParams)

	eci := &EncryptedContentInfo{
		ContentType: OIDData,
		ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm:  OIDAES256GCM,
			Parameters: asn1.RawValue{FullBytes: paramsBytes},
		},
		EncryptedContent: make([]byte, 32),
	}

	_, err := decryptAESGCM(eci, cek)
	if err == nil {
		t.Error("decryptAESGCM() should fail with invalid key length")
	}
}

// =============================================================================
// Unit Tests: Encryption Helper Functions
// =============================================================================

// TestU_EncryptAESGCM tests the encryptAESGCM function directly.
func TestU_EncryptAESGCM(t *testing.T) {
	tests := []struct {
		name    string
		cekSize int
		wantOID asn1.ObjectIdentifier
	}{
		{"AES-256-GCM", 32, OIDAES256GCM},
		{"AES-128-GCM", 16, OIDAES128GCM},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cek := make([]byte, tt.cekSize)
			for i := range cek {
				cek[i] = byte(i)
			}
			data := []byte("test data for AES-GCM encryption")

			ciphertext, algID, err := encryptAESGCM(data, cek)
			if err != nil {
				t.Fatalf("encryptAESGCM() error = %v", err)
			}

			if !algID.Algorithm.Equal(tt.wantOID) {
				t.Errorf("encryptAESGCM() OID = %v, want %v", algID.Algorithm, tt.wantOID)
			}

			// Ciphertext should be longer than plaintext (includes nonce and tag)
			if len(ciphertext) <= len(data) {
				t.Errorf("encryptAESGCM() ciphertext length %d should be > plaintext length %d", len(ciphertext), len(data))
			}

			// Parse GCM parameters
			var params GCMParameters
			_, err = asn1.Unmarshal(algID.Parameters.FullBytes, &params)
			if err != nil {
				t.Fatalf("Failed to parse GCM parameters: %v", err)
			}

			// Nonce should be 12 bytes (GCM standard)
			if len(params.Nonce) != 12 {
				t.Errorf("encryptAESGCM() nonce length = %d, want 12", len(params.Nonce))
			}

			// Tag length should be 16 bytes (128 bits)
			if params.ICVLen != 16 {
				t.Errorf("encryptAESGCM() tag length = %d, want 16", params.ICVLen)
			}
		})
	}
}

// TestU_EncryptAESGCM_InvalidKeyLength tests encryptAESGCM with invalid key length.
func TestU_EncryptAESGCM_InvalidKeyLength(t *testing.T) {
	// Invalid key size (15 bytes)
	cek := make([]byte, 15)
	data := []byte("test data")

	_, _, err := encryptAESGCM(data, cek)
	if err == nil {
		t.Error("encryptAESGCM() should fail with invalid key length")
	}
}

// TestU_EncryptAESGCMAuth tests the encryptAESGCMAuth function.
func TestU_EncryptAESGCMAuth(t *testing.T) {
	tests := []struct {
		name    string
		alg     ContentEncryptionAlgorithm
		cekSize int
		wantOID asn1.ObjectIdentifier
	}{
		{"AES-256-GCM", AES256GCM, 32, OIDAES256GCM},
		{"AES-128-GCM", AES128GCM, 16, OIDAES128GCM},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cek := make([]byte, tt.cekSize)
			for i := range cek {
				cek[i] = byte(i)
			}
			data := []byte("test data for AuthEnvelopedData")

			ciphertext, tag, algID, err := encryptAESGCMAuth(data, cek, tt.alg)
			if err != nil {
				t.Fatalf("encryptAESGCMAuth() error = %v", err)
			}

			if !algID.Algorithm.Equal(tt.wantOID) {
				t.Errorf("encryptAESGCMAuth() OID = %v, want %v", algID.Algorithm, tt.wantOID)
			}

			// Tag should be 16 bytes
			if len(tag) != 16 {
				t.Errorf("encryptAESGCMAuth() tag length = %d, want 16", len(tag))
			}

			// Ciphertext should equal plaintext length (tag is separate)
			if len(ciphertext) != len(data) {
				t.Errorf("encryptAESGCMAuth() ciphertext length = %d, want %d", len(ciphertext), len(data))
			}
		})
	}
}

// TestU_EncryptAESCBC tests the encryptAESCBC function.
func TestU_EncryptAESCBC(t *testing.T) {
	cek := make([]byte, 32) // AES-256
	for i := range cek {
		cek[i] = byte(i)
	}
	data := []byte("test data for AES-CBC encryption")

	ciphertext, algID, err := encryptAESCBC(data, cek)
	if err != nil {
		t.Fatalf("encryptAESCBC() error = %v", err)
	}

	if !algID.Algorithm.Equal(OIDAES256CBC) {
		t.Errorf("encryptAESCBC() OID = %v, want %v", algID.Algorithm, OIDAES256CBC)
	}

	// Ciphertext should be block-aligned (PKCS#7 padding)
	if len(ciphertext)%16 != 0 {
		t.Errorf("encryptAESCBC() ciphertext length %d is not block-aligned", len(ciphertext))
	}

	// Ciphertext should be at least as long as plaintext
	if len(ciphertext) < len(data) {
		t.Errorf("encryptAESCBC() ciphertext shorter than plaintext")
	}

	// Parse IV from parameters
	var iv []byte
	_, err = asn1.Unmarshal(algID.Parameters.FullBytes, &iv)
	if err != nil {
		t.Fatalf("Failed to parse IV: %v", err)
	}

	// IV should be 16 bytes (AES block size)
	if len(iv) != 16 {
		t.Errorf("encryptAESCBC() IV length = %d, want 16", len(iv))
	}
}

// TestU_EncryptContent tests the encryptContent routing function.
func TestU_EncryptContent(t *testing.T) {
	data := []byte("test content")

	// Note: The OID in encryptAESGCM is determined by CEK size, not the ContentEncryptionAlgorithm.
	// A 32-byte CEK always produces AES-256-GCM OID; a 16-byte CEK produces AES-128-GCM OID.
	tests := []struct {
		name    string
		alg     ContentEncryptionAlgorithm
		cekSize int
		wantOID asn1.ObjectIdentifier
	}{
		{"AES256GCM with 32-byte key", AES256GCM, 32, OIDAES256GCM},
		{"AES128GCM with 16-byte key", AES128GCM, 16, OIDAES128GCM},
		{"AES256CBC with 32-byte key", AES256CBC, 32, OIDAES256CBC},
		{"Default (unknown) with 32-byte key", ContentEncryptionAlgorithm(99), 32, OIDAES256GCM}, // defaults to GCM
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cek := make([]byte, tt.cekSize)
			for i := range cek {
				cek[i] = byte(i)
			}

			ciphertext, algID, err := encryptContent(data, cek, tt.alg)
			if err != nil {
				t.Fatalf("encryptContent() error = %v", err)
			}

			if !algID.Algorithm.Equal(tt.wantOID) {
				t.Errorf("encryptContent() OID = %v, want %v", algID.Algorithm, tt.wantOID)
			}

			if len(ciphertext) == 0 {
				t.Error("encryptContent() returned empty ciphertext")
			}
		})
	}
}

// =============================================================================
// Unit Tests: ML-KEM Helper Functions
// =============================================================================

// TestU_IsMLKEMCert tests the isMLKEMCert function.
func TestU_IsMLKEMCert(t *testing.T) {
	// ML-KEM certificate
	t.Run("MLKEM512", func(t *testing.T) {
		kemKP := generateMLKEMKeyPair(t, pkicrypto.AlgMLKEM512)
		cert := generateMLKEMCertificate(t, kemKP)
		if !isMLKEMCert(cert) {
			t.Error("isMLKEMCert() should return true for ML-KEM-512 cert")
		}
	})

	t.Run("MLKEM768", func(t *testing.T) {
		kemKP := generateMLKEMKeyPair(t, pkicrypto.AlgMLKEM768)
		cert := generateMLKEMCertificate(t, kemKP)
		if !isMLKEMCert(cert) {
			t.Error("isMLKEMCert() should return true for ML-KEM-768 cert")
		}
	})

	t.Run("MLKEM1024", func(t *testing.T) {
		kemKP := generateMLKEMKeyPair(t, pkicrypto.AlgMLKEM1024)
		cert := generateMLKEMCertificate(t, kemKP)
		if !isMLKEMCert(cert) {
			t.Error("isMLKEMCert() should return true for ML-KEM-1024 cert")
		}
	})

	// Non-ML-KEM certificates
	t.Run("RSA", func(t *testing.T) {
		rsaKP := generateRSAKeyPair(t, 2048)
		cert := generateTestCertificate(t, rsaKP)
		if isMLKEMCert(cert) {
			t.Error("isMLKEMCert() should return false for RSA cert")
		}
	})

	t.Run("ECDSA", func(t *testing.T) {
		ecKP := generateECDSAKeyPair(t, elliptic.P256())
		cert := generateTestCertificate(t, ecKP)
		if isMLKEMCert(cert) {
			t.Error("isMLKEMCert() should return false for ECDSA cert")
		}
	})
}

// TestU_GetMLKEMAlgorithm tests the getMLKEMAlgorithm function.
func TestU_GetMLKEMAlgorithm(t *testing.T) {
	tests := []struct {
		name    string
		algID   pkicrypto.AlgorithmID
		wantAlg pkicrypto.AlgorithmID
	}{
		{"MLKEM512", pkicrypto.AlgMLKEM512, pkicrypto.AlgMLKEM512},
		{"MLKEM768", pkicrypto.AlgMLKEM768, pkicrypto.AlgMLKEM768},
		{"MLKEM1024", pkicrypto.AlgMLKEM1024, pkicrypto.AlgMLKEM1024},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kemKP := generateMLKEMKeyPair(t, tt.algID)
			cert := generateMLKEMCertificate(t, kemKP)

			alg, err := getMLKEMAlgorithm(cert)
			if err != nil {
				t.Fatalf("getMLKEMAlgorithm() error = %v", err)
			}

			if alg != tt.wantAlg {
				t.Errorf("getMLKEMAlgorithm() = %v, want %v", alg, tt.wantAlg)
			}
		})
	}
}

// TestU_GetMLKEMAlgorithm_NonMLKEM tests getMLKEMAlgorithm with non-ML-KEM cert.
func TestU_GetMLKEMAlgorithm_NonMLKEM(t *testing.T) {
	rsaKP := generateRSAKeyPair(t, 2048)
	cert := generateTestCertificate(t, rsaKP)

	_, err := getMLKEMAlgorithm(cert)
	if err == nil {
		t.Error("getMLKEMAlgorithm() should fail for non-ML-KEM cert")
	}
}

// TestU_GetMLKEMPublicKey tests the getMLKEMPublicKey function.
func TestU_GetMLKEMPublicKey(t *testing.T) {
	tests := []pkicrypto.AlgorithmID{
		pkicrypto.AlgMLKEM512,
		pkicrypto.AlgMLKEM768,
		pkicrypto.AlgMLKEM1024,
	}

	for _, algID := range tests {
		t.Run(string(algID), func(t *testing.T) {
			kemKP := generateMLKEMKeyPair(t, algID)
			cert := generateMLKEMCertificate(t, kemKP)

			pub, alg, err := getMLKEMPublicKey(cert)
			if err != nil {
				t.Fatalf("getMLKEMPublicKey() error = %v", err)
			}

			if pub == nil {
				t.Error("getMLKEMPublicKey() returned nil public key")
			}

			if alg != algID {
				t.Errorf("getMLKEMPublicKey() algorithm = %v, want %v", alg, algID)
			}
		})
	}
}

// =============================================================================
// Unit Tests: ECDH Helper Functions
// =============================================================================

// TestU_ECDHSharedSecret tests the ecdhSharedSecret function.
func TestU_ECDHSharedSecret(t *testing.T) {
	curves := []elliptic.Curve{
		elliptic.P256(),
		elliptic.P384(),
	}

	for _, curve := range curves {
		t.Run(curve.Params().Name, func(t *testing.T) {
			// Generate two key pairs
			kp1 := generateECDSAKeyPair(t, curve)
			kp2 := generateECDSAKeyPair(t, curve)

			priv1 := kp1.PrivateKey.(*ecdsa.PrivateKey)
			pub1 := kp1.PublicKey.(*ecdsa.PublicKey)
			priv2 := kp2.PrivateKey.(*ecdsa.PrivateKey)
			pub2 := kp2.PublicKey.(*ecdsa.PublicKey)

			// Compute shared secrets both ways
			secret1, err := ecdhSharedSecret(priv1, pub2)
			if err != nil {
				t.Fatalf("ecdhSharedSecret(priv1, pub2) error = %v", err)
			}

			secret2, err := ecdhSharedSecret(priv2, pub1)
			if err != nil {
				t.Fatalf("ecdhSharedSecret(priv2, pub1) error = %v", err)
			}

			// Shared secrets should be equal
			if !bytes.Equal(secret1, secret2) {
				t.Error("ECDH shared secrets don't match")
			}

			// Shared secret should be non-empty
			if len(secret1) == 0 {
				t.Error("ECDH shared secret is empty")
			}
		})
	}
}

// TestU_EcdsaToECDH tests the ecdsaToECDH conversion function.
func TestU_EcdsaToECDH(t *testing.T) {
	tests := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P256", elliptic.P256()},
		{"P384", elliptic.P384()},
		{"P521", elliptic.P521()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kp := generateECDSAKeyPair(t, tt.curve)
			ecdsaPub := kp.PublicKey.(*ecdsa.PublicKey)

			ecdhPub, err := ecdsaToECDH(ecdsaPub)
			if err != nil {
				t.Fatalf("ecdsaToECDH() error = %v", err)
			}

			if ecdhPub == nil {
				t.Error("ecdsaToECDH() returned nil")
			}
		})
	}
}

// TestU_ECMarshalUncompressed tests the ecMarshalUncompressed function.
func TestU_ECMarshalUncompressed(t *testing.T) {
	curves := []elliptic.Curve{
		elliptic.P256(),
		elliptic.P384(),
		elliptic.P521(),
	}

	for _, curve := range curves {
		t.Run(curve.Params().Name, func(t *testing.T) {
			kp := generateECDSAKeyPair(t, curve)
			pub := kp.PublicKey.(*ecdsa.PublicKey)

			result := ecMarshalUncompressed(pub)

			// First byte should be 0x04 (uncompressed point)
			if result[0] != 0x04 {
				t.Errorf("ecMarshalUncompressed() first byte = %x, want 0x04", result[0])
			}

			// Length should be 1 + 2 * byteLen
			byteLen := (curve.Params().BitSize + 7) / 8
			expectedLen := 1 + 2*byteLen
			if len(result) != expectedLen {
				t.Errorf("ecMarshalUncompressed() length = %d, want %d", len(result), expectedLen)
			}
		})
	}
}

// =============================================================================
// Unit Tests: KDF Functions
// =============================================================================

// TestU_ANSIX963KDF tests the ansix963KDF function.
func TestU_ANSIX963KDF(t *testing.T) {
	sharedSecret := []byte("shared secret for testing KDF")
	sharedInfo := []byte("additional shared info")

	tests := []struct {
		name    string
		keySize int
	}{
		{"16 bytes", 16},
		{"32 bytes", 32},
		{"64 bytes", 64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := ansix963KDF(sharedSecret, tt.keySize, sharedInfo, sha256.New)
			if err != nil {
				t.Fatalf("ansix963KDF() error = %v", err)
			}

			if len(key) != tt.keySize {
				t.Errorf("ansix963KDF() key length = %d, want %d", len(key), tt.keySize)
			}
		})
	}
}

// TestU_ANSIX963KDFSHA256 tests the ansix963KDFSHA256 wrapper.
func TestU_ANSIX963KDFSHA256(t *testing.T) {
	sharedSecret := []byte("shared secret")
	sharedInfo := []byte("info")

	key, err := ansix963KDFSHA256(sharedSecret, 32, sharedInfo)
	if err != nil {
		t.Fatalf("ansix963KDFSHA256() error = %v", err)
	}

	if len(key) != 32 {
		t.Errorf("ansix963KDFSHA256() key length = %d, want 32", len(key))
	}
}

// TestU_ANSIX963KDF_Deterministic tests KDF is deterministic.
func TestU_ANSIX963KDF_Deterministic(t *testing.T) {
	sharedSecret := []byte("shared secret")
	sharedInfo := []byte("info")

	key1, _ := ansix963KDFSHA256(sharedSecret, 32, sharedInfo)
	key2, _ := ansix963KDFSHA256(sharedSecret, 32, sharedInfo)

	if !bytes.Equal(key1, key2) {
		t.Error("ansix963KDFSHA256() is not deterministic")
	}
}

// TestU_DeriveKEK tests the deriveKEK function (HKDF).
func TestU_DeriveKEK(t *testing.T) {
	sharedSecret := []byte("shared secret from KEM")
	info := []byte("KDF info parameter")

	tests := []struct {
		name    string
		keySize int
	}{
		{"16 bytes", 16},
		{"32 bytes", 32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kek, err := deriveKEK(sharedSecret, tt.keySize, info)
			if err != nil {
				t.Fatalf("deriveKEK() error = %v", err)
			}

			if len(kek) != tt.keySize {
				t.Errorf("deriveKEK() key length = %d, want %d", len(kek), tt.keySize)
			}
		})
	}
}

// TestU_DeriveKEK_Deterministic tests HKDF is deterministic.
func TestU_DeriveKEK_Deterministic(t *testing.T) {
	sharedSecret := []byte("shared secret")
	info := []byte("info")

	kek1, _ := deriveKEK(sharedSecret, 32, info)
	kek2, _ := deriveKEK(sharedSecret, 32, info)

	if !bytes.Equal(kek1, kek2) {
		t.Error("deriveKEK() is not deterministic")
	}
}

// =============================================================================
// Unit Tests: SharedInfo Building Functions
// =============================================================================

// TestU_BuildECCCMSSharedInfo tests the buildECCCMSSharedInfo function.
func TestU_BuildECCCMSSharedInfo(t *testing.T) {
	tests := []struct {
		name      string
		wrapOID   asn1.ObjectIdentifier
		keyBits   int
		wantError bool
	}{
		{"AES-256 Wrap", OIDAESWrap256, 256, false},
		{"AES-128 Wrap", OIDAESWrap128, 128, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sharedInfo, err := buildECCCMSSharedInfo(tt.wrapOID, tt.keyBits)
			if (err != nil) != tt.wantError {
				t.Errorf("buildECCCMSSharedInfo() error = %v, wantError %v", err, tt.wantError)
				return
			}

			if !tt.wantError && len(sharedInfo) == 0 {
				t.Error("buildECCCMSSharedInfo() returned empty sharedInfo")
			}
		})
	}
}

// TestU_BuildKEMKDFInfo tests the buildKEMKDFInfo function.
func TestU_BuildKEMKDFInfo(t *testing.T) {
	wrapAlg := pkix.AlgorithmIdentifier{Algorithm: OIDAESWrap256}

	info, err := buildKEMKDFInfo(wrapAlg, 32, nil)
	if err != nil {
		t.Fatalf("buildKEMKDFInfo() error = %v", err)
	}

	if len(info) == 0 {
		t.Error("buildKEMKDFInfo() returned empty info")
	}

	// Should be valid ASN.1
	var parsed CMSORIforKEMOtherInfo
	_, err = asn1.Unmarshal(info, &parsed)
	if err != nil {
		t.Errorf("buildKEMKDFInfo() produced invalid ASN.1: %v", err)
	}

	if parsed.KEKLength != 32 {
		t.Errorf("buildKEMKDFInfo() KEKLength = %d, want 32", parsed.KEKLength)
	}
}

// =============================================================================
// Unit Tests: ASN.1 Helper Functions
// =============================================================================

// TestU_ExtractASN1Content tests the extractASN1Content function.
func TestU_ExtractASN1Content(t *testing.T) {
	tests := []struct {
		name        string
		der         []byte
		wantContent []byte
		wantError   bool
	}{
		{
			name:        "Short form length",
			der:         []byte{0x30, 0x03, 0x01, 0x02, 0x03},
			wantContent: []byte{0x01, 0x02, 0x03},
			wantError:   false,
		},
		{
			name:        "Long form 1 byte",
			der:         append([]byte{0x30, 0x81, 0x80}, make([]byte, 128)...),
			wantContent: make([]byte, 128),
			wantError:   false,
		},
		{
			name:      "Too short",
			der:       []byte{0x30},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content, err := extractASN1Content(tt.der)
			if (err != nil) != tt.wantError {
				t.Errorf("extractASN1Content() error = %v, wantError %v", err, tt.wantError)
				return
			}

			if !tt.wantError && !bytes.Equal(content, tt.wantContent) {
				t.Errorf("extractASN1Content() = %x, want %x", content, tt.wantContent)
			}
		})
	}
}

// TestU_ExtractASN1Content_LongFormLength tests long form length encoding.
func TestU_ExtractASN1Content_LongFormLength(t *testing.T) {
	// Create DER with 2-byte length (0x82 prefix)
	content := make([]byte, 300)
	for i := range content {
		content[i] = byte(i)
	}
	der := make([]byte, 0, 4+len(content))
	der = append(der, 0x30)                    // SEQUENCE tag
	der = append(der, 0x82)                    // Long form, 2 bytes
	der = append(der, byte(len(content)>>8))   // High byte of length
	der = append(der, byte(len(content)&0xff)) // Low byte of length
	der = append(der, content...)

	extracted, err := extractASN1Content(der)
	if err != nil {
		t.Fatalf("extractASN1Content() error = %v", err)
	}

	if !bytes.Equal(extracted, content) {
		t.Error("extractASN1Content() content mismatch for long form length")
	}
}

// TestU_ExtractASN1Content_TruncatedLength tests truncated length field.
func TestU_ExtractASN1Content_TruncatedLength(t *testing.T) {
	// Long form length but truncated
	der := []byte{0x30, 0x82, 0x01} // Indicates 2 bytes follow but only 1 present

	_, err := extractASN1Content(der)
	if err == nil {
		t.Error("extractASN1Content() should fail with truncated length field")
	}
}
