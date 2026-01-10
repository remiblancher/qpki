package cms

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"testing"

	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
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
