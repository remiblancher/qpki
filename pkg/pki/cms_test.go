package pki

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// =============================================================================
// CMSParseSignedData Tests
// =============================================================================

func TestU_CMSParseSignedData(t *testing.T) {
	t.Run("[Unit] CMSParseSignedData: invalid data", func(t *testing.T) {
		_, err := CMSParseSignedData([]byte("not valid CMS data"))
		if err == nil {
			t.Error("CMSParseSignedData() should fail for invalid data")
		}
	})

	t.Run("[Unit] CMSParseSignedData: empty data", func(t *testing.T) {
		_, err := CMSParseSignedData([]byte{})
		if err == nil {
			t.Error("CMSParseSignedData() should fail for empty data")
		}
	})

	t.Run("[Unit] CMSParseSignedData: nil data", func(t *testing.T) {
		_, err := CMSParseSignedData(nil)
		if err == nil {
			t.Error("CMSParseSignedData() should fail for nil data")
		}
	})
}

// =============================================================================
// CMSParseEnvelopedData Tests
// =============================================================================

func TestU_CMSParseEnvelopedData(t *testing.T) {
	t.Run("[Unit] CMSParseEnvelopedData: invalid data", func(t *testing.T) {
		_, err := CMSParseEnvelopedData([]byte("not valid CMS data"))
		if err == nil {
			t.Error("CMSParseEnvelopedData() should fail for invalid data")
		}
	})

	t.Run("[Unit] CMSParseEnvelopedData: empty data", func(t *testing.T) {
		_, err := CMSParseEnvelopedData([]byte{})
		if err == nil {
			t.Error("CMSParseEnvelopedData() should fail for empty data")
		}
	})
}

// =============================================================================
// CMSParseContentInfo Tests
// =============================================================================

func TestU_CMSParseContentInfo(t *testing.T) {
	t.Run("[Unit] CMSParseContentInfo: invalid data", func(t *testing.T) {
		_, err := CMSParseContentInfo([]byte("not valid ASN.1 data"))
		if err == nil {
			t.Error("CMSParseContentInfo() should fail for invalid data")
		}
	})

	t.Run("[Unit] CMSParseContentInfo: empty data", func(t *testing.T) {
		_, err := CMSParseContentInfo([]byte{})
		if err == nil {
			t.Error("CMSParseContentInfo() should fail for empty data")
		}
	})
}

// =============================================================================
// Type Aliases Tests
// =============================================================================

func TestU_CMSTypes(t *testing.T) {
	// Test that type aliases are properly defined by checking
	// that we can create instances of the types

	t.Run("[Unit] CMSTypes: CMSSignerConfig can be instantiated", func(t *testing.T) {
		cfg := &CMSSignerConfig{}
		_ = cfg // verify it compiles
	})

	t.Run("[Unit] CMSTypes: CMSEncryptOptions can be instantiated", func(t *testing.T) {
		opts := &CMSEncryptOptions{}
		_ = opts // verify it compiles
	})

	t.Run("[Unit] CMSTypes: CMSDecryptOptions can be instantiated", func(t *testing.T) {
		opts := &CMSDecryptOptions{}
		_ = opts // verify it compiles
	})

	t.Run("[Unit] CMSTypes: CMSVerifyConfig can be instantiated", func(t *testing.T) {
		cfg := &CMSVerifyConfig{}
		_ = cfg // verify it compiles
	})
}

// =============================================================================
// CMS Test Helpers
// =============================================================================

// generateCMSTestKeyPair generates an ECDSA key pair for CMS testing.
func generateCMSTestKeyPair(t *testing.T) (crypto.Signer, crypto.PublicKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}
	return priv, &priv.PublicKey
}

// generateCMSTestCertificate creates a self-signed certificate for CMS testing.
func generateCMSTestCertificate(t *testing.T, signer crypto.Signer, pubKey crypto.PublicKey) *x509.Certificate {
	t.Helper()

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("Failed to generate serial number: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "CMS Test Certificate",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pubKey, signer)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

// =============================================================================
// CMSSign Tests
// =============================================================================

func TestU_CMSSign(t *testing.T) {
	t.Run("[Unit] CMSSign: signs content successfully", func(t *testing.T) {
		signer, pubKey := generateCMSTestKeyPair(t)
		cert := generateCMSTestCertificate(t, signer, pubKey)

		content := []byte("Hello, CMS World!")
		config := &CMSSignerConfig{
			Certificate:  cert,
			Signer:       signer,
			DigestAlg:    crypto.SHA256,
			IncludeCerts: true,
		}

		signedData, err := CMSSign(context.Background(), content, config)
		if err != nil {
			t.Fatalf("CMSSign() error = %v", err)
		}
		if len(signedData) == 0 {
			t.Error("CMSSign() returned empty data")
		}

		// Verify we can parse the result
		_, err = CMSParseSignedData(signedData)
		if err != nil {
			t.Errorf("Failed to parse signed data: %v", err)
		}
	})

	t.Run("[Unit] CMSSign: fails without certificate", func(t *testing.T) {
		signer, _ := generateCMSTestKeyPair(t)

		config := &CMSSignerConfig{
			Signer:    signer,
			DigestAlg: crypto.SHA256,
		}

		_, err := CMSSign(context.Background(), []byte("test"), config)
		if err == nil {
			t.Error("CMSSign() should fail without certificate")
		}
	})

	t.Run("[Unit] CMSSign: fails without signer", func(t *testing.T) {
		signer, pubKey := generateCMSTestKeyPair(t)
		cert := generateCMSTestCertificate(t, signer, pubKey)

		config := &CMSSignerConfig{
			Certificate: cert,
			DigestAlg:   crypto.SHA256,
		}

		_, err := CMSSign(context.Background(), []byte("test"), config)
		if err == nil {
			t.Error("CMSSign() should fail without signer")
		}
	})

	t.Run("[Unit] CMSSign: detached signature", func(t *testing.T) {
		signer, pubKey := generateCMSTestKeyPair(t)
		cert := generateCMSTestCertificate(t, signer, pubKey)

		content := []byte("Detached content")
		config := &CMSSignerConfig{
			Certificate: cert,
			Signer:      signer,
			DigestAlg:   crypto.SHA256,
			Detached:    true,
		}

		signedData, err := CMSSign(context.Background(), content, config)
		if err != nil {
			t.Fatalf("CMSSign() with detached = %v", err)
		}
		if len(signedData) == 0 {
			t.Error("CMSSign() returned empty data for detached signature")
		}
	})
}

// =============================================================================
// CMSVerify Tests
// =============================================================================

func TestU_CMSVerify(t *testing.T) {
	t.Run("[Unit] CMSVerify: verifies valid signature", func(t *testing.T) {
		signer, pubKey := generateCMSTestKeyPair(t)
		cert := generateCMSTestCertificate(t, signer, pubKey)

		content := []byte("Content to verify")
		signConfig := &CMSSignerConfig{
			Certificate:  cert,
			Signer:       signer,
			DigestAlg:    crypto.SHA256,
			IncludeCerts: true,
		}

		signedData, err := CMSSign(context.Background(), content, signConfig)
		if err != nil {
			t.Fatalf("CMSSign() error = %v", err)
		}

		// Skip cert chain verification for self-signed test certificate
		verifyConfig := &CMSVerifyConfig{
			SkipCertVerify: true,
		}

		result, err := CMSVerify(context.Background(), signedData, verifyConfig)
		if err != nil {
			t.Fatalf("CMSVerify() error = %v", err)
		}
		if result == nil {
			t.Error("CMSVerify() returned nil result")
		}
	})

	t.Run("[Unit] CMSVerify: fails with invalid data", func(t *testing.T) {
		_, err := CMSVerify(context.Background(), []byte("invalid"), nil)
		if err == nil {
			t.Error("CMSVerify() should fail with invalid data")
		}
	})

	t.Run("[Unit] CMSVerify: fails with empty data", func(t *testing.T) {
		_, err := CMSVerify(context.Background(), []byte{}, nil)
		if err == nil {
			t.Error("CMSVerify() should fail with empty data")
		}
	})
}

// =============================================================================
// CMSEncrypt Tests
// =============================================================================

func TestU_CMSEncrypt(t *testing.T) {
	t.Run("[Unit] CMSEncrypt: fails with nil options", func(t *testing.T) {
		_, err := CMSEncrypt(context.Background(), []byte("test"), nil)
		if err == nil {
			t.Error("CMSEncrypt() should fail with nil options")
		}
	})

	t.Run("[Unit] CMSEncrypt: fails with empty recipients", func(t *testing.T) {
		opts := &CMSEncryptOptions{}
		_, err := CMSEncrypt(context.Background(), []byte("test"), opts)
		if err == nil {
			t.Error("CMSEncrypt() should fail with empty recipients")
		}
	})
}

// =============================================================================
// CMSDecrypt Tests
// =============================================================================

func TestU_CMSDecrypt(t *testing.T) {
	t.Run("[Unit] CMSDecrypt: fails with invalid data", func(t *testing.T) {
		opts := &CMSDecryptOptions{}
		_, err := CMSDecrypt(context.Background(), []byte("invalid"), opts)
		if err == nil {
			t.Error("CMSDecrypt() should fail with invalid data")
		}
	})

	t.Run("[Unit] CMSDecrypt: fails with nil options", func(t *testing.T) {
		_, err := CMSDecrypt(context.Background(), []byte{0x30, 0x00}, nil)
		if err == nil {
			t.Error("CMSDecrypt() should fail with nil options")
		}
	})
}
