package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
)

// loadDecryptionKey loads a private key for CMS decryption.
func loadDecryptionKey(keyPath, passphrase string) (interface{}, error) {
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in key file")
	}

	if block.Type == "PRIVATE KEY" {
		return loadPKCS8Key(keyPath, passphrase)
	}
	return loadStandardKey(keyPath, passphrase)
}

// loadPKCS8Key tries to load a PKCS#8 key (ML-KEM first, then standard).
func loadPKCS8Key(keyPath, passphrase string) (interface{}, error) {
	resolvedPass := pkicrypto.ResolvePassphrase(passphrase)
	kemPair, err := pkicrypto.LoadKEMPrivateKey(keyPath, resolvedPass)
	if err == nil {
		return kemPair.PrivateKey, nil
	}

	return loadStandardKey(keyPath, passphrase)
}

// loadStandardKey loads a standard (RSA, EC) private key.
func loadStandardKey(keyPath, passphrase string) (interface{}, error) {
	keyCfg := pkicrypto.KeyStorageConfig{
		Type:       pkicrypto.KeyProviderTypeSoftware,
		KeyPath:    keyPath,
		Passphrase: passphrase,
	}
	km := pkicrypto.NewKeyProvider(keyCfg)
	signer, err := km.Load(keyCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %w", err)
	}

	softSigner, ok := signer.(*pkicrypto.SoftwareSigner)
	if !ok {
		return nil, fmt.Errorf("CMS decrypt requires a software key (HSM decryption not yet supported)")
	}
	return softSigner.PrivateKey(), nil
}

// loadDecryptionCert loads a certificate for CMS decryption recipient matching.
func loadDecryptionCert(certPath string) (*x509.Certificate, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}
