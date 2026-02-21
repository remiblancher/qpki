package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	pkicrypto "github.com/remiblancher/qpki/pkg/crypto"
	"github.com/remiblancher/qpki/pkg/x509util"
)

// loadSigningCert loads a certificate for CMS signing.
func loadSigningCert(certPath string) (*x509.Certificate, error) {
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

// loadSigningKey loads a private key for CMS signing (HSM or software).
// For Composite/Catalyst certificates, it automatically creates a HybridSigner.
func loadSigningKey(hsmConfig, keyPath, passphrase, keyLabel, keyID string, cert *x509.Certificate) (pkicrypto.Signer, error) {
	var keyCfg pkicrypto.KeyStorageConfig

	if hsmConfig != "" {
		hsmCfg, err := pkicrypto.LoadHSMConfig(hsmConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to load HSM config: %w", err)
		}
		pin, err := hsmCfg.GetPIN()
		if err != nil {
			return nil, fmt.Errorf("failed to get HSM PIN: %w", err)
		}

		// Check if certificate requires HybridSigner (Catalyst or Composite)
		if cert != nil && (x509util.IsCatalystCertificate(cert) || x509util.IsCompositeCertificate(cert)) {
			pkcs11Cfg := pkicrypto.PKCS11Config{
				ModulePath: hsmCfg.PKCS11.Lib,
				TokenLabel: hsmCfg.PKCS11.Token,
				PIN:        pin,
				KeyLabel:   keyLabel,
			}
			return pkicrypto.NewPKCS11HybridSigner(pkcs11Cfg)
		}

		// Single key signer
		keyCfg = pkicrypto.KeyStorageConfig{
			Type:           pkicrypto.KeyProviderTypePKCS11,
			PKCS11Lib:      hsmCfg.PKCS11.Lib,
			PKCS11Token:    hsmCfg.PKCS11.Token,
			PKCS11Pin:      pin,
			PKCS11KeyLabel: keyLabel,
			PKCS11KeyID:    keyID,
		}
		if keyCfg.PKCS11KeyLabel == "" && keyCfg.PKCS11KeyID == "" {
			return nil, fmt.Errorf("--key-label or --key-id required with --hsm-config")
		}
	} else {
		if keyPath == "" {
			return nil, fmt.Errorf("--key required for software mode (or use --hsm-config for HSM)")
		}
		keyCfg = pkicrypto.KeyStorageConfig{
			Type:       pkicrypto.KeyProviderTypeSoftware,
			KeyPath:    keyPath,
			Passphrase: passphrase,
		}
	}

	km := pkicrypto.NewKeyProvider(keyCfg)
	return km.Load(keyCfg)
}

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
