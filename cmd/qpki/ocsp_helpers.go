package main

import (
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"

	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
	"github.com/remiblancher/post-quantum-pki/internal/ocsp"
)

// ocspSignParams holds parameters for OCSP response signing.
type ocspSignParams struct {
	Serial           *big.Int
	CertStatus       ocsp.CertStatus
	RevocationTime   time.Time
	RevocationReason ocsp.RevocationReason
	CACert           *x509.Certificate
	ResponderCert    *x509.Certificate
	Signer           crypto.Signer
	Validity         time.Duration
}

// parseOCSPSerial parses a hex serial number string.
func parseOCSPSerial(serialHex string) (*big.Int, error) {
	serialBytes, err := hex.DecodeString(serialHex)
	if err != nil {
		return nil, fmt.Errorf("invalid serial number: %w", err)
	}
	return new(big.Int).SetBytes(serialBytes), nil
}

// parseOCSPCertStatus parses a status string to CertStatus.
func parseOCSPCertStatus(status string) (ocsp.CertStatus, error) {
	switch strings.ToLower(status) {
	case "good":
		return ocsp.CertStatusGood, nil
	case "revoked":
		return ocsp.CertStatusRevoked, nil
	case "unknown":
		return ocsp.CertStatusUnknown, nil
	default:
		return 0, fmt.Errorf("invalid status: %s (must be good, revoked, or unknown)", status)
	}
}

// parseOCSPRevocationTime parses a revocation time string (RFC3339).
// Returns current time if timeStr is empty.
func parseOCSPRevocationTime(timeStr string) (time.Time, error) {
	if timeStr == "" {
		return time.Now(), nil
	}
	t, err := time.Parse(time.RFC3339, timeStr)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid revocation time: %w", err)
	}
	return t, nil
}

// loadOCSPSigner loads the signer key from HSM or software.
func loadOCSPSigner(hsmConfig, keyPath, passphrase, keyLabel, keyID string) (crypto.Signer, error) {
	var keyCfg pkicrypto.KeyStorageConfig

	if hsmConfig != "" {
		// HSM mode
		hsmCfg, err := pkicrypto.LoadHSMConfig(hsmConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to load HSM config: %w", err)
		}
		pin, err := hsmCfg.GetPIN()
		if err != nil {
			return nil, fmt.Errorf("failed to get HSM PIN: %w", err)
		}
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
		// Software mode
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
	signer, err := km.Load(keyCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %w", err)
	}
	return signer, nil
}

// buildOCSPSignResponse builds an OCSP response from the parameters.
func buildOCSPSignResponse(params *ocspSignParams) ([]byte, error) {
	// Create CertID
	certID, err := ocsp.NewCertIDFromSerial(crypto.SHA256, params.CACert, params.Serial)
	if err != nil {
		return nil, fmt.Errorf("failed to create CertID: %w", err)
	}

	// Build response
	now := time.Now().UTC()
	builder := ocsp.NewResponseBuilder(params.ResponderCert, params.Signer)

	switch params.CertStatus {
	case ocsp.CertStatusGood:
		builder.AddGood(certID, now, now.Add(params.Validity))
	case ocsp.CertStatusRevoked:
		builder.AddRevoked(certID, now, now.Add(params.Validity), params.RevocationTime, params.RevocationReason)
	case ocsp.CertStatusUnknown:
		builder.AddUnknown(certID, now, now.Add(params.Validity))
	}

	responseData, err := builder.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build OCSP response: %w", err)
	}

	return responseData, nil
}

// printOCSPSignResult prints the OCSP sign operation result.
func printOCSPSignResult(output string, serial string, status ocsp.CertStatus, revocationTime time.Time, revocationReason string, validity time.Duration) {
	fmt.Printf("OCSP response written to %s\n", output)
	fmt.Printf("  Serial:     %s\n", serial)
	fmt.Printf("  Status:     %s\n", status)
	if status == ocsp.CertStatusRevoked {
		fmt.Printf("  Revoked:    %s\n", revocationTime.Format(time.RFC3339))
		if revocationReason != "" {
			fmt.Printf("  Reason:     %s\n", revocationReason)
		}
	}
	fmt.Printf("  Valid For:  %s\n", validity)
}
