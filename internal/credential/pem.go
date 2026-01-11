package credential

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/kem/mlkem/mlkem512"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/cloudflare/circl/sign/slhdsa"
	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
)

// ML-KEM OIDs (FIPS 203 / NIST)
var (
	oidMLKEM512  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 1}
	oidMLKEM768  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 2}
	oidMLKEM1024 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 3}
)

// pkcs8PrivateKey is the ASN.1 structure for PKCS#8 private keys.
type pkcs8PrivateKey struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
}

// marshalMLKEMPrivateKeyPKCS8 marshals an ML-KEM private key to PKCS#8 DER format.
func marshalMLKEMPrivateKeyPKCS8(priv crypto.PrivateKey) ([]byte, error) {
	var oid asn1.ObjectIdentifier
	var keyBytes []byte
	var err error

	switch k := priv.(type) {
	case *mlkem512.PrivateKey:
		oid = oidMLKEM512
		keyBytes, err = k.MarshalBinary()
	case *mlkem768.PrivateKey:
		oid = oidMLKEM768
		keyBytes, err = k.MarshalBinary()
	case *mlkem1024.PrivateKey:
		oid = oidMLKEM1024
		keyBytes, err = k.MarshalBinary()
	default:
		return nil, fmt.Errorf("unsupported ML-KEM key type: %T", priv)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to marshal ML-KEM key: %w", err)
	}

	// Wrap raw key bytes in OCTET STRING for PKCS#8 privateKey field
	privKeyOctetString, err := asn1.Marshal(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key octet string: %w", err)
	}

	pkcs8 := pkcs8PrivateKey{
		Version: 0,
		Algo: pkix.AlgorithmIdentifier{
			Algorithm: oid,
		},
		PrivateKey: privKeyOctetString,
	}

	return asn1.Marshal(pkcs8)
}

// EncodeCertificatesPEM encodes multiple certificates to a single PEM file.
// Certificates are written in order, each as a separate PEM block.
func EncodeCertificatesPEM(certs []*x509.Certificate) ([]byte, error) {
	var result []byte

	for _, cert := range certs {
		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		result = append(result, pem.EncodeToMemory(block)...)
	}

	return result, nil
}

// DecodeCertificatesPEM decodes multiple certificates from a PEM file.
func DecodeCertificatesPEM(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}

		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificate: %w", err)
			}
			certs = append(certs, cert)
		}

		data = rest
	}

	return certs, nil
}

// EncodePrivateKeysPEM encodes multiple private keys to a single PEM file.
// If passphrase is provided, each key is encrypted.
// HSM-based signers (PKCS11Signer) are skipped since their keys are stored in the HSM.
func EncodePrivateKeysPEM(signers []pkicrypto.Signer, passphrase []byte) ([]byte, error) {
	var result []byte

	for _, signer := range signers {
		var priv crypto.PrivateKey

		// Handle software signers
		if ss, ok := signer.(*pkicrypto.SoftwareSigner); ok {
			priv = ss.PrivateKey()
		} else if ks, ok := signer.(*pkicrypto.KEMSigner); ok {
			// Handle KEM signers
			priv = ks.PrivateKey()
		} else {
			// Skip non-software signers (e.g., PKCS11Signer)
			continue
		}

		block, err := privateKeyToPEMBlock(priv, signer.Algorithm(), passphrase)
		if err != nil {
			return nil, fmt.Errorf("failed to encode private key: %w", err)
		}

		result = append(result, pem.EncodeToMemory(block)...)
	}

	return result, nil
}

// privateKeyToPEMBlock converts a private key to a PEM block.
func privateKeyToPEMBlock(priv crypto.PrivateKey, alg pkicrypto.AlgorithmID, passphrase []byte) (*pem.Block, error) {
	var pemType string
	var keyBytes []byte
	var err error

	// Handle by key type (more reliable than algorithm matching)
	switch k := priv.(type) {
	case *mldsa44.PrivateKey:
		keyBytes = k.Bytes()
		pemType = "ML-DSA-44 PRIVATE KEY"

	case *mldsa65.PrivateKey:
		keyBytes = k.Bytes()
		pemType = "ML-DSA-65 PRIVATE KEY"

	case *mldsa87.PrivateKey:
		keyBytes = k.Bytes()
		pemType = "ML-DSA-87 PRIVATE KEY"

	case *mlkem512.PrivateKey, *mlkem768.PrivateKey, *mlkem1024.PrivateKey:
		// Use PKCS#8 standard format for OpenSSL 3.6+ compatibility
		keyBytes, err = marshalMLKEMPrivateKeyPKCS8(priv)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal ML-KEM key to PKCS#8: %w", err)
		}
		pemType = "PRIVATE KEY"

	case *slhdsa.PrivateKey:
		keyBytes, err = k.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal SLH-DSA key: %w", err)
		}
		pemType = fmt.Sprintf("%s PRIVATE KEY", k.ID)

	default:
		// Classical keys use PKCS#8
		keyBytes, err = x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal private key: %w", err)
		}
		pemType = "PRIVATE KEY"
	}

	block := &pem.Block{
		Type:  pemType,
		Bytes: keyBytes,
	}

	// Encrypt if passphrase provided
	if len(passphrase) > 0 {
		//nolint:staticcheck // Deprecated but needed
		block, err = x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, passphrase, x509.PEMCipherAES256)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt key: %w", err)
		}
	}

	return block, nil
}

// DecodePrivateKeysPEM decodes multiple private keys from a PEM file.
func DecodePrivateKeysPEM(data []byte, passphrase []byte) ([]pkicrypto.Signer, error) {
	var signers []pkicrypto.Signer

	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}

		signer, err := pkicrypto.LoadPrivateKey("", passphrase)
		if err != nil {
			// Try to parse directly from block
			signer, err = parsePrivateKeyBlock(block, passphrase)
			if err != nil {
				return nil, fmt.Errorf("failed to parse private key: %w", err)
			}
		}

		signers = append(signers, signer)
		data = rest
	}

	return signers, nil
}

// parsePrivateKeyBlock parses a PEM block into a SoftwareSigner.
func parsePrivateKeyBlock(block *pem.Block, passphrase []byte) (*pkicrypto.SoftwareSigner, error) {
	keyBytes := block.Bytes

	// Decrypt if encrypted
	if x509.IsEncryptedPEMBlock(block) { //nolint:staticcheck
		if len(passphrase) == 0 {
			return nil, fmt.Errorf("key is encrypted but no passphrase provided")
		}
		var err error
		keyBytes, err = x509.DecryptPEMBlock(block, passphrase) //nolint:staticcheck
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt key: %w", err)
		}
	}

	// Parse based on PEM type
	switch block.Type {
	case "PRIVATE KEY":
		priv, err := x509.ParsePKCS8PrivateKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS#8 key: %w", err)
		}
		alg, pub := classicalKeyInfo(priv)
		return pkicrypto.NewSoftwareSigner(&pkicrypto.KeyPair{
			Algorithm:  alg,
			PrivateKey: priv,
			PublicKey:  pub,
		})

	default:
		return nil, fmt.Errorf("unsupported PEM type: %s", block.Type)
	}
}

// classicalKeyInfo returns algorithm and public key for classical keys.
func classicalKeyInfo(priv crypto.PrivateKey) (pkicrypto.AlgorithmID, crypto.PublicKey) {
	switch k := priv.(type) {
	case interface{ Public() crypto.PublicKey }:
		pub := k.Public()
		// Determine algorithm from key type
		switch pub.(type) {
		case *interface{}:
			// Handle various key types
		}
		return pkicrypto.AlgECDSAP256, pub // Default
	default:
		return "", nil
	}
}

// SaveCredentialPEM saves a credential's certificates and keys to PEM files.
func SaveCredentialPEM(certsPath, keysPath string, certs []*x509.Certificate, signers []pkicrypto.Signer, passphrase []byte) error {
	// Save certificates
	certsPEM, err := EncodeCertificatesPEM(certs)
	if err != nil {
		return fmt.Errorf("failed to encode certificates: %w", err)
	}

	if err := os.WriteFile(certsPath, certsPEM, 0644); err != nil {
		return fmt.Errorf("failed to write certificates: %w", err)
	}

	// Save keys (with encryption)
	if len(signers) > 0 && keysPath != "" {
		keysPEM, err := EncodePrivateKeysPEM(signers, passphrase)
		if err != nil {
			return fmt.Errorf("failed to encode keys: %w", err)
		}

		if err := os.WriteFile(keysPath, keysPEM, 0600); err != nil {
			return fmt.Errorf("failed to write keys: %w", err)
		}
	}

	return nil
}

// LoadCredentialPEM loads certificates and keys from PEM files.
func LoadCredentialPEM(certsPath, keysPath string, passphrase []byte) ([]*x509.Certificate, []pkicrypto.Signer, error) {
	// Load certificates
	certsData, err := os.ReadFile(certsPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read certificates: %w", err)
	}

	certs, err := DecodeCertificatesPEM(certsData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode certificates: %w", err)
	}

	// Load keys if path provided
	var signers []pkicrypto.Signer
	if keysPath != "" {
		keysData, err := os.ReadFile(keysPath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read keys: %w", err)
		}

		signers, err = DecodePrivateKeysPEM(keysData, passphrase)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode keys: %w", err)
		}
	}

	return certs, signers, nil
}
