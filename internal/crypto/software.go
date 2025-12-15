package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"

	"github.com/cloudflare/circl/sign/dilithium/mode2"
	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/cloudflare/circl/sign/dilithium/mode5"
)

// SoftwareSigner implements Signer using software-based cryptographic operations.
// Private keys are stored in memory and can be serialized to/from PEM files.
type SoftwareSigner struct {
	alg     AlgorithmID
	priv    crypto.PrivateKey
	pub     crypto.PublicKey
	keyPath string
}

// Ensure SoftwareSigner implements Signer.
var _ Signer = (*SoftwareSigner)(nil)

// NewSoftwareSigner creates a new SoftwareSigner from a key pair.
func NewSoftwareSigner(kp *KeyPair) (*SoftwareSigner, error) {
	if kp == nil {
		return nil, fmt.Errorf("key pair is nil")
	}
	return &SoftwareSigner{
		alg:  kp.Algorithm,
		priv: kp.PrivateKey,
		pub:  kp.PublicKey,
	}, nil
}

// GenerateSoftwareSigner generates a new key pair and returns a SoftwareSigner.
func GenerateSoftwareSigner(alg AlgorithmID) (*SoftwareSigner, error) {
	kp, err := GenerateKeyPair(alg)
	if err != nil {
		return nil, err
	}
	return NewSoftwareSigner(kp)
}

// Algorithm returns the algorithm used by this signer.
func (s *SoftwareSigner) Algorithm() AlgorithmID {
	return s.alg
}

// Public returns the public key.
func (s *SoftwareSigner) Public() crypto.PublicKey {
	return s.pub
}

// Sign signs the digest with the private key.
// For classical algorithms, digest should be the hash of the message.
// For PQC algorithms (ML-DSA), digest is the full message (they hash internally).
func (s *SoftwareSigner) Sign(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	switch priv := s.priv.(type) {
	case *ecdsa.PrivateKey:
		return ecdsa.SignASN1(random, priv, digest)

	case ed25519.PrivateKey:
		// Ed25519 expects the full message, not a digest
		return ed25519.Sign(priv, digest), nil

	case *rsa.PrivateKey:
		hash := crypto.SHA256
		if opts != nil {
			hash = opts.HashFunc()
		}
		return rsa.SignPKCS1v15(random, priv, hash, digest)

	case *mode2.PrivateKey:
		// ML-DSA signs the full message
		sig := make([]byte, mode2.SignatureSize)
		mode2.SignTo(priv, digest, sig)
		return sig, nil

	case *mode3.PrivateKey:
		sig := make([]byte, mode3.SignatureSize)
		mode3.SignTo(priv, digest, sig)
		return sig, nil

	case *mode5.PrivateKey:
		sig := make([]byte, mode5.SignatureSize)
		mode5.SignTo(priv, digest, sig)
		return sig, nil

	default:
		return nil, fmt.Errorf("unsupported private key type: %T", priv)
	}
}

// Verify verifies a signature using the algorithm and public key.
func Verify(alg AlgorithmID, pub crypto.PublicKey, message, signature []byte) bool {
	switch alg {
	case AlgECDSAP256, AlgECDSAP384, AlgECDSAP521:
		ecPub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return false
		}
		return ecdsa.VerifyASN1(ecPub, message, signature)

	case AlgEd25519:
		edPub, ok := pub.(ed25519.PublicKey)
		if !ok {
			return false
		}
		return ed25519.Verify(edPub, message, signature)

	case AlgRSA2048, AlgRSA4096:
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return false
		}
		err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, message, signature)
		return err == nil

	case AlgMLDSA44:
		mlPub, ok := pub.(*mode2.PublicKey)
		if !ok {
			return false
		}
		return mode2.Verify(mlPub, message, signature)

	case AlgMLDSA65:
		mlPub, ok := pub.(*mode3.PublicKey)
		if !ok {
			return false
		}
		return mode3.Verify(mlPub, message, signature)

	case AlgMLDSA87:
		mlPub, ok := pub.(*mode5.PublicKey)
		if !ok {
			return false
		}
		return mode5.Verify(mlPub, message, signature)

	default:
		return false
	}
}

// SavePrivateKey saves the private key to a PEM file.
// If passphrase is provided, the key is encrypted.
func (s *SoftwareSigner) SavePrivateKey(path string, passphrase []byte) error {
	var pemBlock *pem.Block

	switch priv := s.priv.(type) {
	case *ecdsa.PrivateKey, ed25519.PrivateKey, *rsa.PrivateKey:
		// Use PKCS#8 for classical keys
		der, err := x509.MarshalPKCS8PrivateKey(s.priv)
		if err != nil {
			return fmt.Errorf("failed to marshal private key: %w", err)
		}
		pemBlock = &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: der,
		}

	case *mode2.PrivateKey:
		pemBlock = &pem.Block{
			Type:  "ML-DSA-44 PRIVATE KEY",
			Bytes: priv.Bytes(),
		}

	case *mode3.PrivateKey:
		pemBlock = &pem.Block{
			Type:  "ML-DSA-65 PRIVATE KEY",
			Bytes: priv.Bytes(),
		}

	case *mode5.PrivateKey:
		pemBlock = &pem.Block{
			Type:  "ML-DSA-87 PRIVATE KEY",
			Bytes: priv.Bytes(),
		}

	default:
		return fmt.Errorf("unsupported private key type: %T", s.priv)
	}

	// Encrypt if passphrase provided
	if len(passphrase) > 0 {
		var err error
		pemBlock, err = x509.EncryptPEMBlock(rand.Reader, pemBlock.Type, pemBlock.Bytes, passphrase, x509.PEMCipherAES256) //nolint:staticcheck // Deprecated but still used
		if err != nil {
			return fmt.Errorf("failed to encrypt private key: %w", err)
		}
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create key file: %w", err)
	}
	defer f.Close()

	if err := pem.Encode(f, pemBlock); err != nil {
		return fmt.Errorf("failed to write PEM: %w", err)
	}

	s.keyPath = path
	return nil
}

// LoadPrivateKey loads a private key from a PEM file.
func LoadPrivateKey(path string, passphrase []byte) (*SoftwareSigner, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}

	keyBytes := block.Bytes

	// Decrypt if encrypted
	if x509.IsEncryptedPEMBlock(block) { //nolint:staticcheck
		if len(passphrase) == 0 {
			return nil, fmt.Errorf("private key is encrypted but no passphrase provided")
		}
		keyBytes, err = x509.DecryptPEMBlock(block, passphrase) //nolint:staticcheck
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt private key: %w", err)
		}
	}

	var priv crypto.PrivateKey
	var pub crypto.PublicKey
	var alg AlgorithmID

	switch block.Type {
	case "PRIVATE KEY":
		// PKCS#8 format
		priv, err = x509.ParsePKCS8PrivateKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS#8 key: %w", err)
		}
		alg, pub = classicalKeyInfo(priv)

	case "EC PRIVATE KEY":
		// SEC1 format
		priv, err = x509.ParseECPrivateKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EC key: %w", err)
		}
		alg, pub = classicalKeyInfo(priv)

	case "RSA PRIVATE KEY":
		// PKCS#1 format
		priv, err = x509.ParsePKCS1PrivateKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RSA key: %w", err)
		}
		alg, pub = classicalKeyInfo(priv)

	case "ML-DSA-44 PRIVATE KEY":
		var mlPriv mode2.PrivateKey
		if err := mlPriv.UnmarshalBinary(keyBytes); err != nil {
			return nil, fmt.Errorf("failed to parse ML-DSA-44 key: %w", err)
		}
		priv = &mlPriv
		pub = mlPriv.Public()
		alg = AlgMLDSA44

	case "ML-DSA-65 PRIVATE KEY":
		var mlPriv mode3.PrivateKey
		if err := mlPriv.UnmarshalBinary(keyBytes); err != nil {
			return nil, fmt.Errorf("failed to parse ML-DSA-65 key: %w", err)
		}
		priv = &mlPriv
		pub = mlPriv.Public()
		alg = AlgMLDSA65

	case "ML-DSA-87 PRIVATE KEY":
		var mlPriv mode5.PrivateKey
		if err := mlPriv.UnmarshalBinary(keyBytes); err != nil {
			return nil, fmt.Errorf("failed to parse ML-DSA-87 key: %w", err)
		}
		priv = &mlPriv
		pub = mlPriv.Public()
		alg = AlgMLDSA87

	default:
		return nil, fmt.Errorf("unknown PEM type: %s", block.Type)
	}

	return &SoftwareSigner{
		alg:     alg,
		priv:    priv,
		pub:     pub,
		keyPath: path,
	}, nil
}

// classicalKeyInfo returns the algorithm and public key for a classical private key.
func classicalKeyInfo(priv crypto.PrivateKey) (AlgorithmID, crypto.PublicKey) {
	switch k := priv.(type) {
	case *ecdsa.PrivateKey:
		switch k.Curve.Params().BitSize {
		case 256:
			return AlgECDSAP256, &k.PublicKey
		case 384:
			return AlgECDSAP384, &k.PublicKey
		case 521:
			return AlgECDSAP521, &k.PublicKey
		}
	case ed25519.PrivateKey:
		return AlgEd25519, k.Public()
	case *rsa.PrivateKey:
		if k.N.BitLen() <= 2048 {
			return AlgRSA2048, &k.PublicKey
		}
		return AlgRSA4096, &k.PublicKey
	}
	return "", nil
}

// SoftwareSignerProvider implements SignerProvider for software-based keys.
type SoftwareSignerProvider struct{}

// Ensure SoftwareSignerProvider implements SignerProvider.
var _ SignerProvider = (*SoftwareSignerProvider)(nil)

// LoadSigner loads a signer from the configuration.
func (p *SoftwareSignerProvider) LoadSigner(cfg SignerConfig) (Signer, error) {
	if cfg.Type != SignerTypeSoftware && cfg.Type != "" {
		return nil, fmt.Errorf("SoftwareSignerProvider only supports software signers, got: %s", cfg.Type)
	}

	passphrase := resolvePassphrase(cfg.Passphrase)
	return LoadPrivateKey(cfg.KeyPath, passphrase)
}

// GenerateAndSave generates a new key pair and saves it.
func (p *SoftwareSignerProvider) GenerateAndSave(alg AlgorithmID, cfg SignerConfig) (Signer, error) {
	signer, err := GenerateSoftwareSigner(alg)
	if err != nil {
		return nil, err
	}

	passphrase := resolvePassphrase(cfg.Passphrase)
	if err := signer.SavePrivateKey(cfg.KeyPath, passphrase); err != nil {
		return nil, err
	}

	return signer, nil
}

// resolvePassphrase resolves a passphrase that may be "env:VAR_NAME".
func resolvePassphrase(passphrase string) []byte {
	if passphrase == "" {
		return nil
	}
	if len(passphrase) > 4 && passphrase[:4] == "env:" {
		envValue := os.Getenv(passphrase[4:])
		return []byte(envValue)
	}
	return []byte(passphrase)
}

// KeyPath returns the path where the private key is stored.
func (s *SoftwareSigner) KeyPath() string {
	return s.keyPath
}

// PrivateKey returns the underlying private key.
// Use with caution - prefer using Sign() instead.
func (s *SoftwareSigner) PrivateKey() crypto.PrivateKey {
	return s.priv
}
