package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/cloudflare/circl/sign/slhdsa"
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
//
// If opts is a *SignerOptsConfig, it can specify RSA-PSS vs PKCS#1 v1.5.
// If opts is *rsa.PSSOptions, RSA-PSS is used directly.
// Otherwise, defaults are used based on the algorithm.
func (s *SoftwareSigner) Sign(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	switch priv := s.priv.(type) {
	case *ecdsa.PrivateKey:
		return ecdsa.SignASN1(random, priv, digest)

	case ed25519.PrivateKey:
		// Ed25519 expects the full message, not a digest
		return ed25519.Sign(priv, digest), nil

	case *rsa.PrivateKey:
		// Check if we have extended options for PSS
		if extOpts, ok := opts.(*SignerOptsConfig); ok && extOpts.UsePSS {
			return rsa.SignPSS(random, priv, extOpts.Hash, digest, extOpts.PSSOptions)
		}

		// Check if opts is already rsa.PSSOptions
		if pssOpts, ok := opts.(*rsa.PSSOptions); ok {
			return rsa.SignPSS(random, priv, pssOpts.Hash, digest, pssOpts)
		}

		// Default to PKCS#1 v1.5 for backwards compatibility
		hash := crypto.SHA256
		if opts != nil {
			hash = opts.HashFunc()
		}
		return rsa.SignPKCS1v15(random, priv, hash, digest)

	case *mldsa44.PrivateKey:
		// ML-DSA (FIPS 204) implements crypto.Signer
		// Note: opts.HashFunc() must return 0 for pure ML-DSA
		return priv.Sign(random, digest, crypto.Hash(0))

	case *mldsa65.PrivateKey:
		return priv.Sign(random, digest, crypto.Hash(0))

	case *mldsa87.PrivateKey:
		return priv.Sign(random, digest, crypto.Hash(0))

	case *slhdsa.PrivateKey:
		// SLH-DSA signs the full message using crypto.Signer interface
		return priv.Sign(random, digest, nil)

	default:
		return nil, fmt.Errorf("unsupported private key type: %T", priv)
	}
}

// Verify verifies a signature using the algorithm and public key.
// For RSA, defaults to PKCS#1 v1.5 for backwards compatibility.
// Use VerifyWithOpts for RSA-PSS verification.
func Verify(alg AlgorithmID, pub crypto.PublicKey, message, signature []byte) bool {
	return VerifyWithOpts(alg, pub, message, signature, nil)
}

// VerifySignature verifies a signature and returns an error if verification fails.
// This is a convenience wrapper around Verify that returns an error instead of bool.
func VerifySignature(pub crypto.PublicKey, alg AlgorithmID, message, signature []byte) error {
	if !Verify(alg, pub, message, signature) {
		return fmt.Errorf("signature verification failed for algorithm %s", alg)
	}
	return nil
}

// VerifyWithOpts verifies a signature with explicit options.
// If opts is nil, defaults are used based on the algorithm.
func VerifyWithOpts(alg AlgorithmID, pub crypto.PublicKey, message, signature []byte, opts *SignerOptsConfig) bool {
	switch alg {
	case AlgECDSAP256, AlgECDSAP384, AlgECDSAP521, AlgECP256, AlgECP384, AlgECP521:
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

		// Use PSS if opts specify it
		if opts != nil && opts.UsePSS {
			err := rsa.VerifyPSS(rsaPub, opts.Hash, message, signature, opts.PSSOptions)
			return err == nil
		}

		// Default to PKCS#1 v1.5 for backwards compatibility
		hash := crypto.SHA256
		if opts != nil {
			hash = opts.Hash
		}
		err := rsa.VerifyPKCS1v15(rsaPub, hash, message, signature)
		return err == nil

	case AlgMLDSA44:
		mlPub, ok := pub.(*mldsa44.PublicKey)
		if !ok {
			return false
		}
		return mldsa44.Verify(mlPub, message, nil, signature)

	case AlgMLDSA65:
		mlPub, ok := pub.(*mldsa65.PublicKey)
		if !ok {
			return false
		}
		return mldsa65.Verify(mlPub, message, nil, signature)

	case AlgMLDSA87:
		mlPub, ok := pub.(*mldsa87.PublicKey)
		if !ok {
			return false
		}
		return mldsa87.Verify(mlPub, message, nil, signature)

	case AlgSLHDSA128s, AlgSLHDSA128f, AlgSLHDSA192s, AlgSLHDSA192f, AlgSLHDSA256s, AlgSLHDSA256f:
		slhPub, ok := pub.(*slhdsa.PublicKey)
		if !ok {
			return false
		}
		msg := slhdsa.NewMessage(message)
		return slhdsa.Verify(slhPub, msg, signature, nil)

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

	case *mldsa44.PrivateKey:
		pemBlock = &pem.Block{
			Type:  "ML-DSA-44 PRIVATE KEY",
			Bytes: priv.Bytes(),
		}

	case *mldsa65.PrivateKey:
		pemBlock = &pem.Block{
			Type:  "ML-DSA-65 PRIVATE KEY",
			Bytes: priv.Bytes(),
		}

	case *mldsa87.PrivateKey:
		pemBlock = &pem.Block{
			Type:  "ML-DSA-87 PRIVATE KEY",
			Bytes: priv.Bytes(),
		}

	case *slhdsa.PrivateKey:
		privBytes, err := priv.MarshalBinary()
		if err != nil {
			return fmt.Errorf("failed to marshal SLH-DSA key: %w", err)
		}
		pemBlock = &pem.Block{
			Type:  fmt.Sprintf("%s PRIVATE KEY", priv.ID),
			Bytes: privBytes,
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
		var mlPriv mldsa44.PrivateKey
		if err := mlPriv.UnmarshalBinary(keyBytes); err != nil {
			return nil, fmt.Errorf("failed to parse ML-DSA-44 key: %w", err)
		}
		priv = &mlPriv
		pub = mlPriv.Public()
		alg = AlgMLDSA44

	case "ML-DSA-65 PRIVATE KEY":
		var mlPriv mldsa65.PrivateKey
		if err := mlPriv.UnmarshalBinary(keyBytes); err != nil {
			return nil, fmt.Errorf("failed to parse ML-DSA-65 key: %w", err)
		}
		priv = &mlPriv
		pub = mlPriv.Public()
		alg = AlgMLDSA65

	case "ML-DSA-87 PRIVATE KEY":
		var mlPriv mldsa87.PrivateKey
		if err := mlPriv.UnmarshalBinary(keyBytes); err != nil {
			return nil, fmt.Errorf("failed to parse ML-DSA-87 key: %w", err)
		}
		priv = &mlPriv
		pub = mlPriv.Public()
		alg = AlgMLDSA87

	default:
		// Check for SLH-DSA key types
		if slhAlg, slhID, ok := parseSLHDSAPEMType(block.Type); ok {
			var slhPriv slhdsa.PrivateKey
			slhPriv.ID = slhID
			if err := slhPriv.UnmarshalBinary(keyBytes); err != nil {
				return nil, fmt.Errorf("failed to parse %s key: %w", block.Type, err)
			}
			priv = &slhPriv
			pub = slhPriv.PublicKey()
			alg = slhAlg
		} else {
			return nil, fmt.Errorf("unknown PEM type: %s", block.Type)
		}
	}

	return &SoftwareSigner{
		alg:     alg,
		priv:    priv,
		pub:     pub,
		keyPath: path,
	}, nil
}

// LoadPrivateKeysAsHybrid loads all private keys from a PEM file.
// If two keys are found (classical + PQC), it returns a HybridSigner.
// If one key is found, it returns a regular Signer.
func LoadPrivateKeysAsHybrid(path string, passphrase []byte) (Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	var signers []*SoftwareSigner
	rest := data

	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
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

		signer, err := parsePEMKeyBlock(block.Type, keyBytes, path)
		if err != nil {
			return nil, err
		}
		signers = append(signers, signer)
	}

	if len(signers) == 0 {
		return nil, fmt.Errorf("no private keys found in %s", path)
	}

	if len(signers) == 1 {
		return signers[0], nil
	}

	// Two keys found - create a HybridSigner
	// Determine which is classical and which is PQC
	var classical, pqc *SoftwareSigner
	for _, s := range signers {
		algType := s.Algorithm().Type()
		if algType == TypePQCSignature {
			pqc = s
		} else if algType == TypeClassicalSignature {
			classical = s
		}
	}

	if classical == nil || pqc == nil {
		return nil, fmt.Errorf("hybrid key file must contain one classical and one PQC key")
	}

	return NewHybridSigner(classical, pqc)
}

// parsePEMKeyBlock parses a single PEM key block.
func parsePEMKeyBlock(pemType string, keyBytes []byte, path string) (*SoftwareSigner, error) {
	var priv crypto.PrivateKey
	var pub crypto.PublicKey
	var alg AlgorithmID
	var err error

	switch pemType {
	case "PRIVATE KEY":
		priv, err = x509.ParsePKCS8PrivateKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS#8 key: %w", err)
		}
		alg, pub = classicalKeyInfo(priv)

	case "EC PRIVATE KEY":
		priv, err = x509.ParseECPrivateKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EC key: %w", err)
		}
		alg, pub = classicalKeyInfo(priv)

	case "RSA PRIVATE KEY":
		priv, err = x509.ParsePKCS1PrivateKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RSA key: %w", err)
		}
		alg, pub = classicalKeyInfo(priv)

	case "ML-DSA-44 PRIVATE KEY":
		var mlPriv mldsa44.PrivateKey
		if err := mlPriv.UnmarshalBinary(keyBytes); err != nil {
			return nil, fmt.Errorf("failed to parse ML-DSA-44 key: %w", err)
		}
		priv = &mlPriv
		pub = mlPriv.Public()
		alg = AlgMLDSA44

	case "ML-DSA-65 PRIVATE KEY":
		var mlPriv mldsa65.PrivateKey
		if err := mlPriv.UnmarshalBinary(keyBytes); err != nil {
			return nil, fmt.Errorf("failed to parse ML-DSA-65 key: %w", err)
		}
		priv = &mlPriv
		pub = mlPriv.Public()
		alg = AlgMLDSA65

	case "ML-DSA-87 PRIVATE KEY":
		var mlPriv mldsa87.PrivateKey
		if err := mlPriv.UnmarshalBinary(keyBytes); err != nil {
			return nil, fmt.Errorf("failed to parse ML-DSA-87 key: %w", err)
		}
		priv = &mlPriv
		pub = mlPriv.Public()
		alg = AlgMLDSA87

	default:
		// Check for SLH-DSA key types
		if slhAlg, slhID, ok := parseSLHDSAPEMType(pemType); ok {
			var slhPriv slhdsa.PrivateKey
			slhPriv.ID = slhID
			if err := slhPriv.UnmarshalBinary(keyBytes); err != nil {
				return nil, fmt.Errorf("failed to parse %s key: %w", pemType, err)
			}
			priv = &slhPriv
			pub = slhPriv.PublicKey()
			alg = slhAlg
		} else {
			return nil, fmt.Errorf("unknown PEM type: %s", pemType)
		}
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

// KeyPath returns the path where the private key is stored.
func (s *SoftwareSigner) KeyPath() string {
	return s.keyPath
}

// PrivateKey returns the underlying private key.
// Use with caution - prefer using Sign() instead.
func (s *SoftwareSigner) PrivateKey() crypto.PrivateKey {
	return s.priv
}

// Decrypt implements crypto.Decrypter for RSA keys.
// Returns an error for non-RSA keys.
func (s *SoftwareSigner) Decrypt(_ io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	rsaKey, ok := s.priv.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("Decrypt only supported for RSA keys, got %T", s.priv)
	}

	// Handle different decryption options
	switch o := opts.(type) {
	case *rsa.OAEPOptions:
		hash := o.Hash.New()
		return rsa.DecryptOAEP(hash, rand.Reader, rsaKey, ciphertext, o.Label)
	case *rsa.PKCS1v15DecryptOptions:
		// PKCS#1 v1.5 decryption
		return rsa.DecryptPKCS1v15(rand.Reader, rsaKey, ciphertext)
	default:
		// Default to OAEP with SHA-256
		return rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaKey, ciphertext, nil)
	}
}

// parseSLHDSAPEMType parses SLH-DSA PEM type headers like "SLH-DSA-SHA2-128s PRIVATE KEY".
func parseSLHDSAPEMType(pemType string) (AlgorithmID, slhdsa.ID, bool) {
	slhTypes := map[string]struct {
		alg AlgorithmID
		id  slhdsa.ID
	}{
		"SLH-DSA-SHA2-128s PRIVATE KEY": {AlgSLHDSA128s, slhdsa.SHA2_128s},
		"SLH-DSA-SHA2-128f PRIVATE KEY": {AlgSLHDSA128f, slhdsa.SHA2_128f},
		"SLH-DSA-SHA2-192s PRIVATE KEY": {AlgSLHDSA192s, slhdsa.SHA2_192s},
		"SLH-DSA-SHA2-192f PRIVATE KEY": {AlgSLHDSA192f, slhdsa.SHA2_192f},
		"SLH-DSA-SHA2-256s PRIVATE KEY": {AlgSLHDSA256s, slhdsa.SHA2_256s},
		"SLH-DSA-SHA2-256f PRIVATE KEY": {AlgSLHDSA256f, slhdsa.SHA2_256f},
	}

	if info, ok := slhTypes[pemType]; ok {
		return info.alg, info.id, true
	}
	return "", 0, false
}
