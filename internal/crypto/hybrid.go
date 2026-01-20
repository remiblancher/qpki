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

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/cloudflare/circl/sign/slhdsa"
)

// HybridSignerImpl implements HybridSigner by combining a classical and PQC signer.
// This is used for Catalyst certificates where both signatures are needed.
type HybridSignerImpl struct {
	classical Signer
	pqc       Signer
	alg       AlgorithmID // Combined algorithm identifier
}

// Ensure HybridSignerImpl implements HybridSigner.
var _ HybridSigner = (*HybridSignerImpl)(nil)

// NewHybridSigner creates a new HybridSigner from classical and PQC signers.
func NewHybridSigner(classical, pqc Signer) (*HybridSignerImpl, error) {
	if classical == nil {
		return nil, fmt.Errorf("classical signer is nil")
	}
	if pqc == nil {
		return nil, fmt.Errorf("PQC signer is nil")
	}

	// Verify classical is indeed classical
	if classical.Algorithm().IsPQC() {
		return nil, fmt.Errorf("classical signer uses PQC algorithm: %s", classical.Algorithm())
	}

	// Verify PQC is indeed PQC
	if !pqc.Algorithm().IsPQC() {
		return nil, fmt.Errorf("PQC signer uses non-PQC algorithm: %s", pqc.Algorithm())
	}

	// Create combined algorithm ID
	algID := AlgorithmID(fmt.Sprintf("hybrid-%s-%s", classical.Algorithm(), pqc.Algorithm()))

	return &HybridSignerImpl{
		classical: classical,
		pqc:       pqc,
		alg:       algID,
	}, nil
}

// GenerateHybridSigner generates a new hybrid signer with the specified algorithms.
func GenerateHybridSigner(classicalAlg, pqcAlg AlgorithmID) (*HybridSignerImpl, error) {
	classical, err := GenerateSoftwareSigner(classicalAlg)
	if err != nil {
		return nil, fmt.Errorf("failed to generate classical key: %w", err)
	}

	pqc, err := GenerateSoftwareSigner(pqcAlg)
	if err != nil {
		return nil, fmt.Errorf("failed to generate PQC key: %w", err)
	}

	return NewHybridSigner(classical, pqc)
}

// Algorithm returns the combined algorithm identifier.
func (h *HybridSignerImpl) Algorithm() AlgorithmID {
	return h.alg
}

// Public returns the classical public key.
// For X.509 certificates, the classical key is in SubjectPublicKeyInfo,
// and the PQC key is in the AltSubjectPublicKeyInfo extension.
func (h *HybridSignerImpl) Public() crypto.PublicKey {
	return h.classical.Public()
}

// Sign signs with the classical signer only.
// This implements crypto.Signer for compatibility.
// For dual signing, use SignHybrid instead.
func (h *HybridSignerImpl) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return h.classical.Sign(rand, digest, opts)
}

// ClassicalSigner returns the classical (non-PQC) signer.
func (h *HybridSignerImpl) ClassicalSigner() Signer {
	return h.classical
}

// PQCSigner returns the PQC signer.
func (h *HybridSignerImpl) PQCSigner() Signer {
	return h.pqc
}

// SignHybrid signs the message with both classical and PQC algorithms.
// Returns classical signature, PQC signature, and any error.
//
// For Catalyst certificates:
//   - Classical signature goes in the standard X.509 signatureValue
//   - PQC signature goes in the AltSignatureValue extension
func (h *HybridSignerImpl) SignHybrid(rand io.Reader, message []byte) (classical, pqc []byte, err error) {
	// Sign with classical algorithm
	classical, err = h.classical.Sign(rand, message, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("classical signing failed: %w", err)
	}

	// Sign with PQC algorithm
	pqc, err = h.pqc.Sign(rand, message, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("PQC signing failed: %w", err)
	}

	return classical, pqc, nil
}

// VerifyHybrid verifies both classical and PQC signatures.
// Returns true only if both signatures are valid.
func (h *HybridSignerImpl) VerifyHybrid(message, classicalSig, pqcSig []byte) bool {
	classicalOK := Verify(h.classical.Algorithm(), h.classical.Public(), message, classicalSig)
	if !classicalOK {
		return false
	}

	pqcOK := Verify(h.pqc.Algorithm(), h.pqc.Public(), message, pqcSig)
	return pqcOK
}

// ClassicalAlgorithm returns the classical algorithm.
func (h *HybridSignerImpl) ClassicalAlgorithm() AlgorithmID {
	return h.classical.Algorithm()
}

// PQCAlgorithm returns the PQC algorithm.
func (h *HybridSignerImpl) PQCAlgorithm() AlgorithmID {
	return h.pqc.Algorithm()
}

// ClassicalPublicKey returns the classical public key.
func (h *HybridSignerImpl) ClassicalPublicKey() crypto.PublicKey {
	return h.classical.Public()
}

// PQCPublicKey returns the PQC public key.
func (h *HybridSignerImpl) PQCPublicKey() crypto.PublicKey {
	return h.pqc.Public()
}

// PQCPublicKeyBytes returns the raw bytes of the PQC public key.
// This is used when encoding the AltSubjectPublicKeyInfo extension.
func (h *HybridSignerImpl) PQCPublicKeyBytes() ([]byte, error) {
	kp := &KeyPair{
		Algorithm: h.pqc.Algorithm(),
		PublicKey: h.pqc.Public(),
	}
	return kp.PublicKeyBytes()
}

// SaveHybridKeys saves both keys to separate PEM files.
// classicalPath: path for the classical key
// pqcPath: path for the PQC key
func (h *HybridSignerImpl) SaveHybridKeys(classicalPath, pqcPath string, passphrase []byte) error {
	// Save classical key
	if ss, ok := h.classical.(*SoftwareSigner); ok {
		if err := ss.SavePrivateKey(classicalPath, passphrase); err != nil {
			return fmt.Errorf("failed to save classical key: %w", err)
		}
	} else {
		return fmt.Errorf("classical signer is not a SoftwareSigner")
	}

	// Save PQC key
	if ss, ok := h.pqc.(*SoftwareSigner); ok {
		if err := ss.SavePrivateKey(pqcPath, passphrase); err != nil {
			return fmt.Errorf("failed to save PQC key: %w", err)
		}
	} else {
		return fmt.Errorf("PQC signer is not a SoftwareSigner")
	}

	return nil
}

// SaveHybridKeyBundle saves both keys to a single PEM file (bundle format).
// The file contains two PEM blocks: first classical, then PQC.
func (h *HybridSignerImpl) SaveHybridKeyBundle(path string, passphrase []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create bundle file: %w", err)
	}
	defer func() { _ = f.Close() }()

	// Write classical key
	classicalSS, ok := h.classical.(*SoftwareSigner)
	if !ok {
		return fmt.Errorf("classical signer is not a SoftwareSigner")
	}
	classicalBlock, err := privateKeyToPEMBlock(classicalSS.PrivateKey(), classicalSS.Algorithm(), passphrase)
	if err != nil {
		return fmt.Errorf("failed to encode classical key: %w", err)
	}
	if err := pem.Encode(f, classicalBlock); err != nil {
		return fmt.Errorf("failed to write classical key: %w", err)
	}

	// Write PQC key
	pqcSS, ok := h.pqc.(*SoftwareSigner)
	if !ok {
		return fmt.Errorf("PQC signer is not a SoftwareSigner")
	}
	pqcBlock, err := privateKeyToPEMBlock(pqcSS.PrivateKey(), pqcSS.Algorithm(), passphrase)
	if err != nil {
		return fmt.Errorf("failed to encode PQC key: %w", err)
	}
	if err := pem.Encode(f, pqcBlock); err != nil {
		return fmt.Errorf("failed to write PQC key: %w", err)
	}

	return nil
}

// LoadHybridSigner loads a hybrid signer from two separate key files.
func LoadHybridSigner(classicalPath, pqcPath string, passphrase []byte) (*HybridSignerImpl, error) {
	classical, err := LoadPrivateKey(classicalPath, passphrase)
	if err != nil {
		return nil, fmt.Errorf("failed to load classical key: %w", err)
	}

	pqc, err := LoadPrivateKey(pqcPath, passphrase)
	if err != nil {
		return nil, fmt.Errorf("failed to load PQC key: %w", err)
	}

	return NewHybridSigner(classical, pqc)
}

// LoadHybridSignerBundle loads a hybrid signer from a bundled PEM file.
// The file should contain two PEM blocks: classical key first, then PQC key.
func LoadHybridSignerBundle(path string, passphrase []byte) (*HybridSignerImpl, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read bundle file: %w", err)
	}

	// Parse first block (classical)
	classicalBlock, rest := pem.Decode(data)
	if classicalBlock == nil {
		return nil, fmt.Errorf("no classical key PEM block found")
	}

	classical, err := parsePEMBlockToSigner(classicalBlock, passphrase)
	if err != nil {
		return nil, fmt.Errorf("failed to parse classical key: %w", err)
	}

	// Parse second block (PQC)
	pqcBlock, _ := pem.Decode(rest)
	if pqcBlock == nil {
		return nil, fmt.Errorf("no PQC key PEM block found")
	}

	pqc, err := parsePEMBlockToSigner(pqcBlock, passphrase)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PQC key: %w", err)
	}

	return NewHybridSigner(classical, pqc)
}

// ToHybridSigner creates a HybridSigner from a HybridKeyPair.
func (hkp *HybridKeyPair) ToHybridSigner() (*HybridSignerImpl, error) {
	classical, err := NewSoftwareSigner(hkp.Classical)
	if err != nil {
		return nil, fmt.Errorf("failed to create classical signer: %w", err)
	}

	pqc, err := NewSoftwareSigner(hkp.PQC)
	if err != nil {
		return nil, fmt.Errorf("failed to create PQC signer: %w", err)
	}

	return NewHybridSigner(classical, pqc)
}

// privateKeyToPEMBlock converts a private key to a PEM block.
func privateKeyToPEMBlock(priv crypto.PrivateKey, alg AlgorithmID, passphrase []byte) (*pem.Block, error) {
	var block *pem.Block

	switch p := priv.(type) {
	case *ecdsa.PrivateKey, ed25519.PrivateKey, *rsa.PrivateKey:
		der, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal private key: %w", err)
		}
		block = &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: der,
		}

	case *mldsa44.PrivateKey:
		block = &pem.Block{
			Type:  "ML-DSA-44 PRIVATE KEY",
			Bytes: p.Bytes(),
		}

	case *mldsa65.PrivateKey:
		block = &pem.Block{
			Type:  "ML-DSA-65 PRIVATE KEY",
			Bytes: p.Bytes(),
		}

	case *mldsa87.PrivateKey:
		block = &pem.Block{
			Type:  "ML-DSA-87 PRIVATE KEY",
			Bytes: p.Bytes(),
		}

	case *slhdsa.PrivateKey:
		privBytes, err := p.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal SLH-DSA key: %w", err)
		}
		block = &pem.Block{
			Type:  fmt.Sprintf("%s PRIVATE KEY", p.ID),
			Bytes: privBytes,
		}

	default:
		return nil, fmt.Errorf("unsupported private key type: %T", priv)
	}

	// Encrypt if passphrase provided
	if len(passphrase) > 0 {
		var err error
		block, err = x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, passphrase, x509.PEMCipherAES256) //nolint:staticcheck
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt private key: %w", err)
		}
	}

	return block, nil
}

// parsePEMBlockToSigner parses a PEM block into a SoftwareSigner.
func parsePEMBlockToSigner(block *pem.Block, passphrase []byte) (*SoftwareSigner, error) {
	keyBytes := block.Bytes

	// Decrypt if encrypted
	if x509.IsEncryptedPEMBlock(block) { //nolint:staticcheck
		if len(passphrase) == 0 {
			return nil, fmt.Errorf("private key is encrypted but no passphrase provided")
		}
		var err error
		keyBytes, err = x509.DecryptPEMBlock(block, passphrase) //nolint:staticcheck
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt private key: %w", err)
		}
	}

	var priv crypto.PrivateKey
	var pub crypto.PublicKey
	var alg AlgorithmID
	var err error

	switch block.Type {
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
		if slhAlg, slhID, ok := parseSLHDSAPEMType(block.Type); ok {
			var slhPriv slhdsa.PrivateKey
			slhPriv.ID = slhID
			if err := slhPriv.UnmarshalBinary(keyBytes); err != nil {
				return nil, fmt.Errorf("failed to parse %s key: %w", block.Type, err)
			}
			priv = &slhPriv
			slhPub := slhPriv.PublicKey()
			pub = &slhPub // Store pointer to public key for Verify to work
			alg = slhAlg
		} else {
			return nil, fmt.Errorf("unknown PEM type: %s", block.Type)
		}
	}

	return &SoftwareSigner{
		alg:  alg,
		priv: priv,
		pub:  pub,
	}, nil
}
