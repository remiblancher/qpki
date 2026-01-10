// Package crypto provides cryptographic primitives for the PKI.
package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/kem/mlkem/mlkem512"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/cloudflare/circl/sign/slhdsa"
)

// Operation represents a cryptographic operation type.
type Operation int

const (
	OpSign Operation = 1 << iota
	OpVerify
	OpEncapsulate
	OpDecapsulate
	OpEncrypt
	OpDecrypt
)

// CryptoContext provides a unified interface for cryptographic operations.
// It encapsulates algorithm-specific logic and supports signing, verification,
// and KEM operations through a single interface.
//
// Use NewSigningContext or NewVerificationContext to create instances.
type CryptoContext interface {
	// Algorithm returns the algorithm identifier.
	Algorithm() AlgorithmID

	// SupportsOperation returns true if the context supports the given operation.
	SupportsOperation(op Operation) bool

	// Sign signs the message and returns the signature.
	// Returns an error if signing is not supported.
	Sign(rand io.Reader, message []byte) ([]byte, error)

	// Verify verifies a signature against a message.
	// Returns an error if verification is not supported.
	Verify(message, signature []byte) error

	// PublicKey returns the public key associated with this context.
	PublicKey() crypto.PublicKey
}

// KEMContext extends CryptoContext with Key Encapsulation Mechanism operations.
type KEMContext interface {
	CryptoContext

	// Encapsulate generates a shared secret and ciphertext for the public key.
	// Returns (ciphertext, sharedSecret, error).
	Encapsulate() ([]byte, []byte, error)

	// Decapsulate recovers the shared secret from a ciphertext.
	// Returns (sharedSecret, error).
	Decapsulate(ciphertext []byte) ([]byte, error)
}

// HybridContext extends CryptoContext for hybrid (classical + PQC) operations.
type HybridContext interface {
	CryptoContext

	// ClassicalContext returns the classical algorithm context.
	ClassicalContext() CryptoContext

	// PQCContext returns the post-quantum algorithm context.
	PQCContext() CryptoContext

	// SignBoth signs with both algorithms and returns both signatures.
	SignBoth(rand io.Reader, message []byte) (classical, pqc []byte, err error)

	// VerifyBoth verifies both signatures.
	VerifyBoth(message, classicalSig, pqcSig []byte) error
}

// signingContext implements CryptoContext for signing operations.
type signingContext struct {
	signer Signer
}

// NewSigningContext creates a CryptoContext from a Signer.
func NewSigningContext(signer Signer) CryptoContext {
	if signer == nil {
		return nil
	}

	// Check if it's a hybrid signer
	if hs, ok := signer.(HybridSigner); ok {
		return &hybridSigningContext{
			signer:    hs,
			classical: NewSigningContext(hs.ClassicalSigner()),
			pqc:       NewSigningContext(hs.PQCSigner()),
		}
	}

	return &signingContext{signer: signer}
}

func (c *signingContext) Algorithm() AlgorithmID {
	return c.signer.Algorithm()
}

func (c *signingContext) SupportsOperation(op Operation) bool {
	alg := c.signer.Algorithm()
	switch op {
	case OpSign:
		// KEM keys cannot sign
		return !alg.IsKEM()
	case OpVerify:
		return alg.IsSignature() || alg.IsHybrid()
	case OpEncapsulate, OpDecapsulate:
		return alg.IsKEM()
	default:
		return false
	}
}

func (c *signingContext) Sign(rand io.Reader, message []byte) ([]byte, error) {
	if !c.SupportsOperation(OpSign) {
		return nil, fmt.Errorf("algorithm %s does not support signing", c.signer.Algorithm())
	}

	alg := c.signer.Algorithm()

	// For PQC algorithms (ML-DSA, SLH-DSA), sign the message directly (pure mode)
	// For classical algorithms, the message should be pre-hashed by the caller
	if alg.IsPQC() {
		return c.signer.Sign(rand, message, crypto.Hash(0))
	}

	// Classical algorithms - message is expected to be a digest
	return c.signer.Sign(rand, message, nil)
}

func (c *signingContext) Verify(message, signature []byte) error {
	if !c.SupportsOperation(OpVerify) {
		return fmt.Errorf("algorithm %s does not support verification", c.signer.Algorithm())
	}

	if !Verify(c.signer.Algorithm(), c.signer.Public(), message, signature) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

func (c *signingContext) PublicKey() crypto.PublicKey {
	return c.signer.Public()
}

// verificationContext implements CryptoContext for verification-only operations.
type verificationContext struct {
	alg AlgorithmID
	pub crypto.PublicKey
}

// NewVerificationContext creates a CryptoContext for verification only.
func NewVerificationContext(alg AlgorithmID, pub crypto.PublicKey) CryptoContext {
	return &verificationContext{
		alg: alg,
		pub: pub,
	}
}

func (c *verificationContext) Algorithm() AlgorithmID {
	return c.alg
}

func (c *verificationContext) SupportsOperation(op Operation) bool {
	switch op {
	case OpVerify:
		return c.alg.IsSignature() || c.alg.IsHybrid()
	case OpEncapsulate:
		return c.alg.IsKEM()
	default:
		return false
	}
}

func (c *verificationContext) Sign(_ io.Reader, _ []byte) ([]byte, error) {
	return nil, fmt.Errorf("verification context does not support signing")
}

func (c *verificationContext) Verify(message, signature []byte) error {
	if !c.SupportsOperation(OpVerify) {
		return fmt.Errorf("algorithm %s does not support verification", c.alg)
	}

	if !Verify(c.alg, c.pub, message, signature) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

func (c *verificationContext) PublicKey() crypto.PublicKey {
	return c.pub
}

// hybridSigningContext implements HybridContext for hybrid signers.
type hybridSigningContext struct {
	signer    HybridSigner
	classical CryptoContext
	pqc       CryptoContext
}

// Ensure hybridSigningContext implements HybridContext.
var _ HybridContext = (*hybridSigningContext)(nil)

func (c *hybridSigningContext) Algorithm() AlgorithmID {
	return c.signer.Algorithm()
}

func (c *hybridSigningContext) SupportsOperation(op Operation) bool {
	switch op {
	case OpSign, OpVerify:
		return true
	default:
		return false
	}
}

func (c *hybridSigningContext) Sign(rand io.Reader, message []byte) ([]byte, error) {
	// For hybrid, use classical signature by default (Catalyst mode)
	return c.classical.Sign(rand, message)
}

func (c *hybridSigningContext) Verify(message, signature []byte) error {
	// Try classical verification first
	return c.classical.Verify(message, signature)
}

func (c *hybridSigningContext) PublicKey() crypto.PublicKey {
	return c.signer.Public()
}

func (c *hybridSigningContext) ClassicalContext() CryptoContext {
	return c.classical
}

func (c *hybridSigningContext) PQCContext() CryptoContext {
	return c.pqc
}

func (c *hybridSigningContext) SignBoth(rand io.Reader, message []byte) (classical, pqc []byte, err error) {
	return c.signer.SignHybrid(rand, message)
}

func (c *hybridSigningContext) VerifyBoth(message, classicalSig, pqcSig []byte) error {
	if err := c.classical.Verify(message, classicalSig); err != nil {
		return fmt.Errorf("classical verification failed: %w", err)
	}
	if err := c.pqc.Verify(message, pqcSig); err != nil {
		return fmt.Errorf("PQC verification failed: %w", err)
	}
	return nil
}

// NewContextFromCertificate creates a verification context from an X.509 certificate.
func NewContextFromCertificate(cert *x509.Certificate) (CryptoContext, error) {
	if cert == nil {
		return nil, fmt.Errorf("certificate is nil")
	}

	alg := AlgorithmFromPublicKey(cert.PublicKey)
	if alg == AlgUnknown {
		return nil, fmt.Errorf("unknown algorithm for public key type %T", cert.PublicKey)
	}

	return NewVerificationContext(alg, cert.PublicKey), nil
}

// AlgorithmFromPublicKey determines the AlgorithmID from a public key.
func AlgorithmFromPublicKey(pub crypto.PublicKey) AlgorithmID {
	return detectAlgorithmFromPublicKey(pub)
}

// detectAlgorithmFromPublicKey infers the algorithm from a public key type.
func detectAlgorithmFromPublicKey(pub crypto.PublicKey) AlgorithmID {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve.Params().BitSize {
		case 256:
			return AlgECDSAP256
		case 384:
			return AlgECDSAP384
		case 521:
			return AlgECDSAP521
		}
	case ed25519.PublicKey:
		return AlgEd25519
	case *rsa.PublicKey:
		if k.N.BitLen() <= 2048 {
			return AlgRSA2048
		}
		return AlgRSA4096
	case *mldsa44.PublicKey:
		return AlgMLDSA44
	case *mldsa65.PublicKey:
		return AlgMLDSA65
	case *mldsa87.PublicKey:
		return AlgMLDSA87
	// SLH-DSA can be value or pointer type
	case *slhdsa.PublicKey:
		return slhdsaAlgorithmFromID(k.ID)
	case slhdsa.PublicKey:
		return slhdsaAlgorithmFromID(k.ID)
	case *mlkem512.PublicKey:
		return AlgMLKEM512
	case *mlkem768.PublicKey:
		return AlgMLKEM768
	case *mlkem1024.PublicKey:
		return AlgMLKEM1024
	}
	return AlgUnknown
}

// slhdsaAlgorithmFromID maps SLH-DSA ID to AlgorithmID.
func slhdsaAlgorithmFromID(id slhdsa.ID) AlgorithmID {
	switch id {
	case slhdsa.SHA2_128s:
		return AlgSLHDSA128s
	case slhdsa.SHA2_128f:
		return AlgSLHDSA128f
	case slhdsa.SHA2_192s:
		return AlgSLHDSA192s
	case slhdsa.SHA2_192f:
		return AlgSLHDSA192f
	case slhdsa.SHA2_256s:
		return AlgSLHDSA256s
	case slhdsa.SHA2_256f:
		return AlgSLHDSA256f
	default:
		return AlgUnknown
	}
}

// =============================================================================
// KEM Context Implementation
// =============================================================================

// kemContext implements KEMContext for ML-KEM operations.
type kemContext struct {
	alg  AlgorithmID
	priv crypto.PrivateKey // nil for encapsulation-only contexts
	pub  crypto.PublicKey
}

// Ensure kemContext implements KEMContext.
var _ KEMContext = (*kemContext)(nil)

// NewKEMContext creates a KEMContext from a KEM key pair.
// The context can perform both encapsulation and decapsulation.
func NewKEMContext(kp *KEMKeyPair) (KEMContext, error) {
	if kp == nil {
		return nil, fmt.Errorf("KEM key pair is nil")
	}
	if !kp.Algorithm.IsKEM() {
		return nil, fmt.Errorf("not a KEM algorithm: %s", kp.Algorithm)
	}
	return &kemContext{
		alg:  kp.Algorithm,
		priv: kp.PrivateKey,
		pub:  kp.PublicKey,
	}, nil
}

// NewKEMContextForEncapsulation creates a KEMContext from a public key.
// The context can only perform encapsulation (not decapsulation).
func NewKEMContextForEncapsulation(alg AlgorithmID, pub crypto.PublicKey) (KEMContext, error) {
	if !alg.IsKEM() {
		return nil, fmt.Errorf("not a KEM algorithm: %s", alg)
	}
	return &kemContext{
		alg: alg,
		pub: pub,
	}, nil
}

func (c *kemContext) Algorithm() AlgorithmID {
	return c.alg
}

func (c *kemContext) SupportsOperation(op Operation) bool {
	switch op {
	case OpEncapsulate:
		return c.pub != nil
	case OpDecapsulate:
		return c.priv != nil
	default:
		return false
	}
}

func (c *kemContext) Sign(_ io.Reader, _ []byte) ([]byte, error) {
	return nil, fmt.Errorf("KEM context does not support signing")
}

func (c *kemContext) Verify(_, _ []byte) error {
	return fmt.Errorf("KEM context does not support verification")
}

func (c *kemContext) PublicKey() crypto.PublicKey {
	return c.pub
}

// Encapsulate generates a shared secret and ciphertext for the public key.
func (c *kemContext) Encapsulate() (ciphertext, sharedSecret []byte, err error) {
	if c.pub == nil {
		return nil, nil, fmt.Errorf("no public key available for encapsulation")
	}

	// Get the appropriate scheme
	var scheme kem.Scheme
	switch c.alg {
	case AlgMLKEM512:
		scheme = mlkem512.Scheme()
	case AlgMLKEM768:
		scheme = mlkem768.Scheme()
	case AlgMLKEM1024:
		scheme = mlkem1024.Scheme()
	default:
		return nil, nil, fmt.Errorf("unsupported KEM algorithm: %s", c.alg)
	}

	// Cast to kem.PublicKey interface
	kemPub, ok := c.pub.(kem.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("public key does not implement kem.PublicKey: %T", c.pub)
	}

	ct, ss, err := scheme.Encapsulate(kemPub)
	if err != nil {
		return nil, nil, fmt.Errorf("%s encapsulation failed: %w", c.alg, err)
	}
	return ct, ss, nil
}

// Decapsulate recovers the shared secret from a ciphertext.
func (c *kemContext) Decapsulate(ciphertext []byte) (sharedSecret []byte, err error) {
	if c.priv == nil {
		return nil, fmt.Errorf("no private key available for decapsulation")
	}

	// Get the appropriate scheme
	var scheme kem.Scheme
	switch c.alg {
	case AlgMLKEM512:
		scheme = mlkem512.Scheme()
	case AlgMLKEM768:
		scheme = mlkem768.Scheme()
	case AlgMLKEM1024:
		scheme = mlkem1024.Scheme()
	default:
		return nil, fmt.Errorf("unsupported KEM algorithm: %s", c.alg)
	}

	// Cast to kem.PrivateKey interface
	kemPriv, ok := c.priv.(kem.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key does not implement kem.PrivateKey: %T", c.priv)
	}

	ss, err := scheme.Decapsulate(kemPriv, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("%s decapsulation failed: %w", c.alg, err)
	}
	return ss, nil
}
