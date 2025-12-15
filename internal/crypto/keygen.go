package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign/dilithium/mode2"
	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/cloudflare/circl/sign/dilithium/mode5"
)

// KeyPair holds a public/private key pair.
type KeyPair struct {
	Algorithm  AlgorithmID
	PrivateKey crypto.PrivateKey
	PublicKey  crypto.PublicKey
}

// GenerateKeyPair generates a new key pair for the specified algorithm.
//
// Supported algorithms:
//   - Classical: ecdsa-p256, ecdsa-p384, ecdsa-p521, ed25519, rsa-2048, rsa-4096
//   - PQC: ml-dsa-44, ml-dsa-65, ml-dsa-87
//
// For hybrid algorithms, use GenerateHybridKeyPair instead.
//
// Example:
//
//	kp, err := crypto.GenerateKeyPair(crypto.AlgECDSAP256)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Generated %s key pair\n", kp.Algorithm)
func GenerateKeyPair(alg AlgorithmID) (*KeyPair, error) {
	return GenerateKeyPairWithRand(rand.Reader, alg)
}

// GenerateKeyPairWithRand generates a key pair using the provided random source.
// This is useful for testing with deterministic randomness.
func GenerateKeyPairWithRand(random io.Reader, alg AlgorithmID) (*KeyPair, error) {
	if !alg.IsValid() {
		return nil, fmt.Errorf("unsupported algorithm: %s", alg)
	}

	if alg.IsHybrid() {
		return nil, fmt.Errorf("use GenerateHybridKeyPair for hybrid algorithms: %s", alg)
	}

	var priv crypto.PrivateKey
	var pub crypto.PublicKey
	var err error

	switch alg {
	// ECDSA
	case AlgECDSAP256:
		priv, pub, err = generateECDSA(random, elliptic.P256())
	case AlgECDSAP384:
		priv, pub, err = generateECDSA(random, elliptic.P384())
	case AlgECDSAP521:
		priv, pub, err = generateECDSA(random, elliptic.P521())

	// EdDSA
	case AlgEd25519:
		priv, pub, err = generateEd25519(random)

	// RSA
	case AlgRSA2048:
		priv, pub, err = generateRSA(random, 2048)
	case AlgRSA4096:
		priv, pub, err = generateRSA(random, 4096)

	// ML-DSA (Dilithium)
	case AlgMLDSA44:
		priv, pub, err = generateMLDSA44(random)
	case AlgMLDSA65:
		priv, pub, err = generateMLDSA65(random)
	case AlgMLDSA87:
		priv, pub, err = generateMLDSA87(random)

	// ML-KEM - key generation for KEM
	case AlgMLKEM512, AlgMLKEM768, AlgMLKEM1024:
		return nil, fmt.Errorf("use GenerateKEMKeyPair for KEM algorithms: %s", alg)

	default:
		return nil, fmt.Errorf("key generation not implemented for: %s", alg)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to generate %s key: %w", alg, err)
	}

	return &KeyPair{
		Algorithm:  alg,
		PrivateKey: priv,
		PublicKey:  pub,
	}, nil
}

// generateECDSA generates an ECDSA key pair on the specified curve.
func generateECDSA(random io.Reader, curve elliptic.Curve) (crypto.PrivateKey, crypto.PublicKey, error) {
	priv, err := ecdsa.GenerateKey(curve, random)
	if err != nil {
		return nil, nil, err
	}
	return priv, &priv.PublicKey, nil
}

// generateEd25519 generates an Ed25519 key pair.
func generateEd25519(random io.Reader) (crypto.PrivateKey, crypto.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(random)
	if err != nil {
		return nil, nil, err
	}
	return priv, pub, nil
}

// generateRSA generates an RSA key pair with the specified bit size.
func generateRSA(random io.Reader, bits int) (crypto.PrivateKey, crypto.PublicKey, error) {
	priv, err := rsa.GenerateKey(random, bits)
	if err != nil {
		return nil, nil, err
	}
	return priv, &priv.PublicKey, nil
}

// ML-DSA (Dilithium) key types for type assertion.
type (
	MLDSA44PublicKey  = mode2.PublicKey
	MLDSA44PrivateKey = mode2.PrivateKey
	MLDSA65PublicKey  = mode3.PublicKey
	MLDSA65PrivateKey = mode3.PrivateKey
	MLDSA87PublicKey  = mode5.PublicKey
	MLDSA87PrivateKey = mode5.PrivateKey
)

// generateMLDSA44 generates an ML-DSA-44 (Dilithium2) key pair.
func generateMLDSA44(random io.Reader) (crypto.PrivateKey, crypto.PublicKey, error) {
	pub, priv, err := mode2.GenerateKey(random)
	if err != nil {
		return nil, nil, err
	}
	return priv, pub, nil
}

// generateMLDSA65 generates an ML-DSA-65 (Dilithium3) key pair.
func generateMLDSA65(random io.Reader) (crypto.PrivateKey, crypto.PublicKey, error) {
	pub, priv, err := mode3.GenerateKey(random)
	if err != nil {
		return nil, nil, err
	}
	return priv, pub, nil
}

// generateMLDSA87 generates an ML-DSA-87 (Dilithium5) key pair.
func generateMLDSA87(random io.Reader) (crypto.PrivateKey, crypto.PublicKey, error) {
	pub, priv, err := mode5.GenerateKey(random)
	if err != nil {
		return nil, nil, err
	}
	return priv, pub, nil
}

// HybridKeyPair holds both classical and PQC key pairs.
type HybridKeyPair struct {
	Algorithm AlgorithmID
	Classical *KeyPair
	PQC       *KeyPair
}

// GenerateHybridKeyPair generates a hybrid key pair combining classical and PQC algorithms.
//
// Supported hybrid algorithms:
//   - hybrid-p256-mldsa44: ECDSA P-256 + ML-DSA-44
//   - hybrid-p384-mldsa65: ECDSA P-384 + ML-DSA-65
//
// Example:
//
//	hkp, err := crypto.GenerateHybridKeyPair(crypto.AlgHybridP256MLDSA44)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Classical: %s, PQC: %s\n", hkp.Classical.Algorithm, hkp.PQC.Algorithm)
func GenerateHybridKeyPair(alg AlgorithmID) (*HybridKeyPair, error) {
	return GenerateHybridKeyPairWithRand(rand.Reader, alg)
}

// GenerateHybridKeyPairWithRand generates a hybrid key pair using the provided random source.
func GenerateHybridKeyPairWithRand(random io.Reader, alg AlgorithmID) (*HybridKeyPair, error) {
	if !alg.IsHybrid() {
		return nil, fmt.Errorf("not a hybrid algorithm: %s", alg)
	}

	var classicalAlg, pqcAlg AlgorithmID

	switch alg {
	case AlgHybridP256MLDSA44:
		classicalAlg = AlgECDSAP256
		pqcAlg = AlgMLDSA44
	case AlgHybridP384MLDSA65:
		classicalAlg = AlgECDSAP384
		pqcAlg = AlgMLDSA65
	case AlgHybridX25519MLKEM768:
		return nil, fmt.Errorf("X25519+ML-KEM hybrid not yet implemented")
	default:
		return nil, fmt.Errorf("unknown hybrid algorithm: %s", alg)
	}

	classical, err := GenerateKeyPairWithRand(random, classicalAlg)
	if err != nil {
		return nil, fmt.Errorf("failed to generate classical key: %w", err)
	}

	pqc, err := GenerateKeyPairWithRand(random, pqcAlg)
	if err != nil {
		return nil, fmt.Errorf("failed to generate PQC key: %w", err)
	}

	return &HybridKeyPair{
		Algorithm: alg,
		Classical: classical,
		PQC:       pqc,
	}, nil
}

// PublicKeyBytes returns the public key encoded as bytes.
// The encoding depends on the algorithm type.
func (kp *KeyPair) PublicKeyBytes() ([]byte, error) {
	switch pub := kp.PublicKey.(type) {
	case *ecdsa.PublicKey:
		// Use uncompressed point encoding for X.509 compatibility
		//nolint:staticcheck // elliptic.Marshal is deprecated but still needed for X.509
		return elliptic.Marshal(pub.Curve, pub.X, pub.Y), nil
	case ed25519.PublicKey:
		return pub, nil
	case *rsa.PublicKey:
		// For RSA, we'd need to use x509 encoding
		return nil, fmt.Errorf("RSA public key bytes not implemented")
	case *mode2.PublicKey:
		return pub.Bytes(), nil
	case *mode3.PublicKey:
		return pub.Bytes(), nil
	case *mode5.PublicKey:
		return pub.Bytes(), nil
	default:
		return nil, fmt.Errorf("unknown public key type: %T", pub)
	}
}
