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

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/kem/mlkem/mlkem512"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/sign/dilithium/mode2"
	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/cloudflare/circl/sign/dilithium/mode5"
	"github.com/cloudflare/circl/sign/slhdsa"
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
//   - PQC ML-DSA: ml-dsa-44, ml-dsa-65, ml-dsa-87
//   - PQC SLH-DSA: slh-dsa-128s, slh-dsa-128f, slh-dsa-192s, slh-dsa-192f, slh-dsa-256s, slh-dsa-256f
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
	// ECDSA (including ec-* aliases used by profiles)
	case AlgECDSAP256, AlgECP256:
		priv, pub, err = generateECDSA(random, elliptic.P256())
	case AlgECDSAP384, AlgECP384:
		priv, pub, err = generateECDSA(random, elliptic.P384())
	case AlgECDSAP521, AlgECP521:
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

	// SLH-DSA (SPHINCS+)
	case AlgSLHDSA128s:
		priv, pub, err = generateSLHDSA(random, slhdsa.SHA2_128s)
	case AlgSLHDSA128f:
		priv, pub, err = generateSLHDSA(random, slhdsa.SHA2_128f)
	case AlgSLHDSA192s:
		priv, pub, err = generateSLHDSA(random, slhdsa.SHA2_192s)
	case AlgSLHDSA192f:
		priv, pub, err = generateSLHDSA(random, slhdsa.SHA2_192f)
	case AlgSLHDSA256s:
		priv, pub, err = generateSLHDSA(random, slhdsa.SHA2_256s)
	case AlgSLHDSA256f:
		priv, pub, err = generateSLHDSA(random, slhdsa.SHA2_256f)

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

// SLH-DSA key types for type assertion.
type (
	SLHDSAPublicKey  = slhdsa.PublicKey
	SLHDSAPrivateKey = slhdsa.PrivateKey
)

// generateSLHDSA generates an SLH-DSA key pair for the specified parameter set.
func generateSLHDSA(random io.Reader, id slhdsa.ID) (crypto.PrivateKey, crypto.PublicKey, error) {
	pub, priv, err := slhdsa.GenerateKey(random, id)
	if err != nil {
		return nil, nil, err
	}
	return &priv, &pub, nil
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

// ParsePublicKey parses raw public key bytes into a crypto.PublicKey.
// This is the inverse of KeyPair.PublicKeyBytes().
func ParsePublicKey(alg AlgorithmID, data []byte) (crypto.PublicKey, error) {
	switch alg {
	case AlgMLDSA44:
		var pub mode2.PublicKey
		if err := pub.UnmarshalBinary(data); err != nil {
			return nil, fmt.Errorf("failed to parse ML-DSA-44 public key: %w", err)
		}
		return &pub, nil

	case AlgMLDSA65:
		var pub mode3.PublicKey
		if err := pub.UnmarshalBinary(data); err != nil {
			return nil, fmt.Errorf("failed to parse ML-DSA-65 public key: %w", err)
		}
		return &pub, nil

	case AlgMLDSA87:
		var pub mode5.PublicKey
		if err := pub.UnmarshalBinary(data); err != nil {
			return nil, fmt.Errorf("failed to parse ML-DSA-87 public key: %w", err)
		}
		return &pub, nil

	case AlgSLHDSA128s, AlgSLHDSA128f, AlgSLHDSA192s, AlgSLHDSA192f, AlgSLHDSA256s, AlgSLHDSA256f:
		var pub slhdsa.PublicKey
		pub.ID = algorithmToSLHDSAID(alg)
		if err := pub.UnmarshalBinary(data); err != nil {
			return nil, fmt.Errorf("failed to parse %s public key: %w", alg, err)
		}
		return &pub, nil

	case AlgECDSAP256:
		// Note: elliptic.Unmarshal is deprecated since Go 1.21 in favor of crypto/ecdh,
		// but crypto/ecdh is for ECDH key agreement, not ECDSA signing. There's no
		// direct replacement for parsing raw ECDSA public keys from uncompressed points.
		x, y := elliptic.Unmarshal(elliptic.P256(), data) //nolint:staticcheck // No ECDSA alternative
		if x == nil {
			return nil, fmt.Errorf("failed to parse P-256 public key")
		}
		return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil

	case AlgECDSAP384:
		x, y := elliptic.Unmarshal(elliptic.P384(), data) //nolint:staticcheck // No ECDSA alternative
		if x == nil {
			return nil, fmt.Errorf("failed to parse P-384 public key")
		}
		return &ecdsa.PublicKey{Curve: elliptic.P384(), X: x, Y: y}, nil

	case AlgECDSAP521:
		x, y := elliptic.Unmarshal(elliptic.P521(), data) //nolint:staticcheck // No ECDSA alternative
		if x == nil {
			return nil, fmt.Errorf("failed to parse P-521 public key")
		}
		return &ecdsa.PublicKey{Curve: elliptic.P521(), X: x, Y: y}, nil

	case AlgEd25519:
		if len(data) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid Ed25519 public key size: %d", len(data))
		}
		return ed25519.PublicKey(data), nil

	default:
		return nil, fmt.Errorf("unsupported algorithm for public key parsing: %s", alg)
	}
}

// algorithmToSLHDSAID maps AlgorithmID to slhdsa.ID.
func algorithmToSLHDSAID(alg AlgorithmID) slhdsa.ID {
	switch alg {
	case AlgSLHDSA128s:
		return slhdsa.SHA2_128s
	case AlgSLHDSA128f:
		return slhdsa.SHA2_128f
	case AlgSLHDSA192s:
		return slhdsa.SHA2_192s
	case AlgSLHDSA192f:
		return slhdsa.SHA2_192f
	case AlgSLHDSA256s:
		return slhdsa.SHA2_256s
	case AlgSLHDSA256f:
		return slhdsa.SHA2_256f
	default:
		return 0
	}
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
	case *slhdsa.PublicKey:
		return pub.MarshalBinary()
	case *mlkem512.PublicKey:
		return pub.MarshalBinary()
	case *mlkem768.PublicKey:
		return pub.MarshalBinary()
	case *mlkem1024.PublicKey:
		return pub.MarshalBinary()
	default:
		return nil, fmt.Errorf("unknown public key type: %T", pub)
	}
}

// ML-KEM key types for type assertion.
type (
	MLKEM512PublicKey   = mlkem512.PublicKey
	MLKEM512PrivateKey  = mlkem512.PrivateKey
	MLKEM768PublicKey   = mlkem768.PublicKey
	MLKEM768PrivateKey  = mlkem768.PrivateKey
	MLKEM1024PublicKey  = mlkem1024.PublicKey
	MLKEM1024PrivateKey = mlkem1024.PrivateKey
)

// KEMKeyPair holds a KEM public/private key pair.
type KEMKeyPair struct {
	Algorithm  AlgorithmID
	PrivateKey crypto.PrivateKey
	PublicKey  crypto.PublicKey
}

// GenerateKEMKeyPair generates a new ML-KEM key pair.
func GenerateKEMKeyPair(alg AlgorithmID) (*KEMKeyPair, error) {
	return GenerateKEMKeyPairWithRand(rand.Reader, alg)
}

// GenerateKEMKeyPairWithRand generates a KEM key pair using the provided random source.
func GenerateKEMKeyPairWithRand(random io.Reader, alg AlgorithmID) (*KEMKeyPair, error) {
	var priv crypto.PrivateKey
	var pub crypto.PublicKey
	var err error

	switch alg {
	case AlgMLKEM512:
		pub, priv, err = mlkem512.GenerateKeyPair(random)
	case AlgMLKEM768:
		pub, priv, err = mlkem768.GenerateKeyPair(random)
	case AlgMLKEM1024:
		pub, priv, err = mlkem1024.GenerateKeyPair(random)
	default:
		return nil, fmt.Errorf("unsupported KEM algorithm: %s", alg)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to generate %s key pair: %w", alg, err)
	}

	return &KEMKeyPair{
		Algorithm:  alg,
		PrivateKey: priv,
		PublicKey:  pub,
	}, nil
}

// ParseMLKEMPublicKey parses raw ML-KEM public key bytes.
func ParseMLKEMPublicKey(alg AlgorithmID, data []byte) (crypto.PublicKey, error) {
	var scheme kem.Scheme

	switch alg {
	case AlgMLKEM512:
		scheme = mlkem512.Scheme()
	case AlgMLKEM768:
		scheme = mlkem768.Scheme()
	case AlgMLKEM1024:
		scheme = mlkem1024.Scheme()
	default:
		return nil, fmt.Errorf("unsupported KEM algorithm: %s", alg)
	}

	pub, err := scheme.UnmarshalBinaryPublicKey(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s public key: %w", alg, err)
	}

	return pub, nil
}

// ParseMLKEMPrivateKey parses raw ML-KEM private key bytes.
func ParseMLKEMPrivateKey(alg AlgorithmID, data []byte) (crypto.PrivateKey, error) {
	var scheme kem.Scheme

	switch alg {
	case AlgMLKEM512:
		scheme = mlkem512.Scheme()
	case AlgMLKEM768:
		scheme = mlkem768.Scheme()
	case AlgMLKEM1024:
		scheme = mlkem1024.Scheme()
	default:
		return nil, fmt.Errorf("unsupported KEM algorithm: %s", alg)
	}

	priv, err := scheme.UnmarshalBinaryPrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s private key: %w", alg, err)
	}

	return priv, nil
}

// MLKEMPublicKeyBytes returns the raw bytes of an ML-KEM public key.
func MLKEMPublicKeyBytes(pub crypto.PublicKey) ([]byte, error) {
	switch k := pub.(type) {
	case *mlkem512.PublicKey:
		return k.MarshalBinary()
	case *mlkem768.PublicKey:
		return k.MarshalBinary()
	case *mlkem1024.PublicKey:
		return k.MarshalBinary()
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", pub)
	}
}

// MLKEMPrivateKeyBytes returns the raw bytes of an ML-KEM private key.
func MLKEMPrivateKeyBytes(priv crypto.PrivateKey) ([]byte, error) {
	switch k := priv.(type) {
	case *mlkem512.PrivateKey:
		return k.MarshalBinary()
	case *mlkem768.PrivateKey:
		return k.MarshalBinary()
	case *mlkem1024.PrivateKey:
		return k.MarshalBinary()
	default:
		return nil, fmt.Errorf("unsupported private key type: %T", priv)
	}
}
