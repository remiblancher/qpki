package cose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/cloudflare/circl/sign/slhdsa"
	gocose "github.com/veraison/go-cose"
)

// Signer wraps a crypto.Signer to implement gocose.Signer.
// It handles the differences between classical algorithms (which use pre-hashing)
// and PQC algorithms (which sign raw data).
type Signer struct {
	signer    crypto.Signer
	algorithm gocose.Algorithm
}

// NewSigner creates a new COSE signer from a crypto.Signer.
func NewSigner(s crypto.Signer) (*Signer, error) {
	alg, err := COSEAlgorithmFromKey(s.Public())
	if err != nil {
		return nil, fmt.Errorf("failed to determine algorithm: %w", err)
	}
	return &Signer{
		signer:    s,
		algorithm: alg,
	}, nil
}

// NewSignerWithAlgorithm creates a new COSE signer with an explicit algorithm.
func NewSignerWithAlgorithm(s crypto.Signer, alg gocose.Algorithm) *Signer {
	return &Signer{
		signer:    s,
		algorithm: alg,
	}
}

// Algorithm returns the COSE algorithm identifier.
func (s *Signer) Algorithm() gocose.Algorithm {
	return s.algorithm
}

// Sign signs the given data.
// For COSE Sign1/Sign, the data is the Sig_structure (to-be-signed bytes).
func (s *Signer) Sign(rand2 io.Reader, data []byte) ([]byte, error) {
	// PQC algorithms sign raw data without pre-hashing
	if IsPQCAlgorithm(s.algorithm) {
		return s.signPQC(data)
	}
	// Classical algorithms use pre-hashing
	return s.signClassical(data)
}

// signClassical signs data using classical algorithms with pre-hashing.
func (s *Signer) signClassical(data []byte) ([]byte, error) {
	var hash crypto.Hash
	switch s.algorithm {
	case AlgES256, AlgPS256:
		hash = crypto.SHA256
	case AlgES384, AlgPS384:
		hash = crypto.SHA384
	case AlgES512, AlgPS512:
		hash = crypto.SHA512
	case AlgEdDSA:
		// EdDSA signs raw data
		return s.signer.Sign(rand.Reader, data, crypto.Hash(0))
	default:
		return nil, fmt.Errorf("unsupported classical algorithm: %d", s.algorithm)
	}

	h := hash.New()
	h.Write(data)
	digest := h.Sum(nil)

	// For RSA-PSS, use PSS options
	var opts crypto.SignerOpts = hash
	if _, ok := s.signer.Public().(*rsa.PublicKey); ok {
		opts = &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       hash,
		}
	}

	// Sign the digest
	sig, err := s.signer.Sign(rand.Reader, digest, opts)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}

	// For ECDSA, convert from ASN.1 DER to raw R||S format
	if _, ok := s.signer.Public().(*ecdsa.PublicKey); ok {
		return ecdsaDERToRaw(sig, s.algorithm)
	}

	return sig, nil
}

// signPQC signs data using PQC algorithms (sign raw data without hashing).
func (s *Signer) signPQC(data []byte) ([]byte, error) {
	switch key := s.signer.(type) {
	case *mldsa44.PrivateKey:
		// ML-DSA implements crypto.Signer - use Sign with Hash(0) for pure mode
		return key.Sign(rand.Reader, data, crypto.Hash(0))
	case *mldsa65.PrivateKey:
		return key.Sign(rand.Reader, data, crypto.Hash(0))
	case *mldsa87.PrivateKey:
		return key.Sign(rand.Reader, data, crypto.Hash(0))
	case *slhdsa.PrivateKey:
		// SLH-DSA implements crypto.Signer - use Sign with nil opts
		return key.Sign(rand.Reader, data, nil)
	default:
		// Try using the crypto.Signer interface
		return s.signer.Sign(rand.Reader, data, crypto.Hash(0))
	}
}

// ecdsaDERToRaw converts an ECDSA signature from ASN.1 DER to raw R||S format.
func ecdsaDERToRaw(sig []byte, alg gocose.Algorithm) ([]byte, error) {
	// Parse ASN.1 DER signature
	r, sVal, err := parseECDSASignature(sig)
	if err != nil {
		return nil, err
	}

	// Determine the byte length based on curve
	var byteLen int
	switch alg {
	case AlgES256:
		byteLen = 32
	case AlgES384:
		byteLen = 48
	case AlgES512:
		byteLen = 66
	default:
		return nil, fmt.Errorf("unknown ECDSA algorithm: %d", alg)
	}

	// Convert to fixed-size format
	raw := make([]byte, byteLen*2)
	rBytes := r.Bytes()
	sBytes := sVal.Bytes()
	copy(raw[byteLen-len(rBytes):byteLen], rBytes)
	copy(raw[2*byteLen-len(sBytes):], sBytes)

	return raw, nil
}

// parseECDSASignature parses an ASN.1 DER encoded ECDSA signature.
func parseECDSASignature(sig []byte) (r, s interface{ Bytes() []byte }, err error) {
	// Use dedicated ASN.1 parser
	return parseASN1ECDSASig(sig)
}

// bigIntBytes is a helper interface for big.Int-like types
type bigIntBytes interface {
	Bytes() []byte
}

// parseASN1ECDSASig parses an ASN.1 DER encoded ECDSA signature.
func parseASN1ECDSASig(sig []byte) (r, s bigIntBytes, err error) {
	// Parse ASN.1: SEQUENCE { INTEGER r, INTEGER s }
	if len(sig) < 6 {
		return nil, nil, fmt.Errorf("signature too short")
	}

	// Check SEQUENCE tag
	if sig[0] != 0x30 {
		return nil, nil, fmt.Errorf("expected SEQUENCE tag, got %02x", sig[0])
	}

	// Get sequence length (handle long-form length encoding)
	pos := 1
	_, pos, err = parseASN1Length(sig, pos)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid sequence length: %w", err)
	}

	// Parse R
	if sig[pos] != 0x02 {
		return nil, nil, fmt.Errorf("expected INTEGER tag for R, got %02x", sig[pos])
	}
	pos++
	rLen, pos, err := parseASN1Length(sig, pos)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid R length: %w", err)
	}
	if pos+rLen > len(sig) {
		return nil, nil, fmt.Errorf("r length exceeds signature")
	}
	rBytes := sig[pos : pos+rLen]
	pos += rLen

	// Parse S
	if pos >= len(sig) || sig[pos] != 0x02 {
		return nil, nil, fmt.Errorf("expected INTEGER tag for S")
	}
	pos++
	sLen, pos, err := parseASN1Length(sig, pos)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid S length: %w", err)
	}
	if pos+sLen > len(sig) {
		return nil, nil, fmt.Errorf("s length exceeds signature")
	}
	sBytes := sig[pos : pos+sLen]

	// Remove leading zero if present (ASN.1 encoding of positive integers)
	if len(rBytes) > 0 && rBytes[0] == 0 {
		rBytes = rBytes[1:]
	}
	if len(sBytes) > 0 && sBytes[0] == 0 {
		sBytes = sBytes[1:]
	}

	return &bytesWrapper{rBytes}, &bytesWrapper{sBytes}, nil
}

// parseASN1Length parses an ASN.1 DER length field at the given position.
// Returns the length value and the new position after the length field.
func parseASN1Length(data []byte, pos int) (int, int, error) {
	if pos >= len(data) {
		return 0, pos, fmt.Errorf("unexpected end of data")
	}

	b := data[pos]
	pos++

	if b < 0x80 {
		// Short form: length is in this byte
		return int(b), pos, nil
	}

	// Long form: b & 0x7f = number of bytes for length
	numBytes := int(b & 0x7f)
	if numBytes == 0 || numBytes > 4 {
		return 0, pos, fmt.Errorf("invalid length encoding")
	}
	if pos+numBytes > len(data) {
		return 0, pos, fmt.Errorf("unexpected end of data in length")
	}

	length := 0
	for i := 0; i < numBytes; i++ {
		length = (length << 8) | int(data[pos])
		pos++
	}

	return length, pos, nil
}

// bytesWrapper wraps a byte slice to implement Bytes().
type bytesWrapper struct {
	b []byte
}

func (w *bytesWrapper) Bytes() []byte {
	return w.b
}

// PublicKey returns the public key of the signer.
func (s *Signer) PublicKey() crypto.PublicKey {
	return s.signer.Public()
}

// Verify verifies a signature (for testing purposes).
func (s *Signer) Verify(data, signature []byte) error {
	return Verify(s.signer.Public(), s.algorithm, data, signature)
}

// Verify verifies a signature using the given public key and algorithm.
func Verify(pub crypto.PublicKey, alg gocose.Algorithm, data, signature []byte) error {
	if IsPQCAlgorithm(alg) {
		return verifyPQC(pub, data, signature)
	}
	return verifyClassical(pub, alg, data, signature)
}

// verifyClassical verifies a signature using classical algorithms.
func verifyClassical(pub crypto.PublicKey, alg gocose.Algorithm, data, signature []byte) error {
	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		return verifyECDSA(key, alg, data, signature)
	case ed25519.PublicKey:
		if !ed25519.Verify(key, data, signature) {
			return fmt.Errorf("Ed25519 signature verification failed")
		}
		return nil
	case *rsa.PublicKey:
		return verifyRSAPSS(key, alg, data, signature)
	default:
		return fmt.Errorf("unsupported public key type: %T", pub)
	}
}

// verifyECDSA verifies an ECDSA signature in raw R||S format.
func verifyECDSA(pub *ecdsa.PublicKey, alg gocose.Algorithm, data, signature []byte) error {
	// Determine hash and byte length
	var hash crypto.Hash
	var byteLen int
	switch alg {
	case AlgES256:
		hash = crypto.SHA256
		byteLen = 32
	case AlgES384:
		hash = crypto.SHA384
		byteLen = 48
	case AlgES512:
		hash = crypto.SHA512
		byteLen = 66
	default:
		return fmt.Errorf("unsupported ECDSA algorithm: %d", alg)
	}

	if len(signature) != byteLen*2 {
		return fmt.Errorf("invalid signature length: expected %d, got %d", byteLen*2, len(signature))
	}

	// Hash the data
	h := hash.New()
	h.Write(data)
	digest := h.Sum(nil)

	// Extract R and S from raw format
	r := signature[:byteLen]
	s := signature[byteLen:]

	// Verify using ECDSA
	if !ecdsa.VerifyASN1(pub, digest, ecdsaRawToASN1(r, s)) {
		return fmt.Errorf("ECDSA signature verification failed")
	}
	return nil
}

// ecdsaRawToASN1 converts raw R||S to ASN.1 DER format.
func ecdsaRawToASN1(r, s []byte) []byte {
	// Remove leading zeros for encoding
	for len(r) > 1 && r[0] == 0 {
		r = r[1:]
	}
	for len(s) > 1 && s[0] == 0 {
		s = s[1:]
	}

	// Add leading zero if high bit is set (for positive integer encoding)
	if r[0]&0x80 != 0 {
		r = append([]byte{0}, r...)
	}
	if s[0]&0x80 != 0 {
		s = append([]byte{0}, s...)
	}

	// Build ASN.1 SEQUENCE { INTEGER r, INTEGER s }
	rEnc := encodeASN1Integer(r)
	sEnc := encodeASN1Integer(s)
	content := append(rEnc, sEnc...)
	return encodeASN1Sequence(content)
}

// encodeASN1Integer encodes a byte slice as an ASN.1 INTEGER.
func encodeASN1Integer(data []byte) []byte {
	return append(encodeASN1Tag(0x02, len(data)), data...)
}

// encodeASN1Sequence encodes content as an ASN.1 SEQUENCE.
func encodeASN1Sequence(content []byte) []byte {
	return append(encodeASN1Tag(0x30, len(content)), content...)
}

// encodeASN1Tag encodes an ASN.1 tag with proper length encoding.
func encodeASN1Tag(tag byte, length int) []byte {
	if length < 128 {
		// Short form
		return []byte{tag, byte(length)}
	}
	// Long form
	if length < 256 {
		return []byte{tag, 0x81, byte(length)}
	}
	// 2-byte length (for completeness, unlikely for ECDSA)
	return []byte{tag, 0x82, byte(length >> 8), byte(length)}
}

// verifyRSAPSS verifies an RSA-PSS signature.
func verifyRSAPSS(pub *rsa.PublicKey, alg gocose.Algorithm, data, signature []byte) error {
	var hash crypto.Hash
	switch alg {
	case AlgPS256:
		hash = crypto.SHA256
	case AlgPS384:
		hash = crypto.SHA384
	case AlgPS512:
		hash = crypto.SHA512
	default:
		return fmt.Errorf("unsupported RSA algorithm: %d", alg)
	}

	h := hash.New()
	h.Write(data)
	digest := h.Sum(nil)

	opts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       hash,
	}
	return rsa.VerifyPSS(pub, hash, digest, signature, opts)
}

// verifyPQC verifies a signature using PQC algorithms.
func verifyPQC(pub crypto.PublicKey, data, signature []byte) error {
	switch key := pub.(type) {
	case *mldsa44.PublicKey:
		if !mldsa44.Verify(key, data, nil, signature) {
			return fmt.Errorf("ML-DSA-44 signature verification failed")
		}
		return nil
	case *mldsa65.PublicKey:
		if !mldsa65.Verify(key, data, nil, signature) {
			return fmt.Errorf("ML-DSA-65 signature verification failed")
		}
		return nil
	case *mldsa87.PublicKey:
		if !mldsa87.Verify(key, data, nil, signature) {
			return fmt.Errorf("ML-DSA-87 signature verification failed")
		}
		return nil
	case *slhdsa.PublicKey:
		// SLH-DSA uses NewMessage to wrap the data
		msg := slhdsa.NewMessage(data)
		if !slhdsa.Verify(key, msg, signature, nil) {
			return fmt.Errorf("SLH-DSA signature verification failed")
		}
		return nil
	default:
		return fmt.Errorf("unsupported PQC public key type: %T", pub)
	}
}
