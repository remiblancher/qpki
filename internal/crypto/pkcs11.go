//go:build cgo

// Package crypto provides cryptographic primitives for the PKI.
// This file implements HSM support via PKCS#11.
package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"sync"

	"github.com/miekg/pkcs11"
)

// PKCS11Config holds PKCS#11 configuration.
type PKCS11Config struct {
	// ModulePath is the path to the PKCS#11 module (.so/.dylib/.dll)
	ModulePath string

	// TokenLabel is the label of the token to use
	TokenLabel string

	// TokenSerial is the serial number of the token (alternative to TokenLabel)
	TokenSerial string

	// PIN is the user PIN for the token
	PIN string

	// KeyLabel is the label of the key to use
	KeyLabel string

	// KeyID is the CKA_ID of the key (hex encoded)
	KeyID string

	// SlotID is the slot ID (optional, use TokenLabel if not specified)
	SlotID *uint

	// LogoutAfterUse closes the session after each operation
	LogoutAfterUse bool
}

// PKCS11Signer implements the Signer interface using PKCS#11.
// This provides HSM support for the PKI.
// Sessions are acquired from the pool for each operation and released after.
type PKCS11Signer struct {
	pool      *PKCS11SessionPool
	keyHandle pkcs11.ObjectHandle
	alg       AlgorithmID
	pub       crypto.PublicKey
	mu        sync.Mutex
	closed    bool
}

// NewPKCS11Signer creates a new PKCS#11 signer.
func NewPKCS11Signer(cfg PKCS11Config) (*PKCS11Signer, error) {
	if cfg.ModulePath == "" {
		return nil, fmt.Errorf("PKCS#11 module path is required")
	}
	if cfg.KeyLabel == "" && cfg.KeyID == "" {
		return nil, fmt.Errorf("at least one of key_label or key_id is required")
	}

	// First, find the slot ID using a temporary context
	slotID, err := findSlotID(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to find slot: %w", err)
	}

	// Get session pool (singleton per module+slot)
	pool, err := GetSessionPool(cfg.ModulePath, slotID, cfg.PIN)
	if err != nil {
		return nil, fmt.Errorf("failed to get session pool: %w", err)
	}

	// Acquire a session temporarily to find the key and extract public key
	session, release, err := pool.Acquire()
	if err != nil {
		return nil, fmt.Errorf("failed to acquire session: %w", err)
	}
	defer release() // Release session back to pool after init

	// Find the private key
	keyHandle, err := findPrivateKey(pool.Context(), session, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to find private key: %w", err)
	}

	// Get the public key
	pub, alg, err := extractPublicKey(pool.Context(), session, keyHandle)
	if err != nil {
		return nil, fmt.Errorf("failed to extract public key: %w", err)
	}

	return &PKCS11Signer{
		pool:      pool,
		keyHandle: keyHandle,
		alg:       alg,
		pub:       pub,
	}, nil
}

// findSlotID finds the slot ID for the given configuration.
// This uses a temporary context that is cleaned up after.
func findSlotID(cfg PKCS11Config) (uint, error) {
	// If SlotID is specified, use it directly
	if cfg.SlotID != nil {
		return *cfg.SlotID, nil
	}

	// Need to query HSM for slot - use temporary context
	ctx := pkcs11.New(cfg.ModulePath)
	if ctx == nil {
		return 0, fmt.Errorf("failed to load PKCS#11 module: %s", cfg.ModulePath)
	}
	defer ctx.Destroy()

	if err := ctx.Initialize(); err != nil {
		if p11err, ok := err.(pkcs11.Error); !ok || p11err != pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED {
			return 0, fmt.Errorf("failed to initialize: %w", err)
		}
	}
	// NOTE: Do NOT call ctx.Finalize() here!
	// C_Finalize is a global operation that would affect all PKCS#11 users in the process.
	// The context is destroyed but the module remains initialized for other users.

	return findSlot(ctx, cfg)
}

// findSlot finds the slot matching the configuration.
func findSlot(ctx *pkcs11.Ctx, cfg PKCS11Config) (uint, error) {
	// If SlotID is specified, use it directly
	if cfg.SlotID != nil {
		return *cfg.SlotID, nil
	}

	// Get all slots with tokens
	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return 0, fmt.Errorf("failed to get slot list: %w", err)
	}

	if len(slots) == 0 {
		return 0, fmt.Errorf("no slots with tokens found")
	}

	for _, slot := range slots {
		info, err := ctx.GetTokenInfo(slot)
		if err != nil {
			continue
		}

		// Match by label
		if cfg.TokenLabel != "" && info.Label == cfg.TokenLabel {
			return slot, nil
		}

		// Match by serial
		if cfg.TokenSerial != "" && info.SerialNumber == cfg.TokenSerial {
			return slot, nil
		}
	}

	if cfg.TokenLabel != "" {
		return 0, fmt.Errorf("token with label %q not found", cfg.TokenLabel)
	}
	if cfg.TokenSerial != "" {
		return 0, fmt.Errorf("token with serial %q not found", cfg.TokenSerial)
	}

	// If no specific token requested, use the first one
	return slots[0], nil
}

// findPrivateKey finds the private key matching the configuration.
func findPrivateKey(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, cfg PKCS11Config) (pkcs11.ObjectHandle, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
	}

	// Add key identification attributes
	if cfg.KeyLabel != "" {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_LABEL, cfg.KeyLabel))
	}
	if cfg.KeyID != "" {
		id, err := hex.DecodeString(cfg.KeyID)
		if err != nil {
			return 0, fmt.Errorf("invalid key_id hex: %w", err)
		}
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_ID, id))
	}

	if err := ctx.FindObjectsInit(session, template); err != nil {
		return 0, fmt.Errorf("failed to init find objects: %w", err)
	}
	defer func() { _ = ctx.FindObjectsFinal(session) }()

	objs, _, err := ctx.FindObjects(session, 2)
	if err != nil {
		return 0, fmt.Errorf("failed to find objects: %w", err)
	}

	if len(objs) == 0 {
		return 0, fmt.Errorf("private key not found")
	}
	if len(objs) > 1 {
		return 0, fmt.Errorf("multiple keys found, please specify both key_label and key_id")
	}

	return objs[0], nil
}

// CKK_VENDOR_DEFINED is the base value for vendor-defined key types.
// Utimaco HSMs return this value for ML-DSA/ML-KEM keys instead of the specific vendor type.
const CKK_VENDOR_DEFINED = 0x80000000

// extractPublicKey extracts the public key from a private key handle.
func extractPublicKey(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, keyHandle pkcs11.ObjectHandle) (crypto.PublicKey, AlgorithmID, error) {
	// Get key type
	attrs, err := ctx.GetAttributeValue(session, keyHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
	})
	if err != nil {
		return nil, "", fmt.Errorf("failed to get key type: %w", err)
	}

	keyType := bytesToUint(attrs[0].Value)

	switch keyType {
	case pkcs11.CKK_EC:
		return extractECPublicKey(ctx, session, keyHandle)
	case pkcs11.CKK_RSA:
		return extractRSAPublicKey(ctx, session, keyHandle)
	case CKK_UTI_MLDSA:
		return extractMLDSAPublicKey(ctx, session, keyHandle)
	case CKK_VENDOR_DEFINED:
		// Utimaco returns CKK_VENDOR_DEFINED (0x80000000) for vendor key types.
		// Try ML-DSA extraction first (most common PQC type for signing).
		pub, alg, err := extractMLDSAPublicKey(ctx, session, keyHandle)
		if err == nil {
			return pub, alg, nil
		}
		// Try ML-KEM extraction (for key encapsulation)
		pub, alg, err = extractMLKEMPublicKey(ctx, session, keyHandle)
		if err == nil {
			return pub, alg, nil
		}
		return nil, "", fmt.Errorf("vendor key type (0x%X) not recognized as ML-DSA or ML-KEM", keyType)
	default:
		return nil, "", fmt.Errorf("unsupported key type: 0x%X", keyType)
	}
}

// extractECPublicKey extracts an ECDSA public key.
func extractECPublicKey(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, keyHandle pkcs11.ObjectHandle) (crypto.PublicKey, AlgorithmID, error) {
	// Get EC parameters and point from the private key
	attrs, err := ctx.GetAttributeValue(session, keyHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, nil),
	})
	if err != nil {
		return nil, "", fmt.Errorf("failed to get EC params: %w", err)
	}

	// Parse curve OID
	curve, algID, err := parseECParams(attrs[0].Value)
	if err != nil {
		return nil, "", err
	}

	// Find the corresponding public key
	pubHandle, err := findPublicKeyForPrivate(ctx, session, keyHandle)
	if err != nil {
		return nil, "", err
	}

	// Get the EC point from the public key
	pubAttrs, err := ctx.GetAttributeValue(session, pubHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	})
	if err != nil {
		return nil, "", fmt.Errorf("failed to get EC point: %w", err)
	}

	// Parse the EC point (DER encoded OCTET STRING containing 04 || X || Y)
	point := pubAttrs[0].Value

	// Unwrap DER OCTET STRING if present
	// DER format: 0x04 (OCTET STRING tag) + length + content
	// Content is the uncompressed EC point: 0x04 || X || Y
	if len(point) > 2 && point[0] == 0x04 {
		// Check if this looks like DER-encoded (tag + length + uncompressed point starting with 0x04)
		length := int(point[1])
		if length < 128 {
			// Short form length
			if len(point) >= 2+length && point[2] == 0x04 {
				// Content starts with 0x04, so this is DER-wrapped
				point = point[2 : 2+length]
			}
			// Otherwise, point[0] == 0x04 is the uncompressed point marker itself
		} else if length == 0x81 && len(point) > 3 {
			// Long form length (1 byte): 0x81 means next byte is the length
			actualLen := int(point[2])
			if len(point) >= 3+actualLen && point[3] == 0x04 {
				point = point[3 : 3+actualLen]
			}
		}
	}

	//nolint:staticcheck // elliptic.Unmarshal is deprecated for ECDH but we need ECDSA
	x, y := elliptic.Unmarshal(curve, point)
	if x == nil {
		return nil, "", fmt.Errorf("failed to unmarshal EC point")
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, algID, nil
}

// extractRSAPublicKey extracts an RSA public key.
func extractRSAPublicKey(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, keyHandle pkcs11.ObjectHandle) (crypto.PublicKey, AlgorithmID, error) {
	// Find the corresponding public key
	pubHandle, err := findPublicKeyForPrivate(ctx, session, keyHandle)
	if err != nil {
		return nil, "", err
	}

	attrs, err := ctx.GetAttributeValue(session, pubHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
	})
	if err != nil {
		return nil, "", fmt.Errorf("failed to get RSA attributes: %w", err)
	}

	n := new(big.Int).SetBytes(attrs[0].Value)
	// RSA public exponent is a big integer (big-endian), not CK_ULONG
	e := int(new(big.Int).SetBytes(attrs[1].Value).Int64())

	// Determine algorithm based on key size
	bitLen := n.BitLen()
	var algID AlgorithmID
	switch {
	case bitLen <= 2048:
		algID = "rsa-2048"
	case bitLen <= 3072:
		algID = "rsa-3072"
	case bitLen <= 4096:
		algID = "rsa-4096"
	default:
		algID = "rsa-4096"
	}

	return &rsa.PublicKey{
		N: n,
		E: e,
	}, algID, nil
}

// extractMLDSAPublicKey extracts an ML-DSA (FIPS 204) public key from Utimaco HSM.
func extractMLDSAPublicKey(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, keyHandle pkcs11.ObjectHandle) (crypto.PublicKey, AlgorithmID, error) {
	var pubKeyBytes []byte

	// 1. Try CKA_UTI_CUSTOM_DATA on PRIVATE key first (Utimaco stores pubkey here)
	attrs, err := ctx.GetAttributeValue(session, keyHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(CKA_UTI_CUSTOM_DATA, nil),
	})
	if err == nil && len(attrs[0].Value) > 0 {
		pubKeyBytes = attrs[0].Value
	} else {
		// 2. Fallback: find public key object and read from it
		pubHandle, err := findPublicKeyForPrivate(ctx, session, keyHandle)
		if err != nil {
			return nil, "", fmt.Errorf("failed to find public key: %w", err)
		}

		// Try CKA_VALUE on public key
		attrs, err = ctx.GetAttributeValue(session, pubHandle, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
		})
		if err == nil && len(attrs[0].Value) > 0 {
			pubKeyBytes = attrs[0].Value
		} else {
			// Try CKA_UTI_CUSTOM_DATA on public key
			attrs, err = ctx.GetAttributeValue(session, pubHandle, []*pkcs11.Attribute{
				pkcs11.NewAttribute(CKA_UTI_CUSTOM_DATA, nil),
			})
			if err != nil {
				return nil, "", fmt.Errorf("failed to get ML-DSA public key (tried CKA_UTI_CUSTOM_DATA on private, CKA_VALUE and CKA_UTI_CUSTOM_DATA on public): %w", err)
			}
			pubKeyBytes = attrs[0].Value
		}
	}

	// Determine ML-DSA variant based on public key size
	// ML-DSA-44: 1312 bytes, ML-DSA-65: 1952 bytes, ML-DSA-87: 2592 bytes
	var algID AlgorithmID
	switch len(pubKeyBytes) {
	case 1312:
		algID = "ml-dsa-44"
	case 1952:
		algID = "ml-dsa-65"
	case 2592:
		algID = "ml-dsa-87"
	default:
		return nil, "", fmt.Errorf("unknown ML-DSA public key size: %d", len(pubKeyBytes))
	}

	// Return raw public key bytes wrapped in MLDSAPublicKey
	return &MLDSAPublicKey{
		Algorithm: algID,
		PublicKey: pubKeyBytes,
	}, algID, nil
}

// MLDSAPublicKey represents an ML-DSA public key from HSM.
type MLDSAPublicKey struct {
	Algorithm AlgorithmID
	PublicKey []byte
}

// Bytes returns the raw public key bytes for computing Subject Key ID.
func (k *MLDSAPublicKey) Bytes() []byte {
	return k.PublicKey
}

// extractMLKEMPublicKey extracts an ML-KEM public key from HSM.
// ML-KEM is FIPS 203 (formerly CRYSTALS-Kyber).
func extractMLKEMPublicKey(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, keyHandle pkcs11.ObjectHandle) (crypto.PublicKey, AlgorithmID, error) {
	var pubKeyBytes []byte

	// 1. Try CKA_UTI_CUSTOM_DATA on PRIVATE key first (Utimaco stores pubkey here)
	attrs, err := ctx.GetAttributeValue(session, keyHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(CKA_UTI_CUSTOM_DATA, nil),
	})
	if err == nil && len(attrs[0].Value) > 0 {
		pubKeyBytes = attrs[0].Value
	} else {
		// 2. Fallback: find public key object and read from it
		pubHandle, err := findPublicKeyForPrivate(ctx, session, keyHandle)
		if err != nil {
			return nil, "", fmt.Errorf("failed to find public key: %w", err)
		}

		// Try CKA_VALUE on public key
		attrs, err = ctx.GetAttributeValue(session, pubHandle, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
		})
		if err == nil && len(attrs[0].Value) > 0 {
			pubKeyBytes = attrs[0].Value
		} else {
			// Try CKA_UTI_CUSTOM_DATA on public key
			attrs, err = ctx.GetAttributeValue(session, pubHandle, []*pkcs11.Attribute{
				pkcs11.NewAttribute(CKA_UTI_CUSTOM_DATA, nil),
			})
			if err != nil {
				return nil, "", fmt.Errorf("failed to get ML-KEM public key: %w", err)
			}
			pubKeyBytes = attrs[0].Value
		}
	}

	// Determine ML-KEM variant based on public key size
	var algID AlgorithmID
	switch len(pubKeyBytes) {
	case 800: // ML-KEM-512
		algID = "ml-kem-512"
	case 1184: // ML-KEM-768
		algID = "ml-kem-768"
	case 1568: // ML-KEM-1024
		algID = "ml-kem-1024"
	default:
		return nil, "", fmt.Errorf("unknown ML-KEM public key size: %d", len(pubKeyBytes))
	}

	return &MLKEMPublicKey{
		Algorithm: algID,
		PublicKey: pubKeyBytes,
	}, algID, nil
}

// MLKEMPublicKey represents an ML-KEM public key from HSM.
type MLKEMPublicKey struct {
	Algorithm AlgorithmID
	PublicKey []byte
}

// Bytes returns the raw public key bytes.
func (k *MLKEMPublicKey) Bytes() []byte {
	return k.PublicKey
}

// GetPublicKeyFromHSM extracts the public key from an HSM key.
// This is useful for ML-KEM keys where we need the public key for CSR generation.
func GetPublicKeyFromHSM(cfg PKCS11Config) (crypto.PublicKey, error) {
	if cfg.ModulePath == "" {
		return nil, fmt.Errorf("PKCS#11 module path is required")
	}
	if cfg.KeyLabel == "" && cfg.KeyID == "" {
		return nil, fmt.Errorf("at least one of key_label or key_id is required")
	}

	// Find the slot ID
	slotID, err := findSlotID(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to find slot: %w", err)
	}

	// Get session pool
	pool, err := GetSessionPool(cfg.ModulePath, slotID, cfg.PIN)
	if err != nil {
		return nil, fmt.Errorf("failed to get session pool: %w", err)
	}

	// Acquire a session
	session, release, err := pool.Acquire()
	if err != nil {
		return nil, fmt.Errorf("failed to acquire session: %w", err)
	}
	defer release()

	// Find the private key
	keyHandle, err := findPrivateKey(pool.Context(), session, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to find private key: %w", err)
	}

	// Extract the public key
	pub, _, err := extractPublicKey(pool.Context(), session, keyHandle)
	if err != nil {
		return nil, fmt.Errorf("failed to extract public key: %w", err)
	}

	return pub, nil
}

// findPublicKeyForPrivate finds the public key corresponding to a private key.
func findPublicKeyForPrivate(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, privHandle pkcs11.ObjectHandle) (pkcs11.ObjectHandle, error) {
	// Get the ID and label of the private key
	attrs, err := ctx.GetAttributeValue(session, privHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
	})
	if err != nil {
		return 0, fmt.Errorf("failed to get private key ID/label: %w", err)
	}

	// Find public key with same ID AND label (to avoid collisions)
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, attrs[0].Value),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, attrs[1].Value),
	}

	if err := ctx.FindObjectsInit(session, template); err != nil {
		return 0, fmt.Errorf("failed to init find public key: %w", err)
	}
	defer func() { _ = ctx.FindObjectsFinal(session) }()

	objs, _, err := ctx.FindObjects(session, 1)
	if err != nil {
		return 0, fmt.Errorf("failed to find public key: %w", err)
	}

	if len(objs) == 0 {
		return 0, fmt.Errorf("public key not found for private key")
	}

	return objs[0], nil
}

// parseECParams parses EC parameters and returns the curve and algorithm ID.
func parseECParams(params []byte) (elliptic.Curve, AlgorithmID, error) {
	// EC params are DER encoded OID
	var oid asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(params, &oid); err != nil {
		return nil, "", fmt.Errorf("failed to parse EC params OID: %w", err)
	}

	// Map OID to curve
	switch {
	case oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}): // P-256
		return elliptic.P256(), "ecdsa-p256", nil
	case oid.Equal(asn1.ObjectIdentifier{1, 3, 132, 0, 34}): // P-384
		return elliptic.P384(), "ecdsa-p384", nil
	case oid.Equal(asn1.ObjectIdentifier{1, 3, 132, 0, 35}): // P-521
		return elliptic.P521(), "ecdsa-p521", nil
	default:
		return nil, "", fmt.Errorf("unsupported EC curve OID: %v", oid)
	}
}

// bytesToUint converts a byte slice to uint for CK_ULONG values.
// CK_ULONG is stored in native byte order (little-endian on x86/ARM).
// NOTE: Do NOT use for "Big integer" attributes like CKA_PUBLIC_EXPONENT - use big.Int.SetBytes() instead.
func bytesToUint(b []byte) uint {
	var result uint
	for i := len(b) - 1; i >= 0; i-- {
		result = result<<8 | uint(b[i])
	}
	return result
}

// Algorithm returns the algorithm used by this signer.
func (s *PKCS11Signer) Algorithm() AlgorithmID {
	return s.alg
}

// Public returns the public key.
func (s *PKCS11Signer) Public() crypto.PublicKey {
	return s.pub
}

// Sign signs the digest using the HSM.
func (s *PKCS11Signer) Sign(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, fmt.Errorf("signer is closed")
	}

	// Acquire session from pool
	session, release, err := s.pool.Acquire()
	if err != nil {
		return nil, fmt.Errorf("failed to acquire session: %w", err)
	}
	defer release() // Return session to pool after operation

	// Determine mechanism and prepare data based on key type
	var mech *pkcs11.Mechanism
	dataToSign := digest

	switch pub := s.pub.(type) {
	case *ecdsa.PublicKey:
		mech = pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)
	case *rsa.PublicKey:
		// Use RSA-PKCS for signing
		// CKM_RSA_PKCS requires DigestInfo prefix (PKCS#1 v1.5)
		mech = pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)
		// Add DigestInfo prefix for the hash algorithm
		dataToSign = addDigestInfoPrefix(digest, opts.HashFunc())
	case *MLDSAPublicKey:
		// Use Utimaco ML-DSA sign mechanism
		// ML-DSA signs the full message, not a digest
		mech = pkcs11.NewMechanism(CKM_UTI_MLDSA_SIGN, mldsaMechParam(pub.Algorithm))
	default:
		return nil, fmt.Errorf("unsupported key type for signing")
	}

	ctx := s.pool.Context()
	if err := ctx.SignInit(session, []*pkcs11.Mechanism{mech}, s.keyHandle); err != nil {
		return nil, fmt.Errorf("failed to init sign: %w", err)
	}

	sig, err := ctx.Sign(session, dataToSign)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	// For ECDSA, convert raw signature (r||s) to ASN.1 DER format
	if _, ok := s.pub.(*ecdsa.PublicKey); ok {
		sig, err = convertECDSASignature(sig)
		if err != nil {
			return nil, err
		}
	}

	return sig, nil
}

// DigestInfo prefixes for PKCS#1 v1.5 signatures (RFC 8017)
var digestInfoPrefixes = map[crypto.Hash][]byte{
	crypto.SHA256: {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384: {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512: {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
}

// addDigestInfoPrefix adds the DigestInfo ASN.1 prefix for PKCS#1 v1.5 RSA signatures.
func addDigestInfoPrefix(digest []byte, hash crypto.Hash) []byte {
	prefix, ok := digestInfoPrefixes[hash]
	if !ok {
		// Unknown hash, return digest as-is (will likely fail verification)
		return digest
	}
	result := make([]byte, len(prefix)+len(digest))
	copy(result, prefix)
	copy(result[len(prefix):], digest)
	return result
}

// convertECDSASignature converts raw ECDSA signature (r||s) to ASN.1 DER format.
func convertECDSASignature(rawSig []byte) ([]byte, error) {
	if len(rawSig)%2 != 0 {
		return nil, fmt.Errorf("invalid ECDSA signature length")
	}

	n := len(rawSig) / 2
	r := new(big.Int).SetBytes(rawSig[:n])
	s := new(big.Int).SetBytes(rawSig[n:])

	return asn1.Marshal(struct {
		R, S *big.Int
	}{r, s})
}

// mldsaMechParam returns the Utimaco mechanism parameter for ML-DSA sign/verify.
// Format (big-endian): 4 bytes flags + 4 bytes keytype = 8 bytes total
func mldsaMechParam(alg AlgorithmID) []byte {
	param, _ := MLDSAKeyType(alg)
	// Utimaco expects 8 bytes (big-endian):
	//   - flags:   4 bytes (0)
	//   - keytype: 4 bytes (1=ML-DSA-44, 2=ML-DSA-65, 3=ML-DSA-87)
	mechParam := make([]byte, 8)
	mechParam[7] = byte(param) // keytype in big-endian at bytes 4-7
	return mechParam
}

// Decrypt implements crypto.Decrypter for RSA keys via PKCS#11.
// Returns an error for non-RSA keys.
func (s *PKCS11Signer) Decrypt(_ io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, fmt.Errorf("signer is closed")
	}

	// Only RSA keys support decryption
	if _, ok := s.pub.(*rsa.PublicKey); !ok {
		return nil, fmt.Errorf("Decrypt only supported for RSA keys")
	}

	// Acquire session from pool
	session, release, err := s.pool.Acquire()
	if err != nil {
		return nil, fmt.Errorf("failed to acquire session: %w", err)
	}
	defer release() // Return session to pool after operation

	ctx := s.pool.Context()

	// Determine mechanism based on options
	var mech *pkcs11.Mechanism
	switch o := opts.(type) {
	case *rsa.OAEPOptions:
		// Use RSA-OAEP with specified hash
		// CKM_RSA_PKCS_OAEP requires OAEPParams
		hashMech := uint(pkcs11.CKM_SHA256)
		mgfMech := uint(pkcs11.CKG_MGF1_SHA256)
		switch o.Hash {
		case crypto.SHA1:
			hashMech = uint(pkcs11.CKM_SHA_1)
			mgfMech = uint(pkcs11.CKG_MGF1_SHA1)
		case crypto.SHA384:
			hashMech = uint(pkcs11.CKM_SHA384)
			mgfMech = uint(pkcs11.CKG_MGF1_SHA384)
		case crypto.SHA512:
			hashMech = uint(pkcs11.CKM_SHA512)
			mgfMech = uint(pkcs11.CKG_MGF1_SHA512)
		}
		oaepParams := pkcs11.NewOAEPParams(hashMech, mgfMech, pkcs11.CKZ_DATA_SPECIFIED, o.Label)
		mech = pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, oaepParams)
	case *rsa.PKCS1v15DecryptOptions:
		// Use PKCS#1 v1.5
		mech = pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)
	default:
		// Default to RSA-OAEP with SHA-256
		oaepParams := pkcs11.NewOAEPParams(uint(pkcs11.CKM_SHA256), uint(pkcs11.CKG_MGF1_SHA256), pkcs11.CKZ_DATA_SPECIFIED, nil)
		mech = pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, oaepParams)
	}

	if err := ctx.DecryptInit(session, []*pkcs11.Mechanism{mech}, s.keyHandle); err != nil {
		return nil, fmt.Errorf("failed to init decrypt: %w", err)
	}

	plaintext, err := ctx.Decrypt(session, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// Close marks the signer as closed.
// The session pool is a singleton and manages its own lifecycle via CloseAllPools().
func (s *PKCS11Signer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}
	s.closed = true

	// Pool is a singleton - it will be cleaned up by CloseAllPools() at program exit
	// No need to release anything here
	return nil
}

// HSMInfo contains information about an HSM.
type HSMInfo struct {
	ModulePath string
	Slots      []SlotInfo
}

// SlotInfo contains information about an HSM slot.
type SlotInfo struct {
	ID           uint
	Description  string
	TokenLabel   string
	TokenSerial  string
	Manufacturer string
	HasToken     bool
}

// KeyInfo contains information about a key in the HSM.
type KeyInfo struct {
	Label   string
	ID      string // Hex encoded CKA_ID
	Type    string // "EC" or "RSA"
	Size    int    // Key size in bits
	CanSign bool
}

// ListHSMSlots lists available slots in a PKCS#11 module.
// This uses a temporary context since no session is required for slot listing.
func ListHSMSlots(modulePath string) (*HSMInfo, error) {
	// Use temporary context - no session needed for slot listing
	ctx := pkcs11.New(modulePath)
	if ctx == nil {
		return nil, fmt.Errorf("failed to load PKCS#11 module: %s", modulePath)
	}
	defer ctx.Destroy()

	if err := ctx.Initialize(); err != nil {
		if p11err, ok := err.(pkcs11.Error); !ok || p11err != pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED {
			return nil, fmt.Errorf("failed to initialize: %w", err)
		}
	}
	// NOTE: Do NOT call ctx.Finalize() - it's a global operation

	slots, err := ctx.GetSlotList(false)
	if err != nil {
		return nil, fmt.Errorf("failed to get slot list: %w", err)
	}

	info := &HSMInfo{
		ModulePath: modulePath,
		Slots:      make([]SlotInfo, 0, len(slots)),
	}

	for _, slot := range slots {
		slotInfo, err := ctx.GetSlotInfo(slot)
		if err != nil {
			continue
		}

		si := SlotInfo{
			ID:          slot,
			Description: slotInfo.SlotDescription,
			HasToken:    slotInfo.Flags&pkcs11.CKF_TOKEN_PRESENT != 0,
		}

		if si.HasToken {
			tokenInfo, err := ctx.GetTokenInfo(slot)
			if err == nil {
				si.TokenLabel = tokenInfo.Label
				si.TokenSerial = tokenInfo.SerialNumber
				si.Manufacturer = tokenInfo.ManufacturerID
			}
		}

		info.Slots = append(info.Slots, si)
	}

	return info, nil
}

// GenerateHSMKeyPairConfig holds configuration for key generation.
type GenerateHSMKeyPairConfig struct {
	ModulePath string
	TokenLabel string
	SlotID     *uint // If set, use this slot directly instead of searching by token label
	PIN        string
	KeyLabel   string
	KeyID      []byte // CKA_ID (if nil, auto-generated)
	Algorithm  AlgorithmID
}

// GenerateHSMKeyPairResult holds the result of key generation.
type GenerateHSMKeyPairResult struct {
	KeyLabel string
	KeyID    string // Hex encoded
	Type     string
	Size     int
}

// GenerateHSMKeyPair generates a new key pair in the HSM.
// Uses the singleton session pool for key generation operations.
func GenerateHSMKeyPair(cfg GenerateHSMKeyPairConfig) (*GenerateHSMKeyPairResult, error) {
	if cfg.ModulePath == "" {
		return nil, fmt.Errorf("PKCS#11 module path is required")
	}
	if cfg.KeyLabel == "" {
		return nil, fmt.Errorf("key label is required")
	}

	// Determine slot ID
	var slotID uint
	if cfg.SlotID != nil {
		slotID = *cfg.SlotID
	} else {
		// Need to find slot by token label using temporary context
		slotCfg := PKCS11Config{
			ModulePath: cfg.ModulePath,
			TokenLabel: cfg.TokenLabel,
		}
		var err error
		slotID, err = findSlotID(slotCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to find slot: %w", err)
		}
	}

	// Use the singleton pool for this module+slot
	pool, err := GetSessionPool(cfg.ModulePath, slotID, cfg.PIN)
	if err != nil {
		return nil, fmt.Errorf("failed to get session pool: %w", err)
	}

	// Acquire session from pool
	session, release, err := pool.Acquire()
	if err != nil {
		return nil, fmt.Errorf("failed to acquire session: %w", err)
	}
	defer release()

	ctx := pool.Context()

	// Generate key ID if not provided
	keyID := cfg.KeyID
	if len(keyID) == 0 {
		keyID = make([]byte, 8)
		// Simple unique ID based on label hash
		for i, c := range cfg.KeyLabel {
			keyID[i%8] ^= byte(c)
		}
	}

	// Generate the key pair based on algorithm
	var result *GenerateHSMKeyPairResult
	switch cfg.Algorithm {
	case "ecdsa-p256", "ecdsa-p384", "ecdsa-p521":
		result, err = generateECKeyPair(ctx, session, cfg.KeyLabel, keyID, cfg.Algorithm)
	case "rsa-2048", "rsa-3072", "rsa-4096":
		result, err = generateRSAKeyPair(ctx, session, cfg.KeyLabel, keyID, cfg.Algorithm)
	case "ml-dsa-44", "ml-dsa-65", "ml-dsa-87":
		result, err = generateMLDSAKeyPair(ctx, session, cfg.KeyLabel, keyID, cfg.Algorithm)
	case "ml-kem-512", "ml-kem-768", "ml-kem-1024":
		result, err = generateMLKEMKeyPair(ctx, session, cfg.KeyLabel, keyID, cfg.Algorithm)
	default:
		return nil, fmt.Errorf("unsupported algorithm for HSM key generation: %s", cfg.Algorithm)
	}

	if err != nil {
		return nil, err
	}

	return result, nil
}

// generateECKeyPair generates an ECDSA key pair in the HSM.
func generateECKeyPair(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, label string, keyID []byte, alg AlgorithmID) (*GenerateHSMKeyPairResult, error) {
	// Map algorithm to curve OID
	var ecParams []byte
	var keySize int
	switch alg {
	case "ecdsa-p256":
		// OID 1.2.840.10045.3.1.7 (P-256)
		ecParams = []byte{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}
		keySize = 256
	case "ecdsa-p384":
		// OID 1.3.132.0.34 (P-384)
		ecParams = []byte{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22}
		keySize = 384
	case "ecdsa-p521":
		// OID 1.3.132.0.35 (P-521)
		ecParams = []byte{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23}
		keySize = 521
	default:
		return nil, fmt.Errorf("unsupported EC algorithm: %s", alg)
	}

	// Public key template
	pubTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ecParams),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
	}

	// Private key template
	privTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
	}

	// Generate the key pair
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)}
	_, _, err := ctx.GenerateKeyPair(session, mech, pubTemplate, privTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to generate EC key pair: %w", err)
	}

	return &GenerateHSMKeyPairResult{
		KeyLabel: label,
		KeyID:    hex.EncodeToString(keyID),
		Type:     "EC",
		Size:     keySize,
	}, nil
}

// generateRSAKeyPair generates an RSA key pair in the HSM.
func generateRSAKeyPair(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, label string, keyID []byte, alg AlgorithmID) (*GenerateHSMKeyPairResult, error) {
	// Map algorithm to key size
	var keySize uint
	switch alg {
	case "rsa-2048":
		keySize = 2048
	case "rsa-3072":
		keySize = 3072
	case "rsa-4096":
		keySize = 4096
	default:
		return nil, fmt.Errorf("unsupported RSA algorithm: %s", alg)
	}

	// Public exponent (65537)
	pubExp := []byte{0x01, 0x00, 0x01}

	// Public key template
	pubTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, keySize),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, pubExp),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
	}

	// Private key template
	privTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
	}

	// Generate the key pair
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)}
	_, _, err := ctx.GenerateKeyPair(session, mech, pubTemplate, privTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key pair: %w", err)
	}

	return &GenerateHSMKeyPairResult{
		KeyLabel: label,
		KeyID:    hex.EncodeToString(keyID),
		Type:     "RSA",
		Size:     int(keySize),
	}, nil
}

// generateMLDSAKeyPair generates an ML-DSA (FIPS 204) key pair in a Utimaco HSM.
func generateMLDSAKeyPair(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, label string, keyID []byte, alg AlgorithmID) (*GenerateHSMKeyPairResult, error) {
	// Get ML-DSA variant parameter
	mldsaType, ok := MLDSAKeyType(alg)
	if !ok {
		return nil, fmt.Errorf("unsupported ML-DSA algorithm: %s", alg)
	}

	// Mechanism parameter: MLDSA_KEYGEN structure (pattern "u4u4v2*")
	// See: vendor/utimaco-sim/Crypto_APIs/PKCS11_R3/samples/qptool2/include/MLDSA_KeyGen.h
	// Format (big-endian, Utimaco wire format):
	//   - flags:        4 bytes (1 = pseudo-random mode)
	//   - type:         4 bytes (1=ML-DSA-44, 2=ML-DSA-65, 3=ML-DSA-87)
	//   - l_attributes: 2 bytes (0 = no extra attributes)
	//   - (no seed field when using pseudo-random mode)
	mechParam := make([]byte, 10)
	// flags = 1 (big-endian)
	mechParam[3] = 1
	// type (big-endian)
	mechParam[7] = byte(mldsaType)
	// l_attributes = 0 (bytes 8-9 already zero)

	// Public key template
	pubTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, CKK_UTI_MLDSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
	}

	// Private key template
	privTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, CKK_UTI_MLDSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
	}

	// Generate the key pair using Utimaco ML-DSA mechanism
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(CKM_UTI_MLDSA_GENKEY, mechParam)}
	_, _, err := ctx.GenerateKeyPair(session, mech, pubTemplate, privTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ML-DSA key pair: %w", err)
	}

	// Map algorithm to security level for display
	var securityLevel int
	switch alg {
	case "ml-dsa-44":
		securityLevel = 128 // NIST Level 1
	case "ml-dsa-65":
		securityLevel = 192 // NIST Level 3
	case "ml-dsa-87":
		securityLevel = 256 // NIST Level 5
	}

	return &GenerateHSMKeyPairResult{
		KeyLabel: label,
		KeyID:    hex.EncodeToString(keyID),
		Type:     "ML-DSA",
		Size:     securityLevel,
	}, nil
}

// generateMLKEMKeyPair generates an ML-KEM (FIPS 203) key pair in a Utimaco HSM.
func generateMLKEMKeyPair(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, label string, keyID []byte, alg AlgorithmID) (*GenerateHSMKeyPairResult, error) {
	// Get ML-KEM variant parameter
	mlkemType, ok := MLKEMKeyType(alg)
	if !ok {
		return nil, fmt.Errorf("unsupported ML-KEM algorithm: %s", alg)
	}

	// Mechanism parameter: MLKEM_KEYGEN structure (pattern "u4u4v2*")
	// Same format as MLDSA_KEYGEN (big-endian, 10 bytes)
	mechParam := make([]byte, 10)
	mechParam[3] = 1               // flags = 1 (big-endian)
	mechParam[7] = byte(mlkemType) // type (0x32, 0x33, 0x35)

	// Public key template
	pubTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, CKK_UTI_MLKEM),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
	}

	// Private key template
	privTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, CKK_UTI_MLKEM),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
	}

	// Generate the key pair using Utimaco ML-KEM mechanism
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(CKM_UTI_MLKEM_GENKEY, mechParam)}
	_, _, err := ctx.GenerateKeyPair(session, mech, pubTemplate, privTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ML-KEM key pair: %w", err)
	}

	// Map algorithm to security level for display
	var securityLevel int
	switch alg {
	case "ml-kem-512":
		securityLevel = 128 // NIST Level 1
	case "ml-kem-768":
		securityLevel = 192 // NIST Level 3
	case "ml-kem-1024":
		securityLevel = 256 // NIST Level 5
	}

	return &GenerateHSMKeyPairResult{
		KeyLabel: label,
		KeyID:    hex.EncodeToString(keyID),
		Type:     "ML-KEM",
		Size:     securityLevel,
	}, nil
}

// ListHSMKeysConfig holds configuration for listing keys.
type ListHSMKeysConfig struct {
	ModulePath string
	TokenLabel string
	SlotID     *uint
	PIN        string
}

// ListHSMKeys lists keys in a token.
func ListHSMKeys(modulePath, tokenLabel, pin string) ([]KeyInfo, error) {
	return ListHSMKeysWithConfig(ListHSMKeysConfig{
		ModulePath: modulePath,
		TokenLabel: tokenLabel,
		PIN:        pin,
	})
}

// ListHSMKeysWithConfig lists keys using the provided configuration.
func ListHSMKeysWithConfig(cfg ListHSMKeysConfig) ([]KeyInfo, error) {
	// Determine slot ID
	var slotID uint
	if cfg.SlotID != nil {
		slotID = *cfg.SlotID
	} else {
		// Find slot by token label
		slotCfg := PKCS11Config{
			ModulePath: cfg.ModulePath,
			TokenLabel: cfg.TokenLabel,
		}
		var err error
		slotID, err = findSlotID(slotCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to find slot: %w", err)
		}
	}

	// Use the singleton pool
	pool, err := GetSessionPool(cfg.ModulePath, slotID, cfg.PIN)
	if err != nil {
		return nil, fmt.Errorf("failed to get session pool: %w", err)
	}

	// Acquire session from pool
	session, release, err := pool.Acquire()
	if err != nil {
		return nil, fmt.Errorf("failed to acquire session: %w", err)
	}
	defer release()

	ctx := pool.Context()

	// Find all private keys
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
	}

	if err := ctx.FindObjectsInit(session, template); err != nil {
		return nil, fmt.Errorf("failed to init find objects: %w", err)
	}

	var keys []KeyInfo
	for {
		objs, _, err := ctx.FindObjects(session, 10)
		if err != nil {
			_ = ctx.FindObjectsFinal(session)
			return nil, fmt.Errorf("failed to find objects: %w", err)
		}
		if len(objs) == 0 {
			break
		}

		for _, obj := range objs {
			attrs, err := ctx.GetAttributeValue(session, obj, []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
				pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
				pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
				pkcs11.NewAttribute(pkcs11.CKA_SIGN, nil),
			})
			if err != nil {
				continue
			}

			ki := KeyInfo{
				Label:   string(attrs[0].Value),
				ID:      hex.EncodeToString(attrs[1].Value),
				CanSign: len(attrs[3].Value) > 0 && attrs[3].Value[0] != 0,
			}

			keyType := bytesToUint(attrs[2].Value)
			switch keyType {
			case pkcs11.CKK_EC:
				ki.Type = "EC"
			case pkcs11.CKK_RSA:
				ki.Type = "RSA"
			case CKK_UTI_MLDSA:
				ki.Type = "ML-DSA"
			case CKK_UTI_MLKEM:
				ki.Type = "ML-KEM"
			default:
				ki.Type = fmt.Sprintf("Unknown(0x%X)", keyType)
			}

			keys = append(keys, ki)
		}
	}
	_ = ctx.FindObjectsFinal(session)

	return keys, nil
}
