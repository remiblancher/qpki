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
type PKCS11Signer struct {
	pool      *PKCS11SessionPool
	slotID    uint
	session   pkcs11.SessionHandle
	keyHandle pkcs11.ObjectHandle
	alg       AlgorithmID
	pub       crypto.PublicKey
	cfg       PKCS11Config
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

	// Get session pool (singleton per module)
	pool, err := GetSessionPool(cfg.ModulePath)
	if err != nil {
		return nil, fmt.Errorf("failed to get session pool: %w", err)
	}

	// Find the slot
	slotID, err := findSlot(pool.Context(), cfg)
	if err != nil {
		_ = pool.Release()
		return nil, fmt.Errorf("failed to find slot: %w", err)
	}

	// Get session from pool (handles login)
	session, err := pool.GetSession(slotID, cfg.PIN)
	if err != nil {
		_ = pool.Release()
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	// Find the private key
	keyHandle, err := findPrivateKey(pool.Context(), session, cfg)
	if err != nil {
		_ = pool.Release()
		return nil, fmt.Errorf("failed to find private key: %w", err)
	}

	// Get the public key
	pub, alg, err := extractPublicKey(pool.Context(), session, keyHandle)
	if err != nil {
		_ = pool.Release()
		return nil, fmt.Errorf("failed to extract public key: %w", err)
	}

	return &PKCS11Signer{
		pool:      pool,
		slotID:    slotID,
		session:   session,
		keyHandle: keyHandle,
		alg:       alg,
		pub:       pub,
		cfg:       cfg,
	}, nil
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
	default:
		return nil, "", fmt.Errorf("unsupported key type: %d", keyType)
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

	// Determine mechanism and prepare data based on key type
	var mech *pkcs11.Mechanism
	dataToSign := digest

	switch s.pub.(type) {
	case *ecdsa.PublicKey:
		mech = pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)
	case *rsa.PublicKey:
		// Use RSA-PKCS for signing
		// CKM_RSA_PKCS requires DigestInfo prefix (PKCS#1 v1.5)
		mech = pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)
		// Add DigestInfo prefix for the hash algorithm
		dataToSign = addDigestInfoPrefix(digest, opts.HashFunc())
	default:
		return nil, fmt.Errorf("unsupported key type for signing")
	}

	ctx := s.pool.Context()
	if err := ctx.SignInit(s.session, []*pkcs11.Mechanism{mech}, s.keyHandle); err != nil {
		return nil, fmt.Errorf("failed to init sign: %w", err)
	}

	sig, err := ctx.Sign(s.session, dataToSign)
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

	if err := ctx.DecryptInit(s.session, []*pkcs11.Mechanism{mech}, s.keyHandle); err != nil {
		return nil, fmt.Errorf("failed to init decrypt: %w", err)
	}

	plaintext, err := ctx.Decrypt(s.session, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// Close releases the session pool reference.
// The pool manages session lifecycle; Finalize is only called when all references are released.
func (s *PKCS11Signer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}
	s.closed = true

	// Release our reference to the pool
	// The pool handles cleanup when refCount reaches 0
	return s.pool.Release()
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
func ListHSMSlots(modulePath string) (*HSMInfo, error) {
	// Get session pool (singleton per module)
	pool, err := GetSessionPool(modulePath)
	if err != nil {
		return nil, fmt.Errorf("failed to get session pool: %w", err)
	}
	defer func() { _ = pool.Release() }()

	ctx := pool.Context()

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
// Uses the session pool to avoid C_Finalize() invalidating other sessions.
func GenerateHSMKeyPair(cfg GenerateHSMKeyPairConfig) (*GenerateHSMKeyPairResult, error) {
	if cfg.ModulePath == "" {
		return nil, fmt.Errorf("PKCS#11 module path is required")
	}
	if cfg.KeyLabel == "" {
		return nil, fmt.Errorf("key label is required")
	}

	// Get session pool (singleton per module)
	pool, err := GetSessionPool(cfg.ModulePath)
	if err != nil {
		return nil, fmt.Errorf("failed to get session pool: %w", err)
	}
	defer func() { _ = pool.Release() }()

	ctx := pool.Context()

	// Find the slot
	slotCfg := PKCS11Config{TokenLabel: cfg.TokenLabel}
	slot, err := findSlot(ctx, slotCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to find slot: %w", err)
	}

	// Get session from pool (handles login)
	session, err := pool.GetSession(slot, cfg.PIN)
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

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
	default:
		return nil, fmt.Errorf("unsupported algorithm for HSM key generation: %s (only ec/*, rsa/* supported)", cfg.Algorithm)
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

// ListHSMKeys lists keys in a token.
func ListHSMKeys(modulePath, tokenLabel, pin string) ([]KeyInfo, error) {
	// Get session pool (singleton per module)
	pool, err := GetSessionPool(modulePath)
	if err != nil {
		return nil, fmt.Errorf("failed to get session pool: %w", err)
	}
	defer func() { _ = pool.Release() }()

	ctx := pool.Context()

	// Find the slot
	cfg := PKCS11Config{TokenLabel: tokenLabel}
	slot, err := findSlot(ctx, cfg)
	if err != nil {
		return nil, err
	}

	// Get session from pool (handles login)
	session, err := pool.GetReadOnlySession(slot, pin)
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

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
			default:
				ki.Type = fmt.Sprintf("Unknown(%d)", keyType)
			}

			keys = append(keys, ki)
		}
	}
	_ = ctx.FindObjectsFinal(session)

	return keys, nil
}
