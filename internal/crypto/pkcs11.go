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

	// VerifyKeyCertBinding ensures the HSM key matches the CA certificate
	VerifyKeyCertBinding bool
}

// PKCS11Signer implements the Signer interface using PKCS#11.
// This provides HSM support for the PKI.
type PKCS11Signer struct {
	ctx       *pkcs11.Ctx
	session   pkcs11.SessionHandle
	keyHandle pkcs11.ObjectHandle
	alg       AlgorithmID
	pub       crypto.PublicKey
	cfg       PKCS11Config
	mu        sync.Mutex
	closed    bool
}

// PKCS11SignerProvider implements SignerProvider for PKCS#11.
type PKCS11SignerProvider struct{}

// Ensure PKCS11SignerProvider implements SignerProvider.
var _ SignerProvider = (*PKCS11SignerProvider)(nil)

// NewPKCS11Signer creates a new PKCS#11 signer.
func NewPKCS11Signer(cfg PKCS11Config) (*PKCS11Signer, error) {
	if cfg.ModulePath == "" {
		return nil, fmt.Errorf("PKCS#11 module path is required")
	}
	if cfg.KeyLabel == "" && cfg.KeyID == "" {
		return nil, fmt.Errorf("at least one of key_label or key_id is required")
	}

	// Load the PKCS#11 module
	ctx := pkcs11.New(cfg.ModulePath)
	if ctx == nil {
		return nil, fmt.Errorf("failed to load PKCS#11 module: %s", cfg.ModulePath)
	}

	if err := ctx.Initialize(); err != nil {
		ctx.Destroy()
		return nil, fmt.Errorf("failed to initialize PKCS#11 module: %w", err)
	}

	// Find the slot
	slotID, err := findSlot(ctx, cfg)
	if err != nil {
		ctx.Finalize()
		ctx.Destroy()
		return nil, fmt.Errorf("failed to find slot: %w", err)
	}

	// Open a session
	session, err := ctx.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		ctx.Finalize()
		ctx.Destroy()
		return nil, fmt.Errorf("failed to open session: %w", err)
	}

	// Login with PIN
	if err := ctx.Login(session, pkcs11.CKU_USER, cfg.PIN); err != nil {
		// CKR_USER_ALREADY_LOGGED_IN is acceptable
		if e, ok := err.(pkcs11.Error); !ok || e != pkcs11.CKR_USER_ALREADY_LOGGED_IN {
			ctx.CloseSession(session)
			ctx.Finalize()
			ctx.Destroy()
			return nil, fmt.Errorf("failed to login: %w", err)
		}
	}

	// Find the private key
	keyHandle, err := findPrivateKey(ctx, session, cfg)
	if err != nil {
		ctx.Logout(session)
		ctx.CloseSession(session)
		ctx.Finalize()
		ctx.Destroy()
		return nil, fmt.Errorf("failed to find private key: %w", err)
	}

	// Get the public key
	pub, alg, err := extractPublicKey(ctx, session, keyHandle)
	if err != nil {
		ctx.Logout(session)
		ctx.CloseSession(session)
		ctx.Finalize()
		ctx.Destroy()
		return nil, fmt.Errorf("failed to extract public key: %w", err)
	}

	return &PKCS11Signer{
		ctx:       ctx,
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
	defer ctx.FindObjectsFinal(session)

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
	if len(point) > 0 && point[0] == 0x04 {
		// Already uncompressed point
	} else if len(point) > 2 && point[0] == 0x04 && point[1] == byte(len(point)-2) {
		point = point[2:]
	}

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
	e := int(bytesToUint(attrs[1].Value))

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
	// Get the ID of the private key
	attrs, err := ctx.GetAttributeValue(session, privHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
	})
	if err != nil {
		return 0, fmt.Errorf("failed to get private key ID: %w", err)
	}

	// Find public key with same ID
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, attrs[0].Value),
	}

	if err := ctx.FindObjectsInit(session, template); err != nil {
		return 0, fmt.Errorf("failed to init find public key: %w", err)
	}
	defer ctx.FindObjectsFinal(session)

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

// bytesToUint converts a byte slice to uint.
func bytesToUint(b []byte) uint {
	var result uint
	for _, v := range b {
		result = result<<8 | uint(v)
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

	// Determine mechanism based on key type
	var mech *pkcs11.Mechanism
	switch s.pub.(type) {
	case *ecdsa.PublicKey:
		mech = pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)
	case *rsa.PublicKey:
		// Use RSA-PKCS for signing
		mech = pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)
	default:
		return nil, fmt.Errorf("unsupported key type for signing")
	}

	if err := s.ctx.SignInit(s.session, []*pkcs11.Mechanism{mech}, s.keyHandle); err != nil {
		return nil, fmt.Errorf("failed to init sign: %w", err)
	}

	sig, err := s.ctx.Sign(s.session, digest)
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

// Close closes the PKCS#11 session.
func (s *PKCS11Signer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}
	s.closed = true

	var errs []error

	if err := s.ctx.Logout(s.session); err != nil {
		// Ignore CKR_USER_NOT_LOGGED_IN
		if e, ok := err.(pkcs11.Error); !ok || e != pkcs11.CKR_USER_NOT_LOGGED_IN {
			errs = append(errs, fmt.Errorf("logout: %w", err))
		}
	}

	if err := s.ctx.CloseSession(s.session); err != nil {
		errs = append(errs, fmt.Errorf("close session: %w", err))
	}

	if err := s.ctx.Finalize(); err != nil {
		errs = append(errs, fmt.Errorf("finalize: %w", err))
	}

	s.ctx.Destroy()

	if len(errs) > 0 {
		return fmt.Errorf("errors closing PKCS#11 signer: %v", errs)
	}
	return nil
}

// LoadSigner loads a signer from PKCS#11.
func (p *PKCS11SignerProvider) LoadSigner(cfg SignerConfig) (Signer, error) {
	if cfg.Type != SignerTypePKCS11 {
		return nil, fmt.Errorf("PKCS11SignerProvider only supports pkcs11 signers, got: %s", cfg.Type)
	}

	pkcs11Cfg := PKCS11Config{
		ModulePath: cfg.PKCS11Lib,
		TokenLabel: cfg.PKCS11Token,
		PIN:        cfg.PKCS11Pin,
		KeyLabel:   cfg.PKCS11KeyLabel,
	}

	return NewPKCS11Signer(pkcs11Cfg)
}

// GenerateAndSave generates a new key pair in the HSM.
func (p *PKCS11SignerProvider) GenerateAndSave(alg AlgorithmID, cfg SignerConfig) (Signer, error) {
	// TODO: Implement key generation in HSM using C_GenerateKeyPair (Phase 2)
	return nil, fmt.Errorf("PKCS#11 key generation not yet implemented")
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
	ctx := pkcs11.New(modulePath)
	if ctx == nil {
		return nil, fmt.Errorf("failed to load PKCS#11 module: %s", modulePath)
	}
	defer ctx.Destroy()

	if err := ctx.Initialize(); err != nil {
		return nil, fmt.Errorf("failed to initialize PKCS#11 module: %w", err)
	}
	defer ctx.Finalize()

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
func GenerateHSMKeyPair(cfg GenerateHSMKeyPairConfig) (*GenerateHSMKeyPairResult, error) {
	if cfg.ModulePath == "" {
		return nil, fmt.Errorf("PKCS#11 module path is required")
	}
	if cfg.KeyLabel == "" {
		return nil, fmt.Errorf("key label is required")
	}

	ctx := pkcs11.New(cfg.ModulePath)
	if ctx == nil {
		return nil, fmt.Errorf("failed to load PKCS#11 module: %s", cfg.ModulePath)
	}
	defer ctx.Destroy()

	if err := ctx.Initialize(); err != nil {
		return nil, fmt.Errorf("failed to initialize PKCS#11 module: %w", err)
	}
	defer ctx.Finalize()

	// Find the slot
	slotCfg := PKCS11Config{TokenLabel: cfg.TokenLabel}
	slot, err := findSlot(ctx, slotCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to find slot: %w", err)
	}

	// Open R/W session for key generation
	session, err := ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, fmt.Errorf("failed to open session: %w", err)
	}
	defer ctx.CloseSession(session)

	// Login
	if err := ctx.Login(session, pkcs11.CKU_USER, cfg.PIN); err != nil {
		if e, ok := err.(pkcs11.Error); !ok || e != pkcs11.CKR_USER_ALREADY_LOGGED_IN {
			return nil, fmt.Errorf("failed to login: %w", err)
		}
	}
	defer ctx.Logout(session)

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
	switch {
	case cfg.Algorithm == "ecdsa-p256" || cfg.Algorithm == "ecdsa-p384" || cfg.Algorithm == "ecdsa-p521":
		result, err = generateECKeyPair(ctx, session, cfg.KeyLabel, keyID, cfg.Algorithm)
	case cfg.Algorithm == "rsa-2048" || cfg.Algorithm == "rsa-3072" || cfg.Algorithm == "rsa-4096":
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
	ctx := pkcs11.New(modulePath)
	if ctx == nil {
		return nil, fmt.Errorf("failed to load PKCS#11 module: %s", modulePath)
	}
	defer ctx.Destroy()

	if err := ctx.Initialize(); err != nil {
		return nil, fmt.Errorf("failed to initialize PKCS#11 module: %w", err)
	}
	defer ctx.Finalize()

	// Find the slot
	cfg := PKCS11Config{TokenLabel: tokenLabel}
	slot, err := findSlot(ctx, cfg)
	if err != nil {
		return nil, err
	}

	// Open session
	session, err := ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		return nil, fmt.Errorf("failed to open session: %w", err)
	}
	defer ctx.CloseSession(session)

	// Login
	if err := ctx.Login(session, pkcs11.CKU_USER, pin); err != nil {
		if e, ok := err.(pkcs11.Error); !ok || e != pkcs11.CKR_USER_ALREADY_LOGGED_IN {
			return nil, fmt.Errorf("failed to login: %w", err)
		}
	}
	defer ctx.Logout(session)

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
			ctx.FindObjectsFinal(session)
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
	ctx.FindObjectsFinal(session)

	return keys, nil
}
