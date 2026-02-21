package cms

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/ed448"
	pkicrypto "github.com/remiblancher/qpki/pkg/crypto"
)

// =============================================================================
// Ed448 Test Helpers
// =============================================================================

// generateEd448KeyPair generates an Ed448 key pair for testing.
func generateEd448KeyPair(t *testing.T) *testKeyPair {
	t.Helper()
	pub, priv, err := ed448.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed448 key: %v", err)
	}
	return &testKeyPair{
		PrivateKey: priv,
		PublicKey:  pub,
		Algorithm:  "Ed448",
	}
}

// generateEd448Certificate creates a self-signed certificate using Ed448.
// Since Go's x509 doesn't support Ed448 certificates, we create them manually.
func generateEd448Certificate(t *testing.T, kp *testKeyPair) *x509.Certificate {
	t.Helper()

	sigOID := OIDEd448

	// Get public key bytes - handle both ed448.PublicKey and crypto.Signer.Public()
	var pubBytes []byte
	switch pub := kp.PublicKey.(type) {
	case ed448.PublicKey:
		pubBytes = []byte(pub)
	default:
		// For SoftwareSigner, the public key is also ed448.PublicKey
		if ed448Pub, ok := pub.(ed448.PublicKey); ok {
			pubBytes = []byte(ed448Pub)
		} else {
			t.Fatalf("Unexpected public key type: %T", pub)
		}
	}

	// Build SubjectPublicKeyInfo
	spki := struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: sigOID,
		},
		PublicKey: asn1.BitString{
			Bytes:     pubBytes,
			BitLength: len(pubBytes) * 8,
		},
	}

	spkiBytes, err := asn1.Marshal(spki)
	if err != nil {
		t.Fatalf("Failed to marshal SPKI: %v", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("Failed to generate serial number: %v", err)
	}

	// Build TBSCertificate
	tbs := struct {
		Version            int `asn1:"optional,explicit,default:0,tag:0"`
		SerialNumber       *big.Int
		SignatureAlgorithm pkix.AlgorithmIdentifier
		Issuer             pkix.RDNSequence
		Validity           struct {
			NotBefore, NotAfter time.Time
		}
		Subject              pkix.RDNSequence
		SubjectPublicKeyInfo asn1.RawValue
	}{
		Version:            2,
		SerialNumber:       serialNumber,
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: sigOID},
		Issuer: pkix.RDNSequence{
			pkix.RelativeDistinguishedNameSET{
				pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "Ed448 Test Certificate"},
				pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "Test Org"},
			},
		},
		Validity: struct {
			NotBefore, NotAfter time.Time
		}{
			NotBefore: time.Now().Add(-1 * time.Hour),
			NotAfter:  time.Now().Add(24 * time.Hour),
		},
		Subject: pkix.RDNSequence{
			pkix.RelativeDistinguishedNameSET{
				pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "Ed448 Test Certificate"},
				pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "Test Org"},
			},
		},
		SubjectPublicKeyInfo: asn1.RawValue{FullBytes: spkiBytes},
	}

	tbsBytes, err := asn1.Marshal(tbs)
	if err != nil {
		t.Fatalf("Failed to marshal TBSCertificate: %v", err)
	}

	// Sign TBS with Ed448 (pure mode with empty context)
	// Handle both ed448.PrivateKey and crypto.Signer
	var signature []byte
	switch priv := kp.PrivateKey.(type) {
	case ed448.PrivateKey:
		signature = ed448.Sign(priv, tbsBytes, "")
	case crypto.Signer:
		// For SoftwareSigner, use Sign() method
		var signErr error
		signature, signErr = priv.Sign(rand.Reader, tbsBytes, crypto.Hash(0))
		if signErr != nil {
			t.Fatalf("Failed to sign TBS: %v", signErr)
		}
	default:
		t.Fatalf("Unexpected private key type: %T", priv)
	}

	// Build full certificate
	certStruct := struct {
		TBSCertificate     asn1.RawValue
		SignatureAlgorithm pkix.AlgorithmIdentifier
		SignatureValue     asn1.BitString
	}{
		TBSCertificate:     asn1.RawValue{FullBytes: tbsBytes},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: sigOID},
		SignatureValue: asn1.BitString{
			Bytes:     signature,
			BitLength: len(signature) * 8,
		},
	}

	certDER, err := asn1.Marshal(certStruct)
	if err != nil {
		t.Fatalf("Failed to marshal certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

// =============================================================================
// Functional Tests: Ed448 CMS Sign/Verify
// =============================================================================

// TestF_SignVerify_Ed448 tests Ed448 sign and verify round trip.
func TestF_SignVerify_Ed448(t *testing.T) {
	kp := generateEd448KeyPair(t)
	cert := generateEd448Certificate(t, kp)

	content := []byte("Hello, CMS with Ed448!")

	signConfig := &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		IncludeCerts: true,
	}

	signedData, err := Sign(context.Background(), content, signConfig)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Verify OID is Ed448
	oid := extractSignerInfoOID(t, signedData)
	if !oid.Equal(OIDEd448) {
		t.Errorf("OID mismatch: expected Ed448 (%v), got %v", OIDEd448, oid)
	}

	result, err := Verify(context.Background(), signedData, &VerifyConfig{SkipCertVerify: true})
	if err != nil {
		t.Fatalf("Failed to verify: %v", err)
	}

	if string(result.Content) != string(content) {
		t.Errorf("Content mismatch")
	}
}

// TestF_Sign_Ed448_VerifyOID tests Ed448 signature OID in CMS structure.
func TestF_Sign_Ed448_VerifyOID(t *testing.T) {
	kp := generateEd448KeyPair(t)
	cert := generateEd448Certificate(t, kp)

	content := []byte("test content Ed448")

	signedData, err := Sign(context.Background(), content, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	oid := extractSignerInfoOID(t, signedData)
	if !oid.Equal(OIDEd448) {
		t.Errorf("STRUCTURE: Expected OID %v, got %v", OIDEd448, oid)
	}

	_, err = Verify(context.Background(), signedData, &VerifyConfig{SkipCertVerify: true})
	if err != nil {
		t.Errorf("CRYPTO: Verification failed: %v", err)
	}
}

// =============================================================================
// Functional Tests: Ed448 Detached Signatures
// =============================================================================

// TestF_SignVerify_DetachedEd448 tests detached Ed448 signature.
func TestF_SignVerify_DetachedEd448(t *testing.T) {
	kp := generateEd448KeyPair(t)
	cert := generateEd448Certificate(t, kp)

	content := []byte("Detached content for Ed448")

	signConfig := &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		IncludeCerts: true,
		Detached:     true,
	}

	signedData, err := Sign(context.Background(), content, signConfig)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Verify OID
	oid := extractSignerInfoOID(t, signedData)
	if !oid.Equal(OIDEd448) {
		t.Errorf("OID mismatch: expected Ed448, got %v", oid)
	}

	// Verify with detached content
	result, err := Verify(context.Background(), signedData, &VerifyConfig{
		Data:           content,
		SkipCertVerify: true,
	})
	if err != nil {
		t.Fatalf("Failed to verify: %v", err)
	}

	// Content should not be in the result (detached)
	if result.Content != nil {
		t.Error("Expected nil content for detached signature")
	}
}

// TestF_Sign_DetachedEd448_VerifyOID tests detached Ed448 signature OID.
func TestF_Sign_DetachedEd448_VerifyOID(t *testing.T) {
	kp := generateEd448KeyPair(t)
	cert := generateEd448Certificate(t, kp)

	content := []byte("detached Ed448 content")

	signedData, err := Sign(context.Background(), content, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		IncludeCerts: true,
		Detached:     true,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	oid := extractSignerInfoOID(t, signedData)
	if !oid.Equal(OIDEd448) {
		t.Errorf("STRUCTURE: Expected OID %v, got %v", OIDEd448, oid)
	}

	_, err = Verify(context.Background(), signedData, &VerifyConfig{
		Data:           content,
		SkipCertVerify: true,
	})
	if err != nil {
		t.Errorf("CRYPTO: Verification failed: %v", err)
	}
}

// =============================================================================
// Functional Tests: Ed448 Algorithm Mismatch Detection
// =============================================================================

// TestF_Verify_AlgorithmMismatch_Ed448DeclaredECDSAKey tests detection of algorithm confusion
// where the CMS declares Ed448 OID but the certificate has an ECDSA key.
func TestF_Verify_AlgorithmMismatch_Ed448DeclaredECDSAKey(t *testing.T) {
	// Generate Ed448 key for signing
	ed448KP := generateEd448KeyPair(t)
	ed448Cert := generateEd448Certificate(t, ed448KP)

	content := []byte("test content for algorithm confusion")

	// Sign with Ed448
	signedData, err := Sign(context.Background(), content, &SignerConfig{
		Certificate:  ed448Cert,
		Signer:       ed448KP.PrivateKey,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Modify the OID to claim ECDSA-SHA256
	modifiedData := modifySignedDataOID(t, signedData, OIDECDSAWithSHA256)

	// Verification should fail due to algorithm mismatch
	_, err = Verify(context.Background(), modifiedData, &VerifyConfig{SkipCertVerify: true})
	if err == nil {
		t.Error("Verification should fail for Ed448 signature with ECDSA-SHA256 OID")
	}
}

// TestF_Verify_AlgorithmMismatch_ECDSADeclaredEd448Key tests detection of algorithm confusion
// where the CMS declares ECDSA OID but the certificate has an Ed448 key.
func TestF_Verify_AlgorithmMismatch_ECDSADeclaredEd448Key(t *testing.T) {
	// Create an ECDSA signed message
	ecdsaKP := generateECDSAKeyPair(t, elliptic.P256())
	ecdsaCert := generateTestCertificate(t, ecdsaKP)

	content := []byte("test content")

	signedData, err := Sign(context.Background(), content, &SignerConfig{
		Certificate:  ecdsaCert,
		Signer:       ecdsaKP.PrivateKey,
		DigestAlg:    crypto.SHA256,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Modify the OID to claim Ed448
	modifiedData := modifySignedDataOID(t, signedData, OIDEd448)

	// Verification should fail
	_, err = Verify(context.Background(), modifiedData, &VerifyConfig{SkipCertVerify: true})
	if err == nil {
		t.Error("Verification should fail for ECDSA signature with Ed448 OID")
	}
}

// =============================================================================
// Unit Tests: Ed448 Key Validation
// =============================================================================

// TestU_ValidateEd448KeyMatch tests the Ed448 key OID validation.
func TestU_ValidateEd448KeyMatch(t *testing.T) {
	tests := []struct {
		name    string
		oid     asn1.ObjectIdentifier
		wantErr bool
	}{
		{
			name:    "Valid Ed448 OID",
			oid:     OIDEd448,
			wantErr: false,
		},
		{
			name:    "Invalid ECDSA-SHA256 OID",
			oid:     OIDECDSAWithSHA256,
			wantErr: true,
		},
		{
			name:    "Invalid Ed25519 OID",
			oid:     OIDEd25519,
			wantErr: true,
		},
		{
			name:    "Invalid ML-DSA-65 OID",
			oid:     OIDMLDSA65,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateEd448KeyMatch(tt.oid)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateEd448KeyMatch() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// =============================================================================
// Functional Tests: Ed448 Invalid Signature Detection
// =============================================================================

// TestF_Verify_Ed448_InvalidSignature tests that Ed448 verification fails
// when the signature is corrupted.
func TestF_Verify_Ed448_InvalidSignature(t *testing.T) {
	kp := generateEd448KeyPair(t)
	cert := generateEd448Certificate(t, kp)

	content := []byte("content to sign with Ed448")

	signedData, err := Sign(context.Background(), content, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Modify signature
	modifiedData := modifySignature(t, signedData)

	_, err = Verify(context.Background(), modifiedData, &VerifyConfig{SkipCertVerify: true})
	if err == nil {
		t.Error("Verification should fail with corrupted Ed448 signature")
	}
}

// TestF_Verify_Ed448_ModifiedContent tests that Ed448 verification fails
// when the content is modified.
func TestF_Verify_Ed448_ModifiedContent(t *testing.T) {
	kp := generateEd448KeyPair(t)
	cert := generateEd448Certificate(t, kp)

	content := []byte("original content")

	signedData, err := Sign(context.Background(), content, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Modify message digest
	modifiedData := modifyMessageDigest(t, signedData)

	_, err = Verify(context.Background(), modifiedData, &VerifyConfig{SkipCertVerify: true})
	if err == nil {
		t.Error("Verification should fail with modified content digest")
	}
}

// =============================================================================
// Functional Tests: RFC 8419 Compliance
// =============================================================================

// TestF_RFC8419_Ed25519_UsesCorrectDigest tests that Ed25519 signing
// uses the appropriate digest (SHA-512 per RFC 8419).
func TestF_RFC8419_Ed25519_DigestInCMS(t *testing.T) {
	kp := generateEd25519KeyPair(t)
	cert := generateTestCertificate(t, kp)

	content := []byte("RFC 8419 Ed25519 test content")

	signedData, err := Sign(context.Background(), content, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Verify the OID is Ed25519
	oid := extractSignerInfoOID(t, signedData)
	if !oid.Equal(OIDEd25519) {
		t.Errorf("Expected Ed25519 OID, got %v", oid)
	}

	// Verify the signature works (RFC 8419 requires pure mode)
	_, err = Verify(context.Background(), signedData, &VerifyConfig{SkipCertVerify: true})
	if err != nil {
		t.Errorf("Ed25519 verification should succeed: %v", err)
	}
}

// TestF_RFC8419_Ed448_PureMode tests that Ed448 signing uses pure mode
// as required by RFC 8419.
func TestF_RFC8419_Ed448_PureMode(t *testing.T) {
	kp := generateEd448KeyPair(t)
	cert := generateEd448Certificate(t, kp)

	content := []byte("RFC 8419 Ed448 pure mode test")

	signedData, err := Sign(context.Background(), content, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Verify the OID is Ed448
	oid := extractSignerInfoOID(t, signedData)
	if !oid.Equal(OIDEd448) {
		t.Errorf("Expected Ed448 OID, got %v", oid)
	}

	// Verify the signature works (RFC 8419 requires pure mode with empty context)
	_, err = Verify(context.Background(), signedData, &VerifyConfig{SkipCertVerify: true})
	if err != nil {
		t.Errorf("Ed448 verification should succeed: %v", err)
	}
}

// =============================================================================
// Unit Tests: getSignatureAlgorithmIdentifier for EdDSA
// =============================================================================

// TestU_GetSignatureAlgorithmIdentifier_Ed448 tests that the correct OID
// is returned for Ed448 public keys.
func TestU_GetSignatureAlgorithmIdentifier_Ed448(t *testing.T) {
	kp := generateEd448KeyPair(t)

	algId, err := getSignatureAlgorithmIdentifier(kp.PrivateKey, crypto.Hash(0))
	if err != nil {
		t.Fatalf("getSignatureAlgorithmIdentifier failed: %v", err)
	}

	if !algId.Algorithm.Equal(OIDEd448) {
		t.Errorf("Expected OID %v, got %v", OIDEd448, algId.Algorithm)
	}

	// Parameters should be absent per RFC 8419
	if len(algId.Parameters.FullBytes) > 0 && algId.Parameters.FullBytes[0] != 5 {
		// NULL (0x05, 0x00) is technically allowed but empty is preferred
		t.Log("Note: Ed448 AlgorithmIdentifier has parameters, prefer absent parameters")
	}
}

// =============================================================================
// Comparison Tests: Ed25519 vs Ed448
// =============================================================================

// TestF_EdDSA_BothAlgorithmsWork tests that both Ed25519 and Ed448
// can sign and verify CMS messages.
func TestF_EdDSA_BothAlgorithmsWork(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T) (*testKeyPair, *x509.Certificate)
		wantOID asn1.ObjectIdentifier
	}{
		{
			name: "Ed25519",
			setup: func(t *testing.T) (*testKeyPair, *x509.Certificate) {
				kp := generateEd25519KeyPair(t)
				cert := generateTestCertificate(t, kp)
				return kp, cert
			},
			wantOID: OIDEd25519,
		},
		{
			name: "Ed448",
			setup: func(t *testing.T) (*testKeyPair, *x509.Certificate) {
				kp := generateEd448KeyPair(t)
				cert := generateEd448Certificate(t, kp)
				return kp, cert
			},
			wantOID: OIDEd448,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kp, cert := tt.setup(t)

			content := []byte("EdDSA comparison test content for " + tt.name)

			signedData, err := Sign(context.Background(), content, &SignerConfig{
				Certificate:  cert,
				Signer:       kp.PrivateKey,
				IncludeCerts: true,
			})
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}

			oid := extractSignerInfoOID(t, signedData)
			if !oid.Equal(tt.wantOID) {
				t.Errorf("OID mismatch: expected %v, got %v", tt.wantOID, oid)
			}

			result, err := Verify(context.Background(), signedData, &VerifyConfig{SkipCertVerify: true})
			if err != nil {
				t.Fatalf("Verify failed: %v", err)
			}

			if string(result.Content) != string(content) {
				t.Error("Content mismatch after verification")
			}
		})
	}
}

// =============================================================================
// Integration Tests: Ed448 with pkicrypto Package
// =============================================================================

// TestI_Ed448_SignerFromPkiCrypto tests that Ed448 keys generated
// via pkicrypto package work correctly with CMS signing.
func TestU_CMS_Ed448_SignerFromPkiCrypto(t *testing.T) {
	// Generate key using pkicrypto
	signer, err := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgEd448)
	if err != nil {
		t.Fatalf("GenerateSoftwareSigner failed: %v", err)
	}

	// Create a test key pair wrapper
	kp := &testKeyPair{
		PrivateKey: signer,
		PublicKey:  signer.Public(),
		Algorithm:  "Ed448",
	}

	cert := generateEd448Certificate(t, kp)

	content := []byte("Integration test content")

	signedData, err := Sign(context.Background(), content, &SignerConfig{
		Certificate:  cert,
		Signer:       signer,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	_, err = Verify(context.Background(), signedData, &VerifyConfig{SkipCertVerify: true})
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
}
