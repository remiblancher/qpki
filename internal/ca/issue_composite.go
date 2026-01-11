package ca

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	"github.com/remiblancher/post-quantum-pki/internal/audit"
	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
	"github.com/remiblancher/post-quantum-pki/internal/profile"
	"github.com/remiblancher/post-quantum-pki/internal/x509util"
)

// CompositeAlgorithm defines a composite signature algorithm combination.
// Per IETF draft-ietf-lamps-pq-composite-sigs-13.
type CompositeAlgorithm struct {
	Name         string
	OID          asn1.ObjectIdentifier
	ClassicalAlg pkicrypto.AlgorithmID
	PQCAlg       pkicrypto.AlgorithmID
	HashFunc     crypto.Hash
}

// Supported composite algorithm combinations.
var CompositeAlgorithms = []CompositeAlgorithm{
	{
		Name:         "MLDSA87-ECDSA-P384-SHA512",
		OID:          x509util.OIDMLDSA87ECDSAP384SHA512,
		ClassicalAlg: pkicrypto.AlgECDSAP384,
		PQCAlg:       pkicrypto.AlgMLDSA87,
		HashFunc:     crypto.SHA512,
	},
	{
		Name:         "MLDSA65-ECDSA-P256-SHA512",
		OID:          x509util.OIDMLDSA65ECDSAP256SHA512,
		ClassicalAlg: pkicrypto.AlgECDSAP256,
		PQCAlg:       pkicrypto.AlgMLDSA65,
		HashFunc:     crypto.SHA512,
	},
}

// CompositeSignatureValue represents the ASN.1 structure for composite signatures.
// CompositeSignatureValue ::= SEQUENCE SIZE (2) OF BIT STRING
// Per draft-ietf-lamps-pq-composite-sigs-13 Section 5.
type CompositeSignatureValue struct {
	MLDSASig     asn1.BitString // First: ML-DSA signature
	ClassicalSig asn1.BitString // Second: Classical (ECDSA) signature
}

// CompositeSignaturePublicKey represents the ASN.1 structure for composite public keys.
// CompositeSignaturePublicKey ::= SEQUENCE SIZE (2) OF BIT STRING
// Per draft-ietf-lamps-pq-composite-sigs-13 Section 6.
// Each BIT STRING contains the raw public key bytes (not wrapped in SubjectPublicKeyInfo).
type CompositeSignaturePublicKey struct {
	MLDSAKey     asn1.BitString // First: ML-DSA public key bytes
	ClassicalKey asn1.BitString // Second: Classical public key bytes
}

// compositeCertificate is used for final certificate assembly with raw TBS bytes.
// This ensures the signed TBS bytes are preserved exactly in the output.
type compositeCertificate struct {
	TBSCertificate     asn1.RawValue           // Raw TBS bytes (preserved exactly)
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

// CompositeRequest holds parameters for issuing a composite certificate.
type CompositeRequest struct {
	Template           *x509.Certificate
	ClassicalPublicKey crypto.PublicKey
	PQCPublicKey       crypto.PublicKey
	ClassicalAlg       pkicrypto.AlgorithmID
	PQCAlg             pkicrypto.AlgorithmID
	Extensions         *profile.ExtensionsConfig
	Validity           time.Duration
}

// GetCompositeAlgorithm finds the composite algorithm for a given pair.
func GetCompositeAlgorithm(classical, pqc pkicrypto.AlgorithmID) (*CompositeAlgorithm, error) {
	for i := range CompositeAlgorithms {
		alg := &CompositeAlgorithms[i]
		if alg.ClassicalAlg == classical && alg.PQCAlg == pqc {
			return alg, nil
		}
	}
	return nil, fmt.Errorf("no composite algorithm for %s + %s", classical, pqc)
}

// GetCompositeAlgorithmByOID finds the composite algorithm by OID.
func GetCompositeAlgorithmByOID(oid asn1.ObjectIdentifier) (*CompositeAlgorithm, error) {
	for i := range CompositeAlgorithms {
		alg := &CompositeAlgorithms[i]
		if alg.OID.Equal(oid) {
			return alg, nil
		}
	}
	return nil, fmt.Errorf("unknown composite algorithm OID: %s", oid.String())
}

// IsCompositeOID checks if an OID is a composite signature algorithm.
func IsCompositeOID(oid asn1.ObjectIdentifier) bool {
	for _, alg := range CompositeAlgorithms {
		if alg.OID.Equal(oid) {
			return true
		}
	}
	return false
}

// BuildDomainSeparator creates the domain separator per draft Section 5.2.
// The domain separator is the DER encoding of the composite algorithm OID.
func BuildDomainSeparator(oid asn1.ObjectIdentifier) ([]byte, error) {
	return asn1.Marshal(oid)
}

// EncodeCompositePublicKey encodes two public keys into composite format.
// Order per spec: ML-DSA first, then classical.
// Per draft-ietf-lamps-pq-composite-sigs-13, the encoding is:
//   SubjectPublicKeyInfo.publicKey = BIT STRING containing:
//     CompositeSignaturePublicKey ::= SEQUENCE SIZE (2) OF BIT STRING
func EncodeCompositePublicKey(
	pqcAlg pkicrypto.AlgorithmID, pqcPub crypto.PublicKey,
	classicalAlg pkicrypto.AlgorithmID, classicalPub crypto.PublicKey,
) (publicKeyInfo, error) {
	// Get raw PQC public key bytes
	pqcBytes, err := getPublicKeyBytes(pqcPub)
	if err != nil {
		return publicKeyInfo{}, fmt.Errorf("failed to get PQC public key bytes: %w", err)
	}

	// Get raw classical public key bytes
	classicalBytes, err := getPublicKeyBytes(classicalPub)
	if err != nil {
		return publicKeyInfo{}, fmt.Errorf("failed to get classical public key bytes: %w", err)
	}

	// Marshal the composite public key (PQC first per spec)
	// CompositeSignaturePublicKey ::= SEQUENCE SIZE (2) OF BIT STRING
	compPK := CompositeSignaturePublicKey{
		MLDSAKey: asn1.BitString{
			Bytes:     pqcBytes,
			BitLength: len(pqcBytes) * 8,
		},
		ClassicalKey: asn1.BitString{
			Bytes:     classicalBytes,
			BitLength: len(classicalBytes) * 8,
		},
	}

	compPKBytes, err := asn1.Marshal(compPK)
	if err != nil {
		return publicKeyInfo{}, fmt.Errorf("failed to marshal composite public key: %w", err)
	}

	// Get composite algorithm OID
	compAlg, err := GetCompositeAlgorithm(classicalAlg, pqcAlg)
	if err != nil {
		return publicKeyInfo{}, err
	}

	return publicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: compAlg.OID,
		},
		PublicKey: asn1.BitString{
			Bytes:     compPKBytes,
			BitLength: len(compPKBytes) * 8,
		},
	}, nil
}

// encodeCompositePublicKeyWithOID encodes two public keys into composite format with explicit OID.
// This is used when the subject's algorithm differs from the lookup algorithms.
// Per draft-ietf-lamps-pq-composite-sigs-13, the encoding is:
//   SubjectPublicKeyInfo.publicKey = BIT STRING containing:
//     CompositeSignaturePublicKey ::= SEQUENCE SIZE (2) OF BIT STRING
func encodeCompositePublicKeyWithOID(
	oid asn1.ObjectIdentifier,
	pqcAlg pkicrypto.AlgorithmID, pqcPub crypto.PublicKey,
	classicalAlg pkicrypto.AlgorithmID, classicalPub crypto.PublicKey,
) (publicKeyInfo, error) {
	// Get raw PQC public key bytes
	pqcBytes, err := getPublicKeyBytes(pqcPub)
	if err != nil {
		return publicKeyInfo{}, fmt.Errorf("failed to get PQC public key bytes: %w", err)
	}

	// Get raw classical public key bytes
	classicalBytes, err := getPublicKeyBytes(classicalPub)
	if err != nil {
		return publicKeyInfo{}, fmt.Errorf("failed to get classical public key bytes: %w", err)
	}

	// Marshal the composite public key (PQC first per spec)
	// CompositeSignaturePublicKey ::= SEQUENCE SIZE (2) OF BIT STRING
	compPK := CompositeSignaturePublicKey{
		MLDSAKey: asn1.BitString{
			Bytes:     pqcBytes,
			BitLength: len(pqcBytes) * 8,
		},
		ClassicalKey: asn1.BitString{
			Bytes:     classicalBytes,
			BitLength: len(classicalBytes) * 8,
		},
	}

	compPKBytes, err := asn1.Marshal(compPK)
	if err != nil {
		return publicKeyInfo{}, fmt.Errorf("failed to marshal composite public key: %w", err)
	}

	return publicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: oid,
		},
		PublicKey: asn1.BitString{
			Bytes:     compPKBytes,
			BitLength: len(compPKBytes) * 8,
		},
	}, nil
}

// CreateCompositeSignature creates a composite signature from TBS bytes.
// Per draft Section 5: M' = DomainSeparator || TBS
func CreateCompositeSignature(
	tbsBytes []byte,
	compAlg *CompositeAlgorithm,
	pqcSigner, classicalSigner pkicrypto.Signer,
) ([]byte, error) {
	// Build domain separator
	domainSep, err := BuildDomainSeparator(compAlg.OID)
	if err != nil {
		return nil, fmt.Errorf("failed to build domain separator: %w", err)
	}

	// Prepend domain separator to TBS: M' = DomainSeparator || TBS
	messageToSign := append(domainSep, tbsBytes...)

	// Sign with ML-DSA (signs full message internally)
	pqcSig, err := pqcSigner.Sign(rand.Reader, messageToSign, nil)
	if err != nil {
		return nil, fmt.Errorf("ML-DSA signing failed: %w", err)
	}

	// For classical ECDSA, hash with SHA-512 then sign
	h := sha512.New()
	h.Write(messageToSign)
	digest := h.Sum(nil)

	classicalSig, err := classicalSigner.Sign(rand.Reader, digest, nil)
	if err != nil {
		return nil, fmt.Errorf("classical signing failed: %w", err)
	}

	// Encode as CompositeSignatureValue (ML-DSA first, then classical)
	compSig := CompositeSignatureValue{
		MLDSASig: asn1.BitString{
			Bytes:     pqcSig,
			BitLength: len(pqcSig) * 8,
		},
		ClassicalSig: asn1.BitString{
			Bytes:     classicalSig,
			BitLength: len(classicalSig) * 8,
		},
	}

	return asn1.Marshal(compSig)
}

// IssueComposite issues a certificate using IETF composite signatures.
// The CA must have a composite/hybrid signer loaded.
func (ca *CA) IssueComposite(req CompositeRequest) (*x509.Certificate, error) {
	if ca.signer == nil {
		return nil, fmt.Errorf("CA signer not loaded - call LoadCompositeSigner first")
	}

	// CA must be a HybridSigner (used for both Catalyst and Composite)
	hybridSigner, ok := ca.signer.(pkicrypto.HybridSigner)
	if !ok {
		return nil, fmt.Errorf("CA must use a composite signer to issue composite certificates")
	}

	// Get the CA's composite algorithm (for signature, not subject's algorithm)
	caSignatureOID, err := x509util.ExtractSignatureAlgorithmOID(ca.cert.Raw)
	if err != nil {
		return nil, fmt.Errorf("failed to extract CA signature algorithm: %w", err)
	}
	caCompAlg, err := GetCompositeAlgorithmByOID(caSignatureOID)
	if err != nil {
		return nil, fmt.Errorf("CA is not using a composite algorithm: %w", err)
	}

	// Get subject's composite algorithm (for the subject public key)
	subjectCompAlg, err := GetCompositeAlgorithm(req.ClassicalAlg, req.PQCAlg)
	if err != nil {
		return nil, err
	}

	template := req.Template
	if template == nil {
		template = &x509.Certificate{}
	}

	// Build composite public key for the subject (uses subject's algorithm)
	compositePubKey, err := encodeCompositePublicKeyWithOID(
		subjectCompAlg.OID,
		req.PQCAlg, req.PQCPublicKey,
		req.ClassicalAlg, req.ClassicalPublicKey,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to encode composite public key: %w", err)
	}

	// Build subject from template
	subjectDER, err := asn1.Marshal(template.Subject.ToRDNSequence())
	if err != nil {
		return nil, fmt.Errorf("failed to marshal subject: %w", err)
	}

	// Build issuer from CA certificate
	issuerDER, err := asn1.Marshal(ca.cert.Subject.ToRDNSequence())
	if err != nil {
		return nil, fmt.Errorf("failed to marshal issuer: %w", err)
	}

	// Generate serial number
	serialBytes, err := ca.store.NextSerial(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get serial number: %w", err)
	}
	serial := new(big.Int).SetBytes(serialBytes)

	// Compute subject key ID
	skidHash := sha256.Sum256(compositePubKey.PublicKey.Bytes)
	skid := skidHash[:20]

	// Set validity (use UTC for X.509 standard compliance)
	notBefore := template.NotBefore
	if notBefore.IsZero() {
		notBefore = time.Now().UTC().Add(-1 * time.Hour)
	}
	notAfter := template.NotAfter
	if notAfter.IsZero() {
		if req.Validity > 0 {
			notAfter = notBefore.Add(req.Validity)
		} else {
			notAfter = notBefore.AddDate(1, 0, 0)
		}
	}

	// Determine if EKU should be critical (from profile)
	ekuCritical := false
	if req.Extensions != nil && req.Extensions.ExtKeyUsage != nil {
		ekuCritical = req.Extensions.ExtKeyUsage.IsCritical()
	}

	// Build extensions
	extensions, err := buildEndEntityExtensions(template, skid, ca.cert.SubjectKeyId, ekuCritical)
	if err != nil {
		return nil, fmt.Errorf("failed to build extensions: %w", err)
	}

	// Build TBSCertificate (signature algorithm is CA's algorithm)
	tbs := tbsCertificate{
		Version:      2, // v3
		SerialNumber: serial,
		SignatureAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: caCompAlg.OID,
		},
		Issuer: asn1.RawValue{FullBytes: issuerDER},
		Validity: validity{
			NotBefore: notBefore,
			NotAfter:  notAfter,
		},
		Subject:    asn1.RawValue{FullBytes: subjectDER},
		PublicKey:  compositePubKey,
		Extensions: extensions,
	}

	// Marshal TBSCertificate
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal TBSCertificate: %w", err)
	}

	// Create composite signature using CA's keys and CA's algorithm
	signature, err := CreateCompositeSignature(
		tbsDER,
		caCompAlg,
		hybridSigner.PQCSigner(),
		hybridSigner.ClassicalSigner(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create composite signature: %w", err)
	}

	// Build complete certificate using raw TBS bytes to preserve exact signature
	cert := compositeCertificate{
		TBSCertificate: asn1.RawValue{FullBytes: tbsDER},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: caCompAlg.OID,
		},
		SignatureValue: asn1.BitString{
			Bytes:     signature,
			BitLength: len(signature) * 8,
		},
	}

	// Marshal complete certificate
	certDER, err := asn1.Marshal(cert)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal certificate: %w", err)
	}

	// Parse back using Go's x509
	parsedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse composite certificate: %w", err)
	}

	// Save to store
	if err := ca.store.SaveCert(context.Background(), parsedCert); err != nil {
		return nil, fmt.Errorf("failed to save certificate: %w", err)
	}

	// Audit (subject algorithm for the cert, CA algorithm for the signature)
	if err := audit.LogCertIssued(
		ca.store.BasePath(),
		fmt.Sprintf("0x%X", parsedCert.SerialNumber.Bytes()),
		parsedCert.Subject.String(),
		"Composite",
		fmt.Sprintf("%s (signed by %s)", subjectCompAlg.Name, caCompAlg.Name),
		true,
	); err != nil {
		return nil, err
	}

	return parsedCert, nil
}

// IsCompositeCertificate checks if a certificate uses a composite signature algorithm.
func IsCompositeCertificate(cert *x509.Certificate) bool {
	sigAlgOID, err := x509util.ExtractSignatureAlgorithmOID(cert.Raw)
	if err != nil {
		return false
	}
	return IsCompositeOID(sigAlgOID)
}
