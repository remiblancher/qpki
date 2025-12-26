package ca

import (
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

	"github.com/remiblancher/pki/internal/audit"
	pkicrypto "github.com/remiblancher/pki/internal/crypto"
	"github.com/remiblancher/pki/internal/profile"
	"github.com/remiblancher/pki/internal/x509util"
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

// CompositePublicKey represents the ASN.1 structure for composite public keys.
// CompositePublicKey ::= SEQUENCE SIZE (2) OF SubjectPublicKeyInfo
// Per draft-ietf-lamps-pq-composite-sigs-13 Section 4.
type CompositePublicKey struct {
	MLDSAKey     publicKeyInfo // First: ML-DSA public key
	ClassicalKey publicKeyInfo // Second: Classical public key
}

// compositeCertificate is used for final certificate assembly with raw TBS bytes.
// This ensures the signed TBS bytes are preserved exactly in the output.
type compositeCertificate struct {
	TBSCertificate     asn1.RawValue           // Raw TBS bytes (preserved exactly)
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

// CompositeCAConfig holds configuration for initializing a composite CA.
type CompositeCAConfig struct {
	CommonName string
	Organization string
	Country string
	ClassicalAlgorithm pkicrypto.AlgorithmID
	PQCAlgorithm pkicrypto.AlgorithmID
	ValidityYears int
	PathLen int
	Passphrase string
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
func EncodeCompositePublicKey(
	pqcAlg pkicrypto.AlgorithmID, pqcPub crypto.PublicKey,
	classicalAlg pkicrypto.AlgorithmID, classicalPub crypto.PublicKey,
) (publicKeyInfo, error) {
	// Get PQC SPKI
	pqcSPKI, err := encodeSubjectPublicKeyInfo(pqcPub)
	if err != nil {
		return publicKeyInfo{}, fmt.Errorf("failed to encode PQC public key: %w", err)
	}

	// Get classical SPKI
	classicalSPKI, err := encodeSubjectPublicKeyInfo(classicalPub)
	if err != nil {
		return publicKeyInfo{}, fmt.Errorf("failed to encode classical public key: %w", err)
	}

	// Marshal the composite public key (PQC first per spec)
	compPK := CompositePublicKey{
		MLDSAKey:     pqcSPKI,
		ClassicalKey: classicalSPKI,
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
func encodeCompositePublicKeyWithOID(
	oid asn1.ObjectIdentifier,
	pqcAlg pkicrypto.AlgorithmID, pqcPub crypto.PublicKey,
	classicalAlg pkicrypto.AlgorithmID, classicalPub crypto.PublicKey,
) (publicKeyInfo, error) {
	// Get PQC SPKI
	pqcSPKI, err := encodeSubjectPublicKeyInfo(pqcPub)
	if err != nil {
		return publicKeyInfo{}, fmt.Errorf("failed to encode PQC public key: %w", err)
	}

	// Get classical SPKI
	classicalSPKI, err := encodeSubjectPublicKeyInfo(classicalPub)
	if err != nil {
		return publicKeyInfo{}, fmt.Errorf("failed to encode classical public key: %w", err)
	}

	// Marshal the composite public key (PQC first per spec)
	compPK := CompositePublicKey{
		MLDSAKey:     pqcSPKI,
		ClassicalKey: classicalSPKI,
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

// InitializeCompositeCA creates a new composite CA with self-signed certificate.
// The CA certificate uses IETF composite signature format.
func InitializeCompositeCA(store *Store, cfg CompositeCAConfig) (*CA, error) {
	if store.Exists() {
		return nil, fmt.Errorf("CA already exists at %s", store.BasePath())
	}

	// Get composite algorithm
	compAlg, err := GetCompositeAlgorithm(cfg.ClassicalAlgorithm, cfg.PQCAlgorithm)
	if err != nil {
		return nil, fmt.Errorf("unsupported composite algorithm combination: %w", err)
	}

	if err := store.Init(); err != nil {
		return nil, fmt.Errorf("failed to initialize store: %w", err)
	}

	// Generate classical key pair
	classicalSigner, err := pkicrypto.GenerateSoftwareSigner(cfg.ClassicalAlgorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to generate classical CA key: %w", err)
	}

	// Generate PQC key pair
	pqcSigner, err := pkicrypto.GenerateSoftwareSigner(cfg.PQCAlgorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to generate PQC CA key: %w", err)
	}

	// Save private keys
	passphrase := []byte(cfg.Passphrase)
	if err := classicalSigner.SavePrivateKey(store.CAKeyPath(), passphrase); err != nil {
		return nil, fmt.Errorf("failed to save classical CA key: %w", err)
	}
	if err := pqcSigner.SavePrivateKey(store.CAKeyPath()+".pqc", passphrase); err != nil {
		return nil, fmt.Errorf("failed to save PQC CA key: %w", err)
	}

	// Build composite public key
	compositePubKey, err := EncodeCompositePublicKey(
		cfg.PQCAlgorithm, pqcSigner.Public(),
		cfg.ClassicalAlgorithm, classicalSigner.Public(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to encode composite public key: %w", err)
	}

	// Build subject/issuer Name
	subject := buildName(cfg.CommonName, cfg.Organization, cfg.Country)
	subjectDER, err := asn1.Marshal(subject)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal subject: %w", err)
	}

	// Generate serial number
	serialBytes, err := store.NextSerial()
	if err != nil {
		return nil, fmt.Errorf("failed to get serial number: %w", err)
	}
	serial := new(big.Int).SetBytes(serialBytes)

	// Compute subject key ID (SHA-256 of composite public key)
	skidHash := sha256.Sum256(compositePubKey.PublicKey.Bytes)
	skid := skidHash[:20]

	// Build extensions
	extensions, err := buildCAExtensions(cfg.PathLen, skid)
	if err != nil {
		return nil, fmt.Errorf("failed to build extensions: %w", err)
	}

	// Build validity
	now := time.Now()
	notBefore := now.Add(-1 * time.Hour)
	notAfter := now.AddDate(cfg.ValidityYears, 0, 0)

	// Build TBSCertificate
	tbs := tbsCertificate{
		Version:      2, // v3
		SerialNumber: serial,
		SignatureAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: compAlg.OID,
		},
		Issuer: asn1.RawValue{FullBytes: subjectDER},
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

	// Create composite signature
	signature, err := CreateCompositeSignature(tbsDER, compAlg, pqcSigner, classicalSigner)
	if err != nil {
		return nil, fmt.Errorf("failed to create composite signature: %w", err)
	}

	// Build complete certificate using raw TBS bytes to preserve exact signature
	cert := compositeCertificate{
		TBSCertificate: asn1.RawValue{FullBytes: tbsDER},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: compAlg.OID,
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

	// Save CA certificate
	if err := store.SaveCACert(parsedCert); err != nil {
		return nil, fmt.Errorf("failed to save CA certificate: %w", err)
	}

	// Create composite signer for the CA
	compositeSigner, err := pkicrypto.NewHybridSigner(classicalSigner, pqcSigner)
	if err != nil {
		return nil, fmt.Errorf("failed to create composite signer: %w", err)
	}

	// Audit
	if err := audit.LogCACreated(
		store.BasePath(),
		parsedCert.Subject.String(),
		fmt.Sprintf("Composite: %s", compAlg.Name),
		true,
	); err != nil {
		return nil, err
	}

	return &CA{
		store:  store,
		cert:   parsedCert,
		signer: compositeSigner,
	}, nil
}

// LoadCompositeSigner loads a composite signer from the store.
// This loads both classical and PQC keys and creates a hybrid signer.
func (ca *CA) LoadCompositeSigner(classicalPassphrase, pqcPassphrase string) error {
	// Load classical signer
	classicalSigner, err := pkicrypto.LoadPrivateKey(ca.store.CAKeyPath(), []byte(classicalPassphrase))
	if err != nil {
		_ = audit.LogAuthFailed(ca.store.BasePath(), "failed to load classical CA key")
		return fmt.Errorf("failed to load classical CA key: %w", err)
	}

	// Load PQC signer
	pqcKeyPath := ca.store.CAKeyPath() + ".pqc"
	pqcSigner, err := pkicrypto.LoadPrivateKey(pqcKeyPath, []byte(pqcPassphrase))
	if err != nil {
		_ = audit.LogAuthFailed(ca.store.BasePath(), "failed to load PQC CA key")
		return fmt.Errorf("failed to load PQC CA key: %w", err)
	}

	// Create hybrid signer (used internally for composite)
	hybridSigner, err := pkicrypto.NewHybridSigner(classicalSigner, pqcSigner)
	if err != nil {
		return fmt.Errorf("failed to create composite signer: %w", err)
	}

	if err := audit.LogKeyAccessed(ca.store.BasePath(), true, "Composite CA signing keys loaded"); err != nil {
		return err
	}

	ca.signer = hybridSigner
	return nil
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
	serialBytes, err := ca.store.NextSerial()
	if err != nil {
		return nil, fmt.Errorf("failed to get serial number: %w", err)
	}
	serial := new(big.Int).SetBytes(serialBytes)

	// Compute subject key ID
	skidHash := sha256.Sum256(compositePubKey.PublicKey.Bytes)
	skid := skidHash[:20]

	// Set validity
	notBefore := template.NotBefore
	if notBefore.IsZero() {
		notBefore = time.Now().Add(-1 * time.Hour)
	}
	notAfter := template.NotAfter
	if notAfter.IsZero() {
		if req.Validity > 0 {
			notAfter = notBefore.Add(req.Validity)
		} else {
			notAfter = notBefore.AddDate(1, 0, 0)
		}
	}

	// Build extensions
	extensions, err := buildEndEntityExtensions(template, skid, ca.cert.SubjectKeyId)
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
	if err := ca.store.SaveCert(parsedCert); err != nil {
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
