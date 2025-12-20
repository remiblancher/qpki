package ca

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	"github.com/remiblancher/pki/internal/audit"
	pkicrypto "github.com/remiblancher/pki/internal/crypto"
	"github.com/remiblancher/pki/internal/x509util"
)

// ASN.1 structures for X.509 certificate (RFC 5280).
// These are used for pure PQC certificates since Go's crypto/x509 doesn't support PQC keys.

// tbsCertificate represents the TBSCertificate ASN.1 structure.
type tbsCertificate struct {
	Raw                asn1.RawContent
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Issuer             asn1.RawValue
	Validity           validity
	Subject            asn1.RawValue
	PublicKey          publicKeyInfo
	IssuerUniqueId     asn1.BitString `asn1:"optional,tag:1"`
	SubjectUniqueId    asn1.BitString `asn1:"optional,tag:2"`
	Extensions         []pkix.Extension `asn1:"optional,explicit,tag:3"`
}

// validity represents the X.509 validity period.
type validity struct {
	NotBefore, NotAfter time.Time
}

// publicKeyInfo represents SubjectPublicKeyInfo.
type publicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// certificate represents the full X.509 certificate structure.
type certificate struct {
	TBSCertificate     tbsCertificate
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

// PQCCAConfig holds configuration for initializing a pure PQC CA.
type PQCCAConfig struct {
	// CommonName is the CA's common name.
	CommonName string

	// Organization is the CA's organization.
	Organization string

	// Country is the CA's country code.
	Country string

	// Algorithm is the PQC signature algorithm (ml-dsa-44, ml-dsa-65, ml-dsa-87).
	Algorithm pkicrypto.AlgorithmID

	// ValidityYears is the CA certificate validity in years.
	ValidityYears int

	// PathLen is the maximum path length for the CA.
	PathLen int

	// Passphrase for encrypting the private key.
	Passphrase string
}

// InitializePQCCA creates a new pure PQC CA with self-signed certificate.
//
// This function manually constructs the X.509 certificate using DER encoding
// since Go's crypto/x509 doesn't support PQC algorithms.
//
// Supported algorithms: ml-dsa-44, ml-dsa-65, ml-dsa-87
func InitializePQCCA(store *Store, cfg PQCCAConfig) (*CA, error) {
	if store.Exists() {
		return nil, fmt.Errorf("CA already exists at %s", store.BasePath())
	}

	if !cfg.Algorithm.IsPQC() {
		return nil, fmt.Errorf("algorithm %s is not a PQC algorithm, use Initialize instead", cfg.Algorithm)
	}

	if !cfg.Algorithm.IsSignature() {
		return nil, fmt.Errorf("algorithm %s is not suitable for signing", cfg.Algorithm)
	}

	if err := store.Init(); err != nil {
		return nil, fmt.Errorf("failed to initialize store: %w", err)
	}

	// Generate PQC key pair
	signer, err := pkicrypto.GenerateSoftwareSigner(cfg.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to generate PQC CA key: %w", err)
	}

	// Save private key
	passphrase := []byte(cfg.Passphrase)
	if err := signer.SavePrivateKey(store.CAKeyPath(), passphrase); err != nil {
		return nil, fmt.Errorf("failed to save CA key: %w", err)
	}

	// Get signature algorithm OID
	sigAlgOID, err := algorithmToOID(cfg.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to get algorithm OID: %w", err)
	}

	// Get public key bytes
	kp := &pkicrypto.KeyPair{
		Algorithm: cfg.Algorithm,
		PublicKey: signer.Public(),
	}
	pubBytes, err := kp.PublicKeyBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key bytes: %w", err)
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

	// Compute subject key ID (SHA-256 of public key)
	skidHash := sha256.Sum256(pubBytes)
	skid := skidHash[:20] // Use first 20 bytes as per common practice

	// Build extensions
	extensions, err := buildCAExtensions(cfg.PathLen, skid)
	if err != nil {
		return nil, fmt.Errorf("failed to build extensions: %w", err)
	}

	// Build validity
	now := time.Now()
	notBefore := now.Add(-1 * time.Hour) // Start 1 hour ago to handle clock skew
	notAfter := now.AddDate(cfg.ValidityYears, 0, 0)

	// Build TBSCertificate
	tbs := tbsCertificate{
		Version:      2, // v3
		SerialNumber: serial,
		SignatureAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: sigAlgOID,
		},
		Issuer: asn1.RawValue{FullBytes: subjectDER},
		Validity: validity{
			NotBefore: notBefore,
			NotAfter:  notAfter,
		},
		Subject: asn1.RawValue{FullBytes: subjectDER},
		PublicKey: publicKeyInfo{
			Algorithm: pkix.AlgorithmIdentifier{
				Algorithm: sigAlgOID, // ML-DSA uses same OID for key and signature
			},
			PublicKey: asn1.BitString{
				Bytes:     pubBytes,
				BitLength: len(pubBytes) * 8,
			},
		},
		Extensions: extensions,
	}

	// Marshal TBSCertificate
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal TBSCertificate: %w", err)
	}

	// Sign TBSCertificate with PQC signer
	// ML-DSA signs the full message (not a hash)
	signature, err := signer.Sign(rand.Reader, tbsDER, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to sign certificate: %w", err)
	}

	// Build complete certificate
	cert := certificate{
		TBSCertificate: tbs,
		SignatureAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: sigAlgOID,
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

	// Parse back using Go's x509 to get a proper Certificate object
	// Note: Go's x509.ParseCertificate will parse it but mark signature algorithm as unknown
	parsedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PQC certificate: %w", err)
	}

	// Save CA certificate
	if err := store.SaveCACert(parsedCert); err != nil {
		return nil, fmt.Errorf("failed to save CA certificate: %w", err)
	}

	// Audit: CA created successfully
	if err := audit.LogCACreated(store.BasePath(), parsedCert.Subject.String(), string(cfg.Algorithm), true); err != nil {
		return nil, err
	}

	return &CA{
		store:  store,
		cert:   parsedCert,
		signer: signer,
	}, nil
}

// algorithmToOID returns the OID for a PQC algorithm.
func algorithmToOID(alg pkicrypto.AlgorithmID) (asn1.ObjectIdentifier, error) {
	switch alg {
	case pkicrypto.AlgMLDSA44:
		return x509util.OIDMLDSA44, nil
	case pkicrypto.AlgMLDSA65:
		return x509util.OIDMLDSA65, nil
	case pkicrypto.AlgMLDSA87:
		return x509util.OIDMLDSA87, nil
	default:
		return nil, fmt.Errorf("unsupported PQC algorithm: %s", alg)
	}
}

// buildName creates an RDN sequence for the subject/issuer Name.
func buildName(cn, org, country string) pkix.RDNSequence {
	var rdns pkix.RDNSequence

	if country != "" {
		rdns = append(rdns, pkix.RelativeDistinguishedNameSET{
			{Type: asn1.ObjectIdentifier{2, 5, 4, 6}, Value: country}, // countryName
		})
	}

	if org != "" {
		rdns = append(rdns, pkix.RelativeDistinguishedNameSET{
			{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: org}, // organizationName
		})
	}

	if cn != "" {
		rdns = append(rdns, pkix.RelativeDistinguishedNameSET{
			{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: cn}, // commonName
		})
	}

	return rdns
}

// buildCAExtensions creates the standard CA certificate extensions.
func buildCAExtensions(pathLen int, subjectKeyId []byte) ([]pkix.Extension, error) {
	var exts []pkix.Extension

	// Basic Constraints (critical) - CA:TRUE with path length
	bc := struct {
		IsCA       bool `asn1:"optional"`
		MaxPathLen int  `asn1:"optional"`
	}{
		IsCA:       true,
		MaxPathLen: pathLen,
	}
	bcDER, err := asn1.Marshal(bc)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal BasicConstraints: %w", err)
	}
	exts = append(exts, pkix.Extension{
		Id:       x509util.OIDExtBasicConstraints,
		Critical: true,
		Value:    bcDER,
	})

	// Key Usage (critical) - keyCertSign, cRLSign
	// Bit 5 = keyCertSign, Bit 6 = cRLSign
	ku := asn1.BitString{
		Bytes:     []byte{0x06}, // keyCertSign (5) + cRLSign (6)
		BitLength: 7,
	}
	kuDER, err := asn1.Marshal(ku)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal KeyUsage: %w", err)
	}
	exts = append(exts, pkix.Extension{
		Id:       x509util.OIDExtKeyUsage,
		Critical: true,
		Value:    kuDER,
	})

	// Subject Key Identifier (non-critical)
	skidDER, err := asn1.Marshal(subjectKeyId)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal SubjectKeyIdentifier: %w", err)
	}
	exts = append(exts, pkix.Extension{
		Id:       x509util.OIDExtSubjectKeyId,
		Critical: false,
		Value:    skidDER,
	})

	return exts, nil
}

// VerifyPQCCertificate verifies a pure PQC certificate signature.
func VerifyPQCCertificate(cert, issuer *x509.Certificate) (bool, error) {
	// Extract signature algorithm from certificate
	// Go's x509 will parse it as UnknownSignatureAlgorithm
	alg, err := oidToAlgorithm(cert.SignatureAlgorithm)
	if err != nil {
		return false, err
	}

	// Get issuer's public key
	// For self-signed, issuer == cert
	issuerPubKey := issuer.PublicKey

	// For PQC certificates, the public key in the certificate is raw bytes
	// We need to extract it from the SubjectPublicKeyInfo
	pubBytes, err := extractPQCPublicKey(issuer)
	if err != nil {
		return false, fmt.Errorf("failed to extract issuer public key: %w", err)
	}

	// Parse the public key
	issuerPubKey, err = pkicrypto.ParsePublicKey(alg, pubBytes)
	if err != nil {
		return false, fmt.Errorf("failed to parse issuer public key: %w", err)
	}

	// Verify signature
	return pkicrypto.Verify(alg, issuerPubKey, cert.RawTBSCertificate, cert.Signature), nil
}

// oidToAlgorithm converts a signature algorithm to our AlgorithmID.
func oidToAlgorithm(sigAlg x509.SignatureAlgorithm) (pkicrypto.AlgorithmID, error) {
	// For unknown algorithms, we need to check the OID in the raw certificate
	// This is a limitation - we need to parse the raw DER to get the actual OID
	// For now, return an error for unknown algorithms
	switch sigAlg {
	case x509.ECDSAWithSHA256:
		return pkicrypto.AlgECDSAP256, nil
	case x509.ECDSAWithSHA384:
		return pkicrypto.AlgECDSAP384, nil
	case x509.ECDSAWithSHA512:
		return pkicrypto.AlgECDSAP521, nil
	case x509.PureEd25519:
		return pkicrypto.AlgEd25519, nil
	case x509.SHA256WithRSA:
		return pkicrypto.AlgRSA2048, nil
	default:
		// For PQC, we need to extract from raw
		return "", fmt.Errorf("unknown signature algorithm - use VerifyPQCCertificateRaw for PQC certificates")
	}
}

// extractPQCPublicKey extracts the raw public key bytes from a certificate.
func extractPQCPublicKey(cert *x509.Certificate) ([]byte, error) {
	// Parse the RawSubjectPublicKeyInfo to get the public key bytes
	var spki publicKeyInfo
	_, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &spki)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SubjectPublicKeyInfo: %w", err)
	}
	return spki.PublicKey.Bytes, nil
}

// VerifyPQCCertificateRaw verifies a PQC certificate given the raw DER and issuer cert.
// This handles the case where Go's x509 marks the algorithm as unknown.
func VerifyPQCCertificateRaw(certDER []byte, issuerCert *x509.Certificate) (bool, error) {
	// Parse the raw certificate to extract TBS and signature
	var cert certificate
	_, err := asn1.Unmarshal(certDER, &cert)
	if err != nil {
		return false, fmt.Errorf("failed to parse certificate DER: %w", err)
	}

	// Get the signature algorithm OID
	sigAlgOID := cert.SignatureAlgorithm.Algorithm

	// Map OID to algorithm
	var alg pkicrypto.AlgorithmID
	switch {
	case sigAlgOID.Equal(x509util.OIDMLDSA44):
		alg = pkicrypto.AlgMLDSA44
	case sigAlgOID.Equal(x509util.OIDMLDSA65):
		alg = pkicrypto.AlgMLDSA65
	case sigAlgOID.Equal(x509util.OIDMLDSA87):
		alg = pkicrypto.AlgMLDSA87
	default:
		return false, fmt.Errorf("unsupported signature algorithm OID: %s", sigAlgOID.String())
	}

	// Extract issuer's public key
	issuerPubBytes, err := extractPQCPublicKey(issuerCert)
	if err != nil {
		return false, fmt.Errorf("failed to extract issuer public key: %w", err)
	}

	// Parse the public key
	issuerPubKey, err := pkicrypto.ParsePublicKey(alg, issuerPubBytes)
	if err != nil {
		return false, fmt.Errorf("failed to parse issuer public key: %w", err)
	}

	// Get the TBS bytes (the part that was signed)
	tbsDER, err := asn1.Marshal(cert.TBSCertificate)
	if err != nil {
		return false, fmt.Errorf("failed to re-marshal TBSCertificate: %w", err)
	}

	// Verify signature
	signature := cert.SignatureValue.Bytes
	return pkicrypto.Verify(alg, issuerPubKey, tbsDER, signature), nil
}
