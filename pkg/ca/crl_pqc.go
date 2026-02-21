package ca

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	pkicrypto "github.com/remiblancher/qpki/pkg/crypto"
	"github.com/remiblancher/qpki/pkg/x509util"
)

// =============================================================================
// ASN.1 Structures for CRL (RFC 5280)
// =============================================================================

// tbsCertList represents the TBSCertList structure per RFC 5280.
// This is the "To Be Signed" portion of the CRL.
type tbsCertList struct {
	Raw                 asn1.RawContent
	Version             int `asn1:"optional,default:0"`
	Signature           pkix.AlgorithmIdentifier
	Issuer              asn1.RawValue
	ThisUpdate          time.Time
	NextUpdate          time.Time                 `asn1:"optional"`
	RevokedCertificates []revokedCertificateEntry `asn1:"optional"`
	Extensions          []pkix.Extension          `asn1:"optional,explicit,tag:0"`
}

// revokedCertificateEntry represents a single revoked certificate entry.
type revokedCertificateEntry struct {
	SerialNumber   *big.Int
	RevocationTime time.Time
	Extensions     []pkix.Extension `asn1:"optional"`
}

// certificateList represents the complete CRL structure per RFC 5280.
type certificateList struct {
	TBSCertList        tbsCertList
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

// certificateListRaw is used for final assembly with exact TBS bytes preserved.
type certificateListRaw struct {
	TBSCertList        asn1.RawValue
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

// =============================================================================
// CRL Extension OIDs
// =============================================================================

var (
	// OIDCRLNumber is the OID for CRL Number extension (2.5.29.20)
	OIDCRLNumber = asn1.ObjectIdentifier{2, 5, 29, 20}

	// OIDAuthorityKeyIdentifier is the OID for Authority Key Identifier (2.5.29.35)
	OIDAuthorityKeyIdentifier = asn1.ObjectIdentifier{2, 5, 29, 35}
)

// =============================================================================
// PQC CRL Generation
// =============================================================================

// GeneratePQCCRL generates a CRL signed with a PQC algorithm (ML-DSA, SLH-DSA).
//
// This function manually constructs the CRL using DER encoding since Go's
// crypto/x509.CreateRevocationList doesn't support PQC keys.
func (ca *CA) GeneratePQCCRL(nextUpdate time.Time) ([]byte, error) {
	if ca.signer == nil {
		return nil, fmt.Errorf("CA signer not loaded - call LoadSigner first")
	}

	signerAlg := ca.signer.Algorithm()
	if !signerAlg.IsPQC() {
		return nil, fmt.Errorf("GeneratePQCCRL requires a PQC signer, got: %s", signerAlg)
	}

	// Get signature algorithm OID
	sigAlgOID, err := algorithmToOID(signerAlg)
	if err != nil {
		return nil, fmt.Errorf("failed to get algorithm OID: %w", err)
	}

	// Gather revoked certificates from index
	entries, err := ca.store.ReadIndex(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to read index: %w", err)
	}

	var revokedEntries []revokedCertificateEntry
	for _, entry := range entries {
		if entry.Status != "R" {
			continue
		}

		revokedEntries = append(revokedEntries, revokedCertificateEntry{
			SerialNumber:   new(big.Int).SetBytes(entry.Serial),
			RevocationTime: entry.Revocation,
		})
	}

	// Get CRL number
	crlNumber, err := ca.store.NextCRLNumber(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get CRL number: %w", err)
	}

	// Build CRL extensions
	extensions, err := buildCRLExtensions(crlNumber, ca.cert.SubjectKeyId)
	if err != nil {
		return nil, fmt.Errorf("failed to build CRL extensions: %w", err)
	}

	// Get issuer Name as DER
	issuerDER, err := asn1.Marshal(ca.cert.Subject.ToRDNSequence())
	if err != nil {
		return nil, fmt.Errorf("failed to marshal issuer name: %w", err)
	}

	// Build TBSCertList
	tbs := tbsCertList{
		Version: 1, // v2 CRL
		Signature: pkix.AlgorithmIdentifier{
			Algorithm: sigAlgOID,
		},
		Issuer:              asn1.RawValue{FullBytes: issuerDER},
		ThisUpdate:          time.Now().UTC(),
		NextUpdate:          nextUpdate.UTC(),
		RevokedCertificates: revokedEntries,
		Extensions:          extensions,
	}

	// Marshal TBSCertList
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal TBSCertList: %w", err)
	}

	// Sign TBSCertList with PQC signer
	// PQC algorithms (ML-DSA, SLH-DSA) sign the full message, not a hash
	signature, err := ca.signer.Sign(rand.Reader, tbsDER, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to sign CRL: %w", err)
	}

	// Build complete CRL using raw TBS bytes to preserve exact signature
	crl := certificateListRaw{
		TBSCertList: asn1.RawValue{FullBytes: tbsDER},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: sigAlgOID,
		},
		SignatureValue: asn1.BitString{
			Bytes:     signature,
			BitLength: len(signature) * 8,
		},
	}

	// Marshal complete CRL
	crlDER, err := asn1.Marshal(crl)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal CRL: %w", err)
	}

	return crlDER, nil
}

// GeneratePQCCRLWithEntries generates a CRL signed with a PQC algorithm using pre-filtered entries.
// This is used for algorithm-specific CRL generation.
func (ca *CA) GeneratePQCCRLWithEntries(revokedCerts []pkix.RevokedCertificate, crlNumber []byte, nextUpdate time.Time) ([]byte, error) {
	if ca.signer == nil {
		return nil, fmt.Errorf("CA signer not loaded - call LoadSigner first")
	}

	signerAlg := ca.signer.Algorithm()
	if !signerAlg.IsPQC() {
		return nil, fmt.Errorf("GeneratePQCCRLWithEntries requires a PQC signer, got: %s", signerAlg)
	}

	// Get signature algorithm OID
	sigAlgOID, err := algorithmToOID(signerAlg)
	if err != nil {
		return nil, fmt.Errorf("failed to get algorithm OID: %w", err)
	}

	// Convert pkix.RevokedCertificate to revokedCertificateEntry
	var revokedEntries []revokedCertificateEntry
	for _, rc := range revokedCerts {
		revokedEntries = append(revokedEntries, revokedCertificateEntry{
			SerialNumber:   rc.SerialNumber,
			RevocationTime: rc.RevocationTime,
		})
	}

	// Build CRL extensions
	extensions, err := buildCRLExtensions(crlNumber, ca.cert.SubjectKeyId)
	if err != nil {
		return nil, fmt.Errorf("failed to build CRL extensions: %w", err)
	}

	// Get issuer Name as DER
	issuerDER, err := asn1.Marshal(ca.cert.Subject.ToRDNSequence())
	if err != nil {
		return nil, fmt.Errorf("failed to marshal issuer name: %w", err)
	}

	// Build TBSCertList
	tbs := tbsCertList{
		Version: 1, // v2 CRL
		Signature: pkix.AlgorithmIdentifier{
			Algorithm: sigAlgOID,
		},
		Issuer:              asn1.RawValue{FullBytes: issuerDER},
		ThisUpdate:          time.Now().UTC(),
		NextUpdate:          nextUpdate.UTC(),
		RevokedCertificates: revokedEntries,
		Extensions:          extensions,
	}

	// Marshal TBSCertList
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal TBSCertList: %w", err)
	}

	// Sign TBSCertList with PQC signer
	signature, err := ca.signer.Sign(rand.Reader, tbsDER, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to sign CRL: %w", err)
	}

	// Build complete CRL using raw TBS bytes to preserve exact signature
	crl := certificateListRaw{
		TBSCertList: asn1.RawValue{FullBytes: tbsDER},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: sigAlgOID,
		},
		SignatureValue: asn1.BitString{
			Bytes:     signature,
			BitLength: len(signature) * 8,
		},
	}

	// Marshal complete CRL
	crlDER, err := asn1.Marshal(crl)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal CRL: %w", err)
	}

	return crlDER, nil
}

// buildCRLExtensions creates the standard CRL extensions.
func buildCRLExtensions(crlNumber []byte, authorityKeyId []byte) ([]pkix.Extension, error) {
	var exts []pkix.Extension

	// CRL Number extension (non-critical) - RFC 5280 Section 5.2.3
	crlNumValue := new(big.Int).SetBytes(crlNumber)
	crlNumDER, err := asn1.Marshal(crlNumValue)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal CRL number: %w", err)
	}
	exts = append(exts, pkix.Extension{
		Id:       OIDCRLNumber,
		Critical: false,
		Value:    crlNumDER,
	})

	// Authority Key Identifier extension (non-critical) - RFC 5280 Section 5.2.1
	if len(authorityKeyId) > 0 {
		// AuthorityKeyIdentifier ::= SEQUENCE {
		//   keyIdentifier [0] IMPLICIT KeyIdentifier OPTIONAL
		// }
		akid := struct {
			KeyIdentifier []byte `asn1:"optional,tag:0"`
		}{
			KeyIdentifier: authorityKeyId,
		}
		akidDER, err := asn1.Marshal(akid)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal authority key identifier: %w", err)
		}
		exts = append(exts, pkix.Extension{
			Id:       OIDAuthorityKeyIdentifier,
			Critical: false,
			Value:    akidDER,
		})
	}

	return exts, nil
}

// =============================================================================
// PQC CRL Verification
// =============================================================================

// VerifyPQCCRL verifies a CRL signed with a PQC algorithm.
//
// This function parses the CRL DER, extracts the signature algorithm OID,
// and uses the appropriate PQC verification function.
func VerifyPQCCRL(crlDER []byte, issuerCert *x509.Certificate) (bool, error) {
	// Parse the CRL to extract TBS and signature
	var crl certificateList
	_, err := asn1.Unmarshal(crlDER, &crl)
	if err != nil {
		return false, fmt.Errorf("failed to parse CRL DER: %w", err)
	}

	// Get the signature algorithm OID
	sigAlgOID := crl.SignatureAlgorithm.Algorithm

	// Map OID to algorithm ID
	alg, err := oidToAlgorithmID(sigAlgOID)
	if err != nil {
		return false, err
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
	// We need to re-marshal to get the exact bytes
	tbsDER, err := asn1.Marshal(crl.TBSCertList)
	if err != nil {
		return false, fmt.Errorf("failed to re-marshal TBSCertList: %w", err)
	}

	// Verify signature
	signature := crl.SignatureValue.Bytes
	return pkicrypto.Verify(alg, issuerPubKey, tbsDER, signature), nil
}

// oidToAlgorithmID maps a signature algorithm OID to AlgorithmID.
func oidToAlgorithmID(oid asn1.ObjectIdentifier) (pkicrypto.AlgorithmID, error) {
	switch {
	case oid.Equal(x509util.OIDMLDSA44):
		return pkicrypto.AlgMLDSA44, nil
	case oid.Equal(x509util.OIDMLDSA65):
		return pkicrypto.AlgMLDSA65, nil
	case oid.Equal(x509util.OIDMLDSA87):
		return pkicrypto.AlgMLDSA87, nil
	case oid.Equal(x509util.OIDSLHDSA128s):
		return pkicrypto.AlgSLHDSA128s, nil
	case oid.Equal(x509util.OIDSLHDSA128f):
		return pkicrypto.AlgSLHDSA128f, nil
	case oid.Equal(x509util.OIDSLHDSA192s):
		return pkicrypto.AlgSLHDSA192s, nil
	case oid.Equal(x509util.OIDSLHDSA192f):
		return pkicrypto.AlgSLHDSA192f, nil
	case oid.Equal(x509util.OIDSLHDSA256s):
		return pkicrypto.AlgSLHDSA256s, nil
	case oid.Equal(x509util.OIDSLHDSA256f):
		return pkicrypto.AlgSLHDSA256f, nil
	default:
		return "", fmt.Errorf("unsupported signature algorithm OID: %s", oid.String())
	}
}

// IsPQCSignatureOID returns true if the OID is a PQC signature algorithm.
func IsPQCSignatureOID(oid asn1.ObjectIdentifier) bool {
	_, err := oidToAlgorithmID(oid)
	return err == nil
}

// =============================================================================
// CRL Signature Algorithm OID Extraction
// =============================================================================

// ExtractCRLSignatureAlgorithmOID extracts the signature algorithm OID from a CRL.
func ExtractCRLSignatureAlgorithmOID(crlDER []byte) (asn1.ObjectIdentifier, error) {
	var crl certificateList
	_, err := asn1.Unmarshal(crlDER, &crl)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CRL: %w", err)
	}
	return crl.SignatureAlgorithm.Algorithm, nil
}
