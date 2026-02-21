package ca

import (
	"context"
	"crypto/sha512"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	"github.com/remiblancher/qpki/pkg/audit"
	pkicrypto "github.com/remiblancher/qpki/pkg/crypto"
	"github.com/remiblancher/qpki/pkg/x509util"
)

// GenerateCompositeCRL generates a CRL with IETF composite signature.
//
// Per draft-ietf-lamps-pq-composite-sigs, the signature combines ML-DSA + classical (ECDSA/RSA/Ed25519).
// The signature value is a CompositeSignatureValue structure containing both signatures.
//
// The CA must have a HybridSigner loaded (same signer used for composite CAs).
func (ca *CA) GenerateCompositeCRL(nextUpdate time.Time) ([]byte, error) {
	if ca.signer == nil {
		return nil, fmt.Errorf("CA signer not loaded - call LoadCompositeSigner first")
	}

	// CA must be a HybridSigner to generate composite CRLs
	hybridSigner, ok := ca.signer.(pkicrypto.HybridSigner)
	if !ok {
		return nil, fmt.Errorf("CA must use a HybridSigner to generate Composite CRLs")
	}

	// Get the CA's composite algorithm from its certificate
	caSignatureOID, err := x509util.ExtractSignatureAlgorithmOID(ca.cert.Raw)
	if err != nil {
		return nil, fmt.Errorf("failed to extract CA signature algorithm: %w", err)
	}
	compAlg, err := GetCompositeAlgorithmByOID(caSignatureOID)
	if err != nil {
		return nil, fmt.Errorf("CA is not using a composite algorithm: %w", err)
	}

	// Get all revoked certificates
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

	// Build TBSCertList with composite signature algorithm
	tbs := tbsCertList{
		Version: 1, // v2 CRL
		Signature: pkix.AlgorithmIdentifier{
			Algorithm: compAlg.OID,
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

	// Create composite signature (using the same function as IssueComposite)
	signature, err := CreateCompositeSignature(
		tbsDER,
		compAlg,
		hybridSigner.PQCSigner(),
		hybridSigner.ClassicalSigner(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create composite signature: %w", err)
	}

	// Build complete CRL using raw TBS bytes to preserve exact signature
	crl := certificateListRaw{
		TBSCertList: asn1.RawValue{FullBytes: tbsDER},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: compAlg.OID,
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

	// Save CRL
	if err := ca.store.SaveCRL(context.Background(), crlDER); err != nil {
		return nil, fmt.Errorf("failed to save CRL: %w", err)
	}

	// Audit: Composite CRL generated successfully
	if err := audit.LogCRLGenerated(ca.store.BasePath(), len(revokedEntries), true); err != nil {
		return nil, err
	}

	return crlDER, nil
}

// VerifyCompositeCRL verifies a CRL signed with a composite signature algorithm.
//
// This function verifies both the ML-DSA and classical signatures contained in
// the CompositeSignatureValue structure.
func VerifyCompositeCRL(crlDER []byte, issuerCert []byte) (bool, error) {
	// Parse the CRL
	var crl certificateList
	_, err := asn1.Unmarshal(crlDER, &crl)
	if err != nil {
		return false, fmt.Errorf("failed to parse CRL: %w", err)
	}

	// Get the signature algorithm OID
	sigAlgOID := crl.SignatureAlgorithm.Algorithm

	// Check if it's a composite algorithm
	compAlg, err := GetCompositeAlgorithmByOID(sigAlgOID)
	if err != nil {
		return false, fmt.Errorf("CRL is not using a composite algorithm: %w", err)
	}

	// Parse the composite signature value
	var compSig CompositeSignatureValue
	_, err = asn1.Unmarshal(crl.SignatureValue.Bytes, &compSig)
	if err != nil {
		return false, fmt.Errorf("failed to parse composite signature: %w", err)
	}

	// Get the TBS bytes
	tbsDER, err := asn1.Marshal(crl.TBSCertList)
	if err != nil {
		return false, fmt.Errorf("failed to re-marshal TBSCertList: %w", err)
	}

	// Extract public keys from issuer certificate
	pqcPubBytes, classicalPubBytes, err := extractCompositePublicKeys(issuerCert)
	if err != nil {
		return false, fmt.Errorf("failed to extract composite public keys: %w", err)
	}

	// Parse PQC public key
	pqcPub, err := pkicrypto.ParsePublicKey(compAlg.PQCAlg, pqcPubBytes)
	if err != nil {
		return false, fmt.Errorf("failed to parse PQC public key: %w", err)
	}

	// Parse classical public key
	classicalPub, err := pkicrypto.ParsePublicKey(compAlg.ClassicalAlg, classicalPubBytes)
	if err != nil {
		return false, fmt.Errorf("failed to parse classical public key: %w", err)
	}

	// Build domain separator
	domainSep, err := BuildDomainSeparator(compAlg.OID)
	if err != nil {
		return false, fmt.Errorf("failed to build domain separator: %w", err)
	}

	// Prepend domain separator to TBS: M' = DomainSeparator || TBS
	messageToVerify := append(domainSep, tbsDER...)

	// Verify PQC signature (signs full message)
	pqcValid := pkicrypto.Verify(compAlg.PQCAlg, pqcPub, messageToVerify, compSig.MLDSASig.Bytes)
	if !pqcValid {
		return false, nil
	}

	// Verify classical signature (signs hash of message)
	// ECDSA verification expects the hash, not the full message
	h := sha512.New()
	h.Write(messageToVerify)
	digest := h.Sum(nil)

	classicalValid := pkicrypto.Verify(compAlg.ClassicalAlg, classicalPub, digest, compSig.ClassicalSig.Bytes)
	if !classicalValid {
		return false, nil
	}

	return true, nil
}

// extractCompositePublicKeys extracts the PQC and classical public keys from a composite certificate.
func extractCompositePublicKeys(certDER []byte) (pqcPubBytes, classicalPubBytes []byte, err error) {
	// Parse the certificate to extract the composite public key
	var cert struct {
		TBSCertificate struct {
			Raw                asn1.RawContent
			Version            int `asn1:"optional,explicit,default:0,tag:0"`
			SerialNumber       *big.Int
			SignatureAlgorithm pkix.AlgorithmIdentifier
			Issuer             asn1.RawValue
			Validity           struct {
				NotBefore time.Time
				NotAfter  time.Time
			}
			Subject       asn1.RawValue
			PublicKeyInfo publicKeyInfo
		}
	}

	_, err = asn1.Unmarshal(certDER, &cert)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// The public key should be a CompositeSignaturePublicKey
	var compPK CompositeSignaturePublicKey
	_, err = asn1.Unmarshal(cert.TBSCertificate.PublicKeyInfo.PublicKey.Bytes, &compPK)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse composite public key: %w", err)
	}

	return compPK.MLDSAKey.Bytes, compPK.ClassicalKey.Bytes, nil
}
