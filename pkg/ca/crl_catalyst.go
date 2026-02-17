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

	"github.com/remiblancher/post-quantum-pki/pkg/audit"
	pkicrypto "github.com/remiblancher/post-quantum-pki/pkg/crypto"
	"github.com/remiblancher/post-quantum-pki/pkg/x509util"
)

// GenerateCatalystCRL generates a CRL with dual signatures per ITU-T X.509 Section 9.8.
//
// The CRL contains:
//   - Classical signature in standard signatureValue
//   - PQC signature in AltSignatureValue extension (OID 2.5.29.74)
//   - AltSignatureAlgorithm extension (OID 2.5.29.73) indicating the PQC algorithm
//
// The CA must have a HybridSigner loaded to generate Catalyst CRLs.
func (ca *CA) GenerateCatalystCRL(nextUpdate time.Time) ([]byte, error) {
	if ca.signer == nil {
		return nil, fmt.Errorf("CA signer not loaded - call LoadSigner first")
	}

	// CA must be a HybridSigner to generate Catalyst CRLs
	hybridSigner, ok := ca.signer.(pkicrypto.HybridSigner)
	if !ok {
		return nil, fmt.Errorf("CA must use a HybridSigner to generate Catalyst CRLs")
	}

	// Get all revoked certificates
	entries, err := ca.store.ReadIndex(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to read index: %w", err)
	}

	var revokedCerts []pkix.RevokedCertificate
	for _, entry := range entries {
		if entry.Status != "R" {
			continue
		}

		revoked := pkix.RevokedCertificate{
			SerialNumber:   new(big.Int).SetBytes(entry.Serial),
			RevocationTime: entry.Revocation,
		}
		revokedCerts = append(revokedCerts, revoked)
	}

	// Get CRL number
	crlNumber, err := ca.store.NextCRLNumber(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get CRL number: %w", err)
	}

	// Build CRL template
	template := &x509.RevocationList{
		RevokedCertificates: revokedCerts,
		Number:              new(big.Int).SetBytes(crlNumber),
		ThisUpdate:          time.Now().UTC(),
		NextUpdate:          nextUpdate.UTC(),
	}

	// Add AltSignatureAlgorithm extension
	pqcSignerAlg := hybridSigner.PQCSigner().Algorithm()
	altSigAlgExt, err := x509util.EncodeAltSignatureAlgorithm(pqcSignerAlg)
	if err != nil {
		return nil, fmt.Errorf("failed to encode AltSignatureAlgorithm: %w", err)
	}
	template.ExtraExtensions = append(template.ExtraExtensions, altSigAlgExt)

	// Step 1: Create pre-TBS CRL (without AltSignatureValue) using classical signature
	preTBSDER, err := x509.CreateRevocationList(rand.Reader, template, ca.cert, hybridSigner.ClassicalSigner())
	if err != nil {
		return nil, fmt.Errorf("failed to create pre-TBS CRL: %w", err)
	}

	preTBSCRL, err := x509.ParseRevocationList(preTBSDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse pre-TBS CRL: %w", err)
	}

	// Step 2: Build PreTBSCertList for PQC signing
	// Per ITU-T X.509 Section 9.8, PreTBSCertList excludes:
	//   - The signature algorithm field (specific to classical signature)
	//   - The AltSignatureValue extension (would be circular)
	preTBS, err := buildPreTBSCertList(preTBSCRL.Raw)
	if err != nil {
		return nil, fmt.Errorf("failed to build PreTBSCertList: %w", err)
	}

	// Sign PreTBS with PQC signer
	pqcSig, err := hybridSigner.PQCSigner().Sign(rand.Reader, preTBS, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to sign with PQC: %w", err)
	}

	// Step 3: Add AltSignatureValue extension to the template
	altSigValueExt, err := x509util.EncodeAltSignatureValue(pqcSig)
	if err != nil {
		return nil, fmt.Errorf("failed to encode AltSignatureValue: %w", err)
	}
	template.ExtraExtensions = append(template.ExtraExtensions, altSigValueExt)

	// Step 4: Create final CRL with all extensions (re-sign with classical)
	finalDER, err := x509.CreateRevocationList(rand.Reader, template, ca.cert, hybridSigner.ClassicalSigner())
	if err != nil {
		return nil, fmt.Errorf("failed to create final Catalyst CRL: %w", err)
	}

	// Save CRL
	if err := ca.store.SaveCRL(context.Background(), finalDER); err != nil {
		return nil, fmt.Errorf("failed to save CRL: %w", err)
	}

	// Audit: Catalyst CRL generated successfully
	if err := audit.LogCRLGenerated(ca.store.BasePath(), len(revokedCerts), true); err != nil {
		return nil, err
	}

	return finalDER, nil
}

// buildPreTBSCertList constructs the PreTBSCertList for alternative signature verification.
//
// Per ITU-T X.509 Section 9.8, the PreTBSCertList is derived from the TBSCertList
// by excluding:
//   - The signature algorithm field (component at index 1)
//   - The AltSignatureValue extension
//
// This function parses the complete CRL DER, extracts the TBSCertList,
// and rebuilds it without the signature algorithm and AltSignatureValue.
func buildPreTBSCertList(crlDER []byte) ([]byte, error) {
	// Parse the complete CRL to extract TBSCertList
	var crl certificateList
	_, err := asn1.Unmarshal(crlDER, &crl)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CRL: %w", err)
	}

	// Get the raw TBSCertList bytes
	tbsBytes := crl.TBSCertList.Raw
	if len(tbsBytes) == 0 {
		return nil, fmt.Errorf("TBSCertList is empty")
	}

	// Parse TBS as a sequence of raw values
	var tbsSeq asn1.RawValue
	_, err = asn1.Unmarshal(tbsBytes, &tbsSeq)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TBS sequence: %w", err)
	}

	// Parse individual components from the sequence
	var components []asn1.RawValue
	remaining := tbsSeq.Bytes
	for len(remaining) > 0 {
		var comp asn1.RawValue
		rest, err := asn1.Unmarshal(remaining, &comp)
		if err != nil {
			return nil, fmt.Errorf("failed to parse TBS component: %w", err)
		}
		components = append(components, comp)
		remaining = rest
	}

	// TBSCertList structure (RFC 5280 Section 5.1):
	//   version                     INTEGER OPTIONAL (DEFAULT v1) -- BARE integer, not tagged!
	//   signature                   AlgorithmIdentifier
	//   issuer                      Name
	//   thisUpdate                  Time
	//   nextUpdate                  Time OPTIONAL
	//   revokedCertificates         SEQUENCE OF ... OPTIONAL
	//   crlExtensions           [0] Extensions OPTIONAL
	//
	// NOTE: Unlike TBSCertificate where version is [0] EXPLICIT INTEGER,
	// in TBSCertList version is a bare INTEGER (not tagged).

	// Find and remove signature algorithm (skip version if present)
	sigAlgIndex := 0
	if len(components) > 0 && components[0].Class == asn1.ClassUniversal && components[0].Tag == asn1.TagInteger {
		// Version is present as a bare INTEGER (not tagged like in certificates)
		sigAlgIndex = 1
	}

	// Build PreTBS without signature algorithm
	var preTBSComponents []asn1.RawValue
	for i, comp := range components {
		if i == sigAlgIndex {
			// Skip signature algorithm
			continue
		}

		// Check if this is the extensions component (context-specific tag 0)
		if comp.Class == asn1.ClassContextSpecific && comp.Tag == 0 {
			// Filter out AltSignatureValue from extensions
			filteredExt, err := filterAltSignatureValueFromExtensions(comp.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to filter extensions: %w", err)
			}
			if len(filteredExt) > 0 {
				// Rebuild the context-specific wrapper
				rebuiltComp := asn1.RawValue{
					Class:      asn1.ClassContextSpecific,
					Tag:        0,
					IsCompound: true,
					Bytes:      filteredExt,
				}
				preTBSComponents = append(preTBSComponents, rebuiltComp)
			}
			continue
		}

		preTBSComponents = append(preTBSComponents, comp)
	}

	// Rebuild the PreTBS sequence
	var preTBSContent []byte
	for _, comp := range preTBSComponents {
		compBytes, err := asn1.Marshal(comp)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal component: %w", err)
		}
		preTBSContent = append(preTBSContent, compBytes...)
	}

	// Wrap in SEQUENCE
	preTBS := asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      preTBSContent,
	}

	return asn1.Marshal(preTBS)
}

// filterAltSignatureValueFromExtensions removes AltSignatureValue from the extensions sequence.
func filterAltSignatureValueFromExtensions(extBytes []byte) ([]byte, error) {
	// Parse as SEQUENCE OF Extension
	var extSeq asn1.RawValue
	_, err := asn1.Unmarshal(extBytes, &extSeq)
	if err != nil {
		return nil, fmt.Errorf("failed to parse extensions sequence: %w", err)
	}

	var filteredExts []asn1.RawValue
	remaining := extSeq.Bytes
	for len(remaining) > 0 {
		var ext asn1.RawValue
		rest, err := asn1.Unmarshal(remaining, &ext)
		if err != nil {
			return nil, fmt.Errorf("failed to parse extension: %w", err)
		}

		// Check if this is AltSignatureValue (OID 2.5.29.74)
		if !isAltSignatureValueExtension(ext.FullBytes) {
			filteredExts = append(filteredExts, ext)
		}

		remaining = rest
	}

	// Rebuild extensions sequence
	var filteredContent []byte
	for _, ext := range filteredExts {
		extBytes, err := asn1.Marshal(ext)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal extension: %w", err)
		}
		filteredContent = append(filteredContent, extBytes...)
	}

	// Wrap in SEQUENCE
	result := asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      filteredContent,
	}

	return asn1.Marshal(result)
}

// isAltSignatureValueExtension checks if an extension is AltSignatureValue (OID 2.5.29.74).
func isAltSignatureValueExtension(extBytes []byte) bool {
	// Parse extension structure
	var ext struct {
		ExtnID asn1.ObjectIdentifier
	}
	_, err := asn1.Unmarshal(extBytes, &ext)
	if err != nil {
		return false
	}

	// OID 2.5.29.74 = AltSignatureValue
	return ext.ExtnID.Equal(x509util.OIDAltSignatureValue)
}

// VerifyCatalystCRL verifies both signatures on a Catalyst CRL.
// Returns true only if both classical and PQC signatures are valid.
func VerifyCatalystCRL(crlDER []byte, issuerCert *x509.Certificate) (bool, error) {
	// Parse CRL
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		return false, fmt.Errorf("failed to parse CRL: %w", err)
	}

	// Verify classical signature
	if err := crl.CheckSignatureFrom(issuerCert); err != nil {
		return false, nil // Classical signature invalid
	}

	// Extract Catalyst extensions from CRL
	var altSigAlg pkicrypto.AlgorithmID
	var altSigValue []byte

	for _, ext := range crl.Extensions {
		if ext.Id.Equal(x509util.OIDAltSignatureAlgorithm) {
			alg, err := x509util.DecodeAltSignatureAlgorithm(ext)
			if err != nil {
				return false, fmt.Errorf("failed to decode AltSignatureAlgorithm: %w", err)
			}
			altSigAlg = alg
		}
		if ext.Id.Equal(x509util.OIDAltSignatureValue) {
			sig, err := x509util.DecodeAltSignatureValue(ext)
			if err != nil {
				return false, fmt.Errorf("failed to decode AltSignatureValue: %w", err)
			}
			altSigValue = sig
		}
	}

	if altSigAlg == "" || altSigValue == nil {
		return false, fmt.Errorf("CRL does not have Catalyst extensions")
	}

	// Get issuer's PQC public key from Catalyst extensions
	issuerCatInfo, err := x509util.ParseCatalystExtensions(issuerCert.Extensions)
	if err != nil {
		return false, fmt.Errorf("failed to parse issuer Catalyst extensions: %w", err)
	}
	if issuerCatInfo == nil {
		return false, fmt.Errorf("issuer certificate does not have Catalyst extensions")
	}

	// Parse issuer's PQC public key
	issuerPQCPub, err := pkicrypto.ParsePublicKey(issuerCatInfo.AltAlgorithm, issuerCatInfo.AltPublicKey)
	if err != nil {
		return false, fmt.Errorf("failed to parse issuer PQC public key: %w", err)
	}

	// Build PreTBSCertList for PQC verification
	preTBS, err := buildPreTBSCertList(crlDER)
	if err != nil {
		return false, fmt.Errorf("failed to reconstruct TBS for PQC verification: %w", err)
	}

	// Verify PQC signature
	pqcValid := pkicrypto.Verify(altSigAlg, issuerPQCPub, preTBS, altSigValue)

	return pqcValid, nil
}
