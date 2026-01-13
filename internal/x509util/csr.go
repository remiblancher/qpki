package x509util

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"

	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
)

// CSR attribute OIDs for dual-signature support.
// These follow the pattern from draft-ietf-lamps-csr-attestation.
var (
	// OIDSubjectAltPublicKeyInfo is the attribute for the alternative public key in a CSR.
	// This carries the PQC public key alongside the classical public key.
	OIDSubjectAltPublicKeyInfo = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 2, 100}

	// OIDAltSignatureAlgorithmAttr is the attribute for the alternative signature algorithm.
	OIDAltSignatureAlgorithmAttr = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 2, 101}

	// OIDAltSignatureValueAttr is the attribute for the alternative signature value.
	OIDAltSignatureValueAttr = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 2, 102}
)

// rawAttribute represents a PKCS#10 attribute in standard format.
// This avoids the extra nesting that Go's pkix.AttributeTypeAndValueSET produces.
// The Values field is wrapped in a SET by Go's asn1 marshaler due to the tag.
type rawAttribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

// HybridCSR represents a CSR with dual signatures (classical + PQC).
// This is used for Catalyst certificate enrollment where the subject
// proves possession of both key pairs.
type HybridCSR struct {
	// Primary is the standard X.509 CSR (signed with classical key).
	Primary *x509.CertificateRequest

	// AltPublicKey is the alternative (PQC) public key.
	AltPublicKey crypto.PublicKey

	// AltPublicKeyBytes is the raw bytes of the alternative public key.
	AltPublicKeyBytes []byte

	// AltAlgorithm is the algorithm for the alternative key.
	AltAlgorithm pkicrypto.AlgorithmID

	// AltSignature is the alternative signature (PQC signature over CSR content).
	AltSignature []byte
}

// HybridCSRRequest holds the parameters for creating a hybrid CSR.
type HybridCSRRequest struct {
	// Subject is the certificate subject.
	Subject pkix.Name

	// DNSNames are the DNS SANs.
	DNSNames []string

	// EmailAddresses are the email SANs.
	EmailAddresses []string

	// ClassicalSigner is the classical signer.
	ClassicalSigner pkicrypto.Signer

	// PQCSigner is the PQC signer.
	PQCSigner pkicrypto.Signer
}

// CreateHybridCSR creates a CSR with dual signatures.
//
// The resulting CSR contains:
//   - Standard SubjectPublicKeyInfo with classical public key
//   - SubjectAltPublicKeyInfo attribute with PQC public key
//   - Standard signature with classical key
//   - AltSignatureValue attribute with PQC signature
//
// This proves possession of both key pairs to the CA.
func CreateHybridCSR(req HybridCSRRequest) (*HybridCSR, error) {
	if req.ClassicalSigner == nil {
		return nil, fmt.Errorf("classical signer is required")
	}
	if req.PQCSigner == nil {
		return nil, fmt.Errorf("PQC signer is required")
	}

	// Get PQC public key bytes
	pqcKP := &pkicrypto.KeyPair{
		Algorithm: req.PQCSigner.Algorithm(),
		PublicKey: req.PQCSigner.Public(),
	}
	pqcPubBytes, err := pqcKP.PublicKeyBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to get PQC public key bytes: %w", err)
	}

	// Build attribute for alternative public key (standard PKCS#10 format)
	altPubKeyInfo := AltSubjectPublicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: req.PQCSigner.Algorithm().OID(),
		},
		SubjectPublicKey: asn1.BitString{
			Bytes:     pqcPubBytes,
			BitLength: len(pqcPubBytes) * 8,
		},
	}

	altPubKeyAttrValue, err := asn1.Marshal(altPubKeyInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal AltSubjectPublicKeyInfo: %w", err)
	}

	// Build attribute for alternative signature algorithm
	altSigAlg := pkix.AlgorithmIdentifier{
		Algorithm: req.PQCSigner.Algorithm().OID(),
	}
	altSigAlgValue, err := asn1.Marshal(altSigAlg)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal AltSignatureAlgorithm: %w", err)
	}

	// Create CSR template for initial CSR (to get TBS for PQC signature)
	template := &x509.CertificateRequest{
		Subject:        req.Subject,
		DNSNames:       req.DNSNames,
		EmailAddresses: req.EmailAddresses,
	}

	// Step 1: Create initial CSR to get the base TBS data
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, req.ClassicalSigner)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSR: %w", err)
	}

	// Parse the CSR to get raw content
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %w", err)
	}

	// Sign the CSR content with PQC key
	// The PQC signature is over the CertificationRequestInfo (before classical signature)
	pqcSig, err := req.PQCSigner.Sign(rand.Reader, csr.RawTBSCertificateRequest, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to sign CSR with PQC: %w", err)
	}

	// Build raw attributes in standard PKCS#10 format
	// Unlike pkix.AttributeTypeAndValueSET, this produces:
	//   SEQUENCE { OID, SET { value } }
	// instead of:
	//   SEQUENCE { OID, SET { SEQUENCE { SEQUENCE { OID, value } } } }
	rawAttrs := []rawAttribute{
		{
			Type:   OIDSubjectAltPublicKeyInfo,
			Values: []asn1.RawValue{{FullBytes: altPubKeyAttrValue}},
		},
		{
			Type:   OIDAltSignatureAlgorithmAttr,
			Values: []asn1.RawValue{{FullBytes: altSigAlgValue}},
		},
		{
			Type:   OIDAltSignatureValueAttr,
			Values: []asn1.RawValue{{FullBytes: mustMarshalBitString(pqcSig)}},
		},
	}

	// Also add extension request attribute if we have SANs
	if len(req.DNSNames) > 0 || len(req.EmailAddresses) > 0 {
		extReqAttr, err := buildExtensionRequestAttr(req.DNSNames, req.EmailAddresses)
		if err != nil {
			return nil, fmt.Errorf("failed to build extension request: %w", err)
		}
		rawAttrs = append(rawAttrs, extReqAttr)
	}

	// Build the final CSR with proper raw attributes
	finalCSRDER, err := buildHybridCSRDER(template.Subject, req.ClassicalSigner, rawAttrs)
	if err != nil {
		return nil, fmt.Errorf("failed to build hybrid CSR: %w", err)
	}

	finalCSR, err := x509.ParseCertificateRequest(finalCSRDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse final CSR: %w", err)
	}

	return &HybridCSR{
		Primary:           finalCSR,
		AltPublicKey:      req.PQCSigner.Public(),
		AltPublicKeyBytes: pqcPubBytes,
		AltAlgorithm:      req.PQCSigner.Algorithm(),
		AltSignature:      pqcSig,
	}, nil
}

// mustMarshalSet wraps a value in an ASN.1 SET using proper DER length encoding.
func mustMarshalSet(data []byte) []byte {
	length := len(data)
	var result []byte

	if length <= 127 {
		// Short form: single byte for length
		result = make([]byte, 2+length)
		result[0] = 0x31 // SET tag
		result[1] = byte(length)
		copy(result[2:], data)
	} else if length <= 255 {
		// Long form: 0x81 + 1 byte length
		result = make([]byte, 3+length)
		result[0] = 0x31
		result[1] = 0x81
		result[2] = byte(length)
		copy(result[3:], data)
	} else if length <= 65535 {
		// Long form: 0x82 + 2 byte length
		result = make([]byte, 4+length)
		result[0] = 0x31
		result[1] = 0x82
		result[2] = byte(length >> 8)
		result[3] = byte(length)
		copy(result[4:], data)
	} else {
		// Long form: 0x83 + 3 byte length (for very large data)
		result = make([]byte, 5+length)
		result[0] = 0x31
		result[1] = 0x83
		result[2] = byte(length >> 16)
		result[3] = byte(length >> 8)
		result[4] = byte(length)
		copy(result[5:], data)
	}
	return result
}

// mustMarshalBitString marshals data as an ASN.1 BIT STRING.
func mustMarshalBitString(data []byte) []byte {
	bs := asn1.BitString{Bytes: data, BitLength: len(data) * 8}
	result, _ := asn1.Marshal(bs)
	return result
}

// buildExtensionRequestAttr builds the extensionRequest attribute for SANs.
func buildExtensionRequestAttr(dnsNames, emails []string) (rawAttribute, error) {
	// OID for extensionRequest (1.2.840.113549.1.9.14)
	oidExtensionRequest := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}
	// OID for subjectAltName (2.5.29.17)
	oidSubjectAltName := asn1.ObjectIdentifier{2, 5, 29, 17}

	// Build GeneralNames for SAN
	var generalNames []asn1.RawValue
	for _, dns := range dnsNames {
		generalNames = append(generalNames, asn1.RawValue{
			Class: asn1.ClassContextSpecific,
			Tag:   2, // dNSName
			Bytes: []byte(dns),
		})
	}
	for _, email := range emails {
		generalNames = append(generalNames, asn1.RawValue{
			Class: asn1.ClassContextSpecific,
			Tag:   1, // rfc822Name
			Bytes: []byte(email),
		})
	}

	sanValue, err := asn1.Marshal(generalNames)
	if err != nil {
		return rawAttribute{}, err
	}

	// Build Extension
	ext := struct {
		OID      asn1.ObjectIdentifier
		Critical bool `asn1:"optional"`
		Value    []byte
	}{
		OID:   oidSubjectAltName,
		Value: sanValue,
	}

	extBytes, err := asn1.Marshal(ext)
	if err != nil {
		return rawAttribute{}, err
	}

	// Build Extensions sequence
	extsBytes, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      extBytes,
	})
	if err != nil {
		return rawAttribute{}, err
	}

	return rawAttribute{
		Type:   oidExtensionRequest,
		Values: []asn1.RawValue{{FullBytes: extsBytes}},
	}, nil
}

// hybridCSRInfo is the TBS portion of a hybrid CSR with raw attributes.
// RawAttributes should contain the complete [0] IMPLICIT SET bytes via FullBytes.
type hybridCSRInfo struct {
	Version       int
	Subject       asn1.RawValue
	PublicKey     asn1.RawValue
	RawAttributes asn1.RawValue
}

// wrapImplicitTag0 wraps content in a context-specific [0] IMPLICIT tag.
// This creates the [0] wrapper for attributes in a CSR.
func wrapImplicitTag0(content []byte) []byte {
	length := len(content)
	var result []byte

	// Tag: 0xA0 = context-specific [0], constructed
	if length <= 127 {
		result = make([]byte, 2+length)
		result[0] = 0xA0
		result[1] = byte(length)
		copy(result[2:], content)
	} else if length <= 255 {
		result = make([]byte, 3+length)
		result[0] = 0xA0
		result[1] = 0x81
		result[2] = byte(length)
		copy(result[3:], content)
	} else if length <= 65535 {
		result = make([]byte, 4+length)
		result[0] = 0xA0
		result[1] = 0x82
		result[2] = byte(length >> 8)
		result[3] = byte(length)
		copy(result[4:], content)
	} else {
		result = make([]byte, 5+length)
		result[0] = 0xA0
		result[1] = 0x83
		result[2] = byte(length >> 16)
		result[3] = byte(length >> 8)
		result[4] = byte(length)
		copy(result[5:], content)
	}
	return result
}

// signatureAlgorithmOID returns the signature algorithm OID for a given key algorithm.
// For ECDSA, this maps the curve to the appropriate ecdsa-with-SHA* OID.
// For PQC algorithms, the key OID is also the signature OID.
func signatureAlgorithmOID(alg pkicrypto.AlgorithmID) asn1.ObjectIdentifier {
	switch alg {
	case pkicrypto.AlgECDSAP256:
		return asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2} // ecdsa-with-SHA256
	case pkicrypto.AlgECDSAP384:
		return asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3} // ecdsa-with-SHA384
	case pkicrypto.AlgECDSAP521:
		return asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4} // ecdsa-with-SHA512
	default:
		// For PQC algorithms (ML-DSA, SLH-DSA), the OID is the same for key and signature
		return alg.OID()
	}
}

// hashForSignature returns the appropriate hash of the message for signing.
// For ECDSA, it returns the SHA-2 hash based on curve.
// For PQC algorithms (ML-DSA, SLH-DSA), it returns the message unchanged (they hash internally).
func hashForSignature(alg pkicrypto.AlgorithmID, message []byte) []byte {
	switch alg {
	case pkicrypto.AlgECDSAP256:
		h := sha256.Sum256(message)
		return h[:]
	case pkicrypto.AlgECDSAP384:
		h := sha512.Sum384(message)
		return h[:]
	case pkicrypto.AlgECDSAP521:
		h := sha512.Sum512(message)
		return h[:]
	default:
		// PQC algorithms hash internally
		return message
	}
}

// buildHybridCSRDER builds a CSR with raw attributes and signs it.
func buildHybridCSRDER(subject pkix.Name, signer pkicrypto.Signer, attrs []rawAttribute) ([]byte, error) {
	// Get public key info
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	// Marshal subject
	subjectBytes, err := asn1.Marshal(subject.ToRDNSequence())
	if err != nil {
		return nil, fmt.Errorf("failed to marshal subject: %w", err)
	}

	// Marshal attributes as SET (not SEQUENCE) per RFC 2986
	// Go's asn1.Marshal produces SEQUENCE for slices, so we manually build a SET
	var attrsContent []byte
	for _, attr := range attrs {
		attrBytes, err := asn1.Marshal(attr)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal attribute: %w", err)
		}
		attrsContent = append(attrsContent, attrBytes...)
	}

	// Wrap attributes in [0] IMPLICIT tag (context-specific, constructed)
	attrsWrapped := wrapImplicitTag0(attrsContent)

	// Build CertificationRequestInfo
	cri := hybridCSRInfo{
		Version:       0,
		Subject:       asn1.RawValue{FullBytes: subjectBytes},
		PublicKey:     asn1.RawValue{FullBytes: pubKeyBytes},
		RawAttributes: asn1.RawValue{FullBytes: attrsWrapped},
	}

	criBytes, err := asn1.Marshal(cri)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal CertificationRequestInfo: %w", err)
	}

	// Sign the TBS (hash it first for classical algorithms like ECDSA)
	tbsHash := hashForSignature(signer.Algorithm(), criBytes)
	sig, err := signer.Sign(rand.Reader, tbsHash, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to sign CSR: %w", err)
	}

	// Get signature algorithm OID (not key algorithm OID)
	sigAlgOID := signatureAlgorithmOID(signer.Algorithm())

	// Build final CSR
	type hybridCSR struct {
		CertificationRequestInfo asn1.RawValue
		SignatureAlgorithm       pkix.AlgorithmIdentifier
		Signature                asn1.BitString
	}

	csr := hybridCSR{
		CertificationRequestInfo: asn1.RawValue{FullBytes: criBytes},
		SignatureAlgorithm:       pkix.AlgorithmIdentifier{Algorithm: sigAlgOID},
		Signature:                asn1.BitString{Bytes: sig, BitLength: len(sig) * 8},
	}

	return asn1.Marshal(csr)
}

// ParseHybridCSR parses a DER-encoded CSR and extracts hybrid attributes.
// Returns nil if the CSR doesn't have hybrid attributes.
func ParseHybridCSR(der []byte) (*HybridCSR, error) {
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %w", err)
	}

	hybrid := &HybridCSR{
		Primary: csr,
	}

	// Look for hybrid attributes in the raw CSR
	// We need to parse the raw attributes since Go's x509 doesn't expose them directly
	type certificationRequestInfo struct {
		Version       int
		Subject       asn1.RawValue
		PublicKey     asn1.RawValue
		RawAttributes asn1.RawValue `asn1:"tag:0"`
	}

	type attribute struct {
		Type   asn1.ObjectIdentifier
		Values asn1.RawValue `asn1:"set"`
	}

	var cri certificationRequestInfo
	if _, err := asn1.Unmarshal(csr.RawTBSCertificateRequest, &cri); err == nil {
		// Parse attributes
		var attrs []attribute
		if _, err := asn1.Unmarshal(cri.RawAttributes.Bytes, &attrs); err == nil {
			for _, attr := range attrs {
				switch {
				case OIDEqual(attr.Type, OIDSubjectAltPublicKeyInfo):
					var info AltSubjectPublicKeyInfo
					// The value is wrapped in a SET, so we need to unwrap it
					var rawValues []asn1.RawValue
					if _, err := asn1.Unmarshal(attr.Values.Bytes, &rawValues); err == nil && len(rawValues) > 0 {
						if _, err := asn1.Unmarshal(rawValues[0].FullBytes, &info); err == nil {
							hybrid.AltPublicKeyBytes = info.SubjectPublicKey.Bytes
							alg, err := oidToAlgorithm(info.Algorithm.Algorithm)
							if err == nil {
								hybrid.AltAlgorithm = alg
								hybrid.AltPublicKey, _ = pkicrypto.ParsePublicKey(alg, info.SubjectPublicKey.Bytes)
							}
						}
					}

				case OIDEqual(attr.Type, OIDAltSignatureValueAttr):
					var rawValues []asn1.RawValue
					if _, err := asn1.Unmarshal(attr.Values.Bytes, &rawValues); err == nil && len(rawValues) > 0 {
						var sig asn1.BitString
						if _, err := asn1.Unmarshal(rawValues[0].FullBytes, &sig); err == nil {
							hybrid.AltSignature = sig.Bytes
						}
					}
				}
			}
		}
	}

	// Check if we found hybrid attributes
	if hybrid.AltPublicKeyBytes == nil && hybrid.AltSignature == nil {
		return nil, nil // Not a hybrid CSR
	}

	return hybrid, nil
}

// Verify verifies both signatures on the hybrid CSR.
// Returns true only if both classical and PQC signatures are valid.
func (h *HybridCSR) Verify() error {
	// Verify classical signature (standard X.509)
	if err := h.Primary.CheckSignature(); err != nil {
		return fmt.Errorf("classical signature verification failed: %w", err)
	}

	// Verify PQC signature
	if h.AltPublicKey == nil || len(h.AltSignature) == 0 {
		return fmt.Errorf("missing PQC public key or signature")
	}

	// The PQC signature is over the TBS (To Be Signed) portion of the CSR
	// Note: This is a simplified verification. The exact TBS format for hybrid CSR
	// verification may need to exclude the AltSignatureValue attribute.
	if !pkicrypto.Verify(h.AltAlgorithm, h.AltPublicKey, h.Primary.RawTBSCertificateRequest, h.AltSignature) {
		return fmt.Errorf("PQC signature verification failed")
	}

	return nil
}

// DER returns the DER-encoded CSR.
func (h *HybridCSR) DER() []byte {
	return h.Primary.Raw
}

// IsHybrid returns true if this is a hybrid CSR with PQC attributes.
func (h *HybridCSR) IsHybrid() bool {
	return h.AltPublicKey != nil && len(h.AltSignature) > 0
}

// CreateHybridCSRFromSigner creates a hybrid CSR using a HybridSigner.
func CreateHybridCSRFromSigner(subject pkix.Name, signer pkicrypto.HybridSigner) (*HybridCSR, error) {
	return CreateHybridCSR(HybridCSRRequest{
		Subject:         subject,
		ClassicalSigner: signer.ClassicalSigner(),
		PQCSigner:       signer.PQCSigner(),
	})
}

// SimpleCSRRequest holds parameters for creating a simple (non-hybrid) CSR.
type SimpleCSRRequest struct {
	Subject        pkix.Name
	DNSNames       []string
	EmailAddresses []string
	Signer         pkicrypto.Signer
}

// CreateSimpleCSR creates a standard CSR with a single signature.
func CreateSimpleCSR(req SimpleCSRRequest) (*x509.CertificateRequest, error) {
	template := &x509.CertificateRequest{
		Subject:        req.Subject,
		DNSNames:       req.DNSNames,
		EmailAddresses: req.EmailAddresses,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, req.Signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSR: %w", err)
	}

	return x509.ParseCertificateRequest(csrDER)
}
