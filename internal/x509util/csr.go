package x509util

import (
	"crypto"
	"crypto/rand"
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

	// Build attribute for alternative public key
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

	// Create CSR template
	template := &x509.CertificateRequest{
		Subject:        req.Subject,
		DNSNames:       req.DNSNames,
		EmailAddresses: req.EmailAddresses,
	}

	// Step 1: Create initial CSR (without AltSignatureValue) to get TBS data
	// We add AltSubjectPublicKeyInfo and AltSignatureAlgorithm as attributes
	template.ExtraExtensions = []pkix.Extension{
		// Note: For CSRs, we use Attributes, not Extensions.
		// But Go's x509 library doesn't support custom attributes directly,
		// so we'll need to work around this.
	}

	// Create CSR with classical signature
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

	// Now create the final CSR with all attributes
	// We need to add the attributes to the CSR

	// Build the attributes
	attrs := []pkix.AttributeTypeAndValueSET{
		{
			Type: OIDSubjectAltPublicKeyInfo,
			Value: [][]pkix.AttributeTypeAndValue{
				{{Type: OIDSubjectAltPublicKeyInfo, Value: asn1.RawValue{FullBytes: altPubKeyAttrValue}}},
			},
		},
		{
			Type: OIDAltSignatureAlgorithmAttr,
			Value: [][]pkix.AttributeTypeAndValue{
				{{Type: OIDAltSignatureAlgorithmAttr, Value: asn1.RawValue{FullBytes: altSigAlgValue}}},
			},
		},
		{
			Type: OIDAltSignatureValueAttr,
			Value: [][]pkix.AttributeTypeAndValue{
				{{Type: OIDAltSignatureValueAttr, Value: asn1.RawValue{
					Class:      asn1.ClassUniversal,
					Tag:        asn1.TagBitString,
					IsCompound: false,
					Bytes:      append([]byte{0}, pqcSig...), // Bit string encoding
				}}},
			},
		},
	}

	// Create CSR with attributes
	// Note: Attributes is deprecated since Go 1.5 in favor of Extensions/ExtraExtensions,
	// but CSR attributes (PKCS#10) are different from X.509 extensions. There's no modern
	// alternative in the standard library for adding custom PKCS#10 attributes.
	template.Attributes = attrs //nolint:staticcheck // No alternative for PKCS#10 attributes

	finalCSRDER, err := x509.CreateCertificateRequest(rand.Reader, template, req.ClassicalSigner)
	if err != nil {
		return nil, fmt.Errorf("failed to create final CSR with attributes: %w", err)
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
