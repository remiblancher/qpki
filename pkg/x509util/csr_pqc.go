package x509util

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"net"

	pkicrypto "github.com/remiblancher/qpki/pkg/crypto"
)

// OID for RFC 9883 privateKeyPossessionStatement attribute
var OIDPrivateKeyPossessionStatement = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 74}

// PrivateKeyPossessionStatement per RFC 9883.
// This allows a subject to claim possession of a private key by referencing
// an existing signature certificate.
type PrivateKeyPossessionStatement struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
	Cert         []byte `asn1:"optional"`
}

// PKCS#10 CertificationRequestInfo (RFC 2986)
type certificationRequestInfo struct {
	Version       int
	Subject       asn1.RawValue
	PublicKeyInfo publicKeyInfo
	Attributes    rawAttributes `asn1:"tag:0"`
}

type publicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

type rawAttributes struct {
	Raw asn1.RawContent
}

// PKCS#10 CertificationRequest
type certificationRequest struct {
	Raw                      asn1.RawContent
	CertificationRequestInfo certificationRequestInfo
	SignatureAlgorithm       pkix.AlgorithmIdentifier
	Signature                asn1.BitString
}

// Attribute for CSR (PKCS#10)
type csrAttribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

// PQCCSRRequest holds parameters for creating a PQC signature CSR.
type PQCCSRRequest struct {
	Subject        pkix.Name
	DNSNames       []string
	EmailAddresses []string
	IPAddresses    []string
	Signer         pkicrypto.Signer
}

// KEMCSRRequest holds parameters for creating a ML-KEM CSR with RFC 9883 attestation.
type KEMCSRRequest struct {
	Subject        pkix.Name
	DNSNames       []string
	EmailAddresses []string
	IPAddresses    []string
	KEMPublicKey   crypto.PublicKey
	KEMAlgorithm   pkicrypto.AlgorithmID
	AttestCert     *x509.Certificate
	AttestSigner   pkicrypto.Signer
	IncludeCert    bool // Include attestation cert in the statement
}

// CreatePQCSignatureCSR creates a CSR signed with a PQC signature algorithm (ML-DSA, SLH-DSA).
// This bypasses Go's x509 library which doesn't support PQC algorithms.
func CreatePQCSignatureCSR(req PQCCSRRequest) ([]byte, error) {
	if req.Signer == nil {
		return nil, fmt.Errorf("signer is required")
	}

	alg := req.Signer.Algorithm()
	if !alg.IsPQC() || !alg.IsSignature() {
		return nil, fmt.Errorf("algorithm %s is not a PQC signature algorithm", alg)
	}

	// Get signature algorithm OID
	sigAlgOID := alg.OID()
	if sigAlgOID == nil {
		return nil, fmt.Errorf("no OID for algorithm %s", alg)
	}

	// Get public key bytes
	pubKeyBytes, err := pkicrypto.PublicKeyBytes(req.Signer.Public())
	if err != nil {
		return nil, fmt.Errorf("failed to get public key bytes: %w", err)
	}

	// Build subject RDN
	subjectRDN, err := marshalSubject(req.Subject)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal subject: %w", err)
	}

	// Build extension request attribute for SANs
	attrs, err := buildCSRAttributes(req.DNSNames, req.EmailAddresses, req.IPAddresses)
	if err != nil {
		return nil, fmt.Errorf("failed to build attributes: %w", err)
	}

	// Build CertificationRequestInfo
	cri := certificationRequestInfo{
		Version: 0,
		Subject: asn1.RawValue{FullBytes: subjectRDN},
		PublicKeyInfo: publicKeyInfo{
			Algorithm: pkix.AlgorithmIdentifier{Algorithm: sigAlgOID},
			PublicKey: asn1.BitString{
				Bytes:     pubKeyBytes,
				BitLength: len(pubKeyBytes) * 8,
			},
		},
	}

	if len(attrs) > 0 {
		attrsBytes, err := asn1.Marshal(attrs)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal attributes: %w", err)
		}
		cri.Attributes = rawAttributes{Raw: attrsBytes}
	}

	// Marshal TBS (to be signed)
	tbsBytes, err := asn1.Marshal(cri)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal CertificationRequestInfo: %w", err)
	}

	// Sign
	signature, err := req.Signer.Sign(rand.Reader, tbsBytes, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to sign CSR: %w", err)
	}

	// Build complete CSR
	csr := certificationRequest{
		CertificationRequestInfo: cri,
		SignatureAlgorithm:       pkix.AlgorithmIdentifier{Algorithm: sigAlgOID},
		Signature: asn1.BitString{
			Bytes:     signature,
			BitLength: len(signature) * 8,
		},
	}

	return asn1.Marshal(csr)
}

// CreateKEMCSRWithAttestation creates a CSR for ML-KEM with RFC 9883 attestation.
// The CSR is signed by an existing signature certificate to prove possession
// of the KEM private key.
func CreateKEMCSRWithAttestation(req KEMCSRRequest) ([]byte, error) {
	if req.KEMPublicKey == nil {
		return nil, fmt.Errorf("KEM public key is required")
	}
	if req.AttestCert == nil {
		return nil, fmt.Errorf("attestation certificate is required")
	}
	if req.AttestSigner == nil {
		return nil, fmt.Errorf("attestation signer is required")
	}

	// Verify the attestation cert matches the signer
	attestAlg := req.AttestSigner.Algorithm()
	if !attestAlg.IsSignature() {
		return nil, fmt.Errorf("attestation algorithm %s is not a signature algorithm", attestAlg)
	}

	// Get KEM algorithm OID
	kemAlgOID := req.KEMAlgorithm.OID()
	if kemAlgOID == nil {
		return nil, fmt.Errorf("no OID for KEM algorithm %s", req.KEMAlgorithm)
	}

	// Get KEM public key bytes
	kemPubBytes, err := pkicrypto.PublicKeyBytes(req.KEMPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get KEM public key bytes: %w", err)
	}

	// Build subject RDN
	subjectRDN, err := marshalSubject(req.Subject)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal subject: %w", err)
	}

	// Build extension request attribute for SANs
	attrs, err := buildCSRAttributes(req.DNSNames, req.EmailAddresses, req.IPAddresses)
	if err != nil {
		return nil, fmt.Errorf("failed to build SAN attributes: %w", err)
	}

	// Build RFC 9883 PrivateKeyPossessionStatement
	statement := PrivateKeyPossessionStatement{
		Issuer:       asn1.RawValue{FullBytes: req.AttestCert.RawIssuer},
		SerialNumber: req.AttestCert.SerialNumber,
	}
	if req.IncludeCert {
		statement.Cert = req.AttestCert.Raw
	}

	statementBytes, err := asn1.Marshal(statement)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal possession statement: %w", err)
	}

	// Add possession statement attribute
	possessionAttr := csrAttribute{
		Type:   OIDPrivateKeyPossessionStatement,
		Values: []asn1.RawValue{{FullBytes: statementBytes}},
	}
	attrs = append(attrs, possessionAttr)

	// Get signature algorithm OID
	sigAlgOID := attestAlg.OID()
	if sigAlgOID == nil {
		return nil, fmt.Errorf("no OID for signature algorithm %s", attestAlg)
	}

	// Build CertificationRequestInfo
	cri := certificationRequestInfo{
		Version: 0,
		Subject: asn1.RawValue{FullBytes: subjectRDN},
		PublicKeyInfo: publicKeyInfo{
			Algorithm: pkix.AlgorithmIdentifier{Algorithm: kemAlgOID},
			PublicKey: asn1.BitString{
				Bytes:     kemPubBytes,
				BitLength: len(kemPubBytes) * 8,
			},
		},
	}

	if len(attrs) > 0 {
		attrsBytes, err := asn1.Marshal(attrs)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal attributes: %w", err)
		}
		cri.Attributes = rawAttributes{Raw: attrsBytes}
	}

	// Marshal TBS
	tbsBytes, err := asn1.Marshal(cri)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal CertificationRequestInfo: %w", err)
	}

	// Sign with attestation key
	signature, err := req.AttestSigner.Sign(rand.Reader, tbsBytes, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to sign CSR: %w", err)
	}

	// Build complete CSR
	csr := certificationRequest{
		CertificationRequestInfo: cri,
		SignatureAlgorithm:       pkix.AlgorithmIdentifier{Algorithm: sigAlgOID},
		Signature: asn1.BitString{
			Bytes:     signature,
			BitLength: len(signature) * 8,
		},
	}

	return asn1.Marshal(csr)
}

// marshalSubject marshals a pkix.Name to DER-encoded RDNSequence.
func marshalSubject(name pkix.Name) ([]byte, error) {
	return asn1.Marshal(name.ToRDNSequence())
}

// OID for extensionRequest attribute (PKCS#9)
var oidExtensionRequest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}

// OID for subjectAltName extension
var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// buildCSRAttributes builds CSR attributes including SANs.
func buildCSRAttributes(dnsNames, emails, ips []string) ([]csrAttribute, error) {
	var attrs []csrAttribute

	// Build SAN extension if we have any SANs
	if len(dnsNames) > 0 || len(emails) > 0 || len(ips) > 0 {
		sanExt, err := buildSANExtension(dnsNames, emails, ips)
		if err != nil {
			return nil, err
		}

		// Wrap in extensionRequest attribute
		extReqValue, err := asn1.Marshal([]pkix.Extension{sanExt})
		if err != nil {
			return nil, fmt.Errorf("failed to marshal extension request: %w", err)
		}

		attrs = append(attrs, csrAttribute{
			Type:   oidExtensionRequest,
			Values: []asn1.RawValue{{FullBytes: extReqValue}},
		})
	}

	return attrs, nil
}

// GeneralName tags for SAN
const (
	nameTagRFC822 = 1
	nameTagDNS    = 2
	nameTagIP     = 7
)

// buildSANExtension creates a SubjectAltName extension.
func buildSANExtension(dnsNames, emails, ips []string) (pkix.Extension, error) {
	var rawValues []asn1.RawValue

	for _, name := range dnsNames {
		rawValues = append(rawValues, asn1.RawValue{
			Tag:   nameTagDNS,
			Class: asn1.ClassContextSpecific,
			Bytes: []byte(name),
		})
	}

	for _, email := range emails {
		rawValues = append(rawValues, asn1.RawValue{
			Tag:   nameTagRFC822,
			Class: asn1.ClassContextSpecific,
			Bytes: []byte(email),
		})
	}

	for _, ip := range ips {
		// Parse and encode IP
		ipBytes := parseIPForSAN(ip)
		if ipBytes != nil {
			rawValues = append(rawValues, asn1.RawValue{
				Tag:   nameTagIP,
				Class: asn1.ClassContextSpecific,
				Bytes: ipBytes,
			})
		}
	}

	sanBytes, err := asn1.Marshal(rawValues)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("failed to marshal SAN: %w", err)
	}

	return pkix.Extension{
		Id:       oidSubjectAltName,
		Critical: false,
		Value:    sanBytes,
	}, nil
}

// parseIPForSAN parses an IP string and returns bytes suitable for SAN.
// Supports both IPv4 (4 bytes) and IPv6 (16 bytes).
func parseIPForSAN(ipStr string) []byte {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil
	}
	// Return 4 bytes for IPv4, 16 bytes for IPv6
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip
}

// ParsePQCCSR parses a PQC CSR and extracts key information.
// Returns the parsed CSR info suitable for certificate issuance.
func ParsePQCCSR(der []byte) (*PQCCSRInfo, error) {
	var csr certificationRequest
	rest, err := asn1.Unmarshal(der, &csr)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal CSR: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data after CSR")
	}

	// Extract subject
	var rdnSeq pkix.RDNSequence
	if _, err := asn1.Unmarshal(csr.CertificationRequestInfo.Subject.FullBytes, &rdnSeq); err != nil {
		return nil, fmt.Errorf("failed to unmarshal subject: %w", err)
	}

	var subject pkix.Name
	subject.FillFromRDNSequence(&rdnSeq)

	// Detect algorithm from signature or public key
	sigAlgOID := csr.SignatureAlgorithm.Algorithm
	pubKeyAlgOID := csr.CertificationRequestInfo.PublicKeyInfo.Algorithm.Algorithm

	info := &PQCCSRInfo{
		Subject:            subject,
		SignatureAlgorithm: sigAlgOID,
		PublicKeyAlgorithm: pubKeyAlgOID,
		PublicKeyBytes:     csr.CertificationRequestInfo.PublicKeyInfo.PublicKey.Bytes,
		SignatureBytes:     csr.Signature.Bytes,
		RawTBS:             nil, // Will be populated below
	}

	// Re-marshal TBS for signature verification
	tbsBytes, err := asn1.Marshal(csr.CertificationRequestInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to re-marshal TBS: %w", err)
	}
	info.RawTBS = tbsBytes

	// Parse attributes for SANs and RFC 9883 statement
	if err := parseCSRAttributes(&csr, info); err != nil {
		return nil, err
	}

	return info, nil
}

// PQCCSRInfo contains parsed information from a PQC CSR.
type PQCCSRInfo struct {
	Subject             pkix.Name
	SignatureAlgorithm  asn1.ObjectIdentifier
	PublicKeyAlgorithm  asn1.ObjectIdentifier
	PublicKeyBytes      []byte
	SignatureBytes      []byte
	RawTBS              []byte
	DNSNames            []string
	EmailAddresses      []string
	IPAddresses         []string
	PossessionStatement *PrivateKeyPossessionStatement
}

// HasPossessionStatement returns true if this CSR contains an RFC 9883 statement.
func (info *PQCCSRInfo) HasPossessionStatement() bool {
	return info.PossessionStatement != nil
}

// parseCSRAttributes extracts SANs and possession statement from CSR attributes.
func parseCSRAttributes(csr *certificationRequest, info *PQCCSRInfo) error {
	rawAttrs := csr.CertificationRequestInfo.Attributes.Raw
	if len(rawAttrs) == 0 {
		return nil
	}

	// The attributes are stored as SET OF Attribute, wrapped in CONTEXT-SPECIFIC [0].
	// Raw bytes typically start with 0xa0 (context-specific [0] constructed).
	// We need to unwrap this tag first.

	var attrs []csrAttribute

	// Check if first byte is context-specific [0] (0xa0)
	if len(rawAttrs) > 0 && rawAttrs[0] == 0xa0 {
		// Parse as RawValue to extract inner bytes
		var wrapper asn1.RawValue
		if _, err := asn1.Unmarshal(rawAttrs, &wrapper); err == nil {
			// Now parse the inner bytes as individual attributes
			// The Bytes field contains the content without the tag/length
			rest := wrapper.Bytes
			for len(rest) > 0 {
				var attr csrAttribute
				var err error
				rest, err = asn1.Unmarshal(rest, &attr)
				if err != nil {
					break
				}
				attrs = append(attrs, attr)
			}
		}
	} else {
		// Try direct parsing as []csrAttribute
		if _, err := asn1.Unmarshal(rawAttrs, &attrs); err == nil {
			// Successfully parsed
		} else {
			// Try parsing individually
			rest := rawAttrs
			for len(rest) > 0 {
				var attr csrAttribute
				var err error
				rest, err = asn1.Unmarshal(rest, &attr)
				if err != nil {
					break
				}
				attrs = append(attrs, attr)
			}
		}
	}

	if len(attrs) > 0 {
		parseExtractedAttributes(attrs, info)
	}

	return nil
}

// parseExtractedAttributes processes a slice of CSR attributes.
func parseExtractedAttributes(attrs []csrAttribute, info *PQCCSRInfo) {
	for _, attr := range attrs {
		switch {
		case attr.Type.Equal(oidExtensionRequest):
			// Parse extension request
			if len(attr.Values) > 0 {
				var exts []pkix.Extension
				if _, err := asn1.Unmarshal(attr.Values[0].FullBytes, &exts); err == nil {
					for _, ext := range exts {
						if ext.Id.Equal(oidSubjectAltName) {
							parseSANExtension(ext.Value, info)
						}
					}
				}
			}

		case attr.Type.Equal(OIDPrivateKeyPossessionStatement):
			// Parse RFC 9883 possession statement
			if len(attr.Values) > 0 {
				var stmt PrivateKeyPossessionStatement
				if _, err := asn1.Unmarshal(attr.Values[0].FullBytes, &stmt); err == nil {
					info.PossessionStatement = &stmt
				}
			}
		}
	}
}

// parseSANExtension extracts SANs from extension value.
func parseSANExtension(value []byte, info *PQCCSRInfo) {
	var rawValues []asn1.RawValue
	if _, err := asn1.Unmarshal(value, &rawValues); err != nil {
		return
	}

	for _, rv := range rawValues {
		switch rv.Tag {
		case nameTagDNS:
			info.DNSNames = append(info.DNSNames, string(rv.Bytes))
		case nameTagRFC822:
			info.EmailAddresses = append(info.EmailAddresses, string(rv.Bytes))
		case nameTagIP:
			if len(rv.Bytes) == 4 {
				info.IPAddresses = append(info.IPAddresses, fmt.Sprintf("%d.%d.%d.%d",
					rv.Bytes[0], rv.Bytes[1], rv.Bytes[2], rv.Bytes[3]))
			}
		}
	}
}

// =============================================================================
// RFC 9883 Validation (CA-side)
// =============================================================================

// ValidateRFC9883Statement validates an RFC 9883 PrivateKeyPossessionStatement
// in a CSR against a provided attestation certificate.
//
// Per RFC 9883 Section 6 (Security Considerations):
// - The CA MUST verify the attestation certificate chain
// - The CA SHOULD check that the attestation certificate is not revoked
// - The CSR subject and attestation certificate subject should match
//
// This function validates:
// 1. The possession statement exists in the CSR
// 2. The serial number matches the attestation certificate
// 3. The issuer matches the attestation certificate
func ValidateRFC9883Statement(csrInfo *PQCCSRInfo, attestCert *x509.Certificate) error {
	if csrInfo == nil {
		return fmt.Errorf("CSR info is nil")
	}

	if !csrInfo.HasPossessionStatement() {
		return fmt.Errorf("CSR does not contain RFC 9883 possession statement")
	}

	stmt := csrInfo.PossessionStatement

	// Validate serial number matches
	if attestCert != nil {
		if stmt.SerialNumber.Cmp(attestCert.SerialNumber) != 0 {
			return fmt.Errorf("possession statement serial number mismatch: "+
				"statement has %s, certificate has %s",
				stmt.SerialNumber.String(), attestCert.SerialNumber.String())
		}

		// Validate issuer matches (compare raw DER)
		if len(stmt.Issuer.FullBytes) > 0 && len(attestCert.RawIssuer) > 0 {
			if !bytesEqual(stmt.Issuer.FullBytes, attestCert.RawIssuer) {
				return fmt.Errorf("possession statement issuer mismatch")
			}
		}
	}

	return nil
}

// bytesEqual compares two byte slices for equality.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// VerifyPQCCSRSignature verifies the signature on a PQC CSR.
// For ML-DSA/SLH-DSA CSRs, it verifies the signature using the public key in the CSR.
// For ML-KEM CSRs with RFC 9883 attestation, it verifies using the attestation public key.
func VerifyPQCCSRSignature(csrInfo *PQCCSRInfo, attestPubKey crypto.PublicKey) error {
	if csrInfo == nil {
		return fmt.Errorf("CSR info is nil")
	}

	if len(csrInfo.RawTBS) == 0 {
		return fmt.Errorf("CSR TBS data is missing")
	}

	if len(csrInfo.SignatureBytes) == 0 {
		return fmt.Errorf("CSR signature is missing")
	}

	// Determine which public key to use for verification
	var pubKeyToVerify crypto.PublicKey

	if csrInfo.HasPossessionStatement() {
		// This is a KEM CSR - use the attestation public key
		if attestPubKey == nil {
			return fmt.Errorf("attestation public key required for KEM CSR verification")
		}
		pubKeyToVerify = attestPubKey
	} else {
		// This is a signature CSR - the public key in the CSR is the signing key
		// We need to reconstruct the public key from the bytes
		alg := pkicrypto.AlgorithmFromOID(csrInfo.PublicKeyAlgorithm)
		if alg == pkicrypto.AlgUnknown {
			return fmt.Errorf("unknown signature algorithm OID: %v", csrInfo.SignatureAlgorithm)
		}

		var err error
		pubKeyToVerify, err = pkicrypto.ParsePublicKey(alg, csrInfo.PublicKeyBytes)
		if err != nil {
			return fmt.Errorf("failed to parse public key: %w", err)
		}
	}

	// Determine signature algorithm
	sigAlg := pkicrypto.AlgorithmFromOID(csrInfo.SignatureAlgorithm)
	if sigAlg == pkicrypto.AlgUnknown {
		return fmt.Errorf("unknown signature algorithm OID: %v", csrInfo.SignatureAlgorithm)
	}

	// Verify signature
	if err := pkicrypto.VerifySignature(pubKeyToVerify, sigAlg, csrInfo.RawTBS, csrInfo.SignatureBytes); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}
