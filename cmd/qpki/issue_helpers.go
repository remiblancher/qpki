package main

import (
	"context"
	gocrypto "crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"net"
	"os"

	"github.com/remiblancher/qpki/pkg/ca"
	"github.com/remiblancher/qpki/pkg/crypto"
	"github.com/remiblancher/qpki/pkg/profile"
	"github.com/remiblancher/qpki/pkg/x509util"
)

// parseIPStrings parses a slice of IP address strings into net.IP values.
func parseIPStrings(ipStrs []string) []net.IP {
	var ips []net.IP
	for _, s := range ipStrs {
		if ip := net.ParseIP(s); ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips
}

// loadCASignerForProfile loads the appropriate signer based on profile requirements.
func loadCASignerForProfile(caInstance *ca.CA, prof *profile.Profile, passphrase string) error {
	if prof.IsCatalyst() {
		if err := caInstance.LoadHybridSigner(passphrase, passphrase); err != nil {
			return fmt.Errorf("failed to load hybrid CA signer: %w", err)
		}
	} else {
		if err := caInstance.LoadSigner(passphrase); err != nil {
			return fmt.Errorf("failed to load CA signer: %w", err)
		}
	}
	return nil
}

// csrParseResult holds the result of parsing a CSR file.
type csrParseResult struct {
	PublicKey interface{}
	Template  *x509.Certificate
}

// parseCSRFromFile reads and parses a CSR file, handling both classical and PQC algorithms.
// It returns the public key and a certificate template with subject information.
func parseCSRFromFile(csrPath string, attestCertPath string) (*csrParseResult, error) {
	csrData, err := os.ReadFile(csrPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CSR file: %w", err)
	}

	block, _ := pem.Decode(csrData)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("invalid CSR file")
	}

	// Try standard Go x509 parsing first (classical algorithms)
	csr, classicalErr := x509.ParseCertificateRequest(block.Bytes)
	if classicalErr == nil {
		return parseClassicalCSR(csr, block.Bytes, attestCertPath)
	}

	// Fallback to PQC CSR parsing (ML-DSA, SLH-DSA, ML-KEM)
	return parsePQCCSRFallback(block.Bytes, classicalErr, attestCertPath)
}

// parseClassicalCSR handles CSRs that Go's x509 package can parse.
// This includes classical algorithms and some PQC algorithms that Go recognizes structurally.
func parseClassicalCSR(csr *x509.CertificateRequest, rawCSR []byte, attestCertPath string) (*csrParseResult, error) {
	if csr.SignatureAlgorithm == x509.UnknownSignatureAlgorithm {
		// Unknown algorithm (likely PQC) - use custom verification
		return parsePQCCSRWithGoTemplate(csr, rawCSR, attestCertPath)
	}

	// Classical algorithm - verify with Go's native verification
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("invalid CSR signature: %w", err)
	}

	return &csrParseResult{
		PublicKey: csr.PublicKey,
		Template: &x509.Certificate{
			Subject:     csr.Subject,
			DNSNames:    csr.DNSNames,
			IPAddresses: csr.IPAddresses,
		},
	}, nil
}

// parsePQCCSRWithGoTemplate handles PQC CSRs when Go can parse the structure but not verify the signature.
func parsePQCCSRWithGoTemplate(csr *x509.CertificateRequest, rawCSR []byte, attestCertPath string) (*csrParseResult, error) {
	pqcInfo, pqcErr := x509util.ParsePQCCSR(rawCSR)
	if pqcErr != nil {
		return nil, fmt.Errorf("failed to parse PQC CSR: %w", pqcErr)
	}

	// Verify PQC CSR signature (handles ML-KEM attestation if needed)
	if err := verifyPQCCSRWithAttestation(pqcInfo, attestCertPath); err != nil {
		return nil, err
	}

	// Use values from Go's parsed CSR (which are correct for subject/SANs)
	result := &csrParseResult{
		PublicKey: csr.PublicKey,
		Template: &x509.Certificate{
			Subject:     csr.Subject,
			DNSNames:    csr.DNSNames,
			IPAddresses: csr.IPAddresses,
		},
	}

	// If Go couldn't parse the public key (PQC), get it from PQC parser
	if result.PublicKey == nil {
		pubKey, err := extractPQCPublicKey(pqcInfo)
		if err != nil {
			return nil, err
		}
		result.PublicKey = pubKey
	}

	return result, nil
}

// parsePQCCSRFallback handles CSRs that Go's x509 package cannot parse at all.
func parsePQCCSRFallback(rawCSR []byte, classicalErr error, attestCertPath string) (*csrParseResult, error) {
	pqcInfo, pqcErr := x509util.ParsePQCCSR(rawCSR)
	if pqcErr != nil {
		return nil, fmt.Errorf("failed to parse CSR (classical: %v, PQC: %v)", classicalErr, pqcErr)
	}

	// Verify PQC CSR signature (handles ML-KEM attestation if needed)
	if err := verifyPQCCSRWithAttestation(pqcInfo, attestCertPath); err != nil {
		return nil, err
	}

	// Reconstruct public key from CSR
	pubKey, err := extractPQCPublicKey(pqcInfo)
	if err != nil {
		return nil, err
	}

	// Build template from PQC CSR info
	return &csrParseResult{
		PublicKey: pubKey,
		Template: &x509.Certificate{
			Subject: pkix.Name{
				CommonName:         pqcInfo.Subject.CommonName,
				Organization:       pqcInfo.Subject.Organization,
				OrganizationalUnit: pqcInfo.Subject.OrganizationalUnit,
				Country:            pqcInfo.Subject.Country,
				Province:           pqcInfo.Subject.Province,
				Locality:           pqcInfo.Subject.Locality,
			},
			DNSNames:    pqcInfo.DNSNames,
			IPAddresses: parseIPStrings(pqcInfo.IPAddresses),
		},
	}, nil
}

// verifyPQCCSRWithAttestation verifies a PQC CSR signature, handling ML-KEM attestation if present.
func verifyPQCCSRWithAttestation(pqcInfo *x509util.PQCCSRInfo, attestCertPath string) error {
	var attestPubKey gocrypto.PublicKey

	if pqcInfo.HasPossessionStatement() {
		// ML-KEM CSR - need attestation cert for verification
		if attestCertPath == "" {
			return fmt.Errorf("ML-KEM CSR with RFC 9883 attestation requires --attest-cert for verification")
		}

		attestCert, err := loadCertificate(attestCertPath)
		if err != nil {
			return fmt.Errorf("failed to load attestation cert: %w", err)
		}

		// Validate RFC 9883 statement
		if err := x509util.ValidateRFC9883Statement(pqcInfo, attestCert); err != nil {
			return fmt.Errorf("RFC 9883 validation failed: %w", err)
		}

		// Extract public key - Go's x509.ParseCertificate returns nil for PQC certs
		attestPubKey, err = extractPQCPublicKeyFromCert(attestCert)
		if err != nil {
			return fmt.Errorf("failed to extract attestation public key: %w", err)
		}
	}

	if err := x509util.VerifyPQCCSRSignature(pqcInfo, attestPubKey); err != nil {
		return fmt.Errorf("invalid PQC CSR signature: %w", err)
	}

	return nil
}

// extractPQCPublicKey extracts and parses the public key from a PQC CSR.
func extractPQCPublicKey(pqcInfo *x509util.PQCCSRInfo) (gocrypto.PublicKey, error) {
	pubKeyAlg := crypto.AlgorithmFromOID(pqcInfo.PublicKeyAlgorithm)
	if pubKeyAlg == crypto.AlgUnknown {
		return nil, fmt.Errorf("unknown public key algorithm OID: %v", pqcInfo.PublicKeyAlgorithm)
	}

	parsedPubKey, err := crypto.ParsePublicKey(pubKeyAlg, pqcInfo.PublicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PQC public key: %w", err)
	}

	return parsedPubKey, nil
}

// mergeCSRVariables merges CSR values into the variable map if not already set.
func mergeCSRVariables(varValues map[string]interface{}, template *x509.Certificate) {
	if _, exists := varValues["cn"]; !exists && template.Subject.CommonName != "" {
		varValues["cn"] = template.Subject.CommonName
	}
	if _, exists := varValues["dns_names"]; !exists && len(template.DNSNames) > 0 {
		varValues["dns_names"] = template.DNSNames
	}
	if _, exists := varValues["ip_addresses"]; !exists && len(template.IPAddresses) > 0 {
		ipStrings := make([]string, len(template.IPAddresses))
		for i, ip := range template.IPAddresses {
			ipStrings[i] = ip.String()
		}
		varValues["ip_addresses"] = ipStrings
	}
}

// issueCatalystCert issues a certificate in Catalyst mode (dual classical + PQC signatures).
func issueCatalystCert(
	ctx context.Context,
	caInstance *ca.CA,
	prof *profile.Profile,
	template *x509.Certificate,
	classicalPubKey interface{},
	resolvedExtensions *profile.ExtensionsConfig,
) (*x509.Certificate, error) {
	// Get PQC algorithm from profile
	pqcAlg := prof.GetAlternativeAlgorithm()

	// Generate PQC key for the subject
	pqcKP, err := crypto.GenerateKeyPair(pqcAlg)
	if err != nil {
		return nil, fmt.Errorf("failed to generate PQC key for Catalyst: %w", err)
	}

	// Build Catalyst request
	catalystReq := ca.CatalystRequest{
		Template:           template,
		ClassicalPublicKey: classicalPubKey,
		PQCPublicKey:       pqcKP.PublicKey,
		PQCAlgorithm:       pqcAlg,
		Extensions:         resolvedExtensions,
		Validity:           prof.Validity,
	}

	cert, err := caInstance.IssueCatalyst(ctx, catalystReq)
	if err != nil {
		return nil, fmt.Errorf("failed to issue Catalyst certificate: %w", err)
	}

	return cert, nil
}

// issueStandardCert issues a certificate in standard or PQC mode.
func issueStandardCert(
	ctx context.Context,
	caInstance *ca.CA,
	prof *profile.Profile,
	template *x509.Certificate,
	subjectPubKey interface{},
	resolvedExtensions *profile.ExtensionsConfig,
	hybridAlgStr string,
) (*x509.Certificate, error) {
	req := ca.IssueRequest{
		Template:      template,
		PublicKey:     subjectPubKey,
		Extensions:    resolvedExtensions,
		SubjectConfig: prof.Subject,
		Validity:      prof.Validity,
	}

	// Add hybrid extension if requested via --hybrid flag
	if hybridAlgStr != "" {
		hybridAlg, err := crypto.ParseAlgorithm(hybridAlgStr)
		if err != nil {
			return nil, fmt.Errorf("invalid hybrid algorithm: %w", err)
		}

		pqcKP, err := crypto.GenerateKeyPair(hybridAlg)
		if err != nil {
			return nil, fmt.Errorf("failed to generate PQC key: %w", err)
		}

		pqcPubBytes, err := pqcKP.PublicKeyBytes()
		if err != nil {
			return nil, fmt.Errorf("failed to get PQC public key: %w", err)
		}

		req.HybridAlgorithm = hybridAlg
		req.HybridPQCKey = pqcPubBytes
		req.HybridPolicy = x509util.HybridPolicyInformational
	}

	cert, err := caInstance.Issue(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to issue certificate: %w", err)
	}

	return cert, nil
}

// writeCertificatePEM writes a certificate to a PEM file.
func writeCertificatePEM(cert *x509.Certificate, path string) error {
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0644); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}
	return nil
}

// spkiForPQC is used to parse SubjectPublicKeyInfo from PQC certificates.
type spkiForPQC struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// loadAndRenderIssueVariables loads variables, merges CSR values, and validates via template engine.
func loadAndRenderIssueVariables(prof *profile.Profile, varFile string, vars []string, csrTemplate *x509.Certificate) (profile.VariableValues, error) {
	varValues, err := profile.LoadVariables(varFile, vars)
	if err != nil {
		return nil, fmt.Errorf("failed to load variables: %w", err)
	}

	mergeCSRVariables(varValues, csrTemplate)

	if len(prof.Variables) > 0 {
		engine, err := profile.NewTemplateEngine(prof)
		if err != nil {
			return nil, fmt.Errorf("failed to create template engine: %w", err)
		}
		rendered, err := engine.Render(varValues)
		if err != nil {
			return nil, fmt.Errorf("variable validation failed: %w", err)
		}
		varValues = rendered.ResolvedValues
	}

	return varValues, nil
}

// issueCertificateByMode issues a certificate based on profile mode (Catalyst or standard).
func issueCertificateByMode(
	ctx context.Context,
	caInstance *ca.CA,
	prof *profile.Profile,
	csrResult *csrParseResult,
	resolvedExtensions *profile.ExtensionsConfig,
	hybridAlg string,
) (*x509.Certificate, error) {
	if prof.IsCatalyst() {
		return issueCatalystCert(ctx, caInstance, prof, csrResult.Template, csrResult.PublicKey, resolvedExtensions)
	}
	return issueStandardCert(ctx, caInstance, prof, csrResult.Template, csrResult.PublicKey, resolvedExtensions, hybridAlg)
}

// extractPQCPublicKeyFromCert extracts the public key from a certificate.
// Go's x509.ParseCertificate returns nil for PublicKey when the algorithm is unknown (PQC).
// This function parses the raw SubjectPublicKeyInfo to extract the PQC public key.
func extractPQCPublicKeyFromCert(cert *x509.Certificate) (gocrypto.PublicKey, error) {
	if cert == nil {
		return nil, fmt.Errorf("certificate is nil")
	}

	// If Go's parser already extracted the public key, use it
	if cert.PublicKey != nil {
		return cert.PublicKey, nil
	}

	// Parse the raw SubjectPublicKeyInfo
	var spki spkiForPQC
	_, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &spki)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SubjectPublicKeyInfo: %w", err)
	}

	// Get the algorithm from the OID
	alg := crypto.AlgorithmFromOID(spki.Algorithm.Algorithm)
	if alg == crypto.AlgUnknown {
		return nil, fmt.Errorf("unknown public key algorithm OID: %v", spki.Algorithm.Algorithm)
	}

	// Parse the public key bytes
	pubKey, err := crypto.ParsePublicKey(alg, spki.PublicKey.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return pubKey, nil
}
