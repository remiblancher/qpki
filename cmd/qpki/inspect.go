package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/remiblancher/post-quantum-pki/pkg/cms"
	"github.com/remiblancher/post-quantum-pki/pkg/tsa"
	"github.com/remiblancher/post-quantum-pki/pkg/x509util"
)

var inspectCmd = &cobra.Command{
	Use:   "inspect [file]",
	Short: "Auto-detect and display file information",
	Long: `Inspect a PKI file and display its contents.

Automatically detects the file type and shows appropriate information:
  - Certificates (.crt, .pem)
  - Certificate Signing Requests (.csr)
  - Private keys (.key)
  - Certificate Revocation Lists (.crl)
  - Timestamp tokens (.tsr)
  - CMS SignedData structures

Examples:
  # Inspect a certificate
  pki inspect server.crt

  # Inspect a CSR
  pki inspect request.csr

  # Inspect a private key
  pki inspect key.pem

  # Inspect a CRL
  pki inspect ca.crl

  # Inspect a timestamp token
  pki inspect token.tsr`,
	Args: cobra.ExactArgs(1),
	RunE: runInspect,
}

func runInspect(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Try PEM first
	block, _ := pem.Decode(data)
	if block != nil {
		switch block.Type {
		case "CERTIFICATE":
			return showCertificate(block.Bytes)
		case "CERTIFICATE REQUEST":
			return showCSR(block.Bytes)
		case "PRIVATE KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY",
			"ML-DSA-44 PRIVATE KEY", "ML-DSA-65 PRIVATE KEY", "ML-DSA-87 PRIVATE KEY":
			return showPrivateKey(block)
		case "X509 CRL":
			return showCRL(block.Bytes)
		default:
			return fmt.Errorf("unknown PEM type: %s", block.Type)
		}
	}

	// Try DER-encoded timestamp token (TimeStampResp or raw SignedData)
	if err := showTimestampToken(data); err == nil {
		return nil
	}

	// Try generic CMS SignedData
	if err := showCMSSignedData(data); err == nil {
		return nil
	}

	return fmt.Errorf("unable to parse file: unknown format")
}

func showCertificate(der []byte) error {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	fmt.Println("Certificate:")
	fmt.Printf("  Version:        %d\n", cert.Version)
	fmt.Printf("  Serial Number:  %s\n", formatSerial(cert.SerialNumber.Bytes()))
	fmt.Printf("  Subject:        %s\n", cert.Subject.String())
	fmt.Printf("  Issuer:         %s\n", cert.Issuer.String())
	fmt.Printf("  Not Before:     %s\n", cert.NotBefore.Format("2006-01-02 15:04:05 UTC"))
	fmt.Printf("  Not After:      %s\n", cert.NotAfter.Format("2006-01-02 15:04:05 UTC"))

	fmt.Printf("  Signature Alg:  %s\n", formatSignatureAlgorithm(cert))
	fmt.Printf("  Public Key Alg: %s\n", formatPublicKeyAlgorithm(cert))

	if cert.IsCA {
		fmt.Printf("  CA:             true (path len: %d)\n", cert.MaxPathLen)
	} else {
		fmt.Printf("  CA:             false\n")
	}

	// Key Usage
	if cert.KeyUsage != 0 {
		fmt.Printf("  Key Usage:      %s\n", formatKeyUsage(cert.KeyUsage))
	}

	// Extended Key Usage
	if len(cert.ExtKeyUsage) > 0 {
		fmt.Printf("  Ext Key Usage:  %s\n", formatExtKeyUsage(cert.ExtKeyUsage))
	}

	// Subject Alternative Names
	if len(cert.DNSNames) > 0 {
		fmt.Printf("  DNS Names:      %s\n", strings.Join(cert.DNSNames, ", "))
	}
	if len(cert.IPAddresses) > 0 {
		ips := make([]string, len(cert.IPAddresses))
		for i, ip := range cert.IPAddresses {
			ips[i] = ip.String()
		}
		fmt.Printf("  IP Addresses:   %s\n", strings.Join(ips, ", "))
	}

	// Subject Key ID
	if len(cert.SubjectKeyId) > 0 {
		fmt.Printf("  Subject Key ID: %s\n", formatHex(cert.SubjectKeyId))
	}

	// Authority Key ID
	if len(cert.AuthorityKeyId) > 0 {
		fmt.Printf("  Auth Key ID:    %s\n", formatHex(cert.AuthorityKeyId))
	}

	// Check for hybrid extension
	hybridInfo, err := x509util.ParseHybridExtension(cert.Extensions)
	if err == nil && hybridInfo != nil {
		fmt.Printf("  Hybrid PQC:\n")
		fmt.Printf("    Algorithm:    %s\n", hybridInfo.Algorithm.Description())
		fmt.Printf("    Policy:       %s\n", hybridInfo.Policy.String())
		fmt.Printf("    Public Key:   %d bytes\n", len(hybridInfo.PublicKey))
	}

	return nil
}

func showCSR(der []byte) error {
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return fmt.Errorf("failed to parse CSR: %w", err)
	}

	fmt.Println("Certificate Signing Request:")
	fmt.Printf("  Subject:        %s\n", csr.Subject.String())
	fmt.Printf("  Signature Alg:  %s\n", formatCSRSignatureAlgorithm(csr))
	fmt.Printf("  Public Key Alg: %s\n", formatCSRPublicKeyAlgorithm(csr))

	if len(csr.DNSNames) > 0 {
		fmt.Printf("  DNS Names:      %s\n", strings.Join(csr.DNSNames, ", "))
	}
	if len(csr.IPAddresses) > 0 {
		ips := make([]string, len(csr.IPAddresses))
		for i, ip := range csr.IPAddresses {
			ips[i] = ip.String()
		}
		fmt.Printf("  IP Addresses:   %s\n", strings.Join(ips, ", "))
	}

	// Verify signature
	if err := csr.CheckSignature(); err != nil {
		fmt.Printf("  Signature:      INVALID (%v)\n", err)
	} else {
		fmt.Printf("  Signature:      valid\n")
	}

	return nil
}

func showPrivateKey(block *pem.Block) error {
	fmt.Println("Private Key:")
	fmt.Printf("  Type:           %s\n", block.Type)

	if x509.IsEncryptedPEMBlock(block) { //nolint:staticcheck
		fmt.Printf("  Encrypted:      yes\n")
	} else {
		fmt.Printf("  Encrypted:      no\n")
	}

	fmt.Printf("  Size:           %d bytes\n", len(block.Bytes))

	return nil
}

func formatSerial(serial []byte) string {
	return hex.EncodeToString(serial)
}

func formatHex(data []byte) string {
	parts := make([]string, len(data))
	for i, b := range data {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

func formatKeyUsage(usage x509.KeyUsage) string {
	var usages []string
	if usage&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "Digital Signature")
	}
	if usage&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "Content Commitment")
	}
	if usage&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "Key Encipherment")
	}
	if usage&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "Data Encipherment")
	}
	if usage&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "Key Agreement")
	}
	if usage&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "Certificate Sign")
	}
	if usage&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRL Sign")
	}
	return strings.Join(usages, ", ")
}

func formatExtKeyUsage(usages []x509.ExtKeyUsage) string {
	var names []string
	for _, u := range usages {
		switch u {
		case x509.ExtKeyUsageServerAuth:
			names = append(names, "Server Auth")
		case x509.ExtKeyUsageClientAuth:
			names = append(names, "Client Auth")
		case x509.ExtKeyUsageCodeSigning:
			names = append(names, "Code Signing")
		case x509.ExtKeyUsageEmailProtection:
			names = append(names, "Email Protection")
		case x509.ExtKeyUsageTimeStamping:
			names = append(names, "Time Stamping")
		case x509.ExtKeyUsageOCSPSigning:
			names = append(names, "OCSP Signing")
		default:
			names = append(names, fmt.Sprintf("OID:%d", u))
		}
	}
	return strings.Join(names, ", ")
}

// formatSignatureAlgorithm returns a human-readable signature algorithm name.
// Falls back to parsing the raw certificate for PQC algorithms not recognized by Go's x509.
func formatSignatureAlgorithm(cert *x509.Certificate) string {
	// Go's x509 returns UnknownSignatureAlgorithm (0) for PQC algorithms
	if cert.SignatureAlgorithm != x509.UnknownSignatureAlgorithm {
		return cert.SignatureAlgorithm.String()
	}
	// Extract the OID from raw certificate bytes
	oid, err := x509util.ExtractSignatureAlgorithmOID(cert.Raw)
	if err != nil {
		return "Unknown"
	}
	return x509util.AlgorithmName(oid)
}

// formatPublicKeyAlgorithm returns a human-readable public key algorithm name.
// Falls back to parsing the raw certificate for PQC algorithms not recognized by Go's x509.
func formatPublicKeyAlgorithm(cert *x509.Certificate) string {
	// Handle ECDSA with curve info
	if ecdsaPub, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
		curveName := ""
		switch ecdsaPub.Curve.Params().BitSize {
		case 256:
			curveName = "P-256"
		case 384:
			curveName = "P-384"
		case 521:
			curveName = "P-521"
		}
		if curveName != "" {
			return fmt.Sprintf("ECDSA %s", curveName)
		}
		return "ECDSA"
	}

	// Handle RSA with key size
	if rsaPub, ok := cert.PublicKey.(*rsa.PublicKey); ok {
		return fmt.Sprintf("RSA %d", rsaPub.N.BitLen())
	}

	// Go's x509 returns UnknownPublicKeyAlgorithm (0) for PQC algorithms
	if cert.PublicKeyAlgorithm != x509.UnknownPublicKeyAlgorithm {
		return cert.PublicKeyAlgorithm.String()
	}
	// Extract the OID from raw certificate bytes
	oid, err := x509util.ExtractPublicKeyAlgorithmOID(cert.Raw)
	if err != nil {
		return "Unknown"
	}
	return x509util.AlgorithmName(oid)
}

// formatCSRSignatureAlgorithm returns a human-readable signature algorithm name for CSR.
func formatCSRSignatureAlgorithm(csr *x509.CertificateRequest) string {
	if csr.SignatureAlgorithm != x509.UnknownSignatureAlgorithm {
		return csr.SignatureAlgorithm.String()
	}
	oid, err := x509util.ExtractCSRSignatureAlgorithmOID(csr.Raw)
	if err != nil {
		return "Unknown"
	}
	return x509util.AlgorithmName(oid)
}

// formatCSRPublicKeyAlgorithm returns a human-readable public key algorithm name for CSR.
func formatCSRPublicKeyAlgorithm(csr *x509.CertificateRequest) string {
	// Handle ECDSA with curve info
	if ecdsaPub, ok := csr.PublicKey.(*ecdsa.PublicKey); ok {
		curveName := ""
		switch ecdsaPub.Curve.Params().BitSize {
		case 256:
			curveName = "P-256"
		case 384:
			curveName = "P-384"
		case 521:
			curveName = "P-521"
		}
		if curveName != "" {
			return fmt.Sprintf("ECDSA %s", curveName)
		}
		return "ECDSA"
	}

	// Handle RSA with key size
	if rsaPub, ok := csr.PublicKey.(*rsa.PublicKey); ok {
		return fmt.Sprintf("RSA %d", rsaPub.N.BitLen())
	}

	// PQC algorithms
	if csr.PublicKeyAlgorithm != x509.UnknownPublicKeyAlgorithm {
		return csr.PublicKeyAlgorithm.String()
	}
	oid, err := x509util.ExtractCSRPublicKeyAlgorithmOID(csr.Raw)
	if err != nil {
		return "Unknown"
	}
	return x509util.AlgorithmName(oid)
}

// formatCRLSignatureAlgorithm returns a human-readable signature algorithm name for CRL.
func formatCRLSignatureAlgorithm(crl *x509.RevocationList) string {
	if crl.SignatureAlgorithm != x509.UnknownSignatureAlgorithm {
		return crl.SignatureAlgorithm.String()
	}
	oid, err := x509util.ExtractCRLSignatureAlgorithmOID(crl.Raw)
	if err != nil {
		return "Unknown"
	}
	return x509util.AlgorithmName(oid)
}

func showCRL(der []byte) error {
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		return fmt.Errorf("failed to parse CRL: %w", err)
	}

	fmt.Println("Certificate Revocation List:")
	fmt.Printf("  Issuer:         %s\n", crl.Issuer.String())
	fmt.Printf("  This Update:    %s\n", crl.ThisUpdate.Format("2006-01-02 15:04:05 UTC"))
	fmt.Printf("  Next Update:    %s\n", crl.NextUpdate.Format("2006-01-02 15:04:05 UTC"))
	fmt.Printf("  Signature Alg:  %s\n", formatCRLSignatureAlgorithm(crl))

	if crl.Number != nil {
		fmt.Printf("  CRL Number:     %s\n", crl.Number.String())
	}

	if len(crl.AuthorityKeyId) > 0 {
		fmt.Printf("  Auth Key ID:    %s\n", formatHex(crl.AuthorityKeyId))
	}

	fmt.Printf("  Revoked Certs:  %d\n", len(crl.RevokedCertificateEntries))

	if len(crl.RevokedCertificateEntries) > 0 {
		fmt.Println("\n  Revoked Certificates:")
		for _, entry := range crl.RevokedCertificateEntries {
			fmt.Printf("    - Serial: %s\n", formatSerial(entry.SerialNumber.Bytes()))
			fmt.Printf("      Revoked: %s\n", entry.RevocationTime.Format("2006-01-02 15:04:05 UTC"))
			if entry.ReasonCode != 0 {
				fmt.Printf("      Reason: %s\n", formatRevocationReason(entry.ReasonCode))
			}
		}
	}

	return nil
}

func formatRevocationReason(reason int) string {
	reasons := map[int]string{
		0:  "Unspecified",
		1:  "Key Compromise",
		2:  "CA Compromise",
		3:  "Affiliation Changed",
		4:  "Superseded",
		5:  "Cessation Of Operation",
		6:  "Certificate Hold",
		8:  "Remove From CRL",
		9:  "Privilege Withdrawn",
		10: "AA Compromise",
	}
	if name, ok := reasons[reason]; ok {
		return name
	}
	return fmt.Sprintf("Unknown (%d)", reason)
}

func showTimestampToken(data []byte) error {
	// Try parsing as TimeStampResp first
	resp, err := tsa.ParseResponse(data)
	if err != nil {
		// Try parsing as raw CMS SignedData token
		token, err := tsa.ParseToken(data)
		if err != nil {
			return fmt.Errorf("not a timestamp token")
		}
		return displayToken(token)
	}

	fmt.Println("Timestamp Response:")
	fmt.Printf("  Status:         %s\n", resp.StatusString())

	if !resp.IsGranted() {
		if failure := resp.FailureString(); failure != "" {
			fmt.Printf("  Failure:        %s\n", failure)
		}
		return nil
	}

	if resp.Token != nil {
		return displayToken(resp.Token)
	}

	return nil
}

func displayToken(token *tsa.Token) error {
	fmt.Println("Timestamp Token:")

	if token.Info == nil {
		fmt.Println("  (no TSTInfo available)")
		return nil
	}

	info := token.Info
	fmt.Printf("  Version:        %d\n", info.Version)
	fmt.Printf("  Serial Number:  %s\n", info.SerialNumber.String())
	fmt.Printf("  Gen Time:       %s\n", info.GenTime.Format(time.RFC3339))
	fmt.Printf("  Policy:         %s\n", info.Policy.String())

	// Message Imprint
	fmt.Println("  Message Imprint:")
	fmt.Printf("    Hash Alg:     %s\n", info.MessageImprint.HashAlgorithm.Algorithm.String())
	fmt.Printf("    Hash:         %s\n", formatHex(info.MessageImprint.HashedMessage))

	// Accuracy
	if !info.Accuracy.IsZero() {
		fmt.Printf("  Accuracy:       %ds %dms %dµs\n",
			info.Accuracy.Seconds, info.Accuracy.Millis, info.Accuracy.Micros)
	}

	// Ordering
	if info.Ordering {
		fmt.Printf("  Ordering:       true\n")
	}

	// Nonce
	if info.Nonce != nil {
		fmt.Printf("  Nonce:          %s\n", info.Nonce.String())
	}

	return nil
}

func showCMSSignedData(data []byte) error {
	// Parse ContentInfo
	var contentInfo cms.ContentInfo
	_, err := asn1.Unmarshal(data, &contentInfo)
	if err != nil {
		return fmt.Errorf("not a CMS structure")
	}

	if !contentInfo.ContentType.Equal(cms.OIDSignedData) {
		return fmt.Errorf("not a SignedData structure")
	}

	// Parse SignedData
	var signedData cms.SignedData
	_, err = asn1.Unmarshal(contentInfo.Content.Bytes, &signedData)
	if err != nil {
		return fmt.Errorf("failed to parse SignedData: %w", err)
	}

	fmt.Println("CMS SignedData:")
	fmt.Printf("  Version:        %d\n", signedData.Version)
	fmt.Printf("  Content Type:   %s\n", signedData.EncapContentInfo.EContentType.String())

	// Check if content is present (attached) or not (detached)
	if signedData.EncapContentInfo.EContent.Bytes != nil {
		fmt.Printf("  Content:        attached (%d bytes)\n", len(signedData.EncapContentInfo.EContent.Bytes))
	} else {
		fmt.Printf("  Content:        detached\n")
	}

	// Digest algorithms
	if len(signedData.DigestAlgorithms) > 0 {
		algNames := make([]string, len(signedData.DigestAlgorithms))
		for i, alg := range signedData.DigestAlgorithms {
			algNames[i] = alg.Algorithm.String()
		}
		fmt.Printf("  Digest Algs:    %s\n", strings.Join(algNames, ", "))
	}

	// Signer info
	fmt.Printf("  Signers:        %d\n", len(signedData.SignerInfos))
	for i, si := range signedData.SignerInfos {
		fmt.Printf("  Signer %d:\n", i+1)
		fmt.Printf("    Digest Alg:   %s\n", si.DigestAlgorithm.Algorithm.String())
		fmt.Printf("    Sig Alg:      %s\n", si.SignatureAlgorithm.Algorithm.String())
		fmt.Printf("    Signature:    %d bytes\n", len(si.Signature))

		// Signing time from attributes
		for _, attr := range si.SignedAttrs {
			if attr.Type.Equal(cms.OIDSigningTime) && len(attr.Values) > 0 {
				var t time.Time
				_, err := asn1.Unmarshal(attr.Values[0].FullBytes, &t)
				if err == nil {
					fmt.Printf("    Signing Time: %s\n", t.Format(time.RFC3339))
				}
			}
		}
	}

	// Certificates
	if len(signedData.Certificates.Raw) > 0 {
		certs, err := cms.ParseCertificates(signedData.Certificates.Raw)
		if err == nil {
			fmt.Printf("  Certificates:   %d\n", len(certs))
			for i, cert := range certs {
				fmt.Printf("    Cert %d:       %s\n", i+1, cert.Subject.CommonName)
			}
		}
	}

	return nil
}
