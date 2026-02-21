package ca

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
	"time"

	"github.com/remiblancher/qpki/pkg/audit"
	pkicrypto "github.com/remiblancher/qpki/pkg/crypto"
	"github.com/remiblancher/qpki/pkg/profile"
	"github.com/remiblancher/qpki/pkg/x509util"
)

// CatalystRequest holds the parameters for issuing a Catalyst certificate.
// Catalyst certificates contain dual signatures (classical + PQC) as per ITU-T X.509 Section 9.8.
type CatalystRequest struct {
	// Template is the base certificate template.
	Template *x509.Certificate

	// ClassicalPublicKey is the subject's classical public key (goes in SubjectPublicKeyInfo).
	ClassicalPublicKey crypto.PublicKey

	// PQCPublicKey is the subject's PQC public key (goes in AltSubjectPublicKeyInfo extension).
	PQCPublicKey crypto.PublicKey

	// PQCAlgorithm is the algorithm for the PQC key.
	PQCAlgorithm pkicrypto.AlgorithmID

	// Extensions is the X.509 extensions configuration from the profile.
	Extensions *profile.ExtensionsConfig

	// Validity is the certificate validity period.
	// If zero, defaults to 1 year.
	Validity time.Duration
}

// IssueCatalyst issues a Catalyst certificate with dual keys and dual signatures.
//
// Catalyst certificates (ITU-T X.509 Section 9.8) contain:
//   - Classical public key in standard SubjectPublicKeyInfo
//   - PQC public key in AltSubjectPublicKeyInfo extension
//   - Classical signature in standard signatureValue
//   - PQC signature in AltSignatureValue extension
//
// The CA must be initialized with a HybridSigner to issue Catalyst certificates.
func (ca *CA) IssueCatalyst(ctx context.Context, req CatalystRequest) (*x509.Certificate, error) {
	_ = ctx // TODO: use for cancellation
	hybridSigner, err := ca.validateCatalystSigner()
	if err != nil {
		return nil, err
	}

	template, err := ca.prepareCatalystTemplate(req)
	if err != nil {
		return nil, err
	}

	if err := ca.addCatalystAltExtensions(template, req, hybridSigner); err != nil {
		return nil, err
	}

	cert, pqcSignerAlg, err := ca.signCatalystCertificate(template, req, hybridSigner)
	if err != nil {
		return nil, err
	}

	return ca.saveCatalystAndAudit(cert, pqcSignerAlg)
}

// validateCatalystSigner validates that the CA can issue Catalyst certificates.
func (ca *CA) validateCatalystSigner() (pkicrypto.HybridSigner, error) {
	if ca.signer == nil {
		return nil, fmt.Errorf("CA signer not loaded - call LoadSigner first")
	}
	hybridSigner, ok := ca.signer.(pkicrypto.HybridSigner)
	if !ok {
		return nil, fmt.Errorf("CA must use a HybridSigner to issue Catalyst certificates")
	}
	return hybridSigner, nil
}

// prepareCatalystTemplate prepares the certificate template for Catalyst issuance.
func (ca *CA) prepareCatalystTemplate(req CatalystRequest) (*x509.Certificate, error) {
	template := req.Template
	if template == nil {
		template = &x509.Certificate{}
	}

	if req.Extensions != nil {
		if err := req.Extensions.Apply(template); err != nil {
			return nil, fmt.Errorf("failed to apply extensions: %w", err)
		}
	}

	template.Issuer = ca.cert.Subject
	template.AuthorityKeyId = ca.cert.SubjectKeyId

	serialBytes, err := ca.store.NextSerial(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get serial number: %w", err)
	}
	template.SerialNumber = new(big.Int).SetBytes(serialBytes)

	if len(template.SubjectKeyId) == 0 {
		skid, err := x509util.SubjectKeyID(req.ClassicalPublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to compute subject key ID: %w", err)
		}
		template.SubjectKeyId = skid
	}

	setCatalystValidity(template, req)
	return template, nil
}

// setCatalystValidity sets the validity period on the template.
func setCatalystValidity(template *x509.Certificate, req CatalystRequest) {
	if template.NotBefore.IsZero() {
		template.NotBefore = time.Now().UTC()
	}
	if template.NotAfter.IsZero() {
		if req.Validity > 0 {
			template.NotAfter = template.NotBefore.Add(req.Validity)
		} else {
			template.NotAfter = template.NotBefore.AddDate(1, 0, 0)
		}
	}
}

// addCatalystAltExtensions adds the alternative public key and signature algorithm extensions.
func (ca *CA) addCatalystAltExtensions(template *x509.Certificate, req CatalystRequest, hybridSigner pkicrypto.HybridSigner) error {
	pqcKP := &pkicrypto.KeyPair{Algorithm: req.PQCAlgorithm, PublicKey: req.PQCPublicKey}
	pqcPubBytes, err := pqcKP.PublicKeyBytes()
	if err != nil {
		return fmt.Errorf("failed to get PQC public key bytes: %w", err)
	}

	altPubKeyExt, err := x509util.EncodeAltSubjectPublicKeyInfo(req.PQCAlgorithm, pqcPubBytes)
	if err != nil {
		return fmt.Errorf("failed to encode AltSubjectPublicKeyInfo: %w", err)
	}
	template.ExtraExtensions = append(template.ExtraExtensions, altPubKeyExt)

	pqcSignerAlg := hybridSigner.PQCSigner().Algorithm()
	altSigAlgExt, err := x509util.EncodeAltSignatureAlgorithm(pqcSignerAlg)
	if err != nil {
		return fmt.Errorf("failed to encode AltSignatureAlgorithm: %w", err)
	}
	template.ExtraExtensions = append(template.ExtraExtensions, altSigAlgExt)

	return nil
}

// signCatalystCertificate creates and signs the Catalyst certificate with dual signatures.
func (ca *CA) signCatalystCertificate(template *x509.Certificate, req CatalystRequest, hybridSigner pkicrypto.HybridSigner) (*x509.Certificate, pkicrypto.AlgorithmID, error) {
	// Step 1: Create pre-TBS certificate (without AltSignatureValue)
	preTBSDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, req.ClassicalPublicKey, hybridSigner.ClassicalSigner())
	if err != nil {
		return nil, "", fmt.Errorf("failed to create pre-TBS certificate: %w", err)
	}

	preTBSCert, err := x509.ParseCertificate(preTBSDER)
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse pre-TBS certificate: %w", err)
	}

	// Step 2: Build PreTBSCertificate and sign with PQC
	preTBS, err := x509util.BuildPreTBSCertificate(preTBSCert.RawTBSCertificate)
	if err != nil {
		return nil, "", fmt.Errorf("failed to build PreTBSCertificate: %w", err)
	}

	pqcSig, err := hybridSigner.PQCSigner().Sign(rand.Reader, preTBS, nil)
	if err != nil {
		return nil, "", fmt.Errorf("failed to sign with PQC: %w", err)
	}

	// Step 3: Add AltSignatureValue extension
	altSigValueExt, err := x509util.EncodeAltSignatureValue(pqcSig)
	if err != nil {
		return nil, "", fmt.Errorf("failed to encode AltSignatureValue: %w", err)
	}
	template.ExtraExtensions = append(template.ExtraExtensions, altSigValueExt)

	// Step 4: Create final certificate (re-sign with classical)
	finalDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, req.ClassicalPublicKey, hybridSigner.ClassicalSigner())
	if err != nil {
		return nil, "", fmt.Errorf("failed to create final Catalyst certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(finalDER)
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse Catalyst certificate: %w", err)
	}

	return cert, hybridSigner.PQCSigner().Algorithm(), nil
}

// saveCatalystAndAudit saves the certificate and logs the audit event.
func (ca *CA) saveCatalystAndAudit(cert *x509.Certificate, pqcSignerAlg pkicrypto.AlgorithmID) (*x509.Certificate, error) {
	if err := ca.store.SaveCert(context.Background(), cert); err != nil {
		return nil, fmt.Errorf("failed to save certificate: %w", err)
	}

	if err := audit.LogCertIssued(
		ca.store.BasePath(),
		fmt.Sprintf("0x%X", cert.SerialNumber.Bytes()),
		cert.Subject.String(),
		"Catalyst",
		fmt.Sprintf("%s + %s", cert.SignatureAlgorithm.String(), pqcSignerAlg),
		true,
	); err != nil {
		return nil, err
	}
	return cert, nil
}

// VerifyCatalystSignatures verifies both signatures on a Catalyst certificate.
// Returns true only if both classical and PQC signatures are valid.
func VerifyCatalystSignatures(cert *x509.Certificate, issuerCert *x509.Certificate) (bool, error) {
	// Parse Catalyst extensions
	catInfo, err := x509util.ParseCatalystExtensions(cert.Extensions)
	if err != nil {
		return false, fmt.Errorf("failed to parse Catalyst extensions: %w", err)
	}
	if catInfo == nil {
		return false, fmt.Errorf("certificate does not have Catalyst extensions")
	}

	// Verify classical signature (standard X.509)
	if err := cert.CheckSignatureFrom(issuerCert); err != nil {
		return false, nil // Classical signature invalid
	}

	// For PQC signature verification, we need to reconstruct what was signed
	// The AltSignatureValue signs a TBS that includes AltSubjectPublicKeyInfo and AltSignatureAlgorithm
	// but not AltSignatureValue itself

	// Get issuer's PQC public key
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

	// Build PreTBSCertificate for PQC verification
	// Per ITU-T X.509 Section 9.8, PreTBSCertificate excludes:
	//   - The signature algorithm field (index 2)
	//   - The AltSignatureValue extension
	tbsWithoutAltSig, err := x509util.BuildPreTBSCertificate(cert.RawTBSCertificate)
	if err != nil {
		return false, fmt.Errorf("failed to reconstruct TBS for PQC verification: %w", err)
	}

	// Verify PQC signature
	pqcValid := pkicrypto.Verify(catInfo.AltSigAlg, issuerPQCPub, tbsWithoutAltSig, catInfo.AltSignature)

	return pqcValid, nil
}
