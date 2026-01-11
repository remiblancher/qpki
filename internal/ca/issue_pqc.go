package ca

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/kem/mlkem/mlkem512"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/sign/slhdsa"
	"github.com/remiblancher/post-quantum-pki/internal/audit"
	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
	"github.com/remiblancher/post-quantum-pki/internal/x509util"
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

// ASN.1 structures for CRL Distribution Points (RFC 5280 Section 4.2.1.13).
// distributionPoint represents a single CRL distribution point.
type distributionPoint struct {
	DistributionPointName distributionPointName `asn1:"optional,tag:0"`
	ReasonFlags           asn1.BitString        `asn1:"optional,tag:1"`
	CRLIssuer             asn1.RawValue         `asn1:"optional,tag:2"`
}

// distributionPointName holds the distribution point name (fullName choice).
type distributionPointName struct {
	FullName []asn1.RawValue `asn1:"optional,tag:0"`
}

// ASN.1 structures for Authority Information Access (RFC 5280 Section 4.2.2.1).
// accessDescription represents a single access method and location.
type accessDescription struct {
	AccessMethod   asn1.ObjectIdentifier
	AccessLocation asn1.RawValue
}

// OIDs for Authority Information Access methods.
var (
	oidAccessMethodOCSP      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
	oidAccessMethodCAIssuers = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 2}
)

// ASN.1 structures for Name Constraints (RFC 5280 Section 4.2.1.10).
// nameConstraints represents the Name Constraints extension.
type nameConstraints struct {
	Permitted []generalSubtree `asn1:"optional,tag:0"`
	Excluded  []generalSubtree `asn1:"optional,tag:1"`
}

// generalSubtree represents a subtree constraint.
type generalSubtree struct {
	Base    asn1.RawValue
	Minimum int `asn1:"optional,tag:0,default:0"`
	Maximum int `asn1:"optional,tag:1"`
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
	case pkicrypto.AlgSLHDSA128s:
		return x509util.OIDSLHDSA128s, nil
	case pkicrypto.AlgSLHDSA128f:
		return x509util.OIDSLHDSA128f, nil
	case pkicrypto.AlgSLHDSA192s:
		return x509util.OIDSLHDSA192s, nil
	case pkicrypto.AlgSLHDSA192f:
		return x509util.OIDSLHDSA192f, nil
	case pkicrypto.AlgSLHDSA256s:
		return x509util.OIDSLHDSA256s, nil
	case pkicrypto.AlgSLHDSA256f:
		return x509util.OIDSLHDSA256f, nil
	default:
		return nil, fmt.Errorf("unsupported PQC algorithm: %s", alg)
	}
}

// slhdsaIDToOID maps SLH-DSA ID to the corresponding OID.
func slhdsaIDToOID(id slhdsa.ID) asn1.ObjectIdentifier {
	switch id {
	case slhdsa.SHA2_128s:
		return x509util.OIDSLHDSA128s
	case slhdsa.SHA2_128f:
		return x509util.OIDSLHDSA128f
	case slhdsa.SHA2_192s:
		return x509util.OIDSLHDSA192s
	case slhdsa.SHA2_192f:
		return x509util.OIDSLHDSA192f
	case slhdsa.SHA2_256s:
		return x509util.OIDSLHDSA256s
	case slhdsa.SHA2_256f:
		return x509util.OIDSLHDSA256f
	default:
		return nil
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

	// For PQC certificates, the public key in the certificate is raw bytes
	// We need to extract it from the SubjectPublicKeyInfo
	pubBytes, err := extractPQCPublicKey(issuer)
	if err != nil {
		return false, fmt.Errorf("failed to extract issuer public key: %w", err)
	}

	// Parse the public key
	issuerPubKey, err := pkicrypto.ParsePublicKey(alg, pubBytes)
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

// IssuePQC issues a certificate using manual DER construction.
//
// This function is called automatically by Issue() when:
// - The CA signer is a PQC algorithm, OR
// - The subject public key is a PQC algorithm
//
// Go's crypto/x509.CreateCertificate doesn't support PQC keys, so we construct the
// certificate DER manually. This works with both classical and PQC CA signers.
func (ca *CA) IssuePQC(ctx context.Context, req IssueRequest) (*x509.Certificate, error) {
	_ = ctx // TODO: use for cancellation
	if ca.signer == nil {
		return nil, fmt.Errorf("CA signer not loaded - call LoadSigner first")
	}

	signerAlg := ca.signer.Algorithm()

	template := req.Template
	if template == nil {
		template = &x509.Certificate{}
	}

	// Apply extensions from profile
	if req.Extensions != nil {
		if err := req.Extensions.Apply(template); err != nil {
			return nil, fmt.Errorf("failed to apply extensions: %w", err)
		}
	}

	// Get signature algorithm OID based on signer type
	var sigAlgOID asn1.ObjectIdentifier
	if signerAlg.IsPQC() {
		var err error
		sigAlgOID, err = algorithmToOID(signerAlg)
		if err != nil {
			return nil, fmt.Errorf("failed to get PQC algorithm OID: %w", err)
		}
	} else {
		// Classical algorithm - get OID from the signer's algorithm
		sigAlgOID = signerAlg.OID()
		if sigAlgOID == nil {
			return nil, fmt.Errorf("unsupported signer algorithm: %s has no OID", signerAlg)
		}
	}

	// Build subject from template
	subjectDER, err := asn1.Marshal(template.Subject.ToRDNSequence())
	if err != nil {
		return nil, fmt.Errorf("failed to marshal subject: %w", err)
	}

	// Build issuer from CA certificate
	issuerDER, err := asn1.Marshal(ca.cert.Subject.ToRDNSequence())
	if err != nil {
		return nil, fmt.Errorf("failed to marshal issuer: %w", err)
	}

	// Generate serial number
	serialBytes, err := ca.store.NextSerial(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get serial number: %w", err)
	}
	serial := new(big.Int).SetBytes(serialBytes)

	// Get subject public key info (full SPKI structure)
	subjectPubKeyInfo, err := encodeSubjectPublicKeyInfo(req.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encode subject public key: %w", err)
	}

	// Get raw public key bytes for SKID calculation
	subjectPubBytes, err := getPublicKeyBytes(req.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key bytes: %w", err)
	}

	// Compute subject key ID
	skidHash := sha256.Sum256(subjectPubBytes)
	skid := skidHash[:20]

	// Set validity (use UTC for X.509 standard compliance)
	notBefore := template.NotBefore
	if notBefore.IsZero() {
		notBefore = time.Now().UTC().Add(-1 * time.Hour) // 1 hour ago for clock skew
	}
	notAfter := template.NotAfter
	if notAfter.IsZero() {
		if req.Validity > 0 {
			notAfter = notBefore.Add(req.Validity)
		} else {
			notAfter = notBefore.AddDate(1, 0, 0) // 1 year default
		}
	}

	// Determine if EKU should be critical (from profile)
	ekuCritical := false
	if req.Extensions != nil && req.Extensions.ExtKeyUsage != nil {
		ekuCritical = req.Extensions.ExtKeyUsage.IsCritical()
	}

	// Build extensions
	extensions, err := buildEndEntityExtensions(template, skid, ca.cert.SubjectKeyId, ekuCritical)
	if err != nil {
		return nil, fmt.Errorf("failed to build extensions: %w", err)
	}

	// Build TBSCertificate
	tbs := tbsCertificate{
		Version:      2, // v3
		SerialNumber: serial,
		SignatureAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: sigAlgOID,
		},
		Issuer: asn1.RawValue{FullBytes: issuerDER},
		Validity: validity{
			NotBefore: notBefore,
			NotAfter:  notAfter,
		},
		Subject:    asn1.RawValue{FullBytes: subjectDER},
		PublicKey:  subjectPubKeyInfo,
		Extensions: extensions,
	}

	// Marshal TBSCertificate
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal TBSCertificate: %w", err)
	}

	// Sign TBSCertificate - handle both classical and PQC signers
	var signature []byte
	signerOpts := pkicrypto.DefaultSignerOpts(signerAlg)
	if signerOpts.Hash != 0 {
		// Classical algorithm - hash the TBS first
		h := signerOpts.Hash.New()
		h.Write(tbsDER)
		digest := h.Sum(nil)
		signature, err = ca.signer.Sign(rand.Reader, digest, signerOpts)
	} else {
		// PQC or Ed25519 - sign the full TBS
		signature, err = ca.signer.Sign(rand.Reader, tbsDER, nil)
	}
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

	// Parse back using Go's x509
	parsedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PQC-signed certificate: %w", err)
	}

	// Save to store
	if err := ca.store.SaveCert(context.Background(), parsedCert); err != nil {
		return nil, fmt.Errorf("failed to save certificate: %w", err)
	}

	// Audit: certificate issued successfully
	if err := audit.LogCertIssued(
		ca.store.BasePath(),
		fmt.Sprintf("0x%X", parsedCert.SerialNumber.Bytes()),
		parsedCert.Subject.String(),
		"PQC",
		signerAlg.String(),
		true,
	); err != nil {
		return nil, err
	}

	return parsedCert, nil
}

// encodeSubjectPublicKeyInfo encodes a public key to SubjectPublicKeyInfo structure.
// Returns the algorithm identifier and the full public key info for embedding in TBSCertificate.
func encodeSubjectPublicKeyInfo(pub interface{}) (publicKeyInfo, error) {
	switch key := pub.(type) {
	case *pkicrypto.MLDSA44PublicKey:
		pubBytes := key.Bytes()
		return publicKeyInfo{
			Algorithm: pkix.AlgorithmIdentifier{Algorithm: x509util.OIDMLDSA44},
			PublicKey: asn1.BitString{Bytes: pubBytes, BitLength: len(pubBytes) * 8},
		}, nil
	case *pkicrypto.MLDSA65PublicKey:
		pubBytes := key.Bytes()
		return publicKeyInfo{
			Algorithm: pkix.AlgorithmIdentifier{Algorithm: x509util.OIDMLDSA65},
			PublicKey: asn1.BitString{Bytes: pubBytes, BitLength: len(pubBytes) * 8},
		}, nil
	case *pkicrypto.MLDSA87PublicKey:
		pubBytes := key.Bytes()
		return publicKeyInfo{
			Algorithm: pkix.AlgorithmIdentifier{Algorithm: x509util.OIDMLDSA87},
			PublicKey: asn1.BitString{Bytes: pubBytes, BitLength: len(pubBytes) * 8},
		}, nil
	case *slhdsa.PublicKey:
		pubBytes, err := key.MarshalBinary()
		if err != nil {
			return publicKeyInfo{}, fmt.Errorf("failed to marshal SLH-DSA public key: %w", err)
		}
		algOID := slhdsaIDToOID(key.ID)
		if algOID == nil {
			return publicKeyInfo{}, fmt.Errorf("unknown SLH-DSA ID: %v", key.ID)
		}
		return publicKeyInfo{
			Algorithm: pkix.AlgorithmIdentifier{Algorithm: algOID},
			PublicKey: asn1.BitString{Bytes: pubBytes, BitLength: len(pubBytes) * 8},
		}, nil
	case *mlkem512.PublicKey:
		pubBytes, err := key.MarshalBinary()
		if err != nil {
			return publicKeyInfo{}, fmt.Errorf("failed to marshal ML-KEM-512 public key: %w", err)
		}
		return publicKeyInfo{
			Algorithm: pkix.AlgorithmIdentifier{Algorithm: x509util.OIDMLKEM512},
			PublicKey: asn1.BitString{Bytes: pubBytes, BitLength: len(pubBytes) * 8},
		}, nil
	case *mlkem768.PublicKey:
		pubBytes, err := key.MarshalBinary()
		if err != nil {
			return publicKeyInfo{}, fmt.Errorf("failed to marshal ML-KEM-768 public key: %w", err)
		}
		return publicKeyInfo{
			Algorithm: pkix.AlgorithmIdentifier{Algorithm: x509util.OIDMLKEM768},
			PublicKey: asn1.BitString{Bytes: pubBytes, BitLength: len(pubBytes) * 8},
		}, nil
	case *mlkem1024.PublicKey:
		pubBytes, err := key.MarshalBinary()
		if err != nil {
			return publicKeyInfo{}, fmt.Errorf("failed to marshal ML-KEM-1024 public key: %w", err)
		}
		return publicKeyInfo{
			Algorithm: pkix.AlgorithmIdentifier{Algorithm: x509util.OIDMLKEM1024},
			PublicKey: asn1.BitString{Bytes: pubBytes, BitLength: len(pubBytes) * 8},
		}, nil
	default:
		// For classical keys, use x509 encoding which includes proper parameters
		pubDER, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return publicKeyInfo{}, fmt.Errorf("unsupported public key type: %T", pub)
		}
		// Parse the SPKI to extract algorithm and key bytes
		var spki publicKeyInfo
		if _, err := asn1.Unmarshal(pubDER, &spki); err != nil {
			return publicKeyInfo{}, fmt.Errorf("failed to parse SPKI: %w", err)
		}
		return spki, nil
	}
}

// getPublicKeyBytes extracts the raw public key bytes for SKID calculation.
func getPublicKeyBytes(pub interface{}) ([]byte, error) {
	switch key := pub.(type) {
	case *pkicrypto.MLDSA44PublicKey:
		return key.Bytes(), nil
	case *pkicrypto.MLDSA65PublicKey:
		return key.Bytes(), nil
	case *pkicrypto.MLDSA87PublicKey:
		return key.Bytes(), nil
	case *slhdsa.PublicKey:
		return key.MarshalBinary()
	case *mlkem512.PublicKey:
		return key.MarshalBinary()
	case *mlkem768.PublicKey:
		return key.MarshalBinary()
	case *mlkem1024.PublicKey:
		return key.MarshalBinary()
	default:
		// For classical keys, use x509 encoding
		pubDER, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return nil, fmt.Errorf("unsupported public key type: %T", pub)
		}
		// Parse the SPKI to extract key bytes
		var spki publicKeyInfo
		if _, err := asn1.Unmarshal(pubDER, &spki); err != nil {
			return nil, fmt.Errorf("failed to parse SPKI: %w", err)
		}
		return spki.PublicKey.Bytes, nil
	}
}

// buildEndEntityExtensions creates extensions for an end-entity certificate.
// ekuCritical controls whether the Extended Key Usage extension is marked critical.
// Per RFC 3161, TSA certificates MUST have EKU marked as critical.
func buildEndEntityExtensions(template *x509.Certificate, subjectKeyId, authorityKeyId []byte, ekuCritical bool) ([]pkix.Extension, error) {
	var exts []pkix.Extension

	// Key Usage (if specified in template)
	if template.KeyUsage != 0 {
		ku := encodeKeyUsage(template.KeyUsage)
		kuDER, err := asn1.Marshal(ku)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal KeyUsage: %w", err)
		}
		exts = append(exts, pkix.Extension{
			Id:       x509util.OIDExtKeyUsage,
			Critical: true,
			Value:    kuDER,
		})
	}

	// Extended Key Usage (if specified in template)
	if len(template.ExtKeyUsage) > 0 {
		ekuDER, err := encodeExtKeyUsage(template.ExtKeyUsage)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal ExtKeyUsage: %w", err)
		}
		exts = append(exts, pkix.Extension{
			Id:       x509util.OIDExtExtKeyUsage,
			Critical: ekuCritical,
			Value:    ekuDER,
		})
	}

	// Basic Constraints (for CA certificates)
	if template.IsCA {
		var bcDER []byte
		var err error

		// Handle MaxPathLen encoding:
		// - MaxPathLen=0 with MaxPathLenZero=true: encode explicit 0
		// - MaxPathLen>0: encode the value
		// - Otherwise: omit path length (unlimited)
		if template.MaxPathLen == 0 && template.MaxPathLenZero {
			// Encode with explicit MaxPathLen: 0
			// We need to manually construct the DER since asn1.Marshal with "optional" omits zero values
			// BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER (0..MAX) OPTIONAL }
			bcDER, err = asn1.Marshal(struct {
				IsCA       bool
				MaxPathLen int
			}{
				IsCA:       true,
				MaxPathLen: 0,
			})
		} else if template.MaxPathLen > 0 {
			bcDER, err = asn1.Marshal(struct {
				IsCA       bool
				MaxPathLen int
			}{
				IsCA:       true,
				MaxPathLen: template.MaxPathLen,
			})
		} else {
			// CA: true without path length (unlimited)
			bcDER, err = asn1.Marshal(struct {
				IsCA bool
			}{
				IsCA: true,
			})
		}
		if err != nil {
			return nil, fmt.Errorf("failed to marshal BasicConstraints: %w", err)
		}
		exts = append(exts, pkix.Extension{
			Id:       x509util.OIDExtBasicConstraints,
			Critical: true,
			Value:    bcDER,
		})
	}

	// Subject Key Identifier
	skidDER, err := asn1.Marshal(subjectKeyId)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal SubjectKeyIdentifier: %w", err)
	}
	exts = append(exts, pkix.Extension{
		Id:       x509util.OIDExtSubjectKeyId,
		Critical: false,
		Value:    skidDER,
	})

	// Authority Key Identifier
	if len(authorityKeyId) > 0 {
		akid := struct {
			KeyIdentifier []byte `asn1:"optional,tag:0"`
		}{
			KeyIdentifier: authorityKeyId,
		}
		akidDER, err := asn1.Marshal(akid)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal AuthorityKeyIdentifier: %w", err)
		}
		exts = append(exts, pkix.Extension{
			Id:       x509util.OIDExtAuthorityKeyId,
			Critical: false,
			Value:    akidDER,
		})
	}

	// Subject Alternative Names (if present in template)
	if len(template.DNSNames) > 0 || len(template.EmailAddresses) > 0 || len(template.IPAddresses) > 0 {
		sanDER, err := encodeSAN(template)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal SubjectAltName: %w", err)
		}
		exts = append(exts, pkix.Extension{
			Id:       x509util.OIDExtSubjectAltName,
			Critical: false,
			Value:    sanDER,
		})
	}

	// CRL Distribution Points (if present in template)
	if len(template.CRLDistributionPoints) > 0 {
		cdpDER, err := encodeCRLDistributionPoints(template.CRLDistributionPoints)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal CRLDistributionPoints: %w", err)
		}
		exts = append(exts, pkix.Extension{
			Id:       x509util.OIDExtCRLDistributionPoints,
			Critical: false,
			Value:    cdpDER,
		})
	}

	// Authority Information Access (OCSP and CA Issuers)
	if len(template.OCSPServer) > 0 || len(template.IssuingCertificateURL) > 0 {
		aiaDER, err := encodeAuthorityInfoAccess(template.OCSPServer, template.IssuingCertificateURL)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal AuthorityInfoAccess: %w", err)
		}
		exts = append(exts, pkix.Extension{
			Id:       x509util.OIDExtAuthorityInfoAccess,
			Critical: false,
			Value:    aiaDER,
		})
	}

	// Name Constraints (for CA certificates only)
	if template.IsCA && hasNameConstraints(template) {
		ncDER, critical, err := encodeNameConstraints(template)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal NameConstraints: %w", err)
		}
		exts = append(exts, pkix.Extension{
			Id:       x509util.OIDExtNameConstraints,
			Critical: critical,
			Value:    ncDER,
		})
	}

	// Extra Extensions (includes CertificatePolicies, OCSPNoCheck, custom extensions)
	// These are already DER-encoded by Extensions.Apply()
	// Filter out extensions that are already explicitly handled above to prevent duplicates.
	// This is necessary because profile.Apply() may add critical EKU to ExtraExtensions
	// for the classical path, but we handle EKU explicitly for PQC certificates.
	handledOIDs := map[string]bool{
		x509util.OIDExtKeyUsage.String():              true, // 2.5.29.15
		x509util.OIDExtExtKeyUsage.String():           true, // 2.5.29.37
		x509util.OIDExtBasicConstraints.String():      true, // 2.5.29.19
		x509util.OIDExtSubjectKeyId.String():          true, // 2.5.29.14
		x509util.OIDExtAuthorityKeyId.String():        true, // 2.5.29.35
		x509util.OIDExtSubjectAltName.String():        true, // 2.5.29.17
		x509util.OIDExtCRLDistributionPoints.String(): true, // 2.5.29.31
		x509util.OIDExtAuthorityInfoAccess.String():   true, // 1.3.6.1.5.5.7.1.1
		x509util.OIDExtNameConstraints.String():       true, // 2.5.29.30
	}
	for _, ext := range template.ExtraExtensions {
		if !handledOIDs[ext.Id.String()] {
			exts = append(exts, ext)
		}
	}

	return exts, nil
}

// encodeKeyUsage encodes KeyUsage to ASN.1 BitString.
func encodeKeyUsage(ku x509.KeyUsage) asn1.BitString {
	var bits byte
	if ku&x509.KeyUsageDigitalSignature != 0 {
		bits |= 0x80 // bit 0
	}
	if ku&x509.KeyUsageContentCommitment != 0 {
		bits |= 0x40 // bit 1
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		bits |= 0x20 // bit 2
	}
	if ku&x509.KeyUsageDataEncipherment != 0 {
		bits |= 0x10 // bit 3
	}
	if ku&x509.KeyUsageKeyAgreement != 0 {
		bits |= 0x08 // bit 4
	}
	if ku&x509.KeyUsageCertSign != 0 {
		bits |= 0x04 // bit 5
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		bits |= 0x02 // bit 6
	}
	if ku&x509.KeyUsageEncipherOnly != 0 {
		bits |= 0x01 // bit 7
	}

	// Calculate bit length (find highest set bit)
	bitLength := 8
	for i := 0; i < 8; i++ {
		if bits&(1<<i) != 0 {
			bitLength = 8 - i
			break
		}
	}

	return asn1.BitString{
		Bytes:     []byte{bits},
		BitLength: bitLength,
	}
}

// encodeExtKeyUsage encodes ExtKeyUsage to ASN.1.
func encodeExtKeyUsage(ekus []x509.ExtKeyUsage) ([]byte, error) {
	var oids []asn1.ObjectIdentifier
	for _, eku := range ekus {
		switch eku {
		case x509.ExtKeyUsageServerAuth:
			oids = append(oids, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1})
		case x509.ExtKeyUsageClientAuth:
			oids = append(oids, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2})
		case x509.ExtKeyUsageCodeSigning:
			oids = append(oids, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3})
		case x509.ExtKeyUsageEmailProtection:
			oids = append(oids, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4})
		case x509.ExtKeyUsageTimeStamping:
			oids = append(oids, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8})
		case x509.ExtKeyUsageOCSPSigning:
			oids = append(oids, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9})
		}
	}
	return asn1.Marshal(oids)
}

// encodeSAN encodes Subject Alternative Names.
func encodeSAN(template *x509.Certificate) ([]byte, error) {
	var rawValues []asn1.RawValue

	for _, name := range template.DNSNames {
		rawValues = append(rawValues, asn1.RawValue{
			Tag:   2, // dNSName
			Class: asn1.ClassContextSpecific,
			Bytes: []byte(name),
		})
	}

	for _, email := range template.EmailAddresses {
		rawValues = append(rawValues, asn1.RawValue{
			Tag:   1, // rfc822Name
			Class: asn1.ClassContextSpecific,
			Bytes: []byte(email),
		})
	}

	for _, ip := range template.IPAddresses {
		rawValues = append(rawValues, asn1.RawValue{
			Tag:   7, // iPAddress
			Class: asn1.ClassContextSpecific,
			Bytes: ip,
		})
	}

	return asn1.Marshal(rawValues)
}

// encodeCRLDistributionPoints encodes CRL Distribution Points extension.
// Each URL is encoded as a DistributionPoint with a fullName containing a uniformResourceIdentifier.
func encodeCRLDistributionPoints(urls []string) ([]byte, error) {
	var dps []distributionPoint

	for _, url := range urls {
		// Encode URL as GeneralName (uniformResourceIdentifier, tag 6)
		urlRaw := asn1.RawValue{
			Tag:   6, // uniformResourceIdentifier
			Class: asn1.ClassContextSpecific,
			Bytes: []byte(url),
		}

		dp := distributionPoint{
			DistributionPointName: distributionPointName{
				FullName: []asn1.RawValue{urlRaw},
			},
		}
		dps = append(dps, dp)
	}

	return asn1.Marshal(dps)
}

// encodeAuthorityInfoAccess encodes Authority Information Access extension.
// This includes OCSP responder URLs and CA Issuers URLs.
func encodeAuthorityInfoAccess(ocspServers, caIssuers []string) ([]byte, error) {
	var accessDescriptions []accessDescription

	// Add OCSP server URLs
	for _, url := range ocspServers {
		urlRaw := asn1.RawValue{
			Tag:   6, // uniformResourceIdentifier
			Class: asn1.ClassContextSpecific,
			Bytes: []byte(url),
		}
		accessDescriptions = append(accessDescriptions, accessDescription{
			AccessMethod:   oidAccessMethodOCSP,
			AccessLocation: urlRaw,
		})
	}

	// Add CA Issuers URLs
	for _, url := range caIssuers {
		urlRaw := asn1.RawValue{
			Tag:   6, // uniformResourceIdentifier
			Class: asn1.ClassContextSpecific,
			Bytes: []byte(url),
		}
		accessDescriptions = append(accessDescriptions, accessDescription{
			AccessMethod:   oidAccessMethodCAIssuers,
			AccessLocation: urlRaw,
		})
	}

	return asn1.Marshal(accessDescriptions)
}

// hasNameConstraints checks if the template has any Name Constraints configured.
func hasNameConstraints(template *x509.Certificate) bool {
	return len(template.PermittedDNSDomains) > 0 ||
		len(template.ExcludedDNSDomains) > 0 ||
		len(template.PermittedEmailAddresses) > 0 ||
		len(template.ExcludedEmailAddresses) > 0 ||
		len(template.PermittedIPRanges) > 0 ||
		len(template.ExcludedIPRanges) > 0 ||
		len(template.PermittedURIDomains) > 0 ||
		len(template.ExcludedURIDomains) > 0
}

// encodeNameConstraints encodes Name Constraints extension.
// Returns the DER encoding, criticality flag, and error.
func encodeNameConstraints(template *x509.Certificate) ([]byte, bool, error) {
	var nc nameConstraints

	// Encode permitted subtrees
	for _, domain := range template.PermittedDNSDomains {
		nc.Permitted = append(nc.Permitted, generalSubtree{
			Base: asn1.RawValue{
				Tag:   2, // dNSName
				Class: asn1.ClassContextSpecific,
				Bytes: []byte(domain),
			},
		})
	}

	for _, email := range template.PermittedEmailAddresses {
		nc.Permitted = append(nc.Permitted, generalSubtree{
			Base: asn1.RawValue{
				Tag:   1, // rfc822Name
				Class: asn1.ClassContextSpecific,
				Bytes: []byte(email),
			},
		})
	}

	for _, ipNet := range template.PermittedIPRanges {
		// IP range is encoded as IP address followed by mask
		ipBytes := append(ipNet.IP, ipNet.Mask...)
		nc.Permitted = append(nc.Permitted, generalSubtree{
			Base: asn1.RawValue{
				Tag:   7, // iPAddress
				Class: asn1.ClassContextSpecific,
				Bytes: ipBytes,
			},
		})
	}

	for _, uri := range template.PermittedURIDomains {
		nc.Permitted = append(nc.Permitted, generalSubtree{
			Base: asn1.RawValue{
				Tag:   6, // uniformResourceIdentifier
				Class: asn1.ClassContextSpecific,
				Bytes: []byte(uri),
			},
		})
	}

	// Encode excluded subtrees
	for _, domain := range template.ExcludedDNSDomains {
		nc.Excluded = append(nc.Excluded, generalSubtree{
			Base: asn1.RawValue{
				Tag:   2, // dNSName
				Class: asn1.ClassContextSpecific,
				Bytes: []byte(domain),
			},
		})
	}

	for _, email := range template.ExcludedEmailAddresses {
		nc.Excluded = append(nc.Excluded, generalSubtree{
			Base: asn1.RawValue{
				Tag:   1, // rfc822Name
				Class: asn1.ClassContextSpecific,
				Bytes: []byte(email),
			},
		})
	}

	for _, ipNet := range template.ExcludedIPRanges {
		ipBytes := append(ipNet.IP, ipNet.Mask...)
		nc.Excluded = append(nc.Excluded, generalSubtree{
			Base: asn1.RawValue{
				Tag:   7, // iPAddress
				Class: asn1.ClassContextSpecific,
				Bytes: ipBytes,
			},
		})
	}

	for _, uri := range template.ExcludedURIDomains {
		nc.Excluded = append(nc.Excluded, generalSubtree{
			Base: asn1.RawValue{
				Tag:   6, // uniformResourceIdentifier
				Class: asn1.ClassContextSpecific,
				Bytes: []byte(uri),
			},
		})
	}

	der, err := asn1.Marshal(nc)
	if err != nil {
		return nil, false, err
	}

	// RFC 5280: Name Constraints MUST be critical
	return der, true, nil
}

// IsPQCSigner returns true if the CA signer is a pure PQC algorithm.
func (ca *CA) IsPQCSigner() bool {
	if ca.signer == nil {
		return false
	}
	return ca.signer.Algorithm().IsPQC()
}

// IsPQCPublicKey returns true if the public key is a PQC key type.
// This is used to determine if manual DER construction is needed for issuing certificates.
func IsPQCPublicKey(pub interface{}) bool {
	switch pub.(type) {
	case *pkicrypto.MLDSA44PublicKey,
		*pkicrypto.MLDSA65PublicKey,
		*pkicrypto.MLDSA87PublicKey,
		*slhdsa.PublicKey,
		*mlkem512.PublicKey,
		*mlkem768.PublicKey,
		*mlkem1024.PublicKey:
		return true
	default:
		return false
	}
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
	case sigAlgOID.Equal(x509util.OIDSLHDSA128s):
		alg = pkicrypto.AlgSLHDSA128s
	case sigAlgOID.Equal(x509util.OIDSLHDSA128f):
		alg = pkicrypto.AlgSLHDSA128f
	case sigAlgOID.Equal(x509util.OIDSLHDSA192s):
		alg = pkicrypto.AlgSLHDSA192s
	case sigAlgOID.Equal(x509util.OIDSLHDSA192f):
		alg = pkicrypto.AlgSLHDSA192f
	case sigAlgOID.Equal(x509util.OIDSLHDSA256s):
		alg = pkicrypto.AlgSLHDSA256s
	case sigAlgOID.Equal(x509util.OIDSLHDSA256f):
		alg = pkicrypto.AlgSLHDSA256f
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
