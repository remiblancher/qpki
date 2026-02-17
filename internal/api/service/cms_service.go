// Package service provides business logic for the REST API.
package service

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/remiblancher/post-quantum-pki/internal/api/dto"
	"github.com/remiblancher/post-quantum-pki/internal/cms"
	"github.com/remiblancher/post-quantum-pki/internal/credential"
	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
)

// CMSService provides CMS operations for the REST API.
type CMSService struct {
	baseDir string
}

// NewCMSService creates a new CMSService.
func NewCMSService(baseDir string) *CMSService {
	return &CMSService{baseDir: baseDir}
}

// Sign creates a CMS SignedData signature.
func (s *CMSService) Sign(ctx context.Context, req *dto.CMSSignRequest) (*dto.CMSSignResponse, error) {
	// Decode data to sign
	data, err := req.Data.Decode()
	if err != nil {
		return nil, fmt.Errorf("failed to decode data: %w", err)
	}

	// Load signer credential
	cert, signer, err := s.loadSigner(ctx, req.SignerID, req.Passphrase)
	if err != nil {
		return nil, fmt.Errorf("failed to load signer credential: %w", err)
	}

	// Create CMS signature
	config := &cms.SignerConfig{
		Certificate:  cert,
		Signer:       signer,
		IncludeCerts: req.IncludeChain,
		Detached:     req.Detached,
		SigningTime:  time.Now().UTC(),
	}

	signedData, err := cms.Sign(ctx, data, config)
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}

	// Build response
	return &dto.CMSSignResponse{
		Signature: dto.BinaryData{
			Data:     base64.StdEncoding.EncodeToString(signedData),
			Encoding: "base64",
		},
		Algorithm: dto.AlgorithmInfo{
			ID: getAlgorithmName(cert),
		},
		SignerInfo: &dto.CertChainItem{
			Subject:  cert.Subject.String(),
			Issuer:   cert.Issuer.String(),
			Serial:   hex.EncodeToString(cert.SerialNumber.Bytes()),
			NotAfter: cert.NotAfter.Format(time.RFC3339),
		},
	}, nil
}

// Verify verifies a CMS SignedData signature.
func (s *CMSService) Verify(ctx context.Context, req *dto.CMSVerifyRequest) (*dto.CMSVerifyResponse, error) {
	// Decode signature
	sigData, err := req.Signature.Decode()
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}

	// Decode original data (for detached signatures)
	var originalData []byte
	if req.Data != nil {
		originalData, err = req.Data.Decode()
		if err != nil {
			return nil, fmt.Errorf("failed to decode original data: %w", err)
		}
	}

	// Build trust anchors pool
	roots := x509.NewCertPool()
	for _, ta := range req.TrustAnchors {
		taData, err := ta.Decode()
		if err != nil {
			continue
		}
		cert, err := parseCertificateCMS(taData)
		if err != nil {
			continue
		}
		roots.AddCert(cert)
	}

	// Verify signature
	config := &cms.VerifyConfig{
		Data:  originalData,
		Roots: roots,
	}

	result, err := cms.Verify(ctx, sigData, config)
	if err != nil {
		return &dto.CMSVerifyResponse{
			Valid:  false,
			Errors: []string{err.Error()},
		}, nil
	}

	// Build signer info
	var signers []dto.CMSSignerInfo
	if result.SignerCert != nil {
		signers = append(signers, dto.CMSSignerInfo{
			Subject:   result.SignerCert.Subject.String(),
			Issuer:    result.SignerCert.Issuer.String(),
			Serial:    hex.EncodeToString(result.SignerCert.SerialNumber.Bytes()),
			Algorithm: result.SignerCert.SignatureAlgorithm.String(),
			SignedAt:  result.SigningTime.Format(time.RFC3339),
		})
	}

	resp := &dto.CMSVerifyResponse{
		Valid:   true,
		Signers: signers,
	}

	// Include content if extracted
	if len(result.Content) > 0 {
		resp.Content = &dto.BinaryData{
			Data:     base64.StdEncoding.EncodeToString(result.Content),
			Encoding: "base64",
		}
	}

	return resp, nil
}

// Encrypt creates a CMS EnvelopedData structure.
func (s *CMSService) Encrypt(ctx context.Context, req *dto.CMSEncryptRequest) (*dto.CMSEncryptResponse, error) {
	// Decode data to encrypt
	data, err := req.Data.Decode()
	if err != nil {
		return nil, fmt.Errorf("failed to decode data: %w", err)
	}

	// Parse recipient certificates
	var recipients []*x509.Certificate
	for _, rcpt := range req.Recipients {
		rcptData, err := rcpt.Decode()
		if err != nil {
			return nil, fmt.Errorf("failed to decode recipient certificate: %w", err)
		}
		cert, err := parseCertificateCMS(rcptData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse recipient certificate: %w", err)
		}
		recipients = append(recipients, cert)
	}

	if len(recipients) == 0 {
		return nil, fmt.Errorf("at least one recipient is required")
	}

	// Create CMS envelope
	opts := &cms.EncryptOptions{
		Recipients: recipients,
	}
	envelopedData, err := cms.Encrypt(ctx, data, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data: %w", err)
	}

	return &dto.CMSEncryptResponse{
		EncryptedData: dto.BinaryData{
			Data:     base64.StdEncoding.EncodeToString(envelopedData),
			Encoding: "base64",
		},
		Algorithm:      "AES-256-GCM",
		RecipientCount: len(recipients),
	}, nil
}

// Decrypt decrypts a CMS EnvelopedData structure.
func (s *CMSService) Decrypt(ctx context.Context, req *dto.CMSDecryptRequest) (*dto.CMSDecryptResponse, error) {
	// Decode encrypted data
	encData, err := req.EncryptedData.Decode()
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted data: %w", err)
	}

	// Load recipient credential
	cert, privKey, err := s.loadDecryptionKey(ctx, req.RecipientID, req.Passphrase)
	if err != nil {
		return nil, fmt.Errorf("failed to load recipient credential: %w", err)
	}

	// Decrypt
	opts := &cms.DecryptOptions{
		PrivateKey:  privKey,
		Certificate: cert,
	}
	result, err := cms.Decrypt(ctx, encData, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	return &dto.CMSDecryptResponse{
		Data: dto.BinaryData{
			Data:     base64.StdEncoding.EncodeToString(result.Content),
			Encoding: "base64",
		},
		ContentType: result.ContentType.String(),
	}, nil
}

// Info returns information about a CMS structure.
func (s *CMSService) Info(ctx context.Context, req *dto.CMSInfoRequest) (*dto.CMSInfoResponse, error) {
	// Decode data
	data, err := req.Data.Decode()
	if err != nil {
		return nil, fmt.Errorf("failed to decode data: %w", err)
	}

	// Parse ContentInfo
	ci, err := cms.ParseContentInfo(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CMS data: %w", err)
	}

	resp := &dto.CMSInfoResponse{}

	// Determine content type
	switch {
	case ci.ContentType.Equal(cms.OIDSignedData):
		resp.Type = "SignedData"
		sd, err := cms.ParseSignedData(data)
		if err == nil {
			resp.Version = sd.Version
			resp.HasEncapsulatedContent = len(sd.EncapContentInfo.EContent.Bytes) > 0
			resp.ContentType = sd.EncapContentInfo.EContentType.String()

			for _, si := range sd.SignerInfos {
				resp.Signers = append(resp.Signers, dto.CMSSignerInfo{
					Serial:    hex.EncodeToString(si.SID.SerialNumber.Bytes()),
					Algorithm: si.SignatureAlgorithm.Algorithm.String(),
				})
			}
		}

	case ci.ContentType.Equal(cms.OIDEnvelopedData):
		resp.Type = "EnvelopedData"
		ed, err := cms.ParseEnvelopedData(data)
		if err == nil {
			resp.Version = ed.Version
			// Note: RecipientInfos are raw ASN.1 values - would need parsing
		}

	case ci.ContentType.Equal(cms.OIDData):
		resp.Type = "Data"

	default:
		resp.Type = fmt.Sprintf("Unknown (%s)", ci.ContentType.String())
	}

	return resp, nil
}

// loadSigner loads a signing certificate and signer from credentials.
func (s *CMSService) loadSigner(ctx context.Context, credID, passphrase string) (*x509.Certificate, crypto.Signer, error) {
	if credID == "" {
		return nil, nil, fmt.Errorf("credential ID is required")
	}

	// Try to load from credentials directory
	credPath := filepath.Join(s.baseDir, "credentials", credID)
	if _, err := os.Stat(credPath); err != nil {
		// Try as absolute path
		credPath = credID
	}

	// Check if credential exists
	if !credential.CredentialExists(credPath) {
		return nil, nil, fmt.Errorf("credential not found at %s", credPath)
	}

	// Load credential metadata
	cred, err := credential.LoadCredential(credPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load credential: %w", err)
	}

	// Get active version
	activeVer := cred.ActiveVersion()
	if activeVer == nil {
		return nil, nil, fmt.Errorf("no active version for credential %s", credID)
	}

	// Load certificate and key
	if len(activeVer.Algos) == 0 {
		return nil, nil, fmt.Errorf("no algorithms in active version")
	}

	// Try to load certificate and key for the first algorithm
	algo := activeVer.Algos[0]
	certPath := cred.CertPath(cred.Active, algo)
	keyPath := cred.KeyPath(cred.Active, algo)

	cert, err := loadCertFromFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load certificate: %w", err)
	}

	signer, err := pkicrypto.LoadPrivateKey(keyPath, []byte(passphrase))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load signer: %w", err)
	}

	return cert, signer, nil
}

// loadDecryptionKey loads a decryption certificate and private key from credentials.
func (s *CMSService) loadDecryptionKey(ctx context.Context, credID, passphrase string) (*x509.Certificate, crypto.PrivateKey, error) {
	if credID == "" {
		return nil, nil, fmt.Errorf("credential ID is required")
	}

	// Try to load from credentials directory
	credPath := filepath.Join(s.baseDir, "credentials", credID)
	if _, err := os.Stat(credPath); err != nil {
		credPath = credID
	}

	if !credential.CredentialExists(credPath) {
		return nil, nil, fmt.Errorf("credential not found at %s", credPath)
	}

	cred, err := credential.LoadCredential(credPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load credential: %w", err)
	}

	activeVer := cred.ActiveVersion()
	if activeVer == nil {
		return nil, nil, fmt.Errorf("no active version for credential %s", credID)
	}

	if len(activeVer.Algos) == 0 {
		return nil, nil, fmt.Errorf("no algorithms in active version")
	}

	algo := activeVer.Algos[0]
	certPath := cred.CertPath(cred.Active, algo)
	keyPath := cred.KeyPath(cred.Active, algo)

	cert, err := loadCertFromFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load certificate: %w", err)
	}

	signer, err := pkicrypto.LoadPrivateKey(keyPath, []byte(passphrase))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load private key: %w", err)
	}

	return cert, signer.PrivateKey(), nil
}

// loadCertFromFile loads a certificate from a PEM file.
func loadCertFromFile(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseCertificateCMS(data)
}

// parseCertificateCMS parses a certificate from PEM or DER format.
func parseCertificateCMS(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block != nil {
		return x509.ParseCertificate(block.Bytes)
	}
	return x509.ParseCertificate(data)
}
