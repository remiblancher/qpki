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
	"github.com/remiblancher/post-quantum-pki/internal/cose"
	"github.com/remiblancher/post-quantum-pki/internal/credential"
	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
)

// COSEService provides COSE operations for the REST API.
type COSEService struct {
	baseDir string
}

// NewCOSEService creates a new COSEService.
func NewCOSEService(baseDir string) *COSEService {
	return &COSEService{baseDir: baseDir}
}

// Sign creates a COSE Sign1 or Sign message.
func (s *COSEService) Sign(ctx context.Context, req *dto.COSESignRequest) (*dto.COSESignResponse, error) {
	// Decode payload
	payload, err := req.Payload.Decode()
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	// Load signer credential
	cert, signer, err := s.loadCOSESigner(ctx, req.SignerID, req.Passphrase)
	if err != nil {
		return nil, fmt.Errorf("failed to load signer credential: %w", err)
	}

	// Create message config
	config := &cose.MessageConfig{
		Certificate:      cert,
		Signer:           signer,
		IncludeCertChain: true,
	}

	var signedData []byte
	var msgType string

	if req.MultiSign {
		// Create COSE Sign (multiple signatures)
		signedData, err = cose.IssueSign(ctx, payload, config)
		msgType = "COSE_Sign"
	} else {
		// Create COSE Sign1 (single signature)
		signedData, err = cose.IssueSign1(ctx, payload, config)
		msgType = "COSE_Sign1"
	}

	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}

	return &dto.COSESignResponse{
		Signature: dto.BinaryData{
			Data:     base64.StdEncoding.EncodeToString(signedData),
			Encoding: "base64",
		},
		Algorithm: dto.AlgorithmInfo{
			ID: getAlgorithmNameFromCert(cert),
		},
		Type: msgType,
	}, nil
}

// Verify verifies a COSE Sign1 or Sign message.
func (s *COSEService) Verify(ctx context.Context, req *dto.COSEVerifyRequest) (*dto.COSEVerifyResponse, error) {
	// Decode signature
	sigData, err := req.Signature.Decode()
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}

	// Build trust anchors pool
	roots := x509.NewCertPool()
	var rootCerts []*x509.Certificate
	for _, ta := range req.TrustAnchors {
		taData, err := ta.Decode()
		if err != nil {
			continue
		}
		cert, err := parseCertificateCOSE(taData)
		if err != nil {
			continue
		}
		roots.AddCert(cert)
		rootCerts = append(rootCerts, cert)
	}

	// Parse message to determine type
	msg, err := cose.Parse(sigData)
	if err != nil {
		return &dto.COSEVerifyResponse{
			Valid:  false,
			Errors: []string{fmt.Sprintf("failed to parse COSE message: %v", err)},
		}, nil
	}

	// Build verify config
	config := &cose.VerifyConfig{
		Roots:     roots,
		RootCerts: rootCerts,
	}

	var result *cose.VerifyResult

	switch msg.Type {
	case cose.TypeSign1:
		result, err = cose.VerifySign1(sigData, config)
	case cose.TypeSign:
		result, err = cose.VerifySign(sigData, config)
	case cose.TypeCWT:
		config.CheckExpiration = true
		result, err = cose.VerifyCWT(sigData, config)
	default:
		return &dto.COSEVerifyResponse{
			Valid:  false,
			Errors: []string{fmt.Sprintf("unsupported COSE message type: %v", msg.Type)},
		}, nil
	}

	if err != nil {
		return &dto.COSEVerifyResponse{
			Valid:  false,
			Errors: []string{err.Error()},
		}, nil
	}

	resp := &dto.COSEVerifyResponse{
		Valid:     result.Valid,
		Errors:    result.Warnings,
		Protected: make(map[string]interface{}),
	}

	// Include payload if available
	if len(msg.Payload) > 0 {
		resp.Payload = &dto.BinaryData{
			Data:     base64.StdEncoding.EncodeToString(msg.Payload),
			Encoding: "base64",
		}
	}

	// Build signer info from first signature
	if len(msg.Signatures) > 0 {
		sig := msg.Signatures[0]
		resp.SignerInfo = &dto.COSESignerInfo{
			Algorithm:     int(sig.Algorithm),
			AlgorithmName: cose.AlgorithmName(sig.Algorithm),
		}
		if len(sig.KeyID) > 0 {
			resp.SignerInfo.KeyID = hex.EncodeToString(sig.KeyID)
		}
	}

	return resp, nil
}

// Info returns information about a COSE structure.
func (s *COSEService) Info(ctx context.Context, req *dto.COSEInfoRequest) (*dto.COSEInfoResponse, error) {
	// Decode data
	data, err := req.Data.Decode()
	if err != nil {
		return nil, fmt.Errorf("failed to decode data: %w", err)
	}

	// Get info
	info, err := cose.GetInfo(data)
	if err != nil {
		return nil, fmt.Errorf("failed to get COSE info: %w", err)
	}

	resp := &dto.COSEInfoResponse{
		Type:        info.Type,
		HasPayload:  info.PayloadSize > 0,
		PayloadSize: info.PayloadSize,
		Protected:   make(map[string]interface{}),
		Unprotected: make(map[string]interface{}),
	}

	if info.ContentType != "" {
		resp.Protected["content_type"] = info.ContentType
	}

	// Add signer info
	for _, sig := range info.Signatures {
		signerInfo := dto.COSESignerInfo{
			Algorithm:     int(sig.AlgorithmID),
			AlgorithmName: sig.Algorithm,
			KeyID:         sig.KeyID,
		}
		resp.Signers = append(resp.Signers, signerInfo)
	}

	return resp, nil
}

// CWTIssue creates a CWT (CBOR Web Token).
func (s *COSEService) CWTIssue(ctx context.Context, req *dto.CWTIssueRequest) (*dto.CWTIssueResponse, error) {
	// Load signer credential
	cert, signer, err := s.loadCOSESigner(ctx, req.SignerID, req.Passphrase)
	if err != nil {
		return nil, fmt.Errorf("failed to load signer credential: %w", err)
	}

	// Build claims
	claims := cose.NewClaims()
	claims.Issuer = req.Claims.Issuer
	claims.Subject = req.Claims.Subject
	claims.Audience = req.Claims.Audience

	if req.Claims.ExpirationTime > 0 {
		claims.Expiration = time.Unix(req.Claims.ExpirationTime, 0)
	}
	if req.Claims.NotBefore > 0 {
		claims.NotBefore = time.Unix(req.Claims.NotBefore, 0)
	}
	if req.Claims.IssuedAt > 0 {
		claims.IssuedAt = time.Unix(req.Claims.IssuedAt, 0)
	}
	if req.Claims.CWTID != "" {
		claims.CWTID = []byte(req.Claims.CWTID)
	}

	// Add custom claims (the DTO uses string keys, convert to int64)
	if req.Claims.Custom != nil {
		for k, v := range req.Claims.Custom {
			// Parse string key as int64
			var key int64
			if _, err := fmt.Sscanf(k, "%d", &key); err == nil {
				claims.Custom[key] = v
			}
		}
	}

	// Create CWT config
	config := &cose.CWTConfig{
		MessageConfig: cose.MessageConfig{
			Certificate:      cert,
			Signer:           signer,
			IncludeCertChain: true,
		},
		Claims:       claims,
		AutoIssuedAt: true,
		AutoCWTID:    true,
	}

	// Issue CWT
	token, err := cose.IssueCWT(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to issue CWT: %w", err)
	}

	return &dto.CWTIssueResponse{
		Token: dto.BinaryData{
			Data:     base64.StdEncoding.EncodeToString(token),
			Encoding: "base64",
		},
		Algorithm: dto.AlgorithmInfo{
			ID: getAlgorithmNameFromCert(cert),
		},
	}, nil
}

// CWTVerify verifies a CWT.
func (s *COSEService) CWTVerify(ctx context.Context, req *dto.CWTVerifyRequest) (*dto.CWTVerifyResponse, error) {
	// Decode token
	tokenData, err := req.Token.Decode()
	if err != nil {
		return nil, fmt.Errorf("failed to decode token: %w", err)
	}

	// Build trust anchors pool
	roots := x509.NewCertPool()
	var rootCerts []*x509.Certificate
	for _, ta := range req.TrustAnchors {
		taData, err := ta.Decode()
		if err != nil {
			continue
		}
		cert, err := parseCertificateCOSE(taData)
		if err != nil {
			continue
		}
		roots.AddCert(cert)
		rootCerts = append(rootCerts, cert)
	}

	// Verify CWT
	config := &cose.VerifyConfig{
		Roots:           roots,
		RootCerts:       rootCerts,
		CheckExpiration: true,
	}

	result, err := cose.VerifyCWT(tokenData, config)
	if err != nil {
		return &dto.CWTVerifyResponse{
			Valid:  false,
			Errors: []string{err.Error()},
		}, nil
	}

	resp := &dto.CWTVerifyResponse{
		Valid:  result.Valid,
		Errors: result.Warnings,
	}

	// Include claims if available
	if result.Claims != nil {
		resp.Claims = &dto.CWTClaims{
			Issuer:   result.Claims.Issuer,
			Subject:  result.Claims.Subject,
			Audience: result.Claims.Audience,
		}
		if !result.Claims.Expiration.IsZero() {
			resp.Claims.ExpirationTime = result.Claims.Expiration.Unix()
		}
		if !result.Claims.NotBefore.IsZero() {
			resp.Claims.NotBefore = result.Claims.NotBefore.Unix()
		}
		if !result.Claims.IssuedAt.IsZero() {
			resp.Claims.IssuedAt = result.Claims.IssuedAt.Unix()
		}
		if len(result.Claims.CWTID) > 0 {
			resp.Claims.CWTID = string(result.Claims.CWTID)
		}
	}

	// Build signer info
	if len(result.Certificates) > 0 {
		cert := result.Certificates[0]
		resp.SignerInfo = &dto.COSESignerInfo{
			AlgorithmName: cert.SignatureAlgorithm.String(),
		}
	}
	if len(result.Algorithms) > 0 {
		if resp.SignerInfo == nil {
			resp.SignerInfo = &dto.COSESignerInfo{}
		}
		resp.SignerInfo.Algorithm = int(result.Algorithms[0])
		resp.SignerInfo.AlgorithmName = cose.AlgorithmName(result.Algorithms[0])
	}

	return resp, nil
}

// loadCOSESigner loads a signing certificate and signer from credentials.
func (s *COSEService) loadCOSESigner(ctx context.Context, credID, passphrase string) (*x509.Certificate, crypto.Signer, error) {
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

	cert, err := loadCertFromFileCOSE(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load certificate: %w", err)
	}

	signer, err := pkicrypto.LoadPrivateKey(keyPath, []byte(passphrase))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load signer: %w", err)
	}

	return cert, signer, nil
}

// loadCertFromFileCOSE loads a certificate from a PEM file.
func loadCertFromFileCOSE(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseCertificateCOSE(data)
}

// parseCertificateCOSE parses a certificate from PEM or DER format.
func parseCertificateCOSE(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block != nil {
		return x509.ParseCertificate(block.Bytes)
	}
	return x509.ParseCertificate(data)
}

// getAlgorithmNameFromCert returns the algorithm name from a certificate.
func getAlgorithmNameFromCert(cert *x509.Certificate) string {
	if cert == nil {
		return "unknown"
	}
	return cert.SignatureAlgorithm.String()
}
