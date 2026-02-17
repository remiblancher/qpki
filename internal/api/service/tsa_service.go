// Package service provides business logic for the REST API.
package service

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/remiblancher/post-quantum-pki/internal/api/dto"
	"github.com/remiblancher/post-quantum-pki/pkg/credential"
	pkicrypto "github.com/remiblancher/post-quantum-pki/pkg/crypto"
	"github.com/remiblancher/post-quantum-pki/pkg/tsa"
)

// Default TSA policy OID (RFC 3161)
var defaultTSAPolicyOID = asn1.ObjectIdentifier{1, 2, 3, 4, 1}

// TSAService provides TSA operations for the REST API.
type TSAService struct {
	baseDir string
}

// NewTSAService creates a new TSAService.
func NewTSAService(baseDir string) *TSAService {
	return &TSAService{baseDir: baseDir}
}

// Sign creates a timestamp token.
func (s *TSAService) Sign(ctx context.Context, req *dto.TSASignRequest) (*dto.TSASignResponse, error) {
	// Get data to timestamp
	var hash []byte
	var hashAlg crypto.Hash

	if req.Hash != nil {
		// Use pre-computed hash
		var err error
		hash, err = req.Hash.Decode()
		if err != nil {
			return nil, fmt.Errorf("failed to decode hash: %w", err)
		}
		hashAlg = parseHashAlgorithm(req.HashAlgorithm)
		if hashAlg == 0 {
			return nil, fmt.Errorf("unsupported hash algorithm: %s", req.HashAlgorithm)
		}
	} else if req.Data != nil {
		// Hash the data
		data, err := req.Data.Decode()
		if err != nil {
			return nil, fmt.Errorf("failed to decode data: %w", err)
		}
		hashAlg = crypto.SHA256 // Default to SHA-256
		if req.HashAlgorithm != "" {
			hashAlg = parseHashAlgorithm(req.HashAlgorithm)
			if hashAlg == 0 {
				return nil, fmt.Errorf("unsupported hash algorithm: %s", req.HashAlgorithm)
			}
		}
		hash = computeTSAHash(data, hashAlg)
	} else {
		return nil, fmt.Errorf("either data or hash is required")
	}

	// Load TSA credential
	cert, signer, err := s.loadTSASigner(ctx, req.Passphrase)
	if err != nil {
		return nil, fmt.Errorf("failed to load TSA credential: %w", err)
	}

	// Build timestamp request
	tsaReq := &tsa.TimeStampReq{
		Version:        1,
		MessageImprint: tsa.NewMessageImprint(hashAlg, hash),
		CertReq:        req.CertReq,
	}

	// Parse nonce if provided
	if req.Nonce != "" {
		tsaReq.Nonce = new(big.Int)
		tsaReq.Nonce.SetString(req.Nonce, 10)
	}

	// Parse policy OID if provided
	policyOID := defaultTSAPolicyOID
	if req.Policy != "" {
		// Parse policy OID from string
		policyOID = parseOID(req.Policy)
	}

	// Create token
	config := &tsa.TokenConfig{
		Certificate: cert,
		Signer:      signer,
		Policy:      policyOID,
		IncludeTSA:  true,
	}

	serialGen := &tsa.RandomSerialGenerator{}
	token, err := tsa.CreateToken(ctx, tsaReq, config, serialGen)
	if err != nil {
		return nil, fmt.Errorf("failed to create timestamp token: %w", err)
	}

	return &dto.TSASignResponse{
		Token: dto.BinaryData{
			Data:     base64.StdEncoding.EncodeToString(token.SignedData),
			Encoding: "base64",
		},
		Time:   token.GenTime().Format(time.RFC3339),
		Serial: hex.EncodeToString(token.SerialNumber().Bytes()),
		Algorithm: dto.AlgorithmInfo{
			ID: cert.SignatureAlgorithm.String(),
		},
		Policy: policyOID.String(),
	}, nil
}

// Verify verifies a timestamp token.
func (s *TSAService) Verify(ctx context.Context, req *dto.TSAVerifyRequest) (*dto.TSAVerifyResponse, error) {
	// Decode token
	tokenData, err := req.Token.Decode()
	if err != nil {
		return nil, fmt.Errorf("failed to decode token: %w", err)
	}

	// Build verify config
	config := &tsa.VerifyConfig{}

	// Add trust anchors
	if len(req.TrustAnchors) > 0 {
		config.Roots = x509.NewCertPool()
		for _, ta := range req.TrustAnchors {
			taData, err := ta.Decode()
			if err != nil {
				continue
			}
			cert, err := parseCertificateTSA(taData)
			if err != nil {
				continue
			}
			config.Roots.AddCert(cert)
			if len(config.RootCertRaw) == 0 {
				config.RootCertRaw = cert.Raw
			}
		}
	}

	// Add data for hash verification
	if req.Data != nil {
		data, err := req.Data.Decode()
		if err == nil {
			config.Data = data
		}
	} else if req.Hash != nil {
		hash, err := req.Hash.Decode()
		if err == nil {
			config.Hash = hash
		}
	}

	// Verify token
	result, err := tsa.Verify(ctx, tokenData, config)
	if err != nil {
		return &dto.TSAVerifyResponse{
			Valid:  false,
			Errors: []string{err.Error()},
		}, nil
	}

	resp := &dto.TSAVerifyResponse{
		Valid: result.Verified,
	}

	if result.Token != nil && result.Token.Info != nil {
		hashAlg, _ := result.Token.HashAlgorithm()
		resp.Info = &dto.TSAInfo{
			Time:          result.Token.GenTime().Format(time.RFC3339),
			Serial:        hex.EncodeToString(result.Token.SerialNumber().Bytes()),
			Policy:        result.Token.Policy().String(),
			HashAlgorithm: hashAlg.String(),
			Hash:          hex.EncodeToString(result.Token.HashedMessage()),
		}

		if result.Token.Info.Nonce != nil {
			resp.Info.Nonce = result.Token.Info.Nonce.String()
		}

		if result.SignerCert != nil {
			resp.Info.TSACertificate = &dto.CertChainItem{
				Subject:  result.SignerCert.Subject.String(),
				Issuer:   result.SignerCert.Issuer.String(),
				Serial:   hex.EncodeToString(result.SignerCert.SerialNumber.Bytes()),
				NotAfter: result.SignerCert.NotAfter.Format(time.RFC3339),
			}
		}
	}

	if config.Data != nil || config.Hash != nil {
		if !result.HashMatch {
			resp.Errors = append(resp.Errors, "hash mismatch: timestamped hash does not match provided data")
		}
	}

	return resp, nil
}

// Info returns information about a timestamp token.
func (s *TSAService) Info(ctx context.Context, req *dto.TSAInfoRequest) (*dto.TSAInfoResponse, error) {
	// Decode token
	tokenData, err := req.Token.Decode()
	if err != nil {
		return nil, fmt.Errorf("failed to decode token: %w", err)
	}

	// Parse token
	token, err := tsa.ParseToken(tokenData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse timestamp token: %w", err)
	}

	if token.Info == nil {
		return nil, fmt.Errorf("invalid timestamp token: no TSTInfo")
	}

	hashAlg, _ := token.HashAlgorithm()

	resp := &dto.TSAInfoResponse{
		Time:          token.GenTime().Format(time.RFC3339),
		Serial:        hex.EncodeToString(token.SerialNumber().Bytes()),
		Policy:        token.Policy().String(),
		HashAlgorithm: hashAlg.String(),
		Hash:          hex.EncodeToString(token.HashedMessage()),
		Ordering:      token.Info.Ordering,
	}

	if token.Info.Nonce != nil {
		resp.Nonce = token.Info.Nonce.String()
	}

	return resp, nil
}

// loadTSASigner loads the TSA signing credential.
func (s *TSAService) loadTSASigner(ctx context.Context, passphrase string) (*x509.Certificate, crypto.Signer, error) {
	// Look for TSA credential in standard location
	tsaCredPath := filepath.Join(s.baseDir, "credentials", "tsa")
	if _, err := os.Stat(tsaCredPath); err != nil {
		// Try alternative locations
		tsaCredPath = filepath.Join(s.baseDir, "tsa")
		if _, err := os.Stat(tsaCredPath); err != nil {
			return nil, nil, fmt.Errorf("TSA credential not found")
		}
	}

	if !credential.CredentialExists(tsaCredPath) {
		return nil, nil, fmt.Errorf("TSA credential not found at %s", tsaCredPath)
	}

	cred, err := credential.LoadCredential(tsaCredPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load TSA credential: %w", err)
	}

	activeVer := cred.ActiveVersion()
	if activeVer == nil {
		return nil, nil, fmt.Errorf("no active version for TSA credential")
	}

	if len(activeVer.Algos) == 0 {
		return nil, nil, fmt.Errorf("no algorithms in active version")
	}

	algo := activeVer.Algos[0]
	certPath := cred.CertPath(cred.Active, algo)
	keyPath := cred.KeyPath(cred.Active, algo)

	cert, err := loadCertFromFileTSA(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load TSA certificate: %w", err)
	}

	signer, err := pkicrypto.LoadPrivateKey(keyPath, []byte(passphrase))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load TSA signer: %w", err)
	}

	return cert, signer, nil
}

// loadCertFromFileTSA loads a certificate from a PEM file.
func loadCertFromFileTSA(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseCertificateTSA(data)
}

// parseCertificateTSA parses a certificate from PEM or DER format.
func parseCertificateTSA(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block != nil {
		return x509.ParseCertificate(block.Bytes)
	}
	return x509.ParseCertificate(data)
}

// parseHashAlgorithm parses a hash algorithm from a string.
func parseHashAlgorithm(alg string) crypto.Hash {
	switch alg {
	case "SHA-256", "sha256", "SHA256":
		return crypto.SHA256
	case "SHA-384", "sha384", "SHA384":
		return crypto.SHA384
	case "SHA-512", "sha512", "SHA512":
		return crypto.SHA512
	case "SHA3-256", "sha3-256":
		return crypto.SHA3_256
	case "SHA3-384", "sha3-384":
		return crypto.SHA3_384
	case "SHA3-512", "sha3-512":
		return crypto.SHA3_512
	default:
		return 0
	}
}

// computeTSAHash computes a hash of data using the specified algorithm.
func computeTSAHash(data []byte, alg crypto.Hash) []byte {
	switch alg {
	case crypto.SHA256:
		h := sha256.Sum256(data)
		return h[:]
	case crypto.SHA384:
		h := sha512.Sum384(data)
		return h[:]
	case crypto.SHA512:
		h := sha512.Sum512(data)
		return h[:]
	default:
		h := sha256.Sum256(data)
		return h[:]
	}
}

// parseOID parses an OID from a string like "1.2.3.4".
func parseOID(s string) asn1.ObjectIdentifier {
	var oid asn1.ObjectIdentifier
	// Simple parsing - split on dots
	var parts []int
	for _, p := range splitOID(s) {
		var n int
		fmt.Sscanf(p, "%d", &n)
		parts = append(parts, n)
	}
	oid = parts
	return oid
}

// splitOID splits an OID string into parts.
func splitOID(s string) []string {
	var parts []string
	var current string
	for _, c := range s {
		if c == '.' {
			if current != "" {
				parts = append(parts, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}
