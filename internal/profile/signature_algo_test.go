package profile

import (
	"crypto"
	"crypto/x509"
	"testing"

	pkicrypto "github.com/remiblancher/pki/internal/crypto"
)

func TestHashAlgorithm_IsValid(t *testing.T) {
	tests := []struct {
		hash  HashAlgorithm
		valid bool
	}{
		{HashSHA256, true},
		{HashSHA384, true},
		{HashSHA512, true},
		{HashSHA3_256, true},
		{HashSHA3_384, true},
		{HashSHA3_512, true},
		{"invalid", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(string(tt.hash), func(t *testing.T) {
			if got := tt.hash.IsValid(); got != tt.valid {
				t.Errorf("HashAlgorithm.IsValid() = %v, want %v", got, tt.valid)
			}
		})
	}
}

func TestHashAlgorithm_CryptoHash(t *testing.T) {
	tests := []struct {
		hash     HashAlgorithm
		expected crypto.Hash
	}{
		{HashSHA256, crypto.SHA256},
		{HashSHA384, crypto.SHA384},
		{HashSHA512, crypto.SHA512},
		{HashSHA3_256, crypto.SHA3_256},
		{HashSHA3_384, crypto.SHA3_384},
		{HashSHA3_512, crypto.SHA3_512},
	}

	for _, tt := range tests {
		t.Run(string(tt.hash), func(t *testing.T) {
			if got := tt.hash.CryptoHash(); got != tt.expected {
				t.Errorf("HashAlgorithm.CryptoHash() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestHashAlgorithm_SizeBytes(t *testing.T) {
	tests := []struct {
		hash     HashAlgorithm
		expected int
	}{
		{HashSHA256, 32},
		{HashSHA384, 48},
		{HashSHA512, 64},
		{HashSHA3_256, 32},
		{HashSHA3_384, 48},
		{HashSHA3_512, 64},
	}

	for _, tt := range tests {
		t.Run(string(tt.hash), func(t *testing.T) {
			if got := tt.hash.SizeBytes(); got != tt.expected {
				t.Errorf("HashAlgorithm.SizeBytes() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestSignatureScheme_IsValid(t *testing.T) {
	tests := []struct {
		scheme SignatureScheme
		valid  bool
	}{
		{SchemeECDSA, true},
		{SchemePKCS1v15, true},
		{SchemeRSASSAPSS, true},
		{SchemeEd25519, true},
		{SchemeEd25519ph, true},
		{SchemeEd448, true},
		{SchemeEd448ph, true},
		{"invalid", false},
	}

	for _, tt := range tests {
		t.Run(string(tt.scheme), func(t *testing.T) {
			if got := tt.scheme.IsValid(); got != tt.valid {
				t.Errorf("SignatureScheme.IsValid() = %v, want %v", got, tt.valid)
			}
		})
	}
}

func TestSignatureScheme_RequiresHash(t *testing.T) {
	tests := []struct {
		scheme   SignatureScheme
		requires bool
	}{
		{SchemeECDSA, true},
		{SchemePKCS1v15, true},
		{SchemeRSASSAPSS, true},
		{SchemeEd25519, false},
		{SchemeEd25519ph, true},
		{SchemeEd448, false},
		{SchemeEd448ph, true},
	}

	for _, tt := range tests {
		t.Run(string(tt.scheme), func(t *testing.T) {
			if got := tt.scheme.RequiresHash(); got != tt.requires {
				t.Errorf("SignatureScheme.RequiresHash() = %v, want %v", got, tt.requires)
			}
		})
	}
}

func TestSignatureAlgoConfig_Resolve_ECDSA(t *testing.T) {
	tests := []struct {
		name           string
		key            pkicrypto.AlgorithmID
		expectedScheme SignatureScheme
		expectedHash   HashAlgorithm
	}{
		{"P-256", pkicrypto.AlgECP256, SchemeECDSA, HashSHA256},
		{"P-384", pkicrypto.AlgECP384, SchemeECDSA, HashSHA384},
		{"P-521", pkicrypto.AlgECP521, SchemeECDSA, HashSHA512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &SignatureAlgoConfig{Key: tt.key}
			resolved, warnings := cfg.Resolve()

			if resolved.Scheme != tt.expectedScheme {
				t.Errorf("Scheme = %v, want %v", resolved.Scheme, tt.expectedScheme)
			}
			if resolved.Hash != tt.expectedHash {
				t.Errorf("Hash = %v, want %v", resolved.Hash, tt.expectedHash)
			}
			if len(warnings) > 0 {
				t.Errorf("Unexpected warnings: %v", warnings)
			}
		})
	}
}

func TestSignatureAlgoConfig_Resolve_RSA(t *testing.T) {
	cfg := &SignatureAlgoConfig{Key: pkicrypto.AlgRSA4096}
	resolved, warnings := cfg.Resolve()

	if resolved.Scheme != SchemeRSASSAPSS {
		t.Errorf("Scheme = %v, want %v", resolved.Scheme, SchemeRSASSAPSS)
	}
	if resolved.Hash != HashSHA256 {
		t.Errorf("Hash = %v, want %v", resolved.Hash, HashSHA256)
	}
	if resolved.PSS == nil {
		t.Error("PSS params should be set for RSA-PSS")
	}
	if resolved.PSS.SaltLength != -1 {
		t.Errorf("SaltLength = %v, want -1", resolved.PSS.SaltLength)
	}
	if len(warnings) > 0 {
		t.Errorf("Unexpected warnings: %v", warnings)
	}
}

func TestSignatureAlgoConfig_Resolve_RSA_PKCS1v15(t *testing.T) {
	cfg := &SignatureAlgoConfig{
		Key:    pkicrypto.AlgRSA4096,
		Scheme: SchemePKCS1v15,
	}
	resolved, warnings := cfg.Resolve()

	if resolved.Scheme != SchemePKCS1v15 {
		t.Errorf("Scheme = %v, want %v", resolved.Scheme, SchemePKCS1v15)
	}
	if resolved.Hash != HashSHA256 {
		t.Errorf("Hash = %v, want %v", resolved.Hash, HashSHA256)
	}
	// PKCS1v15 should trigger a warning
	hasLegacyWarning := false
	for _, w := range warnings {
		if w == "pkcs1v15 is legacy; consider rsassa-pss for new deployments" {
			hasLegacyWarning = true
		}
	}
	if !hasLegacyWarning {
		t.Error("Expected legacy warning for pkcs1v15")
	}
}

func TestSignatureAlgoConfig_Resolve_Ed25519(t *testing.T) {
	cfg := &SignatureAlgoConfig{Key: pkicrypto.AlgEd25519}
	resolved, warnings := cfg.Resolve()

	if resolved.Scheme != SchemeEd25519 {
		t.Errorf("Scheme = %v, want %v", resolved.Scheme, SchemeEd25519)
	}
	if resolved.Hash != "" {
		t.Errorf("Hash = %v, want empty (Ed25519 is pure)", resolved.Hash)
	}
	if len(warnings) > 0 {
		t.Errorf("Unexpected warnings: %v", warnings)
	}
}

func TestSignatureAlgoConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     SignatureAlgoConfig
		wantErr bool
	}{
		{
			name:    "valid ECDSA",
			cfg:     SignatureAlgoConfig{Key: pkicrypto.AlgECP384, Scheme: SchemeECDSA, Hash: HashSHA384},
			wantErr: false,
		},
		{
			name:    "valid RSA-PSS",
			cfg:     SignatureAlgoConfig{Key: pkicrypto.AlgRSA4096, Scheme: SchemeRSASSAPSS, Hash: HashSHA256},
			wantErr: false,
		},
		{
			name:    "missing key",
			cfg:     SignatureAlgoConfig{Scheme: SchemeECDSA},
			wantErr: true,
		},
		{
			name:    "invalid key",
			cfg:     SignatureAlgoConfig{Key: "invalid-key"},
			wantErr: true,
		},
		{
			name:    "invalid scheme",
			cfg:     SignatureAlgoConfig{Key: pkicrypto.AlgECP384, Scheme: "invalid-scheme"},
			wantErr: true,
		},
		{
			name:    "invalid hash",
			cfg:     SignatureAlgoConfig{Key: pkicrypto.AlgECP384, Hash: "invalid-hash"},
			wantErr: true,
		},
		{
			name:    "ECDSA with RSA key",
			cfg:     SignatureAlgoConfig{Key: pkicrypto.AlgRSA4096, Scheme: SchemeECDSA},
			wantErr: true,
		},
		{
			name:    "RSA-PSS with EC key",
			cfg:     SignatureAlgoConfig{Key: pkicrypto.AlgECP384, Scheme: SchemeRSASSAPSS},
			wantErr: true,
		},
		{
			name:    "PSS params with PKCS1v15",
			cfg:     SignatureAlgoConfig{Key: pkicrypto.AlgRSA4096, Scheme: SchemePKCS1v15, PSS: &PSSParams{SaltLength: 32}},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSignatureAlgoConfig_X509SignatureAlgorithm(t *testing.T) {
	tests := []struct {
		name     string
		cfg      SignatureAlgoConfig
		expected x509.SignatureAlgorithm
	}{
		{
			name:     "ECDSA P-256 SHA-256",
			cfg:      SignatureAlgoConfig{Key: pkicrypto.AlgECP256, Scheme: SchemeECDSA, Hash: HashSHA256},
			expected: x509.ECDSAWithSHA256,
		},
		{
			name:     "ECDSA P-384 SHA-384",
			cfg:      SignatureAlgoConfig{Key: pkicrypto.AlgECP384, Scheme: SchemeECDSA, Hash: HashSHA384},
			expected: x509.ECDSAWithSHA384,
		},
		{
			name:     "RSA PKCS#1 v1.5 SHA-256",
			cfg:      SignatureAlgoConfig{Key: pkicrypto.AlgRSA4096, Scheme: SchemePKCS1v15, Hash: HashSHA256},
			expected: x509.SHA256WithRSA,
		},
		{
			name:     "RSA-PSS SHA-256",
			cfg:      SignatureAlgoConfig{Key: pkicrypto.AlgRSA4096, Scheme: SchemeRSASSAPSS, Hash: HashSHA256},
			expected: x509.SHA256WithRSAPSS,
		},
		{
			name:     "Ed25519",
			cfg:      SignatureAlgoConfig{Key: pkicrypto.AlgEd25519, Scheme: SchemeEd25519},
			expected: x509.PureEd25519,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.X509SignatureAlgorithm(); got != tt.expected {
				t.Errorf("X509SignatureAlgorithm() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestSignatureAlgoConfig_NonStandardWarnings(t *testing.T) {
	// P-384 with SHA-256 (non-standard combination)
	cfg := &SignatureAlgoConfig{
		Key:    pkicrypto.AlgECP384,
		Scheme: SchemeECDSA,
		Hash:   HashSHA256, // Non-standard: should be SHA-384
	}
	_, warnings := cfg.Resolve()

	hasWarning := false
	for _, w := range warnings {
		if w == "non-standard combination: ec-p384 with sha256 (expected sha384)" {
			hasWarning = true
		}
	}
	if !hasWarning {
		t.Error("Expected non-standard combination warning")
	}
}
