package profile

import (
	"crypto"
	"crypto/x509"
	"testing"

	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
)

// =============================================================================
// Unit Tests: HashAlgorithm
// =============================================================================

func TestU_HashAlgorithm_IsValid(t *testing.T) {
	tests := []struct {
		name  string
		hash  HashAlgorithm
		valid bool
	}{
		{"[Unit] IsValid: SHA256", HashSHA256, true},
		{"[Unit] IsValid: SHA384", HashSHA384, true},
		{"[Unit] IsValid: SHA512", HashSHA512, true},
		{"[Unit] IsValid: SHA3-256", HashSHA3_256, true},
		{"[Unit] IsValid: SHA3-384", HashSHA3_384, true},
		{"[Unit] IsValid: SHA3-512", HashSHA3_512, true},
		{"[Unit] IsValid: Invalid Hash", "invalid", false},
		{"[Unit] IsValid: Empty Hash", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.hash.IsValid(); got != tt.valid {
				t.Errorf("HashAlgorithm.IsValid() = %v, want %v", got, tt.valid)
			}
		})
	}
}

func TestU_HashAlgorithm_CryptoHash(t *testing.T) {
	tests := []struct {
		name     string
		hash     HashAlgorithm
		expected crypto.Hash
	}{
		{"[Unit] CryptoHash: SHA256", HashSHA256, crypto.SHA256},
		{"[Unit] CryptoHash: SHA384", HashSHA384, crypto.SHA384},
		{"[Unit] CryptoHash: SHA512", HashSHA512, crypto.SHA512},
		{"[Unit] CryptoHash: SHA3-256", HashSHA3_256, crypto.SHA3_256},
		{"[Unit] CryptoHash: SHA3-384", HashSHA3_384, crypto.SHA3_384},
		{"[Unit] CryptoHash: SHA3-512", HashSHA3_512, crypto.SHA3_512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.hash.CryptoHash(); got != tt.expected {
				t.Errorf("HashAlgorithm.CryptoHash() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestU_HashAlgorithm_SizeBytes(t *testing.T) {
	tests := []struct {
		name     string
		hash     HashAlgorithm
		expected int
	}{
		{"[Unit] SizeBytes: SHA256", HashSHA256, 32},
		{"[Unit] SizeBytes: SHA384", HashSHA384, 48},
		{"[Unit] SizeBytes: SHA512", HashSHA512, 64},
		{"[Unit] SizeBytes: SHA3-256", HashSHA3_256, 32},
		{"[Unit] SizeBytes: SHA3-384", HashSHA3_384, 48},
		{"[Unit] SizeBytes: SHA3-512", HashSHA3_512, 64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.hash.SizeBytes(); got != tt.expected {
				t.Errorf("HashAlgorithm.SizeBytes() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// =============================================================================
// Unit Tests: SignatureScheme
// =============================================================================

func TestU_SignatureScheme_IsValid(t *testing.T) {
	tests := []struct {
		name   string
		scheme SignatureScheme
		valid  bool
	}{
		{"[Unit] IsValid: ECDSA", SchemeECDSA, true},
		{"[Unit] IsValid: PKCS1v15", SchemePKCS1v15, true},
		{"[Unit] IsValid: RSASSA-PSS", SchemeRSASSAPSS, true},
		{"[Unit] IsValid: Ed25519", SchemeEd25519, true},
		{"[Unit] IsValid: Ed25519ph", SchemeEd25519ph, true},
		{"[Unit] IsValid: Ed448", SchemeEd448, true},
		{"[Unit] IsValid: Ed448ph", SchemeEd448ph, true},
		{"[Unit] IsValid: Invalid Scheme", "invalid", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.scheme.IsValid(); got != tt.valid {
				t.Errorf("SignatureScheme.IsValid() = %v, want %v", got, tt.valid)
			}
		})
	}
}

func TestU_SignatureScheme_RequiresHash(t *testing.T) {
	tests := []struct {
		name     string
		scheme   SignatureScheme
		requires bool
	}{
		{"[Unit] RequiresHash: ECDSA", SchemeECDSA, true},
		{"[Unit] RequiresHash: PKCS1v15", SchemePKCS1v15, true},
		{"[Unit] RequiresHash: RSASSA-PSS", SchemeRSASSAPSS, true},
		{"[Unit] RequiresHash: Ed25519", SchemeEd25519, false},
		{"[Unit] RequiresHash: Ed25519ph", SchemeEd25519ph, true},
		{"[Unit] RequiresHash: Ed448", SchemeEd448, false},
		{"[Unit] RequiresHash: Ed448ph", SchemeEd448ph, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.scheme.RequiresHash(); got != tt.requires {
				t.Errorf("SignatureScheme.RequiresHash() = %v, want %v", got, tt.requires)
			}
		})
	}
}

// =============================================================================
// Unit Tests: SignatureAlgoConfig
// =============================================================================

func TestU_SignatureAlgoConfig_Resolve_ECDSA(t *testing.T) {
	tests := []struct {
		name           string
		key            pkicrypto.AlgorithmID
		expectedScheme SignatureScheme
		expectedHash   HashAlgorithm
	}{
		{"[Unit] Resolve: ECDSA P-256", pkicrypto.AlgECP256, SchemeECDSA, HashSHA256},
		{"[Unit] Resolve: ECDSA P-384", pkicrypto.AlgECP384, SchemeECDSA, HashSHA384},
		{"[Unit] Resolve: ECDSA P-521", pkicrypto.AlgECP521, SchemeECDSA, HashSHA512},
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

func TestU_SignatureAlgoConfig_Resolve_RSA(t *testing.T) {
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

func TestU_SignatureAlgoConfig_Resolve_RSA_PKCS1v15(t *testing.T) {
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

func TestU_SignatureAlgoConfig_Resolve_Ed25519(t *testing.T) {
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

func TestU_SignatureAlgoConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     SignatureAlgoConfig
		wantErr bool
	}{
		{
			name:    "[Unit] Validate: Valid ECDSA",
			cfg:     SignatureAlgoConfig{Key: pkicrypto.AlgECP384, Scheme: SchemeECDSA, Hash: HashSHA384},
			wantErr: false,
		},
		{
			name:    "[Unit] Validate: Valid RSA-PSS",
			cfg:     SignatureAlgoConfig{Key: pkicrypto.AlgRSA4096, Scheme: SchemeRSASSAPSS, Hash: HashSHA256},
			wantErr: false,
		},
		{
			name:    "[Unit] Validate: Key Missing",
			cfg:     SignatureAlgoConfig{Scheme: SchemeECDSA},
			wantErr: true,
		},
		{
			name:    "[Unit] Validate: Key Invalid",
			cfg:     SignatureAlgoConfig{Key: "invalid-key"},
			wantErr: true,
		},
		{
			name:    "[Unit] Validate: Scheme Invalid",
			cfg:     SignatureAlgoConfig{Key: pkicrypto.AlgECP384, Scheme: "invalid-scheme"},
			wantErr: true,
		},
		{
			name:    "[Unit] Validate: Hash Invalid",
			cfg:     SignatureAlgoConfig{Key: pkicrypto.AlgECP384, Hash: "invalid-hash"},
			wantErr: true,
		},
		{
			name:    "[Unit] Validate: ECDSA With RSA Key Invalid",
			cfg:     SignatureAlgoConfig{Key: pkicrypto.AlgRSA4096, Scheme: SchemeECDSA},
			wantErr: true,
		},
		{
			name:    "[Unit] Validate: RSA-PSS With EC Key Invalid",
			cfg:     SignatureAlgoConfig{Key: pkicrypto.AlgECP384, Scheme: SchemeRSASSAPSS},
			wantErr: true,
		},
		{
			name:    "[Unit] Validate: PSS Params With PKCS1v15 Invalid",
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

func TestU_SignatureAlgoConfig_X509SignatureAlgorithm(t *testing.T) {
	tests := []struct {
		name     string
		cfg      SignatureAlgoConfig
		expected x509.SignatureAlgorithm
	}{
		{
			name:     "[Unit] X509SigAlgo: ECDSA P-256 SHA-256",
			cfg:      SignatureAlgoConfig{Key: pkicrypto.AlgECP256, Scheme: SchemeECDSA, Hash: HashSHA256},
			expected: x509.ECDSAWithSHA256,
		},
		{
			name:     "[Unit] X509SigAlgo: ECDSA P-384 SHA-384",
			cfg:      SignatureAlgoConfig{Key: pkicrypto.AlgECP384, Scheme: SchemeECDSA, Hash: HashSHA384},
			expected: x509.ECDSAWithSHA384,
		},
		{
			name:     "[Unit] X509SigAlgo: RSA PKCS1v15 SHA-256",
			cfg:      SignatureAlgoConfig{Key: pkicrypto.AlgRSA4096, Scheme: SchemePKCS1v15, Hash: HashSHA256},
			expected: x509.SHA256WithRSA,
		},
		{
			name:     "[Unit] X509SigAlgo: RSA-PSS SHA-256",
			cfg:      SignatureAlgoConfig{Key: pkicrypto.AlgRSA4096, Scheme: SchemeRSASSAPSS, Hash: HashSHA256},
			expected: x509.SHA256WithRSAPSS,
		},
		{
			name:     "[Unit] X509SigAlgo: Ed25519",
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

func TestU_SignatureAlgoConfig_NonStandardWarnings(t *testing.T) {
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
