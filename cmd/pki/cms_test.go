package main

import (
	"os"
	"testing"
)

// Note: t.Parallel() is not used because Cobra commands share global flag state.
// Running tests in parallel causes race conditions with flag access.

// =============================================================================
// CMS Sign Tests (Table-Driven)
// =============================================================================

func TestCMSSign(t *testing.T) {
	tests := []struct {
		name      string
		hash      string
		detached  string
		wantErr   bool
		checkSize int // minimum expected size, 0 to skip
	}{
		{
			name:      "basic signing with default hash",
			hash:      "",
			detached:  "",
			wantErr:   false,
			checkSize: 1,
		},
		{
			name:      "signing with SHA-384",
			hash:      "sha384",
			detached:  "",
			wantErr:   false,
			checkSize: 1,
		},
		{
			name:      "signing with SHA-512",
			hash:      "sha512",
			detached:  "",
			wantErr:   false,
			checkSize: 1,
		},
		{
			name:      "attached signature",
			hash:      "",
			detached:  "false",
			wantErr:   false,
			checkSize: 100, // attached should be larger
		},
		{
			name:    "invalid hash algorithm",
			hash:    "md5",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := newTestContext(t)
			resetCMSFlags()

			certPath, keyPath := tc.setupSigningPair()
			dataPath := tc.writeFile("data.txt", "Test content for "+tt.name)
			outputPath := tc.path("signature.p7s")

			args := []string{"cms", "sign",
				"--data", dataPath,
				"--cert", certPath,
				"--key", keyPath,
				"--out", outputPath,
			}

			if tt.hash != "" {
				args = append(args, "--hash", tt.hash)
			}
			if tt.detached != "" {
				args = append(args, "--detached="+tt.detached)
			}

			_, err := executeCommand(rootCmd, args...)

			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if _, err := os.Stat(outputPath); os.IsNotExist(err) {
					t.Error("signature file was not created")
				}
				if tt.checkSize > 0 {
					data, _ := os.ReadFile(outputPath)
					if len(data) < tt.checkSize {
						t.Errorf("signature size = %d, want >= %d", len(data), tt.checkSize)
					}
				}
			}
		})
	}
}

func TestCMSSign_MissingFiles(t *testing.T) {
	tests := []struct {
		name        string
		missingFile string // "data", "cert", or "key"
	}{
		{"missing data file", "data"},
		{"missing certificate", "cert"},
		{"missing key", "key"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := newTestContext(t)
			resetCMSFlags()

			certPath, keyPath := tc.setupSigningPair()
			dataPath := tc.writeFile("data.txt", "test")
			outputPath := tc.path("signature.p7s")

			// Override with nonexistent path based on test case
			switch tt.missingFile {
			case "data":
				dataPath = tc.path("nonexistent.txt")
			case "cert":
				certPath = tc.path("nonexistent.crt")
			case "key":
				keyPath = tc.path("nonexistent.key")
			}

			_, err := executeCommand(rootCmd, "cms", "sign",
				"--data", dataPath,
				"--cert", certPath,
				"--key", keyPath,
				"--out", outputPath,
			)

			if err == nil {
				t.Errorf("expected error for %s", tt.missingFile)
			}
		})
	}
}

// =============================================================================
// CMS Verify Tests (Table-Driven)
// =============================================================================

func TestCMSVerify(t *testing.T) {
	tests := []struct {
		name        string
		detached    bool
		useCA       bool
		provideData bool
		wantErr     bool
	}{
		{
			name:        "detached signature",
			detached:    true,
			useCA:       false,
			provideData: true,
			wantErr:     false,
		},
		{
			name:        "attached signature",
			detached:    false,
			useCA:       false,
			provideData: false,
			wantErr:     false,
		},
		{
			name:        "with CA certificate",
			detached:    true,
			useCA:       true,
			provideData: true,
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := newTestContext(t)
			resetCMSFlags()

			// Create signature first
			certPath, keyPath := tc.setupSigningPair()
			dataPath := tc.writeFile("data.txt", "Content for "+tt.name)
			sigPath := tc.path("signature.p7s")

			signArgs := []string{"cms", "sign",
				"--data", dataPath,
				"--cert", certPath,
				"--key", keyPath,
				"--out", sigPath,
			}
			if !tt.detached {
				signArgs = append(signArgs, "--detached=false")
			}

			if _, err := executeCommand(rootCmd, signArgs...); err != nil {
				t.Fatalf("failed to create signature: %v", err)
			}

			resetCMSFlags()

			// Build verify command
			verifyArgs := []string{"cms", "verify", "--signature", sigPath}
			if tt.provideData {
				verifyArgs = append(verifyArgs, "--data", dataPath)
			}
			if tt.useCA {
				verifyArgs = append(verifyArgs, "--ca", certPath)
			}

			_, err := executeCommand(rootCmd, verifyArgs...)

			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCMSVerify_Errors(t *testing.T) {
	tests := []struct {
		name      string
		setupFunc func(*testContext) (sigPath, dataPath string)
	}{
		{
			name: "missing signature file",
			setupFunc: func(tc *testContext) (string, string) {
				dataPath := tc.writeFile("data.txt", "test")
				return tc.path("nonexistent.p7s"), dataPath
			},
		},
		{
			name: "wrong data for detached signature",
			setupFunc: func(tc *testContext) (string, string) {
				// Create valid signature
				certPath, keyPath := tc.setupSigningPair()
				dataPath := tc.writeFile("data.txt", "Original content")
				sigPath := tc.path("signature.p7s")

				resetCMSFlags()
				_, _ = executeCommand(rootCmd, "cms", "sign",
					"--data", dataPath,
					"--cert", certPath,
					"--key", keyPath,
					"--out", sigPath,
				)

				// Return wrong data
				wrongDataPath := tc.writeFile("wrong.txt", "Different content")
				return sigPath, wrongDataPath
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := newTestContext(t)
			resetCMSFlags()

			sigPath, dataPath := tt.setupFunc(tc)

			resetCMSFlags()
			_, err := executeCommand(rootCmd, "cms", "verify",
				"--signature", sigPath,
				"--data", dataPath,
			)

			if err == nil {
				t.Error("expected error")
			}
		})
	}
}

// =============================================================================
// CMS Round Trip Tests (Table-Driven)
// =============================================================================

func TestCMSRoundTrip(t *testing.T) {
	tests := []struct {
		name     string
		keyType  string // "ecdsa" or "rsa"
		dataSize int    // 0 for default small content
	}{
		{
			name:    "ECDSA key pair",
			keyType: "ecdsa",
		},
		{
			name:    "RSA key pair",
			keyType: "rsa",
		},
		{
			name:     "large file (10KB)",
			keyType:  "ecdsa",
			dataSize: 10 * 1024,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := newTestContext(t)
			resetCMSFlags()

			// Setup key pair based on type
			var certPath, keyPath string
			if tt.keyType == "rsa" {
				priv, pub := generateRSAKeyPair(tc.t, 2048)
				cert := generateSelfSignedCert(tc.t, priv, pub)
				certPath = tc.writeCertPEM("test.crt", cert)
				keyPath = tc.writeKeyPEM("test.key", priv)
			} else {
				certPath, keyPath = tc.setupSigningPair()
			}

			// Create data file
			var dataPath string
			if tt.dataSize > 0 {
				content := make([]byte, tt.dataSize)
				for i := range content {
					content[i] = byte(i % 256)
				}
				dataPath = tc.path("data.bin")
				if err := os.WriteFile(dataPath, content, 0644); err != nil {
					t.Fatalf("failed to create data file: %v", err)
				}
			} else {
				dataPath = tc.writeFile("data.txt", "Round trip content for "+tt.name)
			}

			sigPath := tc.path("signature.p7s")

			// Sign
			_, err := executeCommand(rootCmd, "cms", "sign",
				"--data", dataPath,
				"--cert", certPath,
				"--key", keyPath,
				"--out", sigPath,
			)
			if err != nil {
				t.Fatalf("sign failed: %v", err)
			}

			resetCMSFlags()

			// Verify
			_, err = executeCommand(rootCmd, "cms", "verify",
				"--signature", sigPath,
				"--data", dataPath,
			)
			if err != nil {
				t.Fatalf("verify failed: %v", err)
			}
		})
	}
}
