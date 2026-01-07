package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Note: t.Parallel() is not used because Cobra commands share global flag state.
// Running tests in parallel causes race conditions with flag access.

// =============================================================================
// CMS Sign Tests (Table-Driven)
// =============================================================================

func TestF_CMS_Sign(t *testing.T) {
	tests := []struct {
		name      string
		hash      string
		detached  string
		wantErr   bool
		checkSize int // minimum expected size, 0 to skip
	}{
		{
			name:      "[Functional] CMSSign: DefaultHash",
			hash:      "",
			detached:  "",
			wantErr:   false,
			checkSize: 1,
		},
		{
			name:      "[Functional] CMSSign: SHA384",
			hash:      "sha384",
			detached:  "",
			wantErr:   false,
			checkSize: 1,
		},
		{
			name:      "[Functional] CMSSign: SHA512",
			hash:      "sha512",
			detached:  "",
			wantErr:   false,
			checkSize: 1,
		},
		{
			name:      "[Functional] CMSSign: AttachedSignature",
			hash:      "",
			detached:  "false",
			wantErr:   false,
			checkSize: 100, // attached should be larger
		},
		{
			name:    "[Functional] CMSSign: InvalidHash",
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

func TestF_CMS_Sign_MissingFiles(t *testing.T) {
	tests := []struct {
		name        string
		missingFile string // "data", "cert", or "key"
	}{
		{"[Functional] CMSSign: MissingData", "data"},
		{"[Functional] CMSSign: MissingCert", "cert"},
		{"[Functional] CMSSign: MissingKey", "key"},
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

func TestF_CMS_Verify(t *testing.T) {
	tests := []struct {
		name        string
		detached    bool
		useCA       bool
		provideData bool
		wantErr     bool
	}{
		{
			name:        "[Functional] CMSVerify: DetachedSignature",
			detached:    true,
			useCA:       false,
			provideData: true,
			wantErr:     false,
		},
		{
			name:        "[Functional] CMSVerify: AttachedSignature",
			detached:    false,
			useCA:       false,
			provideData: false,
			wantErr:     false,
		},
		{
			name:        "[Functional] CMSVerify: WithCACert",
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
			verifyArgs := []string{"cms", "verify", sigPath}
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

func TestF_CMS_Verify_Errors(t *testing.T) {
	tests := []struct {
		name      string
		setupFunc func(*testContext) (sigPath, dataPath string)
	}{
		{
			name: "[Functional] CMSVerify: SignatureNotFound",
			setupFunc: func(tc *testContext) (string, string) {
				dataPath := tc.writeFile("data.txt", "test")
				return tc.path("nonexistent.p7s"), dataPath
			},
		},
		{
			name: "[Functional] CMSVerify: WrongData",
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
				sigPath,
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

func TestF_CMS_RoundTrip(t *testing.T) {
	tests := []struct {
		name     string
		keyType  string // "ecdsa" or "rsa"
		dataSize int    // 0 for default small content
	}{
		{
			name:    "[Functional] CMSRoundTrip: ECDSA",
			keyType: "ecdsa",
		},
		{
			name:    "[Functional] CMSRoundTrip: RSA",
			keyType: "rsa",
		},
		{
			name:     "[Functional] CMSRoundTrip: LargeFile",
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
				sigPath,
				"--data", dataPath,
			)
			if err != nil {
				t.Fatalf("verify failed: %v", err)
			}
		})
	}
}

// =============================================================================
// CMS Encrypt Tests (Table-Driven)
// =============================================================================

func TestF_CMS_Encrypt(t *testing.T) {
	tests := []struct {
		name       string
		contentEnc string
		wantErr    bool
	}{
		{
			name:       "[Functional] CMSEncrypt: DefaultAES256GCM",
			contentEnc: "",
			wantErr:    false,
		},
		{
			name:       "[Functional] CMSEncrypt: AES256CBC",
			contentEnc: "aes-256-cbc",
			wantErr:    false,
		},
		{
			name:       "[Functional] CMSEncrypt: AES128GCM",
			contentEnc: "aes-128-gcm",
			wantErr:    false,
		},
		{
			name:       "[Functional] CMSEncrypt: InvalidAlgorithm",
			contentEnc: "invalid-algorithm",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := newTestContext(t)
			resetCMSFlags()

			// Setup RSA recipient (needed for encryption)
			priv, pub := generateRSAKeyPair(tc.t, 2048)
			cert := generateSelfSignedCert(tc.t, priv, pub)
			recipientPath := tc.writeCertPEM("recipient.crt", cert)

			// Create input data
			inputPath := tc.writeFile("plaintext.txt", "Secret content for "+tt.name)
			outputPath := tc.path("encrypted.p7m")

			// Build encrypt command
			args := []string{"cms", "encrypt",
				"--recipient", recipientPath,
				"--in", inputPath,
				"--out", outputPath,
			}
			if tt.contentEnc != "" {
				args = append(args, "--content-enc", tt.contentEnc)
			}

			_, err := executeCommand(rootCmd, args...)

			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				assertFileExists(t, outputPath)
				assertFileNotEmpty(t, outputPath)
			}
		})
	}
}

func TestF_CMS_Encrypt_MissingFlags(t *testing.T) {
	tests := []struct {
		name    string
		missing string // "recipient", "in", or "out"
	}{
		{"[Functional] CMSEncrypt: MissingRecipient", "recipient"},
		{"[Functional] CMSEncrypt: MissingInput", "in"},
		{"[Functional] CMSEncrypt: MissingOutput", "out"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := newTestContext(t)
			resetCMSFlags()

			// Setup valid values
			priv, pub := generateRSAKeyPair(tc.t, 2048)
			cert := generateSelfSignedCert(tc.t, priv, pub)
			recipientPath := tc.writeCertPEM("recipient.crt", cert)
			inputPath := tc.writeFile("plaintext.txt", "test content")
			outputPath := tc.path("encrypted.p7m")

			// Build args, skipping the missing one
			var args []string
			args = append(args, "cms", "encrypt")
			if tt.missing != "recipient" {
				args = append(args, "--recipient", recipientPath)
			}
			if tt.missing != "in" {
				args = append(args, "--in", inputPath)
			}
			if tt.missing != "out" {
				args = append(args, "--out", outputPath)
			}

			_, err := executeCommand(rootCmd, args...)
			assertError(t, err)
		})
	}
}

func TestF_CMS_Encrypt_RecipientNotFound(t *testing.T) {
	tc := newTestContext(t)
	resetCMSFlags()

	inputPath := tc.writeFile("plaintext.txt", "test content")

	_, err := executeCommand(rootCmd, "cms", "encrypt",
		"--recipient", tc.path("nonexistent.crt"),
		"--in", inputPath,
		"--out", tc.path("encrypted.p7m"),
	)
	assertError(t, err)
}

func TestF_CMS_Encrypt_InputNotFound(t *testing.T) {
	tc := newTestContext(t)
	resetCMSFlags()

	priv, pub := generateRSAKeyPair(tc.t, 2048)
	cert := generateSelfSignedCert(tc.t, priv, pub)
	recipientPath := tc.writeCertPEM("recipient.crt", cert)

	_, err := executeCommand(rootCmd, "cms", "encrypt",
		"--recipient", recipientPath,
		"--in", tc.path("nonexistent.txt"),
		"--out", tc.path("encrypted.p7m"),
	)
	assertError(t, err)
}

func TestF_CMS_Encrypt_MultipleRecipients(t *testing.T) {
	tc := newTestContext(t)
	resetCMSFlags()

	// Create two recipients
	priv1, pub1 := generateRSAKeyPair(tc.t, 2048)
	cert1 := generateSelfSignedCert(tc.t, priv1, pub1)
	recipient1Path := tc.writeCertPEM("recipient1.crt", cert1)

	priv2, pub2 := generateRSAKeyPair(tc.t, 2048)
	cert2 := generateSelfSignedCert(tc.t, priv2, pub2)
	recipient2Path := tc.writeCertPEM("recipient2.crt", cert2)

	inputPath := tc.writeFile("plaintext.txt", "Secret for multiple recipients")
	outputPath := tc.path("encrypted.p7m")

	_, err := executeCommand(rootCmd, "cms", "encrypt",
		"--recipient", recipient1Path,
		"--recipient", recipient2Path,
		"--in", inputPath,
		"--out", outputPath,
	)
	assertNoError(t, err)
	assertFileExists(t, outputPath)
}

// =============================================================================
// CMS Decrypt Tests (Table-Driven)
// =============================================================================

func TestF_CMS_Decrypt_MissingFlags(t *testing.T) {
	tests := []struct {
		name    string
		missing string // "key", "in", or "out"
	}{
		{"[Functional] CMSDecrypt: MissingKey", "key"},
		{"[Functional] CMSDecrypt: MissingInput", "in"},
		{"[Functional] CMSDecrypt: MissingOutput", "out"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := newTestContext(t)
			resetCMSFlags()

			// Setup valid values
			priv, pub := generateRSAKeyPair(tc.t, 2048)
			cert := generateSelfSignedCert(tc.t, priv, pub)
			tc.writeCertPEM("recipient.crt", cert)
			keyPath := tc.writeKeyPEM("recipient.key", priv)
			encryptedPath := tc.writeFile("encrypted.p7m", "dummy content")
			outputPath := tc.path("decrypted.txt")

			// Build args, skipping the missing one
			var args []string
			args = append(args, "cms", "decrypt")
			if tt.missing != "key" {
				args = append(args, "--key", keyPath)
			}
			if tt.missing != "in" {
				args = append(args, "--in", encryptedPath)
			}
			if tt.missing != "out" {
				args = append(args, "--out", outputPath)
			}

			_, err := executeCommand(rootCmd, args...)
			assertError(t, err)
		})
	}
}

func TestF_CMS_Decrypt_KeyNotFound(t *testing.T) {
	tc := newTestContext(t)
	resetCMSFlags()

	encryptedPath := tc.writeFile("encrypted.p7m", "dummy content")

	_, err := executeCommand(rootCmd, "cms", "decrypt",
		"--key", tc.path("nonexistent.key"),
		"--in", encryptedPath,
		"--out", tc.path("decrypted.txt"),
	)
	assertError(t, err)
}

func TestF_CMS_Decrypt_InputNotFound(t *testing.T) {
	tc := newTestContext(t)
	resetCMSFlags()

	priv, pub := generateRSAKeyPair(tc.t, 2048)
	cert := generateSelfSignedCert(tc.t, priv, pub)
	tc.writeCertPEM("recipient.crt", cert)
	keyPath := tc.writeKeyPEM("recipient.key", priv)

	_, err := executeCommand(rootCmd, "cms", "decrypt",
		"--key", keyPath,
		"--in", tc.path("nonexistent.p7m"),
		"--out", tc.path("decrypted.txt"),
	)
	assertError(t, err)
}

func TestF_CMS_Decrypt_InvalidInput(t *testing.T) {
	tc := newTestContext(t)
	resetCMSFlags()

	priv, pub := generateRSAKeyPair(tc.t, 2048)
	cert := generateSelfSignedCert(tc.t, priv, pub)
	tc.writeCertPEM("recipient.crt", cert)
	keyPath := tc.writeKeyPEM("recipient.key", priv)
	invalidPath := tc.writeFile("invalid.p7m", "not a valid CMS EnvelopedData")

	_, err := executeCommand(rootCmd, "cms", "decrypt",
		"--key", keyPath,
		"--in", invalidPath,
		"--out", tc.path("decrypted.txt"),
	)
	assertError(t, err)
}

// =============================================================================
// CMS Encrypt/Decrypt Round-Trip Tests
// =============================================================================

// setupCAWithKEMCredential creates a CA and enrolls a credential with key encipherment for CMS tests.
// Returns: caDir, recipientCertPath, recipientKeyPath
func setupCAWithKEMCredential(tc *testContext) (string, string, string) {
	tc.t.Helper()

	resetCAFlags()
	caDir := tc.path("ca")
	credentialsDir := tc.path("credentials")
	_, err := executeCommand(rootCmd, "ca", "init",
		"--profile", "rsa/root-ca",
		"--ca-dir", caDir,
		"--var", "cn=Test CA",
	)
	if err != nil {
		tc.t.Fatalf("failed to init CA: %v", err)
	}

	resetCredentialFlags()
	_, err = executeCommand(rootCmd, "credential", "enroll",
		"--ca-dir", caDir,
		"--cred-dir", credentialsDir,
		"--profile", "rsa/email",
		"--var", "cn=recipient@test.local",
		"--var", "email=recipient@test.local",
	)
	if err != nil {
		tc.t.Fatalf("failed to enroll credential: %v", err)
	}

	// Find the credential
	entries, err := os.ReadDir(credentialsDir)
	if err != nil || len(entries) == 0 {
		tc.t.Fatal("no credentials found")
	}

	credentialDir := filepath.Join(credentialsDir, entries[0].Name())
	recipientCert := filepath.Join(credentialDir, "certificates.pem")
	recipientKey := filepath.Join(credentialDir, "private-keys.pem")

	return caDir, recipientCert, recipientKey
}

func TestF_CMS_EncryptDecrypt_RoundTrip(t *testing.T) {
	tc := newTestContext(t)

	// Setup CA and recipient credential with proper extensions
	_, recipientCert, recipientKey := setupCAWithKEMCredential(tc)

	tests := []struct {
		name       string
		contentEnc string
		content    string
	}{
		{
			name:       "[Functional] CMSEncryptDecrypt: DefaultAES256GCM",
			contentEnc: "",
			content:    "Round trip test with default encryption",
		},
		{
			name:       "[Functional] CMSEncryptDecrypt: AES256CBC",
			contentEnc: "aes-256-cbc",
			content:    "Round trip test with AES-256-CBC",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetCMSFlags()

			// Create input
			inputPath := tc.writeFile("plaintext-"+tt.name+".txt", tt.content)
			encryptedPath := tc.path("encrypted-" + tt.name + ".p7m")
			decryptedPath := tc.path("decrypted-" + tt.name + ".txt")

			// Encrypt
			encryptArgs := []string{"cms", "encrypt",
				"--recipient", recipientCert,
				"--in", inputPath,
				"--out", encryptedPath,
			}
			if tt.contentEnc != "" {
				encryptArgs = append(encryptArgs, "--content-enc", tt.contentEnc)
			}

			_, err := executeCommand(rootCmd, encryptArgs...)
			if err != nil {
				t.Fatalf("encrypt failed: %v", err)
			}

			resetCMSFlags()

			// Decrypt with certificate for matching
			_, err = executeCommand(rootCmd, "cms", "decrypt",
				"--key", recipientKey,
				"--cert", recipientCert,
				"--in", encryptedPath,
				"--out", decryptedPath,
			)
			if err != nil {
				t.Fatalf("decrypt failed: %v", err)
			}

			// Verify content matches
			decrypted, err := os.ReadFile(decryptedPath)
			if err != nil {
				t.Fatalf("failed to read decrypted file: %v", err)
			}

			if string(decrypted) != tt.content {
				t.Errorf("decrypted content mismatch: got %d bytes, want %d bytes",
					len(decrypted), len(tt.content))
			}
		})
	}
}

func TestF_CMS_EncryptDecrypt_WithCert(t *testing.T) {
	tc := newTestContext(t)

	// Setup CA and recipient credential
	_, recipientCert, recipientKey := setupCAWithKEMCredential(tc)

	resetCMSFlags()

	content := "Test with certificate matching"
	inputPath := tc.writeFile("plaintext.txt", content)
	encryptedPath := tc.path("encrypted.p7m")
	decryptedPath := tc.path("decrypted.txt")

	// Encrypt
	_, err := executeCommand(rootCmd, "cms", "encrypt",
		"--recipient", recipientCert,
		"--in", inputPath,
		"--out", encryptedPath,
	)
	assertNoError(t, err)

	resetCMSFlags()

	// Decrypt with certificate for matching
	_, err = executeCommand(rootCmd, "cms", "decrypt",
		"--key", recipientKey,
		"--cert", recipientCert,
		"--in", encryptedPath,
		"--out", decryptedPath,
	)
	assertNoError(t, err)

	// Verify content
	decrypted, err := os.ReadFile(decryptedPath)
	assertNoError(t, err)
	if string(decrypted) != content {
		t.Error("decrypted content does not match original")
	}
}

// =============================================================================
// CMS Info Tests
// =============================================================================

func TestF_CMS_Info_SignedData(t *testing.T) {
	tc := newTestContext(t)

	// Create signed data
	certPath, keyPath := tc.setupSigningPair()
	dataPath := tc.writeFile("data.txt", "test data for info")
	sigPath := tc.path("signature.p7s")

	resetCMSFlags()
	_, err := executeCommand(rootCmd, "cms", "sign",
		"--data", dataPath,
		"--cert", certPath,
		"--key", keyPath,
		"--out", sigPath,
	)
	assertNoError(t, err)

	// Get info about the signed data
	_, err = executeCommand(rootCmd, "cms", "info", sigPath)
	assertNoError(t, err)
}

func TestF_CMS_Info_EnvelopedData(t *testing.T) {
	tc := newTestContext(t)

	// Create enveloped data
	_, recipientCert, _ := setupCAWithKEMCredential(tc)
	inputPath := tc.writeFile("plaintext.txt", "secret content")
	encryptedPath := tc.path("encrypted.p7m")

	resetCMSFlags()
	_, err := executeCommand(rootCmd, "cms", "encrypt",
		"--recipient", recipientCert,
		"--in", inputPath,
		"--out", encryptedPath,
	)
	assertNoError(t, err)

	// Get info about the enveloped data
	_, err = executeCommand(rootCmd, "cms", "info", encryptedPath)
	assertNoError(t, err)
}

func TestF_CMS_Info_FileNotFound(t *testing.T) {
	tc := newTestContext(t)

	_, err := executeCommand(rootCmd, "cms", "info", tc.path("nonexistent.p7s"))
	assertError(t, err)
}

func TestF_CMS_Info_InvalidFile(t *testing.T) {
	tc := newTestContext(t)

	invalidPath := tc.writeFile("invalid.p7s", "not a CMS message")
	_, err := executeCommand(rootCmd, "cms", "info", invalidPath)
	assertError(t, err)
}

func TestF_CMS_Info_ArgMissing(t *testing.T) {
	_, err := executeCommand(rootCmd, "cms", "info")
	assertError(t, err)
}
