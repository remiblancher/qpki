package ca

import (
	"fmt"
	"path/filepath"

	"github.com/remiblancher/post-quantum-pki/pkg/audit"
	pkicrypto "github.com/remiblancher/post-quantum-pki/pkg/crypto"
)

// LoadSigner loads the CA signer from the store.
// For hybrid CAs (with both classical and PQC keys), it automatically loads both
// keys and creates a HybridSigner.
func (ca *CA) LoadSigner(passphrase string) error {
	var signer pkicrypto.Signer

	// Use CAInfo (required for all CAs)
	if ca.info != nil {
		activeVer := ca.info.ActiveVersion()
		if activeVer != nil && len(activeVer.Algos) > 0 {
			// Check for hybrid (has multiple algos with one classical + one PQC)
			if ca.isHybridFromInfo() {
				return ca.loadHybridSignerFromInfo(passphrase, passphrase)
			}

			// Single key CA - use KeyRef (supports HSM and software keys)
			defaultKey := ca.info.GetDefaultKey()
			var keyCfg pkicrypto.KeyStorageConfig
			var km pkicrypto.KeyProvider
			var err error

			if defaultKey != nil {
				// Normal path: use KeyRef
				keyCfg, err = defaultKey.BuildKeyStorageConfig(ca.info.BasePath(), passphrase)
				if err != nil {
					return fmt.Errorf("failed to build key storage config: %w", err)
				}
				km = pkicrypto.NewKeyProvider(keyCfg)
			} else {
				// Fallback: construct key config from algorithm (for CAs without explicit key refs)
				algo := activeVer.Algos[0]
				keyPath := ca.info.KeyPath(ca.info.Active, algo)
				keyCfg = pkicrypto.KeyStorageConfig{
					Type:       pkicrypto.KeyProviderTypeSoftware,
					KeyPath:    keyPath,
					Passphrase: passphrase,
				}
				km = pkicrypto.NewSoftwareKeyProvider()
			}

			signer, err = km.Load(keyCfg)
			if err != nil {
				_ = audit.LogAuthFailed(ca.store.BasePath(), "invalid passphrase or key load error")
				return fmt.Errorf("failed to load CA key: %w", err)
			}

			ca.keyProvider = km
			ca.keyConfig = keyCfg
		}
	}

	// Require CAInfo - no legacy support
	if signer == nil {
		return fmt.Errorf("CA metadata (ca.meta.json) not found or invalid - legacy CA format not supported")
	}

	// Audit: key accessed successfully
	if err := audit.LogKeyAccessed(ca.store.BasePath(), true, "CA signing key loaded"); err != nil {
		return err
	}

	ca.signer = signer
	return nil
}

// isHybridFromInfo checks if this is a hybrid CA (has both classical and PQC algos).
func (ca *CA) isHybridFromInfo() bool {
	if ca.info == nil {
		return false
	}
	activeVer := ca.info.ActiveVersion()
	if activeVer == nil || len(activeVer.Algos) < 2 {
		return false
	}
	// Check if we have both classical and PQC
	hasClassical := false
	hasPQC := false
	for _, algo := range activeVer.Algos {
		if isClassicalAlgo(algo) {
			hasClassical = true
		} else {
			hasPQC = true
		}
	}
	return hasClassical && hasPQC
}

// isClassicalAlgo returns true if the algo is a classical algorithm.
func isClassicalAlgo(algo string) bool {
	// Check both algorithm families and full algorithm IDs
	switch algo {
	// Families
	case "ec", "rsa", "ed25519":
		return true
	// Full algorithm IDs - EC
	case "ecdsa-p256", "ecdsa-p384", "ecdsa-p521":
		return true
	// Full algorithm IDs - RSA
	case "rsa-2048", "rsa-4096":
		return true
	default:
		return false
	}
}

// loadHybridSignerFromInfo loads both classical and PQC keys from CAInfo.
// Supports both software keys (file-based) and HSM keys (PKCS#11).
func (ca *CA) loadHybridSignerFromInfo(classicalPassphrase, pqcPassphrase string) error {
	activeVer := ca.info.ActiveVersion()
	if activeVer == nil {
		return fmt.Errorf("no active version")
	}

	var classicalAlgo, pqcAlgo string
	for _, algo := range activeVer.Algos {
		if isClassicalAlgo(algo) {
			classicalAlgo = algo
		} else {
			pqcAlgo = algo
		}
	}

	if classicalAlgo == "" || pqcAlgo == "" {
		return fmt.Errorf("hybrid CA requires both classical and PQC algorithms")
	}

	// Check if this is an HSM-based hybrid CA
	classicalKeyRef := ca.info.GetKey("classical")
	pqcKeyRef := ca.info.GetKey("pqc")

	// For HSM hybrid CA, use NewPKCS11HybridSigner which can distinguish keys by type
	if classicalKeyRef != nil && classicalKeyRef.Storage.Type == "pkcs11" {
		hybridSigner, err := ca.loadHybridSignerFromHSM(classicalKeyRef)
		if err != nil {
			return err
		}
		ca.signer = hybridSigner
		return audit.LogKeyAccessed(ca.store.BasePath(), true, "Hybrid CA signing keys loaded from HSM")
	}

	// Software-based hybrid CA: load each key separately
	var classicalSigner, pqcSigner pkicrypto.Signer
	var err error

	if classicalKeyRef != nil && classicalKeyRef.Storage.Type == "software" {
		keyCfg, err := classicalKeyRef.BuildKeyStorageConfig(ca.info.BasePath(), classicalPassphrase)
		if err != nil {
			return fmt.Errorf("failed to build classical key config: %w", err)
		}
		km := pkicrypto.NewKeyProvider(keyCfg)
		classicalSigner, err = km.Load(keyCfg)
		if err != nil {
			_ = audit.LogAuthFailed(ca.store.BasePath(), "failed to load classical CA key from KeyRef")
			return fmt.Errorf("failed to load classical CA key: %w", err)
		}
	} else {
		// Fallback: load from file path
		classicalKeyPath := ca.info.KeyPath(ca.info.Active, classicalAlgo)
		classicalSigner, err = pkicrypto.LoadPrivateKey(classicalKeyPath, []byte(classicalPassphrase))
		if err != nil {
			_ = audit.LogAuthFailed(ca.store.BasePath(), "failed to load classical CA key")
			return fmt.Errorf("failed to load classical CA key: %w", err)
		}
	}

	if pqcKeyRef != nil && pqcKeyRef.Storage.Type == "software" {
		keyCfg, err := pqcKeyRef.BuildKeyStorageConfig(ca.info.BasePath(), pqcPassphrase)
		if err != nil {
			return fmt.Errorf("failed to build PQC key config: %w", err)
		}
		km := pkicrypto.NewKeyProvider(keyCfg)
		pqcSigner, err = km.Load(keyCfg)
		if err != nil {
			_ = audit.LogAuthFailed(ca.store.BasePath(), "failed to load PQC CA key from KeyRef")
			return fmt.Errorf("failed to load PQC CA key: %w", err)
		}
	} else {
		// Fallback: load from file path
		pqcKeyPath := ca.info.KeyPath(ca.info.Active, pqcAlgo)
		pqcSigner, err = pkicrypto.LoadPrivateKey(pqcKeyPath, []byte(pqcPassphrase))
		if err != nil {
			_ = audit.LogAuthFailed(ca.store.BasePath(), "failed to load PQC CA key")
			return fmt.Errorf("failed to load PQC CA key: %w", err)
		}
	}

	// Create hybrid signer
	hybridSigner, err := pkicrypto.NewHybridSigner(classicalSigner, pqcSigner)
	if err != nil {
		return fmt.Errorf("failed to create hybrid signer: %w", err)
	}

	if err := audit.LogKeyAccessed(ca.store.BasePath(), true, "Hybrid CA signing keys loaded"); err != nil {
		return err
	}

	ca.signer = hybridSigner
	return nil
}

// loadHybridSignerFromHSM loads a hybrid signer from HSM using NewPKCS11HybridSigner.
// This function uses findPrivateKeyByType to distinguish EC and ML-DSA keys with the same label.
func (ca *CA) loadHybridSignerFromHSM(keyRef *KeyRef) (pkicrypto.HybridSigner, error) {
	// Load HSM config from the path stored in KeyRef
	// Resolve relative path to absolute using CA base path
	hsmConfigPath := keyRef.Storage.Config
	if !filepath.IsAbs(hsmConfigPath) && ca.info != nil {
		hsmConfigPath = filepath.Join(ca.info.BasePath(), hsmConfigPath)
	}
	hsmCfg, err := pkicrypto.LoadHSMConfig(hsmConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load HSM config: %w", err)
	}

	pin, err := hsmCfg.GetPIN()
	if err != nil {
		return nil, fmt.Errorf("failed to get HSM PIN: %w", err)
	}

	pkcs11Cfg := pkicrypto.PKCS11Config{
		ModulePath: hsmCfg.PKCS11.Lib,
		TokenLabel: hsmCfg.PKCS11.Token,
		PIN:        pin,
		KeyLabel:   keyRef.Storage.Label,
	}

	// NewPKCS11HybridSigner uses findPrivateKeyByType to find keys by type
	return pkicrypto.NewPKCS11HybridSigner(pkcs11Cfg)
}

// LoadHybridSigner loads a hybrid signer from the store for Catalyst certificate issuance.
// Deprecated: Use LoadSigner() instead, which automatically detects hybrid CAs.
func (ca *CA) LoadHybridSigner(classicalPassphrase, pqcPassphrase string) error {
	if !ca.isHybridFromInfo() {
		return fmt.Errorf("not a hybrid CA or missing CAInfo metadata")
	}
	return ca.loadHybridSignerFromInfo(classicalPassphrase, pqcPassphrase)
}

// LoadCompositeSigner loads a composite signer from the store.
// This loads both classical and PQC keys and creates a hybrid signer.
func (ca *CA) LoadCompositeSigner(classicalPassphrase, pqcPassphrase string) error {
	if !ca.isHybridFromInfo() {
		return fmt.Errorf("not a composite/hybrid CA or missing CAInfo metadata")
	}
	return ca.loadHybridSignerFromInfo(classicalPassphrase, pqcPassphrase)
}
