package ca

import (
	"fmt"

	"github.com/remiblancher/post-quantum-pki/internal/audit"
	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
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
			if defaultKey == nil {
				return fmt.Errorf("no key reference found in CA metadata")
			}

			keyCfg, err := defaultKey.BuildKeyStorageConfig(ca.info.BasePath(), passphrase)
			if err != nil {
				return fmt.Errorf("failed to build key storage config: %w", err)
			}

			km := pkicrypto.NewKeyProvider(keyCfg)
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

	// Load classical signer
	classicalKeyPath := ca.info.KeyPath(ca.info.Active, classicalAlgo)
	classicalSigner, err := pkicrypto.LoadPrivateKey(classicalKeyPath, []byte(classicalPassphrase))
	if err != nil {
		_ = audit.LogAuthFailed(ca.store.BasePath(), "failed to load classical CA key")
		return fmt.Errorf("failed to load classical CA key: %w", err)
	}

	// Load PQC signer
	pqcKeyPath := ca.info.KeyPath(ca.info.Active, pqcAlgo)
	pqcSigner, err := pkicrypto.LoadPrivateKey(pqcKeyPath, []byte(pqcPassphrase))
	if err != nil {
		_ = audit.LogAuthFailed(ca.store.BasePath(), "failed to load PQC CA key")
		return fmt.Errorf("failed to load PQC CA key: %w", err)
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
