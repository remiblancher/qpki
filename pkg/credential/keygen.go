package credential

import (
	"fmt"

	pkicrypto "github.com/remiblancher/post-quantum-pki/pkg/crypto"
)

// GenerateKey generates a key for a credential using the provided KeyProvider.
// It uses the configured KeyProvider (software or HSM) and returns both
// the signer and a StorageRef describing where the key is stored.
//
// For software keys: generates in memory, store will persist it.
// For HSM keys: generates directly in HSM, returns a storage ref with PKCS#11 info.
//
// The credentialID and keyIndex are used to construct unique key labels for HSM.
// If noSuffix is true, the label is used as-is without adding -{keyIndex} suffix.
// This is used for hybrid/composite credentials where both keys share the same label
// and are distinguished by CKA_KEY_TYPE (like CA does).
func GenerateKey(
	kp pkicrypto.KeyProvider,
	cfg pkicrypto.KeyStorageConfig,
	alg pkicrypto.AlgorithmID,
	credentialID string,
	keyIndex int,
	noSuffix bool,
) (pkicrypto.Signer, pkicrypto.StorageRef, error) {
	switch cfg.Type {
	case pkicrypto.KeyProviderTypePKCS11:
		// HSM: generate with unique label based on credential ID or provided prefix
		hsmCfg := cfg
		labelPrefix := cfg.PKCS11KeyLabel
		if labelPrefix == "" {
			labelPrefix = credentialID
		}
		if noSuffix {
			hsmCfg.PKCS11KeyLabel = labelPrefix
		} else {
			hsmCfg.PKCS11KeyLabel = fmt.Sprintf("%s-%d", labelPrefix, keyIndex)
		}

		signer, err := kp.Generate(alg, hsmCfg)
		if err != nil {
			return nil, pkicrypto.StorageRef{}, err
		}
		return signer, pkicrypto.StorageRef{
			Type:   "pkcs11",
			Config: cfg.PKCS11ConfigPath,
			Label:  hsmCfg.PKCS11KeyLabel,
			KeyID:  cfg.PKCS11KeyID,
		}, nil

	default:
		// Software: generate in memory, FileStore will save it
		// Check if this is a KEM algorithm (ML-KEM)
		if alg.IsKEM() {
			kemSigner, err := pkicrypto.GenerateKEMSigner(alg)
			if err != nil {
				return nil, pkicrypto.StorageRef{}, err
			}
			return kemSigner, pkicrypto.StorageRef{
				Type: "software",
			}, nil
		}

		signer, err := pkicrypto.GenerateSoftwareSigner(alg)
		if err != nil {
			return nil, pkicrypto.StorageRef{}, err
		}
		// Return empty storage ref - FileStore.Save() will fill in the path
		return signer, pkicrypto.StorageRef{
			Type: "software",
		}, nil
	}
}
