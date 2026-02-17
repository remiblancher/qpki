//go:build cgo

package crypto

// Utimaco QuantumProtect PKCS#11 constants for PQC algorithms.
// These are vendor-specific extensions to the PKCS#11 standard.
// Reference: vendor/utimaco-sim/Crypto_APIs/PKCS11_R3/samples/qptool2/include/qptool2.h

const (
	// Mechanism domain identifiers
	utiMechMLVDM = (0xC << 28) | (0xA5 << 16) // 0xCA500000

	// Mechanism operation types
	utiMechVDMGen    = 0x0
	utiMechVDMSign   = (0x3 << 12) // 0x3000
	utiMechVDMVerify = (0x4 << 12) // 0x4000
	utiMechVDMDerive = (0x9 << 12) // 0x9000
	utiMechVDMWrap   = (0x5 << 12) // 0x5000
	utiMechVDMUnwrap = (0x6 << 12) // 0x6000
	utiMechVDMDigest = (0xD << 12) // 0xD000

	// ML-DSA (FIPS 204) mechanisms
	CKM_UTI_MLDSA_GENKEY      = utiMechMLVDM | utiMechVDMGen | 1      // 0xCA500001
	CKM_UTI_MLDSA_SIGN        = utiMechMLVDM | utiMechVDMSign | 1     // 0xCA503001
	CKM_UTI_MLDSA_EXTMU_SIGN  = utiMechMLVDM | utiMechVDMSign | 5     // 0xCA503005
	CKM_UTI_MLDSA_VERIFY      = utiMechMLVDM | utiMechVDMVerify | 1   // 0xCA504001
	CKM_UTI_MLDSA_EXTMU_VERIFY = utiMechMLVDM | utiMechVDMVerify | 5  // 0xCA504005
	CKM_UTI_MLDSA_SHAKE256    = utiMechMLVDM | utiMechVDMDigest | 1   // 0xCA50D001

	// ML-KEM (FIPS 203) mechanisms
	CKM_UTI_MLKEM_GENKEY = utiMechMLVDM | utiMechVDMGen | 2    // 0xCA500002
	CKM_UTI_MLKEM_ENCAP  = utiMechMLVDM | utiMechVDMDerive | 1 // 0xCA509001
	CKM_UTI_MLKEM_DECAP  = utiMechMLVDM | utiMechVDMDerive | 2 // 0xCA509002

	// Key types
	CKK_UTI_MLDSA = CKM_UTI_MLDSA_GENKEY // 0xCA500001
	CKK_UTI_MLKEM = CKM_UTI_MLKEM_GENKEY // 0xCA500002

	// Custom attributes
	CKA_UTI_CUSTOM_DATA = 0x80D00001 // Public attribute containing key data

	// ML-DSA parameter types (passed in mechanism parameter)
	// Internal values: 1=ML-DSA-44, 2=ML-DSA-65, 3=ML-DSA-87
	// (CLI uses 2/3/5 which get converted, but we use internal values directly)
	MLDSA_44 = 1 // ML-DSA-44 (NIST Level 1)
	MLDSA_65 = 2 // ML-DSA-65 (NIST Level 3)
	MLDSA_87 = 3 // ML-DSA-87 (NIST Level 5)

	// ML-KEM parameter types (internal mechanism values)
	// qptool2 CLI uses [2|3|5] but converts internally to [1|2|3]
	// See: test_case_mlkem.c lines 543-547
	MLKEM_512  = 1 // ML-KEM-512 (internal type 1)
	MLKEM_768  = 2 // ML-KEM-768 (internal type 2)
	MLKEM_1024 = 3 // ML-KEM-1024 (internal type 3)
)

// MLDSAKeyType returns the Utimaco mechanism parameter for an ML-DSA algorithm.
func MLDSAKeyType(alg AlgorithmID) (uint32, bool) {
	switch alg {
	case "ml-dsa-44":
		return MLDSA_44, true
	case "ml-dsa-65":
		return MLDSA_65, true
	case "ml-dsa-87":
		return MLDSA_87, true
	default:
		return 0, false
	}
}

// MLKEMKeyType returns the Utimaco mechanism parameter for an ML-KEM algorithm.
func MLKEMKeyType(alg AlgorithmID) (uint32, bool) {
	switch alg {
	case "ml-kem-512":
		return MLKEM_512, true
	case "ml-kem-768":
		return MLKEM_768, true
	case "ml-kem-1024":
		return MLKEM_1024, true
	default:
		return 0, false
	}
}
