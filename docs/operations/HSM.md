---
title: "HSM Integration"
description: "QPKI supports Hardware Security Modules (HSMs) via PKCS#11 to protect CA private keys and perform signing operations without key extraction."
---

# HSM Integration

QPKI supports Hardware Security Modules (HSMs) via PKCS#11 to protect CA private keys and perform signing operations without key extraction.

> **TL;DR** : Un HSM est un coffre-fort matériel pour vos clés privées.
> Utilisez-le en production pour protéger les clés de votre CA.
> En développement, les clés logicielles suffisent.

### Dois-je utiliser un HSM ?

| Environnement | Recommandation |
|---------------|----------------|
| Développement/Test | Non - clés logicielles OK |
| Production interne | Recommandé pour CA racine |
| Production publique | Obligatoire (conformité) |

---

## 1. What is an HSM?

A **Hardware Security Module (HSM)** is a dedicated cryptographic device that protects private keys. Keys stored in an HSM never leave the device - all signing operations happen inside the hardware.

### Why Use an HSM?

| Aspect | Software Keys | HSM Keys |
|--------|--------------|----------|
| Key extraction | Possible | Impossible |
| Tamper resistance | None | Physical protection |
| Compliance | Limited | FIPS 140-2/3, Common Criteria |
| Performance | CPU-bound | Hardware acceleration |

QPKI integrates with HSMs via **PKCS#11**, the standard cryptographic token interface.

---

## 2. Architecture

```
┌─────────────────────────────────────────────────┐
│                    QPKI                         │
│                                                 │
│         ┌───────────────────────────┐           │
│         │      Signer Interface     │           │
│         └─────────────┬─────────────┘           │
│                       │                         │
│         ┌─────────────┴─────────────┐           │
│         │                           │           │
│  ┌──────┴──────┐          ┌────────┴────────┐  │
│  │  Software   │          │    PKCS#11      │  │
│  │  (file)     │          │    (HSM)        │  │
│  └─────────────┘          └────────┬────────┘  │
│                                    │           │
└────────────────────────────────────┼───────────┘
                                     │
                        ┌────────────┴────────────┐
                        │     PKCS#11 Library     │
                        └────────────┬────────────┘
                                     │
                        ┌────────────┴────────────┐
                        │          HSM            │
                        └─────────────────────────┘
```

QPKI uses a unified signer interface to abstract software-based and HSM-based signing implementations while enforcing consistent certificate policies.

**Security invariant:** The signing algorithm is selected by QPKI policy and certificate profiles, never inferred from the HSM key type or PKCS#11 mechanism.

---

## 3. Configuration

HSM configuration is done through a YAML file. The file is referenced via `--hsm-config` flag.

### HSM Configuration File

```yaml
# hsm/thales-luna.yaml
type: pkcs11

pkcs11:
  # Path to PKCS#11 library
  lib: /usr/lib/libCryptoki2_64.so

  # Token identification (choose one)
  token: "CA-Token"           # By label (recommended)
  # token_serial: "ABC123"    # By serial number (more precise)
  # slot: 0                   # By slot ID (less portable)

  # PIN via environment variable (never in file)
  pin_env: HSM_PIN
```

### Key Identification

Key label and key ID are passed via CLI, not in the configuration file:

```bash
# By label
qpki ca init --hsm-config ./hsm.yaml --key-label "root-ca-key" ...

qpki ca init --hsm-config ./hsm.yaml --key-id "0102030405" ...

qpki ca init --hsm-config ./hsm.yaml --key-label "root-ca-key" --key-id "0102030405" ...
```

### PIN Management

| Source | Allowed | Example |
|--------|---------|---------|
| Environment variable | Yes | `pin_env: HSM_PIN` |
| Interactive prompt | Yes | When terminal attached |
| YAML file | Never | - |
| CLI argument | Never | - |

> **Note:** Environment variables may be visible to privileged users on the system. Use a secure secret manager when possible.

---

## 4. Usage

### Initialize a CA with HSM Key

```bash
# Set PIN via environment
export HSM_PIN="****"

qpki ca init --hsm-config ./hsm/thales-luna.yaml \
  --key-label "root-ca-key" \
  --profile ec/root-ca \
  --var cn="HSM Root CA" \
  --dir ./hsm-ca
```

### Issue Certificates

After initialization, the HSM reference is stored in `ca.meta.json` in the CA directory. Subsequent operations load the signer automatically:

```bash
# Issue certificate (PIN still required via env)
export HSM_PIN="****"
qpki cert issue --ca-dir ./hsm-ca \
  --profile ec/tls-server \
  --csr server.csr \
  --out server.crt

qpki crl gen --ca-dir ./hsm-ca
```

### Enroll Credentials with HSM Keys

You can generate end-entity keys directly in the HSM during credential enrollment:

```bash
export HSM_PIN="****"

qpki credential enroll --ca-dir ./hsm-ca --cred-dir ./hsm-ca/credentials \
  --profile ec/tls-server \
  --var cn=server.example.com \
  --var dns_names=server.example.com \
  --hsm-config ./hsm.yaml \
  --key-label "server-key"
```

This generates the private key inside the HSM and issues a certificate signed by the CA. The credential metadata (`credential.meta.json`) stores the HSM key reference:

```json
{
    "id": "server-example-com-20250102-a1b2c3",
    "subject": {
        "common_name": "server.example.com"
    },
    "profiles": ["ec/tls-server"],
    "status": "valid",
    "created": "2025-01-02T10:30:00Z",
    "not_before": "2025-01-02T10:30:00Z",
    "not_after": "2026-01-02T10:30:00Z",
    "certificates": [
        {
            "serial": "0x1A2B3C4D",
            "role": "signature",
            "profile": "ec/tls-server",
            "algorithm": "ECDSA-SHA384",
            "fingerprint": "ABC123DEF456",
            "storage": [
                {
                    "type": "pkcs11",
                    "config": "./hsm.yaml",
                    "label": "server-key"
                }
            ]
        }
    ]
}
```

### HSM Diagnostic Commands

```bash
# List available slots and tokens
qpki hsm list --hsm-config ./hsm.yaml

# Test HSM connectivity and authentication
qpki hsm test --hsm-config ./hsm.yaml

# List supported PKCS#11 mechanisms (algorithms)
qpki hsm mechanisms --hsm-config ./hsm.yaml

# Filter mechanisms by name (e.g., check for HKDF support)
qpki hsm mechanisms --hsm-config ./hsm.yaml --filter HKDF

# Search for post-quantum mechanisms
qpki hsm mechanisms --hsm-config ./hsm.yaml --filter ML
```

### Key Operations (unified file/HSM)

Key operations use `qpki key` commands with `--hsm-config` for HSM mode:

```bash
# List keys in token (requires PIN)
export HSM_PIN="****"
qpki key list --hsm-config ./hsm.yaml

qpki key gen --algorithm ecdsa-p384 \
  --hsm-config ./hsm.yaml \
  --key-label "root-ca-key"

qpki key gen --algorithm rsa-4096 \
  --hsm-config ./hsm.yaml \
  --key-label "rsa-ca-key"

qpki key gen --algorithm ecdsa-p384 \
  --hsm-config ./hsm.yaml \
  --key-label "my-key" \
  --key-id 0102030405
```

Supported algorithms for HSM key generation:
- `ecdsa-p256`, `ecdsa-p384`, `ecdsa-p521` (EC keys)
- `rsa-2048`, `rsa-3072`, `rsa-4096` (RSA keys)
- `ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87` (PQC signatures, Utimaco only)
- `ml-kem-512`, `ml-kem-768`, `ml-kem-1024` (PQC key encapsulation, Utimaco only)

Note: PQC algorithms require HSMs with post-quantum support (see Section 10).

### Initialize CA with HSM

By default, the key is generated in the HSM (like software mode):

```bash
export HSM_PIN="****"
qpki ca init --hsm-config ./hsm.yaml \
  --key-label "root-ca-key" \
  --profile ec/root-ca \
  --var cn="HSM Root CA" \
  --ca-dir ./hsm-ca
```

To use an existing key in the HSM, add `--use-existing-key`:

```bash
qpki ca init --hsm-config ./hsm.yaml \
  --key-label "existing-key" \
  --use-existing-key \
  --profile ec/root-ca \
  --var cn="HSM Root CA" \
  --ca-dir ./hsm-ca
```

---

## 5. Mode Selection: HSM vs Software

QPKI enforces a clear separation between HSM and software modes:

| Mode | Configuration | Supported Profiles |
|------|---------------|-------------------|
| **HSM** | `--hsm-config` provided | Classical (ec/*, rsa/*), PQC with compatible HSMs |
| **Software** | No `--hsm-config` | All profiles (ec/*, rsa/*, ml/*, slh/*, hybrid/*) |

PQC profiles (ml-dsa-*, ml-kem-*) require HSMs with post-quantum algorithm support. See Section 10 for compatible HSMs and testing instructions.

---

## 6. CA Metadata (`ca.meta.json`)

When a CA is initialized, QPKI creates a `ca.meta.json` file that stores key references and configuration. This file is used to reload the CA signer for subsequent operations.

**Key storage is per-version**: Each CA version stores its own key references, enabling proper key rotation where new keys are generated for each version.

**Example: Software CA**
```json
{
    "subject": { "common_name": "My Root CA" },
    "active": "v1",
    "versions": {
        "v1": {
            "profiles": ["ec/root-ca"],
            "algos": ["ecdsa-p384"],
            "status": "active",
            "keys": [
                {
                    "id": "default",
                    "algorithm": "ecdsa-p384",
                    "storage": {
                        "type": "software",
                        "path": "versions/v1/keys/ca.ecdsa-p384.key"
                    }
                }
            ]
        }
    }
}
```

**Example: HSM CA**
```json
{
    "subject": { "common_name": "HSM Root CA" },
    "active": "v1",
    "versions": {
        "v1": {
            "profiles": ["ec/root-ca"],
            "algos": ["ecdsa-p384"],
            "status": "active",
            "keys": [
                {
                    "id": "default",
                    "algorithm": "ecdsa-p384",
                    "storage": {
                        "type": "pkcs11",
                        "config": "./hsm.yaml",
                        "label": "root-ca-key",
                        "key_id": "0001"
                    }
                }
            ]
        }
    }
}
```

**Example: Hybrid CA with HSM (after rotation)**
```json
{
    "subject": { "common_name": "Catalyst Root CA" },
    "active": "v2",
    "versions": {
        "v1": {
            "profiles": ["catalyst"],
            "algos": ["ecdsa-p384", "ml-dsa-65"],
            "status": "archived",
            "keys": [
                {
                    "id": "classical",
                    "algorithm": "ecdsa-p384",
                    "storage": {
                        "type": "pkcs11",
                        "config": "./hsm.yaml",
                        "label": "my-ca",
                        "key_id": "0001"
                    }
                },
                {
                    "id": "pqc",
                    "algorithm": "ml-dsa-65",
                    "storage": {
                        "type": "pkcs11",
                        "config": "./hsm.yaml",
                        "label": "my-ca",
                        "key_id": "0002"
                    }
                }
            ]
        },
        "v2": {
            "profiles": ["catalyst"],
            "algos": ["ecdsa-p384", "ml-dsa-87"],
            "status": "active",
            "keys": [
                {
                    "id": "classical",
                    "algorithm": "ecdsa-p384",
                    "storage": {
                        "type": "pkcs11",
                        "config": "./hsm.yaml",
                        "label": "my-ca",
                        "key_id": "0003"
                    }
                },
                {
                    "id": "pqc",
                    "algorithm": "ml-dsa-87",
                    "storage": {
                        "type": "pkcs11",
                        "config": "./hsm.yaml",
                        "label": "my-ca",
                        "key_id": "0004"
                    }
                }
            ]
        }
    }
}
```

**Key identification in HSM:**
- `label`: CKA_LABEL - can be shared across versions
- `key_id`: CKA_ID - distinguishes keys with the same label

The `ca.meta.json` file is the source of truth for which key to load. During rotation, new keys are generated with unique `key_id` values.

---

## 7. Supported HSMs

QPKI uses PKCS#11 for HSM integration.

| HSM | Status | PQC | Notes | Source |
|-----|--------|-----|-------|--------|
| SoftHSM2 | 🟢 Tested | – | RSA, ECC (CI/CD) | – |
| YubiHSM2 | 🟡 Untested | – | Compact form factor | – |
| Thales Luna 7.9+ | 🟡 Untested | ML-DSA, ML-KEM | | [Thales](https://thalesdocs.com/gphsm/luna/7/docs/network/Content/sdk/extensions/pqc/post_quantum_algorithms.htm) |
| Entrust nShield | 🟡 Untested | ML-DSA, ML-KEM, SLH-DSA | CAVP certified | [Entrust](https://www.entrust.com/blog/2025/09/entrust-nshield-5-hsms-post-quantum-algorithm-support-now-cavp-certified) |
| Securosys Primus | 🟡 Untested | ML-DSA, ML-KEM, SLH-DSA | NIST certified | [Securosys](https://www.securosys.com/en/hsm/post-quantum-cryptography) |
| Eviden Proteccio | 🟡 Untested | ML-DSA, ML-KEM, SLH-DSA | ANSSI QR certified | [Eviden](https://eviden.com/insights/press-releases/eviden-supports-post-quantum-algorithms-with-its-trustway-proteccio-hsm/) |
| Utimaco | 🟡 Untested | ML-DSA, ML-KEM, LMS | CAVP certified | [Utimaco](https://utimaco.com/data-protection/gp-hsm/application-package/quantum-protect) |
| AWS CloudHSM | 🟡 Untested | – | PQC via KMS only | [AWS](https://aws.amazon.com/security/post-quantum-cryptography/) |
| Azure Key Vault | 🔴 N/A | – | No PKCS#11 | – |

**Legend:** 🟢 Tested · 🟡 Untested · 🔴 Not compatible

> PQC column shows vendor capabilities, not QPKI integration.

### Development with SoftHSM2

> ⚠️ **Warning:** SoftHSM2 is a software emulator and does not provide the security guarantees of a certified hardware HSM. Do not use in production.

```bash
# Initialize a token
softhsm2-util --init-token --slot 0 --label "CA-Token" --pin 1234 --so-pin 12345678

pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --token-label "CA-Token" --login --pin 1234 \
  --keypairgen --key-type EC:secp384r1 \
  --label "root-ca-key" --id 01
```

---

## 8. Security Best Practices

### PIN Management

- Use strong PINs (12+ characters)
- Never store PINs in configuration files
- Use environment variables or secure vaults
- Rotate PINs periodically

### Session Management

QPKI automatically logs out after each operation when `logout_after_use: true` is configured.

### Key Ceremony (Root CA)

1. Generate key in offline HSM
2. Create self-signed certificate using QPKI
3. Export certificate (public only)
4. Store HSM in secure location
5. Document all steps with witnesses

### Network HSMs

- Use dedicated network segment
- Enable mutual TLS
- Restrict access by IP
- Monitor for unauthorized access

---

## 9. Example Configurations

See `examples/hsm/` for vendor-specific configurations:

- `softhsm2.yaml` - Development/CI
- `thales-luna.yaml` - Thales Luna Network HSM
- `eviden-proteccio.yaml` - Eviden Proteccio
- `utimaco.yaml` - Utimaco SecurityServer
- `aws-cloudhsm.yaml` - AWS CloudHSM
- `yubihsm2.yaml` - YubiHSM2

## 10. Post-Quantum HSM Testing

Some HSMs now support post-quantum cryptographic algorithms. QPKI supports PQC operations via PKCS#11 with compatible HSMs.

### Supported PQC HSMs

| HSM | ML-DSA | ML-KEM | SLH-DSA | Notes |
|-----|--------|--------|---------|-------|
| Utimaco QuantumProtect | ✓ | ✓ | – | Simulator available for testing |
| Thales Luna 7.9+ | ✓ | ✓ | – | Production HSM |
| Entrust nShield | ✓ | ✓ | ✓ | CAVP certified |
| Securosys Primus | ✓ | ✓ | ✓ | NIST certified |
| Eviden Proteccio | ✓ | ✓ | ✓ | ANSSI QR certified |

### Utimaco QuantumProtect Simulator

Utimaco provides a simulator for development and testing of PQC algorithms. The simulator is Linux-only but can run on macOS via Docker.

#### Prerequisites

1. **QuantumProtect Simulator** (runs in Docker):
   - Download QuantumProtect-1.5.0.0-Evaluation from [Utimaco Support Portal](https://support.utimaco.com/)
   - Extract to `vendor/utimaco-sim/` (excluded from git via `.gitignore`)

2. **PKCS#11 Client Library** (required to connect to the simulator):
   - Download "SecurityServer SDK" separately from the [Utimaco Support Portal](https://support.utimaco.com/)
   - This SDK is **not included** in the QuantumProtect evaluation package
   - Install the library:
     - Linux: `/opt/utimaco/p11/libcs_pkcs11_R3.so`
     - macOS: Contact Utimaco for macOS client, or run tests from inside a Linux Docker container
     - Windows: `C:\Program Files\Utimaco\CryptoServer\Lib\cs_pkcs11_R3.dll`

#### Running with Docker (macOS/Windows)

```bash
# Build the Docker image
cd docker/utimaco-sim
docker build -t utimaco-sim .

# Start the simulator
docker run -d -p 3001:3001 --name utimaco-sim utimaco-sim

# Stop the simulator
docker stop utimaco-sim && docker rm utimaco-sim
```

#### Configuration

Create or use the provided configuration file:

```yaml
# examples/hsm/utimaco-simulator.yaml
type: pkcs11

pkcs11:
  lib: /opt/utimaco/p11/libcs_pkcs11_R3.so
  slot: 0
  pin_env: HSM_PIN
```

Pre-configured simulator credentials:
- **SO PIN:** 12345677
- **User PIN:** 12345688
- **Slot:** 0

#### Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `CS_PKCS11_R3_CFG` | Utimaco PKCS#11 config file | `/path/to/cs_pkcs11_R3.cfg` |
| `HSM_CONFIG` | QPKI HSM configuration | `examples/hsm/utimaco-simulator.yaml` |
| `HSM_PIN` | User PIN | `12345688` |
| `HSM_PQC_ENABLED` | Enable PQC tests | `1` |

#### Running PQC Tests Locally

```bash
# 1. Start the Utimaco simulator (Docker)
docker start utimaco-sim

# 2. Configure environment
export CS_PKCS11_R3_CFG=/path/to/cs_pkcs11_R3.cfg
export HSM_CONFIG=examples/hsm/utimaco-simulator.yaml
export HSM_PIN=12345688
export HSM_PQC_ENABLED=1

# 3. Run PQC acceptance tests
make test-acceptance-hsm-pqc
```

#### PQC Key Generation

```bash
export HSM_PIN="12345688"

# Generate ML-DSA-65 key
qpki key gen --algorithm ml-dsa-65 \
  --hsm-config examples/hsm/utimaco-simulator.yaml \
  --key-label "test-mldsa-key"

# Generate ML-KEM-768 key
qpki key gen --algorithm ml-kem-768 \
  --hsm-config examples/hsm/utimaco-simulator.yaml \
  --key-label "test-mlkem-key"
```

#### Creating a PQC CA with HSM

```bash
export HSM_PIN="12345688"

qpki ca init --hsm-config examples/hsm/utimaco-simulator.yaml \
  --key-label "pqc-root-ca-key" \
  --profile ml/root-ca \
  --var cn="PQC Root CA" \
  --ca-dir ./pqc-hsm-ca
```

### CI/CD Strategy

QPKI uses a two-tier testing strategy for HSM tests:

| Environment | HSM | Algorithms | Tests |
|-------------|-----|------------|-------|
| **CI (GitHub Actions)** | SoftHSM2 | EC, RSA | `make test-acceptance-hsm` |
| **Local Development** | Utimaco Simulator | EC, RSA, ML-DSA, ML-KEM | `make test-acceptance-hsm-pqc` |

PQC tests are automatically skipped in CI when `HSM_PQC_ENABLED` is not set. This is because:

1. The Utimaco simulator is proprietary and cannot be included in the CI environment
2. SoftHSM2 does not support post-quantum algorithms
3. PQC HSM testing requires vendor-specific PKCS#11 mechanisms

To run PQC tests locally, ensure the Utimaco simulator is running and `HSM_PQC_ENABLED=1` is set.

---

## 11. Hybrid and Composite CAs with HSM

QPKI supports initializing hybrid (Catalyst) and composite CAs with HSM-stored keys for post-quantum readiness.

### 11.1 Catalyst CA with HSM

Catalyst CAs use two independent keys (classical + PQC) with the same label but different `CKA_KEY_TYPE`. This requires an HSM with PQC algorithm support.

```bash
# Set environment
export HSM_PIN="****"
export HSM_PQC_ENABLED=1  # Required for PQC HSM operations

# Initialize Catalyst CA with HSM keys
qpki ca init --hsm-config examples/hsm/utimaco-simulator.yaml \
  --key-label "catalyst-root" \
  --profile hybrid/catalyst/root-ca \
  --var cn="Catalyst Root CA" \
  --ca-dir ./catalyst-hsm-ca
```

**How it works:**
- QPKI generates two keys in the HSM with the same label but different types:
  - One EC key (e.g., P-384) for classical signatures
  - One ML-DSA key for PQC signatures
- Keys are distinguished by `CKA_KEY_TYPE` attribute
- The `PKCS11HybridSigner` automatically selects the correct key for each signature

### 11.2 Composite CA with HSM

Composite CAs use IETF draft combined signatures where both algorithms sign atomically.

```bash
export HSM_PIN="****"
export HSM_PQC_ENABLED=1

qpki ca init --hsm-config examples/hsm/utimaco-simulator.yaml \
  --key-label "composite-root" \
  --profile hybrid/composite/root-ca \
  --var cn="Composite Root CA" \
  --ca-dir ./composite-hsm-ca
```

### 11.3 HSM Rotation for Hybrid CAs

When rotating a hybrid CA with HSM keys, new keys are generated with unique `key_id` values:

```bash
export HSM_PIN="****"

# Rotate Catalyst CA (generates new keys in HSM)
qpki ca rotate --ca-dir ./catalyst-hsm-ca \
  --profile hybrid/catalyst/root-ca

# Verify rotation created new key versions
qpki ca versions --ca-dir ./catalyst-hsm-ca
```

Each version stores its own key references in `ca.meta.json` (see Section 6 for structure).

---

## See Also

- [CA](../core-pki/CA.md) - CA operations and certificate issuance
- [Keys](../core-pki/KEYS.md) - Key generation and management
- [Credentials](../end-entities/CREDENTIALS.md) - Credential lifecycle management
- [Profiles](../core-pki/PROFILES.md) - Certificate profile templates
