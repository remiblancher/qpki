# HSM Integration

QPKI supports Hardware Security Modules (HSMs) via PKCS#11 to protect CA private keys and perform signing operations without key extraction.

## Architecture

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

## Configuration

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

# By ID (hex)
qpki ca init --hsm-config ./hsm.yaml --key-id "0102030405" ...

# Both (double verification)
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

## Usage

### Initialize a CA with HSM Key

```bash
# Set PIN via environment
export HSM_PIN="****"

# Initialize CA using existing HSM key
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

# Generate CRL
qpki crl gen --ca-dir ./hsm-ca
```

### Enroll Credentials with HSM Keys

You can generate end-entity keys directly in the HSM during credential enrollment:

```bash
export HSM_PIN="****"

# Enroll credential with key generated in HSM
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
# List available slots and tokens (discovery, no config needed)
qpki hsm list --lib /usr/lib/softhsm/libsofthsm2.so

# Test HSM connectivity and authentication
qpki hsm test --hsm-config ./hsm.yaml
```

### Key Operations (unified file/HSM)

Key operations use `qpki key` commands with `--hsm-config` for HSM mode:

```bash
# List keys in token (requires PIN)
export HSM_PIN="****"
qpki key list --hsm-config ./hsm.yaml

# Generate EC P-384 key in HSM (recommended for CA)
qpki key gen --algorithm ecdsa-p384 \
  --hsm-config ./hsm.yaml \
  --key-label "root-ca-key"

# Generate RSA-4096 key in HSM
qpki key gen --algorithm rsa-4096 \
  --hsm-config ./hsm.yaml \
  --key-label "rsa-ca-key"

# Generate with specific key ID
qpki key gen --algorithm ecdsa-p384 \
  --hsm-config ./hsm.yaml \
  --key-label "my-key" \
  --key-id 0102030405
```

Supported algorithms for HSM key generation:
- `ecdsa-p256`, `ecdsa-p384`, `ecdsa-p521` (EC keys)
- `rsa-2048`, `rsa-3072`, `rsa-4096` (RSA keys)

Note: PQC algorithms (ml-dsa-*, slh-dsa-*) are only available in file mode.

### Initialize CA with New HSM Key

You can generate a key and create a CA in one step using `--generate-key`:

```bash
export HSM_PIN="****"
qpki ca init --hsm-config ./hsm.yaml \
  --key-label "root-ca-key" \
  --generate-key \
  --profile ec/root-ca \
  --var cn="HSM Root CA" \
  --dir ./hsm-ca
```

This generates the key in the HSM and immediately uses it for CA initialization.

## Mode Selection: HSM vs Software

QPKI enforces a clear separation between HSM and software modes:

| Mode | Configuration | Supported Profiles |
|------|---------------|-------------------|
| **HSM** | `--hsm-config` provided | Classical only (ec/*, rsa/*) |
| **Software** | No `--hsm-config` | All profiles (ec/*, rsa/*, ml/*, slh/*, hybrid/*) |

HSM mode does not support PQC or hybrid profiles because current HSMs do not support post-quantum algorithms.

## CA Metadata (`ca.meta.json`)

When a CA is initialized, QPKI creates a `ca.meta.json` file that stores key references and configuration. This file is used to reload the CA signer for subsequent operations.

**Example: Software CA**
```json
{
    "profile": "ec/root-ca",
    "created": "2025-01-02T10:30:00Z",
    "keys": [
        {
            "id": "default",
            "algorithm": "ecdsa-p384",
            "storage": {
                "type": "software",
                "path": "private/ca.ecdsa-p384.key"
            }
        }
    ]
}
```

**Example: HSM CA**
```json
{
    "profile": "ec/root-ca",
    "created": "2025-01-02T10:30:00Z",
    "keys": [
        {
            "id": "default",
            "algorithm": "ecdsa-p384",
            "storage": {
                "type": "pkcs11",
                "config": "./hsm.yaml",
                "label": "root-ca-key"
            }
        }
    ]
}
```

**Example: Hybrid CA (classical HSM + PQC software)**
```json
{
    "profile": "hybrid/catalyst/root-ca",
    "created": "2025-01-02T10:30:00Z",
    "keys": [
        {
            "id": "classical",
            "algorithm": "ecdsa-p384",
            "storage": {
                "type": "pkcs11",
                "config": "./hsm.yaml",
                "label": "ca-root-classical"
            }
        },
        {
            "id": "pqc",
            "algorithm": "ml-dsa-65",
            "storage": {
                "type": "software",
                "path": "private/ca.ml-dsa-65.key"
            }
        }
    ]
}
```

## Supported HSMs

QPKI uses PKCS#11 for HSM integration. The table below shows compatibility, validation status, and vendor PQC capabilities.

| HSM | Interface | PQC (Vendor) | Status | Notes |
|-----|-----------|--------------|--------|-------|
| SoftHSM2 | PKCS#11 | ❌ | ✅ Validated | Tested in CI (ECDSA-P384, RSA-4096) |
| YubiHSM2 | PKCS#11 | ❌ | 📋 Example | ~$650, accessible for small deployments |
| Thales Luna 7.9+ | PKCS#11 | ✅ | 🎯 Candidate | ML-DSA, ML-KEM in firmware v7.9+ |
| Entrust nShield | PKCS#11 | ✅ | 🎯 Candidate | ML-DSA, ML-KEM, SLH-DSA (CAVP) |
| Securosys Primus | PKCS#11 | ✅ | 🎯 Candidate | ML-DSA, ML-KEM, hybrid operations |
| Eviden Proteccio | PKCS#11 | 🔜 | 📋 Example | ANSSI certified, PQC roadmap |
| Utimaco | PKCS#11 | 🔜 | 📋 Example | Quantum Protect product available |
| AWS CloudHSM | PKCS#11 | ❌ | 📋 Example | Cloud-native (PQC via KMS only) |
| Azure Key Vault | REST only | ❌ | ❌ N/A | Not compatible (no PKCS#11) |

**Legend:**
- ✅ Validated: Tested in CI/CD with QPKI
- 🎯 Candidate: Vendor advertises PQC support; QPKI integration not yet validated
- 📋 Example: Configuration file provided, not tested by QPKI team
- 🔜 Roadmap: Vendor has announced PQC but not yet available via PKCS#11
- ❌ N/A: Not compatible with QPKI

**Note:** PQC (Vendor) refers to vendor-provided HSM capabilities. Actual availability depends on firmware versions and licensing. Validated means tested with QPKI in the specified scope; it does not imply vendor certification or production endorsement.

### Development with SoftHSM2

> ⚠️ **Warning:** SoftHSM2 is a software emulator and does not provide the security guarantees of a certified hardware HSM. Do not use in production.

```bash
# Initialize a token
softhsm2-util --init-token --slot 0 --label "CA-Token" --pin 1234 --so-pin 12345678

# Generate a key in the token
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --token-label "CA-Token" --login --pin 1234 \
  --keypairgen --key-type EC:secp384r1 \
  --label "root-ca-key" --id 01
```

## Security Best Practices

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

## Example Configurations

See `examples/hsm/` for vendor-specific configurations:

- `softhsm2.yaml` - Development/CI
- `thales-luna.yaml` - Thales Luna Network HSM
- `eviden-proteccio.yaml` - Eviden Proteccio
- `utimaco.yaml` - Utimaco SecurityServer
- `aws-cloudhsm.yaml` - AWS CloudHSM
- `yubihsm2.yaml` - YubiHSM2

## See Also

- [GUIDE.md](GUIDE.md) - CLI reference and common workflows
- [ARCHITECTURE.md](ARCHITECTURE.md) - System architecture
- [PROFILES.md](PROFILES.md) - Certificate profile templates
