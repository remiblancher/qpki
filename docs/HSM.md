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

session:
  logout_after_use: true       # Logout after each operation

security:
  verify_key_cert_binding: true  # Verify key matches certificate
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

## Usage

### Initialize a CA with HSM Key

```bash
# Set PIN via environment
export HSM_PIN="****"

# Initialize CA using existing HSM key
qpki ca init --hsm-config ./hsm/thales-luna.yaml \
  --key-label "root-ca-key" \
  --profile ec/root-ca \
  --name "HSM Root CA" \
  --dir ./hsm-ca
```

### Issue Certificates

After initialization, the HSM reference is stored in the CA directory. Subsequent operations load the signer automatically:

```bash
# Issue certificate (PIN still required via env)
export HSM_PIN="****"
qpki cert issue --ca-dir ./hsm-ca \
  --profile ec/tls-server \
  --csr server.csr \
  --out server.crt

# Generate CRL
qpki ca crl gen --ca-dir ./hsm-ca
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
  --name "HSM Root CA" \
  --dir ./hsm-ca
```

This generates the key in the HSM and immediately uses it for CA initialization.

## Mode Selection: HSM vs Software

QPKI enforces a clear separation between HSM and software modes:

| Mode | Configuration | Supported Profiles |
|------|---------------|-------------------|
| **HSM** | `--hsm-config` provided | Classical only (ec/*, rsa/*) |
| **Software** | No `--hsm-config` | All profiles (ec/*, rsa/*, ml-dsa/*, hybrid/*) |

HSM mode does not support PQC or hybrid profiles because current HSMs do not support post-quantum algorithms.

## Supported HSMs

| HSM | Status | Notes |
|-----|--------|-------|
| SoftHSM2 | Development | For testing only |
| AWS CloudHSM | Compatible | Cloud-native |
| YubiHSM2 | Compatible | USB-based |
| Thales Luna | Standard PKCS#11 | To validate |
| Eviden Trustway | Standard PKCS#11 | ANSSI certified |
| Utimaco | Standard PKCS#11 | To validate |

### Development with SoftHSM2

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
- `eviden-trustway.yaml` - Eviden Trustway Proteccio
- `utimaco.yaml` - Utimaco SecurityServer
- `aws-cloudhsm.yaml` - AWS CloudHSM
- `yubihsm2.yaml` - YubiHSM2

## Roadmap

### Phase 1: Basic Support (Implemented)
- [x] Load existing keys from PKCS#11
- [x] Sign certificates using HSM
- [x] Support ECDSA and RSA
- [x] HSM diagnostic commands (list, test)

### Phase 2: Key Generation (Implemented)
- [x] Generate keys inside HSM (`qpki key gen --hsm-config`)
- [x] List keys in HSM (`qpki key list --hsm-config`)
- [x] Generate key during CA initialization (`--generate-key`)
- [ ] Key backup/restore

### Phase 3: Advanced Features
- [ ] Session pooling for high-throughput
- [ ] Multi-slot support

### Phase 4: PQC Support
- [ ] ML-DSA support (when HSMs support it)
- [ ] Hybrid key management
