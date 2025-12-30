# HSM Integration

QPKI supports Hardware Security Modules (HSMs) via PKCS#11 to protect CA private keys. All signing operations are delegated to the HSM—private keys never leave the hardware.

> **Status**: HSM support is under development. The PKCS#11 integration is designed but not yet implemented.

## Architecture

```
┌─────────────────────────────────────────────────┐
│                    QPKI                         │
│                                                 │
│  ┌──────────────┐          ┌──────────────┐    │
│  │   Software   │          │   PKCS#11    │    │
│  │   (file)     │          │   (HSM)      │    │
│  └──────────────┘          └──────┬───────┘    │
│                                   │            │
└───────────────────────────────────┼────────────┘
                                    │
                       ┌────────────┴────────────┐
                       │          HSM            │
                       └─────────────────────────┘
```

## Usage

```bash
# Initialize CA with HSM
qpki ca init --profile ec/root-ca \
  --pkcs11-lib /usr/lib/softhsm/libsofthsm2.so \
  --pkcs11-token "CA Token" \
  --pkcs11-pin "****" \
  --pkcs11-key-label "ca-key" \
  --var cn="My Root CA" \
  --dir ./hsm-ca

# Issue certificate (signing in HSM)
qpki credential enroll --ca-dir ./hsm-ca \
  --profile ec/tls-server \
  --var cn=server.example.com \
  --pkcs11-pin "****"
```

## Supported HSMs

> ⚠️ No HSM has been validated yet.

### Production

| Vendor | Model | Notes |
|--------|-------|-------|
| Eviden | Trustway Proteccio | ANSSI QR certified |
| Thales | Luna Network HSM | FIPS 140-3 Level 3 |
| Utimaco | SecurityServer | |
| AWS | CloudHSM | Cloud-native |

### Development

```bash
softhsm2-util --init-token --slot 0 --label "CA Token" --pin 1234 --so-pin 1234
```

> ⚠️ SoftHSM2 must not be used in production.

## Post-Quantum and HSM

PQC support in HSMs is limited. QPKI supports hybrid deployments:

```
Classical key (ECDSA)  →  HSM (hardware)
PQC key (ML-DSA)       →  Software (file)
```

## Security

- Use strong PINs (12+ characters)
- Never store PINs in config files
- QPKI never caches PINs beyond command lifetime

## Roadmap

- [ ] Load keys from PKCS#11
- [ ] Sign certificates using HSM
- [ ] Generate keys inside HSM
- [ ] ML-DSA support (when HSMs support it)
