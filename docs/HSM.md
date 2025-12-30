# HSM Integration

QPKI supports Hardware Security Modules (HSMs) via PKCS#11 to protect CA private keys and perform signing operations without key extraction.

> **Status**: HSM support is currently under development. The PKCS#11 integration is designed but not yet fully implemented.

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

## Usage

### Initialize a CA using an HSM-backed private key

```bash
qpki ca init --profile ec/root-ca \
  --pkcs11-lib /usr/lib/softhsm/libsofthsm2.so \
  --pkcs11-token "CA Token" \
  --pkcs11-pin "****" \
  --pkcs11-key-label "ca-key" \
  --var cn="My Root CA" \
  --dir ./hsm-ca
```

### Issue Certificates

```bash
# Using credential enroll (signing happens in HSM)
qpki credential enroll --ca-dir ./hsm-ca \
  --profile ec/tls-server \
  --var cn=server.example.com \
  --pkcs11-pin "****"

# Using CSR workflow
qpki cert issue --ca-dir ./hsm-ca \
  --profile ec/tls-server \
  --csr server.csr \
  --out server.crt \
  --pkcs11-pin "****"
```

## Supported HSMs

The following table shows HSM compatibility and QPKI integration status.

> ⚠️ **Note**: QPKI HSM integration is under development. No HSM has been validated yet.

### Production HSMs

| Vendor | Model | Notes |
|--------|-------|-------|
| Eviden | Trustway Proteccio | ANSSI QR certified |
| Thales | Luna Network HSM | FIPS 140-3 Level 3 |
| Utimaco | SecurityServer | |
| AWS | CloudHSM | Cloud-native |

### Development

SoftHSM2 can be used for development and testing:

```bash
softhsm2-util --init-token --slot 0 --label "CA Token" --pin 1234 --so-pin 1234
```

> ⚠️ **Warning**: SoftHSM2 is not a certified HSM and must not be used in production.

## Post-Quantum and HSM

Support for post-quantum algorithms in HSMs is currently limited. QPKI supports hybrid deployments combining HSM-protected classical keys and software-based PQC keys:

```
Classical key (ECDSA/RSA)  →  HSM (hardware protection)
PQC key (ML-DSA)           →  Software (file-based)
```

This provides:
- Hardware protection for the classical key
- Post-quantum security via the software PQC key

This hybrid model reflects the current state of the HSM ecosystem and provides the strongest practical security available today.

## Security Best Practices

### PIN Management

- Use strong PINs (12+ characters)
- Never store PINs in configuration files
- Use environment variables or secure vaults
- Rotate PINs periodically

### Session Management

QPKI never caches HSM PINs or sessions beyond the lifetime of a command.

### Key Ceremony (Root CA)

1. Generate key in offline HSM
2. Create self-signed certificate
3. Export certificate (public only)
4. Store HSM in secure location
5. Document all steps with witnesses

### Network HSMs

- Use dedicated network segment
- Enable mutual TLS
- Restrict access by IP
- Monitor for unauthorized access

## Roadmap

### Phase 1: Basic Support
- [ ] Load existing keys from PKCS#11
- [ ] Sign certificates using HSM
- [ ] Support ECDSA and RSA

### Phase 2: Key Generation
- [ ] Generate keys inside HSM
- [ ] Key backup/restore

### Phase 3: Advanced Features
- [ ] Multi-slot support
- [ ] Session pooling

### Phase 4: PQC Support
- [ ] ML-DSA support (when HSMs support it)
- [ ] Hybrid key management
