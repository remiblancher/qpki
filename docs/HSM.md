# HSM Integration

This document covers Hardware Security Module (HSM) integration via PKCS#11.

## 1. Current Status

> **Note**: HSM support is currently **not implemented**. The PKCS#11 interface is defined but returns errors. This document describes the planned implementation.

## 2. PKCS#11 Overview

PKCS#11 (Cryptoki) is the standard API for hardware security modules. It provides:

- Key generation inside the HSM
- Signing operations without key extraction
- Secure key storage
- Access control via PIN/password

## 3. Architecture

### 3.1 Component Design

```
┌─────────────────────────────────────────────────┐
│                    CA Layer                      │
│                                                  │
│  ┌─────────────────────────────────────────┐    │
│  │              Signer Interface            │    │
│  │  • Sign(rand, digest, opts) ([]byte, error) │
│  │  • Public() crypto.PublicKey            │    │
│  │  • Algorithm() AlgorithmID              │    │
│  └──────────────────┬──────────────────────┘    │
│                     │                           │
│         ┌───────────┴───────────┐               │
│         │                       │               │
│  ┌──────┴──────┐        ┌──────┴──────┐        │
│  │ Software    │        │   PKCS#11   │        │
│  │ Signer      │        │   Signer    │        │
│  │             │        │             │        │
│  │ (file-based)│        │ (HSM-based) │        │
│  └─────────────┘        └──────┬──────┘        │
│                                │               │
└────────────────────────────────┼───────────────┘
                                 │
                                 v
                    ┌────────────────────────┐
                    │    PKCS#11 Library     │
                    │  (libsofthsm2.so, etc) │
                    └────────────────────────┘
                                 │
                                 v
                    ┌────────────────────────┐
                    │         HSM            │
                    │  (SoftHSM2, Thales,    │
                    │   Utimaco, etc)        │
                    └────────────────────────┘
```

### 3.2 PKCS#11 Signer Interface

```go
type PKCS11Signer struct {
    module     *pkcs11.Module
    session    pkcs11.SessionHandle
    privateKey pkcs11.ObjectHandle
    publicKey  crypto.PublicKey
    algorithm  AlgorithmID
}

func (s *PKCS11Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
    // Sign using HSM - key never leaves hardware
}

func (s *PKCS11Signer) Public() crypto.PublicKey {
    return s.publicKey
}

func (s *PKCS11Signer) Algorithm() AlgorithmID {
    return s.algorithm
}
```

## 4. Configuration

### 4.1 PKCS#11 Configuration

```go
type PKCS11Config struct {
    ModulePath string // Path to PKCS#11 library
    TokenLabel string // HSM token/slot label
    PIN        string // User PIN
    KeyLabel   string // Key object label
}
```

### 4.2 CLI Flags (Planned)

```bash
pki init-ca --name "HSM CA" \
  --pkcs11-lib /usr/lib/softhsm/libsofthsm2.so \
  --pkcs11-token "CA Token" \
  --pkcs11-pin "1234" \
  --pkcs11-key-label "ca-key" \
  --dir ./hsm-ca
```

## 5. SoftHSM2 Tutorial

SoftHSM2 is a software HSM for development and testing.

### 5.1 Installation

**Ubuntu/Debian:**
```bash
sudo apt-get install softhsm2
```

**macOS:**
```bash
brew install softhsm
```

**Configuration:**
```bash
mkdir -p ~/.softhsm/tokens
echo "directories.tokendir = $HOME/.softhsm/tokens" > ~/.config/softhsm2.conf
export SOFTHSM2_CONF=~/.config/softhsm2.conf
```

### 5.2 Initialize Token

```bash
# Create a new token
softhsm2-util --init-token --slot 0 --label "CA Token" --pin 1234 --so-pin 1234

# Verify token
softhsm2-util --show-slots
```

### 5.3 Generate Key in Token

```bash
# Using pkcs11-tool
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --login --pin 1234 \
  --keypairgen --key-type EC:secp384r1 \
  --label "ca-key"

# List objects
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --login --pin 1234 \
  --list-objects
```

### 5.4 Use with PKI (Planned)

```bash
# Initialize CA using HSM key
pki init-ca --name "HSM Root CA" \
  --pkcs11-lib /usr/lib/softhsm/libsofthsm2.so \
  --pkcs11-token "CA Token" \
  --pkcs11-pin 1234 \
  --pkcs11-key-label "ca-key" \
  --dir ./hsm-ca

# Issue certificate (signing happens in HSM)
pki issue --ca-dir ./hsm-ca \
  --profile tls-server \
  --cn server.example.com \
  --out server.crt --key-out server.key \
  --pkcs11-pin 1234
```

## 6. Production HSM Notes

### 6.1 Supported HSMs (Planned)

**Enterprise HSMs (Production)**

| Vendor | Model | PKCS#11 Library | Notes |
|--------|-------|-----------------|-------|
| Eviden (Atos) | Trustway Proteccio netHSM | libnethsm.so | PQC ready, ANSSI QR certified |
| Thales | Luna Network HSM | libCryptoki2.so | High availability |
| Utimaco | SecurityServer | libcs_pkcs11.so | |
| AWS | CloudHSM | libcloudhsm_pkcs11.so | Cloud-native |

**Development/Small Deployments**

| Vendor | Model | PKCS#11 Library | Notes |
|--------|-------|-----------------|-------|
| N/A | SoftHSM2 | libsofthsm2.so | Software emulation only |

### 6.2 Production Considerations

1. **High Availability**: Use HSM clusters for redundancy
2. **Backup**: Export wrapped keys for disaster recovery
3. **Access Control**: Implement M-of-N PIN sharing
4. **Audit Logging**: Enable HSM audit logs
5. **Network HSM**: Consider network-attached HSMs for scaling

### 6.3 Key Ceremony

For production root CAs:

1. Generate key in offline HSM
2. Create self-signed certificate
3. Export certificate (public only)
4. Store HSM in secure location
5. Document all steps with witnesses

## 7. PQC and HSM

### 7.1 Current Limitations

Most commercial HSMs do not yet support post-quantum algorithms, but support is emerging:

| Vendor | Model | ML-DSA Support | ML-KEM Support |
|--------|-------|----------------|----------------|
| Eviden (Atos) | Trustway Proteccio | Yes (via CryptoNext) | Yes (via CryptoNext) |
| Thales | Luna | Roadmap | Roadmap |
| Utimaco | SecurityServer | Roadmap | Roadmap |
| AWS | CloudHSM | No | No |
| N/A | SoftHSM2 | No | No |

> **Note**: Eviden's Trustway Proteccio netHSM supports post-quantum algorithms in collaboration with CryptoNext Security, aligned with NIST PQC standards.

### 7.2 Hybrid Approach

For hybrid certificates with HSM:

```
CA Private Key (Classical) → HSM (hardware protection)
CA Private Key (PQC) → Software (file-based)
```

The classical signature is performed by the HSM, while the PQC signature is performed in software. This provides:

- Hardware protection for the classical key
- Post-quantum security via the software PQC key
- Best available security given current HSM limitations

## 8. Security Best Practices

### 8.1 PIN Management

- Use strong PINs (12+ characters)
- Never store PINs in configuration files
- Use environment variables or secure vaults
- Rotate PINs periodically

```bash
# Read PIN from environment
export PKCS11_PIN="$(vault kv get -field=pin secret/hsm)"
pki issue --ca-dir ./hsm-ca --pkcs11-pin "$PKCS11_PIN" ...
```

### 8.2 Library Security

- Verify PKCS#11 library integrity
- Use vendor-signed libraries only
- Keep HSM firmware updated

### 8.3 Network Security

For network HSMs:
- Use dedicated network segment
- Enable mutual TLS
- Restrict by IP address
- Monitor for unauthorized access

## 9. Troubleshooting

### 9.1 Common Errors

**"CKR_TOKEN_NOT_PRESENT"**
```
Error: PKCS#11 error: CKR_TOKEN_NOT_PRESENT
```
Solution: Token not initialized or wrong slot. Run `softhsm2-util --show-slots`.

**"CKR_PIN_INCORRECT"**
```
Error: PKCS#11 error: CKR_PIN_INCORRECT
```
Solution: Wrong PIN. Note: 3 wrong attempts may lock the token.

**"CKR_KEY_HANDLE_INVALID"**
```
Error: PKCS#11 error: CKR_KEY_HANDLE_INVALID
```
Solution: Key label not found. Check with `pkcs11-tool --list-objects`.

### 9.2 Debug Mode

```bash
# Enable PKCS#11 debug logging
export SOFTHSM2_DEBUG=1
pki init-ca --pkcs11-lib ... 2>&1 | tee hsm-debug.log
```

## 10. Implementation Roadmap

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
- [ ] Ed25519 support (when HSMs support it)

### Phase 4: PQC Support
- [ ] ML-DSA support (when HSMs support it)
- [ ] Hybrid key management
