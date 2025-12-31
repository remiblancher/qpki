# HSM Configuration Examples

Example configuration files for using QPKI with various Hardware Security Modules (HSMs) via PKCS#11.

## Available Configurations

| File | HSM | Use Case |
|------|-----|----------|
| `softhsm2.yaml` | SoftHSM2 | Development, CI/CD testing |
| `thales-luna.yaml` | Thales Luna Network HSM | Enterprise, high-security |
| `eviden-trustway.yaml` | Eviden Trustway Proteccio | ANSSI certified, French gov |
| `utimaco.yaml` | Utimaco SecurityServer | Enterprise |
| `aws-cloudhsm.yaml` | AWS CloudHSM | Cloud-native |
| `yubihsm2.yaml` | YubiHSM 2 | Small deployments, dev |

## Quick Start

### 1. Copy and customize the configuration

```bash
cp examples/hsm/softhsm2.yaml ./hsm.yaml
# Edit lib path and token name as needed
```

### 2. Set the PIN via environment variable

```bash
export HSM_PIN="your-pin-here"
```

### 3. Test connectivity

```bash
# Discover available tokens
qpki hsm list --lib /usr/lib/softhsm/libsofthsm2.so

# Validate configuration
qpki hsm test --hsm-config ./hsm.yaml
```

### 4. Generate a key in the HSM

```bash
qpki key gen --algorithm ecdsa-p384 \
  --hsm-config ./hsm.yaml \
  --key-label "root-ca-key"
```

### 5. Initialize a CA with the HSM key

```bash
qpki ca init --hsm-config ./hsm.yaml \
  --key-label "root-ca-key" \
  --profile ec/root-ca \
  --name "My HSM Root CA" \
  --dir ./hsm-ca
```

## Configuration Structure

```yaml
type: pkcs11

pkcs11:
  lib: /path/to/pkcs11/library.so  # PKCS#11 library path
  token: "Token-Label"              # Token label (from hsm list)
  pin_env: HSM_PIN                  # Environment variable for PIN

session:
  logout_after_use: true            # Logout after each operation

security:
  verify_key_cert_binding: true     # Verify key matches certificate
```

## PIN Security

| Method | Allowed | Notes |
|--------|---------|-------|
| Environment variable | Yes | `pin_env: HSM_PIN` |
| Interactive prompt | Yes | When terminal attached |
| YAML file | **Never** | Security risk |
| CLI argument | **Never** | Visible in process list |

## Supported Algorithms

HSM mode only supports classical algorithms:

- **ECDSA**: `ecdsa-p256`, `ecdsa-p384`, `ecdsa-p521`
- **RSA**: `rsa-2048`, `rsa-3072`, `rsa-4096`

Post-quantum algorithms (ML-DSA, SLH-DSA) require software mode.

## Development with SoftHSM2

### Installation

```bash
# Debian/Ubuntu
sudo apt-get install softhsm2

# macOS
brew install softhsm

# RHEL/CentOS
sudo yum install softhsm
```

### Initialize a token

```bash
softhsm2-util --init-token --slot 0 \
  --label "QPKI-Dev" \
  --pin 1234 \
  --so-pin 12345678
```

### Find the library path

```bash
# Linux
find /usr -name "libsofthsm2.so" 2>/dev/null

# macOS
find /opt/homebrew -name "libsofthsm2.so" 2>/dev/null
```

## Troubleshooting

### "Token not found"

1. Verify the token label matches exactly (case-sensitive)
2. Check with `qpki hsm list --lib <path>`

### "Failed to load PKCS#11 module"

1. Verify the library path exists
2. Check library architecture (32-bit vs 64-bit)
3. Ensure HSM client software is installed

### "Login failed"

1. Verify PIN is set in environment variable
2. Check PIN format (some HSMs require "user:password" format)
3. Ensure the user/partition has appropriate permissions
