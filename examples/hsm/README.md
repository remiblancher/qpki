# HSM Configuration Examples

Example configuration files for using QPKI with Hardware Security Modules via PKCS#11.

See [HSM Integration Guide](../../docs/HSM.md) for complete documentation.

## Available Configurations

| File | HSM | Use Case |
|------|-----|----------|
| `softhsm2.yaml` | SoftHSM2 | Development, CI/CD testing |
| `thales-luna.yaml` | Thales Luna Network HSM | Enterprise, high-security |
| `eviden-trustway.yaml` | Eviden Trustway Proteccio | ANSSI certified |
| `utimaco.yaml` | Utimaco SecurityServer | Enterprise |
| `aws-cloudhsm.yaml` | AWS CloudHSM | Cloud-native |
| `yubihsm2.yaml` | YubiHSM 2 | Small deployments, dev |

## Quick Start

```bash
# Copy and customize
cp examples/hsm/softhsm2.yaml ./hsm.yaml

# Set PIN
export HSM_PIN="your-pin"

# Use with QPKI
qpki ca init --hsm-config ./hsm.yaml --key-label "my-key" ...
```
