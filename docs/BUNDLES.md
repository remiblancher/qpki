# Certificate Bundles

Bundles group related certificates with a **coupled lifecycle** - all certificates in a bundle are created, renewed, and revoked together.

## Overview

A **bundle** is a collection of certificates issued from a [profile](PROFILES.md) for a specific subject. Bundles provide:

- **Atomic operations**: All certificates are issued/renewed/revoked together
- **Unified validity**: All certificates share the same validity period
- **Linked storage**: Single directory with all certificates and keys
- **Metadata tracking**: JSON manifest with status and history

## Bundle Structure

```
bundles/<bundle-id>/
├── bundle.json           # Metadata (status, certificates, validity)
├── certificates.pem      # All certificates (PEM, concatenated)
└── private-keys.pem      # All private keys (PEM, encrypted)
```

### bundle.json Example

```json
{
  "id": "alice-20250115-abc123",
  "subject": {
    "common_name": "Alice",
    "organization": ["Acme Corp"]
  },
  "profiles": ["ec/client", "ml-dsa-kem/client"],
  "status": "valid",
  "created": "2025-01-15T10:30:00Z",
  "not_before": "2025-01-15T10:30:00Z",
  "not_after": "2026-01-15T10:30:00Z",
  "certificates": [
    {
      "serial": "0x01",
      "role": "signature",
      "profile": "ec/client",
      "algorithm": "SHA256WithECDSA",
      "fingerprint": "A1B2C3..."
    },
    {
      "serial": "0x02",
      "role": "signature",
      "profile": "ml-dsa-kem/client",
      "algorithm": "ML-DSA-65",
      "fingerprint": "D4E5F6..."
    }
  ]
}
```

## Certificate Roles

| Role | Description |
|------|-------------|
| `signature` | Standard signature certificate |
| `signature-classical` | Classical signature in hybrid-separate mode |
| `signature-pqc` | PQC signature in hybrid-separate mode |
| `encryption` | Standard encryption certificate |
| `encryption-classical` | Classical encryption in hybrid-separate mode |
| `encryption-pqc` | PQC encryption in hybrid-separate mode |

## Bundle Status

| Status | Description |
|--------|-------------|
| `pending` | Bundle created but not yet active |
| `valid` | Bundle is active and usable |
| `expired` | Validity period has ended |
| `revoked` | Bundle was revoked (all certs added to CRL) |

## CLI Commands

### Create a Bundle (Enroll)

```bash
# Create bundle with a single profile
pki bundle enroll --profile ec/tls-client \
    --subject "CN=Alice" --ca-dir ./ca

# Create bundle with multiple profiles (crypto-agility)
pki bundle enroll --profile ec/client --profile ml-dsa-kem/client \
    --subject "CN=Alice" --ca-dir ./ca

# With SANs
pki bundle enroll --profile ml-dsa-kem/tls-server-sign \
    --subject "CN=server.example.com" \
    --dns server.example.com --dns www.example.com --ca-dir ./ca

# With custom bundle ID
pki bundle enroll --profile hybrid/catalyst/tls-client \
    --subject "CN=Alice" --id alice-prod --ca-dir ./ca
```

### List Bundles

```bash
pki bundle list --ca-dir ./ca
```

Output:
```
ID                           SUBJECT  PROFILE         STATUS  CERTS  VALID UNTIL
--                           -------  -----           ------  -----  -----------
Alice-20250115-abc123        Alice    hybrid-full     valid   2      2026-01-15
Server-20250110-def456       Server   pqc-basic       valid   1      2025-07-10
```

### Show Bundle Details

```bash
pki bundle info Alice-20250115-abc123 --ca-dir ./ca
```

Output:
```
Bundle ID:    Alice-20250115-abc123
Subject:      Alice
Organization: Acme Corp
Profile:        hybrid-full
Status:       valid
Created:      2025-01-15 10:30:00
Valid From:   2025-01-15 10:30:00
Valid Until:  2026-01-15 10:30:00

Certificates:
  [1] signature
      Serial:      0x01
      Algorithm:   SHA256WithECDSA
      Catalyst:    yes (alt: ML-DSA-65)
      Fingerprint: A1B2C3...
  [2] encryption
      Serial:      0x02
      Algorithm:   ML-KEM-768
      Related to:  0x01
      Fingerprint: D4E5F6...
```

### Renew a Bundle

```bash
# Standard renewal (same profiles)
pki bundle renew alice-20250115-abc123 --ca-dir ./ca

# Crypto-agility: add PQC during renewal
pki bundle renew alice-20250115-abc123 \
    --profile ec/client --profile ml-dsa-kem/client --ca-dir ./ca

# Crypto-agility: remove legacy algorithms
pki bundle renew alice-20250115-abc123 \
    --profile ml-dsa-kem/client --ca-dir ./ca
```

Standard renewal creates a new bundle with fresh certificates using the same profiles.
Using `--profile` allows crypto migration (adding/removing/changing algorithms).

### Revoke a Bundle

```bash
pki bundle revoke alice-20250115-abc123 --ca-dir ./ca --reason keyCompromise
```

All certificates in the bundle are added to the CRL.

### Export Bundle

```bash
# Export certificates only
pki bundle export alice-20250115-abc123 --ca-dir ./ca --out alice.pem

# Export with private keys (requires passphrase)
pki bundle export alice-20250115-abc123 --ca-dir ./ca \
    --keys --passphrase mysecret --out alice-full.pem
```

## Revocation Reasons

| Reason | Description |
|--------|-------------|
| `unspecified` | No specific reason |
| `keyCompromise` | Private key was compromised |
| `caCompromise` | CA key was compromised |
| `affiliationChanged` | Subject's affiliation changed |
| `superseded` | Certificate was replaced |
| `cessationOfOperation` | Subject no longer operates |
| `certificateHold` | Temporary hold (not permanent) |
| `privilegeWithdrawn` | Subject's privileges withdrawn |

## PEM Format

The `certificates.pem` file contains all certificates concatenated:

```
-----BEGIN CERTIFICATE-----
[Signature certificate (Catalyst or classical)]
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
[Encryption certificate (if any)]
-----END CERTIFICATE-----
```

The `private-keys.pem` file contains encrypted private keys:

```
-----BEGIN ENCRYPTED PRIVATE KEY-----
[Signature private key]
-----END ENCRYPTED PRIVATE KEY-----
-----BEGIN ENCRYPTED PRIVATE KEY-----
[Encryption private key (if any)]
-----END ENCRYPTED PRIVATE KEY-----
```

## Lifecycle Workflow

```
┌─────────────┐
│   ENROLL    │
│  (pending)  │
└──────┬──────┘
       │
       ▼
┌─────────────┐     ┌─────────────┐
│    VALID    │────►│   EXPIRED   │
│             │     │ (automatic) │
└──────┬──────┘     └─────────────┘
       │
       │ revoke
       ▼
┌─────────────┐
│   REVOKED   │
│  (on CRL)   │
└─────────────┘
```

### Renewal Flow

```
Bundle A (valid)
    │
    │ renew
    ▼
Bundle B (valid, new certs)
    │
Bundle A (expired, marked as renewed)
```

## Programming Interface

```go
import (
    "github.com/remiblancher/pki/internal/bundle"
    "github.com/remiblancher/pki/internal/ca"
    "github.com/remiblancher/pki/internal/profile"
)

// Load bundle store
store := bundle.NewFileStore("/path/to/ca")

// List all bundles
bundles, _ := store.ListAll()

// Load a specific bundle
b, _ := store.Load("bundle-id")

// Load certificates
certs, _ := store.LoadCertificates("bundle-id")

// Load private keys (requires passphrase)
signers, _ := store.LoadKeys("bundle-id", []byte("passphrase"))

// Enroll new bundle via CA with multiple profiles
caInstance, _ := ca.New(caStore)
profileStore := profile.NewProfileStore("/path/to/ca")
profileStore.Load()

// Get profiles
ecProfile, _ := profileStore.Get("ec/client")
pqcProfile, _ := profileStore.Get("ml-dsa-kem/client")

// Enroll with multiple profiles (crypto-agility)
result, _ := caInstance.EnrollMulti(ca.EnrollmentRequest{
    Subject: pkix.Name{CommonName: "Alice"},
}, []*profile.Profile{ecProfile, pqcProfile})

// Save bundle
store.Save(result.Bundle, result.Certificates, result.Signers, passphrase)

// Generate bundle ID programmatically
bundleID := bundle.GenerateBundleID("Alice") // e.g., "alice-20250115-a1b2c3"
```

## Security Considerations

1. **Private key protection**: Keys are encrypted with AES-256-GCM using PBKDF2-derived keys
2. **Atomic revocation**: Revoking a bundle revokes ALL certificates - no partial revocation
3. **Audit trail**: All operations are logged via the audit system
4. **Passphrase policy**: Strong passphrases recommended for production

## See Also

- [PROFILES.md](PROFILES.md) - Certificate policy templates
- [CATALYST.md](CATALYST.md) - Catalyst certificate details
- [USER_GUIDE.md](USER_GUIDE.md) - Full CLI reference
