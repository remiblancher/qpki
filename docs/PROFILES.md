# Profiles

## Table of Contents

- [1. What is a Profile?](#1-what-is-a-profile)
- [2. Builtin Profiles](#2-builtin-profiles)
- [3. CLI Commands](#3-cli-commands)
- [4. Creating Custom Profiles](#4-creating-custom-profiles)
- [5. YAML Schema](#5-yaml-schema)
- [6. Declarative Variables](#6-declarative-variables)
- [7. X.509 Extensions](#7-x509-extensions)
- [8. Signature Algorithm Defaults](#8-signature-algorithm-defaults)
- [9. Supported Algorithms](#9-supported-algorithms)
- [10. Usage Examples](#10-usage-examples)
- [11. Performance: CompiledProfile](#11-performance-compiledprofile)
- [See Also](#see-also)

---

Profiles are YAML templates that define certificate characteristics: algorithm, validity, subject DN, extensions, and more. Each profile produces exactly one certificate type.

> **Related documentation:**
> - [CA.md](CA.md) - CA initialization and certificate issuance
> - [CREDENTIALS.md](CREDENTIALS.md) - Credential enrollment with profiles
> - [CRYPTO-AGILITY.md](CRYPTO-AGILITY.md) - Algorithm migration guide

## 1. What is a Profile?

A **profile** is a policy template stored as a YAML file that determines:

- **Algorithm**: The cryptographic algorithm for this certificate
- **Mode**: How multiple algorithms are combined (simple, catalyst, composite)
- **Validity period**: How long the certificate remains valid
- **Extensions**: X.509 extensions configuration

### Design Principle: 1 Profile = 1 Certificate

Each profile produces exactly **one certificate**. To create multiple certificates (e.g., signature + encryption), use multiple profiles.

### 1.1 Profile Categories

Profiles are organized by category and stored in `profiles/`:
- `ec/` - ECDSA-based profiles (modern classical)
- `rsa/` - RSA-based profiles (legacy compatibility)
- `rsa-pss/` - RSA-PSS profiles
- `ml/` - ML-DSA and ML-KEM profiles (post-quantum)
- `slh/` - SLH-DSA profiles (hash-based post-quantum)
- `hybrid/catalyst/` - Catalyst hybrid profiles (ITU-T X.509 Section 9.8)
- `hybrid/composite/` - IETF composite hybrid profiles

### 1.2 Profile Modes

| Mode | Description | Algorithm(s) |
|------|-------------|--------------|
| `simple` | Single algorithm | 1 |
| `catalyst` | Dual-key certificate (ITU-T X.509 9.8) | 2 |
| `composite` | IETF composite signature format | 2 |

### Simple Mode

Standard X.509 certificate with a single algorithm:

```yaml
name: ec/tls-server
description: "TLS server ECDSA P-256"

algorithm: ecdsa-p256
validity: 365d

extensions:
  keyUsage:
    critical: true
    values:
      - digitalSignature
  extKeyUsage:
    values:
      - serverAuth
```

### Catalyst Mode (ITU-T X.509 Section 9.8)

A single certificate containing both classical and PQC public keys:

```yaml
name: hybrid/catalyst/tls-server
description: "TLS server hybrid ECDSA P-256 + ML-DSA-65"

mode: catalyst
algorithms:
  - ecdsa-p256           # Classical algorithm (first)
  - ml-dsa-65            # PQC algorithm (second)
validity: 365d

extensions:
  keyUsage:
    critical: true
    values:
      - digitalSignature
  extKeyUsage:
    values:
      - serverAuth
```

### Composite Mode (IETF Format)

IETF composite signature where both signatures are combined and must validate:

```yaml
name: hybrid/composite/tls-server
description: "TLS server hybrid composite ECDSA P-256 + ML-DSA-65"

mode: composite
algorithms:
  - ecdsa-p256           # Classical algorithm (first)
  - ml-dsa-65            # PQC algorithm (second)
validity: 365d

extensions:
  keyUsage:
    critical: true
    values:
      - digitalSignature
  extKeyUsage:
    values:
      - serverAuth
```

---

## 2. Builtin Profiles

### EC (ECDSA - Modern Classical)

| Name | Algorithm | Use Case |
|------|-----------|----------|
| `ec/root-ca` | ECDSA P-384 | Root CA |
| `ec/issuing-ca` | ECDSA P-256 | Intermediate CA |
| `ec/tls-server` | ECDSA P-256 | TLS server |
| `ec/tls-client` | ECDSA P-256 | TLS client |
| `ec/email` | ECDSA P-256 | S/MIME email |
| `ec/code-signing` | ECDSA P-256 | Code signing |
| `ec/timestamping` | ECDSA P-256 | RFC 3161 TSA |
| `ec/ocsp-responder` | ECDSA P-384 | OCSP responder |
| `ec/signing` | ECDSA P-256 | Document signing |

### RSA (Legacy Compatibility)

| Name | Algorithm | Use Case |
|------|-----------|----------|
| `rsa/root-ca` | RSA 4096 | Root CA |
| `rsa/issuing-ca` | RSA 4096 | Intermediate CA |
| `rsa/tls-server` | RSA 2048 | TLS server |
| `rsa/tls-client` | RSA 2048 | TLS client |
| `rsa/email` | RSA 2048 | S/MIME email |
| `rsa/code-signing` | RSA 2048 | Code signing |
| `rsa/timestamping` | RSA 2048 | RFC 3161 TSA |
| `rsa/signing` | RSA 2048 | Document signing |
| `rsa/encryption` | RSA 2048 | Data encryption |

### RSA-PSS

| Name | Algorithm | Use Case |
|------|-----------|----------|
| `rsa-pss/tls-server` | RSA 4096 | TLS server (TLS 1.3) |

### ML-DSA-KEM (Post-Quantum)

| Name | Algorithm | Use Case |
|------|-----------|----------|
| `ml/root-ca` | ML-DSA-87 | Root CA |
| `ml/issuing-ca` | ML-DSA-65 | Intermediate CA |
| `ml/tls-server-sign` | ML-DSA-65 | TLS server signature |
| `ml/tls-server-encrypt` | ML-KEM-768 | TLS server encryption |
| `ml/tls-client` | ML-DSA-65 | TLS client |
| `ml/email-sign` | ML-DSA-65 | S/MIME signature |
| `ml/email-encrypt` | ML-KEM-768 | S/MIME encryption |
| `ml/code-signing` | ML-DSA-65 | Code signing |
| `ml/timestamping` | ML-DSA-65 | RFC 3161 TSA |
| `ml/ocsp-responder` | ML-DSA-65 | OCSP responder |
| `ml/signing` | ML-DSA-65 | Document signing |
| `ml/encryption` | ML-KEM-768 | Data encryption |

### SLH-DSA (Hash-Based Post-Quantum)

| Name | Algorithm | Use Case |
|------|-----------|----------|
| `slh/root-ca` | SLH-DSA-256f | Root CA |
| `slh/issuing-ca` | SLH-DSA-192f | Intermediate CA |
| `slh/tls-server` | SLH-DSA-128f | TLS server |
| `slh/tls-client` | SLH-DSA-128f | TLS client |
| `slh/timestamping` | SLH-DSA-256s | RFC 3161 TSA |
| `slh/signing` | SLH-DSA-256s | Document signing |
| `slh/ocsp-responder` | SLH-DSA-256s | OCSP responder |

### Hybrid Catalyst (ITU-T X.509 Section 9.8)

| Name | Algorithms | Use Case |
|------|------------|----------|
| `hybrid/catalyst/root-ca` | ECDSA P-384 + ML-DSA-87 | Root CA |
| `hybrid/catalyst/issuing-ca` | ECDSA P-256 + ML-DSA-65 | Intermediate CA |
| `hybrid/catalyst/tls-server` | ECDSA P-256 + ML-DSA-65 | TLS server |
| `hybrid/catalyst/tls-client` | ECDSA P-256 + ML-DSA-65 | TLS client |
| `hybrid/catalyst/timestamping` | ECDSA P-384 + ML-DSA-65 | RFC 3161 TSA |
| `hybrid/catalyst/ocsp-responder` | ECDSA P-384 + ML-DSA-65 | OCSP responder |
| `hybrid/catalyst/signing` | ECDSA P-256 + ML-DSA-65 | Document signing |

### Hybrid Composite (IETF Format)

| Name | Algorithms | Use Case |
|------|------------|----------|
| `hybrid/composite/root-ca` | ECDSA P-384 + ML-DSA-87 | Root CA |
| `hybrid/composite/issuing-ca` | ECDSA P-256 + ML-DSA-65 | Intermediate CA |
| `hybrid/composite/tls-server` | ECDSA P-256 + ML-DSA-65 | TLS server |
| `hybrid/composite/tls-client` | ECDSA P-256 + ML-DSA-65 | TLS client |
| `hybrid/composite/timestamping` | ECDSA P-384 + ML-DSA-65 | RFC 3161 TSA |
| `hybrid/composite/signing` | ECDSA P-384 + ML-DSA-87 | Document signing |
| `hybrid/composite/ocsp-responder` | ECDSA P-384 + ML-DSA-87 | OCSP responder |

---

## 3. CLI Commands

### List Available Profiles

```bash
qpki profile list
```

### View Profile Details

```bash
qpki profile info hybrid/catalyst/tls-server
```

### Show Profile YAML

```bash
qpki profile show ec/root-ca
```

### Export Profile for Customization

```bash
# Export single profile
qpki profile export ec/tls-server ./my-tls-server.yaml

# Export all profiles to a directory
qpki profile export --all ./templates/
```

### Validate a Custom Profile

```bash
qpki profile validate my-profile.yaml
```

---

## 4. Creating Custom Profiles

Export a builtin profile, modify it, and use it:

```bash
# Export a template
qpki profile export ec/tls-server ./my-custom.yaml

# Edit the file
vim ./my-custom.yaml

# Use the custom profile with credential enroll
qpki credential enroll --profile ./my-custom.yaml \
    --var cn=server.example.com --var dns_names=server.example.com --ca-dir ./ca

# Or with CSR workflow
qpki cert issue --profile ./my-custom.yaml --csr server.csr --out server.crt --ca-dir ./ca
```

### Profile Loading Priority

QPKI uses a two-tier profile system:

1. **Built-in profiles** - Embedded in the binary (default)
2. **Custom profiles** - Loaded from the CA's `profiles/` directory

Custom profiles can be used in two ways:

- **Override**: Use the same name as a built-in profile to replace it entirely
- **New profile**: Use a different name to add a new profile alongside built-ins

To override a built-in profile:

```bash
# Export the built-in profile
qpki profile export ec/tls-server ./tls-server.yaml

# Modify it
vim ./tls-server.yaml

# Place it in the CA's profiles directory (preserving the category structure)
mkdir -p ./ca/profiles/ec
cp ./tls-server.yaml ./ca/profiles/ec/tls-server.yaml

# Now "ec/tls-server" will use your custom version
qpki credential enroll --profile ec/tls-server --var cn=server.example.com --ca-dir ./ca --cred-dir ./credentials
```

To check which version is active, use `qpki profile list`:

```bash
qpki profile list --dir ./ca
```

The `SOURCE` column indicates:
- `default` - Built-in profile
- `custom (overrides default)` - Custom profile overriding a built-in
- `custom` - Custom profile with no built-in equivalent

To revert to the built-in version, simply delete the custom profile file from `CA/profiles/`.

---

## 5. YAML Schema

```yaml
# =============================================================================
# Profile YAML Structure Reference
# =============================================================================

name: string              # Profile identifier
description: string       # Human-readable description

# -----------------------------------------------------------------------------
# Algorithm - Simple profile (single algorithm)
# -----------------------------------------------------------------------------
algorithm: string         # e.g., ecdsa-p256, rsa-4096, ml-dsa-65

# -----------------------------------------------------------------------------
# Algorithm - Hybrid profile (two algorithms)
# -----------------------------------------------------------------------------
mode: string              # catalyst | composite
algorithms:               # List of algorithm IDs
  - ecdsa-p256            # Classical algorithm (first)
  - ml-dsa-65             # PQC algorithm (second)

# -----------------------------------------------------------------------------
# Signature - Override signature algorithm defaults
# -----------------------------------------------------------------------------
signature:
  scheme: string          # ecdsa | pkcs1v15 | rsassa-pss | ed25519
  hash: string            # sha256 | sha384 | sha512 | sha3-256 | sha3-384 | sha3-512
  pss:                    # RSA-PSS specific parameters
    salt_length: int      # Salt length in bytes (-1 = hash length)
    mgf: string           # MGF hash algorithm (defaults to signature hash)

# -----------------------------------------------------------------------------
# Validity - fixed value or template
# -----------------------------------------------------------------------------
validity: duration        # Duration format (e.g., 365d, 8760h, 1y)
                          # Or template: "{{ validity }}" (resolved at enrollment)

# -----------------------------------------------------------------------------
# Variables - Input parameters with validation
# -----------------------------------------------------------------------------
variables:
  <name>:
    type: string|integer|list|dns_name|dns_names|ip_list|email|uri|oid|duration
    required: bool
    default: value
    description: string
    # Type-specific constraints...

# -----------------------------------------------------------------------------
# Subject DN - Certificate subject fields
# -----------------------------------------------------------------------------
subject:
  cn: "{{ variable }}"    # Common Name
  o: "{{ variable }}"     # Organization
  ou: "static value"      # Organizational Unit (can be static)
  c: "{{ variable }}"     # Country
```

### DN Encoding (RFC 5280)

By default, DN attributes use UTF8String (ASN.1 tag 12). You can specify encoding per attribute:

```yaml
subject:
  cn: "{{ cn }}"                    # UTF8String (default)
  o:
    value: "ACME Corp"
    encoding: printable             # PrintableString (tag 19)
  c:
    value: "FR"
    encoding: printable             # Required by RFC 5280
  email:
    value: "{{ email }}"
    encoding: ia5                   # Required by RFC 5280
```

**Available encodings:**

| Encoding | ASN.1 Tag | Characters | Use Case |
|----------|-----------|------------|----------|
| `utf8` | 12 | Full Unicode | Default, RFC 5280 recommended |
| `printable` | 19 | A-Za-z0-9 '()+,-./:=? space | Country (C), legacy |
| `ia5` | 22 | ASCII 7-bit | Email addresses |

**RFC 5280 constraints (auto-applied):**
- `c` (country): automatically uses `printable` encoding
- `email`: automatically uses `ia5` encoding

You can omit the encoding for these attributes - it will be applied automatically.
If you explicitly specify a wrong encoding (e.g., `c: { encoding: utf8 }`), a validation error is returned.

```yaml
# -----------------------------------------------------------------------------
# Extensions - X.509 v3 extensions
# -----------------------------------------------------------------------------
extensions:
  basicConstraints:
    critical: bool        # MUST true for CA (RFC 5280)
    ca: bool              # true=CA, false=end-entity
    pathLen: int          # Max sub-CAs (only if ca=true)
  keyUsage:
    critical: bool
    values: [digitalSignature, keyEncipherment, ...]
  extKeyUsage:
    values: [serverAuth, clientAuth, ...]
  subjectAltName:
    dns: "{{ dns_names }}"      # DNS names from variable
    ip: "{{ ip_addresses }}"    # IP addresses from variable
    dns_include_cn: bool        # Auto-add CN to DNS SANs
  certificatePolicies:
    policies:
      - oid: string
        cps: string
  crlDistributionPoints:
    urls: [string, ...]
  authorityInfoAccess:
    caIssuers: [string, ...]
    ocsp: [string, ...]
```

### Template Variable Substitution

Variables are referenced using `{{ variable_name }}` syntax. Supported locations:

| Location | Supported | Example |
|----------|-----------|---------|
| `subject:` fields | ✅ Yes | `cn: "{{ cn }}"` |
| `subjectAltName.dns` | ✅ Yes | `dns: "{{ dns_names }}"` |
| `subjectAltName.ip` | ✅ Yes | `ip: "{{ ip_addresses }}"` |
| `subjectAltName.email` | ✅ Yes | `email: "{{ emails }}"` |
| `validity:` | ✅ Yes | `validity: "{{ validity }}"` |
| `crlDistributionPoints.urls` | ✅ Yes | `urls: ["{{ crl_url }}"]` |
| `authorityInfoAccess.caIssuers` | ✅ Yes | `caIssuers: ["{{ ca_issuer }}"]` |
| `authorityInfoAccess.ocsp` | ✅ Yes | `ocsp: ["{{ ocsp_url }}"]` |
| `certificatePolicies.cps` | ✅ Yes | `cps: "{{ cps_url }}"` |

Template variables are resolved at enrollment time. Use `duration` type for validity and `uri` type for URLs.

---

## 6. Declarative Variables

Profiles can declare typed variables with validation constraints. Variables enable:
- Input validation before certificate issuance
- Pattern matching (regex)
- Enumerated values
- Domain constraints (allowed_suffixes, allowed_ranges)
- Default values

### Variable Types

| Type | Go Type | Description |
|------|---------|-------------|
| `string` | `string` | Text with optional pattern/enum validation |
| `integer` | `int` | Number with optional min/max validation |
| `boolean` | `bool` | True/false value |
| `list` | `[]string` | List of strings with suffix/prefix constraints |
| `ip_list` | `[]string` | List of IP addresses with CIDR range constraints |
| `dns_name` | `string` | Single DNS name with RFC 1035/1123 validation + wildcard policy |
| `dns_names` | `[]string` | List of DNS names with RFC 1035/1123 validation + wildcard policy |
| `email` | `string` | Email address with RFC 5322 validation |
| `uri` | `string` | URI with RFC 3986 validation + scheme/host constraints |
| `oid` | `string` | Object Identifier in dot-notation (e.g., `1.2.3.4`) |
| `duration` | `string` | Duration string (Go format + d/w/y units) |

### Profile with Variables Example

```yaml
name: ec/tls-server-secure
description: "Production TLS server with validation"

algorithm: ecdsa-p256
validity: "{{ validity }}"    # Template - resolved at enrollment

# Declarative variables with constraints
variables:
  cn:
    type: string
    required: true
    pattern: "^[a-zA-Z0-9][a-zA-Z0-9.-]+$"
    description: "Common Name (FQDN)"

  organization:
    type: string
    required: false
    default: "ACME Corp"
    description: "Organization name"

  country:
    type: string
    required: false
    default: "FR"
    pattern: "^[A-Z]{2}$"
    minLength: 2
    maxLength: 2
    description: "ISO 3166-1 alpha-2 country code"

  environment:
    type: string
    required: false
    default: "production"
    enum: ["development", "staging", "production"]
    description: "Deployment environment"

  dns_names:
    type: list
    required: false
    default: []
    constraints:
      allowed_suffixes:
        - ".example.com"
        - ".internal"
      denied_prefixes:
        - "test-"
      max_items: 10
    description: "DNS Subject Alternative Names"

  ip_addresses:
    type: ip_list
    required: false
    constraints:
      allowed_ranges:
        - "10.0.0.0/8"
        - "192.168.0.0/16"
      max_items: 5
    description: "IP Subject Alternative Names"

  validity:
    type: duration
    required: false
    default: "365d"
    min_duration: "1d"
    max_duration: "825d"
    description: "Certificate validity period"

  crl_url:
    type: uri
    required: false
    constraints:
      allowed_schemes: ["http", "https"]
    description: "CRL distribution point URL"

  ocsp_url:
    type: uri
    required: false
    constraints:
      allowed_schemes: ["http", "https"]
    description: "OCSP responder URL"

# Subject DN with variable substitution
subject:
  cn: "{{ cn }}"
  o: "{{ organization }}"
  c: "{{ country }}"

# Extensions
extensions:
  basicConstraints:
    critical: true
    ca: false
  keyUsage:
    critical: true
    values:
      - digitalSignature
      - keyEncipherment
  extKeyUsage:
    values:
      - serverAuth
  # SANs with variable substitution
  subjectAltName:
    dns: "{{ dns_names }}"
    ip: "{{ ip_addresses }}"
    dns_include_cn: true
  # CDP/AIA with template variables
  crlDistributionPoints:
    urls:
      - "{{ crl_url }}"
  authorityInfoAccess:
    ocsp:
      - "{{ ocsp_url }}"
```

### Variable Constraints Reference

#### String Constraints

```yaml
variables:
  my_var:
    type: string
    required: true          # Must be provided
    default: "value"        # Default if not provided
    pattern: "^[a-z]+$"     # Regex pattern
    enum: ["a", "b", "c"]   # Allowed values
    minLength: 1            # Minimum length
    maxLength: 64           # Maximum length
```

#### Integer Constraints

```yaml
variables:
  days:
    type: integer
    required: false
    default: 365
    min: 1                  # Minimum value
    max: 825                # Maximum value
    enum: ["30", "90", "365"]  # Allowed values (as strings)
```

#### List Constraints

```yaml
variables:
  dns_names:
    type: list
    default: []
    constraints:
      allowed_suffixes:     # Each item must end with one of these
        - ".example.com"
      denied_prefixes:      # Items starting with these are rejected
        - "internal-"
      min_items: 1          # Minimum number of items
      max_items: 10         # Maximum number of items
```

#### IP List Constraints

```yaml
variables:
  ip_addresses:
    type: ip_list
    constraints:
      allowed_ranges:       # IPs must be within one of these CIDRs
        - "10.0.0.0/8"
        - "192.168.0.0/16"
      max_items: 5
```

#### Email Type (RFC 5322)

The `email` type validates email addresses according to RFC 5322 using Go's `net/mail` package.

**Normalization (automatic):**
- Lowercase: `User@Example.COM` → `user@example.com` (RFC 5321 recommendation)

**Constraints:**

```yaml
variables:
  email:
    type: email
    required: true
    constraints:
      allowed_suffixes:      # Domain must match one of these
        - "@example.com"
        - "@acme.com"
      denied_prefixes:       # Local part must not start with these
        - "admin"
        - "root"
```

**Example validation:**

| Value | Options | Result |
|-------|---------|--------|
| `user@example.com` | default | 🟢 Valid |
| `User@Example.COM` | default | 🟢 Normalized to lowercase |
| `user+tag@example.com` | default | 🟢 Plus addressing valid |
| `admin@example.com` | `denied_prefixes: [admin]` | 🔴 Denied prefix |
| `user@other.com` | `allowed_suffixes: [@example.com]` | 🔴 Domain not allowed |
| `not-an-email` | default | 🔴 Invalid format |

**Use case:** S/MIME certificates, TLS client authentication with email identity.

```yaml
# Example: Email certificate for S/MIME
variables:
  email:
    type: email
    required: true
    constraints:
      allowed_suffixes:
        - "@acme.com"
        - "@acme.fr"
    description: "User email address (must be @acme.com or @acme.fr)"
```

#### URI Type (RFC 3986)

The `uri` type validates URIs according to RFC 3986 and supports scheme/host constraints.

**Normalization (automatic):**
- Scheme lowercase: `HTTP://example.com` → `http://example.com`

**Constraints:**

```yaml
variables:
  ocsp_url:
    type: uri
    required: false
    default: "http://ocsp.example.com"
    constraints:
      allowed_schemes:       # Scheme must be one of these
        - "http"
        - "https"
      allowed_hosts:         # Host must be one of these
        - "ocsp.example.com"
        - "ocsp2.example.com"
```

**Example validation:**

| Value | Options | Result |
|-------|---------|--------|
| `http://example.com` | default | 🟢 Valid |
| `https://example.com/path` | default | 🟢 Valid with path |
| `HTTP://Example.COM` | default | 🟢 Scheme normalized |
| `ftp://example.com` | `allowed_schemes: [http, https]` | 🔴 Scheme not allowed |
| `http://other.com` | `allowed_hosts: [example.com]` | 🔴 Host not allowed |
| `example.com` | default | 🔴 Missing scheme |

**Use case:** AIA (Authority Information Access) URLs, CRL Distribution Points, OCSP responder URLs.

```yaml
# Example: AIA configuration
variables:
  ocsp_url:
    type: uri
    constraints:
      allowed_schemes: ["http", "https"]
      allowed_hosts: ["ocsp.example.com"]
    description: "OCSP responder URL"

  ca_issuer_url:
    type: uri
    constraints:
      allowed_schemes: ["http", "https"]
    description: "CA certificate URL"
```

#### OID Type (Object Identifier)

The `oid` type validates Object Identifiers in dot-notation format (e.g., `1.2.840.113549.1.1.11`).

**Validation rules:**
- Format: digits separated by dots (e.g., `1.2.3.4`)
- Minimum 2 arcs required (e.g., `1.2`)
- First arc must be 0, 1, or 2
- Second arc must be < 40 when first arc is 0 or 1

**Constraints:**

```yaml
variables:
  policy_oid:
    type: oid
    required: false
    default: "1.3.6.1.4.1.99999.1"
    constraints:
      allowed_suffixes:      # OID must start with one of these (prefix check)
        - "2.16.840.1.101.3.4"   # NIST algorithms arc
        - "1.3.6.1.4.1"          # Private enterprise arc
```

> **Note:** For OID type, `allowed_suffixes` acts as **allowed prefixes** - the OID must start with one of the specified values.

**Example validation:**

| Value | Options | Result |
|-------|---------|--------|
| `1.2.3` | default | 🟢 Valid |
| `2.16.840.1.101.3.4.3.17` | default | 🟢 ML-DSA-44 OID |
| `0.2.3` | default | 🟢 First arc 0 |
| `3.2.3` | default | 🔴 First arc > 2 |
| `0.40.1` | default | 🔴 Second arc >= 40 under arc 0 |
| `1` | default | 🔴 Single arc |
| `1.a.3` | default | 🔴 Non-numeric |

**Use case:** Certificate policies, custom extension OIDs, algorithm identifiers.

```yaml
# Example: Certificate policy
variables:
  policy_oid:
    type: oid
    default: "1.3.6.1.4.1.99999.1.1"
    constraints:
      allowed_suffixes:
        - "1.3.6.1.4.1.99999"    # Your private enterprise arc
    description: "Certificate policy OID"
```

#### Duration Type

The `duration` type validates duration strings, supporting both Go's standard format and extended units for days, weeks, and years.

**Supported formats:**
- Go standard: `1h`, `30m`, `60s`, `1h30m`
- Extended: `1d` (days), `1w` (weeks), `1y` (years)
- Combined: `1y6m`, `30d12h`, `1w1d`

**Conversion:**
- 1 day = 24 hours
- 1 week = 7 days
- 1 year = 365 days

**Constraints:**

```yaml
variables:
  validity:
    type: duration
    required: false
    default: "365d"
    min_duration: "1d"      # Minimum duration
    max_duration: "825d"    # Maximum (CA/B Forum limit)
```

**Example validation:**

| Value | Options | Result |
|-------|---------|--------|
| `365d` | default | 🟢 Valid |
| `1y` | default | 🟢 365 days |
| `2w` | default | 🟢 14 days |
| `30d12h` | default | 🟢 Combined |
| `1h30m` | default | 🟢 Go format |
| `12h` | `min_duration: "1d"` | 🔴 Below minimum |
| `3y` | `max_duration: "825d"` | 🔴 Above maximum |
| `abc` | default | 🔴 Invalid format |

**Use case:** Certificate validity periods, CRL update intervals.

```yaml
# Example: Validity with CA/B Forum constraints
variables:
  validity:
    type: duration
    default: "365d"
    min_duration: "1d"
    max_duration: "825d"    # CA/B Forum max for TLS
    description: "Certificate validity period"

  crl_validity:
    type: duration
    default: "7d"
    min_duration: "1h"
    max_duration: "30d"
    description: "CRL validity period"
```

#### DNS Name Type (RFC 1035/1123)

The `dns_name` and `dns_names` types provide built-in DNS name validation according to RFC 1035/1123, plus optional wildcard policy (RFC 6125).

**Normalization (automatic):**
- Lowercase: `API.Example.COM` → `api.example.com` (RFC 4343)
- Trailing dot stripped: `example.com.` → `example.com` (FQDN)

**Validation rules:**
- Total DNS name length ≤ 253 characters
- Each label (between dots) ≤ 63 characters
- No empty labels (double dots `..` rejected)
- Labels contain only alphanumeric characters and hyphens
- Labels don't start or end with a hyphen
- Minimum 2 labels required (unless `allow_single_label: true`)

```yaml
variables:
  # Single DNS name (e.g., for CN)
  cn:
    type: dns_name
    required: true
    wildcard:                     # Wildcard policy (optional)
      allowed: true               # Permit wildcards like *.example.com (default: false)
      single_label: true          # RFC 6125: * matches exactly one label (default: true)
      forbid_public_suffix: true  # Block wildcards on public suffixes like *.co.uk

  # Internal hostname (single label allowed)
  internal_host:
    type: dns_name
    allow_single_label: true      # Permit "localhost", "db-master", etc.

  # List of DNS names (e.g., for SANs)
  dns_names:
    type: dns_names
    wildcard:
      allowed: false              # No wildcards in SANs
    constraints:
      allowed_suffixes:           # Domain restrictions (label boundary check)
        - ".example.com"
      max_items: 10
```

**DNS Name Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `allow_single_label` | `false` | Permit single-label names like `localhost` |

**Wildcard Policy (RFC 6125):**

| Option | Default | Description |
|--------|---------|-------------|
| `allowed` | `false` | Whether wildcards are permitted |
| `single_label` | `true` | RFC 6125: `*` matches exactly one DNS label |
| `forbid_public_suffix` | `false` | Block wildcards on public suffixes (*.co.uk, *.com.au) |

**Wildcard validation rules:**
- Wildcard must be leftmost label: `*.example.com` 🟢, `api.*.com` 🔴
- Minimum 3 labels required: `*.example.com` 🟢, `*.com` 🔴
- Only one wildcard allowed: `*.*.example.com` 🔴
- With `forbid_public_suffix: true`: `*.co.uk` 🔴, `*.example.co.uk` 🟢

**Suffix matching (security):**

The `allowed_suffixes` constraint uses label boundary matching to prevent security issues:

| DNS Name | Suffix | Result | Reason |
|----------|--------|--------|--------|
| `api.example.com` | `.example.com` | 🟢 | Matches on label boundary |
| `fakeexample.com` | `.example.com` | 🔴 | Not on label boundary |
| `example.com` | `.example.com` | 🟢 | Exact match |

**Example validation:**

| Value | Options | Result |
|-------|---------|--------|
| `api.example.com` | default | 🟢 Valid DNS name |
| `API.Example.COM` | default | 🟢 Normalized to lowercase |
| `example.com.` | default | 🟢 Trailing dot stripped |
| `*.example.com` | `allowed: true` | 🟢 Valid wildcard |
| `*.example.com` | `allowed: false` | 🔴 Wildcards not allowed |
| `*.co.uk` | `forbid_public_suffix: true` | 🔴 Public suffix blocked |
| `localhost` | default | 🔴 Single label (needs 2+) |
| `localhost` | `allow_single_label: true` | 🟢 Single label allowed |
| `*.com` | `allowed: true` | 🔴 Too few labels |
| `example..com` | any | 🔴 Empty label (double dot) |

**When to use `dns_name` vs `string`:**

Use `dns_name` when:
- You want automatic DNS format validation
- You need wildcard certificate support with proper RFC 6125 enforcement
- You want case normalization and trailing dot handling

Use `string` with `pattern` when:
- You need custom regex validation
- You have non-standard hostname requirements

```yaml
# Preferred: Built-in DNS validation
cn:
  type: dns_name
  wildcard:
    allowed: true
    forbid_public_suffix: true  # Recommended for production

# Internal environment (single label hostnames)
internal_cn:
  type: dns_name
  allow_single_label: true

# Fallback: Custom regex (escape hatch)
cn:
  type: string
  pattern: "^[a-z0-9][a-z0-9.-]+$"
```

### Using Variables via CLI

#### Using --var flags

```bash
# Single variable
qpki credential enroll --profile ec/tls-server-secure \
    --var cn=api.example.com

# Multiple variables
qpki credential enroll --profile ec/tls-server-secure \
    --var cn=api.example.com \
    --var dns_names=api.example.com,api2.example.com \
    --var environment=production \
    --var organization="My Company"

# List values are comma-separated
qpki credential enroll --profile ec/tls-server-secure \
    --var cn=api.example.com \
    --var ip_addresses=10.0.0.1,10.0.0.2
```

#### Using --var-file

Create a YAML file with variable values:

```yaml
# vars.yaml
cn: api.example.com
organization: "My Company"
country: US
environment: production
dns_names:
  - api.example.com
  - api2.example.com
ip_addresses:
  - 10.0.0.1
  - 10.0.0.2
validity: "365d"
```

Then use it:

```bash
qpki credential enroll --profile ec/tls-server-secure --var-file vars.yaml
```

#### Mixing --var-file and --var

File values are loaded first, then --var flags override:

```bash
# Load defaults from file, override CN
qpki credential enroll --profile ec/tls-server-secure \
    --var-file defaults.yaml \
    --var cn=custom.example.com
```

### Variable Precedence

When using profiles with variables, the CLI automatically:
1. Loads variables from `--var-file` (if provided)
2. Overrides with `--var` flags
3. Validates all values against profile constraints
4. Applies default values for missing optional variables
5. Builds subject DN from resolved variables

```bash
# Load defaults from file, override specific values
qpki credential enroll --profile ec/tls-server-secure \
    --var-file defaults.yaml \
    --var cn=custom.example.com
```

### Error Messages

Variable validation provides clear error messages:

```
# Pattern mismatch
variable validation failed: cn: value "-invalid" does not match pattern "^[a-zA-Z0-9][a-zA-Z0-9.-]+$"

# Enum violation
variable validation failed: environment: value "test" not in allowed values [development staging production]

# Duration violation
variable validation failed: validity: duration "1000d" exceeds maximum "825d"

# Domain constraint
variable validation failed: dns_names: "api.other.com" does not match allowed suffixes [.example.com .internal]

# IP range constraint
variable validation failed: ip_addresses: IP "8.8.8.8" not in allowed ranges [10.0.0.0/8 192.168.0.0/16]
```

---

## 7. X.509 Extensions

### Supported Extensions

| Extension | OID | Default Critical | Description |
|-----------|-----|------------------|-------------|
| `keyUsage` | 2.5.29.15 | `true` | Key usage restrictions (RFC 5280 §4.2.1.3) |
| `extKeyUsage` | 2.5.29.37 | `false` | Extended key usage purposes (RFC 5280 §4.2.1.12) |
| `basicConstraints` | 2.5.29.19 | `true` | CA flag and path length (RFC 5280 §4.2.1.9) |
| `subjectAltName` | 2.5.29.17 | `false` | Alternative identities (RFC 5280 §4.2.1.6) |
| `crlDistributionPoints` | 2.5.29.31 | `false` | CRL locations (RFC 5280 §4.2.1.13) |
| `authorityInfoAccess` | 1.3.6.1.5.5.7.1.1 | `false` | OCSP and CA issuer URLs (RFC 5280 §4.2.2.1) |
| `certificatePolicies` | 2.5.29.32 | `false` | Certificate policies (RFC 5280 §4.2.1.4) |
| `nameConstraints` | 2.5.29.30 | `true` | Name restrictions for CA (RFC 5280 §4.2.1.10) |
| `ocspNoCheck` | 1.3.6.1.5.5.7.48.1.5 | `false` | Skip OCSP check for responder (RFC 6960 §4.2.2.2.1) |

### Automatic Extensions (Not Configurable)

These extensions are automatically generated by QPKI and cannot be configured in profiles:

| Extension | OID | Critical | Description |
|-----------|-----|----------|-------------|
| Subject Key Identifier | 2.5.29.14 | `false` | SHA-1 hash of public key (RFC 5280 §4.2.1.2) |
| Authority Key Identifier | 2.5.29.35 | `false` | Copied from issuer's SKI (RFC 5280 §4.2.1.1) |

- **SKI**: Computed as `SHA-1(SubjectPublicKeyInfo)` per RFC 5280 method 1
- **AKI**: Copied from the issuing CA certificate's SKI

### Extensions Configuration Example

```yaml
extensions:
  keyUsage:
    critical: true
    values:
      - digitalSignature
      - keyEncipherment

  extKeyUsage:
    critical: false
    values:
      - serverAuth
      - clientAuth

  basicConstraints:
    critical: true
    ca: false

  # CRL Distribution Points - static or template
  crlDistributionPoints:
    urls:
      - "http://pki.example.com/crl/ca.crl"    # Static URL
      - "{{ crl_url }}"                         # Or template variable

  # Authority Info Access - static or template
  authorityInfoAccess:
    ocsp:
      - "{{ ocsp_url }}"                        # Template variable
    caIssuers:
      - "{{ ca_issuer }}"                       # Template variable

  # Certificate Policies - CPS can be template
  certificatePolicies:
    policies:
      - oid: "2.23.140.1.2.1"
        cps: "{{ cps_url }}"                    # Template variable

  # Subject Alternative Names - template variables
  subjectAltName:
    dns: "{{ dns_names }}"       # Template variable (expanded at runtime)
    email: "{{ email }}"         # Template variable
    ip: "{{ ip_addresses }}"     # Template variable
    dns_include_cn: true         # Auto-add CN to DNS SANs
```

### Key Usage Values

| Value | Description |
|-------|-------------|
| `digitalSignature` | Verify digital signatures |
| `contentCommitment` | Non-repudiation |
| `keyEncipherment` | Encrypt keys (RSA key transport) |
| `dataEncipherment` | Encrypt data directly |
| `keyAgreement` | Key agreement (ECDH) |
| `keyCertSign` | Sign certificates (CA only) |
| `crlSign` | Sign CRLs (CA only) |
| `encipherOnly` | Encipher only (with keyAgreement) |
| `decipherOnly` | Decipher only (with keyAgreement) |

### Extended Key Usage Values

| Value | Description | OID |
|-------|-------------|-----|
| `serverAuth` | TLS server authentication | 1.3.6.1.5.5.7.3.1 |
| `clientAuth` | TLS client authentication | 1.3.6.1.5.5.7.3.2 |
| `codeSigning` | Code signing | 1.3.6.1.5.5.7.3.3 |
| `emailProtection` | S/MIME email | 1.3.6.1.5.5.7.3.4 |
| `timeStamping` | Trusted timestamping | 1.3.6.1.5.5.7.3.8 |
| `ocspSigning` | OCSP responder signing | 1.3.6.1.5.5.7.3.9 |
| `any` | Any extended key usage | 2.5.29.37.0 |

### Name Constraints (CA only)

Restricts which names a CA can issue certificates for. Only valid for CA certificates.

```yaml
extensions:
  nameConstraints:
    critical: true           # RFC 5280: MUST be critical
    permitted:
      dns:
        - ".example.com"     # Can issue for *.example.com
        - "example.com"      # Can issue for example.com
      email:
        - "@example.com"     # Can issue for *@example.com
      ip:
        - "10.0.0.0/8"       # CIDR notation
        - "192.168.0.0/16"
    excluded:
      dns:
        - ".forbidden.com"   # Cannot issue for *.forbidden.com
```

### OCSP No Check

Indicates that an OCSP responder certificate should not be checked for revocation. Used for OCSP responder certificates to avoid circular dependencies.

```yaml
extensions:
  ocspNoCheck:
    critical: false          # RFC 6960 default
```

### Basic Constraints

```yaml
extensions:
  basicConstraints:
    critical: true           # RFC 5280: MUST be critical for CA
    ca: true                 # true for CA, false for end-entity
    pathLen: 0               # Optional: max intermediate CAs (0 = no intermediates)
```

### Certificate Policies

```yaml
extensions:
  certificatePolicies:
    critical: false
    policies:
      - oid: "2.23.140.1.2.1"           # CA/Browser Forum DV
        cps: "http://example.com/cps"   # CPS URL
        userNotice: "Certificate issued under DV policy"  # Optional notice
```

---

## 8. Signature Algorithm Defaults

When the `signature:` field is not specified in a profile, the signature algorithm is automatically inferred from the key algorithm. The following table shows the defaults:

| Key Algorithm | Default Scheme | Default Hash | X.509 Signature Algorithm |
|---------------|----------------|--------------|---------------------------|
| `ecdsa-p256` | `ecdsa` | `sha256` | ECDSAWithSHA256 |
| `ecdsa-p384` | `ecdsa` | `sha384` | ECDSAWithSHA384 |
| `ecdsa-p521` | `ecdsa` | `sha512` | ECDSAWithSHA512 |
| `rsa-2048` | `rsassa-pss` | `sha256` | SHA256WithRSAPSS |
| `rsa-4096` | `rsassa-pss` | `sha256` | SHA256WithRSAPSS |
| `ed25519` | `ed25519` | *(none)* | PureEd25519 |
| `ml-dsa-*` | *(intrinsic)* | *(intrinsic)* | ML-DSA |
| `slh-dsa-*` | *(intrinsic)* | *(intrinsic)* | SLH-DSA |

### Override Examples

```yaml
# Use legacy PKCS#1 v1.5 instead of RSA-PSS (for compatibility)
algorithm: rsa-4096
signature:
  scheme: pkcs1v15
  hash: sha256

# Use SHA-384 instead of SHA-256 for RSA
algorithm: rsa-4096
signature:
  hash: sha384

# Use SHA-512 with P-384 (non-standard but valid)
algorithm: ecdsa-p384
signature:
  hash: sha512
```

> **Note:** Post-quantum algorithms (ML-DSA, SLH-DSA) have intrinsic signature schemes and do not use the `signature:` override.

---

## 9. Supported Algorithms

### Signature Algorithms

| ID | Algorithm | Type | Security Level |
|----|-----------|------|----------------|
| `ecdsa-p256` | ECDSA with P-256 | Classical | ~128-bit |
| `ecdsa-p384` | ECDSA with P-384 | Classical | ~192-bit |
| `ecdsa-p521` | ECDSA with P-521 | Classical | ~256-bit |
| `ed25519` | Ed25519 | Classical | ~128-bit |
| `rsa-2048` | RSA 2048-bit | Classical | ~112-bit |
| `rsa-4096` | RSA 4096-bit | Classical | ~140-bit |
| `ml-dsa-44` | ML-DSA-44 | PQC | NIST Level 1 |
| `ml-dsa-65` | ML-DSA-65 | PQC | NIST Level 3 |
| `ml-dsa-87` | ML-DSA-87 | PQC | NIST Level 5 |
| `slh-dsa-128f` | SLH-DSA-128f | PQC | NIST Level 1 |
| `slh-dsa-192f` | SLH-DSA-192f | PQC | NIST Level 3 |
| `slh-dsa-256f` | SLH-DSA-256f | PQC | NIST Level 5 |
| `slh-dsa-256s` | SLH-DSA-256s | PQC | NIST Level 5 |

### KEM Algorithms (Encryption)

| ID | Algorithm | Type | Security Level |
|----|-----------|------|----------------|
| `ml-kem-512` | ML-KEM-512 | PQC | NIST Level 1 |
| `ml-kem-768` | ML-KEM-768 | PQC | NIST Level 3 |
| `ml-kem-1024` | ML-KEM-1024 | PQC | NIST Level 5 |

---

## 10. Usage Examples

### Direct Issuance with Credential Enroll

```bash
# Issue using an ECDSA profile
qpki credential enroll --profile ec/tls-server \
    --var cn=server.example.com --var dns_names=server.example.com \
    --ca-dir ./ca --cred-dir ./credentials

# Issue using a hybrid profile
qpki credential enroll --profile hybrid/catalyst/tls-server \
    --var cn=server.example.com --var dns_names=server.example.com \
    --ca-dir ./ca --cred-dir ./credentials

# Issue using a PQC profile
qpki credential enroll --profile ml/tls-server-sign \
    --var cn=server.example.com --var dns_names=server.example.com \
    --ca-dir ./ca --cred-dir ./credentials
```

### CSR-Based Issuance

```bash
# Generate CSR first
qpki csr gen --algorithm ecdsa-p256 --keyout server.key \
    --cn server.example.com --dns server.example.com --out server.csr

# Issue from CSR
qpki cert issue --profile ec/tls-server --csr server.csr --out server.crt --ca-dir ./ca
```

### Recommended Profiles by Use Case

| Use Case | Recommended Profile | Rationale |
|----------|---------------------|-----------|
| Maximum compatibility | `ec/tls-server` | Works with all modern systems |
| Legacy compatibility | `rsa/tls-server` | Works with older systems |
| Quantum transition | `hybrid/catalyst/tls-server` | Classical + PQC in one cert |
| Full post-quantum | `ml/tls-server-sign` | Pure PQC signature |
| Long-term archive | `slh/timestamping` | Conservative hash-based |

---

## 11. Performance: CompiledProfile

For high-throughput scenarios (web services, APIs), profiles can be pre-compiled at startup to avoid per-certificate parsing overhead.

### Benefits

| Metric | Standard | Compiled | Improvement |
|--------|----------|----------|-------------|
| Profile lookup | ~50ns | ~26ns | 2x faster |
| Extensions parsing | Per-cert | Once at load | Eliminated |
| Regex compilation | Per-cert | Once at load | Eliminated |
| CIDR parsing | Per-cert | Once at load | Eliminated |

### Usage (Go API)

```go
// At startup: compile all profiles once
store := profile.NewCompiledProfileStore("./profiles")
if err := store.Load(); err != nil {
    log.Fatal(err)
}

// Per-request: use pre-compiled profile (26ns lookup, 0 allocs)
cp, ok := store.Get("ec/tls-server")
if !ok {
    return errors.New("profile not found")
}

// Issue certificate with pre-compiled profile
result, err := ca.EnrollWithCompiledProfile(req, cp)
```

### What Gets Pre-Compiled

- **KeyUsage**: String values → `x509.KeyUsage` bits
- **ExtKeyUsage**: String values → `x509.ExtKeyUsage` constants
- **BasicConstraints**: Parsed once
- **NameConstraints**: CIDR strings → `net.IPNet` structures
- **Variable patterns**: Regex strings → `*regexp.Regexp`
- **CIDR ranges**: IP ranges parsed once

---

## See Also

- [CA](CA.md) - CA initialization and certificate issuance
- [CREDENTIALS](CREDENTIALS.md) - Credential enrollment with profiles
- [KEYS](KEYS.md) - Key generation and CSR operations
- [CONCEPTS](CONCEPTS.md) - Catalyst and PQC concepts
- [CLI-REFERENCE](CLI-REFERENCE.md) - Complete command reference
