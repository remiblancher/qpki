# User Guide

This guide covers installation, CLI usage, and common workflows for Post-Quantum PKI (QPKI).

## 1. Installation

### Download Pre-built Binaries (Recommended)

Download the latest release for your platform from [GitHub Releases](https://github.com/remiblancher/post-quantum-pki/releases/latest).

**Linux / macOS:**
```bash
# Download (replace VERSION, OS, and ARCH as needed)
curl -LO https://github.com/remiblancher/post-quantum-pki/releases/latest/download/qpki_VERSION_OS_ARCH.tar.gz

# Extract
tar -xzf qpki_*.tar.gz

# Install
sudo mv qpki /usr/local/bin/

# Verify
qpki --version
```

**Available platforms:**

| OS | Architecture | File |
|----|--------------|------|
| Linux | amd64 | `qpki_VERSION_linux_amd64.tar.gz` |
| Linux | arm64 | `qpki_VERSION_linux_arm64.tar.gz` |
| macOS | Intel | `qpki_VERSION_darwin_amd64.tar.gz` |
| macOS | Apple Silicon | `qpki_VERSION_darwin_arm64.tar.gz` |
| Windows | amd64 | `qpki_VERSION_windows_amd64.zip` |

**Linux packages:**
```bash
# Debian/Ubuntu
sudo dpkg -i qpki_VERSION_linux_amd64.deb

# RHEL/Fedora
sudo rpm -i qpki_VERSION_linux_amd64.rpm
```

### Install via Homebrew (macOS)

```bash
brew tap remiblancher/qpki
brew install qpki
```

### From Source

```bash
git clone https://github.com/remiblancher/post-quantum-pki.git
cd pki
go build -o qpki ./cmd/qpki
sudo mv qpki /usr/local/bin/
```

### Go Install

```bash
go install github.com/remiblancher/post-quantum-pki/cmd/qpki@latest
```

### Verify Installation

```bash
qpki version
qpki --help
```

## 2. CLI Reference

### 2.0 Command Overview

```
qpki [--audit-log PATH]
├── ca                        # Certificate Authority
│   ├── init                  # Initialize CA (root or subordinate)
│   ├── info                  # Display CA information
│   ├── export                # Export CA certificates
│   ├── list                  # List CAs in directory
│   ├── rotate                # Rotate CA with new keys
│   ├── activate              # Activate pending CA version
│   └── versions              # List CA versions
│
├── cert                      # Certificate operations
│   ├── issue                 # Issue certificate from CSR
│   ├── list                  # List issued certificates
│   ├── info                  # Display certificate info
│   ├── revoke                # Revoke a certificate
│   └── verify                # Verify certificate validity
│
├── credential                # Credentials (coupled lifecycle)
│   ├── enroll                # Create new credential
│   ├── list                  # List credentials
│   ├── info                  # Credential details
│   ├── rotate                # Rotate credential
│   ├── activate              # Activate pending version
│   ├── versions              # List credential versions
│   ├── revoke                # Revoke credential
│   ├── export                # Export credential
│   └── import                # Import existing cert/key
│
├── key                       # Key management
│   ├── gen                   # Generate key pair
│   ├── pub                   # Extract public key
│   ├── list                  # List keys
│   ├── info                  # Key information
│   └── convert               # Convert key format
│
├── profile                   # Certificate profiles
│   ├── list                  # List available profiles
│   ├── info                  # Profile details
│   ├── vars                  # Show profile variables
│   ├── show                  # Display YAML content
│   ├── export                # Export profile to file
│   ├── lint                  # Validate profile YAML
│   └── install               # Install default profiles
│
├── csr                       # CSR operations
│   ├── gen                   # Generate CSR
│   ├── info                  # Display CSR info
│   └── verify                # Verify CSR signature
│
├── crl                       # CRL operations
│   ├── gen                   # Generate CRL
│   ├── info                  # Display CRL info
│   ├── verify                # Verify CRL signature
│   └── list                  # List CRLs
│
├── tsa                       # Timestamping (see OPERATIONS.md)
├── cms                       # CMS signatures (see OPERATIONS.md)
├── ocsp                      # OCSP responder (see OPERATIONS.md)
├── hsm                       # HSM integration (see HSM.md)
├── audit                     # Audit logging (see OPERATIONS.md)
│
└── inspect                   # Auto-detect and display file info
```

**Global flags:**
- `--audit-log PATH` - Enable audit logging to file (or set `PKI_AUDIT_LOG` env var)

**Supported algorithms:** ECDSA, Ed25519, RSA, post-quantum (ML-DSA, SLH-DSA, ML-KEM), and hybrid modes (Catalyst, Composite). See [CONCEPTS.md](CONCEPTS.md) for details.

### 2.1 Quick Reference

| Catégorie | Commande | Description |
|-----------|----------|-------------|
| **Clés** | `key gen` | Générer une clé privée |
| | `key pub` | Extraire la clé publique |
| | `key list` | Lister les clés d'un répertoire |
| | `key info` | Afficher les détails d'une clé |
| | `key convert` | Convertir le format d'une clé |
| **CA** | `ca init` | Initialiser une autorité de certification |
| | `ca info` | Afficher les informations d'une CA |
| | `ca export` | Exporter les certificats d'une CA |
| | `ca list` | Lister les CAs d'un répertoire |
| | `ca rotate` | Rotation de CA avec nouvelle clé |
| | `ca activate` | Activer une version en attente |
| | `ca versions` | Lister les versions d'une CA |
| **CSR** | `csr gen` | Générer une demande de certificat |
| | `csr info` | Afficher les détails d'un CSR |
| | `csr verify` | Vérifier la signature d'un CSR |
| **Certificats** | `cert issue` | Émettre un certificat depuis un CSR |
| | `cert list` | Lister les certificats d'une CA |
| | `cert info` | Afficher les détails d'un certificat |
| | `cert revoke` | Révoquer un certificat |
| | `cert verify` | Vérifier un certificat |
| **Credentials** | `credential enroll` | Émettre clé(s) + certificat(s) (recommandé) |
| | `credential list` | Lister les credentials |
| | `credential info` | Afficher les détails d'un credential |
| | `credential rotate` | Renouveler un credential |
| | `credential activate` | Activer une version en attente |
| | `credential versions` | Lister les versions d'un credential |
| | `credential revoke` | Révoquer un credential |
| | `credential export` | Exporter un credential |
| | `credential import` | Importer un certificat existant |
| **CRL** | `crl gen` | Générer une CRL |
| | `crl info` | Afficher les détails d'une CRL |
| | `crl verify` | Vérifier une CRL |
| | `crl list` | Lister les CRLs d'une CA |
| **Profils** | `profile list` | Lister les profils disponibles |
| | `profile info` | Afficher les détails d'un profil |
| | `profile vars` | Lister les variables d'un profil |
| | `profile show` | Afficher le YAML d'un profil |
| | `profile export` | Exporter un profil |
| | `profile lint` | Valider un fichier profil |
| | `profile install` | Installer les profils par défaut |
| **Vérification** | `inspect` | Inspecter certificat, clé ou CRL |
| **CMS** | `cms sign` | Créer une signature CMS |
| | `cms verify` | Vérifier une signature CMS |
| | `cms encrypt` | Chiffrer en CMS EnvelopedData |
| | `cms decrypt` | Déchiffrer un CMS |
| | `cms info` | Afficher les détails d'un CMS |
| **TSA** | `tsa sign` | Horodater un fichier (→ OPERATIONS.md) |
| | `tsa verify` | Vérifier un horodatage |
| | `tsa serve` | Démarrer serveur TSA |
| **OCSP** | `ocsp sign` | Créer une réponse OCSP (→ OPERATIONS.md) |
| | `ocsp verify` | Vérifier une réponse OCSP |
| | `ocsp request` | Créer une requête OCSP |
| | `ocsp serve` | Démarrer serveur OCSP |
| **HSM** | `hsm list` | Lister les tokens HSM (→ HSM.md) |
| | `hsm test` | Tester la connexion HSM |
| **Audit** | `audit verify` | Vérifier le log d'audit (→ OPERATIONS.md) |
| | `audit tail` | Afficher les derniers événements |

### 2.2 Gestion des clés

#### key gen

Generate a private key file.

The output file contains the private key in PEM format. The public key is mathematically derived from the private key and is not stored separately. To extract the public key, use `qpki key pub`.

```bash
qpki key gen [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--algorithm` | `-a` | ecdsa-p256 | Key algorithm |
| `--out` | `-o` | required | Output key file |
| `--passphrase` | | "" | Key passphrase |

**Algorithms:**

| Algorithm | Description |
|-----------|-------------|
| ecdsa-p256 | ECDSA with NIST P-256 curve |
| ecdsa-p384 | ECDSA with NIST P-384 curve |
| ecdsa-p521 | ECDSA with NIST P-521 curve |
| ed25519 | Edwards-curve DSA |
| rsa-2048 | RSA 2048-bit |
| rsa-4096 | RSA 4096-bit |
| ml-dsa-44 | ML-DSA (Dilithium) Level 1 |
| ml-dsa-65 | ML-DSA (Dilithium) Level 3 |
| ml-dsa-87 | ML-DSA (Dilithium) Level 5 |

**Examples:**

```bash
# ECDSA P-256 key
qpki key gen --algorithm ecdsa-p256 --out key.pem

# Ed25519 key
qpki key gen --algorithm ed25519 --out ed25519.key

# PQC key (ML-DSA)
qpki key gen --algorithm ml-dsa-65 --out pqc.key

# Encrypted key
qpki key gen --algorithm ecdsa-p384 --out secure.key --passphrase "secret"
```

#### key pub

Extract the public key from a private key file.

```bash
qpki key pub [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--key` | `-k` | required | Input private key file |
| `--out` | `-o` | required | Output public key file |
| `--passphrase` | | "" | Passphrase for encrypted key |

**Examples:**

```bash
# Extract public key from ECDSA key
qpki key pub --key private.pem --out public.pem

# Extract from encrypted key
qpki key pub --key encrypted.key --passphrase "secret" --out public.pem

# Extract from PQC key
qpki key pub --key mldsa.key --out mldsa.pub
```

#### key list

List private keys in a directory or HSM token.

```bash
qpki key list [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--dir` | `-d` | . | Directory to scan |
| `--hsm-config` | | | HSM configuration file |

**Examples:**

```bash
# List keys in directory
qpki key list --dir ./keys

# List keys in HSM token
qpki key list --hsm-config ./hsm.yaml
```

#### key info

Display information about a private key.

```bash
qpki key info <key-file> [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--passphrase` | `-p` | "" | Passphrase for encrypted key |

**Example:**

```bash
qpki key info private.key
```

#### key convert

Convert a private key to a different format.

```bash
qpki key convert [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--key` | `-k` | required | Input key file |
| `--out` | `-o` | required | Output key file |
| `--format` | `-f` | pem | Output format: pem, der, pkcs8 |
| `--passphrase` | | "" | Passphrase for input key |
| `--out-passphrase` | | "" | Passphrase for output key |

**Examples:**

```bash
# Convert PEM to DER
qpki key convert --key private.pem --out private.der --format der

# Add passphrase protection
qpki key convert --key private.pem --out encrypted.pem --out-passphrase "secret"
```

### 2.3 Gestion des CA

#### ca init

Initialize a new Certificate Authority.

```bash
qpki ca init [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--profile` | `-P` | "" | CA profile (e.g., ec/root-ca, hybrid/catalyst/root-ca) |
| `--var` | | [] | Variable value (key=value, repeatable) |
| `--var-file` | | "" | YAML file with variable values |
| `--algorithm` | `-a` | ecdsa-p256 | Key algorithm (ignored if --profile is set) |
| `--hybrid-algorithm` | | "" | PQC algorithm for hybrid mode |
| `--dir` | `-d` | ./ca | CA directory |
| `--validity` | | 10 | Validity in years (ignored if --profile is set) |
| `--path-len` | | 1 | Path length constraint (ignored if --profile is set) |
| `--passphrase` | `-p` | "" | Key passphrase |
| `--parent` | | "" | Parent CA directory (creates subordinate CA) |
| `--parent-passphrase` | | "" | Parent CA key passphrase |

**Examples:**

```bash
# Using a profile (recommended)
qpki ca init --profile ec/root-ca --dir ./myca --var cn="My Root CA"

# Hybrid Catalyst CA (ITU-T - backward compatible)
qpki ca init --profile hybrid/catalyst/root-ca --dir ./catalyst-ca --var cn="Catalyst Root CA"

# Hybrid Composite CA (IETF draft - stricter security)
qpki ca init --profile hybrid/composite/root-ca --dir ./composite-ca --var cn="Composite Root CA"

# Subordinate CA using a profile
qpki ca init --profile ec/issuing-ca --dir ./issuing-ca \
  --parent ./rootca --var cn="Issuing CA"

# CA with passphrase-protected key
qpki ca init --profile ec/root-ca --passphrase "mysecret" --dir ./secure-ca --var cn="Secure CA"

# PQC root CA with ML-DSA
qpki ca init --profile ml/root-ca --dir ./pqc-ca --var cn="PQC Root CA"

# Using a variables file
qpki ca init --profile ec/root-ca --dir ./myca --var-file ca-vars.yaml
```

**Available CA profiles:**

| Profile | Algorithm | Validity | Description |
|---------|-----------|----------|-------------|
| `ec/root-ca` | EC P-384 | 20 years | Root CA with pathLen=1 |
| `ec/issuing-ca` | EC P-256 | 10 years | Issuing CA with pathLen=0 |
| `hybrid/catalyst/root-ca` | EC P-384 + ML-DSA-87 | 20 years | Hybrid root CA (ITU-T extensions) |
| `hybrid/catalyst/issuing-ca` | EC P-384 + ML-DSA-65 | 10 years | Hybrid issuing CA (ITU-T) |
| `hybrid/composite/root-ca` | EC P-384 + ML-DSA-87 | 20 years | Composite root CA (IETF draft) |
| `hybrid/composite/issuing-ca` | EC P-256 + ML-DSA-65 | 10 years | Composite issuing CA (IETF) |
| `rsa/root-ca` | RSA 4096 | 20 years | RSA root CA |
| `ml/root-ca` | ML-DSA-87 | 20 years | Pure PQC root CA |

#### ca info

Display information about a Certificate Authority.

```bash
qpki ca info [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--dir` | `-d` | ./ca | CA directory |

**Example:**

```bash
qpki ca info --dir ./myca
```

#### ca export

Export CA certificates.

```bash
qpki ca export [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--dir` | `-d` | ./ca | CA directory |
| `--bundle` | `-b` | ca | Bundle type: ca, chain, root |
| `--out` | `-o` | stdout | Output file |

**Examples:**

```bash
# Export CA certificate
qpki ca export --dir ./myca --out ca.crt

# Export full chain (CA + parent)
qpki ca export --dir ./issuing-ca --bundle chain --out chain.pem

# Export root certificate only
qpki ca export --dir ./issuing-ca --bundle root --out root.crt
```

#### ca list

List Certificate Authorities in a directory.

```bash
qpki ca list [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--dir` | `-d` | . | Directory to scan |

**Example:**

```bash
qpki ca list --dir /var/lib/pki
```

#### ca rotate

Rotate a CA with new keys and algorithm.

```bash
qpki ca rotate [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--dir` | `-d` | ./ca | CA directory |
| `--profile` | `-P` | | New profile for rotation |
| `--passphrase` | `-p` | "" | Passphrase for new key |
| `--cross-sign` | | auto | Cross-sign strategy: auto, always, never |

**Examples:**

```bash
# Rotate to a new profile (crypto migration)
qpki ca rotate --dir ./myca --profile hybrid/catalyst/root-ca

# Rotate with explicit cross-signing
qpki ca rotate --dir ./myca --profile ml/root-ca --cross-sign always
```

#### ca activate

Activate a pending CA version after rotation.

```bash
qpki ca activate [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--dir` | `-d` | ./ca | CA directory |
| `--version` | `-v` | | Version to activate |

**Example:**

```bash
qpki ca activate --dir ./myca --version 2
```

#### ca versions

List all versions of a CA.

```bash
qpki ca versions [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--dir` | `-d` | ./ca | CA directory |

**Example:**

```bash
qpki ca versions --dir ./myca
```

### 2.4 Demandes de certificats (CSR)

#### csr gen

Generate a Certificate Signing Request (CSR) for submission to a CA.

```bash
qpki csr gen [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--algorithm` | `-a` | "" | Key algorithm for new key |
| `--keyout` | | "" | Output file for new private key |
| `--key` | | "" | Existing private key file |
| `--passphrase` | | "" | Passphrase for existing key |
| `--key-passphrase` | | "" | Passphrase for new key |
| `--out` | `-o` | required | Output CSR file |
| `--cn` | | required | Common Name |
| `--org` | `-O` | "" | Organization |
| `--country` | `-C` | "" | Country (2-letter code) |
| `--dns` | | [] | DNS SANs |
| `--email` | | [] | Email SANs |
| `--ip` | | [] | IP SANs |
| `--hybrid` | | "" | PQC algorithm for hybrid CSR |
| `--hybrid-keyout` | | "" | Output file for hybrid PQC key |
| `--attest-cert` | | "" | Attestation certificate (RFC 9883) |
| `--attest-key` | | "" | Attestation private key (RFC 9883) |

**Modes:**

| Mode | Description | Command |
|------|-------------|---------|
| Classical | RSA, ECDSA, Ed25519 via Go x509 | `--algorithm ecdsa-p256` |
| PQC Signature | ML-DSA, SLH-DSA (custom PKCS#10) | `--algorithm ml-dsa-65` |
| PQC KEM | ML-KEM with RFC 9883 attestation | `--algorithm ml-kem-768 --attest-cert ...` |
| Hybrid | Classical + PQC dual signatures | `--algorithm ecdsa-p256 --hybrid ml-dsa-65` |

**Examples:**

```bash
# Classical ECDSA CSR
qpki csr gen --algorithm ecdsa-p256 --keyout server.key \
    --cn server.example.com --dns server.example.com --out server.csr

# PQC ML-DSA CSR (direct signature)
qpki csr gen --algorithm ml-dsa-65 --keyout mldsa.key \
    --cn alice@example.com --out mldsa.csr

# PQC ML-KEM CSR with RFC 9883 attestation
# (requires an existing signature certificate for attestation)
qpki csr gen --algorithm ml-kem-768 --keyout kem.key \
    --cn alice@example.com \
    --attest-cert sign.crt --attest-key sign.key \
    --out kem.csr

# Hybrid CSR (ECDSA + ML-DSA dual signatures)
qpki csr gen --algorithm ecdsa-p256 --keyout classical.key \
    --hybrid ml-dsa-65 --hybrid-keyout pqc.key \
    --cn example.com --out hybrid.csr

# CSR with existing key
qpki csr gen --key existing.key --cn server.example.com --out server.csr
```

**RFC 9883 (ML-KEM Attestation):**

ML-KEM keys cannot sign (they're Key Encapsulation Mechanisms). To prove possession of an ML-KEM private key, RFC 9883 defines the `privateKeyPossessionStatement` attribute. This requires:

1. An existing signature certificate (`--attest-cert`)
2. The corresponding private key (`--attest-key`)

The CSR is signed by the attestation key, and includes a reference to the attestation certificate. The CA verifies the attestation chain before issuing the ML-KEM certificate.

#### csr info

Display information about a CSR.

```bash
qpki csr info <csr-file>
```

**Example:**

```bash
qpki csr info server.csr
```

#### csr verify

Verify the signature of a CSR.

```bash
qpki csr verify <csr-file>
```

**Example:**

```bash
qpki csr verify server.csr
```

### 2.5 Émission de certificats

#### cert issue

Issue a certificate from a Certificate Signing Request (CSR).

```bash
qpki cert issue [flags]
```

**Note:** This command requires a CSR file (`--csr`). For direct issuance with automatic key generation, use `qpki credential enroll` instead.

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--ca-dir` | `-d` | ./ca | CA directory |
| `--profile` | `-P` | required | Certificate profile (e.g., ec/tls-server) |
| `--csr` | | required | CSR file |
| `--cn` | | "" | Override common name from CSR |
| `--dns` | | "" | DNS SANs (comma-separated) |
| `--ip` | | "" | IP SANs (comma-separated) |
| `--out` | `-o` | "" | Output certificate file |
| `--days` | | 0 | Validity period (overrides profile default) |
| `--hybrid` | | "" | PQC algorithm for hybrid extension |
| `--attest-cert` | | "" | Attestation cert for ML-KEM CSR (RFC 9883) |
| `--ca-passphrase` | | "" | CA key passphrase |

**Examples:**

```bash
# From classical CSR (ECDSA, RSA)
qpki cert issue --ca-dir ./myca --profile ec/tls-server \
  --csr server.csr --out server.crt

# From PQC signature CSR (ML-DSA, SLH-DSA)
qpki cert issue --ca-dir ./myca --profile ml/tls-server-sign \
  --csr mldsa.csr --out server.crt

# From ML-KEM CSR with RFC 9883 attestation
qpki cert issue --ca-dir ./myca --profile ml-kem/client \
  --csr kem.csr --attest-cert sign.crt --out kem.crt

# From hybrid CSR (classical + PQC dual signatures)
qpki cert issue --ca-dir ./myca --profile hybrid/catalyst/tls-server \
  --csr hybrid.csr --out server.crt
```

#### credential enroll

A credential is a managed bundle of **private key(s) + certificate(s)** with coupled lifecycle management (enrollment, renewal, revocation).

`credential enroll` generates everything in one command:

```bash
qpki credential enroll --profile ec/tls-client --var cn=Alice --ca-dir ./ca

# Output: ca/credentials/<id>/
#   ├── credential.meta.json  # Metadata
#   ├── certificates.pem      # Certificate(s)
#   └── private-keys.pem      # Private key(s)
```

```bash
qpki credential enroll [flags]
```

**Note:** This is the recommended way to issue certificates. For CSR-based workflows, use `qpki cert issue`.

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--profile` | `-P` | required | Profile to use (repeatable for multi-profile) |
| `--var` | | | Variable value (e.g., `cn=example.com`). Repeatable. |
| `--var-file` | | | YAML file with variable values |
| `--ca-dir` | `-d` | ./ca | CA directory |
| `--id` | | auto | Custom credential ID |
| `--passphrase` | `-p` | "" | Passphrase for private keys |

**Examples:**

```bash
# Basic enrollment (single profile)
qpki credential enroll --profile ec/tls-client \
    --var cn=alice@example.com --var email=alice@example.com --ca-dir ./ca

# Multi-profile enrollment (crypto-agility)
qpki credential enroll --profile ec/client --profile ml/client \
    --var cn=alice@example.com --ca-dir ./ca

# Hybrid Catalyst enrollment
qpki credential enroll --profile hybrid/catalyst/tls-client \
    --var cn=alice@example.com --var email=alice@example.com --ca-dir ./ca

# TLS server with DNS SANs
qpki credential enroll --profile ec/tls-server \
    --var cn=server.example.com \
    --var dns_names=server.example.com,www.example.com --ca-dir ./ca

# With custom credential ID
qpki credential enroll --profile ec/tls-client \
    --var cn=alice@example.com --id alice-prod --ca-dir ./ca

# With passphrase protection
qpki credential enroll --profile hybrid/catalyst/tls-client \
    --var cn=alice@example.com --passphrase "secret" --ca-dir ./ca
```

**Important:** For ML-KEM (encryption) profiles, a signature profile must be listed first. This is required by RFC 9883 for proof of possession:

```bash
# Correct: signature profile before KEM profile
qpki credential enroll --profile ec/client --profile ml-kem/client \
    --var cn=alice@example.com --ca-dir ./ca

# Error: KEM profile requires a signature profile first
qpki credential enroll --profile ml-kem/client --var cn=alice@example.com --ca-dir ./ca
# Error: KEM profile "ml-kem/client" requires a signature profile first (RFC 9883)
```

### 2.6 Gestion des credentials

#### credential list

List all credentials in a CA.

```bash
qpki credential list [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--ca-dir` | `-c` | ./ca | CA directory |

**Example:**

```bash
qpki credential list --ca-dir ./ca
```

#### credential info

Show details of a specific credential.

```bash
qpki credential info <credential-id> [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--ca-dir` | `-c` | ./ca | CA directory |

**Example:**

```bash
qpki credential info alice-20250115-abc123 --ca-dir ./ca
```

#### credential rotate

Renew all certificates in a credential.

```bash
qpki credential rotate <credential-id> [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--ca-dir` | `-c` | ./ca | CA directory |
| `--profile` | `-P` | | New profile(s) for crypto migration |
| `--passphrase` | `-p` | "" | Passphrase for private keys |

**Examples:**

```bash
# Simple renewal
qpki credential rotate alice-20250115-abc123 --ca-dir ./ca

# Renew with crypto migration (add/change profiles)
qpki credential rotate alice-20250115-abc123 \
    --profile ec/client --profile ml/client --ca-dir ./ca
```

#### credential revoke

Revoke all certificates in a credential.

```bash
qpki credential revoke <credential-id> [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--ca-dir` | `-c` | ./ca | CA directory |
| `--reason` | `-r` | unspecified | Revocation reason |

**Example:**

```bash
qpki credential revoke alice-20250115-abc123 --ca-dir ./ca --reason keyCompromise
```

#### credential export

Export credential certificates.

```bash
qpki credential export <credential-id> [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--ca-dir` | `-d` | ./ca | CA directory |
| `--out` | `-o` | stdout | Output file |
| `--format` | `-f` | pem | Output format: pem, der |
| `--bundle` | `-b` | cert | Bundle type: cert, chain, all |
| `--version` | `-v` | | Export specific version |
| `--all` | | false | Export all versions |

**Bundle types:**
- `cert` - Certificate(s) only (default)
- `chain` - Certificates + issuing CA chain
- `all` - All certificates from all algorithm families

**Examples:**

```bash
# Export active certificates as PEM
qpki credential export alice-xxx --ca-dir ./ca

# Export as DER
qpki credential export alice-xxx --format der --out alice.der

# Export with full chain
qpki credential export alice-xxx --bundle chain --out alice-chain.pem

# Export a specific version
qpki credential export alice-xxx --version v20260105_abc123

# Export all versions
qpki credential export alice-xxx --all --out alice
```

#### credential activate

Activate a pending credential version after rotation.

```bash
qpki credential activate <credential-id> [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--ca-dir` | `-d` | ./ca | CA directory |
| `--version` | | (required) | Version to activate |

**Example:**

```bash
qpki credential activate alice-xxx --version v20260105_abc123
```

#### credential versions

List all versions of a credential.

```bash
qpki credential versions <credential-id> [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--ca-dir` | `-d` | ./ca | CA directory |

**Example:**

```bash
qpki credential versions alice-xxx --ca-dir ./ca
```

**Output:**
```
Credential: alice-xxx

VERSION              STATUS     PROFILES                       CREATED
-------              ------     --------                       -------
v20260101_abc123     archived   ec/tls-client                  2026-01-01
v20260105_def456     active     ec/tls-client, ml/tls-client   2026-01-05
```

#### credential import

Import an existing certificate and private key as a managed credential.

This is useful for:
- Migrating certificates issued by external CAs
- Bringing legacy certificates under PKI management
- Managing certificates not originally issued by this CA

```bash
qpki credential import [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--cert` | | (required) | Certificate file (PEM) |
| `--key` | | (required) | Private key file (PEM) |
| `--id` | | auto | Custom credential ID |
| `--passphrase` | `-p` | "" | Passphrase for private key |
| `--ca-dir` | `-d` | ./ca | CA directory |

**Note:** Imported credentials can be listed and exported, but cannot be renewed or revoked through this CA since they were not issued by it.

**Examples:**

```bash
# Import certificate and key
qpki credential import --cert server.crt --key server.key --ca-dir ./ca

# Import with custom ID
qpki credential import --cert server.crt --key server.key --id legacy-server

# Import encrypted private key
qpki credential import --cert server.crt --key server.key --passphrase "secret"
```

### 2.7 Consultation et vérification

#### cert list

List certificates in a CA.

```bash
qpki cert list [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--ca-dir` | `-d` | ./ca | CA directory |
| `--status` | | all | Filter by status (valid, revoked, expired, all) |

**Examples:**

```bash
# List all certificates
qpki cert list --ca-dir ./myca

# List only valid certificates
qpki cert list --ca-dir ./myca --status valid

# List revoked certificates
qpki cert list --ca-dir ./myca --status revoked
```

#### cert info

Display information about a certificate.

```bash
qpki cert info <serial> [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--ca-dir` | `-d` | ./ca | CA directory |

**Example:**

```bash
qpki cert info 0x03 --ca-dir ./myca
```

#### inspect

Display information about certificates or keys.

```bash
qpki inspect <file> [flags]
```

**Examples:**

```bash
# Show certificate details
qpki inspect certificate.crt

# Show key information
qpki inspect private.key

# Show CA certificate
qpki inspect ./myca/ca.crt
```

#### verify

Verify a certificate's validity and revocation status.

```bash
qpki verify [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--cert` | | required | Certificate to verify (PEM) |
| `--ca` | | required | CA certificate (PEM) |
| `--crl` | | | CRL file for revocation check (PEM/DER) |
| `--ocsp` | | | OCSP responder URL |

**Checks performed:**
- Certificate signature (signed by CA)
- Validity period (not before / not after)
- Revocation status (if --crl or --ocsp provided)

**Examples:**

```bash
# Basic validation
qpki verify --cert server.crt --ca ca.crt

# With CRL check
qpki verify --cert server.crt --ca ca.crt --crl ca/crl/ca.crl

# With OCSP check
qpki verify --cert server.crt --ca ca.crt --ocsp http://localhost:8080
```

**Exit codes:**
- 0: Certificate is valid
- 1: Certificate is invalid, expired, or revoked

### 2.8 Révocation

#### cert revoke

Revoke a certificate.

```bash
qpki cert revoke <serial> [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--ca-dir` | `-d` | ./ca | CA directory |
| `--reason` | `-r` | unspecified | Revocation reason |
| `--gen-crl` | | false | Generate CRL after revocation |
| `--crl-days` | | 7 | CRL validity in days |
| `--ca-passphrase` | | "" | CA key passphrase |

**Revocation Reasons:**

| Reason | Description |
|--------|-------------|
| unspecified | No specific reason |
| keyCompromise | Private key was compromised |
| caCompromise | CA key was compromised |
| affiliationChanged | Subject's affiliation changed |
| superseded | Replaced by new certificate |
| cessation | Certificate no longer needed |
| hold | Temporary hold |

**Examples:**

```bash
# Revoke by serial number
qpki cert revoke 02 --ca-dir ./myca --reason superseded

# Revoke and generate CRL
qpki cert revoke 02 --ca-dir ./myca --reason keyCompromise --gen-crl

# Revoke with CRL valid for 30 days
qpki cert revoke 02 --ca-dir ./myca --gen-crl --crl-days 30
```

#### crl gen

Generate a Certificate Revocation List.

```bash
qpki crl gen [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--ca-dir` | `-d` | ./ca | CA directory |
| `--days` | | 7 | CRL validity in days |
| `--ca-passphrase` | | "" | CA key passphrase |
| `--algo` | | "" | Algorithm family (ec, ml-dsa, etc.) - multi-profile CA only |
| `--all` | | false | Generate CRLs for all algorithm families |

**Examples:**

```bash
# Generate CRL valid for 7 days
qpki crl gen --ca-dir ./myca

# Generate CRL valid for 30 days
qpki crl gen --ca-dir ./myca --days 30

# For multi-profile CA: generate CRL for specific algorithm
qpki crl gen --ca-dir ./myca --algo ec

# For multi-profile CA: generate all CRLs
qpki crl gen --ca-dir ./myca --all
```

#### crl info

Display detailed information about a Certificate Revocation List.

```bash
qpki crl info <crl-file>
```

**Output includes:**
- Issuer name
- This Update / Next Update timestamps
- Signature algorithm
- CRL Number (if present)
- Authority Key Identifier
- Number of revoked certificates
- Expiry status
- List of revoked serials with revocation date and reason

**Examples:**

```bash
# Display CRL information
qpki crl info ./ca/crl/ca.crl

# Works with PEM or DER format
qpki crl info /path/to/crl.pem
```

#### crl verify

Verify the signature of a Certificate Revocation List.

```bash
qpki crl verify <crl-file> [flags]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--ca` | (required) | CA certificate (PEM) |
| `--check-expiry` | false | Also check if CRL is expired |

**Examples:**

```bash
# Verify CRL signature
qpki crl verify ./ca/crl/ca.crl --ca ./ca/ca.crt

# Verify signature and check expiration
qpki crl verify ./ca/crl/ca.crl --ca ./ca/ca.crt --check-expiry
```

#### crl list

List all CRLs in a CA directory.

```bash
qpki crl list [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--ca-dir` | `-d` | ./ca | CA directory |

**Output columns:**
- NAME: CRL filename
- THIS UPDATE: When the CRL was generated
- NEXT UPDATE: When the CRL expires
- REVOKED: Number of revoked certificates
- STATUS: valid or EXPIRED

**Example:**

```bash
qpki crl list --ca-dir ./myca
```

### 2.9 Profils

#### profile list

List available certificate profiles.

```bash
qpki profile list [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--dir` | `-d` | ./ca | CA directory |

**Example:**

```bash
qpki profile list --dir ./ca
```

#### profile info

Show details of a specific profile.

```bash
qpki profile info <name> [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--dir` | `-d` | ./ca | CA directory |

**Example:**

```bash
qpki profile info ec/tls-server --dir ./ca
```

#### profile vars

List all variables defined in a profile.

Shows variable names, types, constraints (required, pattern, enum), and default values.

```bash
qpki profile vars <name>
```

**Output columns:**
- NAME: Variable name
- TYPE: Variable type (string, string_list, int, etc.)
- REQUIRED: Whether the variable is required
- DEFAULT: Default value if any
- DESCRIPTION: Variable description

**Examples:**

```bash
# List variables for a builtin profile
qpki profile vars ec/tls-server

# List variables for a custom profile file
qpki profile vars ./my-profile.yaml
```

#### profile show

Display the raw YAML content of a profile.

Useful for exporting profiles via shell redirection.

```bash
qpki profile show <name>
```

**Examples:**

```bash
# Display profile YAML
qpki profile show ec/tls-server

# Export to file via redirection
qpki profile show ec/tls-server > my-tls-server.yaml
```

#### profile export

Export a builtin profile to a YAML file for customization.

```bash
qpki profile export <name> <file>
qpki profile export --all <directory>
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--all` | false | Export all builtin profiles to directory |

**Examples:**

```bash
# Export a single profile
qpki profile export ec/tls-server ./my-tls-server.yaml

# Export all builtin profiles to a directory
qpki profile export --all ./templates/
```

#### profile lint

Validate a profile YAML file for correctness.

```bash
qpki profile lint <file>
```

**Example:**

```bash
qpki profile lint my-profile.yaml
```

#### profile install

Install default profiles to a CA directory.

```bash
qpki profile install [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--dir` | `-d` | ./ca | CA directory |
| `--overwrite` | | false | Overwrite existing profiles |

**Example:**

```bash
qpki profile install --dir ./ca
```

## 3. Credentials

Credentials group related certificates with a **coupled lifecycle** - all certificates in a credential are created, renewed, and revoked together.

### 3.1 Credential Structure

```
credentials/<credential-id>/
├── credential.meta.json  # Metadata (status, certificates, validity)
├── certificates.pem      # All certificates (PEM, concatenated)
└── private-keys.pem      # All private keys (PEM, encrypted)
```

### 3.2 Certificate Roles

| Role | Description |
|------|-------------|
| `signature` | Standard signature certificate |
| `signature-classical` | Classical signature in hybrid-separate mode |
| `signature-pqc` | PQC signature in hybrid-separate mode |
| `encryption` | Standard encryption certificate |
| `encryption-classical` | Classical encryption in hybrid-separate mode |
| `encryption-pqc` | PQC encryption in hybrid-separate mode |

### 3.3 Credential Status

| Status | Description |
|--------|-------------|
| `pending` | Credential created but not yet active |
| `valid` | Credential is active and usable |
| `expired` | Validity period has ended |
| `revoked` | Credential was revoked (all certs added to CRL) |

### 3.4 Lifecycle Workflow

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

## 4. Common Workflows

### 4.1 Set Up a Two-Tier PKI

```bash
# 1. Create root CA (keep offline)
qpki ca init --profile ec/root-ca --dir ./root-ca \
  --var cn="Root CA" --var organization="My Company"

# 2. Create issuing CA (signed by root, with full CA structure)
qpki ca init --profile ec/issuing-ca --dir ./issuing-ca \
  --parent ./root-ca --var cn="Issuing CA"

# 3. Issue server certificates from issuing CA
qpki credential enroll --ca-dir ./issuing-ca --profile ec/tls-server \
  --var cn=www.example.com \
  --var dns_names=www.example.com,example.com

# 4. Verify the chain
openssl verify -CAfile ./root-ca/ca.crt ./issuing-ca/ca.crt
```

The `--parent` flag automatically:
- Generates a new key for the subordinate CA
- Issues a CA certificate signed by the parent
- Creates the full CA directory structure
- Generates `chain.crt` with the certificate chain

### 4.2 Set Up mTLS

```bash
# 1. Create CA
qpki ca init --profile ec/root-ca --dir ./mtls-ca --var cn="mTLS CA"

# 2. Issue server certificate
qpki credential enroll --ca-dir ./mtls-ca --profile ec/tls-server \
  --var cn=server.local --var dns_names=server.local

# 3. Issue client certificates
qpki credential enroll --ca-dir ./mtls-ca --profile ec/tls-client \
  --var cn=client-a@example.com --id client-a

qpki credential enroll --ca-dir ./mtls-ca --profile ec/tls-client \
  --var cn=client-b@example.com --id client-b

# 4. Configure server (example with nginx)
# ssl_certificate server.crt;
# ssl_certificate_key server.key;
# ssl_client_certificate mtls-ca/ca.crt;
# ssl_verify_client on;
```

### 4.3 Certificate Rotation with Credentials

```bash
# 1. Renew credential before expiration
qpki credential rotate <credential-id> --ca-dir ./myca

# 2. Deploy new certificates from credential

# 3. Old certificates expire naturally
# Or revoke if needed:
qpki credential revoke <old-credential-id> --ca-dir ./myca --reason superseded
```

### 4.4 Crypto-Agility Migration

```bash
# Start with classical certificates
qpki credential enroll --profile ec/client --var cn=alice@example.com --ca-dir ./ca

# Later: add PQC during renewal
qpki credential rotate alice-20250115-abc123 \
    --profile ec/client --profile ml/client --ca-dir ./ca

# Eventually: remove classical algorithms
qpki credential rotate alice-20250615-def456 \
    --profile ml/client --ca-dir ./ca
```

## 5. Troubleshooting

### 5.1 Common Errors

**"CA not found"**
```
Error: CA not found at ./ca
```
Solution: Specify the correct CA directory with `--ca-dir`.

**"Failed to load CA signer"**
```
Error: failed to load CA signer: x509: decryption password incorrect
```
Solution: Provide the correct passphrase with `--ca-passphrase`.

**"Certificate not found"**
```
Error: certificate with serial 05 not found
```
Solution: Check the serial number with `qpki cert list --ca-dir ./myca`.

### 5.2 Verifying Certificates with OpenSSL

```bash
# Verify certificate chain (using chain.crt from subordinate CA)
openssl verify -CAfile root-ca/ca.crt -untrusted issuing-ca/chain.crt server.crt

# Or verify step by step
openssl verify -CAfile root-ca/ca.crt issuing-ca/ca.crt
openssl verify -CAfile root-ca/ca.crt -untrusted issuing-ca/ca.crt server.crt

# View certificate details
openssl x509 -in server.crt -text -noout

# Check certificate dates
openssl x509 -in server.crt -dates -noout

# Verify CRL
openssl crl -in ca/crl/ca.crl -text -noout
```

### 5.3 Debugging

Enable verbose output:
```bash
qpki --debug issue --ca-dir ./myca ...
```

Check CA index:
```bash
cat ./myca/index.txt
```

Check serial number:
```bash
cat ./myca/serial
```

## 6. FAQ

### Q: How do I create a CA with a custom validity period?

Use the `--validity` flag (in years for CA, days for end-entity):
```bash
qpki ca init --profile ec/root-ca --dir ./ca --var cn="Long-lived CA" --validity 30
```

### Q: Can I use my own private key?

Yes, generate a key first, then create a CSR:
```bash
qpki key gen --algorithm ecdsa-p384 --out mykey.pem
openssl req -new -key mykey.pem -out myreq.csr
qpki cert issue --ca-dir ./myca --csr myreq.csr --out mycert.crt
```

### Q: How do I back up my CA?

Simply copy the entire CA directory:
```bash
tar -czf ca-backup-$(date +%Y%m%d).tar.gz ./myca
```

### Q: Is the PQC extension compatible with browsers?

The PQC extension is non-critical and will be ignored by browsers. The classical signature is used for TLS. The PQC material is for future use or application-level verification.

### Q: What's the difference between ml-dsa-44, ml-dsa-65, and ml-dsa-87?

These correspond to NIST security levels:
- **ml-dsa-44**: Level 1 (equivalent to AES-128)
- **ml-dsa-65**: Level 3 (equivalent to AES-192)
- **ml-dsa-87**: Level 5 (equivalent to AES-256)

Higher levels provide more security but produce larger signatures.

## See Also

- [Quick Start](../README.md#quick-start) - Get started in 5 minutes
- [PROFILES](PROFILES.md) - Certificate profile templates
- [CONCEPTS](CONCEPTS.md) - PQC and hybrid certificate concepts
- [OPERATIONS](OPERATIONS.md) - OCSP, TSA, and audit operations
