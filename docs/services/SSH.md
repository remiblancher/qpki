---
title: "SSH Certificates"
description: "SSH certificate issuance and management using OpenSSH certificate format."
---

# SSH Certificates

This guide covers SSH certificate management using the OpenSSH certificate format (PROTOCOL.certkeys).

## 1. What are SSH Certificates?

**SSH certificates** replace static key-based authentication with short-lived, auditable, scoped credentials signed by a trusted Certificate Authority.

### SSH Keys vs SSH Certificates

| Criterion | SSH Keys | SSH Certificates |
|-----------|----------|-----------------|
| Trust model | Per-key (`authorized_keys`) | CA-based (`TrustedUserCAKeys`) |
| Expiration | None (manual revocation) | Built-in validity period |
| Scope | Full access | Principals, force-command, source-address |
| Provisioning | Copy public key to each server | Sign once, accepted everywhere |
| Audit | Key fingerprint only | Key ID, serial, principals |
| Rotation | Replace key on all servers | Re-sign, no server changes |

### User vs Host Certificates

| Type | Purpose | Principals | Typical Validity |
|------|---------|------------|-----------------|
| **User** | Authenticate users to servers | Usernames (alice, deploy) | 8h - 24h |
| **Host** | Authenticate servers to clients | Hostnames, IPs | 30 - 90 days |

---

## 2. SSH CA Management

### ssh ca-init

Initialize a new SSH Certificate Authority.

```bash
# User CA (recommended: Ed25519)
qpki ssh ca-init --name user-ca --algorithm ed25519 --type user --ca-dir ./ssh-user-ca

# Host CA (separate from user CA)
qpki ssh ca-init --name host-ca --algorithm ed25519 --type host --ca-dir ./ssh-host-ca

# With ECDSA
qpki ssh ca-init --name user-ca --algorithm ecdsa-p256 --type user --ca-dir ./ssh-user-ca
```

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--name` | CA name | Required |
| `--algorithm` | Key algorithm | `ed25519` |
| `--type` | Certificate type: `user` or `host` | Required |
| `--ca-dir` | CA directory | Required |

**Directory structure created:**

```
ssh-user-ca/
  ssh-ca.meta.json    # CA metadata (name, algorithm, cert type)
  ssh-ca.pub          # CA public key (authorized_keys format)
  ssh-ca.key          # CA private key (PEM)
  serial              # Next serial number (decimal)
  certs/              # Issued certificates ({serial}-cert.pub)
  krl/                # Key Revocation Lists
  index.json          # Certificate index (JSON)
```

### ssh ca-info

Display SSH CA information.

```bash
qpki ssh ca-info --ca-dir ./ssh-user-ca
```

Output:
```
SSH Certificate Authority

  Name:        user-ca
  Type:        user
  Algorithm:   ed25519
  Fingerprint: SHA256:abc123...
  Created:     2026-03-10T10:00:00Z
  Directory:   ./ssh-user-ca

  Certificates: 12 total (11 valid, 1 revoked)
```

---

## 3. Issuing Certificates

### ssh issue

Issue an SSH certificate signed by the specified CA.

```bash
# User certificate (8h validity)
qpki ssh issue --ca-dir ./ssh-user-ca \
    --public-key ~/.ssh/id_ed25519.pub \
    --key-id alice@example.com \
    --principals alice,deploy \
    --validity 8h \
    --out ~/.ssh/id_ed25519-cert.pub

# Host certificate (90 days)
qpki ssh issue --ca-dir ./ssh-host-ca \
    --public-key /etc/ssh/ssh_host_ed25519_key.pub \
    --key-id web01.example.com \
    --principals web01.example.com,192.168.1.10 \
    --validity 2160h \
    --out /etc/ssh/ssh_host_ed25519_key-cert.pub

# Restricted certificate (CI/CD)
qpki ssh issue --ca-dir ./ssh-user-ca \
    --public-key ci-key.pub \
    --key-id ci@example.com \
    --principals deploy \
    --validity 1h \
    --force-command "/usr/bin/deploy.sh" \
    --source-address "10.0.0.0/8" \
    --no-pty \
    --out ci-cert.pub
```

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--ca-dir` | CA directory | Required |
| `--public-key` | Path to subject's public key | Required |
| `--key-id` | Human-readable certificate identifier | Required |
| `--principals` | Comma-separated principals | Required |
| `--validity` | Certificate validity duration | `8h` |
| `--passphrase` | CA key passphrase | - |
| `--out` | Output file | stdout |
| `--force-command` | Force a specific command (critical option) | - |
| `--source-address` | Restrict to source IPs/CIDRs (critical option) | - |
| `--no-pty` | Disable pseudo-terminal allocation | false |
| `--no-port-forwarding` | Disable port forwarding | false |
| `--no-agent-forwarding` | Disable agent forwarding | false |

### Extensions and Critical Options

**Extensions** (permissions, user certificates only):

| Extension | Default | Description |
|-----------|---------|-------------|
| `permit-pty` | Enabled | Allow pseudo-terminal allocation |
| `permit-port-forwarding` | Enabled | Allow port forwarding |
| `permit-agent-forwarding` | Enabled | Allow SSH agent forwarding |
| `permit-X11-forwarding` | Enabled | Allow X11 forwarding |
| `permit-user-rc` | Enabled | Allow execution of `~/.ssh/rc` |

**Critical options** (restrictions, enforced by sshd):

| Option | Description |
|--------|-------------|
| `force-command` | Only the specified command can be executed |
| `source-address` | Restrict to specific IPs/CIDRs (comma-separated) |

---

## 4. Inspecting Certificates

### ssh inspect

Display detailed information about an SSH certificate.

```bash
qpki ssh inspect ~/.ssh/id_ed25519-cert.pub
```

Output:
```
SSH Certificate:

  Type:          user certificate
  Serial:        1
  Key ID:        alice@example.com
  Principals:    alice, deploy
  Valid After:   2026-03-10T10:00:00Z
  Valid Before:  2026-03-10T18:00:00Z
  Status:        VALID
  Key Type:      ssh-ed25519
  Fingerprint:   SHA256:abc123...
  Signing CA:    SHA256:def456...

  Extensions:
    permit-pty
    permit-port-forwarding
    permit-agent-forwarding
    permit-X11-forwarding
    permit-user-rc
```

**Cross-validation with OpenSSH:**

```bash
# OpenSSH native inspection
ssh-keygen -L -f ~/.ssh/id_ed25519-cert.pub
```

### ssh list

List all certificates issued by a CA.

```bash
qpki ssh list --ca-dir ./ssh-user-ca
```

Output:
```
SERIAL   STATUS TYPE   KEY ID                         PRINCIPALS                               VALID BEFORE
------------------------------------------------------------------------------------------------------------------------
1        V      user   alice@example.com              alice,deploy                             2026-03-10 18:00
2        V      user   bob@example.com                bob                                      2026-03-10 20:00
3        R      user   ci@example.com                 deploy                                   2026-03-10 11:00
```

---

## 5. Deployment Guide

### User Certificate Authentication

```
┌──────────────────┐         ┌──────────────────┐         ┌──────────────────┐
│   qpki CA        │  sign   │   User Client    │  auth   │   SSH Server     │
│   (ssh-user-ca)  │────────>│   (cert + key)   │────────>│   (sshd)         │
│                  │         │                  │         │                  │
│   ssh-ca.pub ────│─────────│─────────────────>│─────────│─> TrustedUser    │
│                  │         │                  │         │   CAKeys         │
└──────────────────┘         └──────────────────┘         └──────────────────┘
```

**Step 1: Initialize the CA**

```bash
qpki ssh ca-init --name user-ca --algorithm ed25519 --type user --ca-dir ./ssh-user-ca
```

**Step 2: Configure sshd**

```bash
# Copy CA public key to server
scp ./ssh-user-ca/ssh-ca.pub server:/etc/ssh/user-ca.pub

# On the server, add to /etc/ssh/sshd_config:
TrustedUserCAKeys /etc/ssh/user-ca.pub

# Optionally restrict principals per user:
AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u

# Restart sshd
systemctl restart sshd
```

**Step 3: Issue a certificate**

```bash
qpki ssh issue --ca-dir ./ssh-user-ca \
    --public-key ~/.ssh/id_ed25519.pub \
    --key-id alice@example.com \
    --principals alice \
    --validity 8h \
    --out ~/.ssh/id_ed25519-cert.pub
```

**Step 4: Connect**

```bash
# SSH automatically uses the cert if named {key}-cert.pub
ssh alice@server
```

### Host Certificate Authentication

**Step 1: Initialize the host CA**

```bash
qpki ssh ca-init --name host-ca --algorithm ed25519 --type host --ca-dir ./ssh-host-ca
```

**Step 2: Issue a host certificate**

```bash
qpki ssh issue --ca-dir ./ssh-host-ca \
    --public-key /etc/ssh/ssh_host_ed25519_key.pub \
    --key-id web01.example.com \
    --principals web01.example.com,192.168.1.10 \
    --validity 2160h \
    --out /etc/ssh/ssh_host_ed25519_key-cert.pub
```

**Step 3: Configure sshd**

```bash
# Add to /etc/ssh/sshd_config:
HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
```

**Step 4: Configure clients**

```bash
# Add to ~/.ssh/known_hosts:
@cert-authority *.example.com ssh-ed25519 AAAA... (contents of ssh-host-ca/ssh-ca.pub)
```

---

## 6. Certificate Revocation and KRL

SSH certificates can be revoked using OpenSSH Key Revocation Lists (KRL).
KRL is a compact binary format defined in OpenSSH `PROTOCOL.krl` that lists revoked
certificates. It integrates directly with `sshd` via the `RevokedKeys` directive.

### ssh revoke

Revoke a certificate by serial number. This updates the CA index and generates an updated KRL.

```bash
qpki ssh revoke --ca-dir ./ssh-user-ca --serial 3
```

Output:
```
Certificate serial 3 revoked.
KRL updated: ./ssh-user-ca/krl/krl.bin

To use with sshd, add to sshd_config:
  RevokedKeys ./ssh-user-ca/krl/krl.bin
```

### ssh krl

Generate or regenerate a KRL from all revoked certificates.

```bash
# Generate KRL (saved to CA directory)
qpki ssh krl --ca-dir ./ssh-user-ca

# Generate KRL to a custom path
qpki ssh krl --ca-dir ./ssh-user-ca --out /etc/ssh/krl.bin --comment "Production KRL"
```

Output:
```
KRL generated: /etc/ssh/krl.bin
  Revoked certificates: 2
  KRL size: 143 bytes
```

### Deploying KRL

**Step 1: Configure sshd**

```
# /etc/ssh/sshd_config
RevokedKeys /etc/ssh/krl.bin
```

**Step 2: Validate with ssh-keygen**

```bash
# Check if a certificate is revoked
ssh-keygen -Q -f /etc/ssh/krl.bin cert.pub

# Output for revoked cert: "cert.pub: REVOKED"
# Output for valid cert:   "cert.pub: ok"
```

**Step 3: Automate distribution**

Distribute the KRL to all servers after each revocation (e.g., via Ansible, rsync, or a configuration management tool).

> **Note:** Unlike OCSP, KRL is a static file — `sshd` reads it at connection time without network access. Update the file on each server to propagate revocations.

---

## 7. SSH Profiles

QPKI provides built-in SSH profiles in `profiles/ssh/`. Profiles define
validity, extensions, and critical options so that `ssh issue` commands
remain short and reproducible.

### Usage with `--profile`

```bash
# Issue a user certificate using the default profile
qpki ssh issue --ca-dir ./ssh-user-ca \
    --profile ssh/user-default \
    --public-key ~/.ssh/id_ed25519.pub \
    --key-id alice@example.com \
    --principals alice,deploy

# Same thing using --var instead of --key-id / --principals
qpki ssh issue --ca-dir ./ssh-user-ca \
    --profile ssh/user-default \
    --public-key ~/.ssh/id_ed25519.pub \
    --var key_id=alice@example.com \
    --var principals=alice,deploy

# Override validity from profile (8h → 1h)
qpki ssh issue --ca-dir ./ssh-user-ca \
    --profile ssh/user-default \
    --public-key ~/.ssh/id_ed25519.pub \
    --key-id ci@example.com \
    --principals deploy \
    --validity 1h
```

When `--profile` is used:
- **Validity** comes from the profile (unless `--validity` is explicitly set).
- **Extensions** (permit-pty, permit-port-forwarding, etc.) come from the profile. Explicit flags (`--no-pty`, `--force-command`, etc.) override profile values.
- **key_id** and **principals** can be provided via `--key-id`/`--principals` flags or `--var key_id=…`/`--var principals=…`.

### user-default.yaml

Default user certificate profile: Ed25519, 8h validity.

```yaml
name: ssh/user-default
description: "SSH user certificate Ed25519 (short-lived, 8h)"
cert_type: ssh
algorithm: ed25519
validity: 8h

variables:
  key_id:
    type: string
    required: true
    description: "Key identifier (usually email or username)"
  principals:
    type: list
    required: true
    description: "Allowed usernames on target servers"

ssh_extensions:
  type: user
  permissions:
    permit_pty: true
    permit_port_forwarding: true
    permit_agent_forwarding: true
    permit_x11_forwarding: false
    permit_user_rc: true
```

### host-default.yaml

Default host certificate profile: Ed25519, 90 days validity.

```yaml
name: ssh/host-default
description: "SSH host certificate Ed25519 (90 days)"
cert_type: ssh
algorithm: ed25519
validity: 2160h

variables:
  key_id:
    type: string
    required: true
    description: "Key identifier (usually hostname FQDN)"
  principals:
    type: list
    required: true
    description: "Allowed hostnames and IP addresses"

ssh_extensions:
  type: host
```

---

## 8. Supported Algorithms

| Algorithm | SSH Certificate Type | Recommended |
|-----------|---------------------|-------------|
| `ed25519` | `ssh-ed25519-cert-v01@openssh.com` | Yes (default) |
| `ecdsa-p256` | `ecdsa-sha2-nistp256-cert-v01@openssh.com` | Yes |
| `ecdsa-p384` | `ecdsa-sha2-nistp384-cert-v01@openssh.com` | Yes |
| `ecdsa-p521` | `ecdsa-sha2-nistp521-cert-v01@openssh.com` | - |
| `rsa-2048` | `ssh-rsa-cert-v01@openssh.com` | Legacy only |
| `rsa-4096` | `ssh-rsa-cert-v01@openssh.com` | Legacy only |

> **Post-Quantum Note:** PQC algorithms (ML-DSA, SLH-DSA, ML-KEM) are **not supported** for SSH certificates. The SSH protocol has no standardized post-quantum signature algorithms. OpenSSH 10+ only supports PQ key exchange (ML-KEM), not PQ signatures. QPKI will add PQC SSH support when the protocol standardizes it. Attempting to create an SSH CA with a PQC algorithm returns an explicit error.

---

## 9. Troubleshooting

### Common Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `algorithm X is not supported for SSH` | PQC algorithm used for SSH CA | Use a classical algorithm: ed25519, ecdsa-p256, rsa-4096 |
| `SSH CA already exists` | `ca-init` on existing directory | Use a different `--ca-dir` or delete existing CA |
| `at least one principal is required` | Missing `--principals` flag | Specify at least one principal |
| `Permission denied (publickey)` | Certificate not accepted by sshd | Check: TrustedUserCAKeys configured, principals match, cert not expired |
| `no matching host certificate` | Host cert not found by sshd | Check: HostCertificate path in sshd_config, cert file permissions |

### Debugging SSH Certificate Authentication

```bash
# Verbose SSH connection (shows cert details)
ssh -vvv user@server

# Check if sshd accepts the CA
sshd -T | grep trustedusercakeys

# Verify certificate is valid
qpki ssh inspect ~/.ssh/id_ed25519-cert.pub
ssh-keygen -L -f ~/.ssh/id_ed25519-cert.pub

# Check certificate matches the key
# The cert must be named {keyfile}-cert.pub
ls -la ~/.ssh/id_ed25519.pub ~/.ssh/id_ed25519-cert.pub
```

---

## See Also

- [CA](../core-pki/CA.md) - X.509 Certificate Authority management
- [Keys](../core-pki/KEYS.md) - Key generation
- [Profiles](../core-pki/PROFILES.md) - Certificate profile system
- [HSM](../operations/HSM.md) - Hardware Security Module integration
- [OpenSSH PROTOCOL](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL) - SSH certificate format specification
- [OpenSSH PROTOCOL.krl](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.krl) - Key Revocation List format
