---
title: "Audit Logging"
description: "This guide covers the audit logging system for compliance and SIEM integration."
---

# Audit Logging

This guide covers the audit logging system for compliance and SIEM integration.

## 1. What is Audit Logging?

The audit system provides **tamper-evident logging** for PKI operations. It is designed for compliance (eIDAS, ETSI EN 319 401) and SIEM integration.

### Core Principles

1. **Strict separation**: Audit logs are distinct from technical logs
2. **Write guarantee**: If audit fails → operation fails
3. **Cryptographic chaining**: Detects any modification or deletion
4. **No secrets**: No private keys or passphrases in logs

---

## 2. Activation

**Via CLI flag:**
```bash
qpki --audit-log /var/log/pki/audit.jsonl ca init --profile ec/root-ca --var cn="Root CA"
```

**Via environment variable:**
```bash
export PKI_AUDIT_LOG=/var/log/pki/audit.jsonl
qpki ca init --profile ec/root-ca --var cn="Root CA"
```

---

## 3. Event Format

Each event is stored in JSON Lines (JSONL), one line per event:

```json
{
  "event_type": "CERT_ISSUED",
  "timestamp": "2025-01-15T14:30:22Z",
  "actor": {
    "type": "user",
    "id": "admin",
    "host": "ca-server"
  },
  "object": {
    "type": "certificate",
    "serial": "0x03",
    "subject": "CN=server.example.com"
  },
  "context": {
    "profile": "tls-server",
    "ca": "/var/lib/pki/issuing-ca",
    "algorithm": "ECDSA-SHA256"
  },
  "result": "success",
  "hash_prev": "sha256:abc123...",
  "hash": "sha256:def456..."
}
```

---

## 4. Event Types

| Type | Trigger |
|------|---------|
| `CA_CREATED` | New CA created (root or issuing) |
| `CA_LOADED` | Existing CA loaded |
| `KEY_ACCESSED` | CA private key accessed |
| `CERT_ISSUED` | Certificate issued |
| `CERT_REVOKED` | Certificate revoked |
| `CRL_GENERATED` | CRL generated |
| `AUTH_FAILED` | Authentication failed (wrong passphrase) |
| `OCSP_SIGN` | OCSP response created |
| `OCSP_REQUEST` | OCSP request received |
| `TSA_SIGN` | Timestamp token created |
| `TSA_REQUEST` | Timestamp request received |

---

## 5. Cryptographic Chaining

Each event is linked to the previous by SHA-256 hash:

```
H(n) = SHA256( canonical_json(event_n) || H(n-1) )
```

- First event: `hash_prev = "sha256:genesis"`
- Hash is calculated on canonical JSON (without `hash` field)

**Detects:**
- **Modification**: Recalculated hash doesn't match
- **Deletion**: Chain is broken
- **Insertion**: hash_prev doesn't match

---

## 6. Verification

```bash
# Verify log integrity
qpki audit verify --log /var/log/pki/audit.jsonl

qpki audit tail --log /var/log/pki/audit.jsonl --count 20

qpki audit tail --log /var/log/pki/audit.jsonl --json
```

**Verification output:**
```
Verifying audit log: /var/log/pki/audit.jsonl

VERIFICATION PASSED
  Total events: 42
  Hash chain: VALID
```

---

## 7. SIEM Integration

### Splunk

Configuration `inputs.conf`:
```ini
[monitor:///var/log/pki/audit.jsonl]
sourcetype = pki:audit
index = security
```

Query example:
```spl
index=security sourcetype=pki:audit event_type=AUTH_FAILED
| stats count by actor.id, actor.host
```

### Elastic (Filebeat)

Configuration `filebeat.yml`:
```yaml
filebeat.inputs:
  - type: log
    paths:
      - /var/log/pki/audit.jsonl
    json.keys_under_root: true
    json.add_error_key: true
    fields:
      log_type: pki_audit
    fields_under_root: true

output.elasticsearch:
  hosts: ["localhost:9200"]
  index: "pki-audit-%{+yyyy.MM.dd}"
```

Query example:
```
event_type: "CERT_REVOKED" AND context.reason: "keyCompromise"
```

---

## 8. ETSI EN 319 401 Compliance

| Requirement | Implementation |
|-------------|----------------|
| 7.5.1 Logging | All CA events are logged |
| 7.5.2 Integrity | SHA-256 hash chain |
| 7.5.3 Protection | File with fsync, permissions 0600 |
| 7.5.4 Retention | JSONL file, SIEM archiving |

---

## 9. Best Practices

### File Permissions

```bash
# Create directory with restrictive permissions
sudo mkdir -p /var/log/pki
sudo chmod 700 /var/log/pki
```

### Log Rotation (logrotate)

```
/var/log/pki/audit.jsonl {
    daily
    rotate 365
    compress
    delaycompress
    notifempty
    create 0600 root root
    postrotate
        # Verify integrity before archiving
        qpki audit verify --log /var/log/pki/audit.jsonl.1
    endscript
}
```

### Archiving

```bash
qpki audit verify --log /var/log/pki/audit.jsonl
cp /var/log/pki/audit.jsonl /archive/pki/$(date +%Y%m%d)-audit.jsonl
```

---

## 10. Security

**What is NEVER logged:**
- Private keys
- Passphrases
- Encryption secrets
- Sensitive certificate data beyond DN

**File protection:**
- Permissions 0600 (root read/write only)
- fsync after each write
- Hash chain for integrity

---

## See Also

- [CA](../build-pki/CA.md) - CA operations that generate audit events
- [ETSI EN 319 401](https://www.etsi.org/deliver/etsi_en/319400_319499/319401/) - Trust Service Providers
