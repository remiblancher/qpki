# Audit Logging

Ce document décrit le système d'audit logging de la PKI, conçu pour la conformité (eIDAS, ETSI EN 319 401) et l'intégration SIEM.

## Principes Fondamentaux

1. **Séparation stricte** : Les logs d'audit sont distincts des logs techniques
2. **Garantie d'écriture** : Si l'audit échoue → l'opération échoue
3. **Chaînage cryptographique** : Détection de toute altération ou suppression
4. **Jamais de secrets** : Aucune clé privée ou passphrase dans les logs

## Activation

### Via flag CLI

```bash
pki --audit-log /var/log/pki/audit.jsonl ca init --name "Root CA"
```

### Via variable d'environnement

```bash
export PKI_AUDIT_LOG=/var/log/pki/audit.jsonl
pki ca init --name "Root CA"
```

## Format des Événements

Chaque événement est stocké en JSON Lines (JSONL), une ligne par événement :

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

### Champs

| Champ | Type | Description |
|-------|------|-------------|
| `event_type` | string | Type d'événement (voir ci-dessous) |
| `timestamp` | string | Horodatage UTC RFC3339 |
| `actor.type` | string | "user", "system", "service" |
| `actor.id` | string | Identifiant de l'acteur |
| `actor.host` | string | Hostname de la machine |
| `object.type` | string | "ca", "certificate", "crl", "key" |
| `object.serial` | string | Numéro de série (certificats) |
| `object.subject` | string | DN du sujet |
| `object.path` | string | Chemin fichier/CA |
| `context.profile` | string | Profil de certificat utilisé |
| `context.ca` | string | Chemin de la CA |
| `context.algorithm` | string | Algorithme cryptographique |
| `context.reason` | string | Raison (révocation, échec) |
| `result` | string | "success" ou "failure" |
| `hash_prev` | string | Hash SHA-256 de l'événement précédent |
| `hash` | string | Hash SHA-256 de cet événement |

## Types d'Événements

| Type | Déclencheur |
|------|-------------|
| `CA_CREATED` | Création d'une nouvelle CA (root ou issuing) |
| `CA_LOADED` | Chargement d'une CA existante |
| `KEY_ACCESSED` | Accès à la clé privée CA |
| `CERT_ISSUED` | Émission d'un certificat |
| `CERT_REVOKED` | Révocation d'un certificat |
| `CRL_GENERATED` | Génération d'une CRL |
| `AUTH_FAILED` | Échec d'authentification (mauvaise passphrase) |

## Chaînage Cryptographique

Chaque événement est lié au précédent par un hash SHA-256 :

```
H(n) = SHA256( canonical_json(event_n) || H(n-1) )
```

- Premier événement : `hash_prev = "sha256:genesis"`
- Le hash est calculé sur le JSON canonique (sans le champ `hash`)

### Détection d'altération

Le chaînage permet de détecter :
- **Modification** : Le hash recalculé ne correspond plus
- **Suppression** : La chaîne est brisée
- **Insertion** : Le hash_prev ne correspond pas

## Vérification

### CLI

```bash
# Vérifier l'intégrité du log
pki audit verify --log /var/log/pki/audit.jsonl

# Afficher les derniers événements
pki audit tail --log /var/log/pki/audit.jsonl -n 20

# Sortie JSON
pki audit tail --log /var/log/pki/audit.jsonl --json
```

### Sortie de vérification

```
Verifying audit log: /var/log/pki/audit.jsonl

VERIFICATION PASSED
  Total events: 42
  Hash chain: VALID
```

En cas d'altération :

```
VERIFICATION FAILED
  Valid events: 15
  Error: line 16: hash mismatch: expected=sha256:abc..., got=sha256:def...
```

## Intégration SIEM

Les logs d'audit sont conçus pour être ingérés par des SIEM (Splunk, Elastic, etc.).

### Splunk

Configuration `inputs.conf` :

```ini
[monitor:///var/log/pki/audit.jsonl]
sourcetype = pki:audit
index = security
```

### Elastic (Filebeat)

Configuration `filebeat.yml` :

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

### Requêtes d'exemple

**Splunk SPL** :
```spl
index=security sourcetype=pki:audit event_type=AUTH_FAILED
| stats count by actor.id, actor.host
```

**Elastic KQL** :
```
event_type: "CERT_REVOKED" AND context.reason: "keyCompromise"
```

## Conformité ETSI EN 319 401

Le système d'audit répond aux exigences ETSI EN 319 401 :

| Exigence | Implémentation |
|----------|----------------|
| 7.5.1 Journalisation | Tous les événements CA sont journalisés |
| 7.5.2 Intégrité | Hash chain SHA-256 |
| 7.5.3 Protection | Fichier avec fsync, permissions 0600 |
| 7.5.4 Conservation | Fichier JSONL, archivage SIEM |

## Bonnes Pratiques

### Permissions fichier

```bash
# Créer le répertoire avec permissions restrictives
sudo mkdir -p /var/log/pki
sudo chmod 700 /var/log/pki

# Rotation des logs
sudo logrotate -d /etc/logrotate.d/pki
```

### Rotation (logrotate)

```
/var/log/pki/audit.jsonl {
    daily
    rotate 365
    compress
    delaycompress
    notifempty
    create 0600 root root
    postrotate
        # Vérifier l'intégrité avant archivage
        pki audit verify --log /var/log/pki/audit.jsonl.1
    endscript
}
```

### Archivage

Avant rotation, vérifiez l'intégrité :

```bash
pki audit verify --log /var/log/pki/audit.jsonl
cp /var/log/pki/audit.jsonl /archive/pki/$(date +%Y%m%d)-audit.jsonl
```

## Architecture

```
internal/audit/
├── event.go        # Event struct, EventType constants
├── writer.go       # Interface Writer (garantie fsync)
├── file_writer.go  # Implémentation fichier + hash chain
├── audit.go        # Logger global, Init(), MustLog()
└── audit_test.go   # Tests
```

### Principe "Audit fails = Operation fails"

```go
cert, err := ca.Issue(req)
if err != nil {
    return nil, err
}

// Si l'audit échoue, l'opération entière échoue
if err := audit.LogCertIssued(...); err != nil {
    return nil, err
}

return cert, nil
```

## Sécurité

### Ce qui n'est JAMAIS loggé

- Clés privées
- Passphrases
- Secrets de chiffrement
- Données sensibles des certificats au-delà du DN

### Protection du fichier d'audit

- Permissions 0600 (lecture/écriture root uniquement)
- fsync après chaque écriture
- Hash chain pour intégrité
