# OCSP - Online Certificate Status Protocol

## Vue d'ensemble

L'implémentation OCSP de PKI Quantum-Safe est conforme au **RFC 6960** (X.509 Internet PKI OCSP) et au **RFC 5019** (Lightweight OCSP Profile). Elle supporte les algorithmes classiques (ECDSA, RSA, Ed25519) ainsi que les algorithmes post-quantiques (ML-DSA) et hybrides (Catalyst).

### Pourquoi OCSP ?

| Critère | CRL | OCSP |
|---------|-----|------|
| Latence | Téléchargement complet | Requête par certificat |
| Bande passante | Élevée (liste complète) | Faible (réponse unitaire) |
| Temps réel | Non (intervalle de mise à jour) | Oui |
| Confidentialité | Aucune fuite | Le responder voit les requêtes |
| TLS Stapling | Non | Oui |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        OCSP Responder                               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────────────┐    ┌──────────────────┐    ┌──────────────┐  │
│  │  HTTP Handler    │────│    Responder     │────│   CA Store   │  │
│  │  (GET + POST)    │    │    (RFC 6960)    │    │   (index)    │  │
│  └──────────────────┘    └──────────────────┘    └──────────────┘  │
│           │                       │                      │          │
│           │                       │                      │          │
│  ┌──────────────────┐    ┌──────────────────┐    ┌──────────────┐  │
│  │  Request Parser  │    │ Response Builder │    │   Signer     │  │
│  │  (ASN.1 DER)     │    │  (BasicOCSP)     │    │  (PQC-ready) │  │
│  └──────────────────┘    └──────────────────┘    └──────────────┘  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Modes de fonctionnement

1. **Delegated Responder** (recommandé)
   - Certificat responder avec EKU `ocspSigning` (OID 1.3.6.1.5.5.7.3.9)
   - Extension OCSP No Check pour éviter la récursion
   - Clé distincte de la CA

2. **CA-Signed**
   - La CA signe directement les réponses
   - Plus simple mais moins flexible

---

## Commandes CLI

### pki ocsp sign

Crée une réponse OCSP signée pour un certificat spécifique.

```bash
# Réponse "good" pour un certificat valide
pki ocsp sign \
  --serial 0A1B2C3D \
  --status good \
  --ca ca.crt \
  --cert responder.crt \
  --key responder.key \
  --out response.ocsp

# Réponse "revoked" avec raison
pki ocsp sign \
  --serial 0A1B2C3D \
  --status revoked \
  --revocation-time "2024-01-15T10:00:00Z" \
  --revocation-reason keyCompromise \
  --ca ca.crt \
  --cert responder.crt \
  --key responder.key \
  --out response.ocsp

# Réponse "unknown" (certificat non connu)
pki ocsp sign \
  --serial 0A1B2C3D \
  --status unknown \
  --ca ca.crt \
  --cert responder.crt \
  --key responder.key \
  --out response.ocsp
```

**Options :**

| Flag | Description | Défaut |
|------|-------------|--------|
| `--serial` | Numéro de série (hex) | Requis |
| `--status` | good, revoked, unknown | Requis |
| `--ca` | Certificat CA (pour hash issuer) | Requis |
| `--cert` | Certificat responder | Requis |
| `--key` | Clé privée responder | Requis |
| `--validity` | Durée validité réponse | 1h |
| `--revocation-time` | Date révocation (RFC 3339) | - |
| `--revocation-reason` | Raison CRL (voir ci-dessous) | - |
| `-o, --out` | Fichier sortie | stdout |

**Raisons de révocation :**
- `unspecified` (0)
- `keyCompromise` (1)
- `caCompromise` (2)
- `affiliationChanged` (3)
- `superseded` (4)
- `cessationOfOperation` (5)
- `certificateHold` (6)
- `removeFromCRL` (8)
- `privilegeWithdrawn` (9)
- `aaCompromise` (10)

---

### pki ocsp verify

Vérifie une réponse OCSP.

```bash
# Vérification basique
pki ocsp verify --response response.ocsp --ca ca.crt

# Vérification avec certificat cible
pki ocsp verify \
  --response response.ocsp \
  --ca ca.crt \
  --cert server.crt

# Vérification avec nonce (replay protection)
pki ocsp verify \
  --response response.ocsp \
  --ca ca.crt \
  --nonce 0102030405060708
```

**Options :**

| Flag | Description |
|------|-------------|
| `--response` | Fichier réponse OCSP (DER) |
| `--ca` | Certificat CA |
| `--cert` | Certificat à vérifier (optionnel) |
| `--nonce` | Nonce attendu (hex, optionnel) |

**Sortie :**
```
OCSP Response Verification
  Status: successful
  Response Type: Basic OCSP Response

  Certificate Status:
    Serial: 0A1B2C3D4E5F
    Status: good
    This Update: 2024-01-15 10:00:00 UTC
    Next Update: 2024-01-15 11:00:00 UTC

  Signature: VALID
    Algorithm: ECDSA-SHA384
    Responder: CN=ACME OCSP Responder, O=ACME Industrie, C=FR
```

---

### pki ocsp request

Crée une requête OCSP.

```bash
# Requête simple
pki ocsp request \
  --ca ca.crt \
  --cert server.crt \
  --out request.ocsp

# Requête avec nonce (recommandé)
pki ocsp request \
  --ca ca.crt \
  --cert server.crt \
  --nonce \
  --out request.ocsp

# Requête par numéro de série
pki ocsp request \
  --ca ca.crt \
  --serial 0A1B2C3D \
  --out request.ocsp
```

**Options :**

| Flag | Description |
|------|-------------|
| `--ca` | Certificat CA (pour calculer issuer hash) |
| `--cert` | Certificat à vérifier |
| `--serial` | Numéro de série (alternative à --cert) |
| `--nonce` | Ajouter un nonce aléatoire |
| `-o, --out` | Fichier sortie |

---

### pki ocsp info

Affiche les informations d'une requête ou réponse OCSP.

```bash
# Info sur une requête
pki ocsp info request.ocsp

# Info sur une réponse
pki ocsp info response.ocsp
```

**Sortie (requête) :**
```
OCSP Request
  Version: 1
  Request List:
    [0] CertID:
        Hash Algorithm: SHA-256
        Issuer Name Hash: 3A7B...
        Issuer Key Hash: 9C2E...
        Serial Number: 0A1B2C3D
  Extensions:
    Nonce: 0102030405060708...
```

**Sortie (réponse) :**
```
OCSP Response
  Response Status: successful (0)
  Response Type: Basic OCSP Response

  TBS Response Data:
    Version: 1
    Responder ID: CN=ACME OCSP Responder
    Produced At: 2024-01-15 10:00:00 UTC

    Responses:
      [0] Single Response:
          Serial Number: 0A1B2C3D
          Certificate Status: good
          This Update: 2024-01-15 10:00:00 UTC
          Next Update: 2024-01-15 11:00:00 UTC

  Signature Algorithm: ecdsa-with-SHA384
  Certificates: 1 included
```

---

### pki ocsp serve

Lance un serveur HTTP OCSP responder.

```bash
# Mode delegated (certificat responder dédié)
pki ocsp serve \
  --port 8080 \
  --ca-dir /path/to/ca \
  --cert responder.crt \
  --key responder.key

# Avec validité personnalisée
pki ocsp serve \
  --port 8080 \
  --ca-dir /path/to/ca \
  --cert responder.crt \
  --key responder.key \
  --validity 24h

# Écoute sur interface spécifique
pki ocsp serve \
  --addr 192.168.1.10:8080 \
  --ca-dir /path/to/ca \
  --cert responder.crt \
  --key responder.key
```

**Options :**

| Flag | Description | Défaut |
|------|-------------|--------|
| `--port` | Port HTTP | 8080 |
| `--addr` | Adresse d'écoute complète | :8080 |
| `--ca-dir` | Répertoire CA (avec index.txt) | Requis |
| `--cert` | Certificat responder | Requis |
| `--key` | Clé privée responder | Requis |
| `--validity` | Durée validité réponses | 1h |

**Endpoints HTTP :**

| Méthode | Path | Content-Type |
|---------|------|--------------|
| GET | `/{base64-request}` | - |
| POST | `/` | `application/ocsp-request` |

**Réponse :** `application/ocsp-response` (DER)

---

## Protocole HTTP (RFC 6960 Appendix A)

### GET Request

Pour les requêtes courtes (< 255 bytes après encoding), utilisez GET :

```
GET /MEUwQwIBADBBMD8wPTAJBgUrDgMCGgUABBT... HTTP/1.1
Host: ocsp.example.com
```

Le path est la requête DER encodée en base64 (URL-safe).

### POST Request

Pour les requêtes plus longues ou signées :

```
POST / HTTP/1.1
Host: ocsp.example.com
Content-Type: application/ocsp-request
Content-Length: 128

<binary DER data>
```

### Response

```
HTTP/1.1 200 OK
Content-Type: application/ocsp-response
Content-Length: 512

<binary DER data>
```

**Codes d'erreur :**

| Status | Signification |
|--------|---------------|
| 200 | Succès (même si responseStatus != successful) |
| 400 | Requête malformée |
| 405 | Méthode non supportée |
| 500 | Erreur interne |

---

## Profils certificat responder

### ECDSA (classique)

```bash
pki bundle enroll --profile ec/ocsp-responder \
    --var cn=ocsp.example.com --id ocsp-responder --ca-dir ./ca
```

Profil `profiles/ec/ocsp-responder.yaml` :
- Algorithme : ECDSA P-384
- Validité : 1 an
- EKU : ocspSigning (critique)
- Extension : OCSP No Check

### ML-DSA (post-quantique)

```bash
pki bundle enroll --profile ml-dsa-kem/ocsp-responder \
    --var cn=pqc-ocsp.example.com --id pqc-ocsp-responder --ca-dir ./ca
```

Profil `profiles/ml-dsa-kem/ocsp-responder.yaml` :
- Algorithme : ML-DSA-65 (FIPS 204)
- Validité : 1 an
- EKU : ocspSigning (critique)
- Extension : OCSP No Check

### Hybride Catalyst

```bash
pki bundle enroll --profile hybrid/catalyst/ocsp-responder \
    --var cn=hybrid-ocsp.example.com --id hybrid-ocsp-responder --ca-dir ./ca
```

Profil `profiles/hybrid/catalyst/ocsp-responder.yaml` :
- Algorithme classique : ECDSA P-384
- Algorithme PQC : ML-DSA-65
- Mode : Catalyst (dual signature)
- Validité : 1 an

---

## Extension OCSP No Check

L'extension `id-pkix-ocsp-nocheck` (OID 1.3.6.1.5.5.7.48.1.5) indique que le certificat du responder ne doit pas être vérifié via OCSP. Cela évite une boucle infinie de vérification.

```yaml
# Dans un profil
extensions:
  ocspNoCheck:
    critical: false  # DOIT être non-critique (RFC 6960)
```

Cette extension est automatiquement ajoutée aux profils `ocsp-responder`.

---

## Intégration avec la CA

Le serveur OCSP interroge automatiquement l'index de la CA pour déterminer le statut des certificats :

```
CA Directory/
├── ca.crt              # Certificat CA
├── ca.key              # Clé privée CA (chiffrée)
├── index.txt           # Index des certificats
├── certs/              # Certificats émis
└── crl/                # CRLs
```

**Format index.txt :**
```
V   250115100000Z           01      unknown CN=Server 1
R   250115100000Z   240615120000Z,keyCompromise   02      unknown CN=Server 2
```

| Champ | Description |
|-------|-------------|
| V | Valid (bon) |
| R | Revoked (révoqué) |
| E | Expired (expiré) |

---

## Tests d'interopérabilité OpenSSL

### Créer une requête avec OpenSSL

```bash
openssl ocsp -issuer ca.crt -cert server.crt -reqout request.ocsp -no_nonce
```

### Interroger le serveur

```bash
openssl ocsp \
  -issuer ca.crt \
  -cert server.crt \
  -url http://localhost:8080 \
  -resp_text
```

### Vérifier une réponse

```bash
openssl ocsp -respin response.ocsp -CAfile ca.crt -resp_text
```

**Note :** OpenSSL ne supporte pas les algorithmes ML-DSA. Les tests PQC doivent utiliser `pki ocsp verify`.

---

## Bonnes pratiques

### Sécurité

1. **Utilisez un certificat responder dédié** (delegated mode)
   - Ne signez pas les réponses avec la clé CA
   - Facilite la révocation en cas de compromission

2. **Durée de validité courte** (1h - 24h)
   - Limite l'impact d'une réponse compromise
   - Force les clients à re-vérifier régulièrement

3. **Nonce pour replay protection**
   - Activez le nonce pour les requêtes sensibles
   - Le serveur copie le nonce dans la réponse

4. **HTTPS en production**
   - L'OCSP peut révéler les sites visités
   - Utilisez TLS pour protéger les requêtes

### Performance

1. **Cache côté client**
   - Respectez `thisUpdate` et `nextUpdate`
   - Implémentez OCSP Stapling (TLS)

2. **Pré-génération des réponses**
   - Pour les certificats fréquemment vérifiés
   - Réduit la latence

3. **Load balancing**
   - Plusieurs responders avec le même certificat
   - Répartition de charge

### Haute disponibilité

1. **Certificats responder avec longue validité**
   - Permet de continuer à signer si la CA est hors ligne

2. **Réplication de l'index**
   - Synchronisez l'index entre les responders

3. **Monitoring**
   - Surveillez la validité des réponses
   - Alertez si le responder est indisponible

---

## Structure des réponses (ASN.1)

### OCSPResponse

```asn1
OCSPResponse ::= SEQUENCE {
   responseStatus         OCSPResponseStatus,
   responseBytes          [0] EXPLICIT ResponseBytes OPTIONAL }

OCSPResponseStatus ::= ENUMERATED {
   successful            (0),
   malformedRequest      (1),
   internalError         (2),
   tryLater              (3),
   sigRequired           (5),
   unauthorized          (6) }
```

### BasicOCSPResponse

```asn1
BasicOCSPResponse ::= SEQUENCE {
   tbsResponseData      ResponseData,
   signatureAlgorithm   AlgorithmIdentifier,
   signature            BIT STRING,
   certs                [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }

ResponseData ::= SEQUENCE {
   version              [0] EXPLICIT Version DEFAULT v1,
   responderID          ResponderID,
   producedAt           GeneralizedTime,
   responses            SEQUENCE OF SingleResponse,
   responseExtensions   [1] EXPLICIT Extensions OPTIONAL }

SingleResponse ::= SEQUENCE {
   certID               CertID,
   certStatus           CertStatus,
   thisUpdate           GeneralizedTime,
   nextUpdate           [0] EXPLICIT GeneralizedTime OPTIONAL,
   singleExtensions     [1] EXPLICIT Extensions OPTIONAL }
```

---

## OIDs de référence

| Usage | OID |
|-------|-----|
| id-pkix-ocsp | 1.3.6.1.5.5.7.48.1 |
| id-pkix-ocsp-basic | 1.3.6.1.5.5.7.48.1.1 |
| id-pkix-ocsp-nonce | 1.3.6.1.5.5.7.48.1.2 |
| id-pkix-ocsp-crl | 1.3.6.1.5.5.7.48.1.3 |
| id-pkix-ocsp-response | 1.3.6.1.5.5.7.48.1.4 |
| id-pkix-ocsp-nocheck | 1.3.6.1.5.5.7.48.1.5 |
| id-pkix-ocsp-archive-cutoff | 1.3.6.1.5.5.7.48.1.6 |
| id-kp-OCSPSigning | 1.3.6.1.5.5.7.3.9 |

---

## Événements d'audit

L'implémentation OCSP génère les événements d'audit suivants :

| Événement | Description |
|-----------|-------------|
| `OCSP_SIGN` | Création d'une réponse OCSP |
| `OCSP_VERIFY` | Vérification d'une réponse |
| `OCSP_REQUEST` | Réception d'une requête HTTP |
| `OCSP_SERVE` | Démarrage du serveur |

**Exemple de log :**
```json
{
  "timestamp": "2024-01-15T10:00:00Z",
  "event": "OCSP_REQUEST",
  "serial": "0A1B2C3D",
  "status": "good",
  "method": "POST",
  "algorithm": "ecdsa-p384"
}
```

---

## Références

- **RFC 6960** - X.509 Internet Public Key Infrastructure OCSP
- **RFC 5019** - Lightweight OCSP Profile for High-Volume Environments
- **RFC 6277** - Online Certificate Status Protocol Algorithm Agility
- **FIPS 204** - ML-DSA (Module-Lattice-Based Digital Signature Algorithm)
