# Améliorations QPKI - Roadmap

## Vue d'ensemble

Ce document liste les améliorations potentielles pour QPKI (Post-Quantum PKI), organisées par catégorie et priorité.

---

## 1. Sécurité

### 1.1 Support HSM (PKCS#11)
- **Priorité :** Haute
- **Effort :** Moyen
- **Description :** Implémenter le support matériel pour protéger les clés privées CA
- **Fichier :** `internal/crypto/pkcs11.go`
- **HSM supportés :** YubiHSM, SoftHSM2, Thales Luna, AWS CloudHSM

### 1.2 Audit Logging
- **Priorité :** Haute
- **Effort :** Faible
- **Description :** Journaliser toutes les opérations CA (init, issue, revoke, list)
- **Format :** JSON structuré avec timestamp, action, sujet, résultat

### 1.3 Protection accès concurrent
- **Priorité :** Moyenne
- **Effort :** Faible
- **Description :** Verrouillage fichier pour éviter la corruption lors d'accès simultanés
- **Méthode :** Fichier `.lock` avec flock ou équivalent cross-platform

### 1.4 Partage de secret (Shamir)
- **Priorité :** Basse
- **Effort :** Moyen
- **Description :** Diviser la passphrase CA en N parts, M requises pour reconstituer
- **Usage :** Cérémonies de clés, accès root CA

---

## 2. Fonctionnalités certificats

### 2.1 OCSP Responder ✅ IMPLÉMENTÉ
- **Statut :** Complété
- **Description :** Serveur de validation en ligne du statut des certificats (RFC 6960)
- **Fonctionnalités :**
  - Commandes CLI : `pki ocsp sign`, `verify`, `request`, `info`, `serve`
  - Support HTTP GET et POST (RFC 6960 §A.1)
  - Intégration avec le store CA pour lookup des statuts
  - Support algorithmes PQC (ML-DSA) et hybrides (Catalyst)
  - Extension OCSP No Check pour certificats responder
  - Profils : `ec/ocsp-responder`, `ml/ocsp-responder`, `hybrid/catalyst/ocsp-responder`
- **Documentation :** `docs/OCSP.md`

### 2.2 Templates personnalisés
- **Priorité :** Basse
- **Effort :** Moyen
- **Description :** Définir des profils certificat via fichiers YAML
- **Exemple :** Extensions custom, OID spécifiques, policies

### 2.3 Cross-certification
- **Priorité :** Basse
- **Effort :** Moyen
- **Description :** Certificats cross-signés entre deux CAs indépendantes

---

## 3. Post-Quantique (PQC)

### 3.1 SLH-DSA (SPHINCS+)
- **Priorité :** Moyenne
- **Effort :** Moyen
- **Description :** Ajouter support FIPS 205 (signature hash-based stateless)
- **Avantage :** Sécurité basée sur hash, pas sur problèmes mathématiques
- **Niveaux :** SLH-DSA-128s, SLH-DSA-192s, SLH-DSA-256s

### 3.2 Hybrid X25519 + ML-KEM
- **Priorité :** Moyenne
- **Effort :** Moyen
- **Description :** Key encapsulation hybride pour échange de clés TLS
- **Usage :** TLS 1.3 avec protection post-quantique

### 3.3 Persistance clés PQC
- **Priorité :** Haute
- **Effort :** Faible
- **Description :** Sauvegarder les clés privées PQC hybrides pour re-signature
- **Fichier :** `internal/crypto/software.go`

---

## 4. Opérations

### 4.1 Monitoring Prometheus
- **Priorité :** Moyenne
- **Effort :** Moyen
- **Description :** Exposer des métriques pour supervision
- **Métriques :**
  - Certificats expirant dans 30/7/1 jours
  - Âge du CRL
  - Nombre de certificats actifs/révoqués
  - Opérations par type

### 4.2 Alerting expiration
- **Priorité :** Haute
- **Effort :** Faible
- **Description :** Commande pour lister les certificats proches de l'expiration
- **Commande :** `pki check-expiry --days 30`

### 4.3 Backup chiffré
- **Priorité :** Moyenne
- **Effort :** Faible
- **Description :** Export complet de la CA dans une archive chiffrée
- **Commande :** `pki backup --output ca-backup.enc --passphrase-env BACKUP_KEY`

### 4.4 Fichier de configuration
- **Priorité :** Basse
- **Effort :** Faible
- **Description :** Support d'un fichier `pki.yaml` pour les options par défaut
- **Contenu :** Algorithme par défaut, profils, chemins, options

### 4.5 Backend base de données
- **Priorité :** Basse
- **Effort :** Élevé
- **Description :** Option SQLite/PostgreSQL pour grandes installations
- **Avantage :** Requêtes efficaces, transactions, historique

---

## 5. Tests et qualité

### 5.1 Fuzzing cryptographique
- **Priorité :** Moyenne
- **Effort :** Moyen
- **Description :** Tests fuzz sur parsers ASN.1, PEM, certificats
- **Outil :** go-fuzz ou fuzzing natif Go 1.18+

### 5.2 Benchmarks
- **Priorité :** Basse
- **Effort :** Faible
- **Description :** Mesures de performance pour chaque algorithme
- **Métriques :** Génération clé, signature, vérification

### 5.3 Tests interopérabilité
- **Priorité :** Moyenne
- **Effort :** Moyen
- **Description :** Valider les certificats avec OpenSSL, Java, Python, BouncyCastle
- **Fichiers :** `test/openssl/`, `test/bouncycastle/`

### 5.4 Tests E2E TLS
- **Priorité :** Moyenne
- **Effort :** Moyen
- **Description :** Serveur/client TLS réel avec certificats générés
- **Validation :** Chaîne complète, révocation, renouvellement

---

## 6. Documentation

### 6.1 Guide cérémonie de clés
- **Priorité :** Haute
- **Effort :** Faible
- **Description :** Procédure formelle pour génération Root CA en production
- **Contenu :** Environnement air-gap, témoins, vérifications, stockage

### 6.2 Guide migration PQC
- **Priorité :** Moyenne
- **Effort :** Faible
- **Description :** Stratégie de migration vers algorithmes post-quantiques
- **Phases :** Hybride d'abord, pure PQC ensuite

### 6.3 Pages man
- **Priorité :** Basse
- **Effort :** Faible
- **Description :** Documentation man pour chaque commande CLI
- **Génération :** Automatique depuis Cobra

---

## Matrice de priorité

| Amélioration | Impact | Effort | Score |
|--------------|--------|--------|-------|
| Audit logging | Élevé | Faible | ⭐⭐⭐⭐⭐ |
| Check expiry | Élevé | Faible | ⭐⭐⭐⭐⭐ |
| Persistance PQC | Moyen | Faible | ⭐⭐⭐⭐ |
| HSM support | Élevé | Moyen | ⭐⭐⭐⭐ |
| OCSP | ✅ | Complété | ✅ |
| SLH-DSA | Moyen | Moyen | ⭐⭐⭐ |
| Monitoring | Moyen | Moyen | ⭐⭐⭐ |
| Database | Moyen | Élevé | ⭐⭐ |

---

## Prochaines étapes recommandées

1. **Audit logging** - Conformité et traçabilité
2. **Check expiry** - Opérations proactives
3. **HSM support** - Sécurité production
