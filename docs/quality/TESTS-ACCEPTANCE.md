---
title: "Acceptance Tests"
description: "Plan exhaustif des tests d'acceptance QPKI - validation CLI end-to-end."
---

# Tests d'Acceptance QPKI

Ce document présente le plan exhaustif des tests d'acceptance. Ces tests valident les workflows complets via la CLI (boîte noire).

## Vue d'ensemble

| Métrique | Valeur |
|----------|--------|
| **Suites de tests** | 8 |
| **Tests total** | 133 |
| **Priorité P1 (bloquants)** | 110 |
| **Priorité P2** | 23 |
| **Fichiers** | `test/acceptance/*.go` |
| **Build tag** | `//go:build acceptance` |

### Exécution

```bash
# Tous les tests d'acceptance
make test-acceptance

# Une suite spécifique
go test -tags=acceptance ./test/acceptance/... -run TestA_CMS

# Un test individuel
go test -tags=acceptance ./test/acceptance/... -run TestA_CMS_Sign_EC -v
```

---

## Matrice de couverture par algorithme

| Fonctionnalité | EC | RSA | ML-DSA | SLH-DSA | Catalyst | Composite |
|----------------|:--:|:---:|:------:|:-------:|:--------:|:---------:|
| **CA Init** | TC-A-CA-001 | TC-A-CA-002 | TC-A-CA-003 | TC-A-CA-004 | TC-A-CA-005 | TC-A-CA-006 |
| **Key Gen** | TC-A-KEY-001 | TC-A-KEY-002 | TC-A-KEY-003 | TC-A-KEY-004 | - | - |
| **CSR** | TC-A-CSR-001 | TC-A-CSR-002 | - | - | - | - |
| **Credential** | TC-A-CRED-001 | TC-A-CRED-002 | TC-A-CRED-003 | TC-A-CRED-004 | TC-A-CRED-005 | TC-A-CRED-006 |
| **CMS Sign** | TC-A-CMS-001 | TC-A-CMS-002 | TC-A-CMS-003 | TC-A-CMS-004 | TC-A-CMS-005 | TC-A-CMS-006 |
| **CMS Encrypt** | TC-A-CMS-008 | TC-A-CMS-007 | TC-A-CMS-009 | - | - | TC-A-CMS-010 |
| **TSA** | TC-A-TSA-001 | TC-A-TSA-002 | TC-A-TSA-003 | TC-A-TSA-004 | TC-A-TSA-005 | TC-A-TSA-006 |
| **OCSP** | TC-A-OCSP-001 | - | TC-A-OCSP-002 | TC-A-OCSP-003 | TC-A-OCSP-004 | TC-A-OCSP-005 |
| **COSE Sign1** | TC-A-COSE-001 | TC-A-COSE-002 | TC-A-COSE-004 | TC-A-COSE-006 | TC-A-COSE-008 | SKIP |
| **COSE CWT** | TC-A-COSE-003 | - | TC-A-COSE-005 | TC-A-COSE-007 | TC-A-COSE-010 | SKIP |
| **E2E Workflow** | TC-A-E2E-001 | - | TC-A-E2E-002 | - | TC-A-E2E-003 | TC-A-E2E-004 |

---

## 1. PKI Core (`pki_test.go`)

**46 tests** - Workflows PKI fondamentaux

### 1.1 Génération de clés (6 tests)

| TC-ID | Nom | Priorité | Description |
|-------|-----|:--------:|-------------|
| TC-A-KEY-001 | `TestA_Key_Gen_EC_Algorithms` | P1 | Génère clés EC (P-256, P-384, P-521) |
| TC-A-KEY-002 | `TestA_Key_Gen_RSA_Algorithms` | P1 | Génère clés RSA (2048, 3072, 4096) |
| TC-A-KEY-003 | `TestA_Key_Gen_MLDSA_Algorithms` | P1 | Génère clés ML-DSA (44, 65, 87) |
| TC-A-KEY-004 | `TestA_Key_Gen_SLHDSA_Algorithms` | P1 | Génère clés SLH-DSA (128f, 192f, 256f) |
| TC-A-KEY-005 | `TestA_Key_Info` | P2 | Affiche info clé |
| TC-A-KEY-006 | `TestA_Key_List` | P2 | Liste les clés |

### 1.2 Initialisation CA (8 tests)

| TC-ID | Nom | Priorité | Description |
|-------|-----|:--------:|-------------|
| TC-A-CA-001 | `TestA_CA_Init_EC` | P1 | CA racine ECDSA |
| TC-A-CA-002 | `TestA_CA_Init_RSA` | P1 | CA racine RSA |
| TC-A-CA-003 | `TestA_CA_Init_MLDSA` | P1 | CA racine ML-DSA |
| TC-A-CA-004 | `TestA_CA_Init_SLHDSA` | P1 | CA racine SLH-DSA |
| TC-A-CA-005 | `TestA_CA_Init_Catalyst` | P1 | CA hybride Catalyst (EC + ML-DSA) |
| TC-A-CA-006 | `TestA_CA_Init_Composite` | P1 | CA hybride Composite |
| TC-A-CA-007 | `TestA_CA_Init_Subordinate` | P1 | CA subordonnée |
| TC-A-CA-008 | `TestA_CA_Info` | P2 | Affiche info CA |

### 1.3 CSR (3 tests)

| TC-ID | Nom | Priorité | Description |
|-------|-----|:--------:|-------------|
| TC-A-CSR-001 | `TestA_CSR_Gen_EC` | P1 | CSR ECDSA |
| TC-A-CSR-002 | `TestA_CSR_Gen_RSA` | P1 | CSR RSA |
| TC-A-CSR-003 | `TestA_CSR_Gen_MLKEM_WithAttestation` | P1 | CSR ML-KEM avec PoP (RFC 9883) |

### 1.4 Certificats (5 tests)

| TC-ID | Nom | Priorité | Description |
|-------|-----|:--------:|-------------|
| TC-A-CERT-001 | `TestA_Cert_Issue_EC_FromCSR` | P1 | Émet certificat EC depuis CSR |
| TC-A-CERT-002 | `TestA_Cert_Issue_RSA_FromCSR` | P1 | Émet certificat RSA depuis CSR |
| TC-A-CERT-003 | `TestA_Cert_Verify` | P1 | Vérifie chaîne de certificats |
| TC-A-CERT-004 | `TestA_Cert_List` | P2 | Liste certificats émis |
| TC-A-CERT-005 | `TestA_Cert_Inspect` | P2 | Inspecte certificat |

### 1.5 Credentials (6 tests)

| TC-ID | Nom | Priorité | Description |
|-------|-----|:--------:|-------------|
| TC-A-CRED-001 | `TestA_Credential_Enroll_EC_Profiles` | P1 | Enrollment profils EC (tls-server, tls-client, signing, etc.) |
| TC-A-CRED-002 | `TestA_Credential_Enroll_RSA_Profiles` | P1 | Enrollment profils RSA |
| TC-A-CRED-003 | `TestA_Credential_Enroll_MLDSA_Profiles` | P1 | Enrollment profils ML-DSA |
| TC-A-CRED-004 | `TestA_Credential_Enroll_SLHDSA_Profiles` | P1 | Enrollment profils SLH-DSA |
| TC-A-CRED-005 | `TestA_Credential_Enroll_Catalyst_Profiles` | P1 | Enrollment profils Catalyst |
| TC-A-CRED-006 | `TestA_Credential_Enroll_Composite_Profiles` | P1 | Enrollment profils Composite |

### 1.6 CRL (3 tests)

| TC-ID | Nom | Priorité | Description |
|-------|-----|:--------:|-------------|
| TC-A-CRL-001 | `TestA_CRL_Generate` | P1 | Génère CRL |
| TC-A-CRL-002 | `TestA_CRL_Revoke_And_Generate` | P1 | Révoque certificat et génère CRL |
| TC-A-CRL-003 | `TestA_CRL_PQC_Algorithms` | P1 | CRL avec algorithmes PQC |

### 1.7 Profiles (2 tests)

| TC-ID | Nom | Priorité | Description |
|-------|-----|:--------:|-------------|
| TC-A-PROFILE-001 | `TestA_Profile_List` | P2 | Liste profils disponibles |
| TC-A-PROFILE-002 | `TestA_Profile_Show` | P2 | Affiche contenu profil |

### 1.8 Inspect (4 tests)

| TC-ID | Nom | Priorité | Description |
|-------|-----|:--------:|-------------|
| TC-A-INSPECT-001 | `TestA_Inspect_Certificate` | P2 | Inspecte certificat (détails X.509) |
| TC-A-INSPECT-002 | `TestA_Inspect_PQC_Certificate` | P1 | Inspecte certificat PQC |
| TC-A-INSPECT-003 | `TestA_Inspect_CRL` | P2 | Inspecte CRL |
| TC-A-INSPECT-004 | `TestA_Inspect_CSR` | P2 | Inspecte CSR |

### 1.9 E2E Workflows (5 tests)

| TC-ID | Nom | Priorité | Description |
|-------|-----|:--------:|-------------|
| TC-A-E2E-001 | `TestA_E2E_EC_Workflow` | P1 | Workflow complet EC : CA → Cert → CRL → Verify |
| TC-A-E2E-002 | `TestA_E2E_MLDSA_Workflow` | P1 | Workflow complet ML-DSA |
| TC-A-E2E-003 | `TestA_E2E_Catalyst_Workflow` | P1 | Workflow complet Catalyst |
| TC-A-E2E-004 | `TestA_E2E_Composite_Workflow` | P1 | Workflow complet Composite |
| TC-A-E2E-005 | `TestA_E2E_SubordinateCA_Chain` | P1 | Chaîne Root CA → Sub CA → Cert |

### 1.10 CLI (2 tests)

| TC-ID | Nom | Priorité | Description |
|-------|-----|:--------:|-------------|
| TC-A-CLI-001 | `TestA_CLI_Help` | P2 | `qpki --help` |
| TC-A-CLI-002 | `TestA_CLI_Version` | P2 | `qpki --version` |

---

## 2. Crypto Agility (`cryptoagility_test.go`)

**17 tests** - Transitions et rotations d'algorithmes

### 2.1 Transitions d'algorithmes (8 tests)

| TC-ID | Nom | Priorité | Description |
|-------|-----|:--------:|-------------|
| TC-A-AGILITY-001 | `TestA_Agility_EC_Catalyst_PQ` | P1 | EC → Catalyst → ML-DSA |
| TC-A-AGILITY-002 | `TestA_Agility_EC_Composite_PQ` | P1 | EC → Composite → ML-DSA |
| TC-A-AGILITY-003 | `TestA_Agility_RSA_EC_PQ` | P1 | RSA → EC → ML-DSA |
| TC-A-AGILITY-004 | `TestA_Agility_EC_PQ_Direct` | P1 | EC → ML-DSA (direct) |
| TC-A-AGILITY-005 | `TestA_Agility_Catalyst_PQ` | P1 | Catalyst → ML-DSA |
| TC-A-AGILITY-006 | `TestA_Agility_Composite_PQ` | P1 | Composite → ML-DSA |
| TC-A-AGILITY-007 | `TestA_Agility_EC_SLHDSA` | P1 | EC → SLH-DSA |
| TC-A-AGILITY-008 | `TestA_Agility_Full_PKI_Transition` | P1 | Transition complète PKI |

### 2.2 Rotations CA (9 tests)

| TC-ID | Nom | Priorité | Description |
|-------|-----|:--------:|-------------|
| TC-A-AGILITY-009 | `TestA_Agility_Rotate_EC_Catalyst_MLDSA` | P1 | Rotation EC → Catalyst → ML-DSA |
| TC-A-AGILITY-010 | `TestA_Agility_Rotate_EC_Composite_MLDSA` | P1 | Rotation EC → Composite → ML-DSA |
| TC-A-AGILITY-011 | `TestA_Agility_Rotate_RSA_EC_MLDSA` | P1 | Rotation RSA → EC → ML-DSA |
| TC-A-AGILITY-012 | `TestA_Agility_Rotate_EC_MLDSA_Direct` | P1 | Rotation EC → ML-DSA (direct) |
| TC-A-AGILITY-013 | `TestA_Agility_Rotate_Catalyst_MLDSA` | P1 | Rotation Catalyst → ML-DSA |
| TC-A-AGILITY-014 | `TestA_Agility_Rotate_Composite_MLDSA` | P1 | Rotation Composite → ML-DSA |
| TC-A-AGILITY-015 | `TestA_Agility_Rotate_CA_Versions` | P1 | Gestion versions CA |
| TC-A-AGILITY-016 | `TestA_Agility_Rotate_Credential_Versions` | P1 | Gestion versions credential |
| TC-A-AGILITY-017 | `TestA_Agility_Rotate_CA_Info` | P1 | Info CA après rotation |

---

## 3. CMS (`cms_test.go`)

**11 tests** - Signatures et chiffrement CMS

### 3.1 Signature CMS (6 tests)

| TC-ID | Nom | Priorité | Algorithme |
|-------|-----|:--------:|------------|
| TC-A-CMS-001 | `TestA_CMS_Sign_EC` | P1 | ECDSA |
| TC-A-CMS-002 | `TestA_CMS_Sign_RSA` | P1 | RSA |
| TC-A-CMS-003 | `TestA_CMS_Sign_MLDSA` | P1 | ML-DSA |
| TC-A-CMS-004 | `TestA_CMS_Sign_SLHDSA` | P1 | SLH-DSA |
| TC-A-CMS-005 | `TestA_CMS_Sign_Catalyst` | P1 | Catalyst |
| TC-A-CMS-006 | `TestA_CMS_Sign_Composite` | P1 | Composite |

### 3.2 Chiffrement CMS (5 tests)

| TC-ID | Nom | Priorité | Mécanisme |
|-------|-----|:--------:|-----------|
| TC-A-CMS-007 | `TestA_CMS_Encrypt_RSA` | P1 | RSA-OAEP |
| TC-A-CMS-008 | `TestA_CMS_Encrypt_EC` | P1 | ECDH |
| TC-A-CMS-009 | `TestA_CMS_Encrypt_MLKEM` | P1 | ML-KEM |
| TC-A-CMS-010 | `TestA_CMS_Encrypt_Hybrid` | P1 | Hybrid (ECDH + ML-KEM) |
| TC-A-CMS-011 | `TestA_CMS_Verify_InvalidData` | P2 | Erreur sur données invalides |

---

## 4. HSM (`hsm_test.go`)

**13 tests** - Intégration HSM via PKCS#11

> **Prérequis** : SoftHSM2 installé et token initialisé

### 4.1 Gestion HSM (3 tests)

| TC-ID | Nom | Priorité | Description |
|-------|-----|:--------:|-------------|
| TC-A-HSM-001 | `TestA_HSM_List_Tokens` | P1 | Liste tokens disponibles |
| TC-A-HSM-002 | `TestA_HSM_Test_Connection` | P1 | Test connexion HSM |
| TC-A-HSM-003 | `TestA_HSM_Info` | P2 | Info token |

### 4.2 Génération clés HSM (3 tests)

| TC-ID | Nom | Priorité | Description |
|-------|-----|:--------:|-------------|
| TC-A-HSM-004 | `TestA_HSM_Key_Gen_EC` | P1 | Génère clé EC dans HSM |
| TC-A-HSM-005 | `TestA_HSM_Key_Gen_RSA` | P1 | Génère clé RSA dans HSM |
| TC-A-HSM-006 | `TestA_HSM_Key_List` | P2 | Liste clés dans HSM |

### 4.3 CA avec HSM (4 tests)

| TC-ID | Nom | Priorité | Description |
|-------|-----|:--------:|-------------|
| TC-A-HSM-007 | `TestA_HSM_CA_Init_WithExistingKey` | P1 | Init CA avec clé existante |
| TC-A-HSM-008 | `TestA_HSM_CA_Init_GenerateKey` | P1 | Init CA avec génération clé |
| TC-A-HSM-009 | `TestA_HSM_CA_Init_RSA` | P1 | Init CA RSA dans HSM |
| TC-A-HSM-010 | `TestA_HSM_CA_Info` | P2 | Info CA HSM |

### 4.4 Credentials avec HSM (3 tests)

| TC-ID | Nom | Priorité | Description |
|-------|-----|:--------:|-------------|
| TC-A-HSM-011 | `TestA_HSM_Credential_Enroll_SoftwareKey` | P1 | CA HSM, clé logicielle |
| TC-A-HSM-012 | `TestA_HSM_Credential_Enroll_HSMKey` | P1 | CA HSM, clé HSM |
| TC-A-HSM-013 | `TestA_HSM_Credential_List` | P2 | Liste credentials HSM |

---

## 5. TSA (`tsa_test.go`)

**8 tests** - Horodatage RFC 3161

| TC-ID | Nom | Priorité | Algorithme |
|-------|-----|:--------:|------------|
| TC-A-TSA-001 | `TestA_TSA_Sign_EC` | P1 | ECDSA |
| TC-A-TSA-002 | `TestA_TSA_Sign_RSA` | P1 | RSA |
| TC-A-TSA-003 | `TestA_TSA_Sign_MLDSA` | P1 | ML-DSA |
| TC-A-TSA-004 | `TestA_TSA_Sign_SLHDSA` | P1 | SLH-DSA |
| TC-A-TSA-005 | `TestA_TSA_Sign_Catalyst` | P1 | Catalyst |
| TC-A-TSA-006 | `TestA_TSA_Sign_Composite` | P1 | Composite |
| TC-A-TSA-007 | `TestA_TSA_Verify_InvalidData` | P2 | Erreur sur données invalides |
| TC-A-TSA-008 | `TestA_TSA_Info` | P2 | Info timestamp |

---

## 6. OCSP (`ocsp_test.go`)

**7 tests** - Statut certificat RFC 6960

| TC-ID | Nom | Priorité | Algorithme |
|-------|-----|:--------:|------------|
| TC-A-OCSP-001 | `TestA_OCSP_Sign_EC` | P1 | ECDSA |
| TC-A-OCSP-002 | `TestA_OCSP_Sign_MLDSA` | P1 | ML-DSA |
| TC-A-OCSP-003 | `TestA_OCSP_Sign_SLHDSA` | P1 | SLH-DSA |
| TC-A-OCSP-004 | `TestA_OCSP_Sign_Catalyst` | P1 | Catalyst |
| TC-A-OCSP-005 | `TestA_OCSP_Sign_Composite` | P1 | Composite |
| TC-A-OCSP-006 | `TestA_OCSP_Status_Revoked` | P1 | Statut révoqué |
| TC-A-OCSP-007 | `TestA_OCSP_Server` | P1 | Serveur OCSP HTTP |

---

## 7. COSE (`cose_test.go`)

**28 tests** - Signatures COSE/CWT (RFC 9052/8392)

> **Note**: Les tests Composite sont SKIP car COSE ne supporte pas les algorithmes composites directement. Utiliser le mode Catalyst (2 signatures séparées) pour l'hybride.

### 7.1 Algorithmes Classiques (3 tests)

| TC-ID | Nom | Priorité | Algorithme |
|-------|-----|:--------:|------------|
| TC-A-COSE-001 | `TestA_COSE_Sign1_EC` | P1 | ECDSA |
| TC-A-COSE-002 | `TestA_COSE_Sign1_RSA` | P1 | RSA-PSS |
| TC-A-COSE-003 | `TestA_COSE_CWT_EC` | P1 | CWT ECDSA |

### 7.2 ML-DSA (2 tests)

| TC-ID | Nom | Priorité | Algorithme |
|-------|-----|:--------:|------------|
| TC-A-COSE-004 | `TestA_COSE_Sign1_MLDSA` | P1 | ML-DSA-65 |
| TC-A-COSE-005 | `TestA_COSE_CWT_MLDSA` | P1 | CWT ML-DSA-65 |

### 7.3 SLH-DSA (2 tests)

| TC-ID | Nom | Priorité | Algorithme |
|-------|-----|:--------:|------------|
| TC-A-COSE-006 | `TestA_COSE_Sign1_SLHDSA` | P1 | SLH-DSA-SHA2-128f |
| TC-A-COSE-007 | `TestA_COSE_CWT_SLHDSA` | P1 | CWT SLH-DSA-SHA2-128f |

### 7.4 Hybride (4 tests)

| TC-ID | Nom | Priorité | Mode |
|-------|-----|:--------:|------|
| TC-A-COSE-008 | `TestA_COSE_Sign_Catalyst` | P1 | Catalyst (2 signatures) |
| TC-A-COSE-009 | `TestA_COSE_Sign_Composite` | SKIP | Composite (non supporté) |
| TC-A-COSE-010 | `TestA_COSE_CWT_Catalyst` | P1 | CWT Catalyst |
| TC-A-COSE-011 | `TestA_COSE_CWT_Composite` | SKIP | CWT Composite (non supporté) |

### 7.5 HSM Spécifique (3 tests)

| TC-ID | Nom | Priorité | Description |
|-------|-----|:--------:|-------------|
| TC-A-COSE-012 | `TestA_COSE_HSM_Sign1_EC` | P1 | Sign1 EC via HSM |
| TC-A-COSE-013 | `TestA_COSE_HSM_Sign1_MLDSA` | P1 | Sign1 ML-DSA via HSM (UTIMACO) |
| TC-A-COSE-014 | `TestA_COSE_HSM_Hybrid` | P1 | Hybride via HSM (UTIMACO) |

### 7.6 Vérification (7 tests)

| TC-ID | Nom | Priorité | Description |
|-------|-----|:--------:|-------------|
| TC-A-COSE-015 | `TestA_COSE_Verify_OK` | P1 | Vérification valide |
| TC-A-COSE-016 | `TestA_COSE_Verify_EmbeddedPayload` | P1 | Vérification payload embarqué |
| TC-A-COSE-017 | `TestA_COSE_Verify_CertChain` | P1 | Vérification chaîne CA |
| TC-A-COSE-018 | `TestA_COSE_Verify_InvalidSignature` | P1 | Signature invalide rejetée |
| TC-A-COSE-019 | `TestA_COSE_CWT_Expiration` | P1 | Validation expiration |
| TC-A-COSE-020 | `TestA_COSE_Verify_WrongCA` | P2 | Mauvais CA rejeté |
| TC-A-COSE-021 | `TestA_COSE_Sign_MissingKey` | P2 | Erreur clé manquante |

### 7.7 Info (3 tests)

| TC-ID | Nom | Priorité | Description |
|-------|-----|:--------:|-------------|
| TC-A-COSE-022 | `TestA_COSE_Info_Sign1` | P2 | Info Sign1 |
| TC-A-COSE-023 | `TestA_COSE_Info_CWT` | P2 | Info CWT |
| TC-A-COSE-024 | `TestA_COSE_Info_Hybrid` | P2 | Info hybride |

### 7.8 Crypto-Agilité (5 tests)

| TC-ID | Nom | Priorité | Description |
|-------|-----|:--------:|-------------|
| TC-A-COSE-025 | `TestA_COSE_Agility_EC_To_MLDSA` | P1 | Rotation EC -> ML-DSA |
| TC-A-COSE-026 | `TestA_COSE_Agility_EC_Catalyst_PQ` | P1 | PKIs parallèles |
| TC-A-COSE-027 | `TestA_COSE_Agility_VerifyOldTokenAfterRotation` | P1 | Anciens CWT valides |
| TC-A-COSE-028 | `TestA_COSE_Agility_HybridTransition` | P1 | Transition hybride |
| TC-A-COSE-029 | `TestA_COSE_Agility_MultipleIssuers` | P2 | Multi-émetteurs |

---

## Exécution CI

```yaml
# .github/workflows/ci.yml
jobs:
  acceptance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run acceptance tests
        run: make test-acceptance
```

| Job CI | Tests | Durée |
|--------|-------|-------|
| `pki-test` | TC-A-PKI-* | ~10 min |
| `cms-test` | TC-A-CMS-* | ~5 min |
| `tsa-test` | TC-A-TSA-* | ~3 min |
| `ocsp-test` | TC-A-OCSP-* | ~3 min |
| `cose-test` | TC-A-COSE-* | ~5 min |
| `hsm-test` | TC-A-HSM-* | ~5 min |
| `cryptoagility-test` | TC-A-AGILITY-* | ~8 min |

---

## Voir aussi

- [STRATEGY.md](STRATEGY.md) - Philosophie de test
- [TESTS-INTEROP.md](TESTS-INTEROP.md) - Tests d'interopérabilité
- [COMPLIANCE.md](COMPLIANCE.md) - Conformité standards
