---
title: "Quality Assurance"
description: "QPKI quality documentation following ISO/IEC 25010 and 29119 standards."
---

# QPKI Quality Assurance

> Documentation qualite conforme ISO/IEC 25010 (Software Quality) et ISO/IEC 29119 (Testing).

## Vue d'Ensemble

| Caracteristique ISO 25010 | Documentation | Source |
|---------------------------|---------------|--------|
| **Functional Suitability** | [Test Strategy](testing/STRATEGY.md) | Manuel |
| **Reliability** | [Test Catalog](testing/CATALOG.md) | Genere |
| **Security** | [FIPS Compliance](compliance/FIPS.md) | Genere |
| **Compatibility** | [RFC Compliance](compliance/RFC.md) | Genere |
| **Interoperability** | [Interop Matrix](compliance/INTEROP.md) | Manuel |

## Structure

```
docs/quality/
├── testing/                    # ISO 29119 - Documentation de test
│   ├── STRATEGY.md             # Strategie et philosophie de test
│   ├── CATALOG.md              # Catalogue exhaustif des tests (genere)
│   └── COVERAGE.md             # Rapport de couverture (genere par CI)
│
├── compliance/                 # Conformite standards
│   ├── FIPS.md                 # FIPS 203/204/205 (genere)
│   ├── RFC.md                  # RFC 5280, 5652, etc. (genere)
│   └── INTEROP.md              # Matrice d'interoperabilite
│
└── security/                   # Securite
    └── THREAT-MODEL.md         # Modele de menaces (a venir)
```

## Single Source of Truth

La documentation generee provient des specifications machine-readable :

```
specs/compliance/standards-matrix.yaml  ──>  docs/quality/compliance/FIPS.md
                                        ──>  docs/quality/compliance/RFC.md

specs/tests/test-catalog.yaml           ──>  docs/quality/testing/CATALOG.md
```

**Regle** : Ne jamais modifier directement les fichiers generes. Modifier la source dans `specs/` et regenerer.

## Regenerer la Documentation

```bash
# Regenerer toute la documentation qualite
make quality-docs

# Ou individuellement
./scripts/generate-compliance-docs.sh    # Compliance docs
./scripts/generate-test-catalog-docs.sh  # Test catalog
```

## Metriques Qualite

| Metrique | Valeur | Cible | Commande |
|----------|--------|-------|----------|
| Couverture code | ~70% | 70% | `make coverage` |
| Tests unitaires | 340+ | - | `make test` |
| Cibles fuzzing | 14 | 8+ | `make fuzz` |
| Cross-validation | OpenSSL + BC | - | `make crosstest` |

## Voir Aussi

- [specs/compliance/standards-matrix.yaml](../../specs/compliance/standards-matrix.yaml) - Source conformite
- [specs/tests/test-catalog.yaml](../../specs/tests/test-catalog.yaml) - Source catalogue tests
- [Test Strategy](testing/STRATEGY.md) - Philosophie de test
- [Interoperability](compliance/INTEROP.md) - Validation croisee
