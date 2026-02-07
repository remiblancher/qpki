---
title: "Glossary"
description: "PKI and post-quantum cryptography terminology reference."
---

# Glossary

## Cryptographic Algorithms

| Term | Definition |
|------|------------|
| **ML-DSA** | Module-Lattice Digital Signature Algorithm (FIPS 204). Post-quantum signature scheme based on lattices. Replaces RSA/ECDSA for signatures. Security levels: ML-DSA-44 (Level 1), ML-DSA-65 (Level 3), ML-DSA-87 (Level 5). |
| **ML-KEM** | Module-Lattice Key Encapsulation Mechanism (FIPS 203). Post-quantum key exchange. Replaces ECDH/RSA for key establishment. Security levels: ML-KEM-512 (Level 1), ML-KEM-768 (Level 3), ML-KEM-1024 (Level 5). |
| **SLH-DSA** | Stateless Hash-based Digital Signature Algorithm (FIPS 205). Post-quantum signature based on hash functions. Conservative alternative to ML-DSA with larger signatures but different security assumptions. |
| **ECDSA** | Elliptic Curve Digital Signature Algorithm. Classical signature scheme using elliptic curves (P-256, P-384, P-521). Vulnerable to quantum attacks. |
| **Ed25519** | Edwards-curve Digital Signature Algorithm. Fast classical signatures using Curve25519. Vulnerable to quantum attacks. |
| **RSA** | Rivest-Shamir-Adleman. Classical asymmetric algorithm for signatures and encryption. Vulnerable to quantum attacks (Shor's algorithm). |

## PKI Concepts

| Term | Definition |
|------|------------|
| **CA** | Certificate Authority. Entity that issues and signs digital certificates. |
| **Root CA** | Top-level CA in a hierarchy. Self-signed certificate, trust anchor for the PKI. |
| **Issuing CA** | Intermediate/subordinate CA that issues end-entity certificates. Signed by Root CA or another Issuing CA. |
| **End-Entity** | The subject of a certificate (server, client, user). Not a CA. |
| **CSR** | Certificate Signing Request. A message sent to a CA to request a signed certificate. Contains the public key and identity information. |
| **CRL** | Certificate Revocation List. Signed list of revoked certificate serial numbers published by the CA. |
| **OCSP** | Online Certificate Status Protocol (RFC 6960). Real-time certificate validity check as alternative to CRL. |
| **TSA** | Timestamp Authority (RFC 3161). Trusted service that provides cryptographic proof of when data existed. |
| **SAN** | Subject Alternative Name. X.509 extension for multiple identities (DNS names, IP addresses, email). |
| **SKI/AKI** | Subject/Authority Key Identifier. Extensions linking certificates in a chain. |
| **Path Length** | Constraint on how many CAs can exist below an issuing CA in the chain. |

## Post-Quantum Concepts

| Term | Definition |
|------|------------|
| **PQC** | Post-Quantum Cryptography. Algorithms designed to be secure against quantum computer attacks. |
| **SNDL** | Store Now, Decrypt Later. Threat where adversaries capture encrypted data today to decrypt with future quantum computers. Affects confidentiality. |
| **HNDL** | Harvest Now, Decrypt Later. Alternative term for SNDL, emphasizing data harvesting. |
| **TNFL** | Trust Now, Forge Later. Threat where classical signatures can be forged retroactively once quantum computers exist. Affects long-term signature validity. |
| **Hybrid** | Combining classical + post-quantum algorithms for defense in depth. If either algorithm is secure, the hybrid is secure. |
| **Catalyst** | ITU-T X.509 9.8 hybrid certificate format. Dual signatures stored in X.509 extensions, allowing graceful fallback to classical. |
| **Composite** | IETF hybrid format combining keys/signatures into single cryptographic objects. Both algorithms must be verified together. |
| **Crypto-Agility** | Ability to switch cryptographic algorithms without major infrastructure changes. Essential for PQC migration. |
| **LTV** | Long-Term Validation. Signatures that remain verifiable for decades, even after algorithm deprecation. |
| **NIST Levels** | Security strength categories (1, 3, 5) corresponding to AES-128, AES-192, AES-256 equivalent security. |

## QPKI Concepts

| Term | Definition |
|------|------------|
| **Profile** | YAML template defining certificate policies (algorithm, validity, extensions, constraints). One profile = one certificate type. |
| **Credential** | Managed bundle of private key(s) + certificate(s) with coupled lifecycle management (enrollment, renewal, revocation). |
| **Attestation** | RFC 9883 mechanism where a signing certificate attests for a KEM key that cannot sign its own CSR. Required for ML-KEM certificates. |
| **Related Certificate** | X.509 extension linking separate classical and PQC certificates for the same subject. |

## Certificate Types

| Term | Definition |
|------|------------|
| **TLS Server** | Certificate for HTTPS server identity. Contains DNS names in SAN. |
| **TLS Client** | Certificate for client authentication in mTLS. May contain email or user identifier. |
| **Code Signing** | Certificate for signing software releases. Proves software authenticity. |
| **Timestamping** | Certificate for TSA service. Contains id-kp-timeStamping extended key usage. |
| **OCSP Responder** | Certificate for OCSP service. Contains id-kp-OCSPSigning extended key usage. |
| **KEM Certificate** | Certificate containing ML-KEM public key for key encapsulation (encryption). |
| **Signature Certificate** | Certificate containing signing key (ECDSA, ML-DSA, etc.) for digital signatures. |

## Standards

| Term | Definition |
|------|------------|
| **FIPS 203** | NIST standard for ML-KEM (key encapsulation). August 2024. |
| **FIPS 204** | NIST standard for ML-DSA (digital signatures). August 2024. |
| **FIPS 205** | NIST standard for SLH-DSA (hash-based signatures). August 2024. |
| **X.509** | ITU-T standard for public key certificates. Foundation of PKI. |
| **RFC 5280** | Internet X.509 PKI Certificate and CRL Profile. |
| **RFC 6960** | Online Certificate Status Protocol (OCSP). |
| **RFC 3161** | Time-Stamp Protocol (TSP). Standard for trusted timestamping services. |
| **RFC 5652** | Cryptographic Message Syntax (CMS). Format for signed/encrypted data. |
| **RFC 9883** | Use of Post-Quantum KEM in CMS. Defines CSR attestation for KEM keys. |
| **ITU-T X.509 9.8** | Alternative public-key and signature algorithms extension. Basis for Catalyst certificates. |
