# QPKI Specification

This document defines the formal requirements, supported algorithms, X.509 profiles, and data structures for Post-Quantum PKI (QPKI).

## 1. Functional Requirements

### 1.1 Core Capabilities

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-01 | Generate cryptographic key pairs (classical and PQC) | Must |
| FR-02 | Create self-signed root CA certificates | Must |
| FR-03 | Create subordinate/issuing CA certificates | Must |
| FR-04 | Issue end-entity certificates (TLS server, TLS client) | Must |
| FR-05 | Revoke certificates with standard reasons | Must |
| FR-06 | Generate Certificate Revocation Lists (CRL) | Must |
| FR-07 | Support hybrid certificates (classical + PQC) | Should |
| FR-08 | Support HSM via PKCS#11 | Should |

### 1.2 Non-Functional Requirements

| ID | Requirement | Target |
|----|-------------|--------|
| NFR-01 | Pure Go implementation (no CGO) | Required |
| NFR-02 | RFC 5280 compliance for X.509 | Required |
| NFR-03 | Cross-platform support (Linux, macOS, Windows) | Required |
| NFR-04 | CLI-only interface | Required |
| NFR-05 | No database dependency | Required |

## 2. Supported Algorithms

### 2.1 Classical Algorithms (Production)

| Algorithm | OID | Key Size | Usage |
|-----------|-----|----------|-------|
| ECDSA P-256 | 1.2.840.10045.3.1.7 | 256-bit | Default, maximum compatibility |
| ECDSA P-384 | 1.3.132.0.34 | 384-bit | High security |
| ECDSA P-521 | 1.3.132.0.35 | 521-bit | Ultra security |
| Ed25519 | 1.3.101.112 | 256-bit | Modern, fast |
| RSA-2048 | 1.2.840.113549.1.1.1 | 2048-bit | Legacy support |
| RSA-4096 | 1.2.840.113549.1.1.1 | 4096-bit | Legacy high security |

### 2.2 Post-Quantum Algorithms (Experimental)

| Algorithm | Standard | OID | Security Level |
|-----------|----------|-----|----------------|
| ML-DSA-44 | FIPS 204 | 2.16.840.1.101.3.4.3.17 | NIST Level 1 |
| ML-DSA-65 | FIPS 204 | 2.16.840.1.101.3.4.3.18 | NIST Level 3 |
| ML-DSA-87 | FIPS 204 | 2.16.840.1.101.3.4.3.19 | NIST Level 5 |
| ML-KEM-512 | FIPS 203 | 2.16.840.1.101.3.4.4.1 | NIST Level 1 |
| ML-KEM-768 | FIPS 203 | 2.16.840.1.101.3.4.4.2 | NIST Level 3 |
| ML-KEM-1024 | FIPS 203 | 2.16.840.1.101.3.4.4.3 | NIST Level 5 |

## 3. X.509 Certificate Profiles

### 3.1 Root CA Profile

```
Subject: CN=<name>, O=<org>, C=<country>
Key Usage: Certificate Sign, CRL Sign (critical)
Basic Constraints: CA:TRUE, pathlen:<n> (critical)
Subject Key Identifier: <hash of public key>
Validity: 10-30 years typical
```

### 3.2 Issuing CA Profile

```
Subject: CN=<name>, O=<org>, C=<country>
Key Usage: Certificate Sign, CRL Sign (critical)
Basic Constraints: CA:TRUE, pathlen:<n-1> (critical)
Authority Key Identifier: <issuer SKI>
Subject Key Identifier: <hash of public key>
Validity: 5-10 years typical
```

### 3.3 TLS Server Profile

```
Subject: CN=<domain>
Key Usage: Digital Signature, Key Encipherment (critical)
Extended Key Usage: TLS Web Server Authentication
Subject Alternative Name: DNS:<domains>, IP:<addresses>
Basic Constraints: CA:FALSE (critical)
Authority Key Identifier: <issuer SKI>
Subject Key Identifier: <hash of public key>
Validity: 90 days - 2 years typical
```

### 3.4 TLS Client Profile

```
Subject: CN=<identifier>
Key Usage: Digital Signature (critical)
Extended Key Usage: TLS Web Client Authentication
Basic Constraints: CA:FALSE (critical)
Authority Key Identifier: <issuer SKI>
Subject Key Identifier: <hash of public key>
Validity: 1-2 years typical
```

## 4. OID Registry

### 4.1 Standard OIDs Used

| OID | Name | Usage |
|-----|------|-------|
| 2.5.29.14 | Subject Key Identifier | Certificate extension |
| 2.5.29.35 | Authority Key Identifier | Certificate extension |
| 2.5.29.15 | Key Usage | Certificate extension |
| 2.5.29.37 | Extended Key Usage | Certificate extension |
| 2.5.29.17 | Subject Alternative Name | Certificate extension |
| 2.5.29.19 | Basic Constraints | Certificate extension |
| 2.5.29.31 | CRL Distribution Points | Certificate extension |
| 2.5.29.32 | Certificate Policies | Certificate extension |

### 4.2 Private OIDs

| OID | Name | Usage |
|-----|------|-------|
| 2.999.1.1 | Hybrid PQC Extension | Experimental hybrid certificate extension |

## 5. ASN.1 Structures

### 5.1 Hybrid PQC Extension

```asn1
HybridPQCExtension ::= SEQUENCE {
    version        INTEGER (1),
    algorithm      OBJECT IDENTIFIER,
    publicKey      BIT STRING,
    signature      BIT STRING OPTIONAL
}
```

### 5.2 Extension Encoding

- **OID**: 2.999.1.1
- **Critical**: FALSE (for compatibility)
- **Value**: DER-encoded HybridPQCExtension

## 6. File Formats

### 6.1 Private Keys

- Format: PEM (PKCS#8)
- Encryption: Optional AES-256-CBC with PBKDF2
- Header: `-----BEGIN PRIVATE KEY-----` or `-----BEGIN ENCRYPTED PRIVATE KEY-----`

### 6.2 Certificates

- Format: PEM (X.509)
- Header: `-----BEGIN CERTIFICATE-----`

### 6.3 Certificate Revocation Lists

- Format: PEM and DER
- Header: `-----BEGIN X509 CRL-----`

### 6.4 CA Directory Structure

```
ca/
├── ca.crt              # CA certificate (PEM)
├── private/
│   └── ca.key          # CA private key (PEM)
├── certs/              # Issued certificates
│   ├── 01.crt
│   └── 02.crt
├── crl/
│   ├── ca.crl          # Current CRL (PEM)
│   └── ca.crl.der      # Current CRL (DER)
├── index.txt           # Certificate database
├── serial              # Next serial number (hex)
└── crlnumber           # Next CRL number (hex)
```

### 6.5 Index File Format

Tab-separated values:
```
<status>\t<expiry>\t<revocation>\t<serial>\t<filename>\t<subject>
```

Where:
- **status**: V (valid), R (revoked), E (expired)
- **expiry**: YYMMDDHHmmssZ
- **revocation**: Empty or YYMMDDHHmmssZ
- **serial**: Hex serial number
- **filename**: Certificate filename
- **subject**: Distinguished name

## 7. Constraints

### 7.1 Key Size Constraints

| Algorithm | Minimum | Recommended |
|-----------|---------|-------------|
| RSA | 2048 | 4096 |
| ECDSA P-256 | 256 | 256 |
| ECDSA P-384 | 384 | 384 |
| Ed25519 | 256 | 256 |

### 7.2 Validity Constraints

| Certificate Type | Minimum | Maximum | Recommended |
|------------------|---------|---------|-------------|
| Root CA | 1 year | 30 years | 20 years |
| Issuing CA | 1 year | 10 years | 5 years |
| TLS Server | 1 day | 825 days | 90 days |
| TLS Client | 1 day | 2 years | 1 year |

### 7.3 Path Length Constraints

- Root CA: pathlen=1 (allows one level of subordinate CAs)
- Issuing CA: pathlen=0 (cannot issue CA certificates)
- End-entity: CA:FALSE

## 8. Revocation Reasons

| Code | Name | Description |
|------|------|-------------|
| 0 | unspecified | No specific reason |
| 1 | keyCompromise | Private key compromised |
| 2 | caCompromise | CA private key compromised |
| 3 | affiliationChanged | Subject affiliation changed |
| 4 | superseded | Certificate replaced |
| 5 | cessationOfOperation | Certificate no longer needed |
| 6 | certificateHold | Temporary hold |
| 8 | removeFromCRL | Remove from CRL (delta CRL) |
| 9 | privilegeWithdrawn | Privilege withdrawn |
| 10 | aaCompromise | AA compromised |

## 9. Compliance

### 9.1 Standards Compliance

| Standard | Scope | Status |
|----------|-------|--------|
| RFC 5280 | X.509 PKI | Compliant |
| RFC 6960 | OCSP | Not implemented |
| RFC 5652 | CMS | Not implemented |
| FIPS 186-5 | ECDSA, EdDSA | Compliant |
| FIPS 203 | ML-KEM | Experimental |
| FIPS 204 | ML-DSA | Experimental |

### 9.2 Browser Compatibility

| Requirement | Status |
|-------------|--------|
| Subject Alternative Name for TLS | Compliant |
| Basic Constraints critical | Compliant |
| Key Usage critical | Compliant |
| Maximum validity 825 days | Configurable |
