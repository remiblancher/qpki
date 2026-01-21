# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.11.1] - 2026-01-21

### Changed
- Pin `cloudflare/circl` to v1.6.2
- Add license compliance check and SBOM generation in CI
- Test coverage improved from 69.8% to 82.1% (crypto package)

### Fixed
- SLH-DSA public key type: use pointer instead of value for `Verify()` to work

### Documentation
- Add NOTICE file for third-party attributions
- Clarify profiles section wording in README

## [0.11.0] - 2026-01-18

### Added
- **Profile template syntax** for validity, CDP, AIA, and CPS URIs
- **OCSP/TSA graceful shutdown** with `stop` command and `--pid-file` option
- **IANA-allocated composite OIDs** per IETF draft-ietf-lamps-pq-composite-sigs-13
- New composite algorithms: `MLDSA65-ECDSA-P384-SHA512`, `MLDSA87-ECDSA-P521-SHA512`
- P-521 support in composite operations
- Concurrency tests for OCSP responder and TSA key access
- CRL tests for catalyst/composite/multi scenarios
- Profile template resolution and edge case tests
- Helper function unit tests (ca_helpers, cert_info_helpers)

### Changed
- Reduced cyclomatic complexity across CLI commands
- Use long CLI arguments (`--output` instead of `-o`) for consistency
- Test coverage improved from 68.8% to 69.8%

### Fixed
- Hybrid profile detection and archived version activation in CA operations
- ML-KEM CMS decryption interoperability with OpenSSL 3.6+
- Profile export serialization for validity format and subject structure
- BouncyCastle interop: removed BCPQC provider conflict for ML-KEM CMS

### Documentation
- Complete X.509 extensions documentation for profiles
- SKI/AKI automatic extensions documentation
- Key formats documentation (PEM, DER, PKCS#8)
- Add table of contents to all documentation files
- Harmonize documentation structure across all files
- Add `stop` command and `--pid-file` documentation for OCSP/TSA

## [0.10.0] - 2026-01-13

### Added
- RFC 5280 extension criticality validation
- URI support in SubjectAltName extension
- `--composite` flag for IETF draft-13 CSR generation
- `--catalyst` flag for unified hybrid CSR syntax
- Structured error types for ca, cms, profile, tsa packages
- ML-KEM column in cross-validation matrix
- CMS encryption tests (OpenSSL & BouncyCastle)
- Test reporter with TC-IDs for BouncyCastle cross-tests

### Fixed
- Catalyst hybrid CSR signature generation
- CPS URI encoding as IA5String (RFC compliant)

### Documentation
- Add GOVERNANCE.md
- Reorganize testing documentation with CI visibility

### Contributors
- @eabalea - CPS URI IA5String encoding fix

## [0.9.0] - 2026-01-11

### Added
- Unified `CryptoContext` interface for crypto operations
- `Config.Validate()` for CA configuration validation

### Changed
- Add `context.Context` propagation throughout business methods
- Extract `ca.Store` and `profile.Store` interfaces for storage abstraction
- Move enrollment/rotate logic from `ca/` to `credential/`
- Split large files (`ca.go`, `ca_test.go`) into focused modules

### Fixed
- PreTBS version detection for Catalyst CRL interoperability
- Ineffectual assignment lint errors

### Documentation
- Add AI usage policy
- Add CLA and update HSM documentation
- Improve README intro and add QLAB link

## [0.8.0] - 2026-01-09

### Added
- **AuthEnvelopedData (RFC 5083)** for AES-GCM encryption
- `--cred-dir` flag for independent credential storage
- Darwin universal binary (arm64 + amd64)
- Improved hybrid certificate naming convention
- Better certificate chain exports for crypto-agility

### Changed
- Homogenize `--dir` → `--ca-dir` for CA commands
- Remove legacy CA format support (require CAInfo)
- Versioned CA structure

### Fixed
- ML-KEM private keys support in CMS decrypt
- PQC CA rotation nested version structure
- Multiple CAs support in trust bundle verification
- IETF composite certificate creation for rotation
- HSM CA init creates versioned structure

### Documentation
- Restructure documentation with dedicated files
- Add crypto-agility feature description
- Fix all command examples with correct flags

### Contributors
- @eabalea - Darwin universal binary support

## [0.7.0] - 2026-01-07

### Added
- **Multi-profile versioning** for CA and credentials
- Atomic activation with `active/` directory
- `--chain` flag for certificate chain verification
- `key pub` command with ML-KEM support
- Migrate ML-DSA to **FIPS 204** (`mldsa` package)

### Changed
- `--dir` → `--ca-dir` homogenization
- KeyManager → KeyProvider with `crypto.Decrypter` support
- Versioned CA structure with `keys/` and `certs/` directories

### Testing
- BouncyCastle interop tests for CMS, OCSP, TSA
- Comprehensive fuzz testing

## [0.6.0] - 2026-01-03

### Added
- **PKCS#11 HSM support** (SoftHSM2, hardware HSMs)
- Unified KeyManager interface for software/HSM
- Session pooling for HSM operations
- OpenSSL 3.6 cross-tests

### Fixed
- OCSP byKey encoding for RFC compliance
- TSA token encoding for RFC 3161 compliance
- CMS verification with `-binary` flag

## [0.5.0] - 2025-12-30

### Added
- Signature algorithm configuration in YAML profiles
- Renamed profile categories: `ml-dsa-kem` → `ml`, `slh-dsa` → `slh`

### Documentation
- HSM compatibility table
- Security levels for classical vs post-quantum algorithms

## [0.4.0] - 2025-12-30

### Added
- **IETF Composite Signatures** (draft-ietf-lamps-pq-composite-sigs-13)
- Cross-testing infrastructure (OpenSSL + BouncyCastle)
- CA/credential rotation commands
- `--var` and `--var-file` for certificate issuance
- DNS validation (RFC 1035/4343/6125)

### Changed
- CLI restructured to namespace-style (`qpki ca`, `qpki cert`, etc.)
- Rename `pki` → `qpki`
- Bundle → Credential terminology

### Testing
- Test coverage improved to 70%+

## [0.3.0] - 2025-12-24

### Added
- **CMS EnvelopedData** encrypt/decrypt with ML-KEM
- **RFC 6960 OCSP** responder with PQC support
- **RFC 3161 TSA** Time-Stamp Authority with PQC
- **SLH-DSA (FIPS 205)** stateless hash-based signatures
- Certificate profile templates with variables
- `pki verify` command for certificate validation

### Changed
- Unified profile system (Gamme → Profile)
- Certificate templates with `{{ template }}` syntax

## [0.2.0] - 2025-12-16

### Added
- `--parent` flag for subordinate CA creation
- GPG signing for releases
- Homebrew tap support

## [0.1.0] - 2025-12-15

### Added
- Complete PKI implementation with ML-DSA-44/65/87 and ML-KEM-512/768/1024
- CLI tool for certificate management
- GoReleaser for pre-built binaries
