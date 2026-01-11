# Changelog

## [0.9.0] - 2025-01-11

### Added
- Config.Validate() for CA configuration validation
- Unified CryptoContext interface for crypto operations
- CLA (Contributor License Agreement)
- HSM documentation with verified PQC vendor capabilities

### Fixed
- Ineffectual assignment lint errors in CA rotate files

### Changed
- Major refactoring: context.Context propagation throughout codebase
- Split large files into focused modules (ca.go, credential, tests)
- Extract Store interfaces for better abstraction
- Move credential logic from ca/ to credential/

### Documentation
- Add AI usage policy
- Add Contributing section with CLA reference
- Improve HSM compatibility table with PQC vendor info
- Simplify README intro
