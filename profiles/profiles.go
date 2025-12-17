// Package profiles provides embedded certificate profile templates.
//
// These profiles define certificate enrollment policies and are embedded
// in the binary for convenience. Users can also copy and customize them.
package profiles

import "embed"

// FS contains all embedded profile YAML files.
// Profiles are organized in subdirectories:
//   - ecdsa/     - ECDSA algorithm profiles
//   - rsa/       - RSA algorithm profiles (legacy)
//   - pqc/       - Post-quantum (ML-DSA) profiles
//   - slh-dsa/   - Hash-based signature profiles
//   - hybrid/    - Hybrid classical + PQC profiles
//     - catalyst/   - ITU-T X.509 9.8 combined certificates
//     - composite/  - Linked separate certificates
//
//go:embed all:ecdsa all:rsa all:pqc all:slh-dsa all:hybrid
var FS embed.FS
