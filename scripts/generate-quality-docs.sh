#!/bin/bash
# Generate all quality documentation from machine-readable specs
# Single source of truth principle: specs/ -> docs/quality/
#
# Usage: ./scripts/generate-quality-docs.sh
#
# This script generates:
#   - docs/quality/compliance/FIPS.md    (from specs/compliance/standards-matrix.yaml)
#   - docs/quality/compliance/RFC.md     (from specs/compliance/standards-matrix.yaml)
#   - docs/quality/testing/CATALOG.md    (from specs/tests/test-catalog.yaml)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_ROOT"

echo "=== Generating Quality Documentation ==="
echo ""

# Check dependencies
if ! command -v yq &> /dev/null; then
    echo "Error: yq is required. Install with: brew install yq"
    exit 1
fi

# Generate compliance documentation
echo "--- Compliance Documentation ---"
./scripts/generate-compliance-docs.sh
echo ""

# Generate test catalog documentation
echo "--- Test Catalog Documentation ---"
./scripts/generate-test-catalog-docs.sh
echo ""

# Generate CLI coverage documentation
echo "--- CLI Coverage Documentation ---"
./scripts/generate-cli-coverage.sh
echo ""

# Generate feature coverage documentation
echo "--- Feature Coverage Documentation ---"
./scripts/generate-feature-coverage.sh
echo ""

# Generate interoperability documentation
echo "--- Interoperability Documentation ---"
./scripts/generate-interop-docs.sh
echo ""

echo "=== Quality Documentation Complete ==="
echo ""
echo "Generated files:"
echo "  - docs/quality/compliance/FIPS.md"
echo "  - docs/quality/compliance/RFC.md"
echo "  - docs/quality/compliance/INTEROP.md"
echo "  - docs/quality/testing/CATALOG.md"
echo "  - docs/quality/testing/CLI-COVERAGE.md"
echo "  - docs/quality/testing/FEATURES.md"
echo ""
echo "Manual files (not generated):"
echo "  - docs/quality/testing/STRATEGY.md"
echo "  - docs/quality/testing/NAMING.md"
echo "  - docs/quality/README.md"
