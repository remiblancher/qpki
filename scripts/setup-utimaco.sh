#!/bin/bash
# setup-utimaco.sh - End-to-end setup for Utimaco PQC HSM testing
#
# This script automates:
# 1. Verifying prerequisites (SDK files)
# 2. Copying SDK to project vendor directory
# 3. Building Docker images (simulator + qpki-runner)
# 4. Starting the simulator
# 5. Initializing the HSM
# 6. Running acceptance tests
#
# Prerequisites:
#   - Docker installed and running
#   - Utimaco SDK and simulator in ../vendor/ (relative to project root)
#
# Usage:
#   ./scripts/setup-utimaco.sh              # Full setup + tests
#   ./scripts/setup-utimaco.sh --setup-only # Setup without running tests
#   ./scripts/setup-utimaco.sh --test-only  # Only run tests (assumes setup done)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VENDOR_SDK="${VENDOR_SDK:-$PROJECT_DIR/../vendor/utimaco-sdk}"
VENDOR_SIM="${VENDOR_SIM:-$PROJECT_DIR/../vendor/utimaco-sim}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() { echo -e "${GREEN}===${NC} $1"; }
warn() { echo -e "${YELLOW}⚠️  $1${NC}"; }
error() { echo -e "${RED}❌ $1${NC}"; exit 1; }
success() { echo -e "${GREEN}✓${NC} $1"; }

# =============================================================================
# 1. Check prerequisites
# =============================================================================
check_prerequisites() {
    info "Checking prerequisites..."

    # Docker
    if ! command -v docker &> /dev/null; then
        error "Docker not found. Please install Docker."
    fi

    if ! docker info &> /dev/null; then
        error "Docker daemon not running. Please start Docker."
    fi
    success "Docker OK"

    # PKCS#11 library
    if [ ! -f "$VENDOR_SDK/lib/libcs_pkcs11_R3.so" ]; then
        error "Missing: $VENDOR_SDK/lib/libcs_pkcs11_R3.so

Download from Utimaco u.trust GP HSM Simulator:
  Software/Linux/Crypto_APIs/PKCS11_R3/lib/libcs_pkcs11_R3.so"
    fi
    success "PKCS#11 library OK"

    # p11tool2 (for HSM init)
    if [ ! -f "$VENDOR_SDK/bin/p11tool2" ]; then
        warn "Missing: p11tool2 (HSM initialization may fail)"
    else
        success "p11tool2 OK"
    fi

    # qptool2 (for PQC)
    if [ ! -f "$VENDOR_SDK/bin/qptool2" ]; then
        warn "Missing: qptool2 (PQC key gen via CLI will fail)"
    else
        success "qptool2 OK"
    fi

    # ADMIN_SIM.key
    if [ ! -f "$VENDOR_SDK/bin/ADMIN_SIM.key" ]; then
        warn "Missing: ADMIN_SIM.key (HSM initialization may fail)"
    else
        success "ADMIN_SIM.key OK"
    fi

    # Simulator
    if [ ! -d "$VENDOR_SIM/sim5_linux" ]; then
        error "Missing: $VENDOR_SIM/sim5_linux

Download from Utimaco QuantumProtect Evaluation:
  linux/sim5_linux/"
    fi
    success "Simulator OK"

    echo ""
}

# =============================================================================
# 2. Setup vendor directory (copy files for Docker build)
# =============================================================================
setup_vendor() {
    info "Setting up vendor directory..."

    # Create directories
    mkdir -p "$PROJECT_DIR/vendor/utimaco-sdk/lib"
    mkdir -p "$PROJECT_DIR/vendor/utimaco-sdk/bin"
    mkdir -p "$PROJECT_DIR/docker/utimaco-sim/sim5_linux"

    # Copy SDK files
    cp -f "$VENDOR_SDK/lib/libcs_pkcs11_R3.so" "$PROJECT_DIR/vendor/utimaco-sdk/lib/"
    [ -f "$VENDOR_SDK/bin/p11tool2" ] && cp -f "$VENDOR_SDK/bin/p11tool2" "$PROJECT_DIR/vendor/utimaco-sdk/bin/"
    [ -f "$VENDOR_SDK/bin/qptool2" ] && cp -f "$VENDOR_SDK/bin/qptool2" "$PROJECT_DIR/vendor/utimaco-sdk/bin/"
    [ -f "$VENDOR_SDK/bin/ADMIN_SIM.key" ] && cp -f "$VENDOR_SDK/bin/ADMIN_SIM.key" "$PROJECT_DIR/vendor/utimaco-sdk/bin/"

    # Copy simulator for Docker build
    cp -rf "$VENDOR_SIM/sim5_linux/"* "$PROJECT_DIR/docker/utimaco-sim/sim5_linux/"

    success "Vendor directory configured"
    echo ""
}

# =============================================================================
# 3. Build Docker images
# =============================================================================
build_images() {
    info "Building Docker images..."
    cd "$PROJECT_DIR"

    echo "Building utimaco-sim..."
    docker build -t utimaco-sim docker/utimaco-sim/
    success "utimaco-sim built"

    echo "Building qpki-runner..."
    docker build -t qpki-runner -f docker/qpki-runner/Dockerfile .
    success "qpki-runner built"

    echo ""
}

# =============================================================================
# 4. Start simulator
# =============================================================================
start_simulator() {
    info "Starting Utimaco simulator..."

    # Create network if needed
    docker network create qpki-net 2>/dev/null || true

    # Stop existing container
    docker stop utimaco-sim 2>/dev/null || true
    docker rm utimaco-sim 2>/dev/null || true

    # Start simulator
    docker run -d --network qpki-net --name utimaco-sim utimaco-sim

    # Wait for startup
    echo "Waiting for simulator to start..."
    sleep 5

    # Check status
    if docker ps | grep -q utimaco-sim; then
        success "Simulator started"
        docker logs utimaco-sim 2>&1 | tail -3
    else
        error "Simulator failed to start. Check: docker logs utimaco-sim"
    fi

    echo ""
}

# =============================================================================
# 5. Initialize HSM
# =============================================================================
init_hsm() {
    info "Initializing HSM..."

    # Run HSM init script with correct entrypoint
    docker run --rm --network qpki-net --entrypoint /opt/utimaco/bin/init-hsm.sh qpki-runner || {
        warn "HSM initialization failed (may already be initialized)"
    }
    success "HSM initialization completed"

    echo ""
}

# =============================================================================
# 6. Run tests
# =============================================================================
run_tests() {
    info "Running acceptance tests with Utimaco HSM..."
    cd "$PROJECT_DIR"

    echo "Testing qpki version..."
    docker run --rm --network qpki-net \
        -e HSM_PIN=12345688 \
        qpki-runner --version

    echo ""
    echo "Running full acceptance tests..."
    docker run --rm --network qpki-net \
        -e TEST_HSM_MODE=1 \
        -e HSM_CONFIG=/etc/qpki/hsm.yaml \
        -e HSM_PIN=12345688 \
        -e HSM_PQC_ENABLED=1 \
        -e QPKI_BINARY=/opt/qpki/bin/qpki \
        --entrypoint /opt/qpki/bin/hsm_test \
        qpki-runner -test.v

    success "All tests completed"
}

# =============================================================================
# 7. Cleanup
# =============================================================================
cleanup() {
    info "Cleaning up..."
    docker stop utimaco-sim 2>/dev/null || true
    docker rm utimaco-sim 2>/dev/null || true
    success "Cleanup done"
}

# =============================================================================
# Main
# =============================================================================
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --setup-only    Setup environment without running tests"
    echo "  --test-only     Run tests only (assumes setup already done)"
    echo "  --cleanup       Stop and remove containers"
    echo "  --help          Show this help"
    echo ""
    echo "Environment variables:"
    echo "  VENDOR_SDK      Path to Utimaco SDK (default: ../vendor/utimaco-sdk)"
    echo "  VENDOR_SIM      Path to simulator (default: ../vendor/utimaco-sim)"
}

main() {
    cd "$PROJECT_DIR"

    case "${1:-}" in
        --setup-only)
            check_prerequisites
            setup_vendor
            build_images
            start_simulator
            init_hsm
            echo ""
            info "Setup complete! Run tests with: $0 --test-only"
            ;;
        --test-only)
            run_tests
            ;;
        --cleanup)
            cleanup
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        "")
            # Full run
            check_prerequisites
            setup_vendor
            build_images
            start_simulator
            init_hsm
            run_tests
            echo ""
            info "=== All Utimaco tests completed ==="
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
}

main "$@"
