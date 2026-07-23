#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CERT_DIR="${CERT_DIR:-$HOME/test-certs}"

FORCE_CERTS=false
QUICK_MODE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --force) FORCE_CERTS=true; shift ;;
        --quick) QUICK_MODE=true; shift ;;
        --cert-dir) CERT_DIR="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

source ~/.cargo/env

export TEST_CERT_DIR="$CERT_DIR"
export TEST_BINARY_PATH="$PROJECT_ROOT/target/debug/trustruntime"

check_vsock_loopback() {
    echo "Checking vsock_loopback module..."
    if ! lsmod | grep -q vsock_loopback; then
        echo "  Loading vsock_loopback module..."
        sudo modprobe vsock_loopback
        if ! lsmod | grep -q vsock_loopback; then
            echo "ERROR: Failed to load vsock_loopback module"
            exit 1
        fi
        echo "  vsock_loopback module loaded successfully"
    else
        echo "  vsock_loopback module already loaded"
    fi
}

if [ "$QUICK_MODE" = false ]; then
    echo "[1/4] Generating test certificates to $CERT_DIR..."
    if [ "$FORCE_CERTS" = true ] || [ ! -d "$CERT_DIR" ]; then
        cd "$PROJECT_ROOT/tools/cert-gen"
        cargo run -- --output-dir "$CERT_DIR" --force
    else
        echo "  Certificates already exist at $CERT_DIR (use --force to regenerate)"
    fi

    echo "[2/4] Building debug binaries..."
    cd "$PROJECT_ROOT"
    cargo build -p trustruntime

    echo "[3/4] Checking vsock_loopback module..."
    check_vsock_loopback

    echo "[4/4] Running integration tests..."
else
    echo "[1/2] Checking vsock_loopback module..."
    check_vsock_loopback

    echo "[2/2] Running integration tests..."
fi

cd "$PROJECT_ROOT"
cargo test -p integration-tests -- --include-ignored --test-threads=1

echo ""
echo "All integration tests passed!"