#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUST_DIR="$(dirname "$SCRIPT_DIR")/rust"

cd "$RUST_DIR"

echo "[1/4] Checking formatting..."
cargo fmt --check

echo "[2/4] Running clippy..."
cargo clippy --all-targets --all-features -- -D warnings

echo "[3/4] Running tests..."
cargo test --workspace

echo "[4/4] Building RPM..."
cargo build --release -p trustruntime
cargo generate-rpm -p trustruntime

echo ""
echo "RPM package built successfully"
ls -la target/generate-rpm/*.rpm