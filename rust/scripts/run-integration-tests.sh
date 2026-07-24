#!/bin/bash
# 运行集成测试（带 ASan 内存检查）
#
# 用途：
#   - 运行集成测试用例
#   - 自动检测内存泄漏、缓冲区溢出、双重释放等问题
#
# 使用方法：
#   ./scripts/run-integration-tests.sh [--force] [--quick] [--cert-dir <path>]
#
# 前置条件：
#   - 已安装 nightly Rust：rustup install nightly
#   - 在 WSL 或 Linux 环境中运行
#   - vsock_loopback 模块可用
#
# 注意：
#   - ASan 会降低性能 2-3 倍
#   - 建议使用单线程测试

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
export TEST_BINARY_PATH="$PROJECT_ROOT/target/x86_64-unknown-linux-gnu/debug/trustruntime"

export RUSTFLAGS="-Zsanitizer=address -C debug-assertions=on -C overflow-checks=on"
export RUST_BACKTRACE=full
export ASAN_OPTIONS="detect_leaks=1:symbolize=1:external_symbolizer_path=/usr/bin/llvm-symbolizer-18:abort_on_error=1:alloc_dealloc_mismatch=1:print_legend=1:print_stats=1"

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

    echo "[2/4] Building debug binaries with ASan..."
    cd "$PROJECT_ROOT"
    cargo +nightly build -p trustruntime --target x86_64-unknown-linux-gnu

    echo "[3/4] Checking vsock_loopback module..."
    check_vsock_loopback

    echo "[4/4] Running integration tests with ASan..."
else
    echo "[1/2] Checking vsock_loopback module..."
    check_vsock_loopback

    echo "[2/2] Running integration tests with ASan..."
fi

cd "$PROJECT_ROOT"
cargo +nightly test -p integration-tests \
    --target x86_64-unknown-linux-gnu \
    --lib --tests \
    -- --include-ignored --test-threads=1

echo ""
echo "All integration tests passed with ASan!"