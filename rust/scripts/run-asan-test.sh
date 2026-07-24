#!/bin/bash
# 使用 AddressSanitizer 运行测试
#
# 用途：检测内存泄漏、缓冲区溢出、双重释放等问题
#
# 使用方法：
#   ./scripts/run-asan-test.sh
#
# 前置条件：
#   - 已安装 nightly Rust：rustup install nightly
#   - 在 WSL 或 Linux 环境中运行
#
# 注意：
#   - ASan 会降低性能 2-3 倍
#   - 建议使用单线程测试

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUST_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "========================================="
echo "Running tests with AddressSanitizer"
echo "========================================="

# 检查 nightly Rust 是否已安装
if ! rustup show | grep -q "nightly"; then
    echo "Error: nightly Rust not found"
    echo "Please install: rustup install nightly"
    exit 1
fi

# 设置环境变量
export RUSTFLAGS="-Zsanitizer=address -C debug-assertions=on -C overflow-checks=on"
export RUST_BACKTRACE=full
export ASAN_OPTIONS="detect_leaks=1:symbolize=1:external_symbolizer_path=/usr/bin/llvm-symbolizer-18:abort_on_error=1:alloc_dealloc_mismatch=1:print_legend=1:print_stats=1"

# 运行测试
echo ""
echo "Running tests..."
cd "$RUST_DIR"

cargo +nightly test --workspace \
    --target x86_64-unknown-linux-gnu \
    --lib --tests \
    -- --test-threads=1

echo ""
echo "========================================="
echo "ASan tests passed!"
echo "========================================="