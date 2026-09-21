#!/usr/bin/env bash
#
# AgentSandbox workspace unified build script.
#
# Builds workspace crates and collects publishable artifacts into script/out/.
#
# Modes:
#   full (default)     Build all crates (scene 1: controller + hook + proxy_proc + BPF)
#   proxy-lib          Build proxy lib only (scene 2: independent lib integration)
#
# Usage:
#   ./script/build.sh                       # full build, default target
#   ./script/build.sh aarch64-unknown-linux-gnu
#   ./script/build.sh --proxy-lib           # scene 2 proxy lib only
#   ./script/build.sh --proxy-lib aarch64-unknown-linux-gnu
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="$SCRIPT_DIR/out"

# ---- Parse args ----

MODE="full"
TARGET=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --proxy-lib)
            MODE="proxy-lib"
            shift
            ;;
        *)
            TARGET="$1"
            shift
            ;;
    esac
done

if [[ -z "$TARGET" ]]; then
    TARGET="$(sed -n 's/.*target *= *"\(.*\)"/\1/p' "$WORKSPACE_DIR/.cargo/config.toml" 2>/dev/null || true)"
fi

echo "============================================"
echo " AgentSandbox Unified Build"
echo " Mode:     $MODE"
echo " Workspace: $WORKSPACE_DIR"
echo " Target:    ${TARGET:-default}"
echo " Out dir:   $OUT_DIR"
echo "============================================"

cd "$WORKSPACE_DIR"

# ---- Helpers ----

cargo_build() {
    local -a args=(cargo build --release)
    if [[ -n "$TARGET" ]]; then
        args+=(--target "$TARGET")
    fi
    args+=("$@")
    "${args[@]}"
}

target_release_dir() {
    if [[ -n "$TARGET" ]]; then
        echo "$WORKSPACE_DIR/target/$TARGET/release"
    else
        echo "$WORKSPACE_DIR/target/release"
    fi
}

# ---- Full build (scene 1) ----

build_full() {
    echo ""
    echo "[1/3] Building all workspace crates..."
    cargo_build

    local release_dir
    release_dir="$(target_release_dir)"

    echo ""
    echo "[2/3] Collecting artifacts to $OUT_DIR..."
    rm -rf "$OUT_DIR"
    mkdir -p "$OUT_DIR/bin" "$OUT_DIR/bpf"

    # Binaries
    local binaries=(
        "agentsandbox-controller"
        "agentsandbox-hook"
        "agentsandbox-proxy"
    )
    for bin in "${binaries[@]}"; do
        local src="$release_dir/$bin"
        if [[ -f "$src" ]]; then
            cp "$src" "$OUT_DIR/bin/"
            echo "  [bin] $bin"
        else
            echo "  [WARN] binary not found: $bin (expected at $src)"
        fi
    done

    # BPF object files
    local bpf_search_base="$WORKSPACE_DIR/target"
    if [[ -n "$TARGET" ]]; then
        bpf_search_base="$bpf_search_base/$TARGET"
    fi
    local bpf_build_dir
    bpf_build_dir="$(find "$bpf_search_base/release/build" -maxdepth 2 -path '*/agentsandbox-security-*/out' -type d 2>/dev/null | head -1)"
    if [[ -n "$bpf_build_dir" ]]; then
        for obj in "$bpf_build_dir"/*.bpf.o; do
            if [[ -f "$obj" ]]; then
                cp "$obj" "$OUT_DIR/bpf/"
                echo "  [bpf] $(basename "$obj")"
            fi
        done
    else
        echo "  [WARN] BPF build dir not found under target/"
    fi
}

# ---- Proxy lib build (scene 2) ----

build_proxy_lib() {
    echo ""
    echo "[1/3] Building proxy lib (scene 2: independent lib integration)..."
    cargo_build -p agentsandbox-proxy

    local release_dir
    release_dir="$(target_release_dir)"

    echo ""
    echo "[2/3] Collecting artifacts to $OUT_DIR..."
    rm -rf "$OUT_DIR"
    mkdir -p "$OUT_DIR/lib" "$OUT_DIR/header"

    # Proxy rlib
    local rlib
    rlib="$(find "$release_dir" -maxdepth 1 -name 'libagentsandbox_proxy*.rlib' -type f 2>/dev/null | head -1)"
    if [[ -n "$rlib" ]]; then
        cp "$rlib" "$OUT_DIR/lib/"
        echo "  [lib] $(basename "$rlib")"
    else
        echo "  [WARN] proxy rlib not found in $release_dir"
    fi

    # Inference dependency rlib (proxy depends on it)
    local inference_rlib
    inference_rlib="$(find "$release_dir" -maxdepth 1 -name 'libagentsandbox_inference*.rlib' -type f 2>/dev/null | head -1)"
    if [[ -n "$inference_rlib" ]]; then
        cp "$inference_rlib" "$OUT_DIR/lib/"
        echo "  [dep] $(basename "$inference_rlib")"
    fi

    # Inference router config templates (real library deployment defaults —
    # AGENT_ROUTER_CONFIG_DIR points at a directory with these 4 files).
    if [[ -d "$WORKSPACE_DIR/inference/resources/config" ]]; then
        mkdir -p "$OUT_DIR/inference-config"
        cp "$WORKSPACE_DIR"/inference/resources/config/*.json "$OUT_DIR/inference-config/"
        echo "  [cfg] inference-config/*.json"
    fi

    # Copy public API source as header reference for integrators
    if [[ -f "$WORKSPACE_DIR/proxy/src/lib.rs" ]]; then
        cp "$WORKSPACE_DIR/proxy/src/lib.rs" "$OUT_DIR/header/proxy_api.rs"
        echo "  [api] proxy_api.rs"
    fi
    if [[ -f "$WORKSPACE_DIR/proxy/src/facade/mod.rs" ]]; then
        cp "$WORKSPACE_DIR/proxy/src/facade/mod.rs" "$OUT_DIR/header/facade.rs"
        echo "  [api] facade.rs"
    fi
    if [[ -f "$WORKSPACE_DIR/proxy/src/model.rs" ]]; then
        cp "$WORKSPACE_DIR/proxy/src/model.rs" "$OUT_DIR/header/model.rs"
        echo "  [api] model.rs"
    fi

    # Copy Cargo.toml for dependency reference
    cp "$WORKSPACE_DIR/proxy/Cargo.toml" "$OUT_DIR/lib/Cargo.toml.proxy"
    echo "  [meta] Cargo.toml.proxy"
}

# ---- Execute ----

case "$MODE" in
    full)      build_full ;;
    proxy-lib) build_proxy_lib ;;
esac

# ---- Summary ----

echo ""
echo "[3/3] Done. Artifacts:"
find "$OUT_DIR" -type f | sort | while read -r f; do
    SIZE=$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f" 2>/dev/null || echo "?")
    echo "  $f ($SIZE bytes)"
done
