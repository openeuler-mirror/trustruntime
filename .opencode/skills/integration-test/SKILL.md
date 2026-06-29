---
name: integration-test
description: Run integration tests for CMS signing service in WSL. Use when running integration tests, debugging test failures, or when user mentions "integration test" or test scenarios (N01-N03, E01-E20, B01-B07).
---

# Integration Test

## Quick Start (Linux)

```bash
cd rust/scripts && ./run-integration-tests.sh
```

## Quick Start (WSL)

```bash
wsl bash -c "cd <PROJECT_ROOT>/rust/scripts && ./run-integration-tests.sh"
```

Replace `<PROJECT_ROOT>` with actual WSL path (e.g., `/mnt/e/your_name/trustruntime`).

## Script Options

| Option | Description |
|--------|-------------|
| `--force` | Regenerate certificates |
| `--quick` | Skip cert generation and build |
| `--cert-dir <path>` | Custom certificate directory |

## Manual Steps

**IMPORTANT**: Use `--test-threads=1` to avoid vsock port conflicts.

```bash
# 1. Generate certs
cd rust/tools/cert-gen && cargo run --release -- --output-dir ~/test-certs --force

# 2. Build
cd rust && cargo build --release -p trustruntime

# 3. Test (single thread!)
cargo test --release -p integration-tests -- --include-ignored --test-threads=1
```

## Prerequisites

| Requirement | Check (WSL) |
|-------------|-------------|
| vsock module | `wsl bash -c "lsmod | grep vsock"` |
| Rust toolchain | `wsl bash -c "source ~/.cargo/env && rustc --version"` |
| OpenSSL 3.0+ | `wsl bash -c "openssl version"` |

## Troubleshooting

| Issue | Solution |
|-------|----------|
| TLS/vsock errors | Use `--test-threads=1` |
| vsock connection refused | Check vsock module loaded |
| Certificate not found | Run with `--force` |
| Process timeout | Check `/tmp/.tmp*/trustring.log` |

## Test Categories

- **Normal (N01-N03)**: Multi-node signing/verification flows
- **Error (E01-E20)**: Signature failures, certificate issues, format errors
- **Boundary (B01-B07)**: Certificate expiry, message limits, data boundaries

## Reference

- Detailed test scenarios: See [REFERENCE.md](REFERENCE.md)
- Test design: See `docs/integration-test-design.md`