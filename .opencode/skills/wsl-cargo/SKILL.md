---
name: wsl-cargo
description: Run cargo commands in WSL from Windows. Use when running cargo test/build/clippy/fmt for this project. This project uses WSL for Rust compilation.
---

# WSL Cargo Commands

## Pattern

**Always source cargo env before running commands:**

```bash
wsl bash -c "source ~/.cargo/env && cd <PROJECT_ROOT>/rust && cargo <command>"
```

Replace `<PROJECT_ROOT>` with actual WSL path (e.g., `/mnt/e/your_name/trustruntime`).

## Commands

```bash
# Test all crates
wsl bash -c "source ~/.cargo/env && cd <PROJECT_ROOT>/rust && cargo test --workspace"

# Test specific crate
wsl bash -c "source ~/.cargo/env && cd <PROJECT_ROOT>/rust && cargo test -p <crate-name>"

# Build release
wsl bash -c "source ~/.cargo/env && cd <PROJECT_ROOT>/rust && cargo build --release"

# Build debug
wsl bash -c "source ~/.cargo/env && cd <PROJECT_ROOT>/rust && cargo build"

# Clippy
wsl bash -c "source ~/.cargo/env && cd <PROJECT_ROOT>/rust && cargo clippy --workspace -- -D warnings"

# Format check
wsl bash -c "source ~/.cargo/env && cd <PROJECT_ROOT>/rust && cargo fmt --all -- --check"

# Format apply
wsl bash -c "source ~/.cargo/env && cd <PROJECT_ROOT>/rust && cargo fmt --all"

# Build RPM
wsl bash -c "source ~/.cargo/env && cd <PROJECT_ROOT> && bash packaging/build-rpm.sh"
```

## Workspace Crates

- `framework` - trustruntime-framework (library)
- `trustring` - plugins/trustring (library)
- `trustruntime` - main binary
- `integration-tests` - integration tests
- `cert-gen` - tools/cert-gen (binary)

## Notes

- Use `--workspace` for workspace-wide operations
- Set timeout to 180000ms for test/build operations