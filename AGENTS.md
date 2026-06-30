# Agent Instructions

## Build & Test Environment

This project targets **Linux** as the primary build environment.

- **Linux**: Native build environment (recommended)
- **Windows + WSL**: Alternative for Windows developers

**Linux quick reference:**
```bash
cd rust && cargo test --workspace
```

**WSL quick reference (Windows users):**
```bash
wsl bash -c "source ~/.cargo/env && cd <PROJECT_ROOT>/rust && cargo test --workspace"
```

See `.opencode/skills/wsl-cargo/SKILL.md` for WSL-specific command patterns.

## Project Structure

- **CONTEXT.md**: Domain glossary and terminology (authoritative)
- **docs/**: Design documents and ADRs
- **rust/**: Cargo workspace root
  - `framework/`: trustruntime-framework (library)
  - `plugins/trustring/`: trustring (library)
  - `trustruntime/`: trustruntime (binary)

## Testing

- Run all tests: `cargo test --workspace`
- Run specific crate: `cargo test -p <crate-name>`
- Tests use OpenSSL to generate temporary ECC-256 certificates
- Test fixtures are generated programmatically, not committed

## Code Style

- Follow existing patterns in each module
- Use `thiserror` for error types
- Use `serde` for serialization
- Prefer explicit error types over `Box<dyn Error>` in public APIs
- Tests should verify behavior through public interfaces (see TDD philosophy in user instructions)

## Documentation

- Design docs: `docs/detailed-design/` (7 files, one per functional domain)
- ADRs: `docs/adr/` (architecture decisions)
- Requirements: `docs/requirements.md`
- Interface spec: `docs/interface.md`

## Key Conventions

- **Message module**: Pure data layer, no business validation (validation belongs in vsock_server)
- **Config module**: Optional fields use `Option<T>` or `#[serde(default)]`
- **Certificate loading**: PEM/DER dual-format support via `framework::cert`
- **Error mapping**: `error_code_mapper` converts domain errors to result codes 0-9
- **Plugin registration**: Plugins register supported message types via `ctx.register_handler(type)` in `init()`
- **Byte order**: All message serialization uses little-endian (LE) byte order
- **Async architecture**: TransportLayer trait uses async-trait, main.rs uses #[tokio::main]
- **Handler panic recovery**: catch_unwind returns error type 0x00, None returns 0x01
- **Concurrent connection limit**: Semaphore with 16 permits for vsock connections

## RPM Packaging

- Build RPM: `packaging/build-rpm.sh` or use wsl-cargo skill
- RPM config: `rust/trustruntime/Cargo.toml` `[package.metadata.generate-rpm]`
- Output: `target/generate-rpm/trustruntime-<version>-<release>.x86_64.rpm`
- Dependencies auto-detected (OpenSSL, systemd, glibc)
