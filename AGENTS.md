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
- **Async architecture**: TransportLayer trait (transport module) uses async-trait, main.rs uses #[tokio::main(worker_threads = 4)]
- **Handler panic recovery**: catch_unwind returns error type 0x00, None returns 0x01
- **Concurrent connection limit**: Semaphore with 16 permits for vsock connections

## Performance Configuration

- **Tokio runtime**: Fixed 4 worker threads (sufficient for max 16 concurrent connections)
- **Concurrent limit**: Semaphore(16) controls maximum concurrent connections
- **Thread efficiency**: 4 threads can handle 16+ async tasks efficiently (tasks release threads during I/O wait)

## RPM Packaging

- Build RPM: `packaging/build-rpm.sh` or use wsl-cargo skill
- RPM config: `rust/trustruntime/Cargo.toml` `[package.metadata.generate-rpm]`
- Output: `target/generate-rpm/trustruntime-<version>-<release>.x86_64.rpm`
- Dependencies auto-detected (OpenSSL, systemd, glibc)

## Logging Security

### Prohibited Sensitive Information
- File paths (certificate paths, config file paths, key paths)
- Key material (private key content, passwords)
- Certificate details (not_before/not_after timestamps)
- Configuration parameters (port numbers and connection limits are acceptable)

### Secure Logging Patterns
- Use fixed descriptions instead of dynamic paths
- Use error codes instead of error details (when details may contain paths)

### Log Level Restrictions
- Release build: Only info/warn/error levels allowed
- Debug build: All levels (trace/debug/info/warn/error) allowed
- Configuration validation rejects trace/debug in release build

### Compliant Examples
- `log::error!("Handler panic for msg_type {}", msg.header.msg_type)` - Only logs message type code
- `log::warn!("TLS handshake failed: {}", e)` - Error details do not contain sensitive information
