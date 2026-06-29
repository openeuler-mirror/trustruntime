# Integration Test Reference

## Certificate Structure

```
<HOME>/test-certs/
├── cms/
│   ├── ca.crt, cms.crl        # CA root + CRL
│   ├── node-a,b,c/            # Valid node certs
│   ├── expired/, revoked/     # Error scenario certs
│   └── self-signed/           # Chain invalid cert
├── tls/
│   ├── ca.crt                 # TLS CA
│   ├── server/node-a,b,c/     # Server TLS certs
│   └── client/                # Client TLS cert
```

## Test Framework Internals

### ProcessManager (`proc_manager.rs`)
- Starts trustruntime processes with temp configs
- Waits for vsock port readiness (5s timeout)
- Auto-stops all processes on Drop

### VsockClient (`vsock_client.rs`)
- Connects via vsock (Linux) or TCP fallback (non-Linux)
- Wraps connection with TLS (Linux only)
- Sends/receives CMS protocol messages

### Test Paths (`test_utils.rs`)
- Binary: `<PROJECT_ROOT>/rust/target/release/trustruntime`
- Certs: `$HOME/test-certs/`
- Configurable via env vars: `TEST_CERT_DIR`, `TEST_BINARY_PATH`

## Normal Scenarios (`normal_scenarios.rs`)

| Test | Description |
|------|-------------|
| `n01_two_node_sign_verify` | A signs → B verify+sign → A verify |
| `n02_three_node_sign_verify` | A → B → C chain |
| `n03_single_node_sign_verify` | Self-signing identity conflict |

## Error Scenarios (`error_scenarios.rs`)

| Error Type | Result Code |
|------------|-------------|
| Signature mismatch | 5 |
| Certificate chain invalid | 3 |
| CRL revoked | 4 |
| CMS format error | 6 |
| JSON parse error | 10 |
| Base64 parse error | 11 |

## Boundary Scenarios (`boundary_scenarios.rs`)

- Expired certificates
- Message size limits (>10KB)
- Empty/special data