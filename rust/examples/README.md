# TrustRuntime 示例代码

本目录包含与 TrustRuntime CMS 签名验签服务交互的示例代码。

## 示例列表

| 文件 | 说明 | 接口类型 |
|------|------|----------|
| `sign_example.rs` | 签名示例 | 0x10→0x11 |
| `verify_and_sign_example.rs` | 验签+签名示例 | 0x12→0x13 |
| `verify_example.rs` | 验签示例 | 0x14→0x15 |

## 运行环境

示例代码需要：

- Linux 系统（vsock 支持）
- Rust 工具链
- OpenSSL 开发库

## 运行方式

示例代码需要在 WSL 或 Linux 环境中使用 cargo 编译运行：

```bash
cd rust

# 运行签名示例（需要 TrustRuntime 服务已启动）
cargo run --example sign_example

# 运行验签+签名示例
cargo run --example verify_and_sign_example

# 运行验签示例
cargo run --example verify_example
```

## 配置

### 连接配置

| 环境变量 | 默认值 | 说明 |
|----------|--------|------|
| `TRUSTRUNTIME_CID` | 3 | vsock CID（机密虚机） |
| `TRUSTRUNTIME_PORT` | 12345 | vsock 端口 |

### 证书配置

示例代码使用 TLS 双向认证，需配置客户端证书：

| 环境变量 | 默认值 | 说明 |
|----------|--------|------|
| `TRUSTRUNTIME_CLIENT_CERT` | `/etc/cert/cms/communication/client.crt` | 客户端证书 |
| `TRUSTRUNTIME_CLIENT_KEY` | `/etc/cert/cms/communication/client.key` | 客户端私钥 |
| `TRUSTRUNTIME_CA_CERT` | `/etc/cert/cms/communication/ca_root.crt` | CA根证书 |

#### 测试证书

使用 cert-gen 工具生成测试证书：

```bash
cd rust && cargo run -p cert-gen -- --output-dir /tmp/test-certs
```

生成后设置环境变量：

```bash
export TRUSTRUNTIME_CLIENT_CERT=/tmp/test-certs/tls/client/client.crt
export TRUSTRUNTIME_CLIENT_KEY=/tmp/test-certs/tls/client/client.key
export TRUSTRUNTIME_CA_CERT=/tmp/test-certs/tls/ca.crt
```

## 依赖

示例代码依赖以下 crate：

- `openssl` - TLS 客户端
- `vsock` - vsock 通信（需要 Linux 内核支持）

添加到 `Cargo.toml`：

```toml
[dev-dependencies]
openssl = "0.10"
vsock = "0.4"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
base64 = "0.22"
```

## 注意事项

1. 示例代码需要在 TrustRuntime 服务启动后运行
2. 需要配置正确的客户端证书用于 TLS 双向认证
3. 示例证书路径为示例用途，实际部署需要使用真实证书

## 相关文档

- [接口文档](../docs/interface.md)
- [使用指南](../docs/user-guide.md)
- [架构设计](../docs/architecture.md)