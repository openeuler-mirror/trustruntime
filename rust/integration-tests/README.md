# Integration Tests

集成测试，验证CMS签名验签服务的端到端功能。

## 测试场景

| 模块 | 用例 | 说明 |
|------|------|------|
| `normal_scenarios` | N01-N03 | 正常场景：多节点签名/验签流程 |
| `error_scenarios` | E01-E20 | 错误场景：签名不匹配、证书无效、CRL吊销、格式错误 |
| `boundary_scenarios` | B01-B07 | 边界场景：过期证书、消息大小限制、特殊数据 |
| `communication_tests` | C01-C04 | 通信测试：TLS认证、协议错误 |

## 快速运行

推荐使用脚本一键运行。以下命令需在 `rust/integration-tests/` 目录下执行：

```bash
cd ../scripts && ./run-integration-tests.sh
```

选项：
- `--force`: 强制重新生成证书
- `--quick`: 跳过证书生成和编译（仅运行测试）

## 手动运行

以下命令需在 `rust/` 目录下执行。

所有测试用例默认被忽略（需要Linux/vsock环境和预生成证书），必须使用 `--include-ignored` 参数。

**重要**：必须使用 `--test-threads=1` 避免 vsock 端口冲突。

```bash
# 构建release版本
cargo build --release -p trustruntime

# 生成测试证书（默认位置：<HOME>/test-certs）
cargo run --release -p cert-gen -- --output-dir ~/test-certs --force

# 运行所有集成测试
cargo test --release -p integration-tests -- --include-ignored --test-threads=1

# 运行特定测试
cargo test --release -p integration-tests -- --include-ignored --test-threads=1 n01_two_node
```

## 前置条件

| 要求 | Linux检查命令 | WSL检查命令（Windows替代） |
|------|---------------|---------------------------|
| vsock模块 | `lsmod | grep vsock` | `wsl bash -c "lsmod | grep vsock"` |
| Rust工具链 | `rustc --version` | `wsl bash -c "source ~/.cargo/env && rustc --version"` |
| OpenSSL 3.0+ | `openssl version` | `wsl bash -c "openssl version"` |

> **注意**：WSL仅作为Windows开发者的替代方案，Linux环境为首选构建环境。

## 路径配置

测试框架支持通过环境变量配置路径：

| 环境变量 | 说明 | 默认值 |
|----------|------|--------|
| `TEST_CERT_DIR` | 证书目录 | `$HOME/test-certs` |
| `TEST_BINARY_PATH` | 二进制路径 | `target/release/trustruntime` |

使用方式：

```bash
# 使用自定义证书目录
export TEST_CERT_DIR=~/my-certs
cargo test --release -p integration-tests -- --include-ignored --test-threads=1

# 或通过脚本指定
cd ../scripts && ./run-integration-tests.sh --cert-dir ~/my-certs
```

默认值需根据实际环境修改 `test_utils.rs` 中的 `TestPaths::new()`。

## 证书结构

```
<HOME>/test-certs/
├── cms/                          # CMS签名验签证书
│   ├── ca.crt                    # CA根证书
│   ├── ca.key                    # CA私钥
│   ├── cms.crl                   # CRL（含吊销证书）
│   ├── node-a/, node-b/, node-c/ # 有效节点证书
│   ├── expired/                  # 过期证书
│   ├── revoked/                  # 被吊销证书
│   └── self-signed/              # 自签名证书
└── tls/                          # TLS通信证书
    ├── ca.crt                    # TLS CA根证书
    ├── other-ca.crt              # 其他CA（错误CA测试）
    ├── client-crl.crt            # 客户端CRL
    ├── server/node-a/, node-b/, node-c/ # 服务端证书
    └── client/                   # 客户端证书（含被吊销、错误CA）
```

## 测试框架

| 模块 | 说明 |
|------|------|
| `proc_manager` | 进程管理：启动/停止trustruntime服务，等待vsock端口就绪 |
| `vsock_client` | vsock TLS客户端：发送/接收CMS协议消息 |
| `test_utils` | 测试工具：证书路径、断言函数、请求构造 |

## 常见问题

| 问题 | 解决方案 |
|------|----------|
| TLS/vsock错误 | 使用 `--test-threads=1`（并行测试导致端口冲突） |
| vsock连接拒绝 | 检查 `lsmod | grep vsock`，重新加载模块 |
| 证书未找到 | 运行 `cd ../scripts && ./run-integration-tests.sh --force` |
| 进程超时 | 检查 `/tmp/.tmp*/trustring.log` 日志 |
| TLS握手失败 | 验证证书路径与配置匹配 |

## 详细设计

参见 `docs/integration-test-design.md` 和 `.opencode/skills/integration-test/SKILL.md`。