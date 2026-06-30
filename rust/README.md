# Rust Workspace

Cargo workspace，包含框架、插件、主程序、测试和工具。

## 结构

| Crate | 说明 |
|-------|------|
| `framework` | 通用进程框架：vsock通信、TLS、配置、日志、插件管理 |
| `trustruntime` | 主程序入口 |
| `plugins/trustring` | CMS签名验签业务插件 |
| `integration-tests` | 集成测试 |
| `tools/cert-gen` | ECC-256测试证书生成工具 |
| `tools/cms-test-cli` | CMS签名服务交互测试工具（REPL界面） |
| `examples/` | 示例代码（签名、验签、验签+签名） |

## 构建

```bash
# 开发构建
cargo build

# 发布构建
cargo build --release
```

## 测试

```bash
# 单元测试
cargo test --workspace

# 单个crate测试
cargo test -p trustruntime-framework
cargo test -p trustring

# 集成测试（推荐使用脚本）
cd scripts && ./run-integration-tests.sh
```

> **Windows用户替代方案**：使用WSL执行cargo命令，参见 `.opencode/skills/wsl-cargo/SKILL.md`。

## 脚本工具

`scripts/` 目录包含开发和测试脚本：

| 脚本 | 用途 | 证书路径（默认） |
|------|------|----------|
| `run-integration-tests.sh` | 完整集成测试流程（推荐） | `$HOME/test-certs` |
| `vsock-test.sh` | vsock连接测试（多CID） | `/tmp/test-certs` |
| `manual-start.sh` | 手动启动服务+测试连接 | `/tmp/test-certs` |
| `manual-test-home.sh` | 手动启动（集成测试配套） | `$HOME/test-certs` |

### run-integration-tests.sh（推荐）

完整的集成测试流程，自动处理：
- 生成测试证书
- 编译release版本
- 加载vsock_loopback模块
- 运行所有集成测试

```bash
cd scripts

# 完整流程（证书目录默认为 $HOME/test-certs）
./run-integration-tests.sh

# 强制重新生成证书
./run-integration-tests.sh --force

# 快速模式（跳过证书生成和编译）
./run-integration-tests.sh --quick

# 指定证书目录
./run-integration-tests.sh --cert-dir ~/my-certs
```

选项：
- `--force`: 强制重新生成证书
- `--quick`: 跳过证书生成和编译（仅运行测试）
- `--cert-dir <path>`: 指定证书目录（默认 `$HOME/test-certs`）

### vsock连接测试

测试不同CID的vsock连接：

```bash
cd scripts && ./vsock-test.sh
# 测试 CID=1, CID=2, CID=-1 (HOST)
```

### 手动启动测试

```bash
# 使用/tmp路径（临时测试）
cd scripts && ./manual-start.sh

# 使用/home路径（集成测试配套）
cd scripts && ./manual-test-home.sh
```

## 依赖

- Rust 2021 Edition
- OpenSSL (libssl-dev)
- Linux (vsock支持)

> **Windows用户**：可通过WSL获得Linux环境，参见 `.opencode/skills/wsl-cargo/SKILL.md`。

## RPM打包

```bash
cargo build --release
cargo install cargo-generate-rpm
cargo generate-rpm -p trustruntime
# 输出: target/generate-rpm/trustruntime-*.rpm
```