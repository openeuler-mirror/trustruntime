# TrustRuntime 开发指南

| 文档版本 | V1.0 |
| 编写日期 | 2026-06-29 |

---

## 1. 开发环境搭建

### 1.1 系统要求

TrustRuntime 目标平台为 **Linux**，但可以在 Windows 上通过 WSL 进行开发。

| 环境 | 说明 |
|------|------|
| Linux | 原生构建环境（推荐） |
| Windows + WSL | Windows 开发者替代方案 |

### 1.2 Linux 环境

#### 安装 Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

#### 安装依赖

```bash
# Ubuntu/Debian
sudo apt install -y build-essential libssl-dev pkg-config

# CentOS/RHEL
sudo yum install -y gcc openssl-devel pkgconfig
```

#### 克隆项目

```bash
git clone https://github.com/your-org/trustruntime.git
cd trustruntime
```

### 1.3 Windows + WSL 环境

#### 安装 WSL

```powershell
wsl --install -d Ubuntu
```

#### 在 WSL 中配置 Rust

```bash
# 在 WSL Ubuntu 中执行
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

#### 构建/测试项目

Windows 代码仓位于 `/mnt/` 路径下：

```bash
# 进入项目目录（假设在 E:\your_name\trustruntime）
cd /mnt/e/your_name/trustruntime/rust

# 构建
cargo build --release

# 测试
cargo test --workspace
```

**WSL 快捷命令（PowerShell）**：

```powershell
wsl bash -c "source ~/.cargo/env && cd /mnt/e/your_name/trustruntime/rust && cargo test --workspace"
```

更多 WSL 使用方式参见 `.opencode/skills/wsl-cargo/SKILL.md`。

### 1.4 IDE 配置

#### VS Code

推荐扩展：

- rust-analyzer（Rust 语言服务器）
- CodeLLDB（调试器）
- Better TOML（Cargo.toml 编辑）

#### RustRover / IntelliJ IDEA

安装 Rust 插件。

---

## 2. 项目结构

### 2.1 目录结构

```
trustruntime/
├── rust/                    # Cargo workspace
│   ├── framework/           # trustruntime-framework (library)
│   ├── trustruntime/        # 主程序入口 (binary)
│   ├── plugins/trustring/   # trustring (library)
│   ├── integration-tests/   # 集成测试 (test crate)
│   ├── tools/cert-gen/      # 测试证书生成工具
│   └── scripts/             # 开发测试脚本
├── docs/                    # 设计文档
│   ├── adr/                 # 架构决策记录
│   ├── detailed-design/     # 详细设计
│   ├── requirements.md      # 需求文档
│   ├── interface.md         # 接口文档
│   └── functional-design.md # 功能设计
├── conf/                    # 默认配置
├── packaging/               # RPM 打包
├── CONTEXT.md               # 术语表
├── AGENTS.md                # Agent 指令
└── .opencode/               # opencode 配置
```

### 2.2 Cargo Workspace

`rust/Cargo.toml` 定义 workspace：

```toml
[workspace]
members = [
    "framework",
    "trustruntime",
    "plugins/trustring",
    "integration-tests",
    "tools/cert-gen",
]
resolver = "2"
```

### 2.3 Crate 依赖关系

```
trustruntime (binary)
    └── framework (library)
    └── trustring (library)
            └── framework (library)
```

| Crate | 类型 | 说明 |
|-------|------|------|
| `framework` | library | 通用进程框架：vsock 通信、TLS、配置、日志、插件管理 |
| `trustring` | library | CMS 签名验签业务插件，实现 Plugin trait |
| `trustruntime` | binary | 主程序入口，组装 framework + trustring |

---

## 3. 编码规范

### 3.1 Rust 代码风格

遵循标准 Rust 代码风格：

- 使用 `cargo fmt` 格式化代码
- 使用 `cargo clippy` 检查代码质量

```bash
# 格式化
cargo fmt --all

# Clippy 检查
cargo clippy --all-targets --all-features -- -D warnings
```

### 3.2 错误处理

使用 `thiserror` crate 定义错误类型：

```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SignError {
    #[error("证书加载失败: {0}")]
    CertLoadError(#[from] openssl::error::ErrorStack),

    #[error("私钥不可用")]
    KeyUnavailable,

    #[error("签名算法错误")]
    AlgorithmError,
}
```

避免在公共 API 中使用 `Box<dyn Error>`。

### 3.3 日志规范

使用 `log` crate 宏：

```rust
use log::{info, warn, error, debug};

// 启动信息
info!("Service started on vsock port {}", port);

// 告警
warn!("Certificate {} will expire in {} days", cert_path, days);

// 错误
error!("Failed to load certificate: {}", err);

// 调试信息
debug!("Processing request type 0x{:02x}", msg_type);
```

日志系统由 `logger::init_logger(&config.log)` 在启动时初始化（基于 `log4rs`）。

### 3.4 模块职责边界

#### message 模块（纯数据层）

- 负责：报文结构定义、序列化/反序列化
- **不负责**：业务校验（version 匹配、长度限制）、错误响应构造
- 校验逻辑归属 `vsock_server`（通信层）

#### config 模块

- 负责：TOML 配置解析、结构体映射
- 不负责：配置文件存在性检查、文件权限校验、热更新
- 可选字段使用 `Option<T>` 或 `#[serde(default)]`

#### plugin 模块

- 插件在 `init()` 中通过 `ctx.register_handler(type)` 注册消息类型
- Handler panic recovery：`catch_unwind` 返回错误类型 0x00，None 返回 0x01

### 3.5 字节序

所有消息序列化使用 **小端序（Little Endian）**。

```rust
// VsockHeader 序列化示例
let seq_bytes = seq.to_le_bytes();  // 小端序
```

### 3.6 异步架构

- `TransportLayer` trait（定义于 `transport` 模块）使用 `async-trait`
- `main.rs` 使用 `#[tokio::main(worker_threads = 4)]`
- 并发连接使用 `tokio::sync::Semaphore`（16 permits）
- 线程数限制为 4，足够处理最大 16 个并发连接

---

## 4. 提交规范

### 4.1 Commit Message 格式

```
<type>: <标题（英文）>

<描述（中文）>

Code-Owner: <邮箱>
Co-Authored-By: glm-5 (alibaba-cn)
```

#### 类型关键字 (Conventional Commits)

| 类型 | 用途 |
|------|------|
| `feat` | 新功能 |
| `fix` | 修复问题 |
| `test` | 测试用例 |
| `docs` | 文档 |
| `refactor` | 重构 |
| `chore` | 构建/配置/杂项 |
| `style` | 代码风格 |
| `perf` | 性能优化 |

#### 示例

```
feat: add CMS signing implementation

使用 OpenSSL ECC-256 算法实现 CMS 签名功能。

功能特性：
- 使用本地证书签名数据
- 提取 Subject Key ID 作为证书标识
- 支持 PEM/DER 格式证书

依赖模块：
- trustruntime-framework/cert
- trustruntime-framework/message

Code-Owner: your_name@example.com
Co-Authored-By: glm-5 (alibaba-cn)
```

### 4.2 提交前检查清单

- [ ] 使用正确的类型关键字
- [ ] 标题简洁（50字符以内），使用英文
- [ ] 描述清晰说明"做了什么"和"为什么"，使用中文
- [ ] 指定 Code-Owner
- [ ] 包含相关文档（如适用）
- [ ] 包含测试（如适用）
- [ ] 代码可编译

### 4.3 PR 拆分原则

1. **每个 PR 包含**：相关文档 + 代码 + 单元测试
2. **文档先行**：PR 描述中引用设计文档
3. **依赖顺序**：底层模块先提交
4. **编译保证**：每次提交都能编译通过

#### PR 流程

1. 从 `main` 分支创建特性分支

```bash
git checkout -b feature/sign-interface
```

2. 开发并测试

```bash
cargo test --workspace
cargo clippy --all-targets
```

3. 提交代码

```bash
git add .
git commit -m "feat: add CMS signing implementation"
```

4. 推送分支

```bash
git push origin feature/sign-interface
```

5. 创建 Pull Request

确保 PR 包含：
- 功能描述
- 设计文档引用
- 测试覆盖
- 相关 Issue 链接

### 4.4 Code Review 要求

- 所有 PR 需经过至少一人 Review
- CI 测试必须通过
- Clippy 检查无 warning
- 遵循 PR 拆分原则

---

## 5. 测试规范

### 5.1 测试分层

| 层级 | 位置 | 运行方式 |
|------|------|----------|
| 单元测试 | `src/**/*.rs` 内 `#[cfg(test)] mod tests` | `cargo test -p <crate>` |
| 集成测试 | `tests/*.rs`（crate 根目录） | `cargo test -p <crate>` |
| 全 workspace 测试 | 所有 crate | `cargo test --workspace` |

### 5.2 TDD 流程

采用 **Red-Green-Refactor** 循环：

1. **Red**：先写测试，描述期望行为，测试必须失败
2. **Green**：写最少代码使测试通过
3. **Refactor**：重构代码，保持测试通过

开发顺序（按依赖关系）：

```
第1层：纯数据结构 + 配置解析
  ├── message（报文解析/构造）
  ├── config（TOML 配置解析）

第2层：业务逻辑
  ├── cert-loader（证书加载）
  ├── sign（CMS 签名）
  ├── verify（CMS 验签）
  ├── handler（DataHandler 实现）

第3层：基础设施
  ├── logger（日志）
  ├── plugin-manager（插件管理）
  ├── communication/vsock-server

第4层：集成组装
  ├── core（进程管理）
  ├── main.rs（入口）
```

### 5.3 测试 Fixture 管理

- 测试证书放在 `tests/fixtures/` 下
- 测试代码通过相对路径引用 fixture
- 测试证书由 OpenSSL 脚本生成，不提交到仓库

```bash
# 生成测试证书
cd rust/scripts
./gen_test_certs.sh
```

### 5.4 运行测试

```bash
# 全 workspace 测试
cd rust
cargo test --workspace

# 单 crate 测试
cargo test -p trustruntime-framework
cargo test -p trustring

# 集成测试（推荐使用脚本）
cd rust/scripts
./run-integration-tests.sh
```

### 5.5 测试原则

测试应验证行为通过公共接口：

- 不测试内部实现细节
- 测试边界条件和错误场景
- 使用 fixture 而非硬编码数据

---

## 6. 文档规范

### 6.1 文档位置

| 文档类型 | 路径 |
|----------|------|
| 需求文档 | `docs/requirements.md` |
| 接口文档 | `docs/interface.md` |
| 架构决策 | `docs/adr/*.md` |
| 详细设计 | `docs/detailed-design/*.md` |
| 术语表 | `CONTEXT.md` |

### 6.2 ADR 格式

架构决策记录（ADR）格式：

```markdown
# 0001-决策标题

决策摘要。

## Considered Options

1. 选项 A
2. 选项 B
3. 选项 C

## Decision Outcome

选择选项 X，理由...

## Consequences

- 影响 1
- 影响 2
```

### 6.3 详细设计格式

详细设计文档格式：

```markdown
# XXX 详细设计

## 1. 职责与边界
### 负责
### 不负责

## 2. 公开 API

## 3. 内部状态

## 4. 关键场景

## 5. 依赖关系

## 6. 测试策略
```

---

## 7. 发布流程

### 7.1 版本号规则

使用语义化版本号：`MAJOR.MINOR.PATCH`

- MAJOR：不兼容的 API 变化
- MINOR：向后兼容的功能新增
- PATCH：向后兼容的 Bug 修复

### 7.2 RPM 打包

```bash
cd rust
cargo build --release
cargo install cargo-generate-rpm
cargo generate-rpm -p trustruntime

# 输出：target/generate-rpm/trustruntime-*.rpm
```

RPM 配置在 `rust/trustruntime/Cargo.toml` 的 `[package.metadata.generate-rpm]` 部分。

### 7.3 发布检查清单

- [ ] 所有测试通过
- [ ] Clippy 无 warning
- [ ] 文档更新
- [ ] CHANGELOG.md 更新
- [ ] 版本号更新

---

## 8. 相关文档

- [使用指南](user-guide.md)
- [架构设计](architecture.md)
- [接口文档](interface.md)
- [术语表](../CONTEXT.md)
- [AGENTS.md](../AGENTS.md)（Agent 指令）