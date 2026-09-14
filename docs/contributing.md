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
│   ├── interface.md         # 接口文档
│   ├── user-guide.md        # 使用指南
│   ├── faq.md               # FAQ
│   └── contributing.md      # 开发指南
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
    #[error("OpenSSL 错误: {0}")]
    OpenSslError(#[from] openssl::error::ErrorStack),
}
```

避免在公共 API 中使用 `Box<dyn Error>`。

### 3.3 日志规范

使用 `log` crate 宏：

```rust
use log::{info, warn, error};

// 启动信息
info!("Service started on vsock port {}", port);

// 告警
warn!("Certificate will expire in {} days", days);

// 错误
error!("Failed to load certificate: {}", err);
```

日志系统由 `logger::init_logger(&config.log)` 在启动时初始化（基于 `log4rs`）。

**日志级别限制**：

- **Release 版本**：仅支持 info/warn/error 级别
- **Debug 版本**：支持所有级别（trace/debug/info/warn/error）
- 配置验证会在 release 构建时拒绝 debug/trace 级别

**日志安全规范**：

禁止记录敏感信息：
- 文件路径（证书路径、配置文件路径、密钥路径）
- 密钥材料（私钥内容、密码）
- 证书详情（not_before/not_after 时间戳）

使用固定描述代替动态路径：
```rust
// 错误示例（泄露路径）
error!("Failed to load certificate: {}", cert_path);

// 正确示例（固定描述）
error!("Failed to load certificate");
```

### 3.4 Clippy 未覆盖的编码规范

Clippy 无法检测以下规范，需开发者人工遵守。

#### 3.4.1 禁止在 Match 分支的 Guard 条件中使用具有副作用的表达式

Match guard 条件仅限纯比较或纯查询（`==`、`is_empty()`、`starts_with()` 等），禁止赋值、I/O、原子写、锁操作等副作用。

#### 3.4.2 逻辑与/或操作符的右侧不应存在副作用操作

右侧操作数不应包含赋值、I/O、原子写、状态修改等副作用。利用短路求值控制副作用执行时机的写法属于违规，应拆分为嵌套 `if` 将副作用放在内层，并添加 `#[allow(clippy::collapsible_if)]`。

#### 3.4.3 定义宏匹配规则时，应遵循由窄到宽的排列顺序

具体规则在前，通用规则在后，否则通用规则贪婪匹配导致具体规则永不触发（死规则）。

### 3.5 Unsafe 编码规范

#### 3.5.1 禁止滥用 Unsafe 代码，仅在必要场景下使用

- 不为逃避编译器安全检查或提升性能而滥用 unsafe
- 尽量缩小 `unsafe` 块范围，空指针检查、数值比较、日志等安全操作应移出
- 禁止通过 unsafe 将不可变引用/指针手工转换为可变引用/指针

#### 3.5.2 Unsafe 块中涉及的裸指针与内存地址，须在操作前完成有效性校验

所有 FFI 返回的裸指针必须先 null 检查再使用：`if ptr.is_null() { return Err(...); }`

#### 3.5.3 Unsafe 模式下分配的内存资源，须确保释放路径与分配方式匹配，杜绝泄漏与悬垂指针

需区分 OpenSSL `get0`/`get1` 内存所有权语义：

| 后缀 | 栈所有权 | 元素引用计数 | 栈释放方式 |
|------|---------|------------|-----------|
| `get0`（如 `CMS_get0_SignerInfos`） | 借用（不释放） | 不增加 | 不释放 |
| `get1`（如 `CMS_get1_certs`） | 新建（需释放） | 已增加 | `OPENSSL_sk_free` |

**特别注意**：`CMS_get0_signers` 不遵循标准 `get0` 语义——返回新建栈（需 `OPENSSL_sk_free`）但证书不 up_ref。

```rust
// CMS_get0_signers：新建栈 + 借用证书 → 需手动 up_ref
unsafe { X509_up_ref(ptr) };
unsafe { OPENSSL_sk_free(stack) };
Some(unsafe { X509::from_ptr(ptr) })

// CMS_get1_certs：新建栈 + 已 up_ref → 直接接管
certs_vec.push(unsafe { X509::from_ptr(ptr) });
unsafe { OPENSSL_sk_free(stack) };
```

### 3.6 FFI 编码规范

#### 3.6.1 FFI 边界内存安全管理

- **安全性**：确保调用的 C 函数不会导致未定义行为或内存安全问题
- **ABI 兼容性**：使用 `extern "C"` 声明 C 函数，回调函数用 `unsafe extern "C" fn`，确保签名与 C 侧匹配
- **所有权 & 生命周期**：区分 OpenSSL `get0`/`get1` 语义（详见 §3.5.3），借用指针不释放，副本需释放，回调函数指针生命周期需在调用期间有效
- **内存管理**：注意内存的申请和释放，避免内存泄漏/悬垂指针

#### 3.6.2 跨边界数据内存布局兼容

跨 FFI 传递的结构体必须添加 `#[repr(C)]` 避免字段重排。来自 `openssl_sys`/`libc` 的类型已自带，opaque 类型（零变体枚举）仅通过裸指针传递不需要。

```rust
#[repr(C)]
pub struct VsockHeader { pub seq: u32, pub version: u32, pub msg_type: u32, pub len: u32 }
```

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

# ASan 集成测试（可选，需 nightly）
./run-integration-tests.sh --asan
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
| 接口文档 | `docs/interface.md` |
| 使用指南 | `docs/user-guide.md` |
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

**RPM 安装后行为**：

- 服务自动启动：安装后自动启动 trustruntime 服务
- 服务状态检查：`systemctl status trustruntime`
- 日志查看：`journalctl -u trustruntime -f`

### 7.3 发布检查清单

- [ ] 所有测试通过
- [ ] Clippy 无 warning
- [ ] 文档更新
- [ ] CHANGELOG.md 更新
- [ ] 版本号更新

---

## 8. 相关文档

- [使用指南](user-guide.md)
- [接口文档](interface.md)
- [术语表](../CONTEXT.md)
- [AGENTS.md](../AGENTS.md)（Agent 指令）